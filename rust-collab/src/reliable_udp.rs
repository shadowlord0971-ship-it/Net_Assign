use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAGIC: &[u8; 4] = b"RCF1";
const HEADER_LEN: usize = 13;
const START_LEN: usize = HEADER_LEN + 8 + 4 + 32;
const DATA_HEADER_LEN: usize = HEADER_LEN + 4;
const MAX_DATAGRAM_BYTES: usize = 1200;
const CHUNK_BYTES: usize = MAX_DATAGRAM_BYTES - DATA_HEADER_LEN;
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const WINDOW_SIZE: usize = 32;
const RETRANSMIT_AFTER: Duration = Duration::from_millis(150);
const RECEIVE_POLL: Duration = Duration::from_millis(20);
const MAX_RETRIES: u8 = 20;
const RECEIVER_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

const START: u8 = 1;
const READY: u8 = 2;
const DATA: u8 = 3;
const ACK: u8 = 4;
const FINISH: u8 = 5;
const COMPLETE: u8 = 6;
const ERROR: u8 = 7;
const COMPLETE_ACK: u8 = 8;

#[derive(Debug, Clone, Copy)]
pub struct TransferConfig {
    pub window_size: usize,
    pub retransmit_after: Duration,
    pub max_retries: u8,
    pub receiver_idle_timeout: Duration,
}

struct PartFileGuard {
    path: PathBuf,
    committed: bool,
}

impl PartFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PartFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = fs::remove_file(&self.path) {
                if error.kind() != io::ErrorKind::NotFound {
                    eprintln!(
                        "could not remove partial transfer {}: {error}",
                        self.path.display()
                    );
                }
            }
        }
    }
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            window_size: WINDOW_SIZE,
            retransmit_after: RETRANSMIT_AFTER,
            max_retries: MAX_RETRIES,
            receiver_idle_timeout: RECEIVER_IDLE_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferStats {
    pub bytes: u64,
    pub retransmissions: u64,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescription {
    pub size: u64,
    pub digest: [u8; 32],
}

pub fn describe_file(source: &Path) -> io::Result<FileDescription> {
    let mut file = File::open(source)?;
    let size = file.metadata()?.len();
    if size > MAX_FILE_BYTES {
        return Err(invalid_input("file exceeds the 1 GiB transfer limit"));
    }
    Ok(FileDescription {
        size,
        digest: hash_reader(&mut file)?,
    })
}

pub fn send_file(
    socket: &UdpSocket,
    peer: SocketAddr,
    source: &Path,
    config: TransferConfig,
) -> io::Result<TransferStats> {
    send_file_with_id(socket, peer, source, new_transfer_id(), config)
}

pub fn send_file_with_id(
    socket: &UdpSocket,
    peer: SocketAddr,
    source: &Path,
    transfer_id: u64,
    config: TransferConfig,
) -> io::Result<TransferStats> {
    validate_config(config)?;
    let mut file = File::open(source)?;
    let size = file.metadata()?.len();
    if size > MAX_FILE_BYTES {
        return Err(invalid_input("file exceeds the 1 GiB transfer limit"));
    }
    let chunks_u64 = size.div_ceil(CHUNK_BYTES as u64);
    let chunks = u32::try_from(chunks_u64)
        .map_err(|_| invalid_input("file requires too many UDP chunks"))?;
    let digest = hash_reader(&mut file)?;
    let started_at = Instant::now();
    let mut retransmissions = 0;
    let start_packet = encode_start(transfer_id, size, chunks, &digest);
    retry_control(
        socket,
        peer,
        &start_packet,
        transfer_id,
        READY,
        config,
        &mut retransmissions,
    )?;

    let mut pending = BTreeMap::<u32, PendingChunk>::new();
    let mut next_chunk = 0_u32;
    let mut acknowledged = 0_u32;
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES];
    socket.set_read_timeout(Some(RECEIVE_POLL))?;

    while acknowledged < chunks {
        while next_chunk < chunks && pending.len() < config.window_size {
            let data = read_chunk(&mut file, next_chunk, size)?;
            let packet = encode_data(transfer_id, next_chunk, &data);
            socket.send_to(&packet, peer)?;
            pending.insert(
                next_chunk,
                PendingChunk {
                    packet,
                    last_sent: Instant::now(),
                    retries: 0,
                },
            );
            next_chunk += 1;
        }

        match socket.recv_from(&mut buffer) {
            Ok((length, source)) if source == peer => {
                let Some((kind, id, sequence, _)) = decode_packet(&buffer[..length])? else {
                    continue;
                };
                if id == transfer_id && kind == ACK {
                    if sequence < chunks && pending.remove(&sequence).is_some() {
                        acknowledged += 1;
                    }
                } else if id == transfer_id && kind == ERROR {
                    return Err(peer_error(&buffer[..length]));
                }
            }
            Ok(_) => continue,
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }

        let now = Instant::now();
        for chunk in pending.values_mut() {
            if now.duration_since(chunk.last_sent) >= config.retransmit_after {
                if chunk.retries >= config.max_retries {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "UDP chunk retry limit exceeded",
                    ));
                }
                socket.send_to(&chunk.packet, peer)?;
                chunk.retries += 1;
                chunk.last_sent = now;
                retransmissions += 1;
            }
        }
    }

    let finish_packet = encode_control(FINISH, transfer_id);
    retry_control(
        socket,
        peer,
        &finish_packet,
        transfer_id,
        COMPLETE,
        config,
        &mut retransmissions,
    )?;

    Ok(TransferStats {
        bytes: size,
        retransmissions,
        elapsed: started_at.elapsed(),
    })
}

pub fn receive_file(
    socket: &UdpSocket,
    output: &Path,
    config: TransferConfig,
) -> io::Result<TransferStats> {
    receive_file_expected(socket, output, None, config)
}

pub fn validate_output_path(output: &Path) -> io::Result<()> {
    if output.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite {}", output.display()),
        ));
    }
    let partial = part_path(output);
    if partial.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "partial transfer file already exists: {}",
                partial.display()
            ),
        ));
    }
    if output
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty() && !parent.is_dir())
    {
        return Err(invalid_input("output directory does not exist"));
    }
    Ok(())
}

pub fn receive_file_expected(
    socket: &UdpSocket,
    output: &Path,
    offered_digest: Option<[u8; 32]>,
    config: TransferConfig,
) -> io::Result<TransferStats> {
    validate_config(config)?;
    validate_output_path(output)?;
    let part_path = part_path(output);

    let started_at = Instant::now();
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES];
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    let waiting_since = Instant::now();
    let (peer, transfer_id, size, chunks, expected_digest, mut file, mut received, _guard) = loop {
        let (length, peer) = match socket.recv_from(&mut buffer) {
            Ok(datagram) => datagram,
            Err(error) if is_timeout(&error) => {
                if waiting_since.elapsed() >= config.receiver_idle_timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for a UDP file transfer",
                    ));
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        let packet = match decode_packet(&buffer[..length]) {
            Ok(packet) => packet,
            Err(_) => continue,
        };
        let Some((START, transfer_id, _, _)) = packet else {
            continue;
        };
        let Some((size, chunks, digest)) = decode_start(&buffer[..length]) else {
            continue;
        };
        if offered_digest.is_some_and(|expected| expected != digest) {
            send_error(
                socket,
                peer,
                transfer_id,
                "transfer digest differs from accepted offer",
            );
            continue;
        }
        if size > MAX_FILE_BYTES || size.div_ceil(CHUNK_BYTES as u64) != u64::from(chunks) {
            send_error(
                socket,
                peer,
                transfer_id,
                "invalid file size or chunk count",
            );
            continue;
        }
        let file = match OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&part_path)
        {
            Ok(file) => file,
            Err(error) => {
                send_error(socket, peer, transfer_id, &error.to_string());
                return Err(error);
            }
        };
        let guard = PartFileGuard::new(part_path.clone());
        if let Err(error) = file.set_len(size) {
            send_error(socket, peer, transfer_id, &error.to_string());
            return Err(error);
        }
        send_control(socket, peer, READY, transfer_id)?;
        break (
            peer,
            transfer_id,
            size,
            chunks,
            digest,
            file,
            BTreeSet::new(),
            guard,
        );
    };

    let mut retransmissions = 0_u64;
    let mut last_activity = Instant::now();

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, source)) => {
                if source != peer {
                    continue;
                }
                let packet = match decode_packet(&buffer[..length]) {
                    Ok(Some(packet)) => packet,
                    Ok(None) | Err(_) => continue,
                };
                let (kind, id, sequence, body) = packet;
                if id != transfer_id {
                    continue;
                }
                last_activity = Instant::now();
                match kind {
                    START => {
                        if decode_start(&buffer[..length]).is_some_and(
                            |(new_size, new_chunks, new_digest)| {
                                new_size == size
                                    && new_chunks == chunks
                                    && new_digest == expected_digest
                            },
                        ) {
                            send_control(socket, peer, READY, transfer_id)?;
                        }
                    }
                    DATA if sequence < chunks && !body.is_empty() => {
                        let offset = u64::from(sequence) * CHUNK_BYTES as u64;
                        let expected_length = (size - offset).min(CHUNK_BYTES as u64) as usize;
                        if body.len() != expected_length {
                            send_error(socket, peer, transfer_id, "invalid chunk length");
                            continue;
                        }
                        if received.insert(sequence) {
                            file.seek(SeekFrom::Start(offset))?;
                            file.write_all(body)?;
                        } else {
                            retransmissions += 1;
                        }
                        send_ack(socket, peer, transfer_id, sequence)?;
                    }
                    ERROR => return Err(peer_error(&buffer[..length])),
                    FINISH => {
                        if received.len() != chunks as usize {
                            send_error(socket, peer, transfer_id, "file is missing chunks");
                            continue;
                        }
                        file.flush()?;
                        file.seek(SeekFrom::Start(0))?;
                        let actual_digest = hash_reader(&mut file)?;
                        if actual_digest != expected_digest {
                            send_error(socket, peer, transfer_id, "file checksum mismatch");
                            drop(file);
                            return Err(invalid_data("received file checksum mismatch"));
                        }
                        drop(file);
                        fs::rename(&part_path, output)?;
                        _guard.commit();
                        complete_receive_handshake(socket, peer, transfer_id, config)?;
                        break;
                    }
                    _ => {}
                }
            }
            Err(error) if is_timeout(&error) => {
                if last_activity.elapsed() >= config.receiver_idle_timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "receiver idle timeout expired",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }

    Ok(TransferStats {
        bytes: size,
        retransmissions,
        elapsed: started_at.elapsed(),
    })
}

struct PendingChunk {
    packet: Vec<u8>,
    last_sent: Instant,
    retries: u8,
}

fn validate_config(config: TransferConfig) -> io::Result<()> {
    if config.window_size == 0 || config.window_size > 1024 {
        return Err(invalid_input("window size must be between 1 and 1024"));
    }
    if config.retransmit_after.is_zero()
        || config.max_retries == 0
        || config.receiver_idle_timeout.is_zero()
    {
        return Err(invalid_input(
            "transfer timeouts and retry limit must be non-zero",
        ));
    }
    Ok(())
}

fn retry_control(
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    transfer_id: u64,
    expected_kind: u8,
    config: TransferConfig,
    retransmissions: &mut u64,
) -> io::Result<()> {
    socket.set_read_timeout(Some(config.retransmit_after))?;
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES];
    for attempt in 0..=config.max_retries {
        socket.send_to(packet, peer)?;
        if attempt > 0 {
            *retransmissions += 1;
        }
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((length, source)) if source == peer => {
                    let Some((kind, id, _, _)) = decode_packet(&buffer[..length])? else {
                        continue;
                    };
                    if id == transfer_id && kind == expected_kind {
                        if expected_kind == COMPLETE {
                            send_control(socket, peer, COMPLETE_ACK, transfer_id)?;
                        }
                        return Ok(());
                    }
                    if id == transfer_id && kind == ERROR {
                        return Err(peer_error(&buffer[..length]));
                    }
                }
                Ok(_) => continue,
                Err(error) if is_timeout(&error) => break,
                Err(error) => return Err(error),
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "UDP control message retry limit exceeded",
    ))
}

fn complete_receive_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    transfer_id: u64,
    config: TransferConfig,
) -> io::Result<()> {
    let complete = encode_control(COMPLETE, transfer_id);
    let mut buffer = [0_u8; MAX_DATAGRAM_BYTES];
    socket.set_read_timeout(Some(config.retransmit_after))?;
    for _ in 0..=config.max_retries {
        socket.send_to(&complete, peer)?;
        loop {
            match socket.recv_from(&mut buffer) {
                Ok((length, source)) if source == peer => {
                    let Some((kind, id, _, _)) = decode_packet(&buffer[..length])? else {
                        continue;
                    };
                    if id != transfer_id {
                        continue;
                    }
                    if kind == COMPLETE_ACK {
                        return Ok(());
                    }
                    if kind == FINISH {
                        break;
                    }
                    if kind == ERROR {
                        return Err(peer_error(&buffer[..length]));
                    }
                }
                Ok(_) => continue,
                Err(error) if is_timeout(&error) => break,
                Err(error) => return Err(error),
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "completion acknowledgement retry limit exceeded",
    ))
}

fn read_chunk(file: &mut File, sequence: u32, total_size: u64) -> io::Result<Vec<u8>> {
    let offset = u64::from(sequence) * CHUNK_BYTES as u64;
    let length = (total_size - offset).min(CHUNK_BYTES as u64) as usize;
    let mut chunk = vec![0_u8; length];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut chunk)?;
    Ok(chunk)
}

fn hash_reader(reader: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(hasher.finalize().into())
}

fn encode_start(transfer_id: u64, size: u64, chunks: u32, digest: &[u8; 32]) -> Vec<u8> {
    let mut packet = base_packet(START, transfer_id);
    packet.extend_from_slice(&size.to_be_bytes());
    packet.extend_from_slice(&chunks.to_be_bytes());
    packet.extend_from_slice(digest);
    packet
}

fn decode_start(packet: &[u8]) -> Option<(u64, u32, [u8; 32])> {
    if packet.len() != START_LEN || packet[4] != START {
        return None;
    }
    let size = u64::from_be_bytes(packet[HEADER_LEN..HEADER_LEN + 8].try_into().ok()?);
    let chunks = u32::from_be_bytes(packet[HEADER_LEN + 8..HEADER_LEN + 12].try_into().ok()?);
    let digest = packet[HEADER_LEN + 12..START_LEN].try_into().ok()?;
    Some((size, chunks, digest))
}

fn encode_data(transfer_id: u64, sequence: u32, chunk: &[u8]) -> Vec<u8> {
    let mut packet = base_packet(DATA, transfer_id);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(chunk);
    packet
}

fn encode_ack(transfer_id: u64, sequence: u32) -> Vec<u8> {
    let mut packet = base_packet(ACK, transfer_id);
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet
}

fn encode_control(kind: u8, transfer_id: u64) -> Vec<u8> {
    base_packet(kind, transfer_id)
}

fn base_packet(kind: u8, transfer_id: u64) -> Vec<u8> {
    let mut packet = Vec::with_capacity(HEADER_LEN);
    packet.extend_from_slice(MAGIC);
    packet.push(kind);
    packet.extend_from_slice(&transfer_id.to_be_bytes());
    packet
}

type DecodedPacket<'a> = (u8, u64, u32, &'a [u8]);

fn decode_packet(packet: &[u8]) -> io::Result<Option<DecodedPacket<'_>>> {
    if packet.len() < HEADER_LEN || packet.get(..4) != Some(MAGIC.as_slice()) {
        return Ok(None);
    }
    let kind = packet[4];
    let id = u64::from_be_bytes(
        packet[5..HEADER_LEN]
            .try_into()
            .map_err(|_| invalid_data("invalid transfer ID"))?,
    );
    match kind {
        START if packet.len() == START_LEN => Ok(Some((kind, id, 0, &packet[HEADER_LEN..]))),
        READY | COMPLETE | FINISH | COMPLETE_ACK if packet.len() == HEADER_LEN => {
            Ok(Some((kind, id, 0, &packet[HEADER_LEN..])))
        }
        ACK if packet.len() == DATA_HEADER_LEN => {
            let sequence = u32::from_be_bytes(
                packet[HEADER_LEN..DATA_HEADER_LEN]
                    .try_into()
                    .map_err(|_| invalid_data("invalid ACK sequence"))?,
            );
            Ok(Some((kind, id, sequence, &[])))
        }
        DATA if packet.len() > DATA_HEADER_LEN && packet.len() <= MAX_DATAGRAM_BYTES => {
            let sequence = u32::from_be_bytes(
                packet[HEADER_LEN..DATA_HEADER_LEN]
                    .try_into()
                    .map_err(|_| invalid_data("invalid chunk sequence"))?,
            );
            Ok(Some((kind, id, sequence, &packet[DATA_HEADER_LEN..])))
        }
        ERROR if packet.len() > HEADER_LEN && packet.len() <= MAX_DATAGRAM_BYTES => {
            Ok(Some((kind, id, 0, &packet[HEADER_LEN..])))
        }
        _ => Ok(None),
    }
}

fn send_control(
    socket: &UdpSocket,
    peer: SocketAddr,
    kind: u8,
    transfer_id: u64,
) -> io::Result<()> {
    socket.send_to(&encode_control(kind, transfer_id), peer)?;
    Ok(())
}

fn send_ack(
    socket: &UdpSocket,
    peer: SocketAddr,
    transfer_id: u64,
    sequence: u32,
) -> io::Result<()> {
    socket.send_to(&encode_ack(transfer_id, sequence), peer)?;
    Ok(())
}

fn send_error(socket: &UdpSocket, peer: SocketAddr, transfer_id: u64, message: &str) {
    let mut packet = base_packet(ERROR, transfer_id);
    packet.extend_from_slice(
        &message.as_bytes()[..message.len().min(MAX_DATAGRAM_BYTES - HEADER_LEN)],
    );
    if let Err(error) = socket.send_to(&packet, peer) {
        eprintln!("could not send UDP transfer error: {error}");
    }
}

fn peer_error(packet: &[u8]) -> io::Error {
    let message = decode_packet(packet)
        .ok()
        .flatten()
        .and_then(|(_, _, _, body)| std::str::from_utf8(body).ok())
        .unwrap_or("remote transfer error");
    io::Error::other(message.to_owned())
}

pub fn new_transfer_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    time ^ u64::from(std::process::id()).rotate_left(17) ^ NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn part_path(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        thread,
    };

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rust-collab-{label}-{}-{}.tmp",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ))
    }

    #[test]
    fn reliable_transfer_recovers_from_dropped_data_and_ack() {
        let input = temp_path("input");
        let output = temp_path("output");
        let payload: Vec<u8> = (0..(CHUNK_BYTES * 80 + 37))
            .map(|value| (value % 251) as u8)
            .collect();
        fs::write(&input, &payload).unwrap();

        let receiver = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        proxy
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let mut buffer = [0_u8; MAX_DATAGRAM_BYTES];
            let mut sender_address = None;
            let mut dropped_data = false;
            let mut dropped_ack = false;
            let mut dropped_complete = false;
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until {
                let Ok((length, source)) = proxy.recv_from(&mut buffer) else {
                    continue;
                };
                if source == receiver_address {
                    if !dropped_ack
                        && buffer[4] == ACK
                        && u32::from_be_bytes(
                            buffer[HEADER_LEN..DATA_HEADER_LEN].try_into().unwrap(),
                        ) == 1
                    {
                        dropped_ack = true;
                        continue;
                    }
                    if !dropped_complete && buffer[4] == COMPLETE {
                        dropped_complete = true;
                        continue;
                    }
                    if let Some(sender_address) = sender_address {
                        let _ = proxy.send_to(&buffer[..length], sender_address);
                    }
                } else {
                    sender_address = Some(source);
                    if buffer[4] == DATA
                        && !dropped_data
                        && u32::from_be_bytes(
                            buffer[HEADER_LEN..DATA_HEADER_LEN].try_into().unwrap(),
                        ) == 2
                    {
                        dropped_data = true;
                        continue;
                    }
                    let _ = proxy.send_to(&buffer[..length], receiver_address);
                    if buffer[4] == COMPLETE_ACK {
                        break;
                    }
                }
            }
            (dropped_data, dropped_ack, dropped_complete)
        });

        let output_for_receiver = output.clone();
        let receiver_worker = thread::spawn(move || {
            receive_file(&receiver, &output_for_receiver, TransferConfig::default()).unwrap()
        });
        let stats = send_file(
            &sender,
            proxy_address,
            &input,
            TransferConfig {
                retransmit_after: Duration::from_millis(60),
                ..TransferConfig::default()
            },
        )
        .unwrap();
        assert!(stats.retransmissions >= 2);
        let receive_stats = receiver_worker.join().unwrap();
        assert_eq!(receive_stats.bytes, payload.len() as u64);
        assert_eq!(fs::read(&output).unwrap(), payload);
        assert_eq!(proxy_thread.join().unwrap(), (true, true, true));
        fs::remove_file(input).unwrap();
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn empty_file_transfer_is_supported() {
        let input = temp_path("empty-input");
        let output = temp_path("empty-output");
        fs::write(&input, []).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let output_for_thread = output.clone();
        let worker = thread::spawn(move || {
            receive_file(&receiver, &output_for_thread, TransferConfig::default()).unwrap()
        });
        assert_eq!(
            send_file(&sender, address, &input, TransferConfig::default())
                .unwrap()
                .bytes,
            0
        );
        assert_eq!(worker.join().unwrap().bytes, 0);
        assert_eq!(fs::metadata(&output).unwrap().len(), 0);
        fs::remove_file(input).unwrap();
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn datagram_decoder_rejects_invalid_and_oversized_packets() {
        assert!(decode_packet(b"bad").unwrap().is_none());
        let mut oversized = encode_data(1, 0, &[0; CHUNK_BYTES + 1]);
        oversized.push(0);
        assert!(decode_packet(&oversized).unwrap().is_none());
    }

    #[test]
    fn packet_codec_keeps_sequences_and_payloads() {
        let packet = encode_data(42, 7, b"payload");
        assert_eq!(
            decode_packet(&packet).unwrap(),
            Some((DATA, 42, 7, b"payload".as_slice()))
        );
        let ack = encode_ack(42, u32::MAX);
        assert_eq!(
            decode_packet(&ack).unwrap(),
            Some((ACK, 42, u32::MAX, &[][..]))
        );
        assert_eq!(START_LEN, encode_start(1, 0, 0, &[0; 32]).len());
    }
}
