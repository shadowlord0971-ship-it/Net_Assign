use crate::protocol::{
    read_frame, validate_username, write_frame, FrameDecoder, Message, MAX_FRAME_BYTES,
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Sender, SyncSender, TryRecvError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const READ_POLL: Duration = Duration::from_millis(50);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

trait ClientStream: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn send_close_notify(&mut self) -> io::Result<()>;
}

impl ClientStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn send_close_notify(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ClientStream for StreamOwned<ClientConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    fn send_close_notify(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()
    }
}

enum InputAction {
    Send(Message),
    SendFile { recipient: String, path: PathBuf },
    AcceptFile { transfer_id: u64, output: PathBuf },
    RejectFile { transfer_id: u64 },
    CancelFile { transfer_id: u64 },
    Continue,
    Quit,
}

struct TransferResult {
    transfer_id: u64,
    label: String,
    result: io::Result<crate::reliable_udp::TransferStats>,
}

pub fn run(address: SocketAddr, username: &str) -> io::Result<()> {
    let stream = TcpStream::connect(address)?;
    let control = stream.try_clone()?;
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    run_stream(stream, control, udp, username)
}

pub fn load_tls_config(ca_path: &Path) -> io::Result<ClientConfig> {
    let mut reader = BufReader::new(File::open(ca_path)?);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted CA file contains no certificates",
        ));
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub fn run_tls(
    address: SocketAddr,
    username: &str,
    server_name: &str,
    config: ClientConfig,
) -> io::Result<()> {
    let socket = TcpStream::connect(address)?;
    socket.set_read_timeout(Some(LOGIN_TIMEOUT))?;
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let connection = ClientConnection::new(config.into(), server_name)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let stream = StreamOwned::new(connection, socket.try_clone()?);
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    run_stream(stream, socket, udp, username)
}

fn run_stream<S: ClientStream>(
    mut stream: S,
    control: TcpStream,
    udp: UdpSocket,
    username: &str,
) -> io::Result<()> {
    validate_username(username)?;
    write_frame(
        &mut stream,
        &Message::Hello {
            username: username.to_owned(),
        },
    )?;
    match read_frame(&mut stream)? {
        Some(Message::Welcome { username }) => {
            println!("Connected as {username}. Type /help for commands.");
        }
        Some(Message::Error { message }) => {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
        }
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "server sent an unexpected login response",
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "server closed the connection during login",
            ));
        }
    }
    let udp_port = udp.local_addr()?.port();
    write_frame(&mut stream, &Message::UdpRegister { port: udp_port })?;

    stream.set_read_timeout(Some(READ_POLL))?;
    let (input_sender, input_receiver) = mpsc::sync_channel(16);
    spawn_input_reader(input_sender)?;
    let (transfer_sender, transfer_receiver) = mpsc::channel::<TransferResult>();
    let active_transfer = Arc::new(Mutex::new(None::<u64>));
    let mut pending_sends = HashMap::<u64, PathBuf>::new();
    let mut incoming_offers = HashMap::<u64, [u8; 32]>::new();
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0_u8; 8192];
    let mut quit = false;

    while !quit {
        while let Ok(result) = transfer_receiver.try_recv() {
            match result.result {
                Ok(stats) => println!(
                    "\n{}: transferred {} bytes in {:.2?} ({} retransmissions)",
                    result.label, stats.bytes, stats.elapsed, stats.retransmissions
                ),
                Err(error) => eprintln!("\n{} failed: {error}", result.label),
            }
            clear_active_transfer(&active_transfer, result.transfer_id)?;
        }
        loop {
            match input_receiver.try_recv() {
                Ok(Some(line)) => {
                    let action = match parse_input(&line) {
                        Ok(action) => action,
                        Err(error) => {
                            eprintln!("invalid input: {error}");
                            continue;
                        }
                    };
                    match action {
                        InputAction::Send(message) => write_frame(&mut stream, &message)?,
                        InputAction::SendFile { recipient, path } => {
                            if active_transfer
                                .lock()
                                .map_err(|_| io::Error::other("transfer state lock was poisoned"))?
                                .is_some()
                            {
                                eprintln!("finish or reject the active file transfer first");
                                continue;
                            }
                            if !pending_sends.is_empty() {
                                eprintln!("only one outgoing file offer may be pending");
                                continue;
                            }
                            let description = match crate::reliable_udp::describe_file(&path) {
                                Ok(description) => description,
                                Err(error) => {
                                    eprintln!("cannot offer file: {error}");
                                    continue;
                                }
                            };
                            let Some(file_name) = path
                                .file_name()
                                .and_then(|name| name.to_str())
                                .filter(|name| !name.is_empty() && name.len() <= 255)
                            else {
                                eprintln!("file name must be valid UTF-8 and at most 255 bytes");
                                continue;
                            };
                            let file_name = file_name.to_owned();
                            let transfer_id = crate::reliable_udp::new_transfer_id();
                            reserve_active_transfer(&active_transfer, transfer_id)?;
                            pending_sends.insert(transfer_id, path);
                            if let Err(error) = write_frame(
                                &mut stream,
                                &Message::FileOffer {
                                    recipient,
                                    transfer_id,
                                    file_name,
                                    size: description.size,
                                    digest: description.digest,
                                },
                            ) {
                                pending_sends.remove(&transfer_id);
                                clear_active_transfer(&active_transfer, transfer_id)?;
                                return Err(error);
                            }
                            println!("file offer sent (transfer id {transfer_id})");
                        }
                        InputAction::AcceptFile {
                            transfer_id,
                            output,
                        } => {
                            let Some(digest) = incoming_offers.get(&transfer_id).copied() else {
                                eprintln!("no pending file offer with id {transfer_id}");
                                continue;
                            };
                            if let Err(error) = crate::reliable_udp::validate_output_path(&output) {
                                eprintln!("cannot receive file: {error}");
                                continue;
                            }
                            if let Err(error) =
                                reserve_active_transfer(&active_transfer, transfer_id)
                            {
                                eprintln!("cannot accept file offer: {error}");
                                continue;
                            }
                            let receive_socket = match udp.try_clone() {
                                Ok(socket) => socket,
                                Err(error) => {
                                    clear_active_transfer(&active_transfer, transfer_id)?;
                                    eprintln!("cannot prepare UDP receiver: {error}");
                                    continue;
                                }
                            };
                            if let Err(error) = spawn_receive(
                                receive_socket,
                                transfer_id,
                                output,
                                digest,
                                Arc::clone(&active_transfer),
                                transfer_sender.clone(),
                            ) {
                                clear_active_transfer(&active_transfer, transfer_id)?;
                                eprintln!("cannot start UDP receiver: {error}");
                                continue;
                            }
                            incoming_offers.remove(&transfer_id);
                            write_frame(&mut stream, &Message::FileAccept { transfer_id })?;
                            println!("accepted file offer {transfer_id}; receiving over UDP");
                        }
                        InputAction::RejectFile { transfer_id } => {
                            if incoming_offers.remove(&transfer_id).is_none() {
                                eprintln!("no pending file offer with id {transfer_id}");
                                continue;
                            }
                            write_frame(
                                &mut stream,
                                &Message::FileReject {
                                    transfer_id,
                                    reason: "recipient declined".into(),
                                },
                            )?;
                        }
                        InputAction::CancelFile { transfer_id } => {
                            if pending_sends.remove(&transfer_id).is_none() {
                                eprintln!("no pending outgoing offer with id {transfer_id}");
                                continue;
                            }
                            clear_active_transfer(&active_transfer, transfer_id)?;
                            write_frame(
                                &mut stream,
                                &Message::FileReject {
                                    transfer_id,
                                    reason: "sender cancelled".into(),
                                },
                            )?;
                        }
                        InputAction::Continue => {}
                        InputAction::Quit => {
                            quit = true;
                            break;
                        }
                    }
                }
                Ok(None) | Err(TryRecvError::Disconnected) => {
                    quit = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        if quit {
            break;
        }

        match stream.read(&mut buffer) {
            Ok(0) => {
                eprintln!("server closed the connection");
                break;
            }
            Ok(length) => {
                for message in decoder.push(&buffer[..length])? {
                    match message {
                        Message::IncomingFileOffer {
                            sender,
                            transfer_id,
                            file_name,
                            size,
                            digest,
                        } => {
                            println!(
                                "\n{sender} offers {file_name} ({size} bytes), transfer id {transfer_id}."
                            );
                            println!(
                                "Use /accept {transfer_id} <output-path> or /reject {transfer_id}."
                            );
                            incoming_offers.insert(transfer_id, digest);
                        }
                        Message::FilePeer {
                            transfer_id,
                            peer_address,
                        } => {
                            let Some(path) = pending_sends.remove(&transfer_id) else {
                                eprintln!("server accepted unknown file offer {transfer_id}");
                                continue;
                            };
                            let peer: SocketAddr = match peer_address.parse() {
                                Ok(peer) => peer,
                                Err(error) => {
                                    clear_active_transfer(&active_transfer, transfer_id)?;
                                    eprintln!("invalid peer UDP address: {error}");
                                    continue;
                                }
                            };
                            let send_socket = udp.try_clone()?;
                            if let Err(error) = spawn_send(
                                send_socket,
                                peer,
                                transfer_id,
                                path,
                                Arc::clone(&active_transfer),
                                transfer_sender.clone(),
                            ) {
                                clear_active_transfer(&active_transfer, transfer_id)?;
                                return Err(error);
                            }
                        }
                        Message::FileReject {
                            transfer_id,
                            reason,
                        } => {
                            pending_sends.remove(&transfer_id);
                            incoming_offers.remove(&transfer_id);
                            clear_active_transfer(&active_transfer, transfer_id)?;
                            eprintln!("\nfile transfer {transfer_id} rejected: {reason}");
                        }
                        Message::UdpRegistered { port } => {
                            println!("\nUDP endpoint registered on local port {port}");
                        }
                        other => display_message(other),
                    }
                }
            }
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }

    fn reserve_active_transfer(active: &Mutex<Option<u64>>, transfer_id: u64) -> io::Result<()> {
        let mut active = active
            .lock()
            .map_err(|_| io::Error::other("transfer state lock was poisoned"))?;
        if active.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another file transfer is active",
            ));
        }
        *active = Some(transfer_id);
        Ok(())
    }

    fn clear_active_transfer(active: &Mutex<Option<u64>>, transfer_id: u64) -> io::Result<()> {
        let mut active = active
            .lock()
            .map_err(|_| io::Error::other("transfer state lock was poisoned"))?;
        if *active == Some(transfer_id) {
            *active = None;
        }
        Ok(())
    }

    fn spawn_send(
        socket: UdpSocket,
        peer: SocketAddr,
        transfer_id: u64,
        path: PathBuf,
        active: Arc<Mutex<Option<u64>>>,
        results: Sender<TransferResult>,
    ) -> io::Result<()> {
        thread::Builder::new()
            .name(format!("file-send-{transfer_id}"))
            .spawn(move || {
                let result = crate::reliable_udp::send_file_with_id(
                    &socket,
                    peer,
                    &path,
                    transfer_id,
                    crate::reliable_udp::TransferConfig::default(),
                );
                if let Err(error) = clear_active_transfer(&active, transfer_id) {
                    eprintln!("could not clear completed transfer state: {error}");
                }
                if results
                    .send(TransferResult {
                        transfer_id,
                        label: format!("send {}", path.display()),
                        result,
                    })
                    .is_err()
                {
                    eprintln!("could not report completion of file send {transfer_id}");
                }
            })?;
        Ok(())
    }

    fn spawn_receive(
        socket: UdpSocket,
        transfer_id: u64,
        output: PathBuf,
        digest: [u8; 32],
        active: Arc<Mutex<Option<u64>>>,
        results: Sender<TransferResult>,
    ) -> io::Result<()> {
        thread::Builder::new()
            .name(format!("file-receive-{transfer_id}"))
            .spawn(move || {
                let result = crate::reliable_udp::receive_file_expected(
                    &socket,
                    &output,
                    Some(digest),
                    crate::reliable_udp::TransferConfig::default(),
                );
                if let Err(error) = clear_active_transfer(&active, transfer_id) {
                    eprintln!("could not clear completed transfer state: {error}");
                }
                if results
                    .send(TransferResult {
                        transfer_id,
                        label: format!("receive {}", output.display()),
                        result,
                    })
                    .is_err()
                {
                    eprintln!("could not report completion of file receive {transfer_id}");
                }
            })?;
        Ok(())
    }

    stream.send_close_notify()?;
    if let Err(error) = control.shutdown(Shutdown::Both) {
        eprintln!("could not close the server connection cleanly: {error}");
    }
    Ok(())
}

fn spawn_input_reader(sender: SyncSender<Option<String>>) -> io::Result<()> {
    thread::Builder::new()
        .name("stdin-reader".into())
        .spawn(move || {
            print!("> ");
            if let Err(error) = io::stdout().flush() {
                eprintln!("could not flush CLI prompt: {error}");
                return;
            }
            for line in io::stdin().lock().lines() {
                match line {
                    Ok(line) => {
                        let quitting = line == "/quit";
                        if sender.send(Some(line)).is_err() {
                            return;
                        }
                        if quitting {
                            break;
                        }
                        print!("> ");
                        if let Err(error) = io::stdout().flush() {
                            eprintln!("could not flush CLI prompt: {error}");
                            return;
                        }
                    }
                    Err(error) => {
                        eprintln!("could not read CLI input: {error}");
                        break;
                    }
                }
            }
            let _ = sender.send(None);
        })?;
    Ok(())
}

fn parse_input(line: &str) -> io::Result<InputAction> {
    if line == "/quit" {
        return Ok(InputAction::Quit);
    }
    if line == "/help" {
        println!(
            "Commands: /msg <username> <message>, /send <username> <file-path>, \
             /accept <transfer-id> <output-path>, /reject <transfer-id>, \
             /cancel <transfer-id>, /quit, /help"
        );
        return Ok(InputAction::Continue);
    }
    if let Some(rest) = line.strip_prefix("/send ") {
        let Some((recipient, path)) = rest.split_once(' ') else {
            eprintln!("usage: /send <username> <file-path>");
            return Ok(InputAction::Continue);
        };
        validate_username(recipient)?;
        if path.is_empty() {
            eprintln!("file path cannot be empty");
            return Ok(InputAction::Continue);
        }
        return Ok(InputAction::SendFile {
            recipient: recipient.to_owned(),
            path: PathBuf::from(path),
        });
    }
    if let Some(rest) = line.strip_prefix("/accept ") {
        let Some((id, path)) = rest.split_once(' ') else {
            eprintln!("usage: /accept <transfer-id> <output-path>");
            return Ok(InputAction::Continue);
        };
        let transfer_id = match id.parse() {
            Ok(id) => id,
            Err(error) => {
                eprintln!("invalid transfer ID: {error}");
                return Ok(InputAction::Continue);
            }
        };
        if path.is_empty() {
            eprintln!("output path cannot be empty");
            return Ok(InputAction::Continue);
        }
        return Ok(InputAction::AcceptFile {
            transfer_id,
            output: PathBuf::from(path),
        });
    }
    if let Some(id) = line.strip_prefix("/reject ") {
        let transfer_id = match id.parse() {
            Ok(id) => id,
            Err(error) => {
                eprintln!("invalid transfer ID: {error}");
                return Ok(InputAction::Continue);
            }
        };
        return Ok(InputAction::RejectFile { transfer_id });
    }
    if let Some(id) = line.strip_prefix("/cancel ") {
        let transfer_id = match id.parse() {
            Ok(id) => id,
            Err(error) => {
                eprintln!("invalid transfer ID: {error}");
                return Ok(InputAction::Continue);
            }
        };
        return Ok(InputAction::CancelFile { transfer_id });
    }
    if let Some(direct) = line.strip_prefix("/msg ") {
        let Some((recipient, message)) = direct.split_once(' ') else {
            eprintln!("usage: /msg <username> <message>");
            return Ok(InputAction::Continue);
        };
        validate_username(recipient)?;
        if message.is_empty() {
            eprintln!("message cannot be empty");
            return Ok(InputAction::Continue);
        }
        return Ok(InputAction::Send(Message::Direct {
            recipient: recipient.to_owned(),
            message: message.to_owned(),
        }));
    }
    if line.is_empty() {
        return Ok(InputAction::Continue);
    }
    if line.len() > MAX_FRAME_BYTES - 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message is too long",
        ));
    }
    Ok(InputAction::Send(Message::Broadcast {
        message: line.to_owned(),
    }))
}

fn display_message(message: Message) {
    match message {
        Message::Chat { sender, message } => println!("\n{sender}: {message}"),
        Message::Users { usernames } => println!("\nOnline: {}", usernames.join(", ")),
        Message::Presence { username, online } => {
            let state = if online { "online" } else { "offline" };
            println!("\n{username} is {state}");
        }
        Message::Error { message } => eprintln!("\n[server] {message}"),
        Message::UdpRegistered { .. } => {}
        other => eprintln!("\n[protocol] unexpected server message: {other:?}"),
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_input, InputAction};
    use std::path::Path;

    #[test]
    fn file_commands_preserve_paths_with_spaces() {
        assert!(matches!(
            parse_input(r"/send bob C:\lab files\sample.bin").unwrap(),
            InputAction::SendFile { recipient, path }
                if recipient == "bob" && path.as_path() == Path::new(r"C:\lab files\sample.bin")
        ));
        assert!(matches!(
            parse_input(r"/accept 42 C:\lab files\received.bin").unwrap(),
            InputAction::AcceptFile { transfer_id: 42, output }
                if output.as_path() == Path::new(r"C:\lab files\received.bin")
        ));
        assert!(matches!(
            parse_input("/cancel 42").unwrap(),
            InputAction::CancelFile { transfer_id: 42 }
        ));
    }
}
