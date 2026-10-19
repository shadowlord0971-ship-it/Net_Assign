use crate::protocol::{read_frame, validate_username, write_frame, FrameDecoder, Message};
use crate::reliable_udp::MAX_FILE_BYTES;
use rustls::{pki_types::PrivateKeyDer, ServerConfig, ServerConnection, StreamOwned};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TryRecvError, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const MAX_CLIENTS: usize = 64;
const OUTBOUND_QUEUE_SIZE: usize = 128;
const READ_POLL: Duration = Duration::from_millis(50);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);

trait ServerStream: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn send_close_notify(&mut self) -> io::Result<()>;
}

impl ServerStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn send_close_notify(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ServerStream for StreamOwned<ServerConnection, TcpStream> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    fn send_close_notify(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()
    }
}

#[derive(Default)]
struct ServerState {
    clients: Mutex<HashMap<String, Arc<ClientWriter>>>,
    transfers: Mutex<HashMap<u64, TransferRoute>>,
}

struct ClientWriter {
    sender: SyncSender<Message>,
    stopped: Arc<AtomicBool>,
    socket: TcpStream,
    peer_ip: IpAddr,
    udp_address: Mutex<Option<SocketAddr>>,
}

#[derive(Clone)]
struct TransferRoute {
    sender: String,
    recipient: String,
}

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn run(address: SocketAddr) -> io::Result<()> {
    run_with_config(address, None)
}

pub fn run_tls(address: SocketAddr, config: Arc<ServerConfig>) -> io::Result<()> {
    run_with_config(address, Some(config))
}

pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> io::Result<Arc<ServerConfig>> {
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS certificate file contains no certificates",
        ));
    }

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS private key file contains no supported private key",
            )
        })?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(Arc::new(config))
}

fn run_with_config(address: SocketAddr, tls_config: Option<Arc<ServerConfig>>) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    println!(
        "{} server listening on {}",
        if tls_config.is_some() { "TLS" } else { "TCP" },
        listener.local_addr()?
    );
    let state = Arc::new(ServerState::default());
    let active = Arc::new(AtomicUsize::new(0));

    for incoming in listener.incoming() {
        let mut socket = incoming?;
        let peer = socket.peer_addr()?;
        socket.set_read_timeout(Some(LOGIN_TIMEOUT))?;
        if reserve_slot(&active).is_err() {
            eprintln!("rejecting connection: server client limit reached");
            let _ = socket.shutdown(Shutdown::Both);
            continue;
        }
        let state = Arc::clone(&state);
        let active_for_thread = Arc::clone(&active);
        let tls_config = tls_config.clone();
        let spawn_result = thread::Builder::new()
            .name(format!("client-{peer}"))
            .spawn(move || {
                let _active_connection = ActiveConnection(active_for_thread);
                let result = match tls_config {
                    Some(config) => handle_tls_connection(socket, config, state),
                    None => {
                        let writer_socket = socket.try_clone();
                        match writer_socket {
                            Ok(writer_socket) => {
                                handle_connection(&mut socket, writer_socket, state)
                            }
                            Err(error) => Err(error),
                        }
                    }
                };
                if let Err(error) = result {
                    eprintln!("connection from {peer} ended with error: {error}");
                }
            });
        if let Err(error) = spawn_result {
            active.fetch_sub(1, Ordering::Relaxed);
            return Err(error);
        }
    }
    Ok(())
}

fn handle_tls_connection(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    state: Arc<ServerState>,
) -> io::Result<()> {
    let transport = socket.try_clone()?;
    let connection =
        ServerConnection::new(config).map_err(|error| io::Error::other(error.to_string()))?;
    let mut stream = StreamOwned::new(connection, transport);
    handle_connection(&mut stream, socket, state)
}

fn reserve_slot(active: &AtomicUsize) -> io::Result<()> {
    let mut current = active.load(Ordering::Relaxed);
    loop {
        if current >= MAX_CLIENTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "server client limit reached",
            ));
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => current = actual,
        }
    }
}

fn handle_connection<S: ServerStream>(
    stream: &mut S,
    socket: TcpStream,
    state: Arc<ServerState>,
) -> io::Result<()> {
    let Some(Message::Hello { username }) = read_frame(stream)? else {
        write_frame(
            stream,
            &Message::Error {
                message: "first message must be Hello".into(),
            },
        )?;
        return Ok(());
    };

    if let Err(error) = validate_username(&username) {
        write_frame(
            stream,
            &Message::Error {
                message: error.to_string(),
            },
        )?;
        return Ok(());
    }

    let (sender, receiver) = mpsc::sync_channel(OUTBOUND_QUEUE_SIZE);
    let peer_ip = socket.peer_addr()?.ip();
    let client = Arc::new(ClientWriter {
        sender,
        stopped: Arc::new(AtomicBool::new(false)),
        socket: socket.try_clone()?,
        peer_ip,
        udp_address: Mutex::new(None),
    });
    {
        let mut clients = state
            .clients
            .lock()
            .map_err(|_| io::Error::other("client registry lock was poisoned"))?;
        if clients.contains_key(&username) {
            write_frame(
                stream,
                &Message::Error {
                    message: "username is already online".into(),
                },
            )?;
            return Ok(());
        }

        let usernames = clients.keys().cloned().collect();
        write_frame(
            stream,
            &Message::Welcome {
                username: username.clone(),
            },
        )?;
        write_frame(stream, &Message::Users { usernames })?;
        clients.insert(username.clone(), Arc::clone(&client));
    }

    stream.set_read_timeout(Some(READ_POLL))?;
    println!("{username} connected from {}", socket.peer_addr()?);
    notify_presence(&state, &username, true);

    let session_result = serve_messages(stream, &username, &client, receiver, &state);
    let close_result = stream.send_close_notify();
    let cleanup_result = disconnect(&state, &username);
    match (session_result, close_result, cleanup_result) {
        (Err(session_error), Err(close_error), Err(cleanup_error)) => Err(io::Error::new(
            session_error.kind(),
            format!(
                "{session_error}; TLS close also failed: {close_error}; disconnect cleanup also failed: {cleanup_error}"
            ),
        )),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(error),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

fn serve_messages<S: Read + Write>(
    stream: &mut S,
    username: &str,
    client: &ClientWriter,
    receiver: mpsc::Receiver<Message>,
    state: &ServerState,
) -> io::Result<()> {
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0_u8; 8192];
    loop {
        if client.stopped.load(Ordering::Relaxed) {
            return Ok(());
        }
        loop {
            match receiver.try_recv() {
                Ok(message) => write_frame(stream, &message)?,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(length) => {
                for message in decoder.push(&buffer[..length])? {
                    handle_client_message(state, username, client, message);
                }
            }
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
}

fn handle_client_message(
    state: &ServerState,
    username: &str,
    client: &ClientWriter,
    message: Message,
) {
    match message {
        Message::Broadcast { message } => {
            send_to_all(
                state,
                &Message::Chat {
                    sender: username.to_owned(),
                    message,
                },
            );
        }
        Message::Direct { recipient, message } => {
            let recipient_writer = state
                .clients
                .lock()
                .map_err(|_| io::Error::other("client registry lock was poisoned"))
                .map(|clients| clients.get(&recipient).cloned());
            match recipient_writer {
                Ok(Some(writer)) => send_to(
                    &recipient,
                    &writer,
                    &Message::Chat {
                        sender: username.to_owned(),
                        message,
                    },
                ),
                Ok(None) => send_to_user(
                    state,
                    username,
                    &Message::Error {
                        message: format!("user '{recipient}' is not online"),
                    },
                ),
                Err(error) => eprintln!("could not route direct message: {error}"),
            }
        }
        Message::UdpRegister { port } => {
            if port == 0 {
                send_to_user(
                    state,
                    username,
                    &Message::Error {
                        message: "UDP port cannot be zero".into(),
                    },
                );
                return;
            }
            match client.udp_address.lock() {
                Ok(mut address) => {
                    *address = Some(SocketAddr::new(client.peer_ip, port));
                    send_to_user(state, username, &Message::UdpRegistered { port });
                }
                Err(_) => {
                    eprintln!("could not register UDP endpoint for {username}: lock poisoned")
                }
            }
        }
        Message::FileOffer {
            recipient,
            transfer_id,
            file_name,
            size,
            digest,
        } => {
            if transfer_id == 0
                || size > MAX_FILE_BYTES
                || file_name.is_empty()
                || file_name.len() > 255
                || file_name
                    .chars()
                    .any(|character| matches!(character, '/' | '\\' | '\0'))
            {
                reject_file_offer(state, username, transfer_id, "invalid file offer metadata");
                return;
            }
            let recipient_client = match state.clients.lock() {
                Ok(clients) => clients.get(&recipient).cloned(),
                Err(_) => {
                    eprintln!("could not look up file recipient: registry lock poisoned");
                    return;
                }
            };
            let Some(recipient_client) = recipient_client else {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    &format!("user '{recipient}' is not online"),
                );
                return;
            };
            let sender_registered = match client.udp_address.lock() {
                Ok(address) => address.is_some(),
                Err(_) => {
                    eprintln!("could not check UDP endpoint for {username}: lock poisoned");
                    reject_file_offer(state, username, transfer_id, "could not read UDP endpoint");
                    return;
                }
            };
            let recipient_registered = match recipient_client.udp_address.lock() {
                Ok(address) => address.is_some(),
                Err(_) => {
                    eprintln!("could not check UDP endpoint for {recipient}: lock poisoned");
                    reject_file_offer(
                        state,
                        username,
                        transfer_id,
                        "could not read recipient UDP endpoint",
                    );
                    return;
                }
            };
            if !sender_registered || !recipient_registered {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "both users must have registered UDP endpoints",
                );
                return;
            }
            let mut transfers = match state.transfers.lock() {
                Ok(transfers) => transfers,
                Err(_) => {
                    eprintln!("could not register file transfer: transfer lock poisoned");
                    reject_file_offer(
                        state,
                        username,
                        transfer_id,
                        "server transfer registry unavailable",
                    );
                    return;
                }
            };
            if transfers.contains_key(&transfer_id) {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "file transfer ID is already in use",
                );
                return;
            }
            if transfers.values().any(|route| route.sender == username) {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "sender already has a pending file offer",
                );
                return;
            }
            transfers.insert(
                transfer_id,
                TransferRoute {
                    sender: username.to_owned(),
                    recipient: recipient.clone(),
                },
            );
            drop(transfers);
            send_to(
                &recipient,
                &recipient_client,
                &Message::IncomingFileOffer {
                    sender: username.to_owned(),
                    transfer_id,
                    file_name,
                    size,
                    digest,
                },
            );
        }
        Message::FileAccept { transfer_id } => {
            let route = match state.transfers.lock() {
                Ok(transfers) => match transfers.get(&transfer_id) {
                    Some(route) if route.recipient == username => Some(route.clone()),
                    _ => None,
                },
                Err(_) => {
                    eprintln!("could not accept file transfer: transfer lock poisoned");
                    reject_file_offer(
                        state,
                        username,
                        transfer_id,
                        "server transfer registry unavailable",
                    );
                    return;
                }
            };
            let Some(route) = route else {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "file offer is missing or no longer available",
                );
                return;
            };
            let peer_address = match client.udp_address.lock() {
                Ok(address) => *address,
                Err(_) => {
                    eprintln!("could not read UDP endpoint for {username}: lock poisoned");
                    reject_file_offer(state, username, transfer_id, "could not read UDP endpoint");
                    return;
                }
            };
            let Some(peer_address) = peer_address else {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "register a UDP endpoint before accepting files",
                );
                return;
            };
            let sender = match state.clients.lock() {
                Ok(clients) => clients.get(&route.sender).cloned(),
                Err(_) => {
                    eprintln!("could not look up file sender: client registry lock poisoned");
                    reject_file_offer(state, username, transfer_id, "file sender is unavailable");
                    return;
                }
            };
            let removed = match state.transfers.lock() {
                Ok(mut transfers) => transfers.remove(&transfer_id).is_some(),
                Err(_) => {
                    eprintln!("could not complete file offer: transfer lock poisoned");
                    reject_file_offer(
                        state,
                        username,
                        transfer_id,
                        "server transfer registry unavailable",
                    );
                    return;
                }
            };
            if !removed {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "file offer is no longer available",
                );
                return;
            }
            if let Some(sender) = sender {
                send_to(
                    &route.sender,
                    &sender,
                    &Message::FilePeer {
                        transfer_id,
                        peer_address: peer_address.to_string(),
                    },
                );
            } else {
                reject_file_offer(state, username, transfer_id, "file sender disconnected");
            }
        }
        Message::FileReject {
            transfer_id,
            reason,
        } => {
            let route = match state.transfers.lock() {
                Ok(mut transfers) => match transfers.get(&transfer_id) {
                    Some(route) if route.recipient == username || route.sender == username => {
                        transfers.remove(&transfer_id)
                    }
                    _ => None,
                },
                Err(_) => {
                    eprintln!("could not reject file transfer: transfer lock poisoned");
                    return;
                }
            };
            if let Some(route) = route {
                let peer = if route.sender == username {
                    route.recipient
                } else {
                    route.sender
                };
                send_to_user(
                    state,
                    &peer,
                    &Message::FileReject {
                        transfer_id,
                        reason,
                    },
                );
            } else {
                reject_file_offer(
                    state,
                    username,
                    transfer_id,
                    "file offer is missing or no longer available",
                );
            }
        }
        _ => send_to_user(
            state,
            username,
            &Message::Error {
                message: "message type is not valid from a client".into(),
            },
        ),
    }
}

fn reject_file_offer(state: &ServerState, username: &str, transfer_id: u64, reason: &str) {
    send_to_user(
        state,
        username,
        &Message::FileReject {
            transfer_id,
            reason: reason.to_owned(),
        },
    );
}

fn disconnect(state: &ServerState, username: &str) -> io::Result<()> {
    let removed = state
        .clients
        .lock()
        .map_err(|_| io::Error::other("client registry lock was poisoned"))?
        .remove(username);
    if let Some(client) = removed {
        client.stopped.store(true, Ordering::Relaxed);
        println!("{username} disconnected");
        notify_presence(state, username, false);
    }
    let abandoned = {
        let mut transfers = state
            .transfers
            .lock()
            .map_err(|_| io::Error::other("transfer registry lock was poisoned"))?;
        let abandoned = transfers
            .iter()
            .filter(|(_, route)| route.sender == username || route.recipient == username)
            .map(|(id, route)| (*id, route.clone()))
            .collect::<Vec<_>>();
        for (id, _) in &abandoned {
            transfers.remove(id);
        }
        abandoned
    };
    for (transfer_id, route) in abandoned {
        let peer = if route.sender == username {
            route.recipient
        } else {
            route.sender
        };
        send_to_user(
            state,
            &peer,
            &Message::FileReject {
                transfer_id,
                reason: "peer disconnected".into(),
            },
        );
    }
    Ok(())
}

fn notify_presence(state: &ServerState, username: &str, online: bool) {
    let snapshot = match snapshot(state) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("could not notify presence change for {username}: {error}");
            return;
        }
    };
    let usernames = snapshot
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for (name, writer) in snapshot {
        if name != username {
            send_to(
                &name,
                &writer,
                &Message::Presence {
                    username: username.to_owned(),
                    online,
                },
            );
            send_to(
                &name,
                &writer,
                &Message::Users {
                    usernames: usernames.clone(),
                },
            );
        }
    }
}

fn send_to_all(state: &ServerState, message: &Message) {
    match snapshot(state) {
        Ok(snapshot) => {
            for (username, writer) in snapshot {
                send_to(&username, &writer, message);
            }
        }
        Err(error) => eprintln!("could not broadcast message: {error}"),
    }
}

fn send_to_user(state: &ServerState, username: &str, message: &Message) {
    let writer = match state.clients.lock() {
        Ok(clients) => clients.get(username).cloned(),
        Err(_) => {
            eprintln!("could not send to {username}: client registry lock was poisoned");
            return;
        }
    };
    if let Some(writer) = writer {
        send_to(username, &writer, message);
    }
}

fn snapshot(state: &ServerState) -> io::Result<Vec<(String, Arc<ClientWriter>)>> {
    let clients = state
        .clients
        .lock()
        .map_err(|_| io::Error::other("client registry lock was poisoned"))?;
    Ok(clients
        .iter()
        .map(|(username, writer)| (username.clone(), Arc::clone(writer)))
        .collect())
}

fn send_to(username: &str, client: &ClientWriter, message: &Message) {
    match client.sender.try_send(message.clone()) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            eprintln!("disconnecting {username}: outbound queue is full");
            client.stopped.store(true, Ordering::Relaxed);
            if let Err(error) = client.socket.shutdown(Shutdown::Both) {
                eprintln!("could not close slow client {username}: {error}");
            }
        }
        Err(TrySendError::Disconnected(_)) => {
            eprintln!("could not send message to {username}: connection writer stopped");
        }
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
    use super::{handle_connection, handle_tls_connection, ServerState};
    use crate::protocol::{read_frame, write_frame, Message};
    use std::{
        fs,
        io::Write,
        net::{Shutdown, TcpListener, TcpStream, UdpSocket},
        path::PathBuf,
        sync::Arc,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    fn transfer_temp_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rust-collab-{label}-{unique}"))
    }

    fn spawn_test_server(listener: TcpListener, state: Arc<ServerState>, count: usize) {
        thread::spawn(move || {
            let mut handlers = Vec::new();
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let socket = stream.try_clone().unwrap();
                let state = Arc::clone(&state);
                handlers.push(thread::spawn(move || {
                    handle_connection(&mut stream, socket, state).unwrap()
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
    }

    fn login(stream: &mut TcpStream, username: &str) {
        write_frame(
            stream,
            &Message::Hello {
                username: username.into(),
            },
        )
        .unwrap();
        assert_eq!(
            read_frame(stream).unwrap(),
            Some(Message::Welcome {
                username: username.into()
            })
        );
        let _ = read_frame(stream).unwrap();
    }

    #[test]
    fn client_can_login_and_broadcast_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::default());
        spawn_test_server(listener, state, 1);

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        login(&mut client, "alice");
        write_frame(
            &mut client,
            &Message::Broadcast {
                message: "hello".into(),
            },
        )
        .unwrap();
        assert_eq!(
            read_frame(&mut client).unwrap(),
            Some(Message::Chat {
                sender: "alice".into(),
                message: "hello".into()
            })
        );
        client.shutdown(Shutdown::Both).unwrap();
    }

    #[test]
    fn two_clients_receive_presence_and_direct_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::default());
        spawn_test_server(listener, state, 2);

        let mut alice = TcpStream::connect(address).unwrap();
        alice
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        login(&mut alice, "alice");

        let mut bob = TcpStream::connect(address).unwrap();
        bob.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        login(&mut bob, "bob");
        assert_eq!(
            read_frame(&mut alice).unwrap(),
            Some(Message::Presence {
                username: "bob".into(),
                online: true
            })
        );
        assert!(matches!(
            read_frame(&mut alice).unwrap(),
            Some(Message::Users { usernames }) if usernames.len() == 2
        ));

        write_frame(
            &mut bob,
            &Message::Direct {
                recipient: "alice".into(),
                message: "private hello".into(),
            },
        )
        .unwrap();
        assert_eq!(
            read_frame(&mut alice).unwrap(),
            Some(Message::Chat {
                sender: "bob".into(),
                message: "private hello".into()
            })
        );

        alice.shutdown(Shutdown::Both).unwrap();
        bob.shutdown(Shutdown::Both).unwrap();
    }

    #[test]
    fn file_offer_requires_udp_registration_and_routes_acceptance() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::default());
        spawn_test_server(listener, state, 2);

        let mut alice = TcpStream::connect(address).unwrap();
        alice
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        login(&mut alice, "alice");
        let mut bob = TcpStream::connect(address).unwrap();
        bob.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        login(&mut bob, "bob");
        let _ = read_frame(&mut alice).unwrap();
        let _ = read_frame(&mut alice).unwrap();

        write_frame(&mut alice, &Message::UdpRegister { port: 51001 }).unwrap();
        assert_eq!(
            read_frame(&mut alice).unwrap(),
            Some(Message::UdpRegistered { port: 51001 })
        );
        write_frame(&mut bob, &Message::UdpRegister { port: 51002 }).unwrap();
        assert_eq!(
            read_frame(&mut bob).unwrap(),
            Some(Message::UdpRegistered { port: 51002 })
        );
        write_frame(
            &mut alice,
            &Message::FileOffer {
                recipient: "bob".into(),
                transfer_id: 77,
                file_name: "sample.bin".into(),
                size: 4096,
                digest: [7; 32],
            },
        )
        .unwrap();
        assert_eq!(
            read_frame(&mut bob).unwrap(),
            Some(Message::IncomingFileOffer {
                sender: "alice".into(),
                transfer_id: 77,
                file_name: "sample.bin".into(),
                size: 4096,
                digest: [7; 32],
            })
        );
        write_frame(&mut bob, &Message::FileAccept { transfer_id: 77 }).unwrap();
        assert_eq!(
            read_frame(&mut alice).unwrap(),
            Some(Message::FilePeer {
                transfer_id: 77,
                peer_address: "127.0.0.1:51002".into(),
            })
        );

        alice.shutdown(Shutdown::Both).unwrap();
        bob.shutdown(Shutdown::Both).unwrap();
    }

    #[test]
    fn chat_offer_acceptance_transfers_file_over_peer_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::default());
        spawn_test_server(listener, state, 2);

        let mut alice = TcpStream::connect(address).unwrap();
        alice
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        login(&mut alice, "alice");
        let mut bob = TcpStream::connect(address).unwrap();
        bob.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        login(&mut bob, "bob");
        let _ = read_frame(&mut alice).unwrap();
        let _ = read_frame(&mut alice).unwrap();

        let alice_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bob_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        for (stream, socket) in [(&mut alice, &alice_udp), (&mut bob, &bob_udp)] {
            write_frame(
                stream,
                &Message::UdpRegister {
                    port: socket.local_addr().unwrap().port(),
                },
            )
            .unwrap();
            assert!(matches!(
                read_frame(stream).unwrap(),
                Some(Message::UdpRegistered { .. })
            ));
        }

        let input_path = transfer_temp_path("chat-input");
        let output_path = transfer_temp_path("chat-output");
        let contents = (0..32_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&input_path, &contents).unwrap();
        let description = crate::reliable_udp::describe_file(&input_path).unwrap();
        let transfer_id = crate::reliable_udp::new_transfer_id();
        write_frame(
            &mut alice,
            &Message::FileOffer {
                recipient: "bob".into(),
                transfer_id,
                file_name: "sample.bin".into(),
                size: description.size,
                digest: description.digest,
            },
        )
        .unwrap();
        assert_eq!(
            read_frame(&mut bob).unwrap(),
            Some(Message::IncomingFileOffer {
                sender: "alice".into(),
                transfer_id,
                file_name: "sample.bin".into(),
                size: description.size,
                digest: description.digest,
            })
        );

        let receive_socket = bob_udp.try_clone().unwrap();
        let receive_path = output_path.clone();
        let receiver = thread::spawn(move || {
            crate::reliable_udp::receive_file_expected(
                &receive_socket,
                &receive_path,
                Some(description.digest),
                crate::reliable_udp::TransferConfig::default(),
            )
        });
        write_frame(&mut bob, &Message::FileAccept { transfer_id }).unwrap();
        let peer = match read_frame(&mut alice).unwrap().unwrap() {
            Message::FilePeer {
                transfer_id: accepted_id,
                peer_address,
            } => {
                assert_eq!(accepted_id, transfer_id);
                peer_address.parse().unwrap()
            }
            message => panic!("expected FilePeer, received {message:?}"),
        };
        crate::reliable_udp::send_file_with_id(
            &alice_udp,
            peer,
            &input_path,
            transfer_id,
            crate::reliable_udp::TransferConfig::default(),
        )
        .unwrap();
        receiver.join().unwrap().unwrap();
        assert_eq!(fs::read(&output_path).unwrap(), contents);

        fs::remove_file(input_path).unwrap();
        fs::remove_file(output_path).unwrap();
        alice.shutdown(Shutdown::Both).unwrap();
        bob.shutdown(Shutdown::Both).unwrap();
    }

    #[test]
    fn server_tls_configuration_requires_a_certificate_and_key() {
        assert!(super::load_tls_config(
            std::path::Path::new("missing-cert.pem"),
            std::path::Path::new("missing-key.pem")
        )
        .is_err());
    }

    #[test]
    fn tls_client_can_connect_and_chat() {
        use rcgen::{BasicConstraints, IsCa, KeyPair};
        use rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, ServerName},
            ClientConfig, ClientConnection, RootCertStore, ServerConfig, StreamOwned,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["test-ca".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let server_certificate = server_params
            .signed_by(&server_key, &ca_certificate, &ca_key)
            .unwrap();
        let server_certificate_der: CertificateDer<'static> = server_certificate.der().clone();
        let ca_certificate_der: CertificateDer<'static> = ca_certificate.der().clone();
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_certificate_der],
                    PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
                )
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(ca_certificate_der).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::default());
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            handle_tls_connection(socket, server_config, state).unwrap();
        });

        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let name = ServerName::try_from("localhost".to_owned()).unwrap();
        let connection = ClientConnection::new(client_config, name).unwrap();
        let mut tls = StreamOwned::new(connection, socket);
        write_frame(
            &mut tls,
            &Message::Hello {
                username: "secure-user".into(),
            },
        )
        .unwrap();
        assert!(matches!(
            read_frame(&mut tls).unwrap(),
            Some(Message::Welcome { username }) if username == "secure-user"
        ));
        let _ = read_frame(&mut tls).unwrap();
        write_frame(
            &mut tls,
            &Message::Broadcast {
                message: "encrypted chat".into(),
            },
        )
        .unwrap();
        assert_eq!(
            read_frame(&mut tls).unwrap(),
            Some(Message::Chat {
                sender: "secure-user".into(),
                message: "encrypted chat".into()
            })
        );
        tls.conn.send_close_notify();
        tls.flush().unwrap();
        drop(tls);
        server.join().unwrap();
    }
}
