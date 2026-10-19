use std::path::Path;
use std::{env, io, net::SocketAddr, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("server") => {
            let address = parse_address(args.next(), "127.0.0.1:9000")?;
            if args.next().is_some() {
                return Err(invalid_arguments());
            }
            rust_collab::server::run(address)
        }
        Some("server-tls") => {
            let address = parse_address(args.next(), "")?;
            let certificate = args.next().ok_or_else(invalid_arguments)?;
            let private_key = args.next().ok_or_else(invalid_arguments)?;
            if args.next().is_some() {
                return Err(invalid_arguments());
            }
            let config = rust_collab::server::load_tls_config(
                Path::new(&certificate),
                Path::new(&private_key),
            )?;
            rust_collab::server::run_tls(address, config)
        }
        Some("client") => {
            let address = parse_address(args.next(), "")?;
            let username = args.next().ok_or_else(invalid_arguments)?;
            if args.next().is_some() {
                return Err(invalid_arguments());
            }
            rust_collab::client::run(address, &username)
        }
        Some("client-tls") => {
            let address = parse_address(args.next(), "")?;
            let username = args.next().ok_or_else(invalid_arguments)?;
            let server_name = args.next().ok_or_else(invalid_arguments)?;
            let ca_file = args.next().ok_or_else(invalid_arguments)?;
            if args.next().is_some() {
                return Err(invalid_arguments());
            }
            let config = rust_collab::client::load_tls_config(Path::new(&ca_file))?;
            rust_collab::client::run_tls(address, &username, &server_name, config)
        }
        Some("udp-recv") => {
            let address = parse_address(args.next(), "")?;
            let output = args.next().ok_or_else(invalid_arguments)?;
            if args.next().is_some() {
                return Err(invalid_arguments());
            }
            let socket = std::net::UdpSocket::bind(address)?;
            println!(
                "Waiting for one UDP file transfer on {} -> {}",
                socket.local_addr()?,
                output
            );
            let stats = rust_collab::reliable_udp::receive_file(
                &socket,
                Path::new(&output),
                rust_collab::reliable_udp::TransferConfig::default(),
            )?;
            println!(
                "Received {} bytes in {:.2?} ({} retransmissions)",
                stats.bytes, stats.elapsed, stats.retransmissions
            );
            Ok(())
        }
        Some("udp-send") => {
            let address = parse_address(args.next(), "")?;
            let source = args.next().ok_or_else(invalid_arguments)?;
            if args.next().is_some() {
                return Err(invalid_arguments());
            }
            let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let stats = rust_collab::reliable_udp::send_file(
                &socket,
                address,
                Path::new(&source),
                rust_collab::reliable_udp::TransferConfig::default(),
            )?;
            println!(
                "Sent {} bytes in {:.2?} ({} retransmissions)",
                stats.bytes, stats.elapsed, stats.retransmissions
            );
            Ok(())
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(_) => Err(invalid_arguments()),
    }
}

fn parse_address(value: Option<String>, default: &str) -> io::Result<SocketAddr> {
    let value = value.unwrap_or_else(|| default.to_owned());
    value.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid socket address '{value}': {error}"),
        )
    })
}

fn invalid_arguments() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid command arguments; run 'rust-collab help'",
    )
}

fn print_usage() {
    println!("Rust Collaboration Network");
    println!("Usage:");
    println!("  rust-collab server [bind-address]");
    println!("  rust-collab server-tls <bind-address> <certificate.pem> <private-key.pem>");
    println!("  rust-collab client <server-address> <username>");
    println!("  rust-collab client-tls <server-address> <username> <server-name> <trusted-ca.pem>");
    println!("  rust-collab udp-recv <bind-address> <output-file>");
    println!("  rust-collab udp-send <receiver-address> <input-file>");
    println!();
    println!("The server binds to 127.0.0.1:9000 by default.");
}
