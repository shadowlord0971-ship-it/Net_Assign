# Rust Collaboration Network

A personal network-systems project: a small multi-client chat service plus a
reliable-UDP file-transfer experiment. The application is intended to become a
real workload for the Assignment 2 network lab.

## Implemented

- Raw TCP chat with length-prefixed binary framing, username registration,
  online-user updates, broadcast, and direct messages.
- Optional TLS 1.3-protected chat transport using Rustls. The client validates
  the server against an explicitly supplied CA certificate.
- Bounded server resources: 64 simultaneous TCP sessions and a 128-message
  outbound queue per client. A client whose queue fills is disconnected rather
  than allowing unbounded memory growth.
- Peer-to-peer UDP file transfer integrated with chat offers/acceptance, using a fixed-size selective-repeat
  window, sequence numbers, per-chunk ACKs, retransmission limits, a final
  completion handshake, SHA-256 file verification, and a 1 GiB size cap.
- Automated tests for the binary codec, multiple TCP clients, TLS chat,
  zero-byte files, and UDP recovery when a test proxy drops a data packet, an
  ACK, and a completion response.

## Known limits — read before using

- Usernames are **nicknames, not authenticated accounts**. TLS verifies and
  encrypts the chat connection, but does not prove the user's identity.
- Chat carries file offers and acceptance/rejection; file contents then travel
  directly between peers over UDP, not through the server. Peers need direct
  UDP reachability. It does not encrypt or authenticate UDP packets, provide
  NAT traversal, resume interrupted transfers, or implement congestion control.
- SHA-256 detects accidental or adversarial content changes only when the
  expected digest itself is trusted; it does not authenticate the sender.
- The raw `server` command is plaintext and binds to loopback by default.
  Restrict it to local experiments. For a trusted LAN demo, use `server-tls`
  for chat. Do not send sensitive files over the custom UDP mode.
- No EVPN/VXLAN lab integration or QUIC comparison has been run yet. The
  current tests run locally; they do not establish a throughput or latency
  claim for other machines or networks.

This is a learning prototype, not production messaging software and not an
implementation of QUIC or HTTP/3.

## TCP protocol draft

Every TCP frame begins with a four-byte unsigned big-endian payload length,
followed by a payload no larger than 64 KiB. The payload starts with a
one-byte message type. Strings are UTF-8 and encoded as a two-byte unsigned
big-endian byte length followed by the bytes.

| Type | Name | Fields |
| --- | --- | --- |
| 1 | `Hello` | username |
| 2 | `Welcome` | username |
| 3 | `Broadcast` | message |
| 4 | `Direct` | recipient, message |
| 5 | `Chat` | sender, message |
| 6 | `Users` | 2-byte count, then usernames |
| 7 | `Presence` | username, online byte (`0` or `1`) |
| 8 | `Error` | message |
| 9 | `UdpRegister` | peer UDP port |
| 10 | `FileOffer` | recipient, transfer ID, file name, size, SHA-256 digest |
| 11 | `IncomingFileOffer` | sender and offered file metadata |
| 12 | `FileAccept` | transfer ID |
| 13 | `FilePeer` | transfer ID, accepted peer UDP address |
| 14 | `FileReject` | transfer ID, reason |
| 15 | `UdpRegistered` | registered peer UDP port |

Unknown message types, invalid UTF-8, truncated fields, invalid presence values,
trailing bytes, and oversized frames are rejected. The format is an evolving
learning protocol, not a public or security-reviewed standard.

## Build on this Windows machine

Rust stable and the GNU Windows target are installed. The MSYS2 UCRT64 linker
is required by this setup. From PowerShell, in this project directory:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;C:\msys64\ucrt64\bin;$env:Path"
cargo +stable-x86_64-pc-windows-gnu fmt -- --check
cargo +stable-x86_64-pc-windows-gnu test
cargo +stable-x86_64-pc-windows-gnu run -- help
```

On a machine with the standard Rust MSVC build tools installed, plain
`cargo fmt`, `cargo test`, and `cargo run` are sufficient.

## Run TCP chat locally

Start a server:

```powershell
cargo +stable-x86_64-pc-windows-gnu run -- server
```

In another terminal:

```powershell
cargo +stable-x86_64-pc-windows-gnu run -- client 127.0.0.1:9000 alice
```

Run another client with a different username. Regular lines are broadcast;
`/msg <username> <message>` sends a direct message, `/help` shows commands,
and `/quit` disconnects.

## Run chat with TLS on a trusted LAN

Create a test CA and a server certificate with OpenSSL. Keep private keys out
of the repository and share only the CA certificate with clients:

```powershell
openssl req -x509 -newkey rsa:3072 -nodes -keyout ca-key.pem -out ca-cert.pem -days 3650 -subj "/CN=RustCollab Test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -nodes -keyout server-key.pem -out server.csr -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "extendedKeyUsage=serverAuth"
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365 -copy_extensions copy
```

Start the TLS server bound to the lab/LAN interface:

```powershell
cargo +stable-x86_64-pc-windows-gnu run -- server-tls 0.0.0.0:9000 server-cert.pem server-key.pem
```

Connect using the server's reachable IP, while verifying its certificate name:

```powershell
cargo +stable-x86_64-pc-windows-gnu run -- client-tls 192.168.1.20:9000 alice localhost ca-cert.pem
```

Replace `192.168.1.20` with the server's actual lab/LAN IP. Permit TCP port 9000
only on the trusted lab network. A certificate containing only `localhost`
will not validate for a different DNS name or IP; issue a certificate with the
actual server name in its subject alternative name.

## Send a file through chat

Start a chat server and connect two clients as described above. The sender
offers a file by username:

```powershell
/send bob C:\lab\sample.bin
```

The recipient sees the file name, size, and transfer ID and can accept or
decline:

```powershell
/accept <transfer-id> C:\lab\received.bin
/reject <transfer-id>
```

The sender can cancel an offer that is still awaiting acceptance:

```powershell
/cancel <transfer-id>
```

The client automatically binds an ephemeral UDP port and registers it with the
chat server. Once the recipient accepts, file data travels directly between
the peers; the server relays only control messages. Both peers need direct UDP
reachability and suitable host-firewall rules. The receiver refuses to
overwrite an existing output and writes to a temporary `.part` file until the
received content passes the digest check. The deterministic fault test drops
data, ACK, and completion packets to exercise retransmission locally.

## Reproducible Assignment 2 integration experiment

The software can serve as a workload for the network lab, but that integration
has not yet been executed. Once the lab is available:

1. Place a chat server and at least two clients in different routed subnets.
2. Use `server-tls`; confirm normal TCP chat, then capture traffic and verify
   chat payloads are encrypted.
3. Offer and accept a file between chat clients in different routed subnets;
   compare input and output files with a SHA-256 tool.
4. Add an ACL or interrupt a route/link, record chat disconnect/recovery and
   UDP retry/failure behavior, then restore the network and rerun the same
   test.
5. Record topology, commands, packet captures, output hashes, elapsed time,
   retransmission count, and all limitations. Do not report lab results until
   you actually run them.

## Steps and status

- **S0 — Done:** protocol framing, bounds, codec, and malformed-input tests.
- **S1 — Done:** TCP CLI chat, multi-client presence, broadcast/direct
  messages, bounded client count and outbound queues.
- **S2 — Implemented:** reliable UDP file transfer, loss-recovery tests, and
  chat offer/accept/reject control flow for direct peer-to-peer transfers.
- **S3 — Partial:** optional TLS for chat and basic resource limits. Account
  authentication is not implemented, and UDP remains unauthenticated.
- **S4 — Baseline done:** local deterministic fault test and transfer
  measurements (elapsed time and retransmission count). Automated local
  end-to-end offer/accept/file-integrity test; no broad performance benchmark
  or multi-host measurement yet.
- **S5 — Not run:** Assignment 2 network-lab integration requires a topology
  and endpoints that are not currently running.
- **S6 — Not implemented:** a standards-based QUIC comparison is future work.

Do not treat the custom UDP transport as a production replacement for QUIC.
It intentionally omits congestion control, peer authentication, encryption,
NAT traversal, and interoperability.
