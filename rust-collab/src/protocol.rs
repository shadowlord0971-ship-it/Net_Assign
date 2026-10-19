use std::io::{self, Read, Write};

pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello {
        username: String,
    },
    Welcome {
        username: String,
    },
    Broadcast {
        message: String,
    },
    Direct {
        recipient: String,
        message: String,
    },
    Chat {
        sender: String,
        message: String,
    },
    Users {
        usernames: Vec<String>,
    },
    Presence {
        username: String,
        online: bool,
    },
    Error {
        message: String,
    },
    UdpRegister {
        port: u16,
    },
    FileOffer {
        recipient: String,
        transfer_id: u64,
        file_name: String,
        size: u64,
        digest: [u8; 32],
    },
    IncomingFileOffer {
        sender: String,
        transfer_id: u64,
        file_name: String,
        size: u64,
        digest: [u8; 32],
    },
    FileAccept {
        transfer_id: u64,
    },
    FilePeer {
        transfer_id: u64,
        peer_address: String,
    },
    FileReject {
        transfer_id: u64,
        reason: String,
    },
    UdpRegistered {
        port: u16,
    },
}

pub fn validate_username(username: &str) -> io::Result<()> {
    let valid = !username.is_empty()
        && username.len() <= 32
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(invalid_input(
            "username must be 1-32 ASCII letters, digits, '_' or '-'",
        ))
    }
}

impl Message {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut payload = Vec::new();
        match self {
            Self::Hello { username } => {
                payload.push(1);
                put_string(&mut payload, username)?;
            }
            Self::Welcome { username } => {
                payload.push(2);
                put_string(&mut payload, username)?;
            }
            Self::Broadcast { message } => {
                payload.push(3);
                put_string(&mut payload, message)?;
            }
            Self::Direct { recipient, message } => {
                payload.push(4);
                put_string(&mut payload, recipient)?;
                put_string(&mut payload, message)?;
            }
            Self::Chat { sender, message } => {
                payload.push(5);
                put_string(&mut payload, sender)?;
                put_string(&mut payload, message)?;
            }
            Self::Users { usernames } => {
                payload.push(6);
                let count = u16::try_from(usernames.len())
                    .map_err(|_| invalid_input("too many usernames"))?;
                payload.extend_from_slice(&count.to_be_bytes());
                for username in usernames {
                    put_string(&mut payload, username)?;
                }
            }
            Self::Presence { username, online } => {
                payload.push(7);
                put_string(&mut payload, username)?;
                payload.push(u8::from(*online));
            }
            Self::Error { message } => {
                payload.push(8);
                put_string(&mut payload, message)?;
            }
            Self::UdpRegister { port } => {
                payload.push(9);
                payload.extend_from_slice(&port.to_be_bytes());
            }
            Self::FileOffer {
                recipient,
                transfer_id,
                file_name,
                size,
                digest,
            } => {
                payload.push(10);
                put_string(&mut payload, recipient)?;
                payload.extend_from_slice(&transfer_id.to_be_bytes());
                put_string(&mut payload, file_name)?;
                payload.extend_from_slice(&size.to_be_bytes());
                payload.extend_from_slice(digest);
            }
            Self::IncomingFileOffer {
                sender,
                transfer_id,
                file_name,
                size,
                digest,
            } => {
                payload.push(11);
                put_string(&mut payload, sender)?;
                payload.extend_from_slice(&transfer_id.to_be_bytes());
                put_string(&mut payload, file_name)?;
                payload.extend_from_slice(&size.to_be_bytes());
                payload.extend_from_slice(digest);
            }
            Self::FileAccept { transfer_id } => {
                payload.push(12);
                payload.extend_from_slice(&transfer_id.to_be_bytes());
            }
            Self::FilePeer {
                transfer_id,
                peer_address,
            } => {
                payload.push(13);
                payload.extend_from_slice(&transfer_id.to_be_bytes());
                put_string(&mut payload, peer_address)?;
            }
            Self::FileReject {
                transfer_id,
                reason,
            } => {
                payload.push(14);
                payload.extend_from_slice(&transfer_id.to_be_bytes());
                put_string(&mut payload, reason)?;
            }
            Self::UdpRegistered { port } => {
                payload.push(15);
                payload.extend_from_slice(&port.to_be_bytes());
            }
        }

        if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
            return Err(invalid_input("frame exceeds the configured size limit"));
        }
        Ok(payload)
    }

    pub fn decode(payload: &[u8]) -> io::Result<Self> {
        if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
            return Err(invalid_data("invalid frame size"));
        }

        let (&kind, body) = payload
            .split_first()
            .ok_or_else(|| invalid_data("missing message type"))?;
        let mut cursor = Cursor::new(body);
        let message = match kind {
            1 => Self::Hello {
                username: cursor.read_string()?,
            },
            2 => Self::Welcome {
                username: cursor.read_string()?,
            },
            3 => Self::Broadcast {
                message: cursor.read_string()?,
            },
            4 => Self::Direct {
                recipient: cursor.read_string()?,
                message: cursor.read_string()?,
            },
            5 => Self::Chat {
                sender: cursor.read_string()?,
                message: cursor.read_string()?,
            },
            6 => {
                let count = cursor.read_u16()? as usize;
                let mut usernames = Vec::with_capacity(count);
                for _ in 0..count {
                    usernames.push(cursor.read_string()?);
                }
                Self::Users { usernames }
            }
            7 => {
                let username = cursor.read_string()?;
                let online = match cursor.read_byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid_data("invalid presence state")),
                };
                Self::Presence { username, online }
            }
            8 => Self::Error {
                message: cursor.read_string()?,
            },
            9 => Self::UdpRegister {
                port: cursor.read_u16()?,
            },
            10 => Self::FileOffer {
                recipient: cursor.read_string()?,
                transfer_id: cursor.read_u64()?,
                file_name: cursor.read_string()?,
                size: cursor.read_u64()?,
                digest: cursor.read_array()?,
            },
            11 => Self::IncomingFileOffer {
                sender: cursor.read_string()?,
                transfer_id: cursor.read_u64()?,
                file_name: cursor.read_string()?,
                size: cursor.read_u64()?,
                digest: cursor.read_array()?,
            },
            12 => Self::FileAccept {
                transfer_id: cursor.read_u64()?,
            },
            13 => Self::FilePeer {
                transfer_id: cursor.read_u64()?,
                peer_address: cursor.read_string()?,
            },
            14 => Self::FileReject {
                transfer_id: cursor.read_u64()?,
                reason: cursor.read_string()?,
            },
            15 => Self::UdpRegistered {
                port: cursor.read_u16()?,
            },
            _ => return Err(invalid_data("unknown message type")),
        };

        if !cursor.is_empty() {
            return Err(invalid_data("unexpected trailing bytes"));
        }
        Ok(message)
    }
}

pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<Message>> {
    let mut length_bytes = [0; 4];
    if reader.read(&mut length_bytes[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut length_bytes[1..])?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(invalid_data("invalid frame length"));
    }

    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Message::decode(&payload).map(Some)
}

pub fn write_frame<W: Write>(writer: &mut W, message: &Message) -> io::Result<()> {
    let payload = message.encode()?;
    let length = u32::try_from(payload.len()).map_err(|_| invalid_input("frame too large"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)
}

#[derive(Default)]
pub struct FrameDecoder {
    buffered: Vec<u8>,
}

impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<Message>> {
        self.buffered.extend_from_slice(bytes);
        let mut messages = Vec::new();
        loop {
            if self.buffered.len() < 4 {
                break;
            }
            let prefix = self.buffered[..4]
                .try_into()
                .map_err(|_| invalid_data("invalid frame prefix"))?;
            let length = u32::from_be_bytes(prefix) as usize;
            if length == 0 || length > MAX_FRAME_BYTES {
                return Err(invalid_data("invalid frame length"));
            }
            let frame_length = 4 + length;
            if self.buffered.len() < frame_length {
                break;
            }
            let payload = self.buffered[4..frame_length].to_vec();
            self.buffered.drain(..frame_length);
            messages.push(Message::decode(&payload)?);
        }
        if self.buffered.len() > MAX_FRAME_BYTES + 4 {
            return Err(invalid_data(
                "buffered frame exceeds the configured size limit",
            ));
        }
        Ok(messages)
    }
}

fn put_string(output: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let length = u16::try_from(value.len()).map_err(|_| invalid_input("string is too long"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_byte(&mut self) -> io::Result<u8> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| invalid_data("truncated message"))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let bytes = self.read_exact_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        let bytes = self.read_exact_bytes(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| invalid_data("invalid u64"))?,
        ))
    }

    fn read_array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.read_exact_bytes(N)?
            .try_into()
            .map_err(|_| invalid_data("invalid fixed-size field"))
    }

    fn read_string(&mut self) -> io::Result<String> {
        let length = self.read_u16()? as usize;
        let bytes = self.read_exact_bytes(length)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| invalid_data("string is not valid UTF-8"))?;
        Ok(value.to_owned())
    }

    fn read_exact_bytes(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| invalid_data("message length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_data("truncated message"))?;
        self.position = end;
        Ok(bytes)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{read_frame, write_frame, Message, MAX_FRAME_BYTES};
    use std::io::{self, Cursor};

    #[test]
    fn every_message_round_trips() {
        let messages = [
            Message::Hello {
                username: "alice".into(),
            },
            Message::Welcome {
                username: "alice".into(),
            },
            Message::Broadcast {
                message: "hello 🌐".into(),
            },
            Message::Direct {
                recipient: "bob".into(),
                message: "private".into(),
            },
            Message::Chat {
                sender: "alice".into(),
                message: "hello".into(),
            },
            Message::Users {
                usernames: vec!["alice".into(), "bob".into()],
            },
            Message::Presence {
                username: "bob".into(),
                online: false,
            },
            Message::Error {
                message: "not found".into(),
            },
            Message::UdpRegister { port: 9001 },
            Message::FileOffer {
                recipient: "bob".into(),
                transfer_id: 42,
                file_name: "report.bin".into(),
                size: 1234,
                digest: [0xAB; 32],
            },
            Message::IncomingFileOffer {
                sender: "alice".into(),
                transfer_id: 42,
                file_name: "report.bin".into(),
                size: 1234,
                digest: [0xCD; 32],
            },
            Message::FileAccept { transfer_id: 42 },
            Message::FilePeer {
                transfer_id: 42,
                peer_address: "192.0.2.1:54321".into(),
            },
            Message::FileReject {
                transfer_id: 42,
                reason: "cancelled".into(),
            },
            Message::UdpRegistered { port: 52000 },
        ];

        for message in messages {
            let encoded = message.encode().expect("message should encode");
            assert_eq!(Message::decode(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn frame_round_trips_over_a_stream() {
        let message = Message::Broadcast {
            message: "split reads are valid".into(),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &message).unwrap();

        let mut reader = Cursor::new(bytes);
        assert_eq!(read_frame(&mut reader).unwrap(), Some(message));
    }

    #[test]
    fn clean_eof_is_distinct_from_a_truncated_frame() {
        assert_eq!(read_frame(&mut Cursor::new([])).unwrap(), None);
        let error = read_frame(&mut Cursor::new([0, 0])).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn incremental_decoder_handles_partial_and_coalesced_frames() {
        let first = Message::Broadcast {
            message: "first".into(),
        };
        let second = Message::Broadcast {
            message: "second".into(),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &first).unwrap();
        write_frame(&mut bytes, &second).unwrap();
        let split = 3;
        let mut decoder = super::FrameDecoder::default();
        assert!(decoder.push(&bytes[..split]).unwrap().is_empty());
        assert_eq!(decoder.push(&bytes[split..]).unwrap(), vec![first, second]);
    }

    #[test]
    fn rejects_oversized_frame_before_allocating_payload() {
        let oversized_length = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        let error = read_frame(&mut Cursor::new(oversized_length)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_truncated_and_malformed_payloads() {
        assert!(Message::decode(&[1, 0]).is_err());
        assert!(Message::decode(&[99]).is_err());
        assert!(Message::decode(&[7, 0, 1, b'a', 2]).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert!(Message::decode(&[3, 0, 0, 0]).is_err());
    }

    #[test]
    fn usernames_are_bounded_and_ascii_safe() {
        assert!(super::validate_username("alice-01").is_ok());
        assert!(super::validate_username("").is_err());
        assert!(super::validate_username("two words").is_err());
        assert!(super::validate_username("álîce").is_err());
        assert!(super::validate_username(&"a".repeat(33)).is_err());
    }
}
