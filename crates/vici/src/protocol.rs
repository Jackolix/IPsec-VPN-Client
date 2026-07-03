//! vici packet framing and a blocking request/event client.
//!
//! Each packet is a 4-byte big-endian length prefix followed by that many
//! bytes: a one-byte packet type and a type-specific payload.
//!
//! | type | packet           | payload            |
//! |------|------------------|--------------------|
//! | 0    | CMD_REQUEST      | name + message     |
//! | 1    | CMD_RESPONSE     | message            |
//! | 2    | CMD_UNKNOWN      | —                  |
//! | 3    | EVENT_REGISTER   | name               |
//! | 4    | EVENT_UNREGISTER | name               |
//! | 5    | EVENT_CONFIRM    | —                  |
//! | 6    | EVENT_UNKNOWN    | —                  |
//! | 7    | EVENT            | name + message     |

use crate::message::{CodecError, Message};
use std::io::{self, Read, Write};
use thiserror::Error;

const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
const EVENT_REGISTER: u8 = 3;
const EVENT_UNREGISTER: u8 = 4;
const EVENT_CONFIRM: u8 = 5;
const EVENT_UNKNOWN: u8 = 6;
const EVENT: u8 = 7;

/// Reject absurd frame sizes rather than allocating on a hostile/desynced peer.
const MAX_PACKET_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vici I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("charon does not know command {0:?}")]
    UnknownCommand(String),
    #[error("charon does not know event {0:?}")]
    UnknownEvent(String),
    #[error("vici packet of {0} bytes exceeds the sanity limit")]
    PacketTooLarge(usize),
    #[error("received an empty vici packet")]
    EmptyPacket,
    #[error("element name exceeds 255 bytes")]
    NameTooLong,
}

/// A blocking vici client over any byte stream (Unix socket in production,
/// anything `Read + Write` in tests).
pub struct Client<S> {
    stream: S,
}

impl<S: Read + Write> Client<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Issue a simple command and return its `CMD_RESPONSE` message. Any
    /// stray events are ignored (none are expected without a registration).
    pub fn request(&mut self, command: &str, message: Message) -> Result<Message, Error> {
        self.write_packet(CMD_REQUEST, Some(command), Some(&message))?;
        loop {
            let (ptype, body) = self.read_packet()?;
            match ptype {
                CMD_RESPONSE => return Ok(Message::decode(&body)?),
                CMD_UNKNOWN => return Err(Error::UnknownCommand(command.to_string())),
                _ => continue,
            }
        }
    }

    /// Register for `event`, issue `command`, collect every matching event
    /// until the terminating `CMD_RESPONSE`, then unregister. This is how
    /// streamed commands such as `list-sas` (event `list-sa`) work.
    pub fn stream_request(
        &mut self,
        command: &str,
        event: &str,
        message: Message,
    ) -> Result<(Vec<Message>, Message), Error> {
        self.register(event)?;
        self.write_packet(CMD_REQUEST, Some(command), Some(&message))?;

        let mut events = Vec::new();
        let response = loop {
            let (ptype, body) = self.read_packet()?;
            match ptype {
                EVENT => {
                    if let Some(msg) = parse_event(&body, event)? {
                        events.push(msg);
                    }
                }
                CMD_RESPONSE => break Message::decode(&body)?,
                CMD_UNKNOWN => {
                    let _ = self.unregister(event);
                    return Err(Error::UnknownCommand(command.to_string()));
                }
                _ => {}
            }
        };
        self.unregister(event)?;
        Ok((events, response))
    }

    fn register(&mut self, event: &str) -> Result<(), Error> {
        self.write_packet(EVENT_REGISTER, Some(event), None)?;
        loop {
            let (ptype, _) = self.read_packet()?;
            match ptype {
                EVENT_CONFIRM => return Ok(()),
                EVENT_UNKNOWN => return Err(Error::UnknownEvent(event.to_string())),
                _ => continue,
            }
        }
    }

    fn unregister(&mut self, event: &str) -> Result<(), Error> {
        self.write_packet(EVENT_UNREGISTER, Some(event), None)?;
        loop {
            let (ptype, _) = self.read_packet()?;
            if ptype == EVENT_CONFIRM {
                return Ok(());
            }
        }
    }

    fn write_packet(
        &mut self,
        ptype: u8,
        name: Option<&str>,
        message: Option<&Message>,
    ) -> Result<(), Error> {
        let mut payload = vec![ptype];
        if let Some(name) = name {
            if name.len() > u8::MAX as usize {
                return Err(Error::NameTooLong);
            }
            payload.push(name.len() as u8);
            payload.extend_from_slice(name.as_bytes());
        }
        if let Some(message) = message {
            payload.extend_from_slice(&message.encode()?);
        }
        self.stream.write_all(&(payload.len() as u32).to_be_bytes())?;
        self.stream.write_all(&payload)?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_packet(&mut self) -> Result<(u8, Vec<u8>), Error> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_PACKET_LEN {
            return Err(Error::PacketTooLarge(len));
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload)?;
        let ptype = *payload.first().ok_or(Error::EmptyPacket)?;
        Ok((ptype, payload[1..].to_vec()))
    }
}

/// Split an `EVENT` payload (name + message) and decode it if the name
/// matches the event we care about.
fn parse_event(body: &[u8], want: &str) -> Result<Option<Message>, Error> {
    let name_len = *body.first().ok_or(Error::EmptyPacket)? as usize;
    let name_end = 1 + name_len;
    let name = body
        .get(1..name_end)
        .ok_or(Error::Codec(CodecError::Malformed("event name")))?;
    if String::from_utf8_lossy(name) != want {
        return Ok(None);
    }
    Ok(Some(Message::decode(&body[name_end..])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A fake stream that serves a canned response to any write, so we can
    /// exercise the request framing without a real charon.
    struct Loopback {
        to_read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Loopback {
        fn with_response(response: Message) -> Self {
            let body = response.encode().unwrap();
            let mut payload = vec![CMD_RESPONSE];
            payload.extend_from_slice(&body);
            let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&payload);
            Self {
                to_read: Cursor::new(framed),
                written: Vec::new(),
            }
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }
    impl Write for Loopback {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn request_frames_command_and_parses_response() {
        let mut client = Client::new(Loopback::with_response(
            Message::new().str("success", "yes"),
        ));
        let resp = client
            .request("load-conn", Message::new().str("x", "y"))
            .unwrap();
        assert_eq!(resp.get_str("success").as_deref(), Some("yes"));

        // Written frame: len(4) + CMD_REQUEST + namelen + "load-conn" + msg.
        let w = &client.stream.written;
        assert_eq!(w[4], CMD_REQUEST);
        assert_eq!(w[5], "load-conn".len() as u8);
        assert_eq!(&w[6..6 + 9], b"load-conn");
    }
}
