//! vici message encoding/decoding.
//!
//! A vici message is an ordered tree of named elements. On the wire each
//! element is introduced by a one-byte type tag:
//!
//! | tag | element        | payload                                        |
//! |-----|----------------|------------------------------------------------|
//! | 1   | SECTION_START  | name; nested elements follow until SECTION_END |
//! | 2   | SECTION_END    | —                                              |
//! | 3   | KEY_VALUE      | name + value                                   |
//! | 4   | LIST_START     | name; LIST_ITEMs follow until LIST_END         |
//! | 5   | LIST_ITEM      | value                                          |
//! | 6   | LIST_END       | —                                              |
//!
//! Names use a 1-byte length prefix (max 255); values use a 2-byte
//! big-endian length prefix (max 65535). This module is pure logic and is
//! unit-tested on every platform, including Windows dev boxes where the
//! Unix-socket transport is unavailable.

use std::fmt::Write as _;
use thiserror::Error;

const SECTION_START: u8 = 1;
const SECTION_END: u8 = 2;
const KEY_VALUE: u8 = 3;
const LIST_START: u8 = 4;
const LIST_ITEM: u8 = 5;
const LIST_END: u8 = 6;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("element name exceeds 255 bytes")]
    NameTooLong,
    #[error("value exceeds 65535 bytes")]
    ValueTooLong,
    #[error("malformed vici message: {0}")]
    Malformed(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(Vec<u8>),
    List(Vec<Vec<u8>>),
    Section(Message),
}

/// An ordered vici message. Built fluently for requests, or produced by
/// [`Message::decode`] for responses/events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    pub entries: Vec<(String, Value)>,
}

impl Message {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key/value pair. Accepts anything byte-like (`&str`, `String`,
    /// `Vec<u8>`, `&[u8]`).
    pub fn str(mut self, key: &str, value: impl AsRef<[u8]>) -> Self {
        self.entries
            .push((key.to_string(), Value::Str(value.as_ref().to_vec())));
        self
    }

    /// Add a list of string values.
    pub fn list(mut self, key: &str, items: impl IntoIterator<Item = String>) -> Self {
        let items = items.into_iter().map(String::into_bytes).collect();
        self.entries.push((key.to_string(), Value::List(items)));
        self
    }

    /// Add a nested section.
    pub fn section(mut self, key: &str, sub: Message) -> Self {
        self.entries.push((key.to_string(), Value::Section(sub)));
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_str(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Some(Value::Str(b)) => Some(String::from_utf8_lossy(b).into_owned()),
            _ => None,
        }
    }

    pub fn get_section(&self, key: &str) -> Option<&Message> {
        match self.get(key) {
            Some(Value::Section(m)) => Some(m),
            _ => None,
        }
    }

    pub fn get_list(&self, key: &str) -> Option<Vec<String>> {
        match self.get(key) {
            Some(Value::List(l)) => Some(
                l.iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Iterate over the direct sub-sections (name, message).
    pub fn sections(&self) -> impl Iterator<Item = (&str, &Message)> {
        self.entries.iter().filter_map(|(k, v)| match v {
            Value::Section(m) => Some((k.as_str(), m)),
            _ => None,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::new();
        encode_into(self, &mut buf)?;
        Ok(buf)
    }

    pub fn decode(buf: &[u8]) -> Result<Message, CodecError> {
        let mut pos = 0;
        let msg = parse(buf, &mut pos, true)?;
        Ok(msg)
    }

    /// Human-readable rendering for debugging/log output.
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        pretty_into(self, 0, &mut out);
        out
    }
}

fn push_name(buf: &mut Vec<u8>, name: &str) -> Result<(), CodecError> {
    if name.len() > u8::MAX as usize {
        return Err(CodecError::NameTooLong);
    }
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());
    Ok(())
}

fn push_value(buf: &mut Vec<u8>, value: &[u8]) -> Result<(), CodecError> {
    if value.len() > u16::MAX as usize {
        return Err(CodecError::ValueTooLong);
    }
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

fn encode_into(msg: &Message, buf: &mut Vec<u8>) -> Result<(), CodecError> {
    for (key, value) in &msg.entries {
        match value {
            Value::Str(v) => {
                buf.push(KEY_VALUE);
                push_name(buf, key)?;
                push_value(buf, v)?;
            }
            Value::List(items) => {
                buf.push(LIST_START);
                push_name(buf, key)?;
                for item in items {
                    buf.push(LIST_ITEM);
                    push_value(buf, item)?;
                }
                buf.push(LIST_END);
            }
            Value::Section(sub) => {
                buf.push(SECTION_START);
                push_name(buf, key)?;
                encode_into(sub, buf)?;
                buf.push(SECTION_END);
            }
        }
    }
    Ok(())
}

fn read_name(buf: &[u8], pos: &mut usize) -> Result<String, CodecError> {
    let len = *buf.get(*pos).ok_or(CodecError::Malformed("truncated name length"))? as usize;
    *pos += 1;
    let end = *pos + len;
    let bytes = buf.get(*pos..end).ok_or(CodecError::Malformed("truncated name"))?;
    *pos = end;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn read_value(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, CodecError> {
    let hi = *buf.get(*pos).ok_or(CodecError::Malformed("truncated value length"))?;
    let lo = *buf.get(*pos + 1).ok_or(CodecError::Malformed("truncated value length"))?;
    *pos += 2;
    let len = u16::from_be_bytes([hi, lo]) as usize;
    let end = *pos + len;
    let bytes = buf.get(*pos..end).ok_or(CodecError::Malformed("truncated value"))?;
    *pos = end;
    Ok(bytes.to_vec())
}

fn parse(buf: &[u8], pos: &mut usize, at_top: bool) -> Result<Message, CodecError> {
    let mut msg = Message::new();
    while *pos < buf.len() {
        let tag = buf[*pos];
        *pos += 1;
        match tag {
            SECTION_START => {
                let name = read_name(buf, pos)?;
                let sub = parse(buf, pos, false)?;
                msg.entries.push((name, Value::Section(sub)));
            }
            SECTION_END => {
                if at_top {
                    return Err(CodecError::Malformed("unexpected section end"));
                }
                return Ok(msg);
            }
            KEY_VALUE => {
                let name = read_name(buf, pos)?;
                let value = read_value(buf, pos)?;
                msg.entries.push((name, Value::Str(value)));
            }
            LIST_START => {
                let name = read_name(buf, pos)?;
                let mut items = Vec::new();
                loop {
                    let t = *buf.get(*pos).ok_or(CodecError::Malformed("unterminated list"))?;
                    *pos += 1;
                    match t {
                        LIST_ITEM => items.push(read_value(buf, pos)?),
                        LIST_END => break,
                        _ => return Err(CodecError::Malformed("unexpected element in list")),
                    }
                }
                msg.entries.push((name, Value::List(items)));
            }
            _ => return Err(CodecError::Malformed("unknown element type")),
        }
    }
    if at_top {
        Ok(msg)
    } else {
        Err(CodecError::Malformed("unterminated section"))
    }
}

fn pretty_into(msg: &Message, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    for (key, value) in &msg.entries {
        match value {
            Value::Str(v) => {
                let _ = writeln!(out, "{pad}{key} = {}", String::from_utf8_lossy(v));
            }
            Value::List(items) => {
                let joined = items
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "{pad}{key} = [{joined}]");
            }
            Value::Section(sub) => {
                let _ = writeln!(out, "{pad}{key} {{");
                pretty_into(sub, indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_key_value_exactly() {
        let msg = Message::new().str("key", "value");
        assert_eq!(
            msg.encode().unwrap(),
            vec![KEY_VALUE, 3, b'k', b'e', b'y', 0, 5, b'v', b'a', b'l', b'u', b'e']
        );
    }

    #[test]
    fn roundtrips_nested_structure() {
        let msg = Message::new()
            .str("version", "2")
            .list("remote_addrs", ["192.168.100.10".to_string()])
            .section(
                "local",
                Message::new().str("auth", "psk").str("id", "test-1@test.local"),
            )
            .list("proposals", ["aes256-sha256-prfsha256-modp3072".to_string()]);

        let bytes = msg.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(msg, back);
        assert_eq!(back.get_str("version").as_deref(), Some("2"));
        assert_eq!(
            back.get_section("local").unwrap().get_str("auth").as_deref(),
            Some("psk")
        );
        assert_eq!(
            back.get_list("remote_addrs"),
            Some(vec!["192.168.100.10".to_string()])
        );
    }

    #[test]
    fn empty_list_roundtrips() {
        let msg = Message::new().list("owners", Vec::<String>::new());
        let back = Message::decode(&msg.encode().unwrap()).unwrap();
        assert_eq!(back.get_list("owners"), Some(vec![]));
    }

    #[test]
    fn binary_value_survives() {
        let msg = Message::new().str("data", vec![0u8, 255, 10, 0, 3]);
        let back = Message::decode(&msg.encode().unwrap()).unwrap();
        assert_eq!(back.get("data"), Some(&Value::Str(vec![0, 255, 10, 0, 3])));
    }

    #[test]
    fn truncated_input_is_error_not_panic() {
        assert!(Message::decode(&[KEY_VALUE, 3, b'k']).is_err());
        assert!(Message::decode(&[SECTION_START, 1, b'a']).is_err());
        assert!(Message::decode(&[99]).is_err());
    }
}
