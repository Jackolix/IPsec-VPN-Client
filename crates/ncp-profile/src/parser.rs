//! Minimal, defensive ini parser for NCP profile exports.
//!
//! Hand-rolled rather than a generic ini crate so we control exactly how
//! quoted values (the PSK contains `#`, `&`, `%`, ...) and malformed input
//! are handled. The input is untrusted: a user can be handed a hostile
//! profile file.

use thiserror::Error;

/// Hard cap on input size; a legitimate profile export is well under 1 MiB.
pub const MAX_INPUT_LEN: usize = 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("input exceeds {MAX_INPUT_LEN} bytes")]
    TooLarge,
    #[error("line {0}: key/value pair before any [SECTION] header")]
    KeyOutsideSection(usize),
    #[error("line {0}: malformed line (expected [SECTION] or KEY=VALUE)")]
    MalformedLine(usize),
    #[error("line {0}: empty section name")]
    EmptySectionName(usize),
}

/// One `[NAME]` section with its key/value pairs in file order.
/// Keys are matched case-insensitively via [`Section::get`]; duplicate keys
/// keep the last occurrence, matching typical ini semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub entries: Vec<(String, String)>,
}

impl Section {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub sections: Vec<Section>,
}

impl Document {
    /// First section whose name matches case-insensitively.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// All sections whose name starts with `prefix` (case-insensitive),
    /// e.g. every `[IKEV2POLICYn]`.
    pub fn sections_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = &'a Section> {
        self.sections.iter().filter(move |s| {
            s.name.len() >= prefix.len()
                && s.name[..prefix.len()].eq_ignore_ascii_case(prefix)
        })
    }
}

/// Strip one pair of surrounding double quotes, if present. NCP quotes values
/// containing special characters (notably `Secret="..."`).
fn unquote(v: &str) -> &str {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

pub fn parse(input: &str) -> Result<Document, ParseError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(ParseError::TooLarge);
    }

    let mut sections: Vec<Section> = Vec::new();

    for (idx, raw_line) in input.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw_line.trim_start_matches('\u{feff}').trim();

        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix('[') {
            let Some(name) = rest.strip_suffix(']') else {
                return Err(ParseError::MalformedLine(lineno));
            };
            let name = name.trim();
            if name.is_empty() {
                return Err(ParseError::EmptySectionName(lineno));
            }
            sections.push(Section {
                name: name.to_string(),
                entries: Vec::new(),
            });
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(ParseError::MalformedLine(lineno));
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(ParseError::MalformedLine(lineno));
        }
        let Some(section) = sections.last_mut() else {
            return Err(ParseError::KeyOutsideSection(lineno));
        };
        section
            .entries
            .push((key.to_string(), unquote(value).to_string()));
    }

    Ok(Document { sections })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_and_quoted_values() {
        let doc = parse("[A]\nKey=1\nSecret=\"a&b#c\"\n[B]\nKey=2\n").unwrap();
        assert_eq!(doc.sections.len(), 2);
        assert_eq!(doc.section("a").unwrap().get("KEY"), Some("1"));
        assert_eq!(doc.section("A").unwrap().get("Secret"), Some("a&b#c"));
        assert_eq!(doc.section("B").unwrap().get("Key"), Some("2"));
    }

    #[test]
    fn rejects_key_outside_section() {
        assert_eq!(parse("Key=1\n"), Err(ParseError::KeyOutsideSection(1)));
    }

    #[test]
    fn rejects_garbage_line() {
        assert_eq!(parse("[A]\nnonsense\n"), Err(ParseError::MalformedLine(2)));
    }

    #[test]
    fn duplicate_key_last_wins() {
        let doc = parse("[A]\nK=1\nK=2\n").unwrap();
        assert_eq!(doc.section("A").unwrap().get("K"), Some("2"));
    }

    #[test]
    fn handles_crlf_and_comments() {
        let doc = parse("; comment\r\n[A]\r\nK=1\r\n").unwrap();
        assert_eq!(doc.section("A").unwrap().get("K"), Some("1"));
    }
}
