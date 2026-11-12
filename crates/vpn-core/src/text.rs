//! Decode a profile file's bytes into text, whatever Windows tool wrote it.
//!
//! Profile exports are not reliably UTF-8. The LANCOM Advanced VPN Client
//! (NCP-based) writes its `.ini` in the Windows ANSI code page, so a single
//! umlaut in a profile name, a user id or the PSK makes the file invalid
//! UTF-8; Notepad's "Unicode" save writes UTF-16 with a BOM. Both have to
//! import, so the bytes are decoded here instead of insisting on UTF-8.
//!
//! Order: a byte-order mark decides outright; then BOM-less UTF-16 (detected by
//! its NUL bytes, which never appear in a text profile); then UTF-8; and
//! anything else is read as Windows-1252, which every byte sequence decodes
//! under — so this never fails, and an exotic encoding at worst garbles a
//! non-ASCII character rather than refusing the whole file.

/// Decode `bytes` into a `String`, dropping any byte-order mark.
pub fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, u16::from_be_bytes);
    }
    if let Some(from_bytes) = bomless_utf16(bytes) {
        return utf16(bytes, from_bytes);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => windows_1252(bytes),
    }
}

/// Read a file and [`decode`] it.
pub fn read_file(path: &std::path::Path) -> std::io::Result<String> {
    std::fs::read(path).map(|b| decode(&b))
}

/// UTF-16 without a BOM: ASCII-heavy text has a NUL in every other byte, on
/// the odd positions for little-endian and the even ones for big-endian.
fn bomless_utf16(bytes: &[u8]) -> Option<fn([u8; 2]) -> u16> {
    if bytes.len() < 4 || bytes.len() % 2 != 0 {
        return None;
    }
    let sample = &bytes[..bytes.len().min(512)];
    let pairs = sample.len() / 2;
    let nul_at = |offset: usize| sample.iter().skip(offset).step_by(2).filter(|&&b| b == 0).count();
    // Most code units of a profile are ASCII; demand a clear majority so a
    // binary blob with the odd NUL is not mistaken for text.
    if nul_at(1) * 4 >= pairs * 3 && nul_at(0) == 0 {
        Some(u16::from_le_bytes)
    } else if nul_at(0) * 4 >= pairs * 3 && nul_at(1) == 0 {
        Some(u16::from_be_bytes)
    } else {
        None
    }
}

fn utf16(bytes: &[u8], from_bytes: fn([u8; 2]) -> u16) -> String {
    let units = bytes.chunks_exact(2).map(|p| from_bytes([p[0], p[1]]));
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Windows-1252: Latin-1 except for 0x80–0x9F, where it puts the euro sign,
/// curly quotes, dashes and a few letters. The five codes it leaves undefined
/// map to the C1 control of the same value, as Windows itself does.
fn windows_1252(bytes: &[u8]) -> String {
    const HIGH: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8D}', 'Ž', '\u{8F}',
        '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9D}', 'ž', 'Ÿ',
    ];
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9F => HIGH[(b - 0x80) as usize],
            _ => b as char,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "[PROFILE1]\r\nName=Bötsch Büro\r\nSecret=\"ä€§\"\r\n";

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn utf16be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    #[test]
    fn plain_utf8_passes_through() {
        assert_eq!(decode(TEXT.as_bytes()), TEXT);
    }

    #[test]
    fn utf8_bom_is_dropped() {
        let mut b = vec![0xEF, 0xBB, 0xBF];
        b.extend_from_slice(TEXT.as_bytes());
        assert_eq!(decode(&b), TEXT);
    }

    #[test]
    fn utf16_with_bom() {
        let mut le = vec![0xFF, 0xFE];
        le.extend(utf16le(TEXT));
        assert_eq!(decode(&le), TEXT);
        let mut be = vec![0xFE, 0xFF];
        be.extend(utf16be(TEXT));
        assert_eq!(decode(&be), TEXT);
    }

    #[test]
    fn utf16_without_bom() {
        assert_eq!(decode(&utf16le(TEXT)), TEXT);
        assert_eq!(decode(&utf16be(TEXT)), TEXT);
    }

    /// What the LANCOM Advanced VPN Client writes: ANSI, umlauts as single
    /// bytes (0xF6 = ö, 0xFC = ü, 0xE4 = ä, 0x80 = €, 0xA7 = §).
    #[test]
    fn ansi_export_decodes_as_windows_1252() {
        let mut b = b"[PROFILE1]\r\nName=B\xF6tsch B\xFCro\r\nSecret=\"\xE4\x80\xA7\"\r\n".to_vec();
        assert_eq!(decode(&b), TEXT);
        // Every byte decodes; nothing is refused.
        b.extend(0u8..=255);
        assert!(decode(&b).starts_with("[PROFILE1]"));
    }
}
