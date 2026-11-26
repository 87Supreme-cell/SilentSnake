//! Turns untrusted name bytes from the wire (DNS labels, TLS SNI) into safe, printable text.
//!
//! Only `[A-Za-z0-9-_*]` pass through unchanged; every other byte becomes `\xNN`. Names
//! captured from traffic therefore can't carry control characters, ANSI escapes, quotes or
//! spaces into logs, terminals, the UI or the LLM analyst's context.

#![deny(clippy::indexing_slicing)]

use std::fmt::Write;

fn plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*'
}

/// Appends one DNS label; a literal `.` inside a label is escaped so it can't fake a separator.
pub fn push_label(out: &mut String, label: &[u8]) {
    for &b in label {
        if plain(b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
}

/// A dotted host name (TLS SNI): `.` passes through as the separator.
pub fn hostname(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if plain(b) || b == b'.' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_everything_unsafe() {
        assert_eq!(hostname(b"api.github.com"), "api.github.com");
        assert_eq!(
            hostname(b"a b\x1b[31m\"\n"),
            "a\\x20b\\x1b\\x5b31m\\x22\\x0a"
        );
        let mut s = String::new();
        push_label(&mut s, b"evil.com");
        assert_eq!(s, "evil\\x2ecom");
        assert_eq!(hostname("é".as_bytes()), "\\xc3\\xa9");
    }
}
