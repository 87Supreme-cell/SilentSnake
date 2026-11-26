//! TLS ClientHello parser: extracts the server name (SNI) and flags Encrypted Client Hello.
//!
//! Input is the client-to-server byte stream from the start of the connection. The parser
//! follows the ClientHello across TLS records, returns `Ok(None)` while it needs more bytes,
//! and never reads past a length it has checked. Sizes are capped at [`MAX_HANDSHAKE`].

#![deny(clippy::indexing_slicing)]

use crate::sanitize;

/// Largest ClientHello handshake message accepted (real ones are ~0.5 to 3 KiB).
pub const MAX_HANDSHAKE: usize = 16 * 1024;
/// TLSPlaintext.length limit (RFC 8446 section 5.1).
pub const MAX_RECORD: usize = 16 * 1024;
/// Longest DNS host name; longer SNI values are truncated for display and flagged.
pub const MAX_SNI: usize = 255;

const EXT_SERVER_NAME: u16 = 0;
const EXT_ECH: u16 = 0xfe0d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    NotHandshake,
    NotClientHello,
    BadVersion,
    TooLarge,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Sanitized SNI host name, if the client sent one.
    pub server_name: Option<String>,
    /// Encrypted Client Hello in use: `server_name` is then only the outer, public name.
    pub ech: bool,
    /// Protocol oddities worth an analyst's attention.
    pub anomalies: Vec<&'static str>,
}

/// Cheap check on the first client bytes: a TLS handshake record starts `16 03 xx`.
pub fn looks_like_tls(first: &[u8]) -> bool {
    first.first() == Some(&0x16) && first.get(1).is_none_or(|&b| b == 0x03)
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self {
        R { b, p: 0 }
    }
    fn left(&self) -> usize {
        self.b.len().saturating_sub(self.p)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self.p.checked_add(n).ok_or(TlsError::Malformed)?;
        let s = self.b.get(self.p..end).ok_or(TlsError::Malformed)?;
        self.p = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
        self.take(1)?.first().copied().ok_or(TlsError::Malformed)
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        Ok((u16::from(self.u8()?) << 8) | u16::from(self.u8()?))
    }
    fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// Parses the ClientHello at the start of `stream`. `Ok(None)` means "need more bytes".
pub fn parse_client_hello(stream: &[u8]) -> Result<Option<ClientHello>, TlsError> {
    let mut hs: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    loop {
        // Once the handshake header is in, we know how much we need.
        if let (Some(&t), Some(len_bytes)) = (hs.first(), hs.get(1..4)) {
            if t != 1 {
                return Err(TlsError::NotClientHello);
            }
            let len = len_bytes
                .iter()
                .fold(0usize, |a, &b| (a << 8) | usize::from(b));
            if len > MAX_HANDSHAKE {
                return Err(TlsError::TooLarge);
            }
            if let Some(body) = hs.get(4..4 + len) {
                return parse_body(body).map(Some);
            }
        }
        let Some(header) = stream.get(pos..pos + 5) else {
            return Ok(None);
        };
        let mut h = R::new(header);
        if h.u8()? != 0x16 {
            return Err(TlsError::NotHandshake);
        }
        if h.u8()? != 0x03 {
            return Err(TlsError::BadVersion);
        }
        let _minor = h.u8()?;
        let rec_len = usize::from(h.u16()?);
        if rec_len == 0 || rec_len > MAX_RECORD {
            return Err(TlsError::Malformed);
        }
        let Some(body) = stream.get(pos + 5..pos + 5 + rec_len) else {
            return Ok(None);
        };
        hs.extend_from_slice(body);
        pos += 5 + rec_len;
        if hs.len() > MAX_HANDSHAKE + 4 {
            return Err(TlsError::TooLarge);
        }
    }
}

fn parse_body(body: &[u8]) -> Result<ClientHello, TlsError> {
    let mut r = R::new(body);
    let mut ch = ClientHello {
        server_name: None,
        ech: false,
        anomalies: Vec::new(),
    };

    let version = r.u16()?;
    if version >> 8 != 0x03 {
        return Err(TlsError::BadVersion);
    }
    if version < 0x0303 {
        ch.anomalies.push("legacy_tls_version");
    }
    r.take(32)?; // random
    let session_id = r.vec8()?;
    if session_id.len() > 32 {
        return Err(TlsError::Malformed);
    }
    let suites = r.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return Err(TlsError::Malformed);
    }
    r.vec8()?; // compression methods
    if r.left() == 0 {
        ch.anomalies.push("no_extensions");
        return Ok(ch);
    }
    let exts = r.vec16()?;
    if r.left() != 0 {
        ch.anomalies.push("trailing_bytes");
    }

    let mut e = R::new(exts);
    let mut seen: Vec<u16> = Vec::new();
    while e.left() > 0 {
        let ty = e.u16()?;
        let data = e.vec16()?;
        if seen.contains(&ty) {
            push_once(&mut ch.anomalies, "duplicate_extension");
        } else {
            seen.push(ty);
        }
        match ty {
            EXT_SERVER_NAME if ch.server_name.is_none() => parse_sni(data, &mut ch)?,
            EXT_ECH => ch.ech = true,
            _ => {}
        }
    }
    Ok(ch)
}

fn parse_sni(data: &[u8], ch: &mut ClientHello) -> Result<(), TlsError> {
    let mut r = R::new(data);
    let list = r.vec16()?;
    let mut l = R::new(list);
    while l.left() > 0 {
        let name_type = l.u8()?;
        let name = l.vec16()?;
        if name_type != 0 {
            continue;
        }
        if name.is_empty() {
            push_once(&mut ch.anomalies, "sni_empty");
            return Ok(());
        }
        let shown = match name.get(..MAX_SNI) {
            Some(prefix) if name.len() > MAX_SNI => {
                push_once(&mut ch.anomalies, "sni_too_long");
                prefix
            }
            _ => name,
        };
        if !name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        {
            push_once(&mut ch.anomalies, "sni_unusual_characters");
        }
        ch.server_name = Some(sanitize::hostname(shown));
        return Ok(());
    }
    Ok(())
}

fn push_once(v: &mut Vec<&'static str>, s: &'static str) {
    if !v.contains(&s) {
        v.push(s);
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello carrying `sni` (and an ECH extension if `ech`), padded with a fake
    /// key-share extension of `pad` bytes, wrapped in records of at most `record_max` bytes.
    pub fn client_hello(sni: Option<&str>, ech: bool, pad: usize, record_max: usize) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        if ech {
            exts.extend_from_slice(&EXT_ECH.to_be_bytes());
            exts.extend_from_slice(&4u16.to_be_bytes());
            exts.extend_from_slice(&[0, 0, 1, 0]);
        }
        exts.extend_from_slice(&51u16.to_be_bytes()); // key_share
        exts.extend_from_slice(&(pad as u16).to_be_bytes());
        exts.extend(std::iter::repeat_n(0xAB, pad));

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![1u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut out = Vec::new();
        for chunk in hs.chunks(record_max) {
            out.extend_from_slice(&[0x16, 0x03, 0x01]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    #[test]
    fn extracts_sni() {
        let ch = parse_client_hello(&client_hello(Some("example.com"), false, 32, 16384))
            .unwrap()
            .unwrap();
        assert_eq!(ch.server_name.as_deref(), Some("example.com"));
        assert!(!ch.ech);
        assert!(ch.anomalies.is_empty());
    }

    #[test]
    fn needs_more_until_complete_then_succeeds() {
        // Post-quantum-sized hello (~1.3 KiB key share) split over three records.
        let full = client_hello(Some("pq.example"), false, 1250, 600);
        for cut in [0, 3, 5, 100, 700, full.len() - 1] {
            assert_eq!(parse_client_hello(&full[..cut]), Ok(None), "cut at {cut}");
        }
        assert_eq!(
            parse_client_hello(&full)
                .unwrap()
                .unwrap()
                .server_name
                .as_deref(),
            Some("pq.example")
        );
    }

    #[test]
    fn flags_ech_and_missing_sni() {
        let ch = parse_client_hello(&client_hello(Some("public.example"), true, 8, 16384))
            .unwrap()
            .unwrap();
        assert!(ch.ech);
        let ch = parse_client_hello(&client_hello(None, false, 8, 16384))
            .unwrap()
            .unwrap();
        assert_eq!(ch.server_name, None);
    }

    #[test]
    fn rejects_non_tls_and_oversize() {
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\n"),
            Err(TlsError::NotHandshake)
        );
        assert!(!looks_like_tls(b"GET /"));
        let mut big = vec![0x16, 0x03, 0x01, 0x00, 0x04, 1, 0xFF, 0xFF, 0xFF];
        assert_eq!(parse_client_hello(&big), Err(TlsError::TooLarge));
        big[5] = 2; // ServerHello
        assert_eq!(parse_client_hello(&big), Err(TlsError::NotClientHello));
    }

    #[test]
    fn escapes_hostile_sni() {
        let ch = parse_client_hello(&client_hello(Some("a b\u{1b}.com"), false, 8, 16384))
            .unwrap()
            .unwrap();
        assert_eq!(ch.server_name.as_deref(), Some("a\\x20b\\x1b.com"));
        assert!(ch.anomalies.contains(&"sni_unusual_characters"));
    }
}
