//! Bounded DNS message parser (RFC 1035) for UDP DNS, mDNS and LLMNR.
//!
//! Safe Rust, no allocation proportional to attacker-chosen counts: at most
//! [`MAX_QUESTIONS`] questions and [`MAX_ANSWERS`] answers are decoded, names are capped
//! at 255 wire bytes, and compression pointers must point strictly backwards (which rules
//! out loops) with at most [`MAX_POINTER_JUMPS`] jumps per name.

#![deny(clippy::indexing_slicing)]

use crate::sanitize;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_QUESTIONS: usize = 16;
pub const MAX_ANSWERS: usize = 64;
pub const MAX_POINTER_JUMPS: usize = 32;
pub const MAX_NAME_WIRE_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    BadLabel,
    NameTooLong,
    BadPointer,
    TooManyJumps,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Question {
    pub name: String,
    pub qtype: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Answer {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    /// Decoded data for A, AAAA, CNAME, PTR and NS records; omitted for other types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip)]
    pub addr: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Message {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: String,
    /// The TC flag: the server truncated its answer (the client will retry over TCP).
    pub truncated_by_server: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
    /// True when counts exceeded the parser's limits and the rest was not decoded.
    pub partially_decoded: bool,
}

pub fn type_name(t: u16) -> String {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        _ => return format!("TYPE{t}"),
    }
    .to_string()
}

pub fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => return format!("RCODE{r}"),
    }
    .to_string()
}

struct Reader<'a> {
    msg: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DnsError> {
        let end = self.pos.checked_add(n).ok_or(DnsError::Truncated)?;
        let s = self.msg.get(self.pos..end).ok_or(DnsError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, DnsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([
            *b.first().ok_or(DnsError::Truncated)?,
            *b.get(1).ok_or(DnsError::Truncated)?,
        ]))
    }
    fn u32(&mut self) -> Result<u32, DnsError> {
        Ok((u32::from(self.u16()?) << 16) | u32::from(self.u16()?))
    }
    fn name(&mut self) -> Result<String, DnsError> {
        let (name, end) = read_name(self.msg, self.pos)?;
        self.pos = end;
        Ok(name)
    }
}

/// Reads a possibly compressed name starting at `start`; returns it and the offset just past
/// it in the original (uncompressed) position.
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    let mut wire_len = 0usize;
    let mut out = String::new();
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Truncated)?;
        match len & 0xC0 {
            0x00 if len == 0 => {
                if out.is_empty() {
                    out.push('.');
                }
                return Ok((out, end.unwrap_or(pos + 1)));
            }
            0x00 => {
                let l = usize::from(len);
                let label = msg.get(pos + 1..pos + 1 + l).ok_or(DnsError::Truncated)?;
                wire_len += l + 1;
                if wire_len > MAX_NAME_WIRE_LEN {
                    return Err(DnsError::NameTooLong);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                sanitize::push_label(&mut out, label);
                pos += 1 + l;
            }
            0xC0 => {
                let lo = *msg.get(pos + 1).ok_or(DnsError::Truncated)?;
                let target = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                // Strictly backwards: a pointer can never reach itself or anything after it.
                if target >= pos {
                    return Err(DnsError::BadPointer);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsError::TooManyJumps);
                }
                if end.is_none() {
                    end = Some(pos + 2);
                }
                pos = target;
            }
            _ => return Err(DnsError::BadLabel),
        }
    }
}

/// Parses one DNS message (UDP payload).
pub fn parse(msg: &[u8]) -> Result<Message, DnsError> {
    let mut r = Reader { msg, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = usize::from(r.u16()?);
    let an = usize::from(r.u16()?);
    let _ns = r.u16()?;
    let _ar = r.u16()?;

    let mut m = Message {
        id,
        is_response: flags & 0x8000 != 0,
        opcode: u8::try_from((flags >> 11) & 0x0F).unwrap_or(0),
        rcode: rcode_name(u8::try_from(flags & 0x0F).unwrap_or(0)),
        truncated_by_server: flags & 0x0200 != 0,
        questions: Vec::new(),
        answers: Vec::new(),
        partially_decoded: false,
    };

    for _ in 0..qd {
        if m.questions.len() >= MAX_QUESTIONS {
            // Positions of later sections are unknown without decoding every question.
            m.partially_decoded = true;
            return Ok(m);
        }
        let name = r.name()?;
        let qtype = r.u16()?;
        let _qclass = r.u16()?;
        m.questions.push(Question {
            name,
            qtype: type_name(qtype),
        });
    }

    for _ in 0..an {
        if m.answers.len() >= MAX_ANSWERS {
            m.partially_decoded = true;
            break;
        }
        let name = r.name()?;
        let rtype = r.u16()?;
        let _class = r.u16()?;
        let ttl = r.u32()?;
        let rdlen = usize::from(r.u16()?);
        let rdata_start = r.pos;
        let rdata = r.take(rdlen)?;
        let addr = match (rtype, rdata.len()) {
            (1, 4) => <[u8; 4]>::try_from(rdata)
                .ok()
                .map(|a| IpAddr::V4(Ipv4Addr::from(a))),
            (28, 16) => <[u8; 16]>::try_from(rdata)
                .ok()
                .map(|a| IpAddr::V6(Ipv6Addr::from(a))),
            _ => None,
        };
        let data = match rtype {
            1 | 28 => addr.map(|a| a.to_string()),
            2 | 5 | 12 => read_name(msg, rdata_start)
                .ok()
                .filter(|(_, end)| *end <= rdata_start + rdlen)
                .map(|(n, _)| n),
            _ => None,
        };
        m.answers.push(Answer {
            name,
            rtype: type_name(rtype),
            ttl,
            data,
            addr,
        });
    }
    Ok(m)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    pub fn encode_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// Query (or response, if `answers` is non-empty or `rcode` != 0) for `name`/A.
    pub fn build(
        id: u16,
        name: &str,
        response: bool,
        rcode: u8,
        answers: &[(u16, &[u8], u32)],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_be_bytes());
        let flags: u16 = if response {
            0x8180 | u16::from(rcode)
        } else {
            0x0100
        };
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        encode_name(&mut v, name);
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        for (rtype, rdata, ttl) in answers {
            v.extend_from_slice(&[0xC0, 12]); // pointer to the question name
            v.extend_from_slice(&rtype.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&ttl.to_be_bytes());
            v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            v.extend_from_slice(rdata);
        }
        v
    }

    #[test]
    fn query_and_response() {
        let q = parse(&build(7, "example.com", false, 0, &[])).unwrap();
        assert!(!q.is_response);
        assert_eq!(
            q.questions,
            vec![Question {
                name: "example.com".into(),
                qtype: "A".into()
            }]
        );

        let mut cname = Vec::new();
        encode_name(&mut cname, "edge.example.net");
        let r = parse(&build(
            7,
            "example.com",
            true,
            0,
            &[(5, &cname, 60), (1, &[93, 184, 216, 34], 300)],
        ))
        .unwrap();
        assert!(r.is_response);
        assert_eq!(r.rcode, "NOERROR");
        assert_eq!(r.answers[0].data.as_deref(), Some("edge.example.net"));
        assert_eq!(r.answers[1].name, "example.com");
        assert_eq!(r.answers[1].data.as_deref(), Some("93.184.216.34"));
        assert_eq!(r.answers[1].ttl, 300);
    }

    #[test]
    fn nxdomain() {
        let r = parse(&build(1, "nope.invalid", true, 3, &[])).unwrap();
        assert_eq!(r.rcode, "NXDOMAIN");
        assert!(r.answers.is_empty());
    }

    #[test]
    fn rejects_pointer_loops_and_forward_pointers() {
        let mut m = build(1, "a.b", false, 0, &[]);
        // Make the question name a pointer to itself (offset 12).
        m.truncate(12);
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(parse(&m), Err(DnsError::BadPointer));
        // Forward pointer.
        m.truncate(12);
        m.extend_from_slice(&[0xC0, 40, 0, 1, 0, 1]);
        assert_eq!(parse(&m), Err(DnsError::BadPointer));
    }

    #[test]
    fn rejects_long_names_and_bad_labels() {
        let long = vec!["a".repeat(63); 5].join(".");
        assert_eq!(
            parse(&build(1, &long, false, 0, &[])),
            Err(DnsError::NameTooLong)
        );
        let mut m = build(1, "a", false, 0, &[]);
        m[12] = 0x80; // reserved label type
        assert_eq!(parse(&m), Err(DnsError::BadLabel));
    }

    #[test]
    fn caps_question_count() {
        let mut m = build(1, "a", false, 0, &[]);
        m[4..6].copy_from_slice(&1000u16.to_be_bytes());
        for _ in 1..1000 {
            m.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        }
        let r = parse(&m).unwrap();
        assert_eq!(r.questions.len(), MAX_QUESTIONS);
        assert!(r.partially_decoded);
    }

    #[test]
    fn hostile_label_bytes_are_escaped() {
        let mut v = build(1, "x", false, 0, &[]);
        v.truncate(12);
        v.extend_from_slice(&[4, b'a', b' ', b'\n', b'.', 0, 0, 1, 0, 1]);
        assert_eq!(parse(&v).unwrap().questions[0].name, "a\\x20\\x0a\\x2e");
    }
}
