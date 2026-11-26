//! Link-layer dispatch and header decoding (via `etherparse`) down to IP + transport.

#![deny(clippy::indexing_slicing)]

use etherparse::{EtherType, LaxNetSlice, LaxSlicedPacket, LenSource, TransportSlice};
use std::net::IpAddr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;
const UDP_HEADER_LEN: usize = 8;

/// Capture link types SilentSnake decodes (libpcap DLT_* / LINKTYPE_* values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// BSD loopback (4-byte address family header); appears in files from other systems.
    Null,
    Ethernet,
    /// Raw IP (no link header).
    Raw,
    /// Linux "cooked" capture v1 (the `any` pseudo-interface).
    LinuxSll,
    /// Linux "cooked" capture v2.
    LinuxSll2,
    Unsupported(i32),
}

impl LinkType {
    pub fn from_dlt(v: i32) -> Self {
        match v {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            12 | 14 | 101 | 228 | 229 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            other => LinkType::Unsupported(other),
        }
    }

    pub fn name(&self) -> String {
        match self {
            LinkType::Null => "null".into(),
            LinkType::Ethernet => "ethernet".into(),
            LinkType::Raw => "raw-ip".into(),
            LinkType::LinuxSll => "linux-sll".into(),
            LinkType::LinuxSll2 => "linux-sll2".into(),
            LinkType::Unsupported(v) => format!("unsupported-{v}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub seq: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub tcp: Option<TcpInfo>,
    /// Captured transport payload (may be shorter than on the wire if `truncated`).
    pub payload: &'a [u8],
    /// The packet was cut short by the snaplen; counts use the on-wire length regardless.
    pub truncated: bool,
    /// Whole UDP datagram whose length field is shorter than its IP payload: Linux trims and
    /// delivers it, so it is decoded, but the bytes after `ulen` are a known evasion trick.
    pub udp_trailing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<'a> {
    Ip(Decoded<'a>),
    /// ARP and other non-IP frames.
    NonIp,
    /// IP fragments: not reassembled in stage A, counted only.
    Fragment,
    /// Headers that don't parse (corrupt, hostile, or cut inside a header).
    Malformed,
    UnsupportedLink,
}

/// Slices with etherparse's *lax* parser: a packet cut short by the snaplen (common for
/// outgoing GSO super-packets) still yields its headers and the captured part of its payload,
/// instead of failing as malformed (ADV-0002).
fn slice(link: LinkType, data: &[u8]) -> Option<Result<LaxSlicedPacket<'_>, ()>> {
    fn ether_type_at(data: &[u8], at: usize) -> Option<EtherType> {
        let b = data.get(at..at + 2)?;
        Some(EtherType(u16::from_be_bytes([*b.first()?, *b.get(1)?])))
    }
    let r = match link {
        LinkType::Ethernet => LaxSlicedPacket::from_ethernet(data).map_err(|_| ()),
        // Linux cooked v1: 16-byte header, protocol (EtherType) in bytes 14..16.
        LinkType::LinuxSll => match (ether_type_at(data, 14), data.get(16..)) {
            (Some(et), Some(rest)) => Ok(LaxSlicedPacket::from_ether_type(et, rest)),
            _ => Err(()),
        },
        // Linux cooked v2: 20-byte header, protocol (EtherType) in bytes 0..2.
        LinkType::LinuxSll2 => match (ether_type_at(data, 0), data.get(20..)) {
            (Some(et), Some(rest)) => Ok(LaxSlicedPacket::from_ether_type(et, rest)),
            _ => Err(()),
        },
        LinkType::Raw => LaxSlicedPacket::from_ip(data).map_err(|_| ()),
        LinkType::Null => match data.get(4..) {
            Some(rest) => LaxSlicedPacket::from_ip(rest).map_err(|_| ()),
            None => Err(()),
        },
        LinkType::Unsupported(_) => return None,
    };
    Some(r)
}

/// `cut` is true when the capture truncated the packet (captured length < on-wire length).
/// Only then are incomplete layers accepted. A packet that arrived whole but whose length
/// fields lie, or whose headers stop parsing, is one the host's own stack would drop, so it is
/// Malformed and creates no flow, DNS name or SNI (ADV-0025).
pub fn decode(link: LinkType, data: &[u8], cut: bool) -> Outcome<'_> {
    let sliced = match slice(link, data) {
        None => return Outcome::UnsupportedLink,
        Some(Err(())) => return Outcome::Malformed,
        Some(Ok(s)) => s,
    };
    if !cut && sliced.stop_err.is_some() {
        return Outcome::Malformed;
    }
    let (src, dst, ip_payload) = match &sliced.net {
        Some(LaxNetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                v4.payload(),
            )
        }
        Some(LaxNetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                v6.payload(),
            )
        }
        Some(LaxNetSlice::Arp(_)) | None => return Outcome::NonIp,
    };
    if ip_payload.fragmented {
        return Outcome::Fragment;
    }
    if !cut {
        // Whole packet: the IP header's own length field must have been usable. Lax parsing
        // silently falls back to the captured length when it isn't (e.g. IPv4 total length
        // smaller than the header), which the kernel would reject.
        let expected = match &sliced.net {
            Some(LaxNetSlice::Ipv4(_)) => LenSource::Ipv4HeaderTotalLen,
            _ => LenSource::Ipv6HeaderPayloadLen,
        };
        if ip_payload.incomplete || ip_payload.len_source != expected {
            return Outcome::Malformed;
        }
    }
    let proto = ip_payload.ip_number.0;
    let truncated = ip_payload.incomplete;
    let mut udp_trailing = false;
    let (sport, dport, tcp, payload): (u16, u16, Option<TcpInfo>, &[u8]) = match &sliced.transport {
        Some(TransportSlice::Tcp(t)) => (
            t.source_port(),
            t.destination_port(),
            Some(TcpInfo {
                syn: t.syn(),
                ack: t.ack(),
                fin: t.fin(),
                rst: t.rst(),
                seq: t.sequence_number(),
            }),
            t.payload(),
        ),
        // Match Linux `__udp4_lib_rcv` / `udpv6_rcv` (ADV-0025, ADV-0029): a UDP length below
        // the header size is dropped, and so is a whole datagram claiming more than its IP
        // payload. A shorter claim is trimmed to `ulen` and *delivered*, so it must decode
        // (lax parsing already slices the payload to `ulen`), flagged as trailing bytes.
        Some(TransportSlice::Udp(u)) => {
            let ulen = usize::from(u.length());
            let ip_len = ip_payload.payload.len();
            if ulen < UDP_HEADER_LEN || (!cut && ulen > ip_len) {
                return Outcome::Malformed;
            }
            udp_trailing = !cut && ulen < ip_len;
            (u.source_port(), u.destination_port(), None, u.payload())
        }
        // A TCP/UDP header we couldn't read would make a bogus port-0 flow: count it instead.
        None if proto == PROTO_TCP || proto == PROTO_UDP => return Outcome::Malformed,
        _ => (0, 0, None, &[]),
    };
    Outcome::Ip(Decoded {
        src,
        dst,
        proto,
        sport,
        dport,
        tcp,
        payload,
        truncated,
        udp_trailing,
    })
}

pub fn proto_name(p: u8) -> String {
    match p {
        PROTO_ICMP => "icmp".into(),
        PROTO_TCP => "tcp".into(),
        PROTO_UDP => "udp".into(),
        PROTO_ICMPV6 => "icmpv6".into(),
        2 => "igmp".into(),
        47 => "gre".into(),
        50 => "esp".into(),
        132 => "sctp".into(),
        other => format!("ip-proto-{other}"),
    }
}

/// Port-based service hint for the responder side of a flow. A hint, not an identification.
pub fn service_hint(proto: u8, port: u16) -> Option<&'static str> {
    let tcp = proto == PROTO_TCP;
    let udp = proto == PROTO_UDP;
    Some(match port {
        20 | 21 if tcp => "ftp",
        22 if tcp => "ssh",
        23 if tcp => "telnet",
        25 if tcp => "smtp",
        53 => "dns",
        67 | 68 if udp => "dhcp",
        80 if tcp => "http",
        110 if tcp => "pop3",
        123 if udp => "ntp",
        143 if tcp => "imap",
        443 if tcp => "https",
        443 if udp => "quic",
        465 if tcp => "smtps",
        546 | 547 if udp => "dhcpv6",
        587 if tcp => "smtp-submission",
        631 => "ipp",
        853 if tcp => "dns-over-tls",
        853 if udp => "dns-over-quic",
        993 if tcp => "imaps",
        995 if tcp => "pop3s",
        1900 if udp => "ssdp",
        3389 => "rdp",
        5353 if udp => "mdns",
        5355 => "llmnr",
        8080 if tcp => "http-alt",
        8443 if tcp => "https-alt",
        _ => return None,
    })
}
