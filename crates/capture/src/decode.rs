//! Link-layer dispatch and header decoding (via `etherparse`) down to IP + transport.

#![deny(clippy::indexing_slicing)]

use etherparse::{EtherType, NetSlice, SlicedPacket, TransportSlice};
use std::net::IpAddr;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

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
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<'a> {
    Ip(Decoded<'a>),
    /// ARP and other non-IP frames.
    NonIp,
    /// IP fragments: not reassembled in stage A, counted only.
    Fragment,
    /// Headers that don't parse (truncated, corrupt or hostile).
    Malformed,
    UnsupportedLink,
}

fn slice(link: LinkType, data: &[u8]) -> Option<Result<SlicedPacket<'_>, ()>> {
    let r = match link {
        LinkType::Ethernet => SlicedPacket::from_ethernet(data),
        LinkType::LinuxSll => SlicedPacket::from_linux_sll(data),
        LinkType::LinuxSll2 => {
            // 20-byte header; the first two bytes are the EtherType of the payload.
            let (Some(proto), Some(rest)) = (data.get(..2), data.get(20..)) else {
                return Some(Err(()));
            };
            let et = u16::from_be_bytes([*proto.first()?, *proto.get(1)?]);
            SlicedPacket::from_ether_type(EtherType(et), rest)
        }
        LinkType::Raw => SlicedPacket::from_ip(data),
        LinkType::Null => match data.get(4..) {
            Some(rest) => SlicedPacket::from_ip(rest),
            None => return Some(Err(())),
        },
        LinkType::Unsupported(_) => return None,
    };
    Some(r.map_err(|_| ()))
}

pub fn decode(link: LinkType, data: &[u8]) -> Outcome<'_> {
    let sliced = match slice(link, data) {
        None => return Outcome::UnsupportedLink,
        Some(Err(())) => return Outcome::Malformed,
        Some(Ok(s)) => s,
    };
    let (src, dst, ip_payload) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                v4.payload(),
            )
        }
        Some(NetSlice::Ipv6(v6)) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                v6.payload(),
            )
        }
        Some(NetSlice::Arp(_)) | None => return Outcome::NonIp,
    };
    if ip_payload.fragmented {
        return Outcome::Fragment;
    }
    let proto = ip_payload.ip_number.0;
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
        Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port(), None, u.payload()),
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
