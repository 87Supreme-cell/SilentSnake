//! Event schema `silentsnake.capture/1`, emitted as one JSON object per line.
//! Documented in `docs/api/capture-events.md`; any breaking change bumps the schema version.

use crate::dns;
use crate::time::Ts;
use serde::Serialize;
use std::fmt;
use std::net::IpAddr;

pub const SCHEMA: &str = "silentsnake.capture/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ip, self.port) {
            (ip, 0) => write!(f, "{ip}"),
            (IpAddr::V6(ip), port) => write!(f, "[{ip}]:{port}"),
            (ip, port) => write!(f, "{ip}:{port}"),
        }
    }
}

/// Direction relative to this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Started by this machine to another host.
    Outbound,
    /// Started by another host to this machine.
    Inbound,
    /// Both ends are this machine (loopback or own addresses).
    Local,
    /// Neither end is this machine (forwarded or promiscuous traffic).
    Transit,
    /// This machine's addresses are not known (e.g. reading a file without `--local-addr`).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    /// From the TLS ClientHello server_name extension.
    Sni,
    /// From an earlier DNS answer for the responder's address.
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowInfo {
    pub flow_id: u64,
    pub proto: String,
    pub direction: Direction,
    pub initiator: Endpoint,
    pub responder: Endpoint,
    /// True when the flow was already running when capture started, so which side started it
    /// is a guess from port numbers.
    pub initiator_inferred: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name_source: Option<NameSource>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// TCP FIN from both sides.
    Closed,
    /// TCP RST.
    Reset,
    /// No packets for the idle timeout.
    Idle,
    /// Dropped from the flow table to keep memory bounded.
    Evicted,
    /// The capture file ended.
    CaptureEnd,
    /// Live capture was stopped.
    CaptureStopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Duration,
    PacketCount,
    EndOfFile,
    OutputClosed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub packets_seen: u64,
    pub bytes_seen: u64,
    pub packets_non_ip: u64,
    pub packets_fragmented: u64,
    pub packets_undecoded: u64,
    pub packets_unsupported_link: u64,
    pub packets_after_close: u64,
    pub flows_started: u64,
    pub flows_ended: u64,
    pub flows_evicted: u64,
    pub dns_messages: u64,
    pub dns_parse_errors: u64,
    pub tls_client_hellos: u64,
    pub tls_unparsed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatsInfo {
    #[serde(flatten)]
    pub counters: Counters,
    pub flows_active: usize,
    /// libpcap kernel counters (live capture only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_received: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_dropped: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_dropped: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceInfo {
    /// `live` or `file`.
    pub kind: &'static str,
    pub name: String,
    pub link_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    pub euid: u32,
    pub cap_net_raw: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventBody {
    EngineStart {
        version: &'static str,
        source: SourceInfo,
    },
    FlowStart {
        #[serde(flatten)]
        flow: FlowInfo,
    },
    FlowEnd {
        #[serde(flatten)]
        flow: FlowInfo,
        reason: EndReason,
        duration_ms: i64,
        initiator_packets: u64,
        initiator_bytes: u64,
        responder_packets: u64,
        responder_bytes: u64,
    },
    Dns {
        flow_id: u64,
        /// `dns`, `mdns` or `llmnr`.
        protocol: &'static str,
        client: Endpoint,
        server: Endpoint,
        #[serde(flatten)]
        message: dns::Message,
    },
    TlsClientHello {
        flow_id: u64,
        client: Endpoint,
        server: Endpoint,
        server_name: Option<String>,
        ech: bool,
        anomalies: Vec<&'static str>,
    },
    Stats {
        #[serde(flatten)]
        stats: StatsInfo,
    },
    EngineStop {
        reason: StopReason,
        #[serde(flatten)]
        stats: StatsInfo,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub ts: Ts,
    pub body: EventBody,
    /// Plain-English description for people (and the UI); the structured fields are authoritative.
    pub summary: String,
}

/// The on-the-wire shape: `{schema, seq, ts, type, ...fields, summary}`.
#[derive(Serialize)]
pub struct Envelope<'a> {
    pub schema: &'static str,
    /// Gap-free sequence number per engine run; a gap means lost events.
    pub seq: u64,
    pub ts: Ts,
    #[serde(flatten)]
    pub body: &'a EventBody,
    pub summary: &'a str,
}
