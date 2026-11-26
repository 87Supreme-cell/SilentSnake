//! Plain-English summaries. Every name in them has already been sanitized.

use crate::dns;
use crate::event::{
    Direction, EndReason, Endpoint, FlowInfo, NameSource, SourceInfo, StatsInfo, StopReason,
};

fn proto_upper(f: &FlowInfo) -> String {
    f.proto.to_uppercase()
}

fn noun(f: &FlowInfo) -> &'static str {
    if f.proto == "tcp" {
        "connection"
    } else {
        "traffic"
    }
}

fn service(f: &FlowInfo) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = f.service {
        parts.push(s.to_uppercase());
    }
    if let Some(n) = &f.server_name {
        let via = match f.server_name_source {
            Some(NameSource::Sni) => " via TLS",
            Some(NameSource::Dns) => " via DNS",
            None => "",
        };
        parts.push(format!("{n}{via}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

fn in_progress(f: &FlowInfo) -> &'static str {
    if f.initiator_inferred {
        " It was already in progress when capture started."
    } else {
        ""
    }
}

pub fn flow_start(f: &FlowInfo) -> String {
    let (p, n, i, r, s) = (
        proto_upper(f),
        noun(f),
        f.initiator,
        f.responder,
        service(f),
    );
    let body = match f.direction {
        Direction::Outbound => format!("New outbound {p} {n} from this machine ({i}) to {r}{s}."),
        Direction::Inbound => format!("New inbound {p} {n} from {i} to this machine ({r}){s}."),
        Direction::Local => format!("New local {p} {n} within this machine, {i} to {r}{s}."),
        Direction::Transit => {
            format!("New {p} {n} passing through, {i} to {r}{s}; neither end is this machine.")
        }
        Direction::Unknown => format!("New {p} {n} from {i} to {r}{s}."),
    };
    format!("{body}{}", in_progress(f))
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1000.0;
    let mut unit = UNITS[0];
    for u in UNITS.iter().skip(1) {
        if v < 1000.0 {
            break;
        }
        v /= 1000.0;
        unit = u;
    }
    format!("{v:.1} {unit}")
}

fn packets(n: u64) -> String {
    if n == 1 {
        "1 packet".into()
    } else {
        format!("{n} packets")
    }
}

fn duration(ms: i64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 120_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{:.1} min", ms as f64 / 60_000.0)
    }
}

pub struct EndStats {
    pub reason: EndReason,
    pub duration_ms: i64,
    pub init_packets: u64,
    pub init_bytes: u64,
    pub resp_packets: u64,
    pub resp_bytes: u64,
}

pub fn flow_end(f: &FlowInfo, e: &EndStats) -> String {
    let why = match e.reason {
        EndReason::Closed => "closed normally".to_string(),
        EndReason::Reset => "was reset".to_string(),
        EndReason::Idle => "went idle".to_string(),
        EndReason::Evicted => "was dropped from tracking to keep memory use bounded".to_string(),
        EndReason::CaptureEnd => "was still open when the capture file ended".to_string(),
        EndReason::CaptureStopped => "was still open when capture stopped".to_string(),
    };
    let target = match &f.server_name {
        Some(n) => format!("{n} ({})", f.responder),
        None => f.responder.to_string(),
    };
    let (p, n, d) = (proto_upper(f), noun(f), duration(e.duration_ms));
    let sent_i = format!("{} in {}", bytes(e.init_bytes), packets(e.init_packets));
    let sent_r = format!("{} in {}", bytes(e.resp_bytes), packets(e.resp_packets));
    match f.direction {
        Direction::Outbound => {
            format!(
                "Outbound {p} {n} to {target} {why} after {d}: this machine sent {sent_i} and received {sent_r}."
            )
        }
        Direction::Inbound => format!(
            "Inbound {p} {n} from {} to this machine ({target}) {why} after {d}: this machine received {sent_i} and sent {sent_r}.",
            f.initiator
        ),
        _ => format!(
            "{p} {n} from {} to {target} {why} after {d}: the initiator sent {sent_i}, the responder sent {sent_r}.",
            f.initiator
        ),
    }
}

fn rcode_meaning(r: &str) -> &'static str {
    match r {
        "NXDOMAIN" => " (the name does not exist)",
        "SERVFAIL" => " (the server could not answer)",
        "REFUSED" => " (the server refused the query)",
        "FORMERR" => " (the server could not parse the query)",
        _ => "",
    }
}

pub fn dns(label: &str, client: &Endpoint, server: &Endpoint, m: &dns::Message) -> String {
    let what = match m.questions.first() {
        Some(q) => format!("{} ({})", q.name, q.qtype),
        None => "a record".to_string(),
    };
    let label = label.to_uppercase();
    if !m.is_response {
        return format!("{label} query for {what} from {client} to {server}.");
    }
    if m.rcode != "NOERROR" {
        return format!(
            "{label} lookup for {what} failed: {}{}.",
            m.rcode,
            rcode_meaning(&m.rcode)
        );
    }
    let data: Vec<&str> = m.answers.iter().filter_map(|a| a.data.as_deref()).collect();
    let shown = match data.len() {
        0 => "no records".to_string(),
        1..=4 => data.join(", "),
        n => format!(
            "{} and {} more",
            data.get(..4).unwrap_or_default().join(", "),
            n - 4
        ),
    };
    let trunc = if m.truncated_by_server {
        " The answer was truncated; the client may retry over TCP."
    } else {
        ""
    };
    format!("{label} answer from {server} for {what}: {shown}.{trunc}")
}

pub fn tls(server: &Endpoint, server_name: Option<&str>, ech: bool, anomalies: &[&str]) -> String {
    let mut s = match server_name {
        Some(n) => format!(
            "TLS handshake started to {n} ({server}); the server name was read from the ClientHello."
        ),
        None => format!("TLS handshake started to {server} without a server name."),
    };
    if ech {
        s.push_str(" Encrypted Client Hello is in use, so the visible name may be a front for the real destination.");
    }
    if !anomalies.is_empty() {
        s.push_str(&format!(" Unusual: {}.", anomalies.join(", ")));
    }
    s
}

fn dropped_warning(st: &StatsInfo) -> String {
    // u64 sum: two u32 counters near their limit must not overflow (ADV-0013).
    let dropped =
        u64::from(st.kernel_dropped.unwrap_or(0)) + u64::from(st.interface_dropped.unwrap_or(0));
    let unprocessed = st.counters.packets_unprocessed_at_stop;
    match (dropped > 0, unprocessed > 0) {
        (true, false) => format!(
            " Warning: {dropped} packets were dropped before SilentSnake saw them, so this record is incomplete."
        ),
        (false, true) => format!(
            " Warning: {unprocessed} packets captured before the stop were not processed, so this record is incomplete."
        ),
        (true, true) => format!(
            " Warning: {dropped} packets were dropped before SilentSnake saw them and {unprocessed} captured before the stop were not processed, so this record is incomplete."
        ),
        (false, false) => String::new(),
    }
}

pub fn stats(st: &StatsInfo) -> String {
    let dropped = match st.kernel_dropped {
        Some(d) => format!(", {d} dropped by the kernel"),
        None => String::new(),
    };
    format!(
        "Engine health: {} packets ({}) seen{dropped}, {} active flows, {} flows so far.{}",
        st.counters.packets_seen,
        bytes(st.counters.bytes_seen),
        st.flows_active,
        st.counters.flows_started,
        dropped_warning(st)
    )
}

pub fn engine_start(src: &SourceInfo) -> String {
    let filter = match &src.filter {
        Some(f) => format!(" with filter \"{}\"", f.escape_default()),
        None => " with no filter".to_string(),
    };
    match src.kind {
        "live" if src.name == "any" => format!("Live capture started on all interfaces{filter}."),
        "live" => format!(
            "Live capture started on interface {}{filter}.",
            src.name.escape_default()
        ),
        _ => format!(
            "Reading capture file {}{filter}.",
            src.name.escape_default()
        ),
    }
}

pub fn engine_stop(reason: StopReason, st: &StatsInfo) -> String {
    let why = match reason {
        StopReason::Duration => "the requested duration elapsed",
        StopReason::PacketCount => "the requested packet count was reached",
        StopReason::EndOfFile => "the capture file ended",
        StopReason::OutputClosed => "the output was closed",
    };
    format!(
        "Capture stopped because {why}: {} packets seen, {} flows recorded.{}",
        st.counters.packets_seen,
        st.counters.flows_started,
        dropped_warning(st)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Counters;

    #[test]
    fn byte_units() {
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(3_200), "3.2 KB");
        assert_eq!(bytes(48_100_000), "48.1 MB");
    }

    #[test]
    fn unprocessed_at_stop_marks_the_record_incomplete() {
        // ADV-0032: a backlog left in the ring at stop is not a kernel drop, but it must still
        // be reported as an incomplete record.
        let mut st = StatsInfo {
            counters: Counters::default(),
            flows_active: 0,
            kernel_received: Some(80_000),
            kernel_dropped: Some(0),
            interface_dropped: Some(0),
        };
        assert!(dropped_warning(&st).is_empty());
        st.counters.packets_unprocessed_at_stop = 39_814;
        let w = engine_stop(StopReason::Duration, &st);
        assert!(w.contains("39814 packets captured before the stop were not processed"));
        assert!(w.contains("incomplete"));
        st.kernel_dropped = Some(5);
        let w = dropped_warning(&st);
        assert!(
            w.contains("5 packets were dropped") && w.contains("39814 captured before the stop")
        );
    }
}
