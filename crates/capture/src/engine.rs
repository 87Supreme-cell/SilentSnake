//! Flow tracking, DNS/TLS extraction and event generation. Independent of libpcap so it can be
//! tested and fuzzed with plain byte slices.
//!
//! Memory is bounded: at most `max_flows` flows, `dns_cache_max` cached names, and
//! `max_tls_collecting` flows buffering a ClientHello (each at most [`MAX_TLS_BUFFER`] bytes).

use crate::decode::{self, Decoded, LinkType, Outcome, PROTO_TCP, PROTO_UDP};
use crate::dns;
use crate::event::{
    Counters, Direction, EndReason, Endpoint, Event, EventBody, FlowInfo, NameSource, StatsInfo,
};
use crate::summary::{self, EndStats};
use crate::time::Ts;
use crate::tls;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

pub const MAX_TLS_BUFFER: usize = tls::MAX_HANDSHAKE + 1024;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub max_flows: usize,
    pub tcp_idle_secs: i64,
    pub udp_idle_secs: i64,
    pub other_idle_secs: i64,
    /// How long a closed TCP flow absorbs late packets (final ACKs, retransmits).
    pub close_linger_secs: i64,
    pub dns_cache_max: usize,
    pub max_tls_collecting: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            max_flows: 65_536,
            tcp_idle_secs: 300,
            udp_idle_secs: 60,
            other_idle_secs: 30,
            close_linger_secs: 10,
            dns_cache_max: 16_384,
            max_tls_collecting: 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    a: (IpAddr, u16),
    b: (IpAddr, u16),
}

impl FlowKey {
    fn new(proto: u8, x: (IpAddr, u16), y: (IpAddr, u16)) -> Self {
        if x <= y {
            FlowKey { proto, a: x, b: y }
        } else {
            FlowKey { proto, a: y, b: x }
        }
    }
}

#[derive(Debug)]
enum TlsState {
    Pending,
    Collecting { next_seq: u32, buf: Vec<u8> },
    Done,
}

#[derive(Debug)]
struct Flow {
    info: FlowInfo,
    first_seen: Ts,
    last_seen: Ts,
    init_packets: u64,
    init_bytes: u64,
    resp_packets: u64,
    resp_bytes: u64,
    fin_init: bool,
    fin_resp: bool,
    closed_at: Option<Ts>,
    tls: TlsState,
}

#[derive(Debug, Default)]
struct LocalAddrs {
    set: HashSet<IpAddr>,
    known: bool,
}

fn is_group(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        IpAddr::V6(a) => a.is_multicast(),
    }
}

impl LocalAddrs {
    fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.set.contains(&ip)
    }

    fn classify(&self, init: IpAddr, resp: IpAddr) -> Direction {
        let li = self.is_local(init);
        if is_group(resp) {
            return if li {
                Direction::Outbound
            } else if self.known {
                Direction::Inbound
            } else {
                Direction::Unknown
            };
        }
        match (li, self.is_local(resp)) {
            (true, true) => Direction::Local,
            (true, false) => Direction::Outbound,
            (false, true) => Direction::Inbound,
            (false, false) if self.known => Direction::Transit,
            (false, false) => Direction::Unknown,
        }
    }
}

pub struct Engine {
    cfg: EngineConfig,
    flows: HashMap<FlowKey, Flow>,
    dns_cache: HashMap<IpAddr, (String, Ts)>,
    local: LocalAddrs,
    counters: Counters,
    next_flow_id: u64,
    last_tick: Ts,
    latest: Ts,
    tls_collecting: usize,
}

fn dns_label(sport: u16, dport: u16) -> Option<&'static str> {
    match (sport, dport) {
        (53, _) | (_, 53) => Some("dns"),
        (5353, _) | (_, 5353) => Some("mdns"),
        (5355, _) | (_, 5355) => Some("llmnr"),
        _ => None,
    }
}

/// Which side started the flow, and whether that is a guess.
fn initiator_is_src(d: &Decoded<'_>) -> (bool, bool) {
    let (s, t) = (d.sport, d.dport);
    match d.tcp {
        Some(f) if f.syn && !f.ack => (true, false),
        Some(f) if f.syn && f.ack => (false, false),
        Some(_) => {
            // Mid-stream: the well-known or lower port is usually the server.
            if s < 1024 && t >= 1024 {
                (false, true)
            } else if t < 1024 && s >= 1024 {
                (true, true)
            } else {
                (s >= t, true)
            }
        }
        None if d.proto == PROTO_UDP && s < 1024 && t >= 1024 => (false, true),
        None => (true, false),
    }
}

fn end_event(f: &Flow, reason: EndReason) -> Event {
    let e = EndStats {
        reason,
        duration_ms: f.last_seen.millis_since(f.first_seen).max(0),
        init_packets: f.init_packets,
        init_bytes: f.init_bytes,
        resp_packets: f.resp_packets,
        resp_bytes: f.resp_bytes,
    };
    Event {
        ts: f.last_seen,
        summary: summary::flow_end(&f.info, &e),
        body: EventBody::FlowEnd {
            flow: f.info.clone(),
            reason,
            duration_ms: e.duration_ms,
            initiator_packets: e.init_packets,
            initiator_bytes: e.init_bytes,
            responder_packets: e.resp_packets,
            responder_bytes: e.resp_bytes,
        },
    }
}

/// Releases a flow's ClientHello buffer and its slot in the global budget.
fn release_tls(state: &mut TlsState, collecting: &mut usize) {
    if matches!(state, TlsState::Collecting { .. }) {
        *collecting = collecting.saturating_sub(1);
    }
    *state = TlsState::Done;
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Self {
        Engine {
            cfg,
            flows: HashMap::new(),
            dns_cache: HashMap::new(),
            local: LocalAddrs::default(),
            counters: Counters::default(),
            next_flow_id: 1,
            last_tick: Ts::default(),
            latest: Ts::default(),
            tls_collecting: 0,
        }
    }

    /// Sets this machine's addresses (loopback is always local). Enables direction labels.
    pub fn set_local_addrs<I: IntoIterator<Item = IpAddr>>(&mut self, addrs: I) {
        self.local.set = addrs.into_iter().collect();
        self.local.known = true;
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn active_flows(&self) -> usize {
        self.flows
            .values()
            .filter(|f| f.closed_at.is_none())
            .count()
    }

    /// Latest packet timestamp seen.
    pub fn latest(&self) -> Ts {
        self.latest
    }

    pub fn tls_buffers_in_use(&self) -> usize {
        self.tls_collecting
    }

    pub fn stats(&self, kernel: Option<(u32, u32, u32)>) -> StatsInfo {
        StatsInfo {
            counters: self.counters.clone(),
            flows_active: self.active_flows(),
            kernel_received: kernel.map(|k| k.0),
            kernel_dropped: kernel.map(|k| k.1),
            interface_dropped: kernel.map(|k| k.2),
        }
    }

    pub fn stats_event(&self, ts: Ts, kernel: Option<(u32, u32, u32)>) -> Event {
        let stats = self.stats(kernel);
        Event {
            ts,
            summary: summary::stats(&stats),
            body: EventBody::Stats { stats },
        }
    }

    /// Feeds one captured packet. `wire_len` is the original length on the wire.
    pub fn process(
        &mut self,
        ts: Ts,
        link: LinkType,
        data: &[u8],
        wire_len: u32,
        out: &mut Vec<Event>,
    ) {
        self.counters.packets_seen += 1;
        self.counters.bytes_seen += u64::from(wire_len);
        if ts > self.latest {
            self.latest = ts;
        }
        match decode::decode(link, data) {
            Outcome::Ip(d) => self.handle_ip(ts, &d, u64::from(wire_len), out),
            Outcome::NonIp => self.counters.packets_non_ip += 1,
            Outcome::Fragment => self.counters.packets_fragmented += 1,
            Outcome::Malformed => self.counters.packets_undecoded += 1,
            Outcome::UnsupportedLink => self.counters.packets_unsupported_link += 1,
        }
        if ts.millis_since(self.last_tick) >= 1000 {
            self.tick(ts, out);
        }
    }

    /// Expires idle flows and stale DNS names. Safe to call often; time never goes backwards.
    pub fn tick(&mut self, now: Ts, out: &mut Vec<Event>) {
        if now < self.last_tick {
            return;
        }
        self.last_tick = now;
        self.expire(now, out);
        self.dns_cache.retain(|_, (_, exp)| *exp > now);
    }

    /// Ends every open flow (capture finished) and clears all state.
    pub fn flush(&mut self, reason: EndReason, out: &mut Vec<Event>) {
        let mut ended: Vec<Flow> = self
            .flows
            .drain()
            .map(|(_, f)| f)
            .filter(|f| f.closed_at.is_none())
            .collect();
        ended.sort_by_key(|f| f.info.flow_id);
        for f in &ended {
            out.push(end_event(f, reason));
            self.counters.flows_ended += 1;
        }
        self.tls_collecting = 0;
    }

    fn expire(&mut self, now: Ts, out: &mut Vec<Event>) {
        let cfg = &self.cfg;
        let counters = &mut self.counters;
        let collecting = &mut self.tls_collecting;
        let mut ended: Vec<Event> = Vec::new();
        self.flows.retain(|_, f| {
            if let Some(c) = f.closed_at {
                return now.millis_since(c) < cfg.close_linger_secs * 1000;
            }
            let idle = match f.info.proto.as_str() {
                "tcp" => cfg.tcp_idle_secs,
                "udp" => cfg.udp_idle_secs,
                _ => cfg.other_idle_secs,
            };
            if now.millis_since(f.last_seen) < idle * 1000 {
                return true;
            }
            release_tls(&mut f.tls, collecting);
            ended.push(end_event(f, EndReason::Idle));
            counters.flows_ended += 1;
            false
        });
        ended.sort_by_key(|e| match &e.body {
            EventBody::FlowEnd { flow, .. } => flow.flow_id,
            _ => 0,
        });
        out.append(&mut ended);
    }

    fn ensure_capacity(&mut self, now: Ts, out: &mut Vec<Event>) {
        if self.flows.len() < self.cfg.max_flows {
            return;
        }
        self.expire(now, out);
        if self.flows.len() < self.cfg.max_flows {
            return;
        }
        // Evict a batch (closed flows first, then least recently seen) so this stays amortized O(1).
        let mut order: Vec<(bool, Ts, FlowKey)> = self
            .flows
            .iter()
            .map(|(k, f)| (f.closed_at.is_none(), f.last_seen, *k))
            .collect();
        order.sort_unstable_by_key(|(open, last, _)| (*open, *last));
        let n = (self.flows.len() / 16).max(1);
        for (_, _, key) in order.into_iter().take(n) {
            if let Some(mut f) = self.flows.remove(&key) {
                release_tls(&mut f.tls, &mut self.tls_collecting);
                if f.closed_at.is_none() {
                    out.push(end_event(&f, EndReason::Evicted));
                    self.counters.flows_evicted += 1;
                    self.counters.flows_ended += 1;
                }
            }
        }
    }

    fn new_flow(&mut self, ts: Ts, d: &Decoded<'_>) -> Flow {
        let (src_is_init, inferred) = initiator_is_src(d);
        let src = Endpoint {
            ip: d.src,
            port: d.sport,
        };
        let dst = Endpoint {
            ip: d.dst,
            port: d.dport,
        };
        let (initiator, responder) = if src_is_init { (src, dst) } else { (dst, src) };
        let name = self
            .dns_cache
            .get(&responder.ip)
            .filter(|(_, exp)| *exp > ts)
            .map(|(n, _)| n.clone());
        let id = self.next_flow_id;
        self.next_flow_id += 1;
        Flow {
            info: FlowInfo {
                flow_id: id,
                proto: decode::proto_name(d.proto),
                direction: self.local.classify(initiator.ip, responder.ip),
                initiator,
                responder,
                initiator_inferred: inferred,
                service: decode::service_hint(d.proto, responder.port),
                server_name_source: name.as_ref().map(|_| NameSource::Dns),
                server_name: name,
            },
            first_seen: ts,
            last_seen: ts,
            init_packets: 0,
            init_bytes: 0,
            resp_packets: 0,
            resp_bytes: 0,
            fin_init: false,
            fin_resp: false,
            closed_at: None,
            tls: if d.proto == PROTO_TCP {
                TlsState::Pending
            } else {
                TlsState::Done
            },
        }
    }

    fn handle_ip(&mut self, ts: Ts, d: &Decoded<'_>, wire_len: u64, out: &mut Vec<Event>) {
        let key = FlowKey::new(d.proto, (d.src, d.sport), (d.dst, d.dport));
        let syn_only = d.tcp.is_some_and(|t| t.syn && !t.ack);

        if let Some(f) = self.flows.get(&key)
            && f.closed_at.is_some()
        {
            if syn_only {
                self.flows.remove(&key); // port reuse: a new connection on the same 4-tuple
            } else {
                self.counters.packets_after_close += 1;
                return;
            }
        }

        if !self.flows.contains_key(&key) {
            self.ensure_capacity(ts, out);
            let flow = self.new_flow(ts, d);
            out.push(Event {
                ts,
                summary: summary::flow_start(&flow.info),
                body: EventBody::FlowStart {
                    flow: flow.info.clone(),
                },
            });
            self.flows.insert(key, flow);
            self.counters.flows_started += 1;
        }

        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        let from_init = flow.info.initiator.ip == d.src && flow.info.initiator.port == d.sport;
        if from_init {
            flow.init_packets += 1;
            flow.init_bytes += wire_len;
        } else {
            flow.resp_packets += 1;
            flow.resp_bytes += wire_len;
        }
        flow.last_seen = ts;

        // TLS ClientHello from the initiator.
        if let Some(t) = d.tcp
            && from_init
            && !d.payload.is_empty()
            && let Some(ch) = feed_tls(
                &mut flow.tls,
                t.seq,
                d.payload,
                &mut self.counters,
                &mut self.tls_collecting,
                self.cfg.max_tls_collecting,
            )
        {
            if let Some(n) = &ch.server_name {
                flow.info.server_name = Some(n.clone());
                flow.info.server_name_source = Some(NameSource::Sni);
            }
            let (client, server) = (flow.info.initiator, flow.info.responder);
            out.push(Event {
                ts,
                summary: summary::tls(&server, ch.server_name.as_deref(), ch.ech, &ch.anomalies),
                body: EventBody::TlsClientHello {
                    flow_id: flow.info.flow_id,
                    client,
                    server,
                    server_name: ch.server_name,
                    ech: ch.ech,
                    anomalies: ch.anomalies,
                },
            });
        }

        // DNS / mDNS / LLMNR over UDP.
        let mut learned: Vec<(IpAddr, String, Ts)> = Vec::new();
        if d.proto == PROTO_UDP
            && let Some(label) = dns_label(d.sport, d.dport)
        {
            match dns::parse(d.payload) {
                Ok(msg) => {
                    self.counters.dns_messages += 1;
                    let (client, server) = if msg.is_response {
                        (
                            Endpoint {
                                ip: d.dst,
                                port: d.dport,
                            },
                            Endpoint {
                                ip: d.src,
                                port: d.sport,
                            },
                        )
                    } else {
                        (
                            Endpoint {
                                ip: d.src,
                                port: d.sport,
                            },
                            Endpoint {
                                ip: d.dst,
                                port: d.dport,
                            },
                        )
                    };
                    if msg.is_response && msg.rcode == "NOERROR" {
                        let qname = msg.questions.first().map(|q| q.name.clone());
                        for a in &msg.answers {
                            if let Some(ip) = a.addr {
                                let ttl = i64::from(a.ttl).clamp(60, 3600);
                                let name = qname.clone().unwrap_or_else(|| a.name.clone());
                                learned.push((ip, name, ts.plus_secs(ttl)));
                            }
                        }
                    }
                    out.push(Event {
                        ts,
                        summary: summary::dns(label, &client, &server, &msg),
                        body: EventBody::Dns {
                            flow_id: flow.info.flow_id,
                            protocol: label,
                            client,
                            server,
                            message: msg,
                        },
                    });
                }
                Err(_) => self.counters.dns_parse_errors += 1,
            }
        }

        // TCP teardown.
        if let Some(t) = d.tcp {
            let mut reason = None;
            if t.rst {
                reason = Some(EndReason::Reset);
            } else if t.fin {
                if from_init {
                    flow.fin_init = true;
                } else {
                    flow.fin_resp = true;
                }
                if flow.fin_init && flow.fin_resp {
                    reason = Some(EndReason::Closed);
                }
            }
            if let Some(r) = reason {
                flow.closed_at = Some(ts);
                release_tls(&mut flow.tls, &mut self.tls_collecting);
                out.push(end_event(flow, r));
                self.counters.flows_ended += 1;
            }
        }

        self.learn_names(learned, ts);
    }

    fn learn_names(&mut self, learned: Vec<(IpAddr, String, Ts)>, now: Ts) {
        for (ip, name, exp) in learned {
            if self.dns_cache.len() >= self.cfg.dns_cache_max && !self.dns_cache.contains_key(&ip) {
                self.dns_cache.retain(|_, (_, e)| *e > now);
                if self.dns_cache.len() >= self.cfg.dns_cache_max {
                    self.dns_cache.clear();
                }
            }
            self.dns_cache.insert(ip, (name, exp));
        }
    }
}

/// Follows the initiator's in-order bytes until a ClientHello parses (or clearly won't).
fn feed_tls(
    state: &mut TlsState,
    seq: u32,
    payload: &[u8],
    counters: &mut Counters,
    collecting: &mut usize,
    max_collecting: usize,
) -> Option<tls::ClientHello> {
    let seg_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    match state {
        TlsState::Done => return None,
        TlsState::Pending => {
            if !tls::looks_like_tls(payload) {
                *state = TlsState::Done;
                return None;
            }
            if *collecting >= max_collecting {
                counters.tls_unparsed += 1;
                *state = TlsState::Done;
                return None;
            }
            // Buffer at most MAX_TLS_BUFFER bytes of the first segment (ADV-0015), but still
            // parse them: a hello followed by more data in one segment keeps its SNI (ADV-0021).
            let head = payload.get(..MAX_TLS_BUFFER).unwrap_or(payload);
            *collecting += 1;
            *state = TlsState::Collecting {
                next_seq: seq.wrapping_add(seg_len),
                buf: head.to_vec(),
            };
        }
        TlsState::Collecting { next_seq, buf } => {
            // Signed distance in sequence space: 0 in order, < 0 retransmit/overlap, > 0 gap.
            let off = seq.wrapping_sub(*next_seq).cast_signed();
            if off > 0 {
                counters.tls_unparsed += 1;
                release_tls(state, collecting);
                return None;
            }
            let skip = usize::try_from(off.unsigned_abs()).unwrap_or(usize::MAX);
            let Some(fresh) = payload.get(skip..).filter(|f| !f.is_empty()) else {
                return None; // pure retransmission
            };
            if buf.len() + fresh.len() > MAX_TLS_BUFFER {
                counters.tls_unparsed += 1;
                release_tls(state, collecting);
                return None;
            }
            buf.extend_from_slice(fresh);
            *next_seq = next_seq.wrapping_add(u32::try_from(fresh.len()).unwrap_or(u32::MAX));
        }
    }
    let TlsState::Collecting { buf, .. } = state else {
        return None;
    };
    match tls::parse_client_hello(buf) {
        // Buffer full and still incomplete: it can never parse, so free the slot now.
        Ok(None) if buf.len() >= MAX_TLS_BUFFER => {
            counters.tls_unparsed += 1;
            release_tls(state, collecting);
            None
        }
        Ok(None) => None,
        Ok(Some(ch)) => {
            counters.tls_client_hellos += 1;
            release_tls(state, collecting);
            Some(ch)
        }
        Err(_) => {
            counters.tls_unparsed += 1;
            release_tls(state, collecting);
            None
        }
    }
}
