//! libpcap I/O: opens a live interface or a capture file, pumps packets through the
//! [`Engine`], and writes events as JSON lines. Output goes only to the given writer
//! (stdout in the binary); stage A never writes events to disk (CLAUDE.md section 3).

use crate::decode::LinkType;
use crate::engine::{Engine, EngineConfig};
use crate::event::{EndReason, Envelope, Event, EventBody, SCHEMA, SourceInfo, StopReason};
use crate::privilege::Identity;
use crate::summary;
use crate::time::Ts;
use pcap::{Activated, Capture, Device};
use std::fmt;
use std::io::{self, BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// 18 KiB: a full TLS record (16 KiB + headers), so a single-segment ClientHello of any legal
/// size keeps its SNI (ADV-0024). With TPACKET_V3 (see `run`) packets are packed into the ring
/// at their captured length, so the snaplen no longer limits how many fit (ADV-0028). Longer
/// packets are truncated, decoded laxly, and counted at their full on-the-wire length.
pub const SNAPLEN: i32 = 18_432;
/// TPACKET_V3 block retire timeout: a partly filled block is handed over after at most this
/// long, which bounds the extra delivery latency on a quiet link.
pub const READ_TIMEOUT_MS: i32 = 10;
pub const KERNEL_BUFFER_BYTES: i32 = 32 * 1024 * 1024;
const ADDR_REFRESH: Duration = Duration::from_secs(60);
/// Sleep when no packet is waiting (non-blocking live capture): bounds added latency.
const IDLE_SLEEP: Duration = Duration::from_millis(1);
/// After a `--duration` stop: time to keep processing packets captured before the stop, then
/// time to count (not process) any that are left (ADV-0032).
const DRAIN_BUDGET: Duration = Duration::from_secs(2);
const SKIM_BUDGET: Duration = Duration::from_secs(1);
/// One block-retire interval plus margin, so the last partly filled block is visible.
const DRAIN_RETIRE_WAIT: Duration = Duration::from_millis(READ_TIMEOUT_MS as u64 + 5);
pub const MAX_FILTER_LEN: usize = 4096;

#[derive(Debug, Clone)]
pub enum Source {
    Live { interface: String },
    File { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub source: Source,
    pub filter: Option<String>,
    pub duration: Option<Duration>,
    pub max_packets: Option<u64>,
    /// Periodic `stats` events during live capture; `None` disables them.
    pub stats_interval: Option<Duration>,
    /// Extra addresses to treat as this machine (added to detected ones in live mode).
    pub local_addrs: Vec<IpAddr>,
    pub engine: EngineConfig,
    pub identity: Identity,
}

#[derive(Debug)]
pub enum RunError {
    Open(String),
    Filter(String),
    Capture(String),
    Output(io::Error),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Open(e) => write!(f, "cannot open capture: {e}"),
            RunError::Filter(e) => write!(f, "invalid filter: {e}"),
            RunError::Capture(e) => write!(f, "capture failed: {e}"),
            RunError::Output(e) => write!(f, "cannot write output: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Numbers every event (gap-free `seq`) and writes it as one JSON line.
pub struct EventWriter<W: Write> {
    out: BufWriter<W>,
    seq: u64,
}

impl<W: Write> EventWriter<W> {
    pub fn new(out: W) -> Self {
        EventWriter {
            out: BufWriter::new(out),
            seq: 0,
        }
    }

    pub fn write(&mut self, events: &mut Vec<Event>) -> io::Result<()> {
        for e in events.drain(..) {
            self.seq += 1;
            let env = Envelope {
                schema: SCHEMA,
                seq: self.seq,
                ts: e.ts,
                body: &e.body,
                summary: &e.summary,
            };
            serde_json::to_writer(&mut self.out, &env).map_err(io::Error::other)?;
            self.out.write_all(b"\n")?;
        }
        self.out.flush()
    }
}

/// All addresses on this machine's interfaces, as libpcap reports them.
pub fn machine_addrs() -> Vec<IpAddr> {
    Device::list()
        .map(|ds| {
            ds.into_iter()
                .flat_map(|d| d.addresses.into_iter().map(|a| a.addr))
                .collect()
        })
        .unwrap_or_default()
}

pub fn run<W: Write>(cfg: &RunConfig, out: W) -> Result<StopReason, RunError> {
    if let Some(f) = &cfg.filter
        && f.len() > MAX_FILTER_LEN
    {
        return Err(RunError::Filter(format!(
            "longer than {MAX_FILTER_LEN} bytes"
        )));
    }
    match &cfg.source {
        Source::Live { interface } => {
            let cap = Capture::from_device(interface.as_str())
                .map_err(|e| RunError::Open(e.to_string()))?
                .snaplen(SNAPLEN)
                .promisc(false)
                // Not immediate mode: on Linux, libpcap then uses TPACKET_V3, which packs
                // packets into ring blocks by captured length. Immediate mode forces TPACKET_V2
                // with one fixed snaplen-sized frame per packet, which overflowed on 20k-datagram
                // bursts at an 18 KiB snaplen (ADV-0028). Latency is bounded by READ_TIMEOUT_MS.
                .immediate_mode(false)
                .timeout(READ_TIMEOUT_MS)
                .buffer_size(KERNEL_BUFFER_BYTES)
                .open()
                .map_err(|e| RunError::Open(e.to_string()))?
                // Non-blocking: with TPACKET_V3 the read timeout only starts once a packet
                // arrives (pcap(3PCAP)), so a blocking read on a quiet interface never returns
                // and --duration, idle expiry and stats would stall. We sleep IDLE_SLEEP instead.
                .setnonblock()
                .map_err(|e| RunError::Open(e.to_string()))?;
            pump(cap, cfg, interface.clone(), true, out)
        }
        Source::File { path } => {
            let cap = Capture::from_file(path).map_err(|e| RunError::Open(e.to_string()))?;
            pump(cap, cfg, path.display().to_string(), false, out)
        }
    }
}

fn pump<T: Activated + ?Sized, W: Write>(
    mut cap: Capture<T>,
    cfg: &RunConfig,
    name: String,
    live: bool,
    out: W,
) -> Result<StopReason, RunError> {
    if let Some(f) = &cfg.filter {
        cap.filter(f, true)
            .map_err(|e| RunError::Filter(e.to_string()))?;
    }
    let link = LinkType::from_dlt(cap.get_datalink().0);
    let mut engine = Engine::new(cfg.engine.clone());
    let refresh_addrs = |engine: &mut Engine| {
        let mut addrs = if live { machine_addrs() } else { Vec::new() };
        addrs.extend(cfg.local_addrs.iter().copied());
        if live || !cfg.local_addrs.is_empty() {
            engine.set_local_addrs(addrs);
        }
    };
    refresh_addrs(&mut engine);

    let mut writer = EventWriter::new(out);
    let mut events: Vec<Event> = Vec::new();
    let source = SourceInfo {
        kind: if live { "live" } else { "file" },
        name,
        link_type: link.name(),
        filter: cfg.filter.clone(),
        euid: cfg.identity.euid(),
        cap_net_raw: cfg.identity.has_cap_net_raw(),
    };
    let now = Ts::now();
    events.push(Event {
        ts: now,
        summary: summary::engine_start(&source),
        body: EventBody::EngineStart {
            version: env!("CARGO_PKG_VERSION"),
            source,
        },
    });

    let started = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_refresh = Instant::now();
    let mut packets: u64 = 0;
    let kernel = |cap: &mut Capture<T>| -> Option<(u32, u32, u32)> {
        if live {
            cap.stats()
                .ok()
                .map(|s| (s.received, s.dropped, s.if_dropped))
        } else {
            None
        }
    };

    let reason = loop {
        if let Some(d) = cfg.duration
            && started.elapsed() >= d
        {
            break StopReason::Duration;
        }
        if let Some(m) = cfg.max_packets
            && packets >= m
        {
            break StopReason::PacketCount;
        }
        match cap.next_packet() {
            Ok(p) => {
                packets += 1;
                let ts = Ts::new(p.header.ts.tv_sec, p.header.ts.tv_usec);
                engine.process(ts, link, p.data, p.header.len, &mut events);
            }
            Err(pcap::Error::TimeoutExpired) => {
                if live {
                    engine.tick(Ts::now(), &mut events);
                    std::thread::sleep(IDLE_SLEEP);
                }
            }
            Err(pcap::Error::NoMorePackets) => break StopReason::EndOfFile,
            Err(e) => return Err(RunError::Capture(e.to_string())),
        }
        if live && last_refresh.elapsed() >= ADDR_REFRESH {
            refresh_addrs(&mut engine);
            last_refresh = Instant::now();
        }
        if live
            && let Some(iv) = cfg.stats_interval
            && last_stats.elapsed() >= iv
        {
            events.push(engine.stats_event(Ts::now(), kernel(&mut cap)));
            last_stats = Instant::now();
        }
        if !events.is_empty() {
            match writer.write(&mut events) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    return Ok(StopReason::OutputClosed);
                }
                Err(e) => return Err(RunError::Output(e)),
            }
        }
    };

    // ADV-0032: a `--duration` stop must not discard what the ring already holds. TPACKET_V3
    // keeps up to 32 MiB of packets (everything that arrived while we were behind) plus a
    // block that retires only after READ_TIMEOUT_MS. Process every packet timestamped before
    // the stop for up to DRAIN_BUDGET, then count (without processing) whatever is left, for up
    // to SKIM_BUDGET, so an incomplete record always says so. `--count` stops are exact by
    // definition and are not drained.
    //
    // ADV-0033: the kernel counters are read at the stop, so packets arriving during the drain
    // don't inflate `kernel_received` (a packet already in the ring can no longer be dropped).
    // The skim window starts when skimming starts, so a stdout write that blocked through the
    // processing budget can't cut the count short. The boundary is never earlier than the
    // newest packet already processed: a packet stamped after "now" proves the wall clock
    // stepped back, and the backlog behind it belongs to this run.
    let mut kernel_at_stop = None;
    if live && reason == StopReason::Duration {
        kernel_at_stop = kernel(&mut cap);
        let stop = Ts::now().max(engine.latest());
        let process_until = Instant::now() + DRAIN_BUDGET;
        let mut skim_until: Option<Instant> = None;
        let mut idle = 0u32;
        let mut unprocessed: u64 = 0;
        loop {
            match cap.next_packet() {
                Ok(p) => {
                    idle = 0;
                    let ts = Ts::new(p.header.ts.tv_sec, p.header.ts.tv_usec);
                    if ts > stop {
                        break; // arrived after the stop: not part of this run
                    }
                    let now = Instant::now();
                    if now < process_until {
                        engine.process(ts, link, p.data, p.header.len, &mut events);
                    } else {
                        unprocessed += 1;
                        if now >= *skim_until.get_or_insert(now + SKIM_BUDGET) {
                            break;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Empty twice, a block-retire interval apart: the partly filled block has
                    // been handed over and read.
                    idle += 1;
                    if idle >= 2 {
                        break;
                    }
                    std::thread::sleep(DRAIN_RETIRE_WAIT);
                }
                Err(pcap::Error::NoMorePackets) => break,
                Err(e) => return Err(RunError::Capture(e.to_string())),
            }
            if !events.is_empty() {
                match writer.write(&mut events) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                        return Ok(StopReason::OutputClosed);
                    }
                    Err(e) => return Err(RunError::Output(e)),
                }
            }
        }
        engine.note_unprocessed_at_stop(unprocessed);
    }

    let end_ts = if live { Ts::now() } else { engine.latest() };
    engine.flush(
        if live {
            EndReason::CaptureStopped
        } else {
            EndReason::CaptureEnd
        },
        &mut events,
    );
    let stats = engine.stats(kernel_at_stop.or_else(|| kernel(&mut cap)));
    events.push(Event {
        ts: end_ts,
        summary: summary::engine_stop(reason, &stats),
        body: EventBody::EngineStop { reason, stats },
    });
    match writer.write(&mut events) {
        Ok(()) => Ok(reason),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(StopReason::OutputClosed),
        Err(e) => Err(RunError::Output(e)),
    }
}
