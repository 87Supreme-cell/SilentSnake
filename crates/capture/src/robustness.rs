//! Deterministic randomized robustness tests: hostile bytes must never panic, hang or grow
//! memory without bound. Stands in for cargo-fuzz until a nightly toolchain is approved.

#![allow(clippy::indexing_slicing)]

use crate::decode::LinkType;
use crate::engine::{Engine, EngineConfig};
use crate::event::{Direction, EndReason, EventBody, NameSource};
use crate::time::Ts;
use crate::{dns, tls};
use etherparse::PacketBuilder;

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() as usize) % (max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        match self.next() % 3 {
            0 if !v.is_empty() => {
                let cut = (self.next() as usize) % v.len();
                v.truncate(cut);
            }
            _ => {
                for _ in 0..1 + self.next() % 8 {
                    if v.is_empty() {
                        break;
                    }
                    let i = (self.next() as usize) % v.len();
                    v[i] ^= 1 << (self.next() % 8);
                }
            }
        }
        v
    }
}

const ROUNDS: usize = 20_000;

#[test]
fn dns_parser_survives_garbage_and_mutations() {
    let mut r = XorShift(0x5eed_d115);
    let seed = dns::tests::build(
        9,
        "www.example.com",
        true,
        0,
        &[(1, &[1, 2, 3, 4], 30), (28, &[0; 16], 30)],
    );
    for _ in 0..ROUNDS {
        let _ = dns::parse(&r.bytes(600));
        let _ = dns::parse(&r.mutate(&seed));
    }
}

#[test]
fn tls_parser_survives_garbage_and_mutations() {
    let mut r = XorShift(0x71_5eed);
    let seed = tls::tests::client_hello(Some("example.com"), true, 900, 512);
    for _ in 0..ROUNDS {
        let mut g = r.bytes(2000);
        if !g.is_empty() {
            g[0] = 0x16;
        }
        let _ = tls::parse_client_hello(&g);
        let _ = tls::parse_client_hello(&r.mutate(&seed));
    }
}

#[test]
fn engine_survives_garbage_on_every_link_type_with_bounded_state() {
    let mut r = XorShift(0xe1_5eed);
    let cfg = EngineConfig {
        max_flows: 64,
        max_tls_collecting: 8,
        dns_cache_max: 32,
        ..EngineConfig::default()
    };
    let mut e = Engine::new(cfg);
    let mut out = Vec::new();
    let links = [
        LinkType::Ethernet,
        LinkType::LinuxSll,
        LinkType::LinuxSll2,
        LinkType::Raw,
        LinkType::Null,
    ];
    let seed = tcp_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        40000,
        443,
        1,
        Flags::Ack,
        &tls::tests::client_hello(Some("x.test"), false, 64, 16384),
    );
    for i in 0..ROUNDS {
        let ts = Ts::new(1_000 + (i as i64) / 50, 0);
        let link = links[i % links.len()];
        let data = if i % 2 == 0 {
            r.bytes(300)
        } else {
            r.mutate(&seed)
        };
        e.process(ts, link, &data, data.len() as u32, &mut out);
        assert!(e.active_flows() <= 64);
        assert!(e.tls_buffers_in_use() <= 8);
        out.clear();
    }
}

// ---- engine behaviour tests ------------------------------------------------------------

#[derive(Clone, Copy)]
enum Flags {
    Syn,
    SynAck,
    Ack,
    Fin,
    Rst,
}

fn tcp_packet(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    f: Flags,
    payload: &[u8],
) -> Vec<u8> {
    let b = PacketBuilder::ipv4(src, dst, 64).tcp(sport, dport, seq, 64_000);
    let b = match f {
        Flags::Syn => b.syn(),
        Flags::SynAck => b.syn().ack(1),
        Flags::Ack => b.ack(1),
        Flags::Fin => b.fin().ack(1),
        Flags::Rst => b.rst(),
    };
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

fn udp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    PacketBuilder::ipv4(src, dst, 64)
        .udp(sport, dport)
        .write(&mut v, payload)
        .unwrap();
    v
}

fn feed(e: &mut Engine, secs: i64, pkt: &[u8]) -> Vec<EventBody> {
    let mut out = Vec::new();
    e.process(
        Ts::new(secs, 0),
        LinkType::Raw,
        pkt,
        pkt.len() as u32,
        &mut out,
    );
    out.into_iter().map(|ev| ev.body).collect()
}

const ME: [u8; 4] = [192, 168, 1, 10];
const SRV: [u8; 4] = [93, 184, 216, 34];

fn engine() -> Engine {
    let mut e = Engine::new(EngineConfig::default());
    e.set_local_addrs([ME.into()]);
    e
}

#[test]
fn tcp_lifecycle_with_dns_name_and_split_client_hello() {
    let mut e = engine();
    let answer = dns::tests::build(5, "example.com", true, 0, &[(1, &SRV, 300)]);
    let ev = feed(
        &mut e,
        100,
        &udp_packet([1, 1, 1, 1], ME, 53, 50000, &answer),
    );
    assert!(
        matches!(&ev[1], EventBody::Dns { message, .. } if message.answers[0].data.as_deref() == Some("93.184.216.34"))
    );

    let ev = feed(
        &mut e,
        101,
        &tcp_packet(ME, SRV, 51000, 443, 1000, Flags::Syn, &[]),
    );
    let EventBody::FlowStart { flow } = &ev[0] else {
        panic!("{ev:?}")
    };
    assert_eq!(flow.direction, Direction::Outbound);
    assert_eq!(flow.server_name.as_deref(), Some("example.com"));
    assert_eq!(flow.server_name_source, Some(NameSource::Dns));
    assert!(!flow.initiator_inferred);

    feed(
        &mut e,
        101,
        &tcp_packet(SRV, ME, 443, 51000, 5000, Flags::SynAck, &[]),
    );
    let hello = tls::tests::client_hello(Some("www.example.com"), false, 1300, 16384);
    let (a, b) = hello.split_at(700);
    assert!(
        feed(
            &mut e,
            101,
            &tcp_packet(ME, SRV, 51000, 443, 1001, Flags::Ack, a)
        )
        .is_empty()
    );
    // A retransmission of the first segment is ignored.
    assert!(
        feed(
            &mut e,
            101,
            &tcp_packet(ME, SRV, 51000, 443, 1001, Flags::Ack, a)
        )
        .is_empty()
    );
    let ev = feed(
        &mut e,
        101,
        &tcp_packet(ME, SRV, 51000, 443, 1701, Flags::Ack, b),
    );
    assert!(
        matches!(&ev[0], EventBody::TlsClientHello { server_name: Some(n), .. } if n == "www.example.com")
    );
    assert_eq!(e.tls_buffers_in_use(), 0);

    feed(
        &mut e,
        102,
        &tcp_packet(ME, SRV, 51000, 443, 2400, Flags::Fin, &[]),
    );
    let ev = feed(
        &mut e,
        102,
        &tcp_packet(SRV, ME, 443, 51000, 9000, Flags::Fin, &[]),
    );
    let EventBody::FlowEnd {
        flow,
        reason,
        initiator_packets,
        responder_packets,
        ..
    } = &ev[0]
    else {
        panic!("{ev:?}")
    };
    assert_eq!(*reason, EndReason::Closed);
    assert_eq!(flow.server_name.as_deref(), Some("www.example.com"));
    assert_eq!(flow.server_name_source, Some(NameSource::Sni));
    assert_eq!((*initiator_packets, *responder_packets), (5, 2));

    // The final ACK after close is absorbed, not reported as a new flow.
    assert!(
        feed(
            &mut e,
            102,
            &tcp_packet(ME, SRV, 51000, 443, 2401, Flags::Ack, &[])
        )
        .is_empty()
    );
    assert_eq!(e.counters().packets_after_close, 1);
    // A new SYN on the same 4-tuple is a new connection.
    let ev = feed(
        &mut e,
        103,
        &tcp_packet(ME, SRV, 51000, 443, 7, Flags::Syn, &[]),
    );
    assert!(matches!(&ev[0], EventBody::FlowStart { flow } if flow.flow_id == 3));
}

#[test]
fn reset_inbound_and_midstream_inference() {
    let mut e = engine();
    let ev = feed(
        &mut e,
        10,
        &tcp_packet([10, 9, 9, 9], ME, 40000, 22, 1, Flags::Syn, &[]),
    );
    assert!(
        matches!(&ev[0], EventBody::FlowStart { flow } if flow.direction == Direction::Inbound && flow.service == Some("ssh"))
    );
    let ev = feed(
        &mut e,
        10,
        &tcp_packet(ME, [10, 9, 9, 9], 22, 40000, 1, Flags::Rst, &[]),
    );
    assert!(matches!(
        &ev[0],
        EventBody::FlowEnd {
            reason: EndReason::Reset,
            ..
        }
    ));

    // Mid-stream packet from the server side: initiator is inferred to be the client.
    let ev = feed(
        &mut e,
        11,
        &tcp_packet(SRV, ME, 443, 52000, 1, Flags::Ack, b"data"),
    );
    let EventBody::FlowStart { flow } = &ev[0] else {
        panic!()
    };
    assert!(flow.initiator_inferred);
    assert_eq!(flow.initiator.port, 52000);
    assert_eq!(flow.direction, Direction::Outbound);
}

#[test]
fn idle_expiry_and_eviction_are_bounded() {
    let mut e = Engine::new(EngineConfig {
        max_flows: 32,
        ..EngineConfig::default()
    });
    e.set_local_addrs([ME.into()]);
    let mut ends = 0;
    for p in 0..200u16 {
        for b in feed(&mut e, 50, &udp_packet(ME, SRV, 10_000 + p, 9999, b"x")) {
            if let EventBody::FlowEnd { reason, .. } = b {
                assert_eq!(reason, EndReason::Evicted);
                ends += 1;
            }
        }
        assert!(e.active_flows() <= 32);
    }
    assert_eq!(ends, 200 - e.active_flows());
    let mut out = Vec::new();
    e.tick(Ts::new(50 + 61, 0), &mut out);
    assert!(out.iter().all(|ev| matches!(
        ev.body,
        EventBody::FlowEnd {
            reason: EndReason::Idle,
            ..
        }
    )));
    assert_eq!(e.active_flows(), 0);
}

#[test]
fn loopback_is_local_without_address_list() {
    let mut e = Engine::new(EngineConfig::default());
    let ev = feed(
        &mut e,
        1,
        &udp_packet([127, 0, 0, 1], [127, 0, 0, 1], 40000, 8765, b"hi"),
    );
    assert!(matches!(&ev[0], EventBody::FlowStart { flow } if flow.direction == Direction::Local));
    let ev = feed(&mut e, 1, &udp_packet(ME, SRV, 40000, 9, b"hi"));
    assert!(
        matches!(&ev[0], EventBody::FlowStart { flow } if flow.direction == Direction::Unknown)
    );
}

#[test]
fn tls_buffer_budget_is_enforced() {
    let mut e = Engine::new(EngineConfig {
        max_tls_collecting: 2,
        ..EngineConfig::default()
    });
    let partial = &tls::tests::client_hello(Some("a.test"), false, 3000, 16384)[..100];
    for p in 0..5u16 {
        feed(
            &mut e,
            1,
            &tcp_packet(ME, SRV, 30_000 + p, 443, 1, Flags::Ack, partial),
        );
    }
    assert_eq!(e.tls_buffers_in_use(), 2);
    assert_eq!(e.counters().tls_unparsed, 3);
    let mut out = Vec::new();
    e.flush(EndReason::CaptureEnd, &mut out);
    assert_eq!(out.len(), 5);
    assert_eq!(e.tls_buffers_in_use(), 0);
}

#[test]
fn oversized_first_tls_segment_is_not_buffered() {
    // ADV-0015: the first segment alone must respect MAX_TLS_BUFFER.
    let mut e = engine();
    let mut big = vec![0x16, 0x03, 0x01, 0x40, 0x00];
    big.resize(crate::engine::MAX_TLS_BUFFER + 1000, 0xAB);
    feed(
        &mut e,
        1,
        &tcp_packet(ME, SRV, 30_000, 443, 1, Flags::Ack, &big),
    );
    assert_eq!(e.tls_buffers_in_use(), 0);
    assert_eq!(e.counters().tls_unparsed, 1);
}

#[test]
fn drop_warning_does_not_overflow() {
    // ADV-0013: u32::MAX + u32::MAX must not panic (debug) or wrap to 0 (release).
    let st = crate::event::StatsInfo {
        counters: Default::default(),
        flows_active: 0,
        kernel_received: Some(0),
        kernel_dropped: Some(u32::MAX),
        interface_dropped: Some(u32::MAX),
    };
    assert!(crate::summary::stats(&st).contains("8589934590 packets were dropped"));
}

#[test]
fn hello_followed_by_bulk_data_in_one_segment_keeps_sni() {
    // ADV-0021: the head of an oversized first segment is still parsed.
    let mut e = engine();
    let mut seg = tls::tests::client_hello(Some("bulk.example"), false, 64, 16384);
    seg.resize(seg.len() + 32 * 1024, 0x17);
    let ev = feed(
        &mut e,
        1,
        &tcp_packet(ME, SRV, 30_001, 443, 1, Flags::Ack, &seg),
    );
    assert!(ev.iter().any(|b| matches!(b, EventBody::TlsClientHello { server_name: Some(n), .. } if n == "bulk.example")));
    assert_eq!(e.tls_buffers_in_use(), 0);
}

// ---- ADV-0002: smaller snaplen means truncated packets; they must still count ----------

fn feed_cut(e: &mut Engine, link: LinkType, pkt: &[u8], keep: usize) -> Vec<EventBody> {
    let mut out = Vec::new();
    e.process(
        Ts::new(5, 0),
        link,
        &pkt[..keep.min(pkt.len())],
        pkt.len() as u32,
        &mut out,
    );
    out.into_iter().map(|ev| ev.body).collect()
}

#[test]
fn truncated_packets_still_make_flows_and_count_full_wire_bytes() {
    let mut e = engine();
    let pkt = tcp_packet(ME, SRV, 40_000, 443, 1, Flags::Ack, &[0x17; 6000]);
    let ev = feed_cut(&mut e, LinkType::Raw, &pkt, 1000);
    assert!(matches!(&ev[0], EventBody::FlowStart { .. }), "{ev:?}");
    assert_eq!(e.counters().packets_undecoded, 0);
    let mut out = Vec::new();
    e.flush(EndReason::CaptureEnd, &mut out);
    let EventBody::FlowEnd {
        initiator_bytes, ..
    } = &out[0].body
    else {
        panic!()
    };
    assert_eq!(
        *initiator_bytes,
        pkt.len() as u64,
        "bytes must be the on-wire length"
    );
}

#[test]
fn truncated_client_hello_is_unparsed_not_guessed() {
    let mut e = engine();
    let hello = tls::tests::client_hello(Some("cut.example"), false, 3000, 16384);
    let pkt = tcp_packet(ME, SRV, 40_001, 443, 1, Flags::Ack, &hello);
    let ev = feed_cut(&mut e, LinkType::Raw, &pkt, 1500);
    assert!(
        !ev.iter()
            .any(|b| matches!(b, EventBody::TlsClientHello { .. }))
    );
    assert_eq!(e.counters().tls_unparsed, 1);
    assert_eq!(e.tls_buffers_in_use(), 0);
    // A hello that fits inside the captured part still parses from a truncated packet.
    let small = tls::tests::client_hello(Some("fits.example"), false, 64, 16384);
    let mut payload = small.clone();
    payload.extend_from_slice(&[0x17; 9000]);
    let pkt = tcp_packet(ME, SRV, 40_002, 443, 1, Flags::Ack, &payload);
    let ev = feed_cut(&mut e, LinkType::Raw, &pkt, 8192);
    assert!(ev.iter().any(|b| matches!(b, EventBody::TlsClientHello { server_name: Some(n), .. } if n == "fits.example")));
}

#[test]
fn linux_sll_v1_and_v2_still_decode() {
    let ip = udp_packet(ME, SRV, 5000, 53, b"x");
    let mut sll = vec![0u8; 14];
    sll.extend_from_slice(&0x0800u16.to_be_bytes());
    sll.extend_from_slice(&ip);
    assert!(matches!(
        crate::decode::decode(LinkType::LinuxSll, &sll, false),
        crate::decode::Outcome::Ip(_)
    ));
    let mut sll2 = 0x0800u16.to_be_bytes().to_vec();
    sll2.extend_from_slice(&[0u8; 18]);
    sll2.extend_from_slice(&ip);
    assert!(matches!(
        crate::decode::decode(LinkType::LinuxSll2, &sll2, false),
        crate::decode::Outcome::Ip(_)
    ));
    assert!(matches!(
        crate::decode::decode(LinkType::LinuxSll, &sll[..10], true),
        crate::decode::Outcome::Malformed
    ));
}

// ---- ADV-0025: whole packets whose headers lie are malformed, not phantom traffic --------

#[test]
fn whole_packets_with_lying_lengths_are_malformed() {
    use crate::decode::{Outcome, decode};
    // IPv4 total length smaller than its own header.
    let mut v4 = tcp_packet(ME, SRV, 40_000, 443, 1, Flags::Syn, &[]);
    v4[2..4].copy_from_slice(&10u16.to_be_bytes());
    assert!(matches!(
        decode(LinkType::Raw, &v4, false),
        Outcome::Malformed
    ));
    // UDP length fields the kernel drops (ADV-0029: only these): longer than the IP payload,
    // or shorter than the UDP header itself (also when the capture cut the packet).
    let answer = dns::tests::build(5, "evil.example", true, 0, &[(1, &SRV, 300)]);
    let good = udp_packet([1, 1, 1, 1], ME, 53, 50000, &answer);
    let ulen = u16::from_be_bytes([good[24], good[25]]);
    for (bad, cut) in [(ulen + 7, false), (7, false), (0, false), (4, true)] {
        let mut p = good.clone();
        p[24..26].copy_from_slice(&bad.to_be_bytes());
        let keep = if cut { p.len() - 4 } else { p.len() };
        assert!(
            matches!(decode(LinkType::Raw, &p[..keep], cut), Outcome::Malformed),
            "ulen {bad} cut {cut}"
        );
    }
    let mut udp = good.clone();
    udp[24..26].copy_from_slice(&(ulen + 7).to_be_bytes());
    // Through the engine: no flow, no DNS name learned, counted as undecoded.
    let mut e = engine();
    assert!(feed(&mut e, 1, &udp).is_empty());
    assert_eq!(e.counters().packets_undecoded, 1);
    // The same packet genuinely cut by the capture is still accepted.
    assert!(matches!(
        decode(LinkType::Raw, &good[..good.len() - 4], true),
        Outcome::Ip(_)
    ));
}

// ---- ADV-0029: Linux trims a short UDP length and delivers it, so it must stay visible ----

#[test]
fn udp_length_shorter_than_ip_payload_is_trimmed_and_flagged() {
    use crate::decode::{Outcome, decode};
    let answer = dns::tests::build(9, "hidden.example", true, 0, &[(1, &SRV, 300)]);
    let mut body = answer.clone();
    body.extend_from_slice(&[0xAA; 3_000]);
    let ulen = u16::try_from(8 + answer.len()).unwrap();

    // IPv4: the IP total length covers the junk, the UDP length only the DNS message.
    let mut v4 = udp_packet([1, 1, 1, 1], ME, 53, 50000, &body);
    v4[24..26].copy_from_slice(&ulen.to_be_bytes());
    v4[26..28].copy_from_slice(&[0, 0]);
    match decode(LinkType::Raw, &v4, false) {
        Outcome::Ip(d) => {
            assert!(d.udp_trailing);
            assert_eq!(
                d.payload,
                &answer[..],
                "payload is what the kernel delivers"
            );
        }
        other => panic!("trimmed IPv4 UDP must decode, got {other:?}"),
    }
    let mut e = engine();
    let ev = feed(&mut e, 1, &v4);
    assert!(ev.iter().any(|b| matches!(b, EventBody::FlowStart { .. })));
    assert!(
        ev.iter()
            .any(|b| matches!(b, EventBody::Dns { message, .. } if message.answers[0].data.as_deref() == Some("93.184.216.34")))
    );
    assert_eq!(e.counters().flows_started, 1);
    assert_eq!(e.counters().packets_undecoded, 0);
    assert_eq!(e.counters().udp_trailing_bytes, 1);

    // IPv6: same shape (UDP length at 40 + 4).
    let (a, b) = (
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    );
    let mut v6 = Vec::new();
    PacketBuilder::ipv6(a, b, 64)
        .udp(40_000, 5_000)
        .write(&mut v6, &body)
        .unwrap();
    v6[44..46].copy_from_slice(&ulen.to_be_bytes());
    assert!(matches!(
        decode(LinkType::Raw, &v6, false),
        Outcome::Ip(d) if d.udp_trailing && d.payload.len() == answer.len()
    ));

    // An exact UDP length (normal traffic) is never flagged, and neither is a cut packet.
    let normal = udp_packet([1, 1, 1, 1], ME, 53, 50000, &answer);
    assert!(matches!(decode(LinkType::Raw, &normal, false), Outcome::Ip(d) if !d.udp_trailing));
    assert!(matches!(
        decode(LinkType::Raw, &v4[..v4.len() - 100], true),
        Outcome::Ip(d) if !d.udp_trailing
    ));
}

#[test]
fn snaplen_holds_a_full_tls_record_with_headers() {
    // ADV-0024: a single-segment ClientHello of any legal size must be captured whole.
    // Worst-case headers: Linux SLL2 (20) + IPv6 (40) + TCP with options (60) + TLS record (5).
    let needed = tls::MAX_RECORD + 5 + 20 + 40 + 60;
    assert!(usize::try_from(crate::source::SNAPLEN).unwrap() >= needed);
}
