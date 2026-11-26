#![no_main]
//! Whole engine on a packet sequence, with small limits so eviction and budgets are hit.
//! Input: repeated [link selector][time step][len hi][len lo][packet bytes...].
use libfuzzer_sys::fuzz_target;
use silentsnake_capture::decode::LinkType;
use silentsnake_capture::engine::{Engine, EngineConfig};
use silentsnake_capture::time::Ts;

fuzz_target!(|data: &[u8]| {
    let cfg = EngineConfig { max_flows: 16, max_tls_collecting: 4, dns_cache_max: 8, ..EngineConfig::default() };
    let mut e = Engine::new(cfg);
    e.set_local_addrs(["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
    let mut out = Vec::new();
    let mut t: i64 = 1_000;
    let mut rest = data;
    while let [sel, step, hi, lo, tail @ ..] = rest {
        let len = (usize::from(*hi) << 8 | usize::from(*lo)).min(tail.len());
        let (pkt, next) = tail.split_at(len);
        t += i64::from(*step);
        let link = if sel % 2 == 0 { LinkType::Raw } else { LinkType::Ethernet };
        e.process(Ts::new(t, 0), link, pkt, u32::try_from(pkt.len()).unwrap_or(u32::MAX), &mut out);
        assert!(e.active_flows() <= 16);
        assert!(e.tls_buffers_in_use() <= 4);
        out.clear();
        rest = next;
    }
    e.flush(silentsnake_capture::event::EndReason::CaptureEnd, &mut out);
    assert_eq!(e.tls_buffers_in_use(), 0);
});
