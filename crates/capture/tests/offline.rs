//! End to end through real libpcap: writes a synthetic pcap file, runs the library and the
//! `silentsnake-capture` binary on it, and checks the JSON-lines output.

use etherparse::PacketBuilder;
use serde_json::Value;
use silentsnake_capture::engine::EngineConfig;
use silentsnake_capture::privilege::Identity;
use silentsnake_capture::source::{self, RunConfig, Source};
use std::path::{Path, PathBuf};
use std::process::Command;

const ME: [u8; 4] = [192, 168, 1, 10];
const DNS: [u8; 4] = [1, 1, 1, 1];
const SRV: [u8; 4] = [93, 184, 216, 34];
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p =
            std::env::temp_dir().join(format!("silentsnake-capture-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Classic pcap file (LINKTYPE_ETHERNET, microsecond timestamps).
fn write_pcap(path: &Path, packets: &[(u32, u32, Vec<u8>)]) {
    let mut f = Vec::new();
    f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    f.extend_from_slice(&2u16.to_le_bytes());
    f.extend_from_slice(&4u16.to_le_bytes());
    f.extend_from_slice(&0i32.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&262_144u32.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    for (s, us, data) in packets {
        f.extend_from_slice(&s.to_le_bytes());
        f.extend_from_slice(&us.to_le_bytes());
        f.extend_from_slice(&(data.len() as u32).to_le_bytes());
        f.extend_from_slice(&(data.len() as u32).to_le_bytes());
        f.extend_from_slice(data);
    }
    std::fs::write(path, f).unwrap();
}

fn eth_udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(src, dst, 64)
        .udp(sp, dp)
        .write(&mut v, payload)
        .unwrap();
    v
}

fn eth_tcp(
    src: [u8; 4],
    dst: [u8; 4],
    sp: u16,
    dp: u16,
    seq: u32,
    kind: &str,
    payload: &[u8],
) -> Vec<u8> {
    let b = PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(src, dst, 64)
        .tcp(sp, dp, seq, 64_000);
    let b = match kind {
        "syn" => b.syn(),
        "synack" => b.syn().ack(1),
        "fin" => b.fin().ack(1),
        _ => b.ack(1),
    };
    let mut v = Vec::new();
    b.write(&mut v, payload).unwrap();
    v
}

fn dns_msg(response: bool) -> Vec<u8> {
    let mut v = vec![0x12, 0x34];
    v.extend_from_slice(if response {
        &[0x81, 0x80]
    } else {
        &[0x01, 0x00]
    });
    v.extend_from_slice(&[0, 1, 0, u8::from(response), 0, 0, 0, 0]);
    v.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    if response {
        v.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4]);
        v.extend_from_slice(&SRV);
    }
    v
}

fn client_hello(sni: &str) -> Vec<u8> {
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    entry.extend_from_slice(sni.as_bytes());
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&((entry.len() + 2) as u16).to_be_bytes());
    ext.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    ext.extend_from_slice(&entry);
    ext.extend_from_slice(&[0, 51, 0x04, 0xE2]); // key_share, 1250 bytes (post-quantum sized)
    ext.extend(std::iter::repeat_n(0xAB, 1250));
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn scenario() -> Vec<(u32, u32, Vec<u8>)> {
    let hello = client_hello("www.example.com");
    let (a, b) = hello.split_at(1000);
    vec![
        (
            1_795_628_100,
            0,
            eth_udp(ME, DNS, 50000, 53, &dns_msg(false)),
        ),
        (
            1_795_628_100,
            20_000,
            eth_udp(DNS, ME, 53, 50000, &dns_msg(true)),
        ),
        (
            1_795_628_100,
            30_000,
            eth_tcp(ME, SRV, 51000, 443, 100, "syn", &[]),
        ),
        (
            1_795_628_100,
            60_000,
            eth_tcp(SRV, ME, 443, 51000, 900, "synack", &[]),
        ),
        (
            1_795_628_100,
            61_000,
            eth_tcp(ME, SRV, 51000, 443, 101, "ack", a),
        ),
        (
            1_795_628_100,
            61_500,
            eth_tcp(ME, SRV, 51000, 443, 1101, "ack", b),
        ),
        (
            1_795_628_101,
            0,
            eth_tcp(SRV, ME, 443, 51000, 901, "ack", &[0x17; 900]),
        ),
        (
            1_795_628_102,
            0,
            eth_tcp(ME, SRV, 51000, 443, 101 + hello.len() as u32, "fin", &[]),
        ),
        (
            1_795_628_102,
            1_000,
            eth_tcp(SRV, ME, 443, 51000, 1801, "fin", &[]),
        ),
    ]
}

fn lines(out: &[u8]) -> Vec<Value> {
    std::str::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn check(events: &[Value]) {
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "engine_start",
            "flow_start",
            "dns",
            "dns",
            "flow_start",
            "tls_client_hello",
            "flow_end",
            "flow_end",
            "engine_stop"
        ]
    );
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e["schema"], "silentsnake.capture/1");
        assert_eq!(e["seq"], i as u64 + 1, "seq must be gap-free");
        assert!(!e["summary"].as_str().unwrap().is_empty());
        assert!(e["ts"].as_str().unwrap().ends_with('Z'));
    }
    assert_eq!(events[0]["source"]["kind"], "file");
    assert_eq!(events[3]["answers"][0]["data"], "93.184.216.34");
    assert_eq!(
        events[3]["summary"],
        "DNS answer from 1.1.1.1:53 for example.com (A): 93.184.216.34."
    );

    let tcp = &events[4];
    assert_eq!(tcp["direction"], "outbound");
    assert_eq!(tcp["server_name"], "example.com");
    assert_eq!(tcp["server_name_source"], "dns");
    assert_eq!(tcp["ts"], "2026-11-25T17:35:00.030000Z");

    assert_eq!(events[5]["server_name"], "www.example.com");
    let end = &events[6];
    assert_eq!(end["reason"], "closed");
    assert_eq!(end["server_name"], "www.example.com");
    assert_eq!(end["server_name_source"], "sni");
    assert_eq!(end["duration_ms"], 1971);
    assert_eq!(
        (
            end["initiator_packets"].as_u64(),
            end["responder_packets"].as_u64()
        ),
        (Some(4), Some(3))
    );
    assert!(end["summary"].as_str().unwrap().starts_with(
        "Outbound TCP connection to www.example.com (93.184.216.34:443) closed normally after 2.0 s"
    ));

    assert_eq!(events[7]["proto"], "udp");
    assert_eq!(events[7]["reason"], "capture_end");
    assert_eq!(events[8]["reason"], "end_of_file");
    assert_eq!(events[8]["packets_seen"], 9);
    assert_eq!(events[8]["tls_client_hellos"], 1);
}

#[test]
fn library_reads_pcap_through_libpcap() {
    let dir = TempDir::new("lib");
    let path = dir.0.join("scenario.pcap");
    write_pcap(&path, &scenario());
    let cfg = RunConfig {
        source: Source::File { path },
        filter: None,
        duration: None,
        max_packets: None,
        stats_interval: None,
        local_addrs: vec![ME.into()],
        engine: EngineConfig::default(),
        identity: Identity::unprivileged(1000),
    };
    let mut out = Vec::new();
    source::run(&cfg, &mut out).unwrap();
    check(&lines(&out));

    // A BPF filter is compiled and applied by libpcap: only DNS survives.
    let mut out = Vec::new();
    source::run(
        &RunConfig {
            filter: Some("udp port 53".into()),
            ..cfg.clone()
        },
        &mut out,
    )
    .unwrap();
    let ev = lines(&out);
    assert!(ev.iter().all(|e| e["type"] != "tls_client_hello"));
    assert_eq!(ev.last().unwrap()["packets_seen"], 2);

    let bad = source::run(
        &RunConfig {
            filter: Some("not a ( filter".into()),
            ..cfg
        },
        &mut Vec::new(),
    );
    assert!(bad.unwrap_err().to_string().starts_with("invalid filter"));
}

#[test]
fn binary_end_to_end_and_usage_errors() {
    let dir = TempDir::new("bin");
    let path = dir.0.join("scenario.pcap");
    write_pcap(&path, &scenario());
    let bin = env!("CARGO_BIN_EXE_silentsnake-capture");

    let out = Command::new(bin)
        .args([
            "--read",
            path.to_str().unwrap(),
            "--local-addr",
            "192.168.1.10",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    check(&lines(&out.stdout));

    let out = Command::new(bin).args(["--bogus"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin)
        .args(["-i", "lo", "-r", "x.pcap"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin)
        .args(["--read", "/nonexistent.pcap"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}
