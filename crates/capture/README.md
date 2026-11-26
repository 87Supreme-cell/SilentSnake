# capture (Rust): stage A

Live and offline packet capture on libpcap: flows, DNS, TLS SNI, and plain-English summaries, emitted as JSON lines (`silentsnake.capture/1`).

- **Why libpcap, and how it deploys locally:** [`docs/decisions/0001-stage-a-libpcap-capture.md`](../../docs/decisions/0001-stage-a-libpcap-capture.md)
- **Event schema:** [`docs/api/capture-events.md`](../../docs/api/capture-events.md)

## Use

```sh
silentsnake-capture --help
silentsnake-capture --list-interfaces
silentsnake-capture -r trace.pcap --local-addr 192.168.1.10     # no privileges needed
silentsnake-capture -i any -f "tcp port 443 or udp port 53"     # needs CAP_NET_RAW
```

Live capture needs `CAP_NET_RAW` on the binary, never root: `sudo setcap cap_net_raw=ep <path>`. The engine refuses to start as root or with any other effective capability (exit 3).

**Stage A writes only to stdout.** Logs must be encrypted at rest (`CLAUDE.md` section 3) and the encrypted log store doesn't exist yet, so don't redirect the output to a file outside testing.

## Layout

| Module | Role |
|---|---|
| `source.rs` | libpcap I/O (live non-blocking / file), BPF filter, JSON-lines writer with gap-free `seq` |
| `engine.rs` | Flow table (bounded), direction, DNS name cache, TLS ClientHello reassembly (budgeted) |
| `decode.rs` | Link layers (Ethernet, Linux SLL/SLL2, raw IP, BSD null) → IP + TCP/UDP via `etherparse` |
| `dns.rs`, `tls.rs` | Bounded, safe-Rust parsers (no indexing panics: `clippy::indexing_slicing` denied) |
| `sanitize.rs` | Escapes untrusted name bytes before they reach logs, the UI or the LLM |
| `privilege.rs` | Root / capability guard from `/proc/self/status` |
| `summary.rs`, `event.rs`, `time.rs` | Summaries, schema, RFC 3339 timestamps |

## Tests

- `cargo test -p silentsnake-capture`: parser unit tests, engine behaviour, randomized robustness (20 000 hostile inputs per parser), and end-to-end runs of the library and binary through real libpcap on a synthetic pcap file.
- `scripts/smoke-capture-loopback.sh`: live loopback capture as a non-root user with only `CAP_NET_RAW`, plus refusal of root, of extra capabilities, and of capture without `CAP_NET_RAW`.
