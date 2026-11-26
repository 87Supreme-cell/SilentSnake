# NIST control mapping

Maps SilentSnake controls to NIST SP 800-53 and NIST SSDF (SP 800-218), per CLAUDE.md section 4. Filled in as each control is implemented; a row is only added once a test or the 60-second proof demonstrates it.

| SilentSnake control | Implemented in | Proven by | NIST SP 800-53 | NIST SSDF |
|---|---|---|---|---|
| Capture runs without root, with `CAP_NET_RAW` only; refuses root and extra capabilities (fails closed) | `crates/capture/src/privilege.rs`, `main.rs` | `scripts/smoke-capture-loopback.sh` (checks 1 to 4); `privilege.rs` unit tests | AC-6, AC-6(9) | PW.5.1 |
| Untrusted packet data parsed only in memory-safe Rust with bounded, panic-free parsers | `crates/capture/src/{dns,tls,decode}.rs` (`unsafe` forbidden, `clippy::indexing_slicing` denied) | `robustness.rs` randomized tests; `cargo geiger` (crate forbids unsafe) | SI-10, SI-16 | PW.5.1, PW.8.2 |
| Names from traffic sanitized before reaching logs, UI or LLM | `crates/capture/src/sanitize.rs` | `sanitize.rs`, `dns.rs`, `tls.rs` unit tests (control bytes, spaces, quotes, fake separators) | SI-10, SI-15 | PW.5.1 |
| Bounded memory under hostile traffic (flow table, DNS cache, TLS buffers) | `crates/capture/src/engine.rs` | `robustness.rs`: `engine_survives_garbage…`, `idle_expiry_and_eviction_are_bounded`, `tls_buffer_budget_is_enforced` | SC-5 | PW.5.1, PW.8.2 |
| Capture completeness is visible: gap-free event `seq`, kernel drop counts reported | `crates/capture/src/source.rs`, `summary.rs` | `tests/offline.rs` (seq check); smoke test (seq check) | AU-3, AU-5 | PW.8.2 |
| Monitoring survives traffic bursts (no kernel ring overflow) | `crates/capture/src/source.rs` (snaplen, TPACKET_V3 ring, idle wait), lax decoding in `decode.rs` | `scripts/smoke-capture-loopback.sh` check 1b: three tight 20,000-datagram bursts (240,000 packets), 0 kernel drops, all processed, 0 unprocessed at stop (runs in CI) | SI-4, SC-5 | PW.8.2 |
| Local API cannot be reached off-host or abused locally | `services/api` (`main.go` loopback-only `--listen`; `server.go` loopback peer + Host check, constant-time bearer token, GET only, strict query validation, rate limit; token file 0600 in 0700 dirs) | `scripts/smoke-api.sh` (no listener on the non-loopback address, 401 without token, refuses `--listen 0.0.0.0`); `go test -race` guard tests; `go test -fuzz` on query handling (runs in CI) | AC-3, IA-2, SC-7, SI-10, SC-5 | PW.7, PW.8 |
| Mature capture library reused instead of new `unsafe` code | libpcap via `pcap` crate (ADR-0001) | `cargo deny`, `cargo audit`, `osv-scanner` clean on `Cargo.lock` | SA-15, SR-3 | PW.4.1 |
