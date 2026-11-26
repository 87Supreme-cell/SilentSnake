# ADR-0001: Stage A capture on libpcap (via the `pcap` crate) with `etherparse`

- **Status:** accepted (Ronin approved stage A, 2026-11-25)
- **Traces to:** `dependencies.json` > `capture_integration_roadmap` stage A ("Rust engine on libpcap; flows, DNS, TLS SNI; plain-English summaries"); `runtime_dependencies.rust` (`pcap`, `etherparse`, `serde`/`serde_json`); `runtime_dependencies.system` (`libpcap`); `CLAUDE.md` sections 1, 3 and 4.
- **Pins:** `pcap =2.5.0`, `etherparse =0.21.1`, `serde =1.0.229`, `serde_json =1.0.154` (approved 2026-11-25, locked with hashes in `Cargo.lock`). System libpcap is whatever the distribution ships (1.10.7 on the build container and on the reference host).

## Context

SilentSnake must watch inbound and outbound traffic on a single Linux machine, fully locally, without running as root, and feed a log store and a local API. Stage A is the first capture backend; stages B to E add tcpdump/tshark adapters, eBPF process attribution, optional mitmproxy and optional Zeek on top of it.

The engine has to run on whatever Linux machine Ronin (or, in phase 2, an administrator) puts it on, with no cloud service, no network dependency and as few moving parts as possible.

## Decision

Capture packets with **libpcap**, called from Rust through the **`pcap`** crate, and decode headers with **`etherparse`**. DNS and the TLS ClientHello are decoded by SilentSnake's own small, bounded, safe-Rust parsers, because neither crate covers them.

## Why libpcap is the right fit for this work

1. **It is the standard capture interface on Linux.** tcpdump, tshark/Wireshark, Zeek, Suricata, ntopng and Sniffnet all capture through libpcap. Choosing it means stage A sees exactly what those tools see, and stages B (tcpdump/tshark) and E (Zeek) sit on the same capture layer instead of a second, competing one.
2. **It does the hard kernel work already, in a mature way.** On Linux, libpcap opens a `PF_PACKET` socket with a memory-mapped ring buffer (TPACKET_V3), and compiles filter expressions to BPF that run *in the kernel*, so packets we don't want are dropped before they reach user space. Re-implementing that directly on raw sockets would mean writing and maintaining our own `unsafe` socket and ring-buffer code, which `CLAUDE.md` section 4 tells us to avoid.
3. **Least privilege fits the spec exactly.** A live capture needs only `CAP_NET_RAW` on the capture binary: no root, no kernel module, no daemon. That is the rule in `CLAUDE.md` section 4 and `dependencies.json` > `threat_model` > "privilege escalation". Reading a saved `.pcap` file needs no privileges at all.
4. **Stable, long-lived ABI.** The `libpcap.so.1` shared-library name and its core API have been stable since libpcap 1.0 (2008), so a binary linked against it keeps working across distribution updates.
5. **No kernel-version coupling.** eBPF (stage C, `aya`) depends on kernel version, BTF availability and `CAP_BPF`; libpcap works on any kernel a supported distribution ships. Stage A gives a baseline that runs everywhere; stage C adds process attribution where the kernel allows it.
6. **One open file format.** libpcap reads and writes the pcap format that every analysis tool understands, so captures can be replayed into SilentSnake offline (`--read`) and SilentSnake's own deep-scan captures (later) can be opened in Wireshark for independent verification.
7. **Licensing is clean.** libpcap is BSD-3-Clause; the `pcap` and `etherparse` crates are MIT OR Apache-2.0. All three are on the `deny.toml` allowlist and compatible with SilentSnake's MIT license.

### Why the `pcap` crate and `etherparse` specifically

- **`pcap` 2.5.0** is a thin, widely used binding: its only runtime dependencies on Linux are `libc`, `bitflags` and `errno`. The optional async (`tokio`) and lending-iterator features are left off, so the locked dependency tree stays at 41 crates. All `unsafe` FFI lives inside that crate, so SilentSnake's own code stays `#![forbid(unsafe_code)]`.
- **`etherparse` 0.21.1** is a zero-copy, pure-Rust header parser (Ethernet, Linux cooked capture v1, VLAN, IPv4/IPv6 with extension headers, TCP, UDP, ICMP). It allocates nothing per packet and returns errors rather than panicking on malformed input. That puts all packet parsing in memory-safe Rust, as `dependencies.json` > `threat_model` > "memory leakage" requires. 0.21.1 is the pinned release that fixes RUSTSEC-2026-0596.

## How this allows a universally local deploy

**"Local" here means everything happens on the monitored machine:** capture, decoding and output, with no network service, account, telemetry or cloud dependency.

| Property | How stage A achieves it | Status |
|---|---|---|
| Works fully offline / air-gapped | No network calls of its own and no runtime downloads. Builds fetch crates once, checked against `Cargo.lock` hashes; vendoring for fully offline builds (`threat_model`) is not set up yet | Runtime: by design, adversary to confirm. Offline build: pending |
| No root, no daemon, no kernel module | `CAP_NET_RAW` file capability on one binary; refuses to start as root or with any other effective capability | Enforced in code (`privilege.rs`) and tested |
| Runs on any mainstream distribution | Only system dependencies are glibc and `libpcap.so.1`, which is in the base repositories of Fedora/RHEL, Debian/Ubuntu, Arch, openSUSE and Alpine | Fedora 45 container: live + file capture tested. Aurora 45 host: binary loads the host's libpcap 1.10.7, lists interfaces, fails cleanly without `CAP_NET_RAW`. Other distributions not yet tested |
| Works on immutable/atomic hosts | A single user-owned binary (e.g. `~/.local/bin`) plus one `setcap`; nothing installed into `/usr` | Binary runs from the user's home on Aurora 45 (Kinoite). Live capture there after `setcap`: pending (needs Ronin's sudo) |
| Works in VMs and containers | libpcap needs only a network namespace and `CAP_NET_RAW` | `scripts/smoke-capture-loopback.sh`: live loopback capture as a non-root user with only `CAP_NET_RAW` in the rootless dev container |
| Same view as standard tools | Same library and BPF filter language as tcpdump/tshark | By construction |
| Offline analysis without privileges | `--read file.pcap` replays any capture through the same engine | Tested |

**Open items that "universal" still depends on:**
- **glibc baseline.** A binary built on Fedora 45 needs Fedora 45's glibc or newer. To run on older distributions it must be built on (or for) the oldest supported glibc, or built statically against musl together with a static libpcap. This needs a decision from Ronin and is not claimed as done.
- **Packaging format** (tarball + `setcap`, RPM/deb, or something else) hasn't been decided; it's Ronin's call. Sandboxed app formats such as Flatpak can't grant `CAP_NET_RAW` to a capture binary, so they're not suitable for the capture engine.
- **Architectures.** Only x86_64 is built and tested (`deny.toml` targets). libpcap, the crates and Rust all support aarch64, but nothing is claimed until it is built and tested.

## Alternatives considered

| Option | Why not (for stage A) |
|---|---|
| Raw `AF_PACKET` sockets written by us | Re-implements libpcap's ring buffer and BPF handling with our own `unsafe` code; more attack surface, no benefit |
| eBPF via `aya` | Planned for stage C (process attribution). Kernel/BTF dependent and needs `CAP_BPF`; not a universal baseline |
| `pnet` crate | Larger dependency, not in the approved list, and libpcap is still needed for BPF filters and pcap files |
| Run tcpdump/tshark and parse their output | Planned for stage B as *adapters*. As the only backend it would add a subprocess and a text-parsing boundary with no structured flow state |
| nftables/conntrack (netlink) | Gives connection metadata only: no DNS or SNI, and needs `CAP_NET_ADMIN` |

## Consequences and known limits (stage A)

- **No process attribution yet.** Flows are tagged by address, port and direction only; process and systemd unit come in stage C.
- **QUIC / HTTP/3 server names are not decoded.** The QUIC Initial packet is encrypted with keys derived from the connection ID, and decrypting it needs AEAD code that stage A does not take on. QUIC flows still appear, tagged `quic`, and get a name from earlier DNS answers where one exists.
- **Encrypted Client Hello (ECH)** hides the real server name; the engine flags `ech: true` and reports the outer (public) name only.
- **DNS over TCP, DoT and DoH** are not decoded (DoT/DoH are encrypted by design). Plain UDP DNS, mDNS and LLMNR are.
- **TLS reassembly** only follows in-order client segments, so a ClientHello split by reordering or a gap is counted as `tls_unparsed`, not guessed at.
- **Output is a stream to stdout, never to disk.** `CLAUDE.md` section 3 forbids plaintext logs on disk, so until the encrypted log store exists, stage A has no file or journald output and ships no systemd unit (journald would persist plaintext). Don't redirect it to a file outside testing.
- **libpcap's own C code** parses `.pcap` files given with `--read`. That is third-party C attack surface; only read files you trust until the adversary has reviewed this path.
- **Fuzzing with cargo-fuzz** needs a pinned nightly toolchain, which is pending approval. Until then the DNS, TLS and decode parsers are covered by deterministic randomized robustness tests.
