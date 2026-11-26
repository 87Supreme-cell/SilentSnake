# ADR-0002: Per-distribution builds, tarball packaging, pinned nightly for fuzzing

- **Status:** accepted (Ronin, 2026-11-25), including target versions and the nightly pin.
- **Traces to:** `dependencies.json` > `version_policy`, `security_tooling` (`signing`, `sbom`, `fuzzing`, `memory_safety`), `smoke_tests` ("binaries build reproducibly"); `silentsnake.yaml` > `compliance.supply_chain`; ADR-0001 "Open items".

## Decisions

### 1. Build targets: one build per distribution (Ubuntu, Debian, Fedora)

**Targets (Ronin, 2026-11-25): the latest release of each: Ubuntu 26.04 LTS, Debian 13 (trixie), Fedora 45.**

Each release is built natively for each supported distribution, in a pinned build container per distribution (base image pinned by digest), linking that distribution's own glibc and `libpcap.so.1`.

- **Why (Ronin's choice):** binaries match each distribution's own libraries exactly; libpcap security fixes keep coming from the distribution's updates; no static C dependencies to maintain ourselves.
- **Cost:** one build pipeline and one smoke-test run per target. Each target gets the full gate (tests, `scripts/smoke-capture-loopback.sh`, reproducibility check, SBOM, signatures).
- **Out of scope:** other distributions (Arch, Alpine, RHEL, openSUSE) are not built or claimed. Phase 2 targets come with Ronin's config override.

### 2. Packaging: signed tarball now, native packages later
- **Now:** one tarball per target containing the binary, `LICENSE`, the SBOM (syft, SPDX + CycloneDX), checksums and a cosign signature, plus an install script. The script installs to `~/.local/bin` (user) or `/usr/local/bin` (system) and applies `setcap cap_net_raw=ep` (needs sudo once). This works on immutable hosts without package layering.
- **Later:** `.deb` and `.rpm` (which can set the capability themselves), when Ronin asks.
- **Not suitable:** Flatpak, Snap and AppImage can't carry `CAP_NET_RAW` for the capture binary.

### 3. Pinned nightly toolchain, for fuzzing and Miri only
- A single dated nightly, at least two weeks old (`version_policy`), installed in the dev container next to stable and used **only** for `cargo fuzz` (packet parsers) and `cargo miri` (the `ffi` crate). Release binaries are always built with stable (`rust-toolchain.toml`).
- **Pin (Ronin, 2026-11-25): `nightly-2026-11-10`** (rustc 1.102.0-nightly ac8310ba6), channel manifest SHA-256 `c2986ce080bf1c0e2b96a20d8e704ab33fdd95f1e347f75e0e6ace780909620c`; `miri` and `rust-src` available. The Containerfile checks the published manifest against this hash before rustup installs from it (rustup then verifies every component against the manifest).

- **Fuzz dependencies (Ronin, 2026-11-25):** `libfuzzer-sys =0.4.13` (crate checksum `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2`), in the separate, never-shipped `fuzz/` workspace with its own `Cargo.lock` and `fuzz/deny.toml`. That file adds `NCSA` (LLVM libFuzzer, bundled) to the license allowlist for the fuzz workspace only. Transitive crates new to the project: `arbitrary 1.5.0` (2026-10-06), `jobserver 0.1.35` (2026-07-06), `getrandom 0.4.3` (2026-06-17), `r-efi 6.0.0` (2026-02-03, UEFI targets only, never compiled here). All are MIT/Apache-2.0 and at least two weeks old. cargo-deny, cargo-audit and osv-scanner are clean on `fuzz/Cargo.lock`.
- Run with `scripts/fuzz.sh [target] [seconds]`; targets `dns`, `tls`, `decode`, `engine`. Seeds in `fuzz/seeds/`.

## Open (needs Ronin)
- Base image digests for the Ubuntu 26.04 and Debian 13 build containers (proposed when that work starts).
