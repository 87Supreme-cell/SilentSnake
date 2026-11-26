# CLAUDE.md — SilentSnake

You are building SilentSnake: an MIT-licensed, fully local Linux tool that monitors inbound and outbound traffic, processes, web sessions and systemd daemons, with a real-time GUI, desktop widgets, audit-grade logs, and a sandboxed LLM analyst.

## 0. Authority (read first)
- **Ronin owns every decision.** You implement; you suggest. You never assume intent, add scope, or start a new phase without Ronin's explicit go-ahead. If something is ambiguous, stop and ask.
- **`silentsnake.yaml` and `dependencies.json` are non-negotiable.** They are the spec. Do not contradict, reinterpret, or "improve" them. If you believe one is wrong, raise it with Ronin and wait. Every change must be traceable to a line in one of them.
- **Permissions are set by the user, never by an LLM.** This applies to SilentSnake's runtime and to you while building it.
- Ronin is a senior data/AI engineer. Be precise and terse; no beginner framing.

## 1. Build order
1. **Backend first** (you): capture engine (Rust), encrypted log store (Rust), local REST API + LLM sandbox (Go). Expose a stable, documented, versioned API.
2. **Frontend second** (Ronin leads): Flutter/Dart dashboard and widgets. Do not design or build UI unless Ronin asks. When asked, follow `design:` in `silentsnake.yaml` and section 6 below.
3. Capture backends follow `capture_integration_roadmap` in `dependencies.json` (A native libpcap → B tcpdump/tshark adapters → C eBPF process attribution → D mitmproxy → E Zeek). One stage at a time, each approved by Ronin.

## 2. First-run setup
On first launch SilentSnake creates its own home, with no manual steps:
- `$XDG_DATA_HOME/silentsnake/` (default `~/.local/share/silentsnake/`), mode `0700`, owned by the invoking user.
- Subfolders: `logs/` (encrypted), `exports/` (signed), `keys/` (public material only), `config/`, `llm-sandbox/` (read-only mount of logs).
- Generate the machine signing and encryption keys (section 3), write a signed `setup.manifest`, and print a plain-English summary of what was created.
- Idempotent: re-running never overwrites keys or logs. Refuse to start if permissions on the folder are looser than `0700`.

## 3. Data encryption and signing (non-negotiable)
- **All logs are encrypted at rest.** AEAD only (AES-256-GCM via the FIPS-capable provider in `dependencies.json`). No plaintext log ever touches disk, including temp files and crash dumps.
- **Machine-bound keys.** Keys are generated locally and sealed to the machine: TPM 2.0 when present, otherwise the Linux kernel keyring / OS secret store with a user passphrase. Private keys never leave the machine and are never readable by the LLM sandbox.
- **Signed open/close.** Every open and close of a log is a signed event by the local machine key (Ed25519, or ECDSA P-256 in FIPS mode), appended to a hash-chained audit log. A log cannot be opened without a valid machine signature; tampering breaks the chain and is surfaced in the UI.
- Exports are signed and include a verification command.
- `zeroize` all key material and decrypted buffers after use.

## 4. Security rules for every change
- Pin everything; no new dependency without Ronin's approval (see `version_policy`).
- No `unsafe` Rust outside one reviewed FFI module. Never run as root; use `CAP_NET_RAW`/`CAP_BPF` on the capture binary only.
- REST API binds `127.0.0.1` only, token-authenticated.
- LLM sandbox: read-only on decrypted views of logs it's granted, no network egress, no writes, no exec. Commercial LLM endpoints are off by default and send only redacted summaries when Ronin enables them.
- Map controls to NIST SP 800-53 and NIST SSDF (SP 800-218). Record the mapping in `docs/controls.md`.
- All `security_tooling` and `smoke_tests` in `dependencies.json` gate every merge.

## 5. Definition of done
Smoke tests are necessary, not sufficient. **A feature is done only when it is proven in a recorded 1-minute live session** on a real Linux machine:
1. Fresh install → first-run folder created and keys sealed (≈10 s).
2. Live traffic appears on the dashboard, attributed to processes/daemons, with risk scores (≈20 s).
3. Start and stop a deep scan; results are encrypted, the open/close events are signed and verifiable (≈15 s).
4. Ask the LLM analyst one question; its answer shows its evidence and is written to the audit log; it cannot egress (≈15 s).
Script it as `scripts/demo-60s.sh`, record it with asciinema (terminal) plus a screen capture once the UI exists, and store the result in `docs/proof/`.

## 6. Design direction (when Ronin asks for UI work)
- Follow `design:` in `silentsnake.yaml` and `ui-references/INDEX.md`. Ronin's `ronin-style-reference.jpg` is the primary style.
- **Inspiration: the tactical stealth-espionage aesthetic of Metal Gear Solid**: radar/soliton-style sweep for live connections, codec-style split panel for the LLM analyst, alert states (normal → caution → alert) mapped to the risk scale, mission-HUD typography. **Inspiration only:** no names, logos, characters, sounds, icons, fonts or art from the franchise. Everything original.
- Futuristic, smooth motion: 60 fps target, GPU-friendly Flutter animations (implicit animations, `Rive` or custom shaders where justified), eased transitions, live sweeps and pulses. Respect "reduce motion" settings. Animation never delays a security-relevant state change.
- Accessibility per `color_and_accessibility` (WCAG 2.2 AA, never color alone).
- Images in `ui-references/` are third-party: never commit them to the repo.

## 7. Adversarial agent
A dedicated red-team subagent (`.claude/agents/adversary.md`) attacks every milestone before it is considered done. You must:
- Run it after each backend component and before every release.
- Fix or explicitly document (with Ronin's approval) every finding. Keep the reports in `docs/security/pentest-<date>.md`.
- Never weaken its scope or ignore a finding to make a milestone pass.

## 8. README standard
`README.md` must be portfolio-grade and ready for audit by senior engineers:
- One-line value proposition, hero screenshot/GIF of the real UI (added as the UI is built), and the 60-second proof recording.
- Architecture diagram (capture → encrypted store → API → UI/LLM sandbox), threat model summary, NIST control mapping link, and a crypto design section.
- Exact reproducible install/build steps, SBOM and signature verification instructions, test and pentest results, roadmap, and an MIT license badge.
- No marketing claims that aren't proven by a test or the recording. Update the screenshots every time the UI changes.

## 9. Phases
- Phase 1: civilian and local, with no military content in code, docs or commits.
- Phase 2: GFE deployment via a separate config override supplied by Ronin. Keep every environment-specific value in config, never in code.
