#!/usr/bin/env bash
# Merge gates (dependencies.json > security_tooling, smoke_tests; CLAUDE.md section 4).
# One definition, used locally, by CI (.github/workflows/gates.yml) and by scripts/release.sh.
# Runs in the pinned dev container and fails closed on the first failure.
#   scripts/gates.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
exec "$root/scripts/dev.sh" bash -c '
  set -euo pipefail
  step() { echo; echo "== gate: $*"; }
  step "rustfmt";        cargo fmt --all --check
  step "clippy";         cargo clippy --workspace --all-targets --locked -- -D warnings
  step "tests";          cargo test --workspace --locked
  step "cargo-deny";     cargo deny check
  step "cargo-audit";    cargo audit
  step "fuzz workspace"; (cd fuzz && cargo deny check && cargo audit)
  step "osv-scanner";    osv-scanner scan source -r .
  step "gitleaks (full history)"; gitleaks git --no-banner --redact --log-level=warn .
  step "gitleaks (working tree)"; gitleaks dir --no-banner --redact --log-level=warn .
  echo; echo "ALL GATES PASSED"
'
