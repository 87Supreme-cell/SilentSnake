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
  step "gofmt";          (cd services && test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; })
  step "go vet";         (cd services && go vet ./...)
  step "go test -race";  (cd services && go test -race -count=1 ./...)
  step "go fuzz (10 s)"; (cd services && go test -run=^$ -fuzz=FuzzQueryValidation -fuzztime=10s ./api)
  step "govulncheck";    (cd services && govulncheck ./...)
  step "staticcheck";    (cd services && staticcheck ./...)
  step "gosec";          (cd services && gosec -quiet ./...)
  step "osv-scanner";    osv-scanner scan source -r .
  step "gitleaks (full history)"; gitleaks git --no-banner --redact --log-level=warn .
  step "gitleaks (working tree)"; gitleaks dir --no-banner --redact --log-level=warn .
  echo; echo "ALL GATES PASSED"
'
