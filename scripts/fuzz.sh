#!/usr/bin/env bash
# Coverage-guided fuzzing of the capture parsers with the pinned nightly (ADR-0002).
#   scripts/fuzz.sh                 run every target for 60 s
#   scripts/fuzz.sh dns 600         run one target for 600 s
# Crashes land in fuzz/artifacts/<target>/ (gitignored); seeds come from fuzz/seeds/.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
targets=("${1:-dns}"); [ $# -eq 0 ] && targets=(dns tls decode engine)
secs="${2:-60}"
for t in "${targets[@]}"; do
  "$root/scripts/dev.sh" bash -c "
    set -euo pipefail
    cd fuzz && mkdir -p corpus/$t
    seeds=(); [ -d seeds/$t ] && seeds=(seeds/$t)
    before=\$(sha256sum Cargo.lock)
    cargo +nightly-2026-11-10 fuzz run $t corpus/$t \"\${seeds[@]}\" -- -max_total_time=$secs -rss_limit_mb=2048 -timeout=10
    # cargo fuzz has no --locked: refuse any lockfile change instead.
    [ \"\$before\" = \"\$(sha256sum Cargo.lock)\" ] || { echo 'fuzz/Cargo.lock changed: refusing' >&2; exit 1; }
  "
done
