#!/usr/bin/env bash
# Smoke test (dependencies.json > smoke_tests): "capture engine starts without root and
# captures loopback traffic". Runs the debug binary in the pinned dev container as a
# non-root user holding only CAP_NET_RAW, generates loopback traffic, and checks the events.
# Also checks that the engine refuses root and capabilities beyond CAP_NET_RAW.
#   scripts/smoke-capture-loopback.sh        (builds first)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="silentsnake-dev:$(sha256sum "$root/dev/Containerfile" | cut -c1-12)"
"$root/scripts/dev.sh" cargo build -q -p silentsnake-capture

run() { # run <user> <extra podman args...> -- <bash script>
  local user="$1"; shift
  local args=(); while [ "$1" != "--" ]; do args+=("$1"); shift; done; shift
  timeout 60 podman run --rm --userns=keep-id --user "$user" \
    --security-opt no-new-privileges --cap-drop=all "${args[@]}" \
    -v "$root:/work:Z" "$tag" bash -c "$1"
}
fail() { echo "FAIL: $*" >&2; exit 1; }
bin=./target/debug/silentsnake-capture
me="$(id -u):$(id -g)"

# 1. Unprivileged user + CAP_NET_RAW only: live loopback capture works.
out="$(run "$me" --cap-add=NET_RAW -- "
  ( sleep 1; for i in 1 2 3; do echo smoke > /dev/udp/127.0.0.1/9; done
    (exec 3<>/dev/tcp/127.0.0.1/1) 2>/dev/null; true ) &
  timeout -s KILL 15 $bin -i lo --duration 3 --stats 1")"
n=$(grep -c . <<<"$out")
head -n1 <<<"$out" | grep -q "\"type\":\"engine_start\".*\"euid\":$(id -u),\"cap_net_raw\":true" || fail "engine_start does not show a non-root euid with CAP_NET_RAW"
grep -q '"type":"flow_start".*"proto":"udp","direction":"local".*"responder":{"ip":"127.0.0.1","port":9}' <<<"$out" || fail "no local UDP flow to 127.0.0.1:9"
grep -q '"type":"flow_end".*"proto":"tcp".*"reason":"reset"' <<<"$out" || fail "no reset TCP flow to 127.0.0.1:1"
grep -q '"type":"stats"' <<<"$out" || fail "no stats event"
tail -n1 <<<"$out" | grep -q '"type":"engine_stop","reason":"duration"' || fail "did not stop on --duration"
for i in $(seq 1 "$n"); do sed -n "${i}p" <<<"$out" | grep -q "\"seq\":$i," || fail "seq gap at line $i"; done
echo "ok: non-root + CAP_NET_RAW captured loopback traffic ($n events, gap-free seq)"

# 2. Root is refused (exit 3) before any capture handle is opened.
set +e
run 0:0 --cap-add=NET_RAW -- "$bin -i lo --duration 1" >/dev/null 2>&1; rc=$?
[ $rc -eq 3 ] || fail "root not refused (exit $rc)"
echo "ok: root refused"

# 3. Capabilities beyond CAP_NET_RAW are refused (exit 3).
run "$me" --cap-add=NET_RAW --cap-add=NET_ADMIN -- "$bin -i lo --duration 1" >/dev/null 2>&1; rc=$?
[ $rc -eq 3 ] || fail "extra capability not refused (exit $rc)"
echo "ok: extra capabilities refused"

# 4. Without CAP_NET_RAW, live capture fails cleanly (no partial run).
run "$me" -- "$bin -i lo --duration 1" >/dev/null 2>&1; rc=$?
[ $rc -eq 1 ] || fail "capture without CAP_NET_RAW did not fail cleanly (exit $rc)"
echo "ok: no CAP_NET_RAW -> clean failure"
echo "PASS: smoke-capture-loopback"
