#!/usr/bin/env bash
# Smoke test (dependencies.json > smoke_tests): "capture engine starts without root and
# captures loopback traffic". Runs the release binary in the pinned dev container as a
# non-root user holding only CAP_NET_RAW, generates loopback traffic, and checks the events.
# Also checks that the engine refuses root and capabilities beyond CAP_NET_RAW.
#   scripts/smoke-capture-loopback.sh        (builds the optimized release binary, runs in the dev container)
# Always the release profile: it is what ships, and the burst check measures real throughput.
# Release use (scripts/release.sh) tests the shipped binary in the target distribution's image:
#   SMOKE_BIN=dist/<...>/silentsnake-capture SMOKE_IMAGE=<build image tag> scripts/smoke-capture-loopback.sh
#   SMOKE_BIN is relative to the repository root.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="${SMOKE_IMAGE:-silentsnake-dev:$(sha256sum "$root/dev/Containerfile" | cut -c1-12)}"
if [ -z "${SMOKE_BIN:-}" ]; then
  "$root/scripts/dev.sh" cargo build -q --release --locked -p silentsnake-capture
fi

run() { # run <user> <extra podman args...> -- <bash script>
  local user="$1"; shift
  local args=(); while [ "$1" != "--" ]; do args+=("$1"); shift; done; shift
  timeout 60 podman run --rm --userns=keep-id:uid=1000,gid=1000 --user "$user" \
    --security-opt no-new-privileges --cap-drop=all "${args[@]}" \
    -v "$root:/work:Z" "$tag" bash -c "$1"
}
fail() { echo "FAIL: $*" >&2; exit 1; }
bin="./${SMOKE_BIN:-target/release/silentsnake-capture}"
[ -x "$root/${bin#./}" ] || fail "binary not found: $bin"
me="1000:1000"   # the host user, mapped to the image's unprivileged uid 1000

# 1. Unprivileged user + CAP_NET_RAW only: live loopback capture works.
out="$(run "$me" --cap-add=NET_RAW -- "
  ( sleep 1; for i in 1 2 3; do echo smoke > /dev/udp/127.0.0.1/9; done
    (exec 3<>/dev/tcp/127.0.0.1/1) 2>/dev/null; true ) &
  timeout -s KILL 15 $bin -i lo --duration 3 --stats 1")"
n=$(grep -c . <<<"$out")
head -n1 <<<"$out" | grep -q "\"type\":\"engine_start\".*\"euid\":1000,\"cap_net_raw\":true" || fail "engine_start does not show a non-root euid with CAP_NET_RAW"
grep -q '"type":"flow_start".*"proto":"udp","direction":"local".*"responder":{"ip":"127.0.0.1","port":9}' <<<"$out" || fail "no local UDP flow to 127.0.0.1:9"
grep -q '"type":"flow_end".*"proto":"tcp".*"reason":"reset"' <<<"$out" || fail "no reset TCP flow to 127.0.0.1:1"
grep -q '"type":"stats"' <<<"$out" || fail "no stats event"
tail -n1 <<<"$out" | grep -q '"type":"engine_stop","reason":"duration"' || fail "did not stop on --duration"
for i in $(seq 1 "$n"); do sed -n "${i}p" <<<"$out" | grep -q "\"seq\":$i," || fail "seq gap at line $i"; done
echo "ok: non-root + CAP_NET_RAW captured loopback traffic ($n events, gap-free seq)"

# 1b. Burst (ADV-0002, ADV-0028): three bursts of 20000 datagrams, 0.5 s apart, each from a
#     tight sendto loop (perl with the core Socket module: present in the dev and release
#     images; a bash loop is too slow to reach the overflow regime). That is 240000 packets on
#     lo, counting kernel copies and ICMP replies, and all must arrive with zero kernel drops.
#     One burst overflowed the old TPACKET_V2 ring in about 3 of 4 runs; three make a miss
#     unlikely.
burst="$(run "$me" --cap-add=NET_RAW -- "
  ( sleep 1; perl -MSocket -e 'socket(my \$s, PF_INET, SOCK_DGRAM, 0) or die \$!;
      my \$a = pack_sockaddr_in(9, inet_aton(q(127.0.0.1)));
      for my \$r (1 .. 3) {
        for (1 .. 20000) { send(\$s, q(burst), 0, \$a) or die \$! }
        select(undef, undef, undef, 0.5);
      }' ) &
  timeout -s KILL 30 $bin -i lo --duration 6 --stats 0 | tail -n1")"
grep -q '"type":"engine_stop"' <<<"$burst" || fail "burst run did not stop cleanly"
received=$(grep -o '"kernel_received":[0-9]*' <<<"$burst" | cut -d: -f2 || true)
dropped=$(grep -o '"kernel_dropped":[0-9]*' <<<"$burst" | cut -d: -f2 || true)
[ "${received:-0}" -ge 240000 ] || fail "burst: kernel saw only ${received:-0} packets (expected >= 240000)"
[ "${dropped:-1}" -eq 0 ] || fail "burst: kernel dropped $dropped of $received packets"
# Received is not enough: the engine must have processed them (ADV-0032). On lo libpcap
# discards the outgoing copy of each packet, so half of what the kernel received reaches us.
seen=$(grep -o '"packets_seen":[0-9]*' <<<"$burst" | cut -d: -f2 || true)
unproc=$(grep -o '"packets_unprocessed_at_stop":[0-9]*' <<<"$burst" | cut -d: -f2 || true)
[ -n "$seen" ] && [ -n "$unproc" ] || fail "burst: engine_stop lacks packets_seen / packets_unprocessed_at_stop"
[ "$seen" -ge $((received / 2)) ] || fail "burst: only $seen of $((received / 2)) deliverable packets processed"
[ "$unproc" -eq 0 ] || fail "burst: $unproc packets left unprocessed at stop"
echo "ok: 3 x 20000-datagram tight bursts, $received packets, 0 kernel drops, $seen processed"

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
echo "PASS: smoke-capture-loopback ($bin in $tag)"
