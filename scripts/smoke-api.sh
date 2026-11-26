#!/usr/bin/env bash
# Smoke test (dependencies.json > smoke_tests): "REST API refuses connections from
# non-127.0.0.1 addresses". Builds silentsnake-api and the release capture engine, runs both
# in the pinned dev container as uid 1000 (capture holds only CAP_NET_RAW), and checks:
#   1. the API serves live capture data on 127.0.0.1:8765 with the token,
#   2. it refuses requests without a valid token,
#   3. nothing answers on the container's non-loopback address (it never listens there),
#   4. it refuses to start with a non-127.0.0.1 --listen address.
#   scripts/smoke-api.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="silentsnake-dev:$(sha256sum "$root/dev/Containerfile" | cut -c1-12)"
fail() { echo "FAIL: $*" >&2; exit 1; }
"$root/scripts/dev.sh" bash -c '
  cargo build --release --locked -q -p silentsnake-capture
  cd services && go build -trimpath -o /work/target/silentsnake-api ./api'

out="$(timeout 90 podman run --rm --userns=keep-id:uid=1000,gid=1000 --user 1000:1000 \
  --security-opt no-new-privileges --cap-drop=all --cap-add=NET_RAW \
  -v "$root:/work:Z" -w /work "$tag" bash -c '
  set -u
  export XDG_DATA_HOME="$(mktemp -d)"; chmod 700 "$XDG_DATA_HOME"
  target/silentsnake-api --capture-bin target/release/silentsnake-capture --interface any 2>/dev/null &
  for i in $(seq 50); do [ -s "$XDG_DATA_HOME/silentsnake/config/api-token" ] && break; sleep 0.1; done
  sleep 1
  T="$(cat "$XDG_DATA_HOME/silentsnake/config/api-token")"
  for i in 1 2 3; do echo smoke > /dev/udp/127.0.0.1/9; done; sleep 2
  echo "health_with_token=$(curl -s -o /dev/null -w %{http_code} -H "Authorization: Bearer $T" http://127.0.0.1:8765/v1/health)"
  echo "health_without_token=$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:8765/v1/health)"
  echo "running=$(curl -s -H "Authorization: Bearer $T" http://127.0.0.1:8765/v1/overview | grep -o "\"running\":[a-z]*" | cut -d: -f2)"
  echo "port9_seen=$(curl -s -H "Authorization: Bearer $T" "http://127.0.0.1:8765/v1/connections?state=all&limit=500" | grep -c "\"port\":9}")"
  ext="$(python3 -c "import socket; s=socket.socket(2,2); s.connect((\"192.0.2.1\",9)); print(s.getsockname()[0])" 2>/dev/null | grep -v "^127\." || true)"
  echo "external_ip=${ext:-none}"
  if [ -n "$ext" ]; then
    echo "external_code=$(curl -s -o /dev/null -w %{http_code} --max-time 3 -H "Authorization: Bearer $T" "http://$ext:8765/v1/health")"
  fi
  kill %1; wait 2>/dev/null
  target/silentsnake-api --listen 0.0.0.0:8765 >/dev/null 2>&1; echo "wildcard_exit=$?"
')"
echo "$out"
val() { grep "^$1=" <<<"$out" | cut -d= -f2; }
[ "$(val health_with_token)" = 200 ] || fail "API did not answer with the token"
[ "$(val health_without_token)" = 401 ] || fail "API answered without a token"
[ "$(val running)" = true ] || fail "capture engine not running under the API"
[ "$(val port9_seen)" -ge 1 ] || fail "live loopback flow not visible through the API"
if [ "$(val external_ip)" != none ]; then
  [ "$(val external_code)" = 000 ] || fail "API answered on non-loopback address $(val external_ip)"
  echo "ok: no listener on non-loopback address $(val external_ip)"
else
  echo "note: container has no non-loopback IPv4 address; bind check covered by --listen refusal"
fi
[ "$(val wildcard_exit)" != 0 ] || fail "API started with --listen 0.0.0.0"
echo "PASS: smoke-api (token required, live data, 127.0.0.1 only)"
