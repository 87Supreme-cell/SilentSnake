#!/usr/bin/env bash
# Screenshots of the real app on real data (CLAUDE.md section 8: refresh them whenever the UI
# changes). Runs silentsnake-api + the capture engine in the dev container (uid 1000, only
# CAP_NET_RAW), generates some ordinary traffic (DNS + HTTPS to a few public sites, plus
# loopback), and renders the Linux app under Xvfb in the app container, which shares the API
# container's network namespace so it reaches 127.0.0.1:8765.
#   scripts/screenshot-app.sh [outdir]      default: docs/proof/screenshots
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-docs/proof/screenshots}"
devtag="silentsnake-dev:$(sha256sum "$root/dev/Containerfile" | cut -c1-12)"
apptag="silentsnake-app:$(sha256sum "$root/dev/flutter/Containerfile" | cut -c1-12)"
name="silentsnake-shot-$$"

"$root/scripts/dev.sh" bash -c '
  cargo build --release --locked -q -p silentsnake-capture
  cd services && go build -trimpath -o /work/target/silentsnake-api ./api'
"$root/scripts/app.sh" bash -c 'flutter build linux --release >/dev/null'

xdg="target/shot-xdg"
rm -rf "${root:?}/$xdg" && mkdir -p "$root/$xdg" "$root/$out" && chmod 700 "$root/$xdg"
cleanup() { podman rm -f "$name" >/dev/null 2>&1 || true; rm -rf "${root:?}/$xdg"; }
trap cleanup EXIT

podman run -d --name "$name" --userns=keep-id:uid=1000,gid=1000 --user 1000:1000 \
  --security-opt no-new-privileges --cap-drop=all --cap-add=NET_RAW \
  -v "$root:/work:Z" -w /work -e XDG_DATA_HOME="/work/$xdg" "$devtag" bash -c '
  target/silentsnake-api --capture-bin target/release/silentsnake-capture --interface any &
  sleep 2
  while true; do
    for u in https://example.com https://www.wikipedia.org https://github.com https://www.kernel.org; do
      curl -s -o /dev/null --max-time 5 "$u" || true
    done
    for i in 1 2 3; do echo x > /dev/udp/127.0.0.1/9; done
    sleep 3
  done' >/dev/null

sleep 25   # let traffic, flows and per-minute buckets accumulate

for page in dashboard connections log; do
  podman run --rm --network "container:$name" --userns=keep-id:uid=1000,gid=1000 --user 1000:1000 \
    --security-opt no-new-privileges --cap-drop=all \
    -v "$root:/work:Z" -w /work/app -e XDG_DATA_HOME="/work/$xdg" -e LIBGL_ALWAYS_SOFTWARE=1 \
    "$apptag" bash -c "
    Xvfb :99 -screen 0 1360x920x24 -nolisten tcp >/dev/null 2>&1 &
    sleep 1
    DISPLAY=:99 build/linux/x64/release/bundle/silentsnake --page $page >/dev/null 2>&1 &
    sleep 9
    xwd -root -display :99 -silent | xwdtopnm 2>/dev/null | pnmtopng > /work/$out/$page.png
    kill %2 %1 2>/dev/null; true"
  echo "wrote $out/$page.png"
done
