#!/usr/bin/env bash
# Build (if needed) and enter the pinned Flutter app container (dev/flutter/Containerfile).
#   scripts/app.sh                 interactive shell in app/
#   scripts/app.sh <cmd> [args]    run one command in app/
# The image tag is derived from the Containerfile hash, so any pin change forces a rebuild.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="silentsnake-app:$(sha256sum "$root/dev/flutter/Containerfile" | cut -c1-12)"
if ! podman image exists "$tag"; then
  podman build --pull=missing -t "$tag" -f "$root/dev/flutter/Containerfile" "$root/dev/flutter"
fi
tty=(); [ -t 0 ] && tty=(-it)
exec podman run --rm "${tty[@]}" \
  --userns=keep-id:uid=1000,gid=1000 --user 1000:1000 \
  --security-opt no-new-privileges --cap-drop=all \
  -v "$root:/work:Z" -w /work/app \
  -v silentsnake-pub-cache:/home/dev/.pub-cache \
  "$tag" "${@:-bash}"
