#!/usr/bin/env bash
# Build (if needed) and enter the pinned SilentSnake dev container.
#   scripts/dev.sh                 interactive shell
#   scripts/dev.sh <cmd> [args]    run one command
# The image tag is derived from the Containerfile hash, so any pin change forces a rebuild.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="silentsnake-dev:$(sha256sum "$root/dev/Containerfile" | cut -c1-12)"
if ! podman image exists "$tag"; then
  podman build --pull=missing -t "$tag" -f "$root/dev/Containerfile" "$root/dev"
fi
tty=(); [ -t 0 ] && tty=(-it)
exec podman run --rm "${tty[@]}" \
  --userns=keep-id --user "$(id -u):$(id -g)" \
  --security-opt no-new-privileges --cap-drop=all \
  -v "$root:/work:Z" \
  -v silentsnake-cargo-cache:/home/dev/.cargo-cache \
  -v silentsnake-go-cache:/home/dev/go \
  "$tag" "${@:-bash}"
