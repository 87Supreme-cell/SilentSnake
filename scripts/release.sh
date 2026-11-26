#!/usr/bin/env bash
# Build a SilentSnake capture release for one target distribution (docs/decisions/0002).
#   scripts/release.sh fedora-45
#
# Fails closed at every step. Steps:
#   1. Clean tree at a commit (the release is that commit, nothing else).
#   2. All merge gates in the dev container: fmt, clippy, tests, cargo-deny, cargo-audit,
#      osv-scanner, gitleaks over full history.
#   3. Two independent release builds in the target's build container, network disabled
#      during compilation, compared byte for byte (smoke test: reproducible builds).
#   4. Loopback smoke test with the release binary, inside the target's image.
#   5. Tarball: binary, install.sh, LICENSE, README, BUILD-ENV, SBOMs (SPDX + CycloneDX from
#      Cargo.lock via syft), SHA256SUMS; deterministic tar/gzip; tarball checksum.
#   6. Signing: releases are signed keyless (Sigstore) from CI, with SLSA provenance (Ronin,
#      2026-11-25, ADR-0002). Local builds like this one are always UNSIGNED and must not be
#      published.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
die() { echo "release.sh: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

target="${1:-}"; [ -n "$target" ] || die "usage: scripts/release.sh <target>   (targets: $(ls release | grep -v '\.sh$' | tr '\n' ' '))"
cf="release/$target/Containerfile"; [ -f "$cf" ] || die "unknown target: $target"

step "1. Source"
if [ -n "$(git status --porcelain)" ]; then
  [ "${RELEASE_DRY_RUN:-0}" = 1 ] || die "working tree is not clean; commit first (or RELEASE_DRY_RUN=1 to test)"
  echo "DRY RUN on an uncommitted tree: the output is NOT a release."
fi
commit="$(git rev-parse HEAD)"
epoch="$(git log -1 --format=%ct)"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
name="silentsnake-capture-$version-$target-x86_64"
[ "${RELEASE_DRY_RUN:-0}" = 1 ] && name="$name-DRYRUN"
out="dist/$name"
echo "commit $commit, version $version, target $target"

step "2. Gates (dev container)"
scripts/gates.sh || die "gates failed"

step "3. Reproducible build x2 ($target)"
tag="silentsnake-build-$target:$(sha256sum "$cf" | cut -c1-12)"
podman image exists "$tag" || podman build --pull=missing -t "$tag" -f "$cf" "release/$target"
cache="silentsnake-build-$target-cargo"
build_run() { # build_run <default|none> <script>
  local net=(); [ "$1" = none ] && net=(--network=none)
  podman run --rm --userns=keep-id:uid=1000,gid=1000 --user 1000:1000 \
    --security-opt no-new-privileges --cap-drop=all "${net[@]}" \
    -e SOURCE_DATE_EPOCH="$epoch" -e CARGO_TARGET_DIR=/tmp/target \
    -e RUSTFLAGS="--remap-path-prefix=/home/builder/.cargo-cache=/cargo --remap-path-prefix=/work=/src" \
    -v "$root:/work:Z" -v "$cache:/home/builder/.cargo-cache" "$tag" bash -c "$2"
}
build_run default 'cargo fetch --locked -q'
rm -rf "$out" "dist/.build"; mkdir -p "$out" dist/.build
for n in 1 2; do
  build_run none "set -euo pipefail
    cargo build --release --locked --offline -q -p silentsnake-capture
    cp /tmp/target/release/silentsnake-capture /work/dist/.build/silentsnake-capture.$n"
done
h1="$(sha256sum dist/.build/silentsnake-capture.1 | cut -d' ' -f1)"
h2="$(sha256sum dist/.build/silentsnake-capture.2 | cut -d' ' -f1)"
[ "$h1" = "$h2" ] || die "builds differ: $h1 vs $h2 (not reproducible)"
echo "identical: $h1"
install -m 0755 dist/.build/silentsnake-capture.1 "$out/silentsnake-capture"
rm -rf dist/.build

step "4. Smoke test (release binary, $target image)"
SMOKE_BIN="$out/silentsnake-capture" SMOKE_IMAGE="$tag" scripts/smoke-capture-loopback.sh || die "smoke test failed"

step "5. Package"
install -m 0755 release/install.sh "$out/install.sh"
install -m 0644 LICENSE "$out/LICENSE"
image_id="$(podman image inspect --format '{{.Id}}' "$tag")"
{
  echo "SilentSnake capture $version for $target (x86_64)"
  echo "source commit: $commit"
  echo "build image:   $tag (id $image_id), base: $(sed -n 's/^FROM //p' "$cf")"
  echo "rust:          $(build_run none 'rustc --version')"
  echo "binary sha256: $h1 (two independent builds matched)"
  echo
  echo "Build environment packages:"
  build_run none 'cat /etc/silentsnake-build-env.lock'
} > "$out/BUILD-ENV"
chmod 0644 "$out/BUILD-ENV"
cat > "$out/README" <<EOF
SilentSnake capture engine $version ($target, x86_64)

Install (as your own user, not root):   ./install.sh
It verifies SHA256SUMS, installs to ~/.local/bin with mode 0700, and grants CAP_NET_RAW with
sudo setcap. Read install.sh first; it is short.

Docs: https://github.com/87Supreme-cell/SilentSnake (docs/api/capture-events.md,
docs/decisions/0001-stage-a-libpcap-capture.md). License: MIT (LICENSE).
Output goes to stdout only. Do not redirect it to a file: logs are not encrypted until the
encrypted log store ships.
EOF
chmod 0644 "$out/README"
scripts/dev.sh bash -c "set -euo pipefail
  syft scan file:/work/Cargo.lock --source-name silentsnake-capture --source-version $version -q \
    -o spdx-json=/work/$out/sbom.spdx.json -o cyclonedx-json=/work/$out/sbom.cdx.json"
chmod 0644 "$out"/sbom.*.json
( cd "$out" && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS )
scripts/dev.sh bash -c "set -euo pipefail; cd /work/dist
  tar --sort=name --mtime=@$epoch --owner=0 --group=0 --numeric-owner --format=gnu -cf - $name | gzip -n -9 > $name.tar.gz"
( cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256" )

step "6. Signing"
echo "UNSIGNED local build. Published releases are signed keyless in CI (ADR-0002); do not publish this tarball."
echo
echo "Release artifacts:"
ls -l "dist/$name.tar.gz" "dist/$name.tar.gz.sha256"
cat "dist/$name.tar.gz.sha256"
