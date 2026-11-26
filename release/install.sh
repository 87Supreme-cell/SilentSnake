#!/usr/bin/env bash
# SilentSnake capture engine installer (ships inside the release tarball).
#
#   ./install.sh                  install for this user: ~/.local/bin, mode 0700 (recommended)
#   ./install.sh --prefix DIR     install for this user into DIR/bin (DIR must be yours)
#   ./install.sh --no-setcap      install without granting CAP_NET_RAW (file mode only)
#   ./install.sh --uninstall      remove the installed binary
#
# What it does, in order (nothing else):
#   1. Refuses to run as root. Live capture must never run as root (CLAUDE.md section 4).
#   2. Verifies every file in this folder against SHA256SUMS. Any mismatch stops the install.
#   3. Copies silentsnake-capture to the target dir with mode 0700, so only you can run it.
#   4. Grants CAP_NET_RAW (and nothing else) with: sudo setcap cap_net_raw=ep <binary>.
#      sudo asks for your password here; that is the only privileged step.
#   5. Checks that the capability is exactly cap_net_raw=ep.
#
# Why mode 0700: a binary with CAP_NET_RAW can read all traffic on this machine. Making it
# executable only by you keeps other local users from using it. Any program running as you
# can still use it, the same as you can.
set -euo pipefail
umask 077

name=silentsnake-capture
here="$(cd "$(dirname "$0")" && pwd)"
prefix="$HOME/.local"
setcap_wanted=1
action=install

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; prefix="$2"; shift 2 ;;
    --no-setcap) setcap_wanted=0; shift ;;
    --uninstall) action=uninstall; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -ne 0 ] || die "refusing to run as root. Run as your own user; sudo is used only for setcap."
dest_dir="$prefix/bin"
dest="$dest_dir/$name"

if [ "$action" = uninstall ]; then
  [ -e "$dest" ] || die "$dest is not installed"
  rm -f -- "$dest"
  echo "Removed $dest (its capability goes with it)."
  exit 0
fi

# 2. Integrity: every listed file must match, and the binary must be listed.
cd "$here"
[ -f SHA256SUMS ] || die "SHA256SUMS missing; this folder is incomplete"
grep -q "  $name\$" SHA256SUMS || die "$name is not listed in SHA256SUMS"
sha256sum --quiet --strict -c SHA256SUMS || die "checksum mismatch: do not install this copy"
echo "Checksums verified."

# 3. Install, owned by you, executable only by you.
mkdir -p -- "$dest_dir"
[ -O "$dest_dir" ] || die "$dest_dir is not owned by you; choose a --prefix you own"
tmp="$(mktemp "$dest_dir/.$name.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
install -m 0700 -- "$name" "$tmp"
mv -f -- "$tmp" "$dest"
trap - EXIT
echo "Installed $dest (mode 0700)."

# 4 and 5. Capability.
if [ "$setcap_wanted" -eq 1 ]; then
  command -v setcap >/dev/null && command -v getcap >/dev/null \
    || die "setcap/getcap not found (Fedora: libcap package). Re-run with --no-setcap to skip."
  echo "Granting CAP_NET_RAW (sudo will ask for your password):"
  echo "  sudo setcap cap_net_raw=ep $dest"
  sudo setcap cap_net_raw=ep "$dest"
  caps="$(getcap "$dest")"
  [[ "$caps" == *" cap_net_raw=ep" ]] || die "unexpected capabilities after setcap: $caps"
  echo "Capability set: $caps"
else
  echo "Skipped setcap: --read FILE works; live capture will need CAP_NET_RAW later."
fi

case ":$PATH:" in *":$dest_dir:"*) ;; *) echo "Note: $dest_dir is not on your PATH." ;; esac
echo "Done. Try: $name --list-interfaces"
