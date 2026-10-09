#!/bin/sh
# Install the latest whoknocked release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/tdiprima/whoknocked/main/install.sh | sh
#
# Environment:
#   WHOKNOCKED_INSTALL_DIR   where to put the binary (default: /usr/local/bin,
#                            falling back to ~/.local/bin if not writable)
#   WHOKNOCKED_VERSION       pin a version tag, e.g. v0.4.0 (default: latest)
set -eu

REPO="tdiprima/whoknocked"
BIN="whoknocked"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux)  os_part="unknown-linux-musl" ;;
  Darwin) os_part="apple-darwin" ;;
  *) echo "install.sh: unsupported OS: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64)  arch_part="x86_64" ;;
  aarch64|arm64) arch_part="aarch64" ;;
  *) echo "install.sh: unsupported architecture: $arch" >&2; exit 1 ;;
esac

target="${arch_part}-${os_part}"

if [ -n "${WHOKNOCKED_VERSION:-}" ]; then
  tag="$WHOKNOCKED_VERSION"
else
  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -n1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$tag" ] || { echo "install.sh: could not determine latest release" >&2; exit 1; }
fi

asset="${BIN}-${target}.tar.gz"
url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${BIN} ${tag} for ${target}..."
curl -fsSL "$url" -o "$tmp/$asset"
curl -fsSL "$url.sha256" -o "$tmp/$asset.sha256" 2>/dev/null || true

if [ -f "$tmp/$asset.sha256" ]; then
  expected=$(awk '{print $1}' "$tmp/$asset.sha256")
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
  fi
  [ "$expected" = "$actual" ] || { echo "install.sh: checksum mismatch" >&2; exit 1; }
fi

tar -xzf "$tmp/$asset" -C "$tmp"

dir="${WHOKNOCKED_INSTALL_DIR:-/usr/local/bin}"
if [ ! -w "$dir" ]; then
  if [ -z "${WHOKNOCKED_INSTALL_DIR:-}" ]; then
    dir="$HOME/.local/bin"
    mkdir -p "$dir"
  else
    echo "install.sh: $dir is not writable (try sudo, or set WHOKNOCKED_INSTALL_DIR)" >&2
    exit 1
  fi
fi

install -m 0755 "$tmp/$BIN" "$dir/$BIN"
echo "Installed $dir/$BIN"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Note: $dir is not on your PATH." ;;
esac
