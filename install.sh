#!/bin/sh
# cryptobom installer.
#
# Downloads the prebuilt binary for your platform from the GitHub release,
# verifies its sha256 against the release checksums, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/<your-org>/cryptobom/main/install.sh | sh
#
# Environment overrides:
#   CRYPTOBOM_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   CRYPTOBOM_INSTALL_DIR  install directory (default: /usr/local/bin, else ~/.local/bin)
#   CRYPTOBOM_REPO         GitHub owner/repo (default: cryptobom/cryptobom)
#
# Maintainers: set CRYPTOBOM_REPO's default below to the real GitHub repo before
# publishing this script, and use that repo in the raw URL above.
set -eu

REPO="${CRYPTOBOM_REPO:-cryptobom/cryptobom}"
VERSION="${CRYPTOBOM_VERSION:-latest}"
INSTALL_DIR="${CRYPTOBOM_INSTALL_DIR:-}"
BIN="cryptobom"

err()  { printf 'cryptobom-install: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# fetch URL -> stdout
fetch() {
  if   have curl; then curl -fsSL "$1"
  elif have wget; then wget -qO- "$1"
  else err "need curl or wget"; fi
}

# download URL DEST
download() {
  if   have curl; then curl -fsSL -o "$2" "$1"
  elif have wget; then wget -qO "$2" "$1"
  else err "need curl or wget"; fi
}

detect_platform() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    *) err "unsupported OS: $os (cryptobom ships Linux and macOS builds)" ;;
  esac
  case "$arch" in
    x86_64 | amd64)  arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) err "unsupported architecture: $arch" ;;
  esac
  # Only the combinations the release matrix actually builds.
  case "${os}-${arch}" in
    linux-amd64 | darwin-amd64 | darwin-arm64) ;;
    *) err "no prebuilt binary for ${os}/${arch}; build from source (see README)" ;;
  esac
  PLATFORM="${os}-${arch}"
}

resolve_version() {
  [ "$VERSION" = "latest" ] || return 0
  tag=$(fetch "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
  [ -n "$tag" ] || err "could not resolve the latest release for ${REPO}"
  VERSION="$tag"
}

sha256_of() {
  if   have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum;    then shasum -a 256 "$1" | awk '{print $1}'
  elif have openssl;   then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else err "need sha256sum, shasum, or openssl to verify the download"; fi
}

choose_install_dir() {
  [ -n "$INSTALL_DIR" ] && return 0
  if [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
}

install_binary() {
  dest="${INSTALL_DIR}/${BIN}"
  if mkdir -p "$INSTALL_DIR" 2>/dev/null && mv "$1" "$dest" 2>/dev/null; then
    chmod +x "$dest"
  elif have sudo; then
    info "Installing to ${INSTALL_DIR} (requires sudo) ..."
    sudo mkdir -p "$INSTALL_DIR"
    sudo mv "$1" "$dest"
    sudo chmod +x "$dest"
  else
    err "cannot write to ${INSTALL_DIR}; set CRYPTOBOM_INSTALL_DIR to a writable directory"
  fi
}

main() {
  detect_platform
  resolve_version

  asset="cryptobom-${VERSION}-${PLATFORM}.tar.gz"
  base="https://github.com/${REPO}/releases/download/${VERSION}"

  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t cryptobom)
  trap 'rm -rf "$tmp"' EXIT INT TERM

  info "Downloading ${asset} (${VERSION}) ..."
  download "${base}/${asset}" "${tmp}/${asset}"
  download "${base}/checksums.txt" "${tmp}/checksums.txt"

  info "Verifying checksum ..."
  expected=$(grep " ${asset}\$" "${tmp}/checksums.txt" | awk '{print $1}' | head -n1)
  [ -n "$expected" ] || err "no checksum recorded for ${asset}"
  actual=$(sha256_of "${tmp}/${asset}")
  [ "$expected" = "$actual" ] || err "checksum mismatch for ${asset} (expected ${expected}, got ${actual})"

  info "Extracting ..."
  tar -xzf "${tmp}/${asset}" -C "$tmp"
  # The tarball holds a single top-level dir named like the asset (sans .tar.gz).
  src="${tmp}/cryptobom-${VERSION}-${PLATFORM}/${BIN}"
  [ -f "$src" ] || src=$(find "$tmp" -type f -name "$BIN" | head -n1)
  [ -n "$src" ] && [ -f "$src" ] || err "binary not found in archive"

  choose_install_dir
  install_binary "$src"

  info "Installed ${BIN} ${VERSION} to ${INSTALL_DIR}/${BIN}"
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      info "Note: ${INSTALL_DIR} is not on your PATH. Add it, e.g.:"
      info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac
  "${INSTALL_DIR}/${BIN}" version 2>/dev/null || true
}

main "$@"
