#!/bin/sh
# install.sh - install or update opv from GitHub releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/matt-cochran/1password-vault/main/install.sh | sh
#   sh install.sh [--version vX.Y.Z] [--dir <path>] [--check]
#
# The script installs the release asset that matches the running platform,
# verifies it against the release's SHA256SUMS (and `gh attestation verify`
# when `gh` is available), and moves it into place only after verification.
#
# Test-only environment override:
#   OPV_INSTALL_BASE_URL
#     Replaces the project base URL (https://github.com/matt-cochran/1password-vault).
#     The test harness points this at a file:// fixture. Because a local
#     fixture has no HTTP redirect, the latest tag is then read from
#     <base>/releases/latest.
#
# install.sh handles no secrets and never reads 1Password. It prints paths and
# versions only.

set -eu

REPO="matt-cochran/1password-vault"
RELEASES_URL="https://github.com/$REPO/releases"
BASE_URL="${OPV_INSTALL_BASE_URL:-https://github.com/$REPO}"
DEFAULT_DIR="${HOME:-/tmp}/.local/bin"

version=""
dir="$DEFAULT_DIR"
check_only=0

usage() {
  cat <<EOF
Usage: install.sh [--version vX.Y.Z] [--dir <path>] [--check]
  --version vX.Y.Z  Install exactly this release (default: latest).
  --dir <path>      Install into <path> (default: $DEFAULT_DIR).
  --check           Report what would happen and change nothing.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      if [ $# -lt 2 ]; then
        echo "install.sh: --version needs a value" >&2
        exit 2
      fi
      version="$2"
      shift 2
      ;;
    --version=*)
      version="${1#--version=}"
      shift
      ;;
    --dir)
      if [ $# -lt 2 ]; then
        echo "install.sh: --dir needs a value" >&2
        exit 2
      fi
      dir="$2"
      shift 2
      ;;
    --dir=*)
      dir="${1#--dir=}"
      shift
      ;;
    --check)
      check_only=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# --- downloader selection --------------------------------------------------

have_curl=0
if command -v curl >/dev/null 2>&1; then
  have_curl=1
elif ! command -v wget >/dev/null 2>&1; then
  echo "install.sh: curl or wget is required" >&2
  exit 1
fi

# --- hashing ---------------------------------------------------------------

# Print the SHA-256 of a file with whichever tool is available; non-zero when neither
# sha256sum nor shasum exists.
hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

# The record both install.sh and npm write so either method can tell what installed the
# binary in the canonical location. `$want` is the version; `$1` is its SHA-256.
write_installed_by() {
  data_dir="${HOME:-/tmp}/.local/share/opv"
  mkdir -p "$data_dir" 2>/dev/null || return 0
  printf 'install.sh %s %s\n' "$want" "$1" > "$data_dir/installed-by" 2>/dev/null || true
}

# --- latest release tag ----------------------------------------------------

fetch_latest_tag() {
  latest_url="$BASE_URL/releases/latest"
  case "$BASE_URL" in
    file://*)
      if [ "$have_curl" -eq 1 ]; then
        body=$(curl -fsSL "$latest_url") || {
          echo "install.sh: could not read the latest release tag from $latest_url" >&2
          exit 1
        }
      else
        body=$(wget -qO- "$latest_url") || {
          echo "install.sh: could not read the latest release tag from $latest_url" >&2
          exit 1
        }
      fi
      # shellcheck disable=SC2312 # status of the pipeline is not significant here
      printf '%s\n' "$body" | head -n 1 | tr -d '[:space:]'
      ;;
    *)
      if [ "$have_curl" -eq 1 ]; then
        final=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$latest_url") || {
          echo "install.sh: could not resolve the latest release" >&2
          exit 1
        }
      else
        # shellcheck disable=SC2312 # the pipeline's last command owns the status
        final=$(wget -qS --max-redirect=0 --spider "$latest_url" 2>&1 \
          | awk 'BEGIN{IGNORECASE=1} /^ *Location:/{print $2}' | tr -d '\r' | tail -n 1) || {
          echo "install.sh: could not resolve the latest release" >&2
          exit 1
        }
      fi
      printf '%s\n' "${final##*/}"
      ;;
  esac
}

# --- platform detection ----------------------------------------------------

os=$(uname -s)
arch=$(uname -m)
asset=""

unsupported() {
  echo "install.sh: unsupported platform: $os $arch" >&2
  echo "install.sh: no release asset for $os $arch; see $RELEASES_URL" >&2
  exit 1
}

case "$os" in
  Linux)
    case "$arch" in
      x86_64|amd64) asset="opv-x86_64-unknown-linux-musl" ;;
      aarch64|arm64) asset="opv-aarch64-unknown-linux-musl" ;;
      *) unsupported ;;
    esac
    ;;
  Darwin)
    proc_translated=""
    if [ "$arch" = "x86_64" ]; then
      proc_translated=$(sysctl -n sysctl.proc_translated 2>/dev/null || true)
    fi
    if [ "$proc_translated" = "1" ]; then
      asset="opv-aarch64-apple-darwin"
    else
      case "$arch" in
        x86_64) asset="opv-x86_64-apple-darwin" ;;
        arm64|aarch64) asset="opv-aarch64-apple-darwin" ;;
        *) unsupported ;;
      esac
    fi
    ;;
  *)
    unsupported
    ;;
esac

# --- resolve version -------------------------------------------------------

case "$version" in
  "")
    tag=$(fetch_latest_tag)
    ;;
  v*)
    tag="$version"
    ;;
  *)
    tag="v$version"
    ;;
esac

# A tag must look like vMAJOR.MINOR.PATCH: a failed or changed redirect must never
# turn into a download from an arbitrary path.
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "install.sh: could not determine a release version (got '${tag:-nothing}')" >&2
    exit 1
    ;;
esac
case "${tag#v}" in
  *[!0-9.]*)
    echo "install.sh: invalid release version '$tag'" >&2
    exit 1
    ;;
esac

want="${tag#v}"
exe="$dir/opv"

# --- existing install ------------------------------------------------------

existing=""
if [ -e "$exe" ] && [ -x "$exe" ]; then
  if out=$("$exe" --version 2>/dev/null); then
    current=${out##* }
    if [ -n "$current" ]; then
      existing="$current"
    fi
  fi
fi

print_path_hint() {
  case ":${PATH:-}:" in
    *":$dir:"*) : ;;
    *)
      echo "Add $dir to your PATH:"
      echo "  export PATH=\"$dir:\$PATH\""
      ;;
  esac
}

if [ "$existing" = "$want" ]; then
  echo "opv $want is already installed"
  if actual=$(hash_file "$exe"); then
    write_installed_by "$actual"
  fi
  print_path_hint
  exit 0
fi

if [ "$check_only" -eq 1 ]; then
  if [ -n "$existing" ]; then
    echo "would update opv $existing → $want"
  else
    echo "would install opv $want"
  fi
  print_path_hint
  exit 0
fi

if ! mkdir -p "$dir"; then
  echo "install.sh: cannot create $dir" >&2
  exit 1
fi

tmp="$dir/.opv.tmp.$$"
sums=""

cleanup() {
  if [ -n "${tmp:-}" ]; then
    rm -f "$tmp"
  fi
  if [ -n "${sums:-}" ]; then
    rm -f "$sums"
  fi
}
trap cleanup EXIT HUP INT TERM

# --- download asset --------------------------------------------------------

asset_url="$BASE_URL/releases/download/$tag/$asset"
if [ "$have_curl" -eq 1 ]; then
  if ! curl -fsSL -o "$tmp" "$asset_url"; then
    echo "install.sh: no release asset $asset in $tag ($asset_url)" >&2
    exit 1
  fi
else
  if ! wget -qO "$tmp" "$asset_url"; then
    echo "install.sh: no release asset $asset in $tag ($asset_url)" >&2
    exit 1
  fi
fi

# --- verify checksum -------------------------------------------------------

sums_url="$BASE_URL/releases/download/$tag/SHA256SUMS"
sums="$dir/.opv.sums.$$"
if [ "$have_curl" -eq 1 ]; then
  if ! curl -fsSL -o "$sums" "$sums_url"; then
    echo "install.sh: no SHA256SUMS for release $tag" >&2
    exit 1
  fi
else
  if ! wget -qO "$sums" "$sums_url"; then
    echo "install.sh: no SHA256SUMS for release $tag" >&2
    exit 1
  fi
fi

expected=$(awk -v a="$asset" '$2 == a { print $1; exit }' "$sums")
rm -f "$sums"
sums=""

if [ -z "$expected" ]; then
  echo "install.sh: SHA256SUMS for $tag has no entry for $asset" >&2
  exit 1
fi

if ! actual=$(hash_file "$tmp"); then
  echo "install.sh: sha256sum or shasum is required to verify the download" >&2
  exit 1
fi

if [ "$actual" != "$expected" ]; then
  echo "install.sh: checksum mismatch for $asset (expected $expected, got $actual)" >&2
  exit 1
fi

# Provenance check when gh can do it. A signed-out gh cannot query attestations, so that
# is reported and skipped rather than treated as a failed verification.
if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then
    if ! gh attestation verify "$tmp" --repo "$REPO" >/dev/null; then
      echo "install.sh: gh attestation verification failed for $asset" >&2
      exit 1
    fi
    echo "verified build provenance (gh attestation)"
  else
    echo "note: gh is not signed in; skipped the provenance check (checksum verified)" >&2
  fi
fi

# --- install ---------------------------------------------------------------

chmod 755 "$tmp"
mv -f "$tmp" "$exe"
tmp=""

write_installed_by "$actual"

if [ -n "$existing" ]; then
  echo "opv $existing → $want"
else
  echo "installed opv $want"
fi

print_path_hint
