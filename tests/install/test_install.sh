#!/usr/bin/env bash
# FR-27 acceptance harness for install.sh.
#
# Runs install.sh under every available POSIX shell (dash and bash) with fake
# uname/sysctl/gh on PATH and a local file:// release fixture supplied through
# the test-only OPV_INSTALL_BASE_URL override. Every test exercises exactly one
# observable outcome through the script's public interface.
#
# Exits non-zero if any test fails.

set -u

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
INSTALL_SH="$ROOT/install.sh"

if [ ! -f "$INSTALL_SH" ]; then
  echo "install.sh not found at $INSTALL_SH" >&2
  exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/opv-install-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

FAILURES=0
PASSES=0
CURRENT=""
INSTALL_RC=0
INSTALL_OUT=""

# ---------------------------------------------------------------------------
# Harness plumbing
# ---------------------------------------------------------------------------

pass() {
  PASSES=$((PASSES + 1))
  printf 'ok - %s\n' "$CURRENT"
}

fail() {
  FAILURES=$((FAILURES + 1))
  printf 'not ok - %s: %s\n' "$CURRENT" "$*" >&2
}

check_rc_zero() {
  if [ "$INSTALL_RC" -eq 0 ]; then
    pass
  else
    fail "expected exit 0, got $INSTALL_RC; output: $INSTALL_OUT"
  fi
}

check_rc_nonzero() {
  if [ "$INSTALL_RC" -ne 0 ]; then
    pass
  else
    fail "expected non-zero exit; output: $INSTALL_OUT"
  fi
}

check_out_contains() {
  case "$INSTALL_OUT" in
    *"$1"*) pass ;;
    *) fail "output missing [$1]; output: $INSTALL_OUT" ;;
  esac
}

check_file_equals() {
  if cmp -s "$1" "$2"; then
    pass
  else
    fail "files differ: $1 vs $2"
  fi
}

check_file_contains() {
  if grep -q -- "$2" "$1" 2>/dev/null; then
    pass
  else
    fail "file $1 missing [$2]"
  fi
}

check_not_exists() {
  if [ ! -e "$1" ]; then
    pass
  else
    fail "$1 should not exist"
  fi
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKEBIN="$WORK/fakebin"
mkdir -p "$FAKEBIN"

cat > "$FAKEBIN/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "${FAKE_UNAME_S:?}" ;;
  -m) printf '%s\n' "${FAKE_UNAME_M:?}" ;;
  *)  printf '%s\n' "${FAKE_UNAME_S:?}" ;;
esac
EOF
chmod 755 "$FAKEBIN/uname"

cat > "$FAKEBIN/sysctl" <<'EOF'
#!/bin/sh
if [ "$1" = "-n" ] && [ "$2" = "sysctl.proc_translated" ]; then
  printf '%s\n' "${FAKE_PROC_TRANSLATED:-0}"
fi
EOF
chmod 755 "$FAKEBIN/sysctl"

cat > "$FAKEBIN/gh" <<'EOF'
#!/bin/sh
case "$1" in
  auth) exit "${FAKE_GH_AUTH_EXIT:-0}" ;;
  *) exit "${FAKE_GH_EXIT:-0}" ;;
esac
EOF
chmod 755 "$FAKEBIN/gh"

ASSETS="opv-x86_64-unknown-linux-musl opv-aarch64-unknown-linux-musl opv-x86_64-apple-darwin opv-aarch64-apple-darwin"

# make_release FIXTURE TAG
make_release() {
  fixture="$1"
  tag="$2"
  rdir="$fixture/releases/download/$tag"
  mkdir -p "$rdir"
  for asset in $ASSETS; do
    printf 'binary:%s:%s\n' "$tag" "$asset" > "$rdir/$asset"
  done
  : > "$rdir/SHA256SUMS"
  for asset in $ASSETS; do
    printf '%s  %s\n' "$(hash_file "$rdir/$asset")" "$asset" >> "$rdir/SHA256SUMS"
  done
}

FIXTURE="$WORK/release"
make_release "$FIXTURE" v1.2.3
make_release "$FIXTURE" v9.9.9
printf 'v9.9.9\n' > "$FIXTURE/releases/latest"

FIXTURE_BAD="$WORK/release-bad"
make_release "$FIXTURE_BAD" v1.2.3
printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' \
  "opv-x86_64-unknown-linux-musl" > "$FIXTURE_BAD/releases/download/v1.2.3/SHA256SUMS"
printf 'v1.2.3\n' > "$FIXTURE_BAD/releases/latest"

FIXTURE_NOTAG="$WORK/release-notag"
make_release "$FIXTURE_NOTAG" v1.2.3
printf 'releases\n' > "$FIXTURE_NOTAG/releases/latest"

asset_path() {
  # asset_path TAG ASSET
  printf '%s/releases/download/%s/%s\n' "$BASE_OVERRIDE" "$1" "$2"
}

make_fake_opv() {
  dir="$1"
  ver="$2"
  mkdir -p "$dir"
  cat > "$dir/opv" <<EOF
#!/bin/sh
echo "opv $ver"
EOF
  chmod 755 "$dir/opv"
}

new_case() {
  CASE=$(mktemp -d "$WORK/case.XXXXXX")
  TARGET="$CASE/bin"
  HOME_DIR="$CASE/home"
  mkdir -p "$HOME_DIR"
  FAKE_S=Linux
  FAKE_M=x86_64
  FAKE_RT=0
  FAKE_GH_EXIT=0
  FAKE_GH_AUTH_EXIT=0
  BASE_OVERRIDE="$FIXTURE"
}

install_run() {
  shell_bin="$1"
  shift
  INSTALL_OUT=$(
    PATH="$FAKEBIN:$PATH" \
    HOME="$HOME_DIR" \
    OPV_INSTALL_BASE_URL="file://$BASE_OVERRIDE" \
    FAKE_UNAME_S="$FAKE_S" \
    FAKE_UNAME_M="$FAKE_M" \
    FAKE_PROC_TRANSLATED="$FAKE_RT" \
    FAKE_GH_EXIT="$FAKE_GH_EXIT" \
    FAKE_GH_AUTH_EXIT="$FAKE_GH_AUTH_EXIT" \
    "$shell_bin" "$INSTALL_SH" "$@" 2>&1
  )
  INSTALL_RC=$?
}

SHELLS=""
if command -v dash >/dev/null 2>&1; then
  SHELLS="$SHELLS $(command -v dash)"
fi
if command -v bash >/dev/null 2>&1; then
  SHELLS="$SHELLS $(command -v bash)"
fi
if [ -z "$SHELLS" ]; then
  echo "no POSIX shell (dash/bash) found" >&2
  exit 1
fi

run_for_shells() {
  fn="$1"
  for shell_bin in $SHELLS; do
    CURRENT="$fn [$(basename "$shell_bin")]"
    "$fn" "$shell_bin"
  done
}

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

t_linux_x86_64_installs_musl_binary() {
  new_case
  FAKE_S=Linux FAKE_M=x86_64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-x86_64-unknown-linux-musl)"
}

t_linux_aarch64_installs_musl_binary() {
  new_case
  FAKE_S=Linux FAKE_M=aarch64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-aarch64-unknown-linux-musl)"
}

t_linux_arm64_installs_aarch64_musl_binary() {
  new_case
  FAKE_S=Linux FAKE_M=arm64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-aarch64-unknown-linux-musl)"
}

t_darwin_x86_64_installs_intel_binary() {
  new_case
  FAKE_S=Darwin FAKE_M=x86_64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-x86_64-apple-darwin)"
}

t_darwin_arm64_installs_apple_silicon_binary() {
  new_case
  FAKE_S=Darwin FAKE_M=arm64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-aarch64-apple-darwin)"
}

t_rosetta_installs_apple_silicon_binary() {
  new_case
  FAKE_S=Darwin FAKE_M=x86_64 FAKE_RT=1
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-aarch64-apple-darwin)"
}

t_unsupported_platform_exits_nonzero() {
  new_case
  FAKE_S=FreeBSD FAKE_M=x86_64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_rc_nonzero
}

t_unsupported_platform_names_detected_platform() {
  new_case
  FAKE_S=FreeBSD FAKE_M=x86_64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_out_contains "FreeBSD x86_64"
}

t_unsupported_platform_points_at_releases() {
  new_case
  FAKE_S=FreeBSD FAKE_M=x86_64
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_out_contains "https://github.com/matt-cochran/1password-vault/releases"
}

# ---------------------------------------------------------------------------
# Version selection
# ---------------------------------------------------------------------------

t_pinned_version_installs_that_release() {
  new_case
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-x86_64-unknown-linux-musl)"
}

t_latest_version_installs_latest_release() {
  new_case
  install_run "$1" --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v9.9.9 opv-x86_64-unknown-linux-musl)"
}

# ---------------------------------------------------------------------------
# Already current
# ---------------------------------------------------------------------------

t_already_current_prints_already_installed() {
  new_case
  make_fake_opv "$TARGET" 1.2.3
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_out_contains "opv 1.2.3 is already installed"
}

t_already_current_leaves_binary_unchanged() {
  new_case
  make_fake_opv "$TARGET" 1.2.3
  cp "$TARGET/opv" "$CASE/before"
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$CASE/before"
}

# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------

t_update_replaces_binary() {
  new_case
  make_fake_opv "$TARGET" 0.9.0
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$(asset_path v1.2.3 opv-x86_64-unknown-linux-musl)"
}

t_update_prints_old_to_new() {
  new_case
  make_fake_opv "$TARGET" 0.9.0
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_out_contains "0.9.0 → 1.2.3"
}

# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------

t_check_does_not_install() {
  new_case
  install_run "$1" --check --version v1.2.3 --dir "$TARGET"
  check_not_exists "$TARGET/opv"
}

t_check_reports_target_version() {
  new_case
  install_run "$1" --check --version v1.2.3 --dir "$TARGET"
  check_out_contains "1.2.3"
}

t_check_with_existing_leaves_binary_unchanged() {
  new_case
  make_fake_opv "$TARGET" 0.9.0
  cp "$TARGET/opv" "$CASE/before"
  install_run "$1" --check --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$CASE/before"
}

t_default_dir_installs_into_home_local_bin() {
  new_case
  install_run "$1" --version v1.2.3
  check_file_equals "$HOME_DIR/.local/bin/opv" "$(asset_path v1.2.3 opv-x86_64-unknown-linux-musl)"
}

# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------

t_checksum_mismatch_fails() {
  new_case
  BASE_OVERRIDE="$FIXTURE_BAD"
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_rc_nonzero
}

t_checksum_mismatch_leaves_existing_binary_untouched() {
  new_case
  BASE_OVERRIDE="$FIXTURE_BAD"
  make_fake_opv "$TARGET" 0.9.0
  cp "$TARGET/opv" "$CASE/before"
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$CASE/before"
}

t_attestation_failure_fails() {
  new_case
  FAKE_GH_EXIT=1
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_rc_nonzero
}

t_attestation_failure_leaves_existing_binary_untouched() {
  new_case
  FAKE_GH_EXIT=1
  make_fake_opv "$TARGET" 0.9.0
  cp "$TARGET/opv" "$CASE/before"
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_file_equals "$TARGET/opv" "$CASE/before"
}

t_signed_out_gh_skips_provenance_and_installs() {
  new_case
  FAKE_GH_AUTH_EXIT=1
  FAKE_GH_EXIT=1
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_rc_zero
}

t_signed_out_gh_reports_skipped_provenance() {
  new_case
  FAKE_GH_AUTH_EXIT=1
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_out_contains "skipped the provenance check"
}

t_malformed_latest_tag_fails() {
  new_case
  BASE_OVERRIDE="$FIXTURE_NOTAG"
  install_run "$1" --dir "$TARGET"
  check_rc_nonzero
}

t_malformed_pinned_version_fails() {
  new_case
  install_run "$1" --version v1.2 --dir "$TARGET"
  check_rc_nonzero
}

# ---------------------------------------------------------------------------
# PATH hint
# ---------------------------------------------------------------------------

t_off_path_prints_export_line() {
  new_case
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  check_out_contains "export PATH="
}

# ---------------------------------------------------------------------------
# Shared installed-by record
# ---------------------------------------------------------------------------

t_install_writes_installed_by_record() {
  new_case
  install_run "$1" --version v1.2.3
  printf 'install.sh 1.2.3 %s\n' \
    "$(hash_file "$(asset_path v1.2.3 opv-x86_64-unknown-linux-musl)")" \
    > "$CASE/installed-by.expected"
  check_file_equals "$HOME_DIR/.local/share/opv/installed-by" "$CASE/installed-by.expected"
}

t_custom_dir_install_leaves_no_installed_by_record() {
  new_case
  install_run "$1" --version v1.2.3 --dir "$TARGET"
  if [ ! -e "$HOME_DIR/.local/share/opv/installed-by" ]; then pass; else fail "record written for --dir install"; fi
}

t_reinstall_of_same_version_keeps_an_existing_record() {
  new_case
  mkdir -p "$HOME_DIR/.local/bin" "$HOME_DIR/.local/share/opv"
  make_fake_opv "$HOME_DIR/.local/bin" 1.2.3
  printf 'npm 1.2.3 abc\n' > "$HOME_DIR/.local/share/opv/installed-by"
  printf 'npm 1.2.3 abc\n' > "$CASE/expected"
  install_run "$1" --version v1.2.3
  check_file_equals "$HOME_DIR/.local/share/opv/installed-by" "$CASE/expected"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

for test_fn in \
  t_linux_x86_64_installs_musl_binary \
  t_linux_aarch64_installs_musl_binary \
  t_linux_arm64_installs_aarch64_musl_binary \
  t_darwin_x86_64_installs_intel_binary \
  t_darwin_arm64_installs_apple_silicon_binary \
  t_rosetta_installs_apple_silicon_binary \
  t_unsupported_platform_exits_nonzero \
  t_unsupported_platform_names_detected_platform \
  t_unsupported_platform_points_at_releases \
  t_pinned_version_installs_that_release \
  t_latest_version_installs_latest_release \
  t_already_current_prints_already_installed \
  t_already_current_leaves_binary_unchanged \
  t_update_replaces_binary \
  t_update_prints_old_to_new \
  t_check_does_not_install \
  t_check_reports_target_version \
  t_check_with_existing_leaves_binary_unchanged \
  t_default_dir_installs_into_home_local_bin \
  t_checksum_mismatch_fails \
  t_checksum_mismatch_leaves_existing_binary_untouched \
  t_attestation_failure_fails \
  t_attestation_failure_leaves_existing_binary_untouched \
  t_signed_out_gh_skips_provenance_and_installs \
  t_signed_out_gh_reports_skipped_provenance \
  t_malformed_latest_tag_fails \
  t_malformed_pinned_version_fails \
  t_off_path_prints_export_line \
  t_install_writes_installed_by_record \
  t_custom_dir_install_leaves_no_installed_by_record \
  t_reinstall_of_same_version_keeps_an_existing_record
do
  run_for_shells "$test_fn"
done

printf '\n%d passed, %d failed\n' "$PASSES" "$FAILURES"
if [ "$FAILURES" -ne 0 ]; then
  exit 1
fi
