#!/usr/bin/env bash
# Starts the CI-like shell (A4-V3 onwards): a clean environment with CI=true, the session
# variables, $S/tools on PATH, and two tokens read with hidden input. A token is never an
# argument, never echoed and never written to a file; it lives only in this shell's env.
#
#   S=... REPO=... CANARY=... FLY_APP=... bash steps/ci-shell.sh
#
# Paste when asked:
#   OP_SERVICE_ACCOUNT_TOKEN  the canary CI service account (preflight P8)
#   FLY_API_TOKEN             the deploy token scoped to the throwaway app only (preflight P6)
set -u
: "${S:?}" "${REPO:?}" "${CANARY:?}" "${FLY_APP:?}"
exec env -i HOME="$S/cihome" PATH="$S/rel:$S/tools:/usr/bin:/bin" TERM="${TERM:-xterm}" \
  LANG=C.UTF-8 S="$S" REPO="$REPO" CANARY="$CANARY" FLY_APP="$FLY_APP" CI=true OPV_NO_SKILL=1 \
  OPV_CONFIG="$S/project/secrets.toml" KUBECONFIG="$S/kubeconfig-opv-ci" \
  bash --noprofile --norc -c '
    mkdir -p "$HOME"
    read -rsp "OP_SERVICE_ACCOUNT_TOKEN (hidden): " OP_SERVICE_ACCOUNT_TOKEN; echo
    read -rsp "FLY_API_TOKEN (hidden): " FLY_API_TOKEN; echo
    export OP_SERVICE_ACCOUNT_TOKEN FLY_API_TOKEN
    PS1="[ci-like] \w\$ " exec bash --noprofile --norc -i'
