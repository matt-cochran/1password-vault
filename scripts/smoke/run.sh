#!/bin/sh
# Live smoke test for opv 0.5.0: one command, against the disposable sandbox. See README.md.
#   scripts/smoke/run.sh --account <email or account ID> [--vault <vault ID>]
# Creates its own 1Password test data (random markers), runs every step, rotates a value,
# checks the running apps see it, prunes, and removes the test data on every exit.
# Prints names, versions and lengths only.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGETS=${OPV_SMOKE_TARGETS:-"azure kubernetes eso"}
OPV=${OPV_BIN:-opv}
PREFIX=OPVSMOKE-
# Seconds between checks of what a running app sees (12 tries).
WAIT=${OPV_SMOKE_WAIT:-10}

usage() {
    echo "usage: scripts/smoke/run.sh --account <email or account ID> [--vault <vault ID>]" >&2
    exit 2
}

OPV_SMOKE_OP_ACCOUNT=${OPV_SMOKE_OP_ACCOUNT:-}
GIVEN_VAULT=
while [ $# -gt 0 ]; do
    case $1 in
    --account)
        [ $# -ge 2 ] || usage
        OPV_SMOKE_OP_ACCOUNT=$2
        shift 2
        ;;
    --vault)
        [ $# -ge 2 ] || usage
        GIVEN_VAULT=$2
        shift 2
        ;;
    *) usage ;;
    esac
done
[ -n "$OPV_SMOKE_OP_ACCOUNT" ] || usage

# Names that reach a config file or a command line: a fixed character set only.
safe() {
    case $2 in
    "" | *[!A-Za-z0-9._:/@+-]*)
        echo "$1 is empty or holds a character outside [A-Za-z0-9._:/@+-]" >&2
        exit 2
        ;;
    esac
}

has() {
    for t in $TARGETS; do [ "$t" = "$1" ] && return 0; done
    return 1
}

need_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing tool: $1 ($2)" >&2
        exit 3
    }
}

need_tool op "1Password CLI"
need_tool "$OPV" "opv 0.5.0, or set OPV_BIN"
need_tool az "Azure CLI"
has azure && need_tool script "util-linux script, for az containerapp exec"
{ has kubernetes || has eso; } && need_tool kubectl "kubectl"

# --- Sandbox: defaults and discovery ------------------------------------------------------

OPV_SMOKE_AZ_RG=${OPV_SMOKE_AZ_RG:-opv-spike-rg}
OPV_SMOKE_AZ_APP=${OPV_SMOKE_AZ_APP:-opv-spike-app}
OPV_SMOKE_K8S_CONTEXT=${OPV_SMOKE_K8S_CONTEXT:-kind-opv}
OPV_SMOKE_K8S_NAMESPACE=${OPV_SMOKE_K8S_NAMESPACE:-opv-spike}
OPV_SMOKE_K8S_DEPLOYMENT=${OPV_SMOKE_K8S_DEPLOYMENT:-api}
OPV_SMOKE_ESO_STORE=${OPV_SMOKE_ESO_STORE:-prod-vault}

# Hard refusals: only the disposable sandbox may be used.
case $OPV_SMOKE_K8S_CONTEXT in
kind-*) ;;
*)
    echo "refusing: context $OPV_SMOKE_K8S_CONTEXT is not a kind cluster" >&2
    exit 2
    ;;
esac
for v in "$OPV_SMOKE_AZ_RG" "$OPV_SMOKE_AZ_APP"; do
    case $v in
    opv-spike*) ;;
    *)
        echo "refusing: $v is not an opv-spike sandbox resource" >&2
        exit 2
        ;;
    esac
done

# The Key Vault backs the eso store too, so it is found even when azure is not a target.
if [ -z "${OPV_SMOKE_AZ_SUBSCRIPTION:-}" ]; then
    OPV_SMOKE_AZ_SUBSCRIPTION=$(az account show --query id -o tsv)
fi
if [ -z "${OPV_SMOKE_AZ_KEY_VAULT:-}" ]; then
    vaults=$(az keyvault list -g "$OPV_SMOKE_AZ_RG" --subscription "$OPV_SMOKE_AZ_SUBSCRIPTION" \
        --query "[].name" -o tsv)
    if [ "$(printf '%s\n' "$vaults" | grep -c .)" -ne 1 ]; then
        echo "expected exactly one Key Vault in $OPV_SMOKE_AZ_RG; set OPV_SMOKE_AZ_KEY_VAULT" >&2
        exit 2
    fi
    OPV_SMOKE_AZ_KEY_VAULT=$vaults
fi

for v in OPV_SMOKE_OP_ACCOUNT OPV_SMOKE_AZ_SUBSCRIPTION OPV_SMOKE_AZ_KEY_VAULT \
    OPV_SMOKE_AZ_RG OPV_SMOKE_AZ_APP OPV_SMOKE_K8S_CONTEXT OPV_SMOKE_K8S_NAMESPACE \
    OPV_SMOKE_K8S_DEPLOYMENT OPV_SMOKE_ESO_STORE; do
    eval "safe $v \"\${$v}\""
done
[ -z "$GIVEN_VAULT" ] || safe --vault "$GIVEN_VAULT"

# Every op call below uses this account, never op's default.
export OP_ACCOUNT="$OPV_SMOKE_OP_ACCOUNT"
if ! op whoami >/dev/null 2>&1; then
    echo "not signed in to 1Password account $OPV_SMOKE_OP_ACCOUNT" >&2
    echo "Next: op signin --account $OPV_SMOKE_OP_ACCOUNT" >&2
    exit 7
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/opv-smoke.XXXXXX")
chmod 700 "$WORK"
RECEIPT=$WORK/receipt.txt
: >"$RECEIPT"

log() { printf '%s\n' "$*" | tee -a "$RECEIPT"; }

# --- 1Password test data ------------------------------------------------------------------

# A marker: the prefix plus random letters and digits, $1 characters long in total.
marker() {
    r=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | dd bs=1 count="$(($1 - ${#PREFIX}))" 2>/dev/null)
    printf '%s%s' "$PREFIX" "$r"
}

# The top-level "id" of op's pretty-printed JSON on stdin.
top_id() { sed -n 's/^  "id": "\([^"]*\)",*$/\1/p' | head -n 1; }

TOKEN_LEN_BEFORE=32
TOKEN_LEN_AFTER=48
DB_URL=$(marker 40)
LOG_LEVEL=$(marker 20)
API_TOKEN=$(marker $TOKEN_LEN_BEFORE)

# The item JSON goes only to op's stdin: never an argument, never a file.
field() {
    printf '{"id":"%s","label":"%s","type":"%s","section":{"id":"smoke","label":"smoke"},"value":"%s"}' \
        "$1" "$1" "$2" "$3"
}
item_json() {
    printf '{"title":"opv smoke","category":"SECURE_NOTE",'
    printf '"sections":[{"id":"smoke","label":"smoke"}],"fields":['
    field DB_URL CONCEALED "$DB_URL"
    printf ','
    field API_TOKEN CONCEALED "$API_TOKEN"
    printf ','
    field LOG_LEVEL STRING "$LOG_LEVEL"
    printf ']}'
}

OWN_VAULT=
ITEM=
cleanup() {
    status=$?
    set +e
    if [ -n "$ITEM" ]; then
        if op item delete "$ITEM" --vault "$OPV_SMOKE_OP_VAULT_ID" >/dev/null 2>&1; then
            log "removed test item $ITEM"
        else
            log "WARN  could not remove test item $ITEM; delete it in 1Password"
        fi
    fi
    if [ -n "$OWN_VAULT" ]; then
        if op vault delete "$OWN_VAULT" >/dev/null 2>&1; then
            log "removed test vault $OWN_VAULT"
        else
            log "WARN  could not remove test vault $OWN_VAULT; delete it in 1Password"
        fi
    fi
    echo "receipt: $RECEIPT"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "$GIVEN_VAULT" ]; then
    OPV_SMOKE_OP_VAULT_ID=$GIVEN_VAULT
else
    name=opv-smoke-$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | dd bs=1 count=6 2>/dev/null)
    OWN_VAULT=$(op vault create "$name" --format json | top_id)
    safe "the created vault id" "$OWN_VAULT"
    OPV_SMOKE_OP_VAULT_ID=$OWN_VAULT
    log "created test vault $name ($OWN_VAULT)"
fi
ITEM=$(item_json | op item create - --vault "$OPV_SMOKE_OP_VAULT_ID" --format json | top_id)
safe "the created item id" "$ITEM"
OPV_SMOKE_OP_ITEM_ID=$ITEM
log "created test item $ITEM (markers only)"

# --- Config -------------------------------------------------------------------------------

# Render the template: replace each @@NAME@@ with the (validated) variable.
# $1 = output file, $2 = "keep" or "drop" for the OPTIONAL block.
render() {
    out=$1
    mode=$2
    skip=0
    : >"$out"
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
        "# BEGIN OPTIONAL")
            [ "$mode" = drop ] && skip=1
            continue
            ;;
        "# END OPTIONAL")
            skip=0
            continue
            ;;
        esac
        [ "$skip" -eq 1 ] && continue
        while :; do
            case $line in
            *@@*@@*) ;;
            *) break ;;
            esac
            rest=${line#*@@}
            name=${rest%%@@*}
            eval "val=\${$name:-}"
            if [ -z "$val" ]; then
                echo "template placeholder $name has no value" >&2
                exit 2
            fi
            line=${line%%@@*}$val${rest#*@@}
        done
        printf '%s\n' "$line" >>"$out"
    done <"$HERE/secrets.toml.tmpl"
}

render "$WORK/secrets.toml" keep
render "$WORK/secrets.pruned.toml" drop
log "rendered config: $WORK/secrets.toml (IDs and names only)"

# --- Steps --------------------------------------------------------------------------------

fail() {
    log "FAIL  $*"
    log "Stopped on the first unexpected result."
    exit 1
}

# step <config> <label> <opv args...>: every step is expected to exit 0.
step() {
    cfg=$1
    label=$2
    shift 2
    echo "=== $label: opv $*" >>"$RECEIPT"
    set +e
    OPV_CONFIG=$cfg "$OPV" "$@" >>"$RECEIPT" 2>&1
    got=$?
    set -e
    echo "--- exit $got (expected 0)" >>"$RECEIPT"
    [ "$got" -eq 0 ] || fail "$label  (exit $got)"
    echo "PASS  $label"
}

# The length of variable $2 as the running app of environment $1 sees it (0 when unset).
# Only the length leaves the pipeline; the value is never stored or printed.
seen_len() {
    if [ "$1" = azure ]; then
        # az containerapp exec needs a tty; script(1) supplies one.
        script -qec "az containerapp exec -g $OPV_SMOKE_AZ_RG -n $OPV_SMOKE_AZ_APP \
            --command 'printenv $2'" /dev/null 2>/dev/null | tr -d '\r' |
            grep -v -e '^INFO' -e '^Use ctrl' -e '^Connecting' -e '^$' | tr -d '\n' | wc -c | tr -d ' '
    else
        kubectl --context "$OPV_SMOKE_K8S_CONTEXT" --namespace "$OPV_SMOKE_K8S_NAMESPACE" \
            exec "deploy/$OPV_SMOKE_K8S_DEPLOYMENT" -- printenv "$2" 2>/dev/null |
            tr -d '\n' | wc -c | tr -d ' '
    fi
}

var_for() {
    case $1 in
    eso) printf 'ESO__SMOKE__%s' "$2" ;;
    *) printf 'FLEET__SMOKE__%s' "$2" ;;
    esac
}

# seen <env> <KEY> <expected length>: retried, since a replica that is still terminating can
# answer first and External Secrets refreshes on its own clock.
seen() {
    var=$(var_for "$1" "$2")
    tries=1
    while :; do
        got=$(seen_len "$1" "$var")
        got=${got:-0}
        [ "$got" -eq "$3" ] && break
        [ "$tries" -lt 12 ] || fail "$1 app sees $var with length $got, expected $3"
        tries=$((tries + 1))
        sleep "$WAIT"
    done
    log "PASS  $1 app sees $var (length $3)"
}

for e in $TARGETS; do
    cfg=$WORK/secrets.toml
    step "$cfg" "$e doctor" doctor --env "$e"
    step "$cfg" "$e check" check "$e"
    step "$cfg" "$e plan" plan "$e"
    step "$cfg" "$e sync" sync "$e"
    step "$cfg" "$e sync --deploy" sync "$e" --deploy
    step "$cfg" "$e status" status "$e"
    seen "$e" API_TOKEN $TOKEN_LEN_BEFORE
done

API_TOKEN=$(marker $TOKEN_LEN_AFTER)
item_json | op item edit "$ITEM" --vault "$OPV_SMOKE_OP_VAULT_ID" --format json >/dev/null
log "rotated smoke/API_TOKEN in 1Password (length $TOKEN_LEN_BEFORE -> $TOKEN_LEN_AFTER)"

for e in $TARGETS; do
    cfg=$WORK/secrets.toml
    step "$cfg" "$e plan after rotation" plan "$e"
    step "$cfg" "$e sync --deploy (repin)" sync "$e" --deploy
    step "$cfg" "$e status after repin" status "$e"
    seen "$e" API_TOKEN $TOKEN_LEN_AFTER
    # The pruned config no longer declares LOG_LEVEL, so --prune unsets it on the target.
    step "$WORK/secrets.pruned.toml" "$e sync --deploy --prune (LOG_LEVEL removed)" \
        sync "$e" --deploy --prune
    seen "$e" LOG_LEVEL 0
done

# Leak guard: the receipt must never contain a marker.
if grep -q -F -- "$PREFIX" "$RECEIPT"; then
    fail "the receipt contains a marker; do not share it"
fi
log "PASS  receipt holds no marker"
log "All steps passed."
