#!/bin/sh
# Live smoke test for opv 0.5.0. See README.md. Prints names and versions only.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGETS=${OPV_SMOKE_TARGETS:-"azure kubernetes eso"}
OPV=${OPV_BIN:-opv}

need() {
    eval "v=\${$1:-}"
    if [ -z "$v" ]; then
        echo "missing required variable $1 (see README.md)" >&2
        exit 2
    fi
    case $v in
    *[!A-Za-z0-9._:/@+-]*)
        echo "$1 holds a character outside [A-Za-z0-9._:/@+-]" >&2
        exit 2
        ;;
    esac
}

for v in OPV_SMOKE_OP_ACCOUNT OPV_SMOKE_OP_VAULT_ID OPV_SMOKE_OP_ITEM_ID OPV_SMOKE_AZ_SUBSCRIPTION \
    OPV_SMOKE_AZ_KEY_VAULT OPV_SMOKE_AZ_RG OPV_SMOKE_AZ_APP; do
    need "$v"
done
OPV_SMOKE_K8S_CONTEXT=${OPV_SMOKE_K8S_CONTEXT:-kind-opv}
OPV_SMOKE_K8S_NAMESPACE=${OPV_SMOKE_K8S_NAMESPACE:-opv-spike}
OPV_SMOKE_K8S_DEPLOYMENT=${OPV_SMOKE_K8S_DEPLOYMENT:-api}
OPV_SMOKE_ESO_STORE=${OPV_SMOKE_ESO_STORE:-prod-vault}
for v in OPV_SMOKE_K8S_CONTEXT OPV_SMOKE_K8S_NAMESPACE OPV_SMOKE_K8S_DEPLOYMENT OPV_SMOKE_ESO_STORE; do
    need "$v"
done

# Hard refusals: only the disposable sandbox may be used.
case $OPV_SMOKE_K8S_CONTEXT in
kind-*) ;;
*)
    echo "refusing: context $OPV_SMOKE_K8S_CONTEXT is not a kind cluster" >&2
    exit 2
    ;;
esac
case $OPV_SMOKE_AZ_RG in
opv-spike*) ;;
*)
    echo "refusing: resource group $OPV_SMOKE_AZ_RG is not an opv-spike sandbox" >&2
    exit 2
    ;;
esac
case $OPV_SMOKE_AZ_APP in
opv-spike*) ;;
*)
    echo "refusing: container app $OPV_SMOKE_AZ_APP is not an opv-spike sandbox" >&2
    exit 2
    ;;
esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/opv-smoke.XXXXXX")
RECEIPT=$WORK/receipt.txt
: >"$RECEIPT"
trap 'echo "receipt: $RECEIPT"' EXIT

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
echo "rendered config: $WORK/secrets.toml (no values)" | tee -a "$RECEIPT"

# step <expected-exit> <config> <label> <opv args...>
step() {
    want=$1
    cfg=$2
    label=$3
    shift 3
    {
        echo "=== $label: opv $*"
    } >>"$RECEIPT"
    set +e
    OPV_CONFIG=$cfg "$OPV" "$@" >>"$RECEIPT" 2>&1
    got=$?
    set -e
    echo "--- exit $got (expected $want)" >>"$RECEIPT"
    if [ "$got" -eq "$want" ]; then
        echo "PASS  $label  (exit $got)"
    else
        echo "FAIL  $label  (exit $got, expected $want)"
        echo "Stopped on the first unexpected result."
        exit 1
    fi
}

phase_one() {
    e=$1
    cfg=$WORK/secrets.toml
    step 0 "$cfg" "$e doctor" doctor --env "$e"
    step 0 "$cfg" "$e check" check "$e"
    step 0 "$cfg" "$e plan" plan "$e"
    step 0 "$cfg" "$e sync (stage)" sync "$e"
    step 0 "$cfg" "$e sync --deploy" sync "$e" --deploy
    step 0 "$cfg" "$e status" status "$e"
}

phase_two() {
    e=$1
    cfg=$WORK/secrets.toml
    step 0 "$cfg" "$e plan after change" plan "$e"
    step 0 "$cfg" "$e sync --deploy (repin)" sync "$e" --deploy
    step 0 "$cfg" "$e status after repin" status "$e"
    # The pruned config no longer declares LOG_LEVEL, so --prune unsets it on the target.
    step 0 "$WORK/secrets.pruned.toml" "$e sync --deploy --prune (LOG_LEVEL removed)" \
        sync "$e" --deploy --prune
}

for e in $TARGETS; do
    phase_one "$e"
done

cat <<MSG

Rotation step (manual). In 1Password, in the DISPOSABLE item only:
  vault id: $OPV_SMOKE_OP_VAULT_ID   item id: $OPV_SMOKE_OP_ITEM_ID
  Edit field smoke / API_TOKEN and set a NEW marker value that still starts
  with your marker prefix. Type it in 1Password, never here.
Then press Enter to continue (Ctrl-C to stop; nothing else changes).
MSG
read -r _ignored

for e in $TARGETS; do
    phase_two "$e"
done

# Leak guard: the receipt must never contain a marker value.
if [ -n "${OPV_SMOKE_MARKER_PREFIX:-}" ]; then
    if grep -q -F -- "$OPV_SMOKE_MARKER_PREFIX" "$RECEIPT"; then
        echo "FAIL  receipt contains the marker prefix; do not share it"
        exit 1
    fi
    echo "PASS  receipt holds no marker prefix"
fi
echo "All steps passed."
