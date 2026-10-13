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

# The environment-scoped half of the github target: listing github runs both. The GitHub
# environment it writes must already exist; opv never creates one.
if has github && ! has githubenv; then
    TARGETS="$TARGETS githubenv"
fi

need_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing tool: $1 ($2)" >&2
        exit 3
    }
}

need_tool op "1Password CLI"
need_tool "$OPV" "opv 0.5.0, or set OPV_BIN"
case $("$OPV" --version 2>/dev/null) in
"opv 0."[0-4].*)
    echo "$OPV is $("$OPV" --version); the smoke test needs 0.5.0 or later" >&2
    echo "Next: OPV_BIN=/path/to/opv-0.5.0 scripts/smoke/run.sh --account $OPV_SMOKE_OP_ACCOUNT" >&2
    exit 3
    ;;
esac
need_tool az "Azure CLI"
{ has kubernetes || has eso; } && need_tool kubectl "kubectl"
if has github || has githubenv; then
    need_tool gh "GitHub CLI"
    if ! gh auth status >/dev/null 2>&1; then
        echo "not signed in to GitHub (gh auth status failed)" >&2
        echo "Next: gh auth login" >&2
        exit 7
    fi
fi

# --- Sandbox: defaults and discovery ------------------------------------------------------

OPV_SMOKE_AZ_RG=${OPV_SMOKE_AZ_RG:-opv-spike-rg}
OPV_SMOKE_AZ_APP=${OPV_SMOKE_AZ_APP:-opv-spike-app}
OPV_SMOKE_K8S_CONTEXT=${OPV_SMOKE_K8S_CONTEXT:-kind-opv}
OPV_SMOKE_K8S_NAMESPACE=${OPV_SMOKE_K8S_NAMESPACE:-opv-spike}
OPV_SMOKE_K8S_DEPLOYMENT=${OPV_SMOKE_K8S_DEPLOYMENT:-api}
OPV_SMOKE_ESO_STORE=${OPV_SMOKE_ESO_STORE:-prod-vault}
OPV_SMOKE_GH_REPO=${OPV_SMOKE_GH_REPO:-}
OPV_SMOKE_GH_ENVIRONMENT=${OPV_SMOKE_GH_ENVIRONMENT:-staging}

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

# GitHub sandbox: only a repository whose name part starts with opv-spike may be written.
if has github || has githubenv; then
    [ -n "$OPV_SMOKE_GH_REPO" ] || {
        echo "OPV_SMOKE_GH_REPO is required when github is targeted (owner/name)" >&2
        exit 2
    }
    safe OPV_SMOKE_GH_REPO "$OPV_SMOKE_GH_REPO"
    case $OPV_SMOKE_GH_REPO in
    */*/*)
        echo "OPV_SMOKE_GH_REPO must be owner/name, got $OPV_SMOKE_GH_REPO" >&2
        exit 2
        ;;
    */*) ;;
    *)
        echo "OPV_SMOKE_GH_REPO must be owner/name, got $OPV_SMOKE_GH_REPO" >&2
        exit 2
        ;;
    esac
    case ${OPV_SMOKE_GH_REPO#*/} in
    opv-spike*) ;;
    *)
        echo "refusing: GitHub repository $OPV_SMOKE_GH_REPO is not an opv-spike sandbox repository" >&2
        exit 2
        ;;
    esac
fi

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
    OPV_SMOKE_K8S_DEPLOYMENT OPV_SMOKE_ESO_STORE OPV_SMOKE_GH_ENVIRONMENT; do
    eval "safe $v \"\${$v}\""
done
[ -z "$GIVEN_VAULT" ] || safe --vault "$GIVEN_VAULT"

# op takes an account ID, shorthand or sign-in address, not an email: an email is
# looked up in `op account list` (two accounts can share one sign-in address).
case $OPV_SMOKE_OP_ACCOUNT in
*@*)
    OP_ACCOUNT=$(op account list --format json | awk -v want="$OPV_SMOKE_OP_ACCOUNT" '
        /"email":/ { e = $0; sub(/.*"email": "/, "", e); sub(/".*/, "", e) }
        /"account_uuid":/ { a = $0; sub(/.*"account_uuid": "/, "", a); sub(/".*/, "", a) }
        /}/ { if (e == want && a != "") print a; e = ""; a = "" }' | head -n 1)
    if [ -z "$OP_ACCOUNT" ]; then
        echo "no 1Password account on this machine has the email $OPV_SMOKE_OP_ACCOUNT" >&2
        echo "Next: op account list" >&2
        exit 7
    fi
    safe "the account ID" "$OP_ACCOUNT"
    ;;
*) OP_ACCOUNT=$OPV_SMOKE_OP_ACCOUNT ;;
esac
# Every op call below, and the rendered config, use this account, never op's default.
export OP_ACCOUNT
GIVEN_ACCOUNT=$OPV_SMOKE_OP_ACCOUNT
OPV_SMOKE_OP_ACCOUNT=$OP_ACCOUNT
# Signed out at a terminal: sign in at op's own prompt. The session stays in this
# process's environment (inherited by op and opv below) and ends with it.
if ! op whoami >/dev/null 2>&1 && [ -t 0 ]; then
    echo "signing in to 1Password account $OP_ACCOUNT" >&2
    session=$(op signin --account "$OP_ACCOUNT") || session=
    eval "$session"
    unset session
fi
if ! op whoami >/dev/null 2>&1; then
    echo "not signed in to 1Password account $OP_ACCOUNT" >&2
    echo "Next: scripts/smoke/run.sh --account $GIVEN_ACCOUNT  (at a terminal; it signs in)" >&2
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
    if has github || has githubenv; then
        for n in SMOKE_API_TOKEN SMOKE_DB_URL; do
            gh secret delete "$n" -R "$OPV_SMOKE_GH_REPO" >/dev/null 2>&1
        done
        gh variable delete SMOKE_LOG_LEVEL -R "$OPV_SMOKE_GH_REPO" >/dev/null 2>&1
        gh secret delete OPV_SMOKE_UNMANAGED -R "$OPV_SMOKE_GH_REPO" >/dev/null 2>&1
        if has githubenv; then
            for n in SMOKE_API_TOKEN SMOKE_DB_URL; do
                gh secret delete "$n" -R "$OPV_SMOKE_GH_REPO" -e "$OPV_SMOKE_GH_ENVIRONMENT" >/dev/null 2>&1
            done
            gh variable delete SMOKE_LOG_LEVEL -R "$OPV_SMOKE_GH_REPO" -e "$OPV_SMOKE_GH_ENVIRONMENT" >/dev/null 2>&1
        fi
        log "removed GitHub smoke secrets and variables (SMOKE_*, OPV_SMOKE_UNMANAGED)"
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
# $1 = output file, $2 = "keep" or "prune": the lines of the other block are left out.
render() {
    out=$1
    mode=$2
    skip=0
    : >"$out"
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
        "# BEGIN KEEP")
            [ "$mode" = keep ] || skip=1
            continue
            ;;
        "# BEGIN PRUNE")
            [ "$mode" = prune ] || skip=1
            continue
            ;;
        "# BEGIN TARGET "*)
            target=${line#"# BEGIN TARGET "}
            has "$target" || skip=1
            continue
            ;;
        "# END KEEP" | "# END PRUNE" | "# END TARGET")
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
        # Drop environment names that are not targeted, as the block directive does.
        case $line in
        "environments = ["*)
            inner=${line#environments = [}
            inner=${inner%]}
            kept=
            while IFS= read -r item; do
                envname=$(printf '%s' "$item" | tr -d ' "')
                [ -n "$envname" ] || continue
                has "$envname" || continue
                if [ -z "$kept" ]; then
                    kept="\"$envname\""
                else
                    kept="$kept, \"$envname\""
                fi
            done <<EOF
$(printf '%s' "$inner" | tr ',' '\n')
EOF
            line="environments = [$kept]"
            ;;
        esac
        printf '%s\n' "$line" >>"$out"
    done <"$HERE/secrets.toml.tmpl"
}

render "$WORK/secrets.toml" keep
render "$WORK/secrets.pruned.toml" prune
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
        az_len "$2"
    else
        kubectl --context "$OPV_SMOKE_K8S_CONTEXT" --namespace "$OPV_SMOKE_K8S_NAMESPACE" \
            exec "deploy/$OPV_SMOKE_K8S_DEPLOYMENT" -- printenv "$2" 2>/dev/null |
            tr -d '\n' | wc -c | tr -d ' '
    fi
}

# Container Apps: the live revision's variable, followed to the Key Vault secret version
# it is pinned to. Not `az containerapp exec`, which Azure rate-limits (429, retry after
# 10 minutes) and which needs a tty.
az_app() {
    az containerapp "$@" -g "$OPV_SMOKE_AZ_RG" -n "$OPV_SMOKE_AZ_APP" \
        --subscription "$OPV_SMOKE_AZ_SUBSCRIPTION" -o tsv
}
az_len() {
    rev=$(az_app show --query properties.latestReadyRevisionName)
    env_q="properties.template.containers[0].env[?name=='$1']"
    if [ "$(az_app revision show --revision "$rev" --query "length($env_q)")" = 0 ]; then
        echo 0
        return
    fi
    ref=$(az_app revision show --revision "$rev" --query "$env_q.secretRef | [0]")
    if [ -z "$ref" ] || [ "$ref" = None ]; then
        az_app revision show --revision "$rev" --query "$env_q.value | [0]" |
            tr -d '\n' | wc -c | tr -d ' '
        return
    fi
    url=$(az_app show --query "properties.configuration.secrets[?name=='$ref'].keyVaultUrl | [0]")
    case $url in
    https://*.vault.azure.net/secrets/*/*) ;;
    *)
        echo "-1"
        return
        ;;
    esac
    az keyvault secret show --id "$url" --query value -o tsv | tr -d '\n' | wc -c | tr -d ' '
}

var_for() {
    case $1 in
    eso) printf 'ESO__SMOKE__%s' "$2" ;;
    *) printf 'FLEET__SMOKE__%s' "$2" ;;
    esac
}

# seen <env> <KEY> <expected length>: retried, since a replica that is still terminating can
# answer first and External Secrets refreshes on its own clock. -1 means a Container Apps
# secret is not a versioned Key Vault reference.
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

# --- GitHub verification ----------------------------------------------------------------

# The secret and variable names `gh` lists for a smoke environment: repository values for
# `github`, or the GitHub environment's values for `githubenv`. Names and config only.
gh_secret_names() {
    if [ "$1" = githubenv ]; then
        gh secret list -R "$OPV_SMOKE_GH_REPO" -e "$OPV_SMOKE_GH_ENVIRONMENT" --json name --jq '.[].name'
    else
        gh secret list -R "$OPV_SMOKE_GH_REPO" --json name --jq '.[].name'
    fi
}
gh_variable_names() {
    if [ "$1" = githubenv ]; then
        gh variable list -R "$OPV_SMOKE_GH_REPO" -e "$OPV_SMOKE_GH_ENVIRONMENT" --json name --jq '.[].name'
    else
        gh variable list -R "$OPV_SMOKE_GH_REPO" --json name --jq '.[].name'
    fi
}
gh_variable_value() {
    if [ "$1" = githubenv ]; then
        gh variable get "$2" -R "$OPV_SMOKE_GH_REPO" -e "$OPV_SMOKE_GH_ENVIRONMENT"
    else
        gh variable get "$2" -R "$OPV_SMOKE_GH_REPO"
    fi
}
gh_secret_updated_at() {
    if [ "$1" = githubenv ]; then
        gh secret list -R "$OPV_SMOKE_GH_REPO" -e "$OPV_SMOKE_GH_ENVIRONMENT" --json name,updatedAt \
            --jq '.[] | select(.name == "SMOKE_API_TOKEN") | .updatedAt'
    else
        gh secret list -R "$OPV_SMOKE_GH_REPO" --json name,updatedAt \
            --jq '.[] | select(.name == "SMOKE_API_TOKEN") | .updatedAt'
    fi
}
gh_has_secret() { gh_secret_names "$1" | grep -qxF "$2"; }
gh_has_variable() { gh_variable_names "$1" | grep -qxF "$2"; }

# verify_github <env>: the managed secret names are present and the variable equals the
# item's marker exactly. GitHub never returns a secret value, so names only.
verify_github() {
    gh_has_secret "$1" SMOKE_API_TOKEN || fail "$1 lacks secret SMOKE_API_TOKEN"
    log "PASS  $1 secret SMOKE_API_TOKEN is present"
    gh_has_secret "$1" SMOKE_DB_URL || fail "$1 lacks secret SMOKE_DB_URL"
    log "PASS  $1 secret SMOKE_DB_URL is present"
    got=$(gh_variable_value "$1" SMOKE_LOG_LEVEL 2>/dev/null) || got=
    [ "$got" = "$LOG_LEVEL" ] || fail "$1 variable SMOKE_LOG_LEVEL does not match the item"
    log "PASS  $1 variable SMOKE_LOG_LEVEL matches the item"
}

# step_out <config> <label> <needle> <opv args...>: exit 0 and output holds the needle.
step_out() {
    cfg=$1
    label=$2
    needle=$3
    shift 3
    out=$WORK/step.out
    echo "=== $label: opv $*" >>"$RECEIPT"
    set +e
    OPV_CONFIG=$cfg "$OPV" "$@" >"$out" 2>&1
    got=$?
    set -e
    cat "$out" >>"$RECEIPT"
    echo "--- exit $got (expected 0)" >>"$RECEIPT"
    [ "$got" -eq 0 ] || fail "$label  (exit $got)"
    grep -q -F -- "$needle" "$out" || fail "$label did not report: $needle"
    echo "PASS  $label"
}

# githubenv writes a GitHub environment that must already exist. opv never creates one, so
# name the owner's command and fail before any write.
if has githubenv; then
    if ! gh api "repos/$OPV_SMOKE_GH_REPO/environments" --jq '.environments[].name' 2>/dev/null |
        grep -qxF "$OPV_SMOKE_GH_ENVIRONMENT"; then
        echo "GitHub environment $OPV_SMOKE_GH_ENVIRONMENT is missing from $OPV_SMOKE_GH_REPO" >&2
        echo "Next: gh api -X PUT repos/$OPV_SMOKE_GH_REPO/environments/$OPV_SMOKE_GH_ENVIRONMENT" >&2
        fail "githubenv: GitHub environment $OPV_SMOKE_GH_ENVIRONMENT is missing"
    fi
fi

# A secret opv does not manage: prune must leave it alone. Value on stdin only.
if has github; then
    OPV_SMOKE_UNMANAGED=$(marker 24)
    printf '%s' "$OPV_SMOKE_UNMANAGED" | gh secret set OPV_SMOKE_UNMANAGED -R "$OPV_SMOKE_GH_REPO"
    log "set unmanaged GitHub secret OPV_SMOKE_UNMANAGED (marker only)"
fi

for e in $TARGETS; do
    cfg=$WORK/secrets.toml
    step "$cfg" "$e doctor" doctor --env "$e"
    step "$cfg" "$e check" check "$e"
    step "$cfg" "$e plan" plan "$e"
    step "$cfg" "$e sync" sync "$e"
    case $e in
    github | githubenv) step_out "$cfg" "$e sync --deploy" "nothing to deploy" sync "$e" --deploy ;;
    *) step "$cfg" "$e sync --deploy" sync "$e" --deploy ;;
    esac
    step "$cfg" "$e status" status "$e"
    case $e in
    github | githubenv) verify_github "$e" ;;
    *) seen "$e" API_TOKEN $TOKEN_LEN_BEFORE ;;
    esac
done

API_TOKEN=$(marker $TOKEN_LEN_AFTER)
item_json | op item edit "$ITEM" --vault "$OPV_SMOKE_OP_VAULT_ID" --format json >/dev/null
log "rotated smoke/API_TOKEN in 1Password (length $TOKEN_LEN_BEFORE -> $TOKEN_LEN_AFTER)"

for e in $TARGETS; do
    cfg=$WORK/secrets.toml
    case $e in
    github | githubenv) before=$(gh_secret_updated_at "$e") ;;
    esac
    step "$cfg" "$e plan after rotation" plan "$e"
    step "$cfg" "$e sync --deploy (repin)" sync "$e" --deploy
    step "$cfg" "$e status after repin" status "$e"
    case $e in
    github | githubenv)
        after=$(gh_secret_updated_at "$e")
        [ "$before" != "$after" ] || fail "$e secret SMOKE_API_TOKEN updatedAt did not change"
        log "PASS  $e secret SMOKE_API_TOKEN updatedAt changed"
        verify_github "$e"
        ;;
    *) seen "$e" API_TOKEN $TOKEN_LEN_AFTER ;;
    esac
    # The pruned config declares LOG_LEVEL for no environment, so --prune unsets it.
    step "$WORK/secrets.pruned.toml" "$e sync --deploy --prune (LOG_LEVEL wanted nowhere)" \
        sync "$e" --deploy --prune
    case $e in
    github | githubenv)
        gh_has_variable "$e" SMOKE_LOG_LEVEL && fail "$e variable SMOKE_LOG_LEVEL was not pruned"
        log "PASS  $e variable SMOKE_LOG_LEVEL is gone"
        ;;
    *) seen "$e" LOG_LEVEL 0 ;;
    esac
done

# The unmanaged secret was never declared, so --prune must have left it in place.
if has github; then
    gh_has_secret github OPV_SMOKE_UNMANAGED || fail "unmanaged secret OPV_SMOKE_UNMANAGED was removed"
    log "PASS  unmanaged secret OPV_SMOKE_UNMANAGED is still present"
fi

# Leak guard: the receipt must never contain a marker.
if grep -q -F -- "$PREFIX" "$RECEIPT"; then
    fail "the receipt contains a marker; do not share it"
fi
log "PASS  receipt holds no marker"
log "All steps passed."
