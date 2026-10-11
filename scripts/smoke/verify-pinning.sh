#!/bin/sh
# Checks the running replica's variable LENGTH (never the value).
# Required: OPV_SMOKE_EXPECT_LEN (marker length incl. nothing extra; printenv adds 1 newline,
# which this script accounts for), OPV_SMOKE_VAR (e.g. FLEET__SMOKE__API_TOKEN).
# Kubernetes: OPV_SMOKE_K8S_VAR optional override. Container Apps: OPV_SMOKE_AZ_RG, _AZ_APP.
set -eu

: "${OPV_SMOKE_EXPECT_LEN:?set the expected marker length}"
: "${OPV_SMOKE_VAR:?set the variable name to check}"
CTX=${OPV_SMOKE_K8S_CONTEXT:-kind-opv}
NS=${OPV_SMOKE_K8S_NAMESPACE:-opv-spike}
DEP=${OPV_SMOKE_K8S_DEPLOYMENT:-api}

case $OPV_SMOKE_VAR in
*[!A-Za-z0-9_]*)
    echo "bad variable name" >&2
    exit 2
    ;;
esac
case $OPV_SMOKE_EXPECT_LEN in
*[!0-9]* | "")
    echo "bad length" >&2
    exit 2
    ;;
esac
want=$((OPV_SMOKE_EXPECT_LEN + 1))
fail=0

check() {
    label=$1
    got=$2
    if [ "$got" -eq "$want" ]; then
        echo "PASS  $label  length $OPV_SMOKE_EXPECT_LEN"
    else
        echo "FAIL  $label  length $((got - 1)), expected $OPV_SMOKE_EXPECT_LEN"
        fail=1
    fi
}

if [ "${OPV_SMOKE_SKIP_K8S:-0}" != 1 ]; then
    got=$(kubectl --context "$CTX" --namespace "$NS" exec "deploy/$DEP" -- \
        printenv "$OPV_SMOKE_VAR" | wc -c | tr -d ' ')
    check "kubernetes $NS/$DEP $OPV_SMOKE_VAR" "$got"
fi

if [ "${OPV_SMOKE_SKIP_AZ:-0}" != 1 ]; then
    : "${OPV_SMOKE_AZ_RG:?}" "${OPV_SMOKE_AZ_APP:?}"
    # az containerapp exec needs a tty; script(1) supplies one. Output is reduced to a
    # byte count here and the value is never stored or printed.
    got=$(script -qec "az containerapp exec -g $OPV_SMOKE_AZ_RG -n $OPV_SMOKE_AZ_APP \
        --command 'printenv $OPV_SMOKE_VAR'" /dev/null | tr -d '\r' |
        grep -v -e '^INFO' -e '^Use ctrl' -e '^Connecting' -e '^$' | wc -c | tr -d ' ')
    check "container app $OPV_SMOKE_AZ_APP $OPV_SMOKE_VAR" "$got"
fi
exit "$fail"
