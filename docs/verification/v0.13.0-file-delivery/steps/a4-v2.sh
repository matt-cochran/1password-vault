# A4-V2 (person): kind cluster, kit image, kit objects, the opv-ci context, expectations.
# Writes: a LOCAL throwaway kind cluster only. Rollback: A4-V17 / T4 (kind delete cluster).
source "$(dirname "$0")/lib.sh"; person_only
export KUBECONFIG=$ADMIN_KUBECONFIG
say "A4-V2 cluster"
run kind version; run kubectl version --client
run kind create cluster --name opv-verify-136 --kubeconfig "$KUBECONFIG"
say "A4-V2 image (consumer built in P9 at $S/kit-target/release/opv-verify-136)"
mkdir -p "$S/img" && cp "$S/kit-target/release/opv-verify-136" "$KIT/kit/Dockerfile" "$S/img/"
run docker build -q -t opv-verify-136:0.13.0 "$S/img"
run docker run --rm --entrypoint id opv-verify-136:0.13.0
run docker run --rm --entrypoint sh opv-verify-136:0.13.0 -c 'command -v op opv || echo none'
run kind load docker-image opv-verify-136:0.13.0 --name opv-verify-136
say "A4-V2 objects and expectations (digests and the hex prefix only)"
run kubectl apply -f "$KIT/kit/k8s/00-namespace.yaml" -f "$KIT/kit/k8s/10-rbac.yaml"
run kubectl -n jzverify create configmap jzverify-expect --from-file=expect="$CANARY/expect/expect.txt"
run kubectl apply -f "$KIT/kit/k8s/20-jzverify.yaml" -f "$KIT/kit/k8s/30-jzverify-nofsgroup.yaml"
kubectl -n jzverify rollout status deploy/jzverify --timeout=180s
kubectl -n jzverify rollout status deploy/jzverify-nofsgroup --timeout=180s
say "A4-V2 the opv-ci context (token straight into a 0600 file; never in argv or output)"
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
ca=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
tok=$(kubectl -n jzverify create token opv-ci --duration=8h)
( umask 077; cat > "$CI_KUBECONFIG" <<KC
apiVersion: v1
kind: Config
clusters: [{name: opv-verify-136, cluster: {server: "$server", certificate-authority-data: "$ca"}}]
users: [{name: opv-ci, user: {token: "$tok"}}]
contexts: [{name: opv-ci, context: {cluster: opv-verify-136, user: opv-ci, namespace: jzverify}}]
current-context: opv-ci
KC
); unset tok
run env KUBECONFIG="$CI_KUBECONFIG" kubectl auth whoami
env KUBECONFIG="$CI_KUBECONFIG" kubectl auth can-i --list -n jzverify | grep -vE "selfsubject|^\s*\[/|nonResource"
run env KUBECONFIG="$CI_KUBECONFIG" kubectl auth can-i list secrets -n default
echo "clusterrolebindings naming opv-ci: $(kubectl get clusterrolebindings -o json | jq '[.items[]|select(any(.subjects[]?; .name=="opv-ci"))]|length')"
say "A4-V2 baseline before any sync (expect absent everywhere, result FAIL)"
sleep 5; kubectl -n jzverify logs deploy/jzverify -c journeeze --tail=16
