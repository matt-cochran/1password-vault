set -u
S=${S:?set S to a scratch directory}
export KUBECONFIG=$S/kubeconfig
echo '=== V2 (kit): the opv-ci context, built without the token in argv or output'
server=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
ca=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
tok=$(kubectl -n jzverify create token opv-ci --duration=2h)
umask 077
cat > $S/kubeconfig-opv-ci <<KC
apiVersion: v1
kind: Config
clusters: [{name: opv-verify-136, cluster: {server: "$server", certificate-authority-data: "$ca"}}]
users: [{name: opv-ci, user: {token: "$tok"}}]
contexts: [{name: opv-ci, context: {cluster: opv-verify-136, user: opv-ci, namespace: jzverify}}]
current-context: opv-ci
KC
unset tok
echo '$ KUBECONFIG=<scratch>/kubeconfig-opv-ci kubectl auth whoami; auth can-i --list -n jzverify'
KUBECONFIG=$S/kubeconfig-opv-ci kubectl auth whoami 2>&1
KUBECONFIG=$S/kubeconfig-opv-ci kubectl auth can-i --list -n jzverify 2>&1 | grep -vE "selfsubject|^\s*\[/|nonResource" 
echo '$ ... auth can-i list secrets -n default (expect no)'
KUBECONFIG=$S/kubeconfig-opv-ci kubectl auth can-i list secrets -n default 2>&1
echo '$ ... auth can-i get secrets --all-namespaces (expect no)'
KUBECONFIG=$S/kubeconfig-opv-ci kubectl auth can-i get secrets --all-namespaces 2>&1
echo '=== baseline before any sync: kubectl logs deploy/jzverify -c journeeze (first pass)'
kubectl -n jzverify logs deploy/jzverify -c journeeze 2>&1 | head -15
