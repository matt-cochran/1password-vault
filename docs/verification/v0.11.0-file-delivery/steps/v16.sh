set -u
S=${S:?set S to a scratch directory}
E=${REPO:?set REPO to this checkout}/docs/verification/v0.11.0-file-delivery
export KUBECONFIG=$S/kubeconfig
P=$S/canary.txt
echo '=== V16: canary scan (patterns: every marker, its full-value base64 and offset base64 forms; pattern file kept outside the record)'
echo "patterns: $(wc -l < $P)"
mkdir -p $S/scan
kubectl get deployments,replicasets -A -o yaml > $S/scan/objects.yaml
kubectl get events -A -o yaml > $S/scan/events.yaml
: > $S/scan/logs.txt
for p in $(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  kubectl logs -n "${p%/*}" "${p#*/}" --all-containers --prefix >> $S/scan/logs.txt 2>&1
done
scan() { n=$(grep -c -F -f $P "$2" 2>/dev/null); echo "$1: lines=$(wc -l < "$2") hits=${n:-0}"; }
scan transcript $E/transcript.txt
scan "deployments+replicasets (all namespaces)" $S/scan/objects.yaml
scan "events (all namespaces)" $S/scan/events.yaml
scan "kubectl logs, every pod, all containers" $S/scan/logs.txt
echo '$ docker exec opv-verify-136-control-plane grep -r -c -F -f <patterns> /var/log/pods'
docker cp $P opv-verify-136-control-plane:/tmp/canary.txt
echo "files under /var/log/pods: $(docker exec opv-verify-136-control-plane sh -c 'find /var/log/pods -type f | wc -l')"
echo "files with hits: $(docker exec opv-verify-136-control-plane sh -c 'grep -r -l -F -f /tmp/canary.txt /var/log/pods | wc -l')"
docker exec opv-verify-136-control-plane rm /tmp/canary.txt
echo "secrets/configmaps labelled opv-managed (the stores' own data): $(kubectl get secret,configmap -A -l opv-managed -o name | wc -l)"
echo '=== V17'
echo '$ kind delete cluster --name opv-verify-136'
kind delete cluster --name opv-verify-136 --kubeconfig $KUBECONFIG 2>&1; echo "exit=$?"
echo '$ kind get clusters'; kind get clusters 2>&1
echo '$ docker ps -a --filter name=opv-verify-136 (expect empty)'; docker ps -a --filter name=opv-verify-136 --format '{{.Names}}'; echo "(end)"
