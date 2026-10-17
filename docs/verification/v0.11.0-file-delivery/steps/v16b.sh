set -u
S=${S:?set S to a scratch directory}
K=${REPO:?set REPO to this checkout}/docs/verification/v0.11.0-file-delivery/kit
export KUBECONFIG=$S/kubeconfig
P=$S/canary.txt
N=opv-verify-136-control-plane
echo '=== V16 node-log re-run: the first node scan above did not run (docker cp target missing; grep errored), so V2 is repeated and the node scan re-run with the patterns on stdin'
kind create cluster --name opv-verify-136 --kubeconfig $KUBECONFIG >/dev/null 2>&1; echo "kind create exit=$?"
kind load docker-image opv-verify-136:0.11.0 --name opv-verify-136 >/dev/null 2>&1; echo "kind load exit=$?"
kubectl apply -f $K/k8s/ >/dev/null 2>&1; echo "apply exit=$?"
kubectl -n jzverify rollout status deploy/jzverify --timeout=120s; kubectl -n jzverify rollout status deploy/jzverify-nofsgroup --timeout=120s
sleep 35
echo "pod log files under /var/log/pods (jzverify): $(docker exec $N sh -c 'find /var/log/pods -path "*jzverify*" -type f | wc -l')"
echo "control: lines in the jzverify logs that read 'result:': $(docker exec $N sh -c 'grep -r -h -c "result:" /var/log/pods/jzverify_* | paste -sd+ | bc' 2>/dev/null || echo n/a)"
echo '$ docker exec -i <node> grep -r -l -F -f /dev/stdin /var/log/pods < <patterns>'
docker exec -i $N grep -r -l -F -f /dev/stdin /var/log/pods < $P; echo "grep exit=$? (1 = no hit)"
echo '$ kubectl logs every pod, all containers'
: > $S/scan/logs2.txt
for p in $(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  kubectl logs -n "${p%/*}" "${p#*/}" --all-containers --prefix >> $S/scan/logs2.txt 2>&1
done
grep -c -F -f $P $S/scan/logs2.txt; echo "grep exit=$? (1 = no hit)"
echo '=== V17 (again)'
kind delete cluster --name opv-verify-136 --kubeconfig $KUBECONFIG 2>&1; echo "exit=$?"
kind get clusters 2>&1
