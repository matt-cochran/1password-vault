set -u
S=${S:?set S to a scratch directory}
K=${REPO:?set REPO to this checkout}/docs/verification/v0.11.0-file-delivery/kit
export KUBECONFIG=$S/kubeconfig
echo '=== V2'
echo '$ kind version; kubectl version --client'
kind version; kubectl version --client
echo '$ kind create cluster --name opv-verify-136 --kubeconfig <scratch>/kubeconfig'
kind create cluster --name opv-verify-136 --kubeconfig $KUBECONFIG 2>&1; echo "exit=$?"
echo '$ kubectl version (server)'; kubectl version 2>&1 | grep Server
mkdir -p $S/img && cp $S/kit-target/release/opv-verify-136 $S/img/ && cp $K/Dockerfile $S/img/
echo '$ docker build -t opv-verify-136:0.11.0 <context: Dockerfile + release build>'
docker build -q -t opv-verify-136:0.11.0 $S/img 2>&1; echo "exit=$?"
echo '$ docker run --rm opv-verify-136:0.11.0 sh -c id  (the image user)'
docker run --rm --entrypoint id opv-verify-136:0.11.0; echo "exit=$?"
echo '$ docker run --rm --entrypoint sh opv-verify-136:0.11.0 -c "command -v op opv || echo none"'
docker run --rm --entrypoint sh opv-verify-136:0.11.0 -c 'command -v op opv || echo none'
echo '$ kind load docker-image opv-verify-136:0.11.0 --name opv-verify-136'
kind load docker-image opv-verify-136:0.11.0 --name opv-verify-136 2>&1; echo "exit=$?"
echo '$ kubectl apply -f k8s/'
kubectl apply -f $K/k8s/ 2>&1; echo "exit=$?"
echo '$ kubectl -n jzverify rollout status deploy/jzverify deploy/jzverify-nofsgroup --timeout=120s'
kubectl -n jzverify rollout status deploy/jzverify --timeout=120s; kubectl -n jzverify rollout status deploy/jzverify-nofsgroup --timeout=120s
echo '$ kubectl -n jzverify get deployments,pods'
kubectl -n jzverify get deployments,pods -o wide 2>&1 | awk '{print $1,$2,$3,$4,$5}'
echo '$ kubectl get clusterrolebindings -o json | jq names bound to opv-ci (expect none)'
kubectl get clusterrolebindings -o json | jq -r '.items[]|select(any(.subjects[]?; .name=="opv-ci"))|.metadata.name' ; echo "(end)"
