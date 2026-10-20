# A4-V17: delete the local cluster (also teardown T4).
source "$(dirname "$0")/lib.sh"
say "A4-V17"
run kind delete cluster --name opv-verify-136 --kubeconfig "$ADMIN_KUBECONFIG"
run kind get clusters
left=$(docker ps -a --filter name=opv-verify-136 --format '{{.Names}}' | wc -l)
check A4-V17 gone $([ "$left" = 0 ] && echo 1 || echo 0) "$left containers left"
