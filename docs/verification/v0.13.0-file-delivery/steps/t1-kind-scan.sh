# T1 (CI-like or person): delete the local cluster (A4-V17) and take the final capture of the
# throwaway app for the T6 scan, while the token still works. LIVE READ of the app only.
source "$(dirname "$0")/lib.sh"; guard_app
say "T1 the local cluster"
kind get clusters 2>/dev/null | grep -qx opv-verify-136 && run kind delete cluster --name opv-verify-136 --kubeconfig "$ADMIN_KUBECONFIG"
check T1 kind_gone $(kind get clusters 2>/dev/null | grep -qx opv-verify-136 && echo 0 || echo 1)
say "T1 final capture of the app"
flyq secrets list > "$E/t1-secrets-list.json"
flyq machine list > "$E/t1-machine-list.json"
flysafe logs --no-tail > "$E/t1-logs-app.txt" 2>&1 || true
