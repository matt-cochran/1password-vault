# A4-V9 (admin context; exec needs a right opv-ci doesn't have): the mount itself.
source "$(dirname "$0")/lib.sh"
export KUBECONFIG=$ADMIN_KUBECONFIG
say "A4-V9"
x() { run kubectl -n jzverify exec deploy/jzverify -c "$1" -- sh -c "$2"; }
x journeeze 'stat -f -c %T /run/secrets/journeeze' | tee "$E/v9.txt"
x journeeze 'stat -L -c "%a %u %g" /run/secrets/journeeze/database/url' | tee -a "$E/v9.txt"
x journeeze 'id; command -v op opv || echo none; ls /var/run/secrets/kubernetes.io 2>&1 || true' | tee -a "$E/v9.txt"
x sidecar 'ls /run/secrets/journeeze 2>&1 || true' | tee -a "$E/v9.txt"
check A4-V9 tmpfs $(grep -qx tmpfs "$E/v9.txt" && echo 1 || echo 0)
check A4-V9 mode_440_0_10001 $(grep -qx '440 0 10001' "$E/v9.txt" && echo 1 || echo 0)
check A4-V9 no_op_opv $(grep -qx none "$E/v9.txt" && echo 1 || echo 0)
check A4-V9 no_token_no_sidecar_path $([ "$(grep -c 'No such file' "$E/v9.txt")" -ge 2 ] && echo 1 || echo 0) "no SA token dir in journeeze; no /run/secrets/journeeze in sidecar"
