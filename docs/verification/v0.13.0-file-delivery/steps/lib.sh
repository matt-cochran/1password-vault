# Sourced by every step script. Session variables (set once, preflight P10):
#   S        the session scratch directory, on tmpfs, outside any git work tree
#   REPO     this checkout (the kit is read from here; nothing is written here)
#   CANARY   the generator's output directory for this run
#   FLY_APP  the throwaway canary app the owner created in P5 (opv-136-canary*)
set -u -o pipefail
: "${S:?set S}" "${REPO:?set REPO}" "${CANARY:?set CANARY}" "${FLY_APP:?set FLY_APP}"
KIT=$REPO/docs/verification/v0.13.0-file-delivery
E=$S/evidence                       # captures; scrubbed copies go into the record later
OPV=$S/rel/opv                      # the v0.13.0 release asset (A4-V1)
PROJECT=$S/project                  # kit/opv/secrets.toml + the bindings opv apply writes
PATTERNS=$CANARY/patterns.txt
ADMIN_KUBECONFIG=$S/kubeconfig      # kind's admin context: kit setup and reads only
CI_KUBECONFIG=$S/kubeconfig-opv-ci  # the opv-ci identity: what opv uses
# A5's image: debian-slim pinned by digest (as kit/Dockerfile), for coreutils stat/df -T/sha256sum.
# Digest-only: Fly's image lookup refuses the name:tag@digest form ("not a valid image").
IMAGE_A5='docker.io/library/debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f'
export OPV_NO_SKILL=1 FLY_NO_UPDATE_CHECK=1 NO_COLOR=1
mkdir -p "$E" "$S/a5"

say() { printf '\n=== %s\n' "$*"; }
# Print the command (scratch path scrubbed), run it, print its exit code. Never pass a value.
# The banner and the exit code go to stderr, so `run cmd > file.json` keeps the file clean;
# `script` records both streams in the transcript.
run() {
  printf '$ %s\n' "$*" | sed -e "s#$S#<scratch>#g" -e "s#$REPO#<repo>#g" >&2
  "$@"; local rc=$?; echo "exit=$rc" >&2; return $rc
}
# CHECK lines are what the results tables record.
check() { local id=$1 name=$2 ok=$3; shift 3; echo "CHECK $id $name: $([ "$ok" = 1 ] && echo pass || echo FAIL)${*:+ ($*)}"; }

# --- who may run what ------------------------------------------------------------------
ci_only() {
  [ "${CI:-}" = true ] && [ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] || {
    echo "refused: run this step in the CI-like shell (steps/ci-shell.sh)"; exit 3; }
}
person_only() {
  [ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ] && [ "${CI:-}" != true ] || {
    echo "refused: run this step in your own shell, signed in to 1Password as yourself"; exit 3; }
}

# --- Fly guard: every flyctl call in the kit goes through flysafe or flyq ----------------
# Allowlist: the ONE throwaway app the owner created in P5 (name opv-136-canary*, recorded in
# $S/a5/app.confirmed). Every other app is refused outright: the shared fleet apps
# (mcproductlabs-*), anything with a prod/production/prd segment, anything not confirmed.
guard_app() {
  case "-$FLY_APP-" in *-prod-*|*-production-*|*-prd-*) echo "refused: $FLY_APP looks like production"; exit 3;; esac
  case "$FLY_APP" in mcproductlabs-*) echo "refused: $FLY_APP is a shared fleet app"; exit 3;; esac
  case "$FLY_APP" in opv-136-canary*) ;; *) echo "refused: $FLY_APP is not the throwaway canary app (opv-136-canary*)"; exit 3;; esac
  [ "$FLY_APP" = "$(cat "$S/a5/app.confirmed" 2>/dev/null)" ] || {
    echo "refused: FLY_APP is not the app the owner created in P5 ($S/a5/app.confirmed)"; exit 3; }
  [ "${FLY_APP_CONFIG_CHECKED:-}" = 1 ] || {
    local m; m=$(sed -n 's/^fly\.app *= *"\([^"]*\)".*/\1/p' "$PROJECT/secrets.toml" 2>/dev/null)
    [ "$m" = "$FLY_APP" ] || { echo "refused: the manifest's fly.app ('$m') is not $FLY_APP"; exit 3; }
    FLY_APP_CONFIG_CHECKED=1; }
}
# On the throwaway app, deploys, secrets deploys and machine commands are allowed. Creating or
# destroying apps is the owner's (P5, T2), never a step's; --app is always forced to FLY_APP.
flysafe() {
  guard_app
  case "$1 ${2:-}" in
    "apps "*|"orgs "*|"tokens "*) echo "refused by the kit: flyctl $1 ${2:-} is the owner's, in P5/T2"; return 3;;
  esac
  for a in "$@"; do case $a in -a|--app|--app=*|-o|--org|--org=*) echo "refused: the kit sets --app itself"; return 3;; esac; done
  printf '$ flyctl %s --app <app>\n' "$*" | sed -e "s#$S#<scratch>#g" -e "s#$REPO#<repo>#g" >&2
  flyctl "$@" --app "$FLY_APP"; local rc=$?; echo "exit=$rc" >&2; return $rc
}

# Read-only JSON queries, no wrapper output (machine list, releases, secrets list).
flyq() {
  guard_app
  case "$1 ${2:-}" in "machine list"|"releases "*|"secrets list"|"status "*|"ips list") ;; *) echo "flyq: read-only queries only" >&2; return 3;; esac
  flyctl "$@" --app "$FLY_APP" --json
}
machine_id() { flyq machine list | jq -r --arg n "$1" '.[]|select(.name==$n)|.id'; }

# Run an opv command with the /proc sampler watching argv and environ for canaries.
sampled() {
  local tag=$1; shift
  bash "$KIT/canary/proc-sampler.sh" "$PATTERNS" "$E/proc-$tag.txt" & local sp=$!
  run "$@"; local rc=$?
  kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
  echo "proc sampler ($tag): $(wc -l < "$E/proc-$tag.txt") processes seen; argv hits: $(awk '{split($3,a,"="); s+=a[2]} END{print s+0}' "$E/proc-$tag.txt"); env hits: $(awk '{split($4,b,"="); if (b[2]!="unreadable") s+=b[2]} END{print s+0}' "$E/proc-$tag.txt"); env unreadable: $(grep -c 'env_hits=unreadable' "$E/proc-$tag.txt")"
  return $rc
}

# The keys the manifest declares for <env> and <role>, as product/KEY, one per line (config keys
# included). Checks count these instead of a number written into the kit (run 256debcd: V4f/V5f
# said 7 for verify-fly, while the manifest declares 7 serve secrets plus LOG_LEVEL, so 8).
declared_keys() {
  python3 -I -c 'import sys, tomllib
m = tomllib.load(open(sys.argv[1], "rb"))
for p, pv in m.get("products", {}).items():
    for k, kv in pv.get("keys", {}).items():
        if sys.argv[2] in kv.get("environments", []) and sys.argv[3] in kv.get("roles", []):
            print(f"{p}/{k}")' "$PROJECT/secrets.toml" "$1" "$2"
}

# kind's admin context, for kit setup and for reads opv-ci has no right to (pod logs, exec).
kadmin() { KUBECONFIG=$ADMIN_KUBECONFIG kubectl "$@"; }

# A5: run the fixed probe in a kit machine; output goes to $E/a5/<label>.txt.
# /dev/shm dropped after the first live run: Fly's init writes the file, then its chown hits
# ENOENT (tmpfs mounted over it) and the VM reboots in a loop (#136 F2 finding).
A5_PATHS=(/run/opvcanary/a5-file /opt/opvcanary/a5-file)
a5_file_secret_flags() { for p in "${A5_PATHS[@]}"; do printf -- '--file-secret\n%s=OPVCANARY_A5_FILE\n' "$p"; done; }
# A probe that did not run (no machine, or a machine that isn't running) is a failure, never
# "absent": the file gets a PROBE FAILED line and a5_versions reports every path as unprobed.
# (Run 256debcd: an exec on a stopped machine read as "absent", so F1 same_result and F3 ran
# against nothing.)
probe() {
  local id=$1 label=$2 b64 rc; mkdir -p "$E/a5"
  b64=$(base64 -w0 < "$KIT/canary/a5-probe.sh")
  flysafe machine exec "$id" "sh -c 'echo $b64 | base64 -d | sh'" | tee "$E/a5/$label.txt"; rc=${PIPESTATUS[0]}
  if [ "$rc" != 0 ] || ! grep -q '^uptime_s=.* boot_id=' "$E/a5/$label.txt"; then
    echo "PROBE FAILED: machine '${id}' did not run the probe (exec exit $rc; not running?)" | tee -a "$E/a5/$label.txt"
    return 1
  fi
}
probed() { ! grep -q '^PROBE FAILED' "$1"; }
# Which canary version each path holds: v1, v2, absent, OTHER, or unprobed (the probe failed).
a5_versions() {
  local f=$1 v1 v2; v1=$(awk '$1=="file-v1"{print $2}' "$CANARY/expect/a5.txt"); v2=$(awk '$1=="file-v2"{print $2}' "$CANARY/expect/a5.txt")
  if ! probed "$f"; then for p in "${A5_PATHS[@]}"; do echo "$p=unprobed"; done; return; fi
  for p in "${A5_PATHS[@]}"; do
    line=$(grep -F "$p: present" "$f" || true)
    if [ -z "$line" ]; then echo "$p=absent"
    elif [[ $line == *"sha256=$v1"* ]]; then echo "$p=v1"
    elif [[ $line == *"sha256=$v2"* ]]; then echo "$p=v2"
    else echo "$p=OTHER"; fi
  done
}
