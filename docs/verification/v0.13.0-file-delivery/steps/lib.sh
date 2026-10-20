# Sourced by every step script. Session variables (set once, preflight P10):
#   S        the session scratch directory, on tmpfs, outside any git work tree
#   REPO     this checkout (the kit is read from here; nothing is written here)
#   CANARY   the generator's output directory for this run
#   FLY_APP  the staging fleet app the owner confirmed in P0
set -u -o pipefail
: "${S:?set S}" "${REPO:?set REPO}" "${CANARY:?set CANARY}" "${FLY_APP:?set FLY_APP}"
KIT=$REPO/docs/verification/v0.13.0-file-delivery
E=$S/evidence                       # captures; scrubbed copies go into the record later
OPV=$S/rel/opv                      # the v0.13.0 release asset (A4-V1)
PROJECT=$S/project                  # kit/opv/secrets.toml + the bindings opv apply writes
PATTERNS=$CANARY/patterns.txt
ADMIN_KUBECONFIG=$S/kubeconfig      # kind's admin context: kit setup and reads only
CI_KUBECONFIG=$S/kubeconfig-opv-ci  # the opv-ci identity: what opv uses
IMAGE_A5='debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f'
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

# --- Fly guard: every flyctl call in the kit goes through flysafe -------------------------
guard_app() {
  # Segment match: "mcproductlabs" contains "prod", so a plain *prod* glob would refuse staging.
  case "-$FLY_APP-" in *-prod-*|*-production-*|*-prd-*) echo "refused: $FLY_APP looks like production"; exit 3;; esac
  [ "$FLY_APP" = "$(cat "$S/a5/app.confirmed" 2>/dev/null)" ] || {
    echo "refused: FLY_APP is not the app confirmed in P0 ($S/a5/app.confirmed)"; exit 3; }
}
guard_machine() {
  grep -qx "${1:-none}" "$S/a5/machines" 2>/dev/null || {
    echo "refused: '${1:-}' is not a one-off machine created by this kit"; return 3; }
}
flysafe() {
  guard_app
  case "$1 ${2:-}" in
    "deploy "*|"secrets deploy"|"secrets set"|"scale "*|"apps "*|"machine start"|"machine clone"|"volumes "*)
      echo "refused by the kit: flyctl $1 ${2:-} could touch the running service"; return 3;;
    "secrets import"|"secrets unset")
      [[ " $* " == *" --stage "* ]] || { echo "refused: flyctl $1 $2 without --stage"; return 3; }
      if [ "$2" = unset ]; then
        for n in "${@:3}"; do case $n in --*) ;; OPVCANARY*) ;; *) echo "refused: unset of non-canary name $n"; return 3;; esac; done
      fi;;
    "machine update"|"machine restart"|"machine destroy"|"machine stop"|"machine exec"|"machine status")
      guard_machine "${3:-}" || return 3;;
    "machine run")
      [[ " $* " == *" --name opvcanary-"* ]] || { echo "refused: a kit machine is named opvcanary-*"; return 3; };;
    "logs "*)
      [[ " $* " == *" --machine "* ]] || { echo "refused: fly logs without --machine (the fleet's logs hold other products' data)"; return 3; };;
  esac
  printf '$ flyctl %s --app <app>\n' "$*" | sed -e "s#$S#<scratch>#g" -e "s#$REPO#<repo>#g" >&2
  flyctl "$@" --app "$FLY_APP"; local rc=$?; echo "exit=$rc" >&2; return $rc
}

# Read-only JSON queries, no wrapper output (machine list, releases, secrets list).
flyq() {
  guard_app
  case "$1 ${2:-}" in "machine list"|"releases "*|"secrets list"|"status "*) ;; *) echo "flyq: read-only queries only" >&2; return 3;; esac
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

# kind's admin context, for kit setup and for reads opv-ci has no right to (pod logs, exec).
kadmin() { KUBECONFIG=$ADMIN_KUBECONFIG kubectl "$@"; }

# A5: run the fixed probe in a kit machine; output goes to $E/a5/<label>.txt.
A5_PATHS=(/dev/shm/opvcanary/a5-file /run/opvcanary/a5-file /opt/opvcanary/a5-file)
a5_file_secret_flags() { for p in "${A5_PATHS[@]}"; do printf -- '--file-secret\n%s=OPVCANARY_A5_FILE\n' "$p"; done; }
probe() {
  local id=$1 label=$2 b64; mkdir -p "$E/a5"
  b64=$(base64 -w0 < "$KIT/canary/a5-probe.sh")
  flysafe machine exec "$id" "sh -c 'echo $b64 | base64 -d | sh'" | tee "$E/a5/$label.txt"
}
# Which canary version each path holds: v1, v2, absent or OTHER.
a5_versions() {
  local f=$1 v1 v2; v1=$(awk '$1=="file-v1"{print $2}' "$CANARY/expect/a5.txt"); v2=$(awk '$1=="file-v2"{print $2}' "$CANARY/expect/a5.txt")
  for p in "${A5_PATHS[@]}"; do
    line=$(grep -F "$p: present" "$f" || true)
    if [ -z "$line" ]; then echo "$p=absent"
    elif [[ $line == *"sha256=$v1"* ]]; then echo "$p=v1"
    elif [[ $line == *"sha256=$v2"* ]]; then echo "$p=v2"
    else echo "$p=OTHER"; fi
  done
}
