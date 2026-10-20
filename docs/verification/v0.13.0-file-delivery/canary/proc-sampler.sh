#!/usr/bin/env bash
# /proc sampler for the canary scan's argv and environment channels.
#
#   proc-sampler.sh <patterns.txt> <out-file> &   SAMPLER=$!
#   ... run the opv command ...
#   kill $SAMPLER
#
# Every 0.1 s it looks at each process named opv, op, flyctl, fly, kubectl or docker owned
# by this user and checks /proc/<pid>/cmdline and /proc/<pid>/environ against the patterns
# **in memory**. It writes one line per process seen: `pid comm argv-hits env-hits`, plus
# argv[0..2] (the subcommand). It never writes a full command line or any environment:
# environ holds the real service-account and Fly tokens, which must not reach a file. For
# environ it records the names of the variables that hit, never their values.
set -u -o pipefail
P=${1:?patterns}; OUT=${2:?out-file}
[ -s "$P" ] || { echo "sampler: no patterns" >&2; exit 2; }
declare -A seen
: > "$OUT"
# Only processes started after the sampler: not the owner's unrelated opv sessions.
since=$(awk '{print $22}' /proc/$$/stat)
exec 2>/dev/null   # processes exit mid-read; those races are not findings
while :; do
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ -O "$d" ] || continue
    comm=$(cat "$d/comm" 2>/dev/null) || continue
    case $comm in opv|op|flyctl|fly|kubectl|docker) ;; *) continue;; esac
    st=$(awk '{print $22}' "$d/stat" 2>/dev/null) || continue
    [ "${st:-0}" -ge "$since" ] || continue
    a=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | grep -c -F -f "$P")
    # Names (never values) of the variables that hold a canary. A4-V15 expects LOG_LEVEL here:
    # a config key that opv run delivers as a variable by design.
    # opv makes itself non-dumpable (src/hardening.rs), so even its own user can't read its
    # environ: that is recorded as `unreadable`, never as zero hits.
    if [ -r "$d/environ" ] && head -c0 "$d/environ" 2>/dev/null; then
      en=$(tr '\0' '\n' < "$d/environ" 2>/dev/null | grep -F -f "$P" | cut -d= -f1 | paste -sd, -)
      e=$(printf '%s' "$en" | tr ',' '\n' | grep -c .)
    else
      en=""; e=unreadable
    fi
    key="$pid:$a:$e"
    [ -n "${seen[$key]:-}" ] && continue
    seen[$key]=1
    if [ "${a:-0}" -gt 0 ]; then head3="redacted: argv holds a canary"
    else head3=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null | awk '{print $1, $2, $3}'); fi
    echo "pid=$pid comm=$comm argv_hits=${a:-?} env_hits=${e:-?} env_names=[${en:-}] argv0-2=[$head3]" >> "$OUT"
  done
  sleep 0.1
done
