# A5-F4 (by proxy): when does a changed secret reach the file? `fly secrets deploy` is NOT
# run: it would restart the running fleet. Instead, on machine A only: stage v2, then
# (a) nothing, (b) machine restart, (c) machine update with the same --file-secret flags.
# LIVE WRITE: re-stages OPVCANARY_A5_FILE; restarts/updates machine A only. Rollback: T1, T2.
source "$(dirname "$0")/lib.sh"; guard_app
id=$(head -1 "$S/a5/machines")
say "A5-F4 stage v2"
flysafe secrets import --stage < "$CANARY/a5/import-v2"
probe "$id" f4a-no-action;  a5_versions "$E/a5/f4a-no-action.txt" | tee "$E/a5/f4a.txt"
say "A5-F4 restart machine A"
flysafe machine restart "$id"
sleep 10; probe "$id" f4b-restart; a5_versions "$E/a5/f4b-restart.txt" | tee "$E/a5/f4b.txt"
say "A5-F4 update machine A with the same file flags"
mapfile -t fs < <(a5_file_secret_flags)
flysafe machine update "$id" "${fs[@]}" --skip-health-checks -y
sleep 10; probe "$id" f4c-update; a5_versions "$E/a5/f4c-update.txt" | tee "$E/a5/f4c.txt"
echo "RECORD A5-F4: which of (a) none, (b) restart, (c) update moved the file to v2. [UNSURE: all three; a literal secrets-deploy answer needs a separate owner decision]"
