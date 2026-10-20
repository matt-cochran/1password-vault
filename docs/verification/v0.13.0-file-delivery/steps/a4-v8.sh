# A4-V8 (CI-like): the consumer reads every serve file through MountedSecretStore.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V8 (waits one consumer cycle)"
sleep 40
kadmin -n jzverify logs deploy/jzverify -c journeeze --tail=16 | tee "$E/v8-consumer.txt"
check A4-V8 nine_match $([ "$(grep -c ': match$' "$E/v8-consumer.txt")" -ge 10 ] && echo 1 || echo 0) "9 files + LOG_LEVEL"
check A4-V8 result_ok $(grep -q '^result: ok' "$E/v8-consumer.txt" && echo 1 || echo 0)
