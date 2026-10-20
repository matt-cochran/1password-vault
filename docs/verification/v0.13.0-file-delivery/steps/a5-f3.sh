# A5-F3: are the bytes decoded exactly? (CRLF, NUL, 0xFE 0xFF and trailing spaces in v1.)
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F3"
a5_versions "$E/a5/f2-probe.txt" | tee "$E/a5/f3.txt"
check A5-F3 exact_bytes $(grep -q '=v1$' "$E/a5/f3.txt" && ! grep -q '=OTHER$' "$E/a5/f3.txt" && echo 1 || echo 0) "every present path holds v1 byte for byte"
