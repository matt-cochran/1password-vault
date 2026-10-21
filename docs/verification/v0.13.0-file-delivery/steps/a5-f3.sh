# A5-F3: are the bytes decoded exactly? (CRLF, NUL, 0xFE 0xFF, trailing spaces in v1.)
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F3"
cat "$E/a5/f1-versions-a.txt" "$E/a5/f1-versions-b.txt" | tee "$E/a5/f3.txt"
check A5-F3 exact_bytes $(grep -q '=v1$' "$E/a5/f3.txt" && ! grep -Eq '=(OTHER|unprobed)$' "$E/a5/f3.txt" && echo 1 || echo 0) "every present path holds v1 byte for byte; an unprobed machine fails"
