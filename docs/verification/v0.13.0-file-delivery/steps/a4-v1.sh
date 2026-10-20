# A4-V1: the release artifact. Reads GitHub only.
source "$(dirname "$0")/lib.sh"
mkdir -p "$S/rel" && cd "$S/rel"
say "A4-V1"
run gh release download v0.13.0 -R matt-cochran/1password-vault --clobber; ls -1
run sha256sum -c SHA256SUMS; ok_sum=$?
ok_att=1
for f in opv opv-x86_64-unknown-linux-musl; do
  run gh attestation verify "$f" -R matt-cochran/1password-vault || ok_att=0
done
chmod +x opv opv-*
v=$(HOME="$S/cihome" "$OPV" --version); echo "$v"
run "$OPV" mcp serve --help >/dev/null
echo "sha256 opv: $(sha256sum opv | cut -d' ' -f1)"
check A4-V1 checksums $([ $ok_sum = 0 ] && echo 1 || echo 0)
check A4-V1 attestation $ok_att
check A4-V1 version $([ "$v" = "opv 0.13.0" ] && echo 1 || echo 0) "$v"
