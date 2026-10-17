set -u
S=${S:?set S to a scratch directory}
cd $S/rel
echo '$ gh release download v0.11.0 -R <owner>/1password-vault'
gh release download v0.11.0 -R <owner>/1password-vault --clobber; echo "exit=$?"
ls -1
echo '$ sha256sum -c SHA256SUMS'
sha256sum -c SHA256SUMS; echo "exit=$?"
for f in opv opv-x86_64-unknown-linux-musl; do
  echo "\$ gh attestation verify $f -R <owner>/1password-vault"
  gh attestation verify "$f" -R <owner>/1password-vault 2>&1; echo "exit=$?"
done
chmod +x opv
echo '$ HOME=<scratch> OPV_NO_SKILL=1 ./opv --version'
HOME=$S/home OPV_NO_SKILL=1 ./opv --version; echo "exit=$?"
echo '$ HOME=<scratch> OPV_NO_SKILL=1 ./opv mcp serve --help >/dev/null'
HOME=$S/home OPV_NO_SKILL=1 ./opv mcp serve --help >/dev/null; echo "exit=$?"
echo '$ npm install --prefix <scratch>/npm @<npm-scope>/opv@0.11.0'
HOME=$S/home npm install --prefix $S/npm --no-fund --no-audit @<npm-scope>/opv@0.11.0 2>&1 | tail -3
echo '$ HOME=<scratch> OPV_NO_SKILL=1 <scratch>/npm/node_modules/.bin/opv --version'
HOME=$S/home OPV_NO_SKILL=1 $S/npm/node_modules/.bin/opv --version; echo "exit=$?"
echo '$ sha256 of the npm platform binary vs the release asset'
sha256sum $S/npm/node_modules/@<npm-scope>/opv-linux-x64/bin/opv* opv-x86_64-unknown-linux-musl | sed "s#$S#<scratch>#"
