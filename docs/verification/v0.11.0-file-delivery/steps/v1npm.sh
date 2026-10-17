set -u
S=${S:?set S to a scratch directory}
echo '=== V1 addendum: the npm package, re-checked'
date -u +%H:%M:%SZ
echo '$ npm view @<npm-scope>/opv-linux-x64@0.11.0 version'
npm view @<npm-scope>/opv-linux-x64@0.11.0 version 2>&1 | head -2
rm -rf $S/npm3; mkdir -p $S/npm3
echo '$ npm install --prefix <scratch>/npm3 @<npm-scope>/opv@0.11.0'
HOME=$S/home npm install --prefix $S/npm3 --no-fund --no-audit @<npm-scope>/opv@0.11.0 2>&1 | grep -v install-scripts | tail -3
echo '$ HOME=<scratch> OPV_NO_SKILL=1 <scratch>/npm3/node_modules/.bin/opv --version'
HOME=$S/home OPV_NO_SKILL=1 $S/npm3/node_modules/.bin/opv --version 2>&1; echo "exit=$?"
echo '$ sha256 of the npm platform binary vs the release asset'
sha256sum $S/npm3/node_modules/@<npm-scope>/opv-linux-x64/bin/opv $S/rel/opv-x86_64-unknown-linux-musl | sed "s#$S#<scratch>#g"
