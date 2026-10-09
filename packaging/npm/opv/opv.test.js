'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { setup, run } = require('./_harness.js');

const unix = { skip: process.platform === 'win32' ? 'POSIX shell fixture' : false };

function writeCanonical(h, version, marker) {
  const script = [
    '#!/bin/sh',
    `if [ "$1" = "--version" ]; then echo "opv ${version}"; exit 0; fi`,
    `printf '%s' "$*" > "${marker}"`,
    '',
  ].join('\n');
  fs.writeFileSync(h.target, script);
  fs.chmodSync(h.target, 0o755);
}

function wrapper(h, args) {
  return run(path.join(h.pkgDir, 'bin', 'opv.js'), { home: h.home, args });
}

test('wrapper runs the canonical binary when its version matches', unix, () => {
  const h = setup();
  const marker = path.join(h.root, 'canonical-ran');
  writeCanonical(h, '1.2.3', marker);
  wrapper(h, ['hello', 'world']);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello world');
});

test('wrapper falls back to the bundled binary when the canonical version differs', unix, () => {
  const h = setup();
  const marker = path.join(h.root, 'bundled-ran');
  writeCanonical(h, '9.9.9', path.join(h.root, 'canonical-ran'));
  const bundled = `#!/bin/sh\nprintf '%s' "$*" > "${marker}"\n`;
  fs.writeFileSync(
    path.join(h.platformDir, 'bin', h.exe),
    bundled,
  );
  fs.chmodSync(path.join(h.platformDir, 'bin', h.exe), 0o755);
  wrapper(h, ['hello']);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello');
});

test('wrapper prints the install hint once when scripts were ignored', unix, () => {
  const h = setup();
  const first = wrapper(h, ['one']);
  const second = wrapper(h, ['two']);
  const hits = `${first.stderr}${second.stderr}`.split('npm rebuild @matthew-cochran/opv').length - 1;
  assert.equal(hits, 1);
});
