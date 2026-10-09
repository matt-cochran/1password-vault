'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { setup, run, sha256 } = require('./_harness.js');

const unix = { skip: process.platform === 'win32' ? 'POSIX shell fixture' : false };

function uninstall(h) {
  return run(path.join(h.pkgDir, 'uninstall.js'), { home: h.home });
}

function installThen(h) {
  run(path.join(h.pkgDir, 'install.js'), { home: h.home });
}

test('uninstall removes a binary whose sha256 matches the installed-by record', unix, () => {
  const h = setup();
  installThen(h);
  uninstall(h);
  assert.equal(fs.existsSync(h.target), false);
});

test('uninstall keeps a binary whose sha256 does not match the record', unix, () => {
  const h = setup();
  installThen(h);
  fs.writeFileSync(h.record, `npm 1.2.3 ${'0'.repeat(64)}\n`);
  uninstall(h);
  assert.equal(fs.existsSync(h.target), true);
});

test('uninstall keeps a binary when there is no installed-by record', unix, () => {
  const h = setup();
  installThen(h);
  fs.rmSync(h.record, { force: true });
  uninstall(h);
  assert.equal(fs.existsSync(h.target), true);
});

test('uninstall removes the installed-by record with the binary', unix, () => {
  const h = setup();
  installThen(h);
  uninstall(h);
  assert.equal(fs.existsSync(h.record), false);
});

void sha256;
