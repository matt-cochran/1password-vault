'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { setup, run, sha256 } = require('./_harness.js');

const unix = { skip: process.platform === 'win32' ? 'POSIX shell fixture' : false };

function install(h, env = {}) {
  return run(path.join(h.pkgDir, 'install.js'), { home: h.home, env });
}

test('install copies the platform binary to the canonical path', unix, () => {
  const h = setup({ binary: '#!/bin/sh\necho "opv 1.2.3"\n' });
  install(h);
  assert.equal(fs.readFileSync(h.target, 'utf8'), '#!/bin/sh\necho "opv 1.2.3"\n');
});

test('install sets mode 755 on the installed binary', unix, () => {
  const h = setup();
  install(h);
  assert.equal(fs.statSync(h.target).mode & 0o777, 0o755);
});

test('install writes the npm installed-by record with version and sha256', unix, () => {
  const binary = '#!/bin/sh\necho "opv 1.2.3"\n';
  const h = setup({ binary });
  install(h);
  assert.equal(
    fs.readFileSync(h.record, 'utf8').trim(),
    `npm 1.2.3 ${sha256(Buffer.from(binary))}`,
  );
});

test('install prints opv old to new when replacing an opv binary', unix, () => {
  const h = setup();
  fs.writeFileSync(h.target, '#!/bin/sh\necho "opv 1.0.0"\n');
  fs.chmodSync(h.target, 0o755);
  const { stdout } = install(h);
  assert.match(stdout, /opv 1\.0\.0 → 1\.2\.3/);
});

test('install refuses to overwrite a non-opv file', unix, () => {
  const foreign = 'not an opv binary\n';
  const h = setup();
  fs.writeFileSync(h.target, foreign);
  fs.chmodSync(h.target, 0o755);
  install(h);
  assert.equal(fs.readFileSync(h.target, 'utf8'), foreign);
});

test('install overwrites an opv binary it did not write', unix, () => {
  const h = setup();
  fs.writeFileSync(h.target, '#!/bin/sh\necho "opv 0.9.0"\n');
  fs.chmodSync(h.target, 0o755);
  install(h);
  assert.match(fs.readFileSync(h.target, 'utf8'), /opv 1\.2\.3/);
});

test('install prints the export PATH line when the directory is off PATH', unix, () => {
  const h = setup();
  const { stdout } = install(h, { PATH: '/nonexistent-dir' });
  assert.match(stdout, /export PATH=/);
});

test('install leaves no temporary file behind', unix, () => {
  const h = setup();
  install(h);
  const leftovers = fs
    .readdirSync(path.dirname(h.target))
    .filter((name) => name.startsWith('.opv.tmp'));
  assert.deepEqual(leftovers, []);
});
