'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { setup, run, sha256 } = require('./_harness.js');
const { registerSkill, globalRoot } = require('./install.js');

const unix = { skip: process.platform === 'win32' ? 'POSIX shell fixture' : false };

// The fixture package is not under `npm root -g`, so tests of the shared-copy rules
// ask for a global install explicitly; npm sets npm_config_global for a global script.
function install(h, env = {}) {
  return run(path.join(h.pkgDir, 'install.js'), {
    home: h.home,
    env: { npm_config_global: 'true', ...env },
  });
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

test('a project-local postinstall does not create the canonical binary', unix, () => {
  const h = setup();
  install(h, { npm_config_global: 'false' });
  assert.equal(fs.existsSync(h.target), false);
});

test('a project-local postinstall leaves the canonical binary untouched', unix, () => {
  const h = setup();
  const existing = '#!/bin/sh\necho "opv 0.9.0"\n';
  fs.writeFileSync(h.target, existing);
  fs.chmodSync(h.target, 0o755);
  install(h, { npm_config_global: 'false' });
  assert.equal(fs.readFileSync(h.target, 'utf8'), existing);
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

test('install works when HOME contains a space', unix, () => {
  const h = setup();
  assert.match(h.home, / /);
  install(h);
  assert.equal(fs.existsSync(h.target), true);
});

test('install run twice leaves the same binary hash in the record', unix, () => {
  const h = setup();
  install(h);
  const first = fs.readFileSync(h.record, 'utf8');
  install(h);
  assert.equal(fs.readFileSync(h.record, 'utf8'), first);
});

test('install run twice prints nothing the second time', unix, () => {
  const h = setup();
  install(h);
  assert.equal(install(h).stdout.replace(/Add .*\n.*export PATH.*\n/, ''), '');
});

test('install leaves a foreign file in place and still exits 0', unix, () => {
  const h = setup();
  fs.writeFileSync(h.target, 'not opv\n');
  fs.chmodSync(h.target, 0o755);
  assert.equal(install(h).status, 0);
});

test('install names the next step when it leaves a foreign file alone', unix, () => {
  const h = setup();
  fs.writeFileSync(h.target, 'not opv\n');
  fs.chmodSync(h.target, 0o755);
  assert.match(
    install(h).stderr,
    /node "\$\(npm root -g\)\/@matthew-cochran\/opv\/install\.js"/,
  );
});

test('install under sudo is refused for the invoking user', () => {
  const { sudoProblem } = require('./install.js');
  assert.match(
    sudoProblem({ SUDO_USER: 'mc' }, 0),
    /without sudo: node "\$\(npm root -g\)\/@matthew-cochran\/opv\/install\.js"/,
  );
});

test('install as root without sudo is allowed', () => {
  const { sudoProblem } = require('./install.js');
  assert.equal(sudoProblem({}, 0), null);
});

test('install as a normal user with SUDO_USER set is allowed', () => {
  const { sudoProblem } = require('./install.js');
  assert.equal(sudoProblem({ SUDO_USER: 'mc' }, 1000), null);
});

test('install replaces a broken symlink at the canonical path', unix, () => {
  const h = setup();
  fs.symlinkSync(path.join(h.root, 'missing'), h.target);
  install(h);
  assert.equal(fs.lstatSync(h.target).isSymbolicLink(), false);
});

test('registerSkill runs the installed binary with the user install arguments', () => {
  const calls = [];
  registerSkill('/bin/opv', {
    env: {},
    spawn: (cmd, args) => {
      calls.push([cmd, args]);
      return { status: 0 };
    },
  });
  assert.deepEqual(calls, [
    ['/bin/opv', ['skill', 'install', '--user', '--target', 'all']],
  ]);
});

test('registerSkill does not run the binary when CI is set', () => {
  let calls = 0;
  registerSkill('/bin/opv', {
    env: { CI: 'true' },
    spawn: () => {
      calls += 1;
      return { status: 0 };
    },
  });
  assert.equal(calls, 0);
});

test('registerSkill does not run the binary when OPV_NO_SKILL is 1', () => {
  let calls = 0;
  registerSkill('/bin/opv', {
    env: { OPV_NO_SKILL: '1' },
    spawn: () => {
      calls += 1;
      return { status: 0 };
    },
  });
  assert.equal(calls, 0);
});

test('registerSkill warns on stderr and does not throw when the binary fails', () => {
  let warnings = '';
  registerSkill('/bin/opv', {
    env: {},
    spawn: () => ({ status: 1 }),
    stderr: {
      write: (message) => {
        warnings += message;
      },
    },
  });
  assert.match(warnings, /could not register the agent skill/);
});

test("the global npm root on Windows is under %APPDATA%\\npm, not node's directory", () => {
  assert.equal(
    globalRoot({ APPDATA: 'C:\\Users\\a\\AppData\\Roaming' }, 'C:\\Program Files\\nodejs\\node.exe', 'win32'),
    path.join('C:\\Users\\a\\AppData\\Roaming', 'npm', 'node_modules'),
  );
});
