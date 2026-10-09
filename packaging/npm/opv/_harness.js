'use strict';

// Shared harness for the npm install/uninstall/wrapper tests.
//
// Every test builds a throwaway package directory that looks like an installed
// `@matthew-cochran/opv`: the script under test, its `package.json`, and the
// platform package with its prebuilt binary under `node_modules`. The tests then
// run the script as a child process with a temporary `HOME`, so the canonical
// install path, the installed-by record and the PATH hint are all real.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const SRC = __dirname;

const roots = [];
process.on('exit', () => {
  for (const root of roots) {
    try {
      fs.rmSync(root, { recursive: true, force: true });
    } catch {
      // Best effort: the fixture is under the OS temp directory.
    }
  }
});

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function platformTuple() {
  return `${process.platform}-${process.arch}`;
}

// setup returns a fixture with a temporary HOME and an installed platform package.
function setup({ version = '1.2.3', binary = '#!/bin/sh\necho "opv 1.2.3"\n' } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'opv-npm-test-'));
  roots.push(root);
  const home = path.join(root, 'home');
  const pkgDir = path.join(root, 'pkg');
  fs.mkdirSync(path.join(home, '.local', 'bin'), { recursive: true });
  fs.mkdirSync(path.join(pkgDir, 'bin'), { recursive: true });

  for (const file of ['install.js', 'uninstall.js']) {
    fs.copyFileSync(path.join(SRC, file), path.join(pkgDir, file));
  }
  fs.copyFileSync(path.join(SRC, 'bin', 'opv.js'), path.join(pkgDir, 'bin', 'opv.js'));
  fs.writeFileSync(
    path.join(pkgDir, 'package.json'),
    `${JSON.stringify({ name: '@matthew-cochran/opv', version }, null, 2)}\n`,
  );

  const tuple = platformTuple();
  const platformDir = path.join(pkgDir, 'node_modules', '@matthew-cochran', `opv-${tuple}`);
  fs.mkdirSync(path.join(platformDir, 'bin'), { recursive: true });
  fs.writeFileSync(
    path.join(platformDir, 'package.json'),
    `${JSON.stringify({ name: `@matthew-cochran/opv-${tuple}`, version }, null, 2)}\n`,
  );
  const exe = process.platform === 'win32' ? 'opv.exe' : 'opv';
  fs.writeFileSync(path.join(platformDir, 'bin', exe), binary);
  fs.chmodSync(path.join(platformDir, 'bin', exe), 0o755);

  return {
    root,
    home,
    pkgDir,
    platformDir,
    tuple,
    exe,
    target: path.join(home, '.local', 'bin', exe),
    record: path.join(home, '.local', 'share', 'opv', 'installed-by'),
    hintMarker: path.join(home, '.local', 'share', 'opv', 'npm-hint-shown'),
  };
}

// run launches one of the fixture scripts with the fixture's HOME.
function run(script, { home, env = {}, args = [] }) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: path.dirname(script),
    env: { ...process.env, HOME: home, ...env },
    encoding: 'utf8',
  });
  return {
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

module.exports = { setup, run, sha256, platformTuple };
