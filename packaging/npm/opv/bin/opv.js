#!/usr/bin/env node
'use strict';

// The npm `opv` command. It runs the canonical binary (~/.local/bin/opv) when it
// exists and reports the same version as this package, so every `opv` on PATH runs the
// same file. Otherwise it falls back to this package's bundled copy, which is what
// makes `npx @matthew-cochran/opv` and `--ignore-scripts` installs work.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const install = require('../install.js');

const SUPPORTED = [
  'linux-x64',
  'linux-arm64',
  'darwin-x64',
  'darwin-arm64',
  'win32-x64',
  'win32-arm64',
];

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
const version = pkg.version;

// Print the install hint once per home: with --ignore-scripts the canonical binary is
// never written, and every run would otherwise repeat the same line.
function printInstallHintOnce() {
  let marker;
  try {
    marker = path.join(install.dataDir(), 'npm-hint-shown');
  } catch {
    return;
  }
  if (fs.existsSync(marker)) return;
  try {
    fs.mkdirSync(install.dataDir(), { recursive: true });
    fs.writeFileSync(marker, '');
  } catch {
    // The hint is best-effort; running the bundled copy still matters more.
  }
  const where =
    process.platform === 'win32' ? '%LOCALAPPDATA%\\Programs\\opv' : '~/.local/bin';
  process.stderr.write(
    `opv is not installed at ${where}; run: npm rebuild @matthew-cochran/opv\n`,
  );
}

function bundledBinary() {
  const platform = `${process.platform}-${process.arch}`;
  const dep = `@matthew-cochran/opv-${platform}`;
  try {
    return install.bundledBinary();
  } catch {
    console.error(`opv: no prebuilt binary is available for ${platform}.`);
    console.error(`opv: expected the optional dependency ${dep} to be installed.`);
    console.error(`opv: supported platforms: ${SUPPORTED.join(', ')}`);
    console.error(
      'opv: reinstall with "npm i -g opv" on a supported platform, or use a release binary.',
    );
    process.exit(1);
  }
}

function main() {
  const target = install.canonicalPath();
  let bin = null;
  if (fs.existsSync(target) && install.versionOf(target) === version) {
    bin = target;
  } else {
    if (!fs.existsSync(target)) printInstallHintOnce();
    bin = bundledBinary();
  }

  const result = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });

  if (result.error) {
    console.error(`opv: failed to run ${bin}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.signal) {
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();
