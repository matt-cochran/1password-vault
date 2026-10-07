#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const SUPPORTED = [
  'linux-x64',
  'linux-arm64',
  'darwin-x64',
  'darwin-arm64',
  'win32-x64',
  'win32-arm64',
];

const platform = `${process.platform}-${process.arch}`;
const pkg = `@opv/${platform}`;

let pkgJson;
try {
  pkgJson = require.resolve(`${pkg}/package.json`);
} catch (err) {
  console.error(`opv: no prebuilt binary is available for ${platform}.`);
  console.error(`opv: expected the optional dependency ${pkg} to be installed.`);
  console.error(`opv: supported platforms: ${SUPPORTED.join(', ')}`);
  console.error(
    'opv: reinstall with "npm i -g opv" on a supported platform, or use a release binary.',
  );
  process.exit(1);
}

const pkgDir = path.dirname(pkgJson);
const bin = path.join(pkgDir, 'bin', process.platform === 'win32' ? 'opv.exe' : 'opv');

const result = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });

if (result.error) {
  console.error(`opv: failed to run ${bin}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.exit(1);
}

process.exit(result.status === null ? 1 : result.status);
