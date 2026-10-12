#!/usr/bin/env node
// Assemble the npm packages for opv from release assets.
//
// Usage:
//   node scripts/npm/build.mjs --version X.Y.Z --assets <dir> --out <dir>
//
// Writes:
//   <out>/opv/                    the main "@matthew-cochran/opv" package (shim + README)
//   <out>/@matthew-cochran/opv-<platform>/  one package per platform, carrying the binary
//
// No dependencies: only Node's standard library.

import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..', '..');

// Rust target triple -> npm platform tuple.
const TARGETS = [
  { target: 'x86_64-unknown-linux-musl', platform: 'linux-x64', os: 'linux', cpu: 'x64', exe: false },
  { target: 'aarch64-unknown-linux-musl', platform: 'linux-arm64', os: 'linux', cpu: 'arm64', exe: false },
  { target: 'x86_64-apple-darwin', platform: 'darwin-x64', os: 'darwin', cpu: 'x64', exe: false },
  { target: 'aarch64-apple-darwin', platform: 'darwin-arm64', os: 'darwin', cpu: 'arm64', exe: false },
  { target: 'x86_64-pc-windows-msvc', platform: 'win32-x64', os: 'win32', cpu: 'x64', exe: true },
  { target: 'aarch64-pc-windows-msvc', platform: 'win32-arm64', os: 'win32', cpu: 'arm64', exe: true },
];

const SEMVER = /^\d+\.\d+\.\d+$/;

function fail(message) {
  console.error(`opv npm build: ${message}`);
  process.exit(1);
}

function usage(message) {
  if (message) console.error(`opv npm build: ${message}`);
  console.error('usage: node scripts/npm/build.mjs --version X.Y.Z --assets <dir> --out <dir>');
  process.exit(1);
}

function parseArgs(argv) {
  const known = new Set(['--version', '--assets', '--out']);
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!known.has(arg)) usage(`unknown argument: ${arg}`);
    const value = argv[i + 1];
    if (value === undefined) usage(`missing value for ${arg}`);
    args[arg.slice(2)] = value;
    i += 1;
  }
  return args;
}

function writeJson(file, value) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

const args = parseArgs(process.argv.slice(2));

const version = args.version;
if (version === undefined) usage('--version is required');
if (!SEMVER.test(version)) {
  fail(`--version must be X.Y.Z, got "${version}"`);
}

const assetsDir = args.assets;
if (assetsDir === undefined) usage('--assets is required');
const outDir = args.out;
if (outDir === undefined) usage('--out is required');

if (!existsSync(assetsDir) || !statSync(assetsDir).isDirectory()) {
  fail(`--assets directory does not exist: ${assetsDir}`);
}

const opvPackageDir = join(repoRoot, 'packaging', 'npm', 'opv');
const platformTemplate = join(repoRoot, 'packaging', 'npm', 'platform', 'package.json');

for (const entry of TARGETS) {
  const assetName = `opv-${entry.target}${entry.exe ? '.exe' : ''}`;
  const assetPath = join(assetsDir, assetName);
  if (!existsSync(assetPath)) {
    fail(`missing release asset ${assetName} in ${assetsDir}`);
  }
}

// Main "@matthew-cochran/opv" package: shim, README and the per-platform optional deps.
const mainPackage = JSON.parse(readFileSync(join(opvPackageDir, 'package.json'), 'utf8'));
mainPackage.version = version;
mainPackage.optionalDependencies = Object.fromEntries(
  TARGETS.map((entry) => [`@matthew-cochran/opv-${entry.platform}`, version]),
);
writeJson(join(outDir, 'opv', 'package.json'), mainPackage);

const mainBinDir = join(outDir, 'opv', 'bin');
mkdirSync(mainBinDir, { recursive: true });
const shim = join(mainBinDir, 'opv.js');
copyFileSync(join(opvPackageDir, 'bin', 'opv.js'), shim);
chmodSync(shim, 0o755);
copyFileSync(join(opvPackageDir, 'README.md'), join(outDir, 'opv', 'README.md'));

// The postinstall/preuninstall scripts are part of the published main package, so
// they ship next to `bin/` and the shim can require them (`../install.js`).
for (const script of ['install.js', 'uninstall.js']) {
  const destination = join(outDir, 'opv', script);
  copyFileSync(join(opvPackageDir, script), destination);
  chmodSync(destination, 0o755);
}

// One package per platform, each carrying its prebuilt binary.
const platformPackage = JSON.parse(readFileSync(platformTemplate, 'utf8'));
for (const entry of TARGETS) {
  const pkgDir = join(outDir, '@matthew-cochran', `opv-${entry.platform}`);
  const pkg = {
    ...platformPackage,
    name: `@matthew-cochran/opv-${entry.platform}`,
    version,
    os: [entry.os],
    cpu: [entry.cpu],
  };
  writeJson(join(pkgDir, 'package.json'), pkg);

  const exeName = entry.exe ? 'opv.exe' : 'opv';
  const binDir = join(pkgDir, 'bin');
  mkdirSync(binDir, { recursive: true });
  const destination = join(binDir, exeName);
  copyFileSync(join(assetsDir, `opv-${entry.target}${entry.exe ? '.exe' : ''}`), destination);
  chmodSync(destination, 0o755);
}

console.log(`opv npm build: wrote npm-dist for opv ${version} to ${outDir}`);
