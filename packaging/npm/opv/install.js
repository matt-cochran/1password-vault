#!/usr/bin/env node
'use strict';

// npm postinstall for @matthew-cochran/opv.
//
// npm has already verified the integrity of the platform package, so the binary is
// copied from there to the one canonical location both npm and install.sh share:
//
//   ~/.local/bin/opv                              (Linux, macOS, WSL)
//   %LOCALAPPDATA%\Programs\opv\opv.exe           (Windows)
//
// The copy is atomic (a temporary file in the destination directory, then rename) so
// an interrupted install never leaves a broken `opv`. The script records what it
// installed in ~/.local/share/opv/installed-by (`npm <version> <sha256>`) so
// uninstall.js can tell its own binary from one another method placed there.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

function isWindows(platform = process.platform) {
  return platform === 'win32';
}

// The one canonical install location (Task I). install.sh uses the same Unix path.
function canonicalPath(platform = process.platform) {
  if (isWindows(platform)) {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'Programs', 'opv', 'opv.exe');
  }
  return path.join(os.homedir(), '.local', 'bin', 'opv');
}

// The shared metadata directory: what installed the binary, and its hash.
function dataDir() {
  return path.join(os.homedir(), '.local', 'share', 'opv');
}

function recordPath() {
  return path.join(dataDir(), 'installed-by');
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function hashOrNull(file) {
  try {
    return sha256File(file);
  } catch {
    return null;
  }
}

// The `installed-by` record: `npm 1.2.3 <sha256>` or `install.sh 1.2.3 <sha256>`.
function readRecord() {
  try {
    const [manager, version, sha] = fs
      .readFileSync(recordPath(), 'utf8')
      .trim()
      .split(/\s+/);
    if (!manager || !version || !sha) return null;
    return { manager, version, sha };
  } catch {
    return null;
  }
}

// The installed platform package (e.g. @matthew-cochran/opv-linux-x64), with npm's
// integrity already verified.
function platformPackageDir() {
  const tuple = `${process.platform}-${process.arch}`;
  const pkg = `@matthew-cochran/opv-${tuple}`;
  return path.dirname(require.resolve(`${pkg}/package.json`));
}

function bundledBinary() {
  const exe = isWindows() ? 'opv.exe' : 'opv';
  return path.join(platformPackageDir(), 'bin', exe);
}

// The version a file reports (`opv 1.2.3` -> `1.2.3`), or `null` when it cannot run.
function versionOf(file) {
  const result = spawnSync(file, ['--version'], { encoding: 'utf8' });
  if (result.error || result.status !== 0) return null;
  return (result.stdout || '').trim().split(/\s+/).pop() || null;
}

// A file is an opv binary when `--version` prints `opv ...` (brief). This is what lets
// npm replace a copy install.sh wrote without clobbering an unrelated file.
function isOpvBinary(file) {
  const result = spawnSync(file, ['--version'], { encoding: 'utf8' });
  return (
    !result.error && result.status === 0 && /^opv\s+/.test((result.stdout || '').trim())
  );
}

function printPathHint(dir) {
  const entries = (process.env.PATH || '').split(path.delimiter);
  if (entries.includes(dir)) return;
  process.stdout.write(`Add ${dir} to your PATH:\n`);
  process.stdout.write(`  export PATH="${dir}:$PATH"\n`);
}

function install() {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  const version = pkg.version;
  const target = canonicalPath();
  const dir = path.dirname(target);

  let oldVersion = null;
  if (fs.existsSync(target)) {
    const record = readRecord();
    const ours = record !== null && hashOrNull(target) === record.sha;
    if (!ours && !isOpvBinary(target)) {
      throw new Error(`refusing to overwrite ${target}: it is not an opv binary`);
    }
    oldVersion = versionOf(target);
  }

  fs.mkdirSync(dir, { recursive: true });
  const source = bundledBinary();
  const tmp = path.join(dir, `.opv.tmp.${process.pid}`);
  try {
    fs.copyFileSync(source, tmp);
    fs.chmodSync(tmp, 0o755);
    fs.renameSync(tmp, target);
  } catch (e) {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      // Best effort: the rename failed, so the temporary file may remain.
    }
    throw e;
  }

  const hash = sha256File(target);
  fs.mkdirSync(dataDir(), { recursive: true });
  fs.writeFileSync(recordPath(), `npm ${version} ${hash}\n`);

  if (oldVersion && oldVersion !== version) {
    process.stdout.write(`opv ${oldVersion} → ${version}\n`);
  } else if (!oldVersion) {
    process.stdout.write(`installed opv ${version}\n`);
  }
  printPathHint(dir);
}

if (require.main === module) {
  try {
    install();
  } catch (e) {
    process.stderr.write(`opv: ${e.message}\n`);
    process.exit(1);
  }
}

module.exports = {
  canonicalPath,
  dataDir,
  recordPath,
  sha256File,
  readRecord,
  bundledBinary,
  versionOf,
  isOpvBinary,
  install,
  printPathHint,
};
