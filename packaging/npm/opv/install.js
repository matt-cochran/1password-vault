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
// Only a global install writes the shared copy; a project-local postinstall is left to
// run the package's own binary and never touches it (or the user's skill).
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

// npm's global node_modules directory (`npm root -g`), derived without spawning npm. npm
// exposes its effective prefix to lifecycle scripts as `npm_config_prefix`; outside npm,
// the node executable's own prefix gives the default. Cheap enough to compute per call.
function globalRoot(env = process.env, execPath = process.execPath, platform = process.platform) {
  const explicit = env.npm_config_prefix || env.NPM_CONFIG_PREFIX;
  if (isWindows(platform)) {
    // npm's default global prefix on Windows is %APPDATA%\npm, not node's own directory.
    const prefix = explicit || (env.APPDATA ? path.join(env.APPDATA, 'npm') : path.dirname(execPath));
    return path.join(prefix, 'node_modules');
  }
  return path.join(explicit || path.dirname(path.dirname(execPath)), 'lib', 'node_modules');
}

// Whether this package is the global npm install. Only a global install owns the shared
// binary; a project-local install must never create or replace it. `npm_config_global`,
// which npm sets while running a script, is authoritative when present. Otherwise the
// package's own directory is compared with npm's global root; a package under a project's
// `node_modules` (or one npm names a prefix for) is project-local, while a direct
// invocation with no npm signal keeps today's install behaviour.
function isGlobalInstall(env = process.env, dir = __dirname) {
  if (env.npm_config_global === 'true') return true;
  if (env.npm_config_global === 'false') return false;
  const resolved = path.resolve(dir);
  const inNodeModules = resolved.split(path.sep).includes('node_modules');
  if (!inNodeModules && !env.npm_config_prefix) return true;
  const expected = path.join(globalRoot(env), '@matthew-cochran', 'opv');
  return resolved === path.resolve(expected);
}

// The shared metadata directory: what installed the binary, and its hash.
function dataDir() {
  if (isWindows()) {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'Programs', 'opv', 'data');
  }
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
  const result = spawnSync(file, ['--version'], { encoding: 'utf8', timeout: 10000 });
  if (result.error || result.status !== 0) return null;
  return (result.stdout || '').trim().split(/\s+/).pop() || null;
}

// A file is an opv binary when `--version` prints `opv ...` (brief). This is what lets
// npm replace a copy install.sh wrote without clobbering an unrelated file.
function isOpvBinary(file) {
  const result = spawnSync(file, ['--version'], { encoding: 'utf8', timeout: 10000 });
  return (
    !result.error && result.status === 0 && /^opv\s+/.test((result.stdout || '').trim())
  );
}

// Register the embedded agent skill unless the environment opts out or is CI: a headless
// install must stay non-interactive and leave no per-user side effects.
function shouldRegisterSkill(env = process.env) {
  return !env.CI && env.OPV_NO_SKILL !== '1';
}

// Run the just-installed binary to put the embedded skill where coding agents look, for
// this user and both agents. No shell; the child's stderr reaches ours so a real error is
// visible, but any failure only warns and never fails the npm install. `spawn`, `env` and
// `stderr` are parameters so the skip rules and arguments are unit-testable.
function registerSkill(exe, { spawn = spawnSync, env = process.env, stderr = process.stderr } = {}) {
  if (!shouldRegisterSkill(env)) return false;
  const result = spawn(exe, ['skill', 'install', '--user', '--target', 'all'], {
    stdio: ['ignore', 'ignore', 'inherit'],
    timeout: 30000,
  });
  if (result.error || result.status !== 0) {
    stderr.write(
      `opv: could not register the agent skill (run: ${exe} skill install --user)\n`,
    );
    return false;
  }
  return true;
}

function printPathHint(dir) {
  const entries = (process.env.PATH || '').split(path.delimiter);
  if (entries.includes(dir)) return;
  process.stdout.write(`Add ${dir} to your PATH:\n`);
  process.stdout.write(`  export PATH="${dir}:$PATH"\n`);
}

// Under `sudo npm i -g`, HOME may be the invoking user's, and a root-owned
// ~/.local/bin/opv would block later updates. Refuse, say why, and name the safe command.
function sudoProblem(env = process.env, uid = process.getuid ? process.getuid() : null) {
  if (uid === 0 && env.SUDO_USER) {
    return (
      `npm is running as root for ${env.SUDO_USER}, so opv was not copied to their ` +
      'home (it would become root-owned). The npm command still works. ' +
      'To install the shared copy, run without sudo: npm rebuild -g @matthew-cochran/opv --allow-scripts=@matthew-cochran/opv'
    );
  }
  return null;
}

// This package's version, from the package.json beside this file.
function packageVersion() {
  return JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')).version;
}

// Write `text` to `file` through a temporary file in the same directory and a rename, so
// a reader never sees a partial file.
function writeAtomic(file, text) {
  const tmp = `${file}.tmp.${process.pid}`;
  try {
    fs.writeFileSync(tmp, text);
    fs.renameSync(tmp, file);
  } catch (e) {
    try {
      fs.rmSync(tmp, { force: true });
    } catch {
      // Best effort: the rename failed, so the temporary file may remain.
    }
    throw e;
  }
}

// Copy the platform package's binary to the canonical path and record it as npm's
// (`npm <version> <sha256>`). Both writes are atomic, so an interrupted copy leaves the
// old binary in place. Shared by the postinstall and by the `opv` shim when npm skipped
// the postinstall. Throws when the destination cannot be written. Returns the target.
function placeCanonical(version) {
  const target = canonicalPath();
  const dir = path.dirname(target);
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
  writeAtomic(recordPath(), `npm ${version} ${hash}\n`);
  return target;
}

// The command that reruns this postinstall by hand, for npm installs that skipped it.
const REPAIR_COMMAND = 'node "$(npm root -g)/@matthew-cochran/opv/install.js"';

function install() {
  const problem = sudoProblem();
  if (problem) {
    process.stderr.write(`opv: ${problem}\n`);
    return;
  }
  if (!isGlobalInstall()) {
    // A project-local install runs its own bundled binary and must not write the shared
    // copy (or register the user's skill); the npm wrapper already falls back to it.
    return;
  }
  const version = packageVersion();
  const target = canonicalPath();
  const dir = path.dirname(target);

  let oldVersion = null;
  if (fs.existsSync(target)) {
    const record = readRecord();
    const ours = record !== null && hashOrNull(target) === record.sha;
    if (!ours && !isOpvBinary(target)) {
      throw new Error(
        `${target} is not an opv binary, so it was left untouched. The npm command still ` +
          'works. Move that file, then run: npm rebuild -g @matthew-cochran/opv --allow-scripts=@matthew-cochran/opv',
      );
    }
    oldVersion = versionOf(target);
  }

  placeCanonical(version);

  try {
    registerSkill(target);
  } catch {
    // Best effort: registering the skill never fails the install.
  }

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
    // Never fail `npm install`: the wrapper falls back to its bundled binary.
    process.stderr.write(
      `opv: could not install to the shared location (${e.message}). ` +
        'The npm command still works; fix the cause, then run: npm rebuild -g @matthew-cochran/opv --allow-scripts=@matthew-cochran/opv\n',
    );
  }
}

module.exports = {
  sudoProblem,
  canonicalPath,
  globalRoot,
  isGlobalInstall,
  dataDir,
  recordPath,
  sha256File,
  readRecord,
  bundledBinary,
  versionOf,
  isOpvBinary,
  install,
  packageVersion,
  placeCanonical,
  hashOrNull,
  REPAIR_COMMAND,
  printPathHint,
  shouldRegisterSkill,
  registerSkill,
};
