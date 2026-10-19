#!/usr/bin/env node
'use strict';

// The npm `opv` command. It runs the canonical binary (~/.local/bin/opv), so every `opv`
// on PATH runs the same file, and repairs that copy when npm skipped the postinstall
// (`--ignore-scripts`, or npm 12's default):
//
//   1. installed-by records this package's version and the file exists: run it. This is
//      the common case and costs one stat and one small read.
//   2. this package is project-local (not the global install): run the platform package's
//      own binary and never create or replace the shared copy.
//   3. the file is missing, or installed-by says npm placed it for another version and its
//      sha256 still matches that record: copy the platform binary there (install.js's
//      placeCanonical), say so in one stderr line, and run it.
//   4. another method placed it (installed-by absent or not npm, or the file no longer
//      matches npm's record): never overwrite it. Run it when it reports this version;
//      otherwise run the platform package's own binary and print one hint.
//
// When the copy cannot be written (an unwritable directory, or sudo for another user),
// the platform package's binary runs instead, so `opv` always works.

const fs = require('node:fs');
const os = require('node:os');
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

const version = install.packageVersion();

// `~/.local/bin/opv` rather than the full home path, as the docs name it.
function shown(file) {
  if (process.platform === 'win32') return file;
  const home = os.homedir();
  return file.startsWith(`${home}${path.sep}`) ? `~${file.slice(home.length)}` : file;
}

// Print `text` at most once per mismatch: the marker holds the last hint shown, so a run
// that repeats the same situation stays quiet, and a new mismatch is reported once.
function printHintOnce(text) {
  let marker;
  try {
    marker = path.join(install.dataDir(), 'npm-hint-shown');
  } catch {
    return;
  }
  try {
    if (fs.readFileSync(marker, 'utf8') === text) return;
  } catch {
    // No marker yet: show the hint.
  }
  try {
    fs.mkdirSync(install.dataDir(), { recursive: true });
    fs.writeFileSync(marker, text);
  } catch {
    // The hint is best-effort; running opv still matters more.
  }
  process.stderr.write(`opv: ${text}\n`);
}

function fileExists(file) {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

// Copy the platform binary to `target` (rule 2). Returns true when the copy now runs.
function repair(target) {
  const problem = install.sudoProblem();
  if (problem) return false;
  try {
    install.placeCanonical(version);
  } catch (e) {
    printHintOnce(
      `could not update ${shown(target)} to ${version} (${e.code || e.message}), so npm's ` +
        `copy ran; fix the cause, then run: ${install.REPAIR_COMMAND}`,
    );
    return false;
  }
  try {
    install.registerSkill(target);
  } catch {
    // Best effort, as in the postinstall.
  }
  process.stderr.write(
    `opv: updated ${shown(target)} to ${version} (npm skipped its install script)\n`,
  );
  return true;
}

// Which binary to run for this invocation, following the rules at the top of this file.
function choose() {
  const target = install.canonicalPath();
  const exists = fileExists(target);
  const record = install.readRecord();
  if (exists && record && record.version === version) return target;

  // Only a global npm install owns the shared copy. A project-local install runs the
  // platform package's own binary and never creates or replaces ~/.local/bin/opv.
  if (!install.isGlobalInstall()) return bundledBinary();

  const npmOwned =
    exists &&
    record !== null &&
    record.manager === 'npm' &&
    install.hashOrNull(target) === record.sha;
  if (!exists || npmOwned) {
    return repair(target) ? target : bundledBinary();
  }

  const have = install.versionOf(target);
  if (have === version) return target;
  const by = record && record.manager !== 'npm' ? record.manager : 'another method';
  printHintOnce(
    `${shown(target)} is ${have || 'an unknown version'}, not ${version} (installed by ${by}), ` +
      `so npm's copy ran; update it the way it was installed, or let npm own it: ${install.REPAIR_COMMAND}`,
  );
  return bundledBinary();
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
      'opv: reinstall with "npm i -g @matthew-cochran/opv" on a supported platform, or use a release binary.',
    );
    process.exit(1);
  }
}

function main() {
  const bin = choose();

  const result = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });

  if (result.error) {
    console.error(`opv: failed to run ${bin}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.signal) {
    // Die by the same signal so the caller sees what the child saw.
    process.kill(process.pid, result.signal);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();
