#!/usr/bin/env node
'use strict';

// npm preuninstall for @matthew-cochran/opv.
//
// The canonical binary is removed only when its sha256 matches the `installed-by`
// record this package wrote at postinstall time. A copy another method installed (or a
// file a user replaced) is left alone, so uninstalling npm never deletes an opv that
// install.sh owns.

const fs = require('node:fs');

const {
  canonicalPath,
  readRecord,
  recordPath,
  sha256File,
} = require('./install.js');

function uninstall() {
  const target = canonicalPath();
  if (!fs.existsSync(target)) return;

  const record = readRecord();
  if (record === null) return;

  let hash;
  try {
    hash = sha256File(target);
  } catch {
    return;
  }
  if (hash !== record.sha) return;

  fs.rmSync(target, { force: true });
  fs.rmSync(recordPath(), { force: true });
}

if (require.main === module) {
  try {
    uninstall();
  } catch (e) {
    process.stderr.write(`opv: ${e.message}\n`);
    process.exit(1);
  }
}

module.exports = { uninstall };
