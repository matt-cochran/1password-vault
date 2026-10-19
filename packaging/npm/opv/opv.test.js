'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { setup, run, sha256 } = require('./_harness.js');

const REPAIR = 'node "$(npm root -g)/@matthew-cochran/opv/install.js"';

const unix = { skip: process.platform === 'win32' ? 'POSIX shell fixture' : false };

function writeCanonical(h, version, marker) {
  const script = [
    '#!/bin/sh',
    `if [ "$1" = "--version" ]; then echo "opv ${version}"; exit 0; fi`,
    `printf '%s' "$*" > "${marker}"`,
    '',
  ].join('\n');
  fs.writeFileSync(h.target, script);
  fs.chmodSync(h.target, 0o755);
}

// The fixture package is not under `npm root -g`, so tests of the shared-copy rules
// ask for a global install explicitly; npm sets npm_config_global for a global script.
function wrapper(h, args, env = {}) {
  return run(path.join(h.pkgDir, 'bin', 'opv.js'), {
    home: h.home,
    args,
    env: { npm_config_global: 'true', ...env },
  });
}

test('wrapper runs the canonical binary when its version matches', unix, () => {
  const h = setup();
  const marker = path.join(h.root, 'canonical-ran');
  writeCanonical(h, '1.2.3', marker);
  wrapper(h, ['hello', 'world']);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello world');
});

test('wrapper falls back to the bundled binary when the canonical version differs', unix, () => {
  const h = setup();
  const marker = path.join(h.root, 'bundled-ran');
  writeCanonical(h, '9.9.9', path.join(h.root, 'canonical-ran'));
  const bundled = `#!/bin/sh\nprintf '%s' "$*" > "${marker}"\n`;
  fs.writeFileSync(
    path.join(h.platformDir, 'bin', h.exe),
    bundled,
  );
  fs.chmodSync(path.join(h.platformDir, 'bin', h.exe), 0o755);
  wrapper(h, ['hello']);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello');
});

test('wrapper prints the hint once when another method installed an older copy', unix, () => {
  const h = setup();
  writeCanonical(h, '9.9.9', path.join(h.root, 'unused'));
  const first = wrapper(h, ['one']);
  const second = wrapper(h, ['two']);
  const hits = `${first.stderr}${second.stderr}`.split(REPAIR).length - 1;
  assert.equal(hits, 1);
});

test('wrapper passes the child exit code through', unix, () => {
  const h = setup();
  fs.writeFileSync(path.join(h.platformDir, 'bin', h.exe), '#!/bin/sh\nexit 7\n');
  fs.chmodSync(path.join(h.platformDir, 'bin', h.exe), 0o755);
  assert.equal(wrapper(h, []).status, 7);
});

test('wrapper passes arguments with spaces and quotes through unchanged', unix, () => {
  const h = setup();
  const marker = path.join(h.root, 'argv');
  writeCanonical(h, '1.2.3', marker);
  wrapper(h, ['a b', "c'd", '$HOME']);
  assert.equal(fs.readFileSync(marker, 'utf8'), "a b c'd $HOME");
});

test('wrapper hint says the canonical copy is stale when versions differ', unix, () => {
  const h = setup();
  writeCanonical(h, '9.9.9', path.join(h.root, 'unused'));
  assert.match(wrapper(h, ['x']).stderr, /is 9\.9\.9, not 1\.2\.3/);
});

// A platform binary that records its arguments in `marker` when it runs.
function writeBundled(h, marker) {
  const file = path.join(h.platformDir, 'bin', h.exe);
  fs.writeFileSync(file, `#!/bin/sh\nprintf '%s' "$*" > "${marker}"\n`);
  fs.chmodSync(file, 0o755);
}

// A canonical binary placed by `manager` for `version`, with a matching installed-by record.
function writeRecorded(h, manager, version) {
  const body = `#!/bin/sh\necho "opv ${version}"\n`;
  fs.writeFileSync(h.target, body);
  fs.chmodSync(h.target, 0o755);
  fs.mkdirSync(path.dirname(h.record), { recursive: true });
  fs.writeFileSync(h.record, `${manager} ${version} ${sha256(Buffer.from(body))}\n`);
  return body;
}

const bundledBody = '#!/bin/sh\necho "opv 1.2.3"\n';

test('the shim installs a missing canonical binary', unix, () => {
  const h = setup({ binary: bundledBody });
  wrapper(h, ['x']);
  assert.equal(fs.readFileSync(h.target, 'utf8'), bundledBody);
});

test('a project-local shim does not create the canonical binary', unix, () => {
  const h = setup({ binary: bundledBody });
  wrapper(h, ['x'], { npm_config_global: 'false' });
  assert.equal(fs.existsSync(h.target), false);
});

test('a project-local shim runs the platform package binary', unix, () => {
  const h = setup();
  const marker = path.join(h.root, 'bundled-ran');
  writeBundled(h, marker);
  writeCanonical(h, '1.2.3', path.join(h.root, 'canonical-ran'));
  wrapper(h, ['hello'], { npm_config_global: 'false' });
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello');
});

test('a project-local shim leaves an existing canonical binary unchanged', unix, () => {
  const h = setup();
  const existing = '#!/bin/sh\necho "opv 0.9.0"\n';
  fs.writeFileSync(h.target, existing);
  fs.chmodSync(h.target, 0o755);
  wrapper(h, ['x'], { npm_config_global: 'false' });
  assert.equal(fs.readFileSync(h.target, 'utf8'), existing);
});

test('a shim outside npm root -g does not create the canonical binary', unix, () => {
  const h = setup({ binary: bundledBody });
  run(path.join(h.pkgDir, 'bin', 'opv.js'), {
    home: h.home,
    args: ['x'],
    env: { npm_config_global: '', npm_config_prefix: path.join(h.root, 'global') },
  });
  assert.equal(fs.existsSync(h.target), false);
});

test('the shim records npm as the installer after a repair', unix, () => {
  const h = setup({ binary: bundledBody });
  wrapper(h, ['x']);
  assert.equal(
    fs.readFileSync(h.record, 'utf8').trim(),
    `npm 1.2.3 ${sha256(Buffer.from(bundledBody))}`,
  );
});

test('the shim replaces a binary npm installed for an older version', unix, () => {
  const h = setup({ binary: bundledBody });
  writeRecorded(h, 'npm', '1.0.0');
  wrapper(h, ['x']);
  assert.equal(fs.readFileSync(h.target, 'utf8'), bundledBody);
});

test('the shim says it updated the canonical binary', unix, () => {
  const h = setup({ binary: bundledBody });
  writeRecorded(h, 'npm', '1.0.0');
  assert.match(
    wrapper(h, ['x']).stderr,
    /^opv: updated ~\/\.local\/bin\/opv to 1\.2\.3 \(npm skipped its install script\)$/m,
  );
});

test('the shim runs the repaired canonical binary', unix, () => {
  const h = setup({ binary: bundledBody });
  writeRecorded(h, 'npm', '1.0.0');
  assert.equal(wrapper(h, ['x']).stdout, 'opv 1.2.3\n');
});

test('the shim leaves a binary another method installed', unix, () => {
  const h = setup({ binary: bundledBody });
  const body = writeRecorded(h, 'install.sh', '1.0.0');
  wrapper(h, ['x']);
  assert.equal(fs.readFileSync(h.target, 'utf8'), body);
});

test('the shim leaves a binary that no longer matches npm\'s record', unix, () => {
  const h = setup({ binary: bundledBody });
  writeRecorded(h, 'npm', '1.0.0');
  const replaced = '#!/bin/sh\necho "opv 1.1.0"\n';
  fs.writeFileSync(h.target, replaced);
  wrapper(h, ['x']);
  assert.equal(fs.readFileSync(h.target, 'utf8'), replaced);
});

test('the shim runs the platform binary when another method installed an older copy', unix, () => {
  const h = setup();
  writeRecorded(h, 'install.sh', '1.0.0');
  const marker = path.join(h.root, 'bundled-ran');
  writeBundled(h, marker);
  wrapper(h, ['hello']);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello');
});

test('the shim runs the platform binary when the canonical directory is unwritable', {
  skip: process.platform === 'win32' || process.getuid() === 0 ? 'needs a non-root POSIX user' : false,
}, () => {
  const h = setup();
  const marker = path.join(h.root, 'bundled-ran');
  writeBundled(h, marker);
  fs.chmodSync(path.dirname(h.target), 0o555);
  try {
    wrapper(h, ['hello']);
  } finally {
    fs.chmodSync(path.dirname(h.target), 0o755);
  }
  assert.equal(fs.readFileSync(marker, 'utf8'), 'hello');
});

test('the shim does not run the canonical binary to read its version when installed-by matches', unix, () => {
  const h = setup();
  const probed = path.join(h.root, 'probed');
  writeRecorded(h, 'npm', '1.2.3');
  fs.writeFileSync(
    h.target,
    `#!/bin/sh\nif [ "$1" = "--version" ]; then : > "${probed}"; fi\n`,
  );
  wrapper(h, ['x']);
  assert.equal(fs.existsSync(probed), false);
});

test('wrapper never uses a shell', () => {
  const source = fs.readFileSync(path.join(__dirname, 'bin', 'opv.js'), 'utf8');
  assert.doesNotMatch(source, /shell:\s*true|execSync|exec\(/);
});
