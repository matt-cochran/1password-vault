import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findRetainedCandidate, npmPublishAction, orderNpmTarballs, publishNpmTarballs, validate, waitForIntegrity, type Manifest } from '../scripts/release-assets.ts';
const repository = 'matt-cochran/1password-vault';
const tree = 'a'.repeat(40);
const actual: Record<string, string> = {};
for (const target of ['x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl', 'x86_64-apple-darwin', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc.exe', 'aarch64-pc-windows-msvc.exe']) actual[`dist/opv-${target}`] = 'd'.repeat(64);
actual['dist/opv'] = 'd'.repeat(64); actual['dist/SHA256SUMS'] = 'd'.repeat(64);
for (let n = 0; n < 7; n++) actual[`npm/package-${n}.tgz`] = 'd'.repeat(64);
const manifest: Manifest = { schema: 1, repository, workflow: 'release.yml', tree, source_sha: 'b'.repeat(40), run_id: 12, run_attempt: 2, files: actual };
const run = { id: 12, run_attempt: 2, status: 'completed', conclusion: 'success', event: 'push', head_branch: 'staging', head_sha: manifest.source_sha, path: '.github/workflows/release.yml', head_repository: { full_name: repository } };
test('an exact successful staging release qualifies', () => validate(manifest, run, repository, tree, actual));
test('main, fork and failed runs never qualify', () => {
  for (const changed of [{ ...run, head_branch: 'main' }, { ...run, conclusion: 'failure' }, { ...run, head_repository: { full_name: 'fork/opv' } }, { ...run, event: 'pull_request' }, { ...run, path: '.github/workflows/other.yml' }]) assert.throws(() => validate(manifest, changed, repository, tree, actual));
});
test('rerun attempts and complete tree identity are pinned', () => {
  assert.throws(() => validate(manifest, { ...run, run_attempt: 3 }, repository, tree, actual));
  assert.throws(() => validate(manifest, run, repository, 'c'.repeat(40), actual));
  assert.throws(() => validate({ ...manifest, source_sha: 'c'.repeat(40) }, run, repository, tree, actual));
});
test('changed or added files fail checksums', () => {
  assert.throws(() => validate(manifest, run, repository, tree, { ...actual, 'dist/opv': 'e'.repeat(64) }));
  assert.throws(() => validate(manifest, run, repository, tree, { ...actual, 'dist/extra': 'e'.repeat(64) }));
});
test('path traversal and missing targets are refused', () => {
  const traversal = { ...actual, '../escape': 'd'.repeat(64) };
  assert.throws(() => validate({ ...manifest, files: traversal }, run, repository, tree, traversal));
  const missing = { ...actual }; delete missing['dist/opv-aarch64-pc-windows-msvc.exe'];
  assert.throws(() => validate({ ...manifest, files: missing }, run, repository, tree, missing));
});
test('all seven npm tarballs are required', () => {
  const missing = { ...actual }; delete missing['npm/package-6.tgz'];
  assert.throws(() => validate({ ...manifest, files: missing }, run, repository, tree, missing));
});

const retained = `opv-release-${tree}-${run.run_attempt}`;
const retainedArtifacts = [{ name: retained, expired: false }];

test('a successful staging run retaining the current tree candidate is found', () => {
  assert.deepEqual(findRetainedCandidate([run], () => retainedArtifacts, repository, tree, 99), { run, artifact: retained });
});

test('the current run is never reused as its own candidate', () => {
  assert.equal(findRetainedCandidate([run], () => retainedArtifacts, repository, tree, run.id), undefined);
});

test('an expired retained artifact is not a candidate', () => {
  assert.equal(findRetainedCandidate([run], () => [{ name: retained, expired: true }], repository, tree, 99), undefined);
});

test('a main-branch run is not a staging candidate', () => {
  assert.equal(findRetainedCandidate([{ ...run, head_branch: 'main' }], () => retainedArtifacts, repository, tree, 99), undefined);
});

test('a fork run is not a staging candidate', () => {
  assert.equal(findRetainedCandidate([{ ...run, head_repository: { full_name: 'fork/opv' } }], () => retainedArtifacts, repository, tree, 99), undefined);
});

test('an artifact named for a different tree is not a candidate', () => {
  assert.equal(findRetainedCandidate([run], () => [{ name: `opv-release-${'c'.repeat(40)}-${run.run_attempt}`, expired: false }], repository, tree, 99), undefined);
});

const platforms = ['linux-x64', 'linux-arm64', 'darwin-x64', 'darwin-arm64', 'win32-x64', 'win32-arm64'];
function tarball(file: string, name: string) {
  return { file, path: file, name, version: '1.2.3', integrity: 'sha512-retained' };
}
function fakeClock() {
  let time = 0;
  return { now: () => time, sleep: async (milliseconds: number) => { time += milliseconds; } };
}

test('every platform tarball precedes the main package regardless of file name order', () => {
  const mainFirstByFileName = [tarball('matthew-cochran-opv-1.2.3.tgz', '@matthew-cochran/opv'),
    ...platforms.map((platform) => tarball(`matthew-cochran-opv-${platform}-1.2.3.tgz`, `@matthew-cochran/opv-${platform}`))];
  const ordered = orderNpmTarballs(mainFirstByFileName);
  assert.ok(ordered.slice(0, -1).every((pkg) => pkg.name !== '@matthew-cochran/opv') && ordered.at(-1)?.name === '@matthew-cochran/opv');
});

test('an unpublished package is published', () => {
  assert.equal(npmPublishAction(undefined, 'sha512-retained', '@matthew-cochran/opv@1.2.3'), 'publish');
});

test('an already published identical integrity is skipped', () => {
  assert.equal(npmPublishAction('sha512-retained', 'sha512-retained', '@matthew-cochran/opv@1.2.3'), 'skip');
});

test('published bytes that differ are refused', () => {
  assert.throws(() => npmPublishAction('sha512-published', 'sha512-retained', '@matthew-cochran/opv@1.2.3'), /Published npm bytes differ for @matthew-cochran\/opv@1\.2\.3/);
});

test('no registry wait happens between platform publishes', async () => {
  const events: string[] = [];
  const clock = fakeClock();
  const released = new Set<string>();
  let listed = false;
  const packages = [...platforms.map((platform) => tarball(`opv-${platform}.tgz`, `@matthew-cochran/opv-${platform}`)),
    tarball('opv-main.tgz', '@matthew-cochran/opv')];
  await publishNpmTarballs(packages, {
    integrity: async (pkg) => (listed && released.has(pkg.name) ? pkg.integrity : undefined),
    publish: async (pkg) => { released.add(pkg.name); events.push(`publish:${pkg.name}`); },
    now: clock.now,
    sleep: async (milliseconds) => { events.push('sleep'); listed = true; await clock.sleep(milliseconds); },
  });
  const firstWait = events.indexOf('sleep');
  assert.ok(firstWait > 0 && events.slice(0, firstWait).every((event) => event.startsWith('publish:@matthew-cochran/opv-')));
});

test('the registry wait resolves once npm lists the retained integrity', async () => {
  const clock = fakeClock();
  const pkg = tarball('opv-linux-x64.tgz', '@matthew-cochran/opv-linux-x64');
  let listed: string | undefined;
  await assert.doesNotReject(waitForIntegrity([pkg], {
    integrity: async () => listed,
    publish: async () => {},
    now: clock.now,
    sleep: async (milliseconds) => { listed = pkg.integrity; await clock.sleep(milliseconds); },
    timeoutMs: 1000,
    intervalMs: 100,
  }));
});

test('the registry wait refuses an integrity that differs from the retained bytes', async () => {
  const clock = fakeClock();
  const pkg = tarball('opv-linux-x64.tgz', '@matthew-cochran/opv-linux-x64');
  await assert.rejects(waitForIntegrity([pkg], {
    integrity: async () => 'sha512-published',
    publish: async () => {},
    now: clock.now,
    sleep: clock.sleep,
    timeoutMs: 1000,
    intervalMs: 100,
  }), /Published npm bytes differ for @matthew-cochran\/opv-linux-x64@1\.2\.3/);
});

test('a duplicate-publish refusal for an unlisted version waits instead of failing', async () => {
  const clock = fakeClock();
  const pkg = tarball('opv-linux-x64.tgz', '@matthew-cochran/opv-linux-x64');
  let listed: string | undefined;
  const refusal = Object.assign(new Error('npm error code E403'), { code: 'E403' });
  await assert.doesNotReject(publishNpmTarballs([pkg], {
    integrity: async () => listed,
    publish: async () => { throw refusal; },
    now: clock.now,
    sleep: async (milliseconds) => { listed = pkg.integrity; await clock.sleep(milliseconds); },
    timeoutMs: 1000,
    intervalMs: 100,
  }));
});

test('a registry wait timeout names the packages and says re-running the job is safe', async () => {
  const clock = fakeClock();
  const pkg = tarball('opv-darwin-arm64.tgz', '@matthew-cochran/opv-darwin-arm64');
  await assert.rejects(waitForIntegrity([pkg], {
    integrity: async () => undefined,
    publish: async () => {},
    now: clock.now,
    sleep: clock.sleep,
    timeoutMs: 500,
    intervalMs: 100,
  }), /npm did not list @matthew-cochran\/opv-darwin-arm64@1\.2\.3 within 500ms; the job is safe to re-run/);
});
