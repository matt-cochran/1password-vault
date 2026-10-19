import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validate, type Manifest } from '../scripts/release-assets.ts';
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
