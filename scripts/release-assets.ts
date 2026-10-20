import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

type Run = { id: number; run_attempt: number; status: string; conclusion: string; event: string; head_branch: string; head_sha: string; path: string; head_repository: { full_name: string } };
export type Manifest = { schema: 1; repository: string; workflow: 'release.yml'; tree: string; source_sha: string; run_id: number; run_attempt: number; files: Record<string, string> };
const sha = /^[a-f0-9]{40}$/;
const digest = /^[a-f0-9]{64}$/;
const targets = ['x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl', 'x86_64-apple-darwin', 'aarch64-apple-darwin', 'x86_64-pc-windows-msvc.exe', 'aarch64-pc-windows-msvc.exe'];
function command(args: string[]): string { return execFileSync(args[0], args.slice(1), { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).trim(); }
function api(path: string): any { return JSON.parse(command(['gh', 'api', path])); }
function files(root: string, dir = root): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of readdirSync(dir).sort()) {
    const file = join(dir, name);
    const stat = lstatSync(file);
    if (stat.isSymbolicLink()) throw new Error('Release artifacts may not contain symlinks');
    if (stat.isDirectory()) Object.assign(result, files(root, file));
    else {
      const key = relative(root, file).replaceAll('\\', '/');
      if (key === 'manifest.json') continue;
      if (!/^(dist|npm)\/[A-Za-z0-9_.-]+$/.test(key)) throw new Error('Unexpected release artifact path');
      result[key] = createHash('sha256').update(readFileSync(file)).digest('hex');
    }
  }
  return result;
}
export function validate(manifest: Manifest, run: Run, repository: string, tree: string, actual: Record<string, string>): void {
  if (run.status !== 'completed' || run.conclusion !== 'success' || run.head_repository?.full_name !== repository
      || run.path !== '.github/workflows/release.yml' || run.head_branch !== 'staging'
      || !['push', 'workflow_dispatch'].includes(run.event)) throw new Error('Untrusted staging release run');
  if (manifest.schema !== 1 || manifest.repository !== repository || manifest.workflow !== 'release.yml'
      || manifest.tree !== tree || !sha.test(tree) || manifest.source_sha !== run.head_sha || !sha.test(manifest.source_sha)
      || manifest.run_id !== run.id || manifest.run_attempt !== run.run_attempt) throw new Error('Release provenance mismatch');
  for (const [name, hash] of Object.entries(manifest.files)) {
    if (!/^(dist|npm)\/[A-Za-z0-9_.-]+$/.test(name) || !digest.test(hash)) throw new Error('Invalid release file declaration');
  }
  if (JSON.stringify(Object.entries(manifest.files).sort()) !== JSON.stringify(Object.entries(actual).sort())) throw new Error('Release artifact checksum mismatch');
  for (const target of targets) if (!manifest.files[`dist/opv-${target}`]) throw new Error('Missing platform binary');
  if (!manifest.files['dist/opv'] || !manifest.files['dist/SHA256SUMS']) throw new Error('Missing release aliases or checksums');
  if (Object.keys(manifest.files).filter(p => p.startsWith('npm/') && p.endsWith('.tgz')).length !== 7) throw new Error('Expected all seven staged npm tarballs');
}
export type RetainedCandidate = { run: Run; artifact: string };
// A successful staging run in this repository that already retained a complete candidate for
// the current tree. The current run is excluded so a staging push reuses an earlier candidate.
export function findRetainedCandidate(runs: Run[], artifactsFor: (run: Run) => { name: string; expired: boolean }[], repository: string, tree: string, selfRunId: number): RetainedCandidate | undefined {
  for (const run of runs) {
    if (run.id === selfRunId || run.head_branch !== 'staging' || run.head_repository?.full_name !== repository) continue;
    const artifact = `opv-release-${tree}-${run.run_attempt}`;
    if (artifactsFor(run).some((entry) => entry.name === artifact && !entry.expired)) return { run, artifact };
  }
  return undefined;
}
export type NpmTarball = { file: string; path: string; name: string; version: string; integrity: string };
const npmMainPackage = '@matthew-cochran/opv';
// Platform packages must be published before the main package that depends on them.
export function orderNpmTarballs<T extends { name: string }>(packages: T[]): T[] {
  const rank = (pkg: { name: string }) => Number(pkg.name === npmMainPackage);
  return [...packages].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
}
// An identical retained tarball is skipped; different published bytes are always refused.
export function npmPublishAction(existing: string | undefined, expected: string, label: string): 'publish' | 'skip' {
  if (existing === undefined) return 'publish';
  if (existing !== expected) throw new Error(`Published npm bytes differ for ${label}`);
  return 'skip';
}
function readNpmTarballs(directory: string): NpmTarball[] {
  return readdirSync(directory).filter((name) => name.endsWith('.tgz')).map((file) => {
    const path = join(directory, file);
    const metadata = JSON.parse(command(['tar', '-xOf', path, 'package/package.json']));
    return { file, path, name: metadata.name, version: metadata.version, integrity: `sha512-${createHash('sha512').update(readFileSync(path)).digest('base64')}` };
  });
}
// npm can take well over 15 minutes to list a freshly published version (0.13.0's
// darwin-arm64 was published at 13:21 and listed at 13:36), so one 45-minute window
// covers every tarball in a single waiting pass after all publishes are done.
const npmListTimeoutMs = 2_700_000;
function npmLabel(pkg: NpmTarball): string { return `${pkg.name}@${pkg.version}`; }
export type NpmPublishDeps = {
  integrity: (pkg: NpmTarball) => Promise<string | undefined>;
  publish: (pkg: NpmTarball) => Promise<void>;
  now: () => number;
  sleep: (milliseconds: number) => Promise<void>;
  timeoutMs?: number;
  intervalMs?: number;
  log?: (message: string) => void;
};
function duplicatePublishRefusal(error: unknown): boolean {
  const failure = error as { code?: unknown; message?: unknown; stdout?: unknown; stderr?: unknown };
  return failure?.code === 'E403'
    || /(^|[^A-Za-z])E403([^A-Za-z]|$)/.test(String(failure?.message ?? ''))
    || /You cannot publish over/.test(`${failure?.stdout ?? ''}\n${failure?.stderr ?? ''}`);
}
// Poll the registry metadata together until every retained tarball's bytes are listed.
// A mismatch is a hard refusal; unlisted versions are retried inside one bounded window.
export async function waitForIntegrity(packages: NpmTarball[], deps: NpmPublishDeps): Promise<void> {
  const timeoutMs = deps.timeoutMs ?? npmListTimeoutMs;
  const intervalMs = deps.intervalMs ?? 5_000;
  const deadline = deps.now() + timeoutMs;
  let pending = packages;
  for (;;) {
    const unlisted: NpmTarball[] = [];
    const mismatched: NpmTarball[] = [];
    for (const pkg of pending) {
      const listed = await deps.integrity(pkg);
      if (listed === pkg.integrity) continue;
      (listed === undefined ? unlisted : mismatched).push(pkg);
    }
    if (mismatched.length > 0) throw new Error(`Published npm bytes differ for ${mismatched.map(npmLabel).join(', ')}`);
    pending = unlisted;
    if (pending.length === 0) return;
    if (deps.now() >= deadline) throw new Error(`npm did not list ${pending.map(npmLabel).join(', ')} within ${timeoutMs}ms; the job is safe to re-run`);
    await deps.sleep(intervalMs);
  }
}
// A version npm refuses to republish (E403) but has not listed yet is pending, not failed:
// wait for the listing instead of aborting the release. Returns whether a listing is owed.
async function publishNpmPackage(pkg: NpmTarball, deps: NpmPublishDeps): Promise<boolean> {
  const existing = await deps.integrity(pkg);
  if (npmPublishAction(existing, pkg.integrity, npmLabel(pkg)) === 'skip') {
    deps.log?.(`Already published identical retained bytes: ${npmLabel(pkg)}`);
    return false;
  }
  try {
    await deps.publish(pkg);
  } catch (error) {
    if (!duplicatePublishRefusal(error)) throw error;
    deps.log?.(`npm already has ${npmLabel(pkg)} but has not listed it; waiting for the registry listing`);
  }
  return true;
}
// Publish every platform package back to back, then confirm all of their bytes together;
// only then publish the main package that depends on them.
export async function publishNpmTarballs(packages: NpmTarball[], deps: NpmPublishDeps): Promise<void> {
  const ordered = orderNpmTarballs(packages);
  const platforms = ordered.filter((pkg) => pkg.name !== npmMainPackage);
  const mainPackages = ordered.filter((pkg) => pkg.name === npmMainPackage);
  const pending: NpmTarball[] = [];
  for (const pkg of platforms) if (await publishNpmPackage(pkg, deps)) pending.push(pkg);
  await waitForIntegrity(pending, deps);
  for (const pkg of mainPackages) if (await publishNpmPackage(pkg, deps)) await waitForIntegrity([pkg], deps);
}
async function lookupNpmIntegrity(pkg: NpmTarball): Promise<string | undefined> {
  try {
    return JSON.parse(command(['npm', 'view', `${pkg.name}@${pkg.version}`, 'dist.integrity', '--json']));
  } catch (error) {
    let response: any;
    try { response = JSON.parse(String((error as { stdout?: unknown }).stdout)); } catch { throw new Error(`Cannot verify existing npm release ${npmLabel(pkg)}`); }
    if (response.error?.code === 'E404') return undefined;
    throw new Error('npm lookup failed; refusing a blind publication');
  }
}
// stderr is captured (and echoed) so a duplicate-publish refusal is visible to the caller.
async function publishNpmPackageForReal(pkg: NpmTarball): Promise<void> {
  try {
    execFileSync('npm', ['publish', pkg.path, '--provenance', '--access', 'public'], { stdio: ['ignore', 'inherit', 'pipe'] });
  } catch (error) {
    process.stderr.write(String((error as { stderr?: unknown }).stderr ?? ''));
    throw error;
  }
}
function npmPublishDeps(): NpmPublishDeps {
  return {
    integrity: lookupNpmIntegrity,
    publish: publishNpmPackageForReal,
    now: () => Date.now(),
    sleep: (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)),
    log: (message: string) => console.log(message),
  };
}
function output(name: string, value: string): void { if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`); }
// Scan successful staging runs for a retained candidate of the current tree, the same way resolve does.
function retainedCandidate(repository: string, tree: string): RetainedCandidate | undefined {
  const selfRunId = Number(process.env.GITHUB_RUN_ID);
  for (let page = 1; page <= 10; page++) {
    const runs: Run[] = api(`repos/${repository}/actions/workflows/release.yml/runs?status=success&per_page=100&page=${page}`).workflow_runs;
    const candidate = findRetainedCandidate(runs, (run) => api(`repos/${repository}/actions/runs/${run.id}/artifacts?per_page=100`).artifacts, repository, tree, selfRunId);
    if (candidate) return candidate;
    if (runs.length < 100) break;
  }
  return undefined;
}
// Download a retained candidate and reapply the full trust checks before it is trusted or reused.
function materializeCandidate(root: string, repository: string, tree: string, candidate: RetainedCandidate): void {
  mkdirSync(root, { recursive: true });
  command(['gh', 'run', 'download', String(candidate.run.id), '--repo', repository, '--name', candidate.artifact, '--dir', root]);
  const manifest: Manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
  validate(manifest, candidate.run, repository, tree, files(root));
  if (api(`repos/${repository}/git/commits/${manifest.source_sha}`).tree.sha !== tree) throw new Error('Staging commit tree mismatch');
}
export async function main(): Promise<void> {
  const [mode, directory] = process.argv.slice(2);
  if (!directory) throw new Error('Usage: release-assets.ts record|check|resolve|verify|publish DIRECTORY');
  const root = resolve(directory);
  const repository = process.env.GITHUB_REPOSITORY!;
  const tree = command(['git', 'rev-parse', 'HEAD^{tree}']);
  if (!sha.test(tree)) throw new Error('Invalid source tree');
  if (mode === 'record') {
    if (process.env.GITHUB_REF !== 'refs/heads/staging') throw new Error('Release candidates are built only on staging');
    const manifest: Manifest = { schema: 1, repository, workflow: 'release.yml', tree,
      source_sha: command(['git', 'rev-parse', 'HEAD']), run_id: Number(process.env.GITHUB_RUN_ID), run_attempt: Number(process.env.GITHUB_RUN_ATTEMPT), files: files(root) };
    // Validate the record against the expected successful completion before upload.
    validate(manifest, { id: manifest.run_id, run_attempt: manifest.run_attempt, status: 'completed', conclusion: 'success', event: process.env.GITHUB_EVENT_NAME!, head_branch: 'staging', head_sha: manifest.source_sha, path: '.github/workflows/release.yml', head_repository: { full_name: repository } }, repository, tree, manifest.files);
    writeFileSync(join(root, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
    output('artifact', `opv-release-${tree}-${manifest.run_attempt}`);
    return;
  }
  if (mode === 'verify') {
    const manifest: Manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8'));
    const run: Run = api(`repos/${repository}/actions/runs/${manifest.run_id}`);
    validate(manifest, run, repository, tree, files(root));
    if (api(`repos/${repository}/git/commits/${manifest.source_sha}`).tree.sha !== tree) throw new Error('Staging commit tree mismatch');
    output('run-id', String(run.id));
    output('artifact', `opv-release-${tree}-${run.run_attempt}`);
    return;
  }
  if (mode === 'publish') {
    await publishNpmTarballs(readNpmTarballs(join(root, 'npm')), npmPublishDeps());
    return;
  }
  if (mode === 'check') {
    const candidate = retainedCandidate(repository, tree);
    // A corrupt retained candidate must fail the check rather than trigger a second candidate.
    if (candidate) materializeCandidate(root, repository, tree, candidate);
    output('found', String(candidate !== undefined));
    return;
  }
  if (mode !== 'resolve') throw new Error('Unknown release asset mode');
  if (existsSync(root)) throw new Error('Use a fresh release candidate directory');
  const candidate = retainedCandidate(repository, tree);
  if (!candidate) throw new Error('No successful retained staging release matches this complete source tree. Build and validate staging first; production never rebuilds or retests.');
  materializeCandidate(root, repository, tree, candidate);
  output('run-id', String(candidate.run.id)); output('artifact', candidate.artifact);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error: unknown) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
