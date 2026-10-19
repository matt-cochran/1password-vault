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
export type TarballWait = {
  fetch: (url: string) => Promise<{ status: number }>;
  now: () => number;
  sleep: (milliseconds: number) => Promise<void>;
  timeoutMs?: number;
  intervalMs?: number;
};
// Poll until the registry serves the published tarball, then stop. A bounded wall clock
// (injectable so tests never sleep) guarantees we fail rather than wait forever.
export async function waitForTarball(url: string, wait: TarballWait): Promise<void> {
  const timeoutMs = wait.timeoutMs ?? 300_000;
  const intervalMs = wait.intervalMs ?? 5_000;
  const deadline = wait.now() + timeoutMs;
  for (;;) {
    if ((await wait.fetch(url)).status === 200) return;
    if (wait.now() >= deadline) throw new Error(`npm tarball was not served within ${timeoutMs}ms: ${url}`);
    await wait.sleep(intervalMs);
  }
}
function readNpmTarballs(directory: string): NpmTarball[] {
  return readdirSync(directory).filter((name) => name.endsWith('.tgz')).map((file) => {
    const path = join(directory, file);
    const metadata = JSON.parse(command(['tar', '-xOf', path, 'package/package.json']));
    return { file, path, name: metadata.name, version: metadata.version, integrity: `sha512-${createHash('sha512').update(readFileSync(path)).digest('base64')}` };
  });
}
function registryTarballUrl(pkg: NpmTarball): string {
  const short = pkg.name.split('/').pop()!;
  return `https://registry.npmjs.org/${pkg.name}/-/${short}-${pkg.version}.tgz`;
}
async function publishNpmTarball(pkg: NpmTarball): Promise<void> {
  let existing: string | undefined;
  try {
    existing = JSON.parse(command(['npm', 'view', `${pkg.name}@${pkg.version}`, 'dist.integrity', '--json']));
  } catch (error) {
    let response: any;
    try { response = JSON.parse(String((error as { stdout?: unknown }).stdout)); } catch { throw new Error(`Cannot verify existing npm release ${pkg.name}@${pkg.version}`); }
    if (response.error?.code !== 'E404') throw new Error('npm lookup failed; refusing a blind publication');
  }
  if (npmPublishAction(existing, pkg.integrity, `${pkg.name}@${pkg.version}`) === 'skip') {
    console.log(`Already published identical retained bytes: ${pkg.name}@${pkg.version}`);
    return;
  }
  execFileSync('npm', ['publish', pkg.path, '--provenance', '--access', 'public'], { stdio: 'inherit' });
  await waitForTarball(registryTarballUrl(pkg), {
    fetch: (url: string) => fetch(url, { method: 'HEAD' }),
    now: () => Date.now(),
    sleep: (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)),
  });
  console.log(`Served ${pkg.name}@${pkg.version}`);
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
    for (const pkg of orderNpmTarballs(readNpmTarballs(join(root, 'npm')))) await publishNpmTarball(pkg);
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
