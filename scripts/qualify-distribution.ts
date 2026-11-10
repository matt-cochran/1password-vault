// Execute retained release bytes on their native host, without registry or 1Password access.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
export const platforms = {
  'linux-x64': 'x86_64-unknown-linux-musl', 'linux-arm64': 'aarch64-unknown-linux-musl',
  'darwin-x64': 'x86_64-apple-darwin', 'darwin-arm64': 'aarch64-apple-darwin',
  'win32-x64': 'x86_64-pc-windows-msvc.exe', 'win32-arm64': 'aarch64-pc-windows-msvc.exe',
};
export const checks = ['native-version', 'native-contract', 'native-help-schema-skill', 'npm-install', 'npm-binary-parity', 'npm-version', 'npm-contract', 'npm-help-schema-skill'];
export const hash = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
export type Qualification = { schema: 1; platform: string; version: string; source_sha: string; tree: string; run_id: number; run_attempt: number; input_sha256: string; binary_sha256: string; checks: string[] };
export function validateQualification(q: Qualification, input: any, platform: string): void {
  if (q.schema !== 1 || q.platform !== platform || q.version !== input.version || q.source_sha !== input.source_sha || q.tree !== input.tree
      || q.run_id !== input.run_id || q.run_attempt !== input.run_attempt || q.input_sha256 !== hash(JSON.stringify(input))
      || q.binary_sha256 !== input.files[`dist/opv-${platforms[platform as keyof typeof platforms]}`]
      || JSON.stringify(q.checks) !== JSON.stringify(checks)) throw new Error('Distribution qualification binding or required checks mismatch');
}
export function qualify(directory: string): void {
  const root = resolve(directory);
  const input = JSON.parse(readFileSync(join(root, 'input.json'), 'utf8'));
  const platform = `${process.platform}-${process.arch}` as keyof typeof platforms;
  if (!platforms[platform]) throw new Error('Unsupported qualification host');
  for (const [name, expected] of Object.entries(input.files)) {
    if (!/^(dist|npm)\/[A-Za-z0-9_.-]+$/.test(name) || hash(readFileSync(join(root, name))) !== expected) throw new Error('Input checksum mismatch');
  }
  const scratch = mkdtempSync(join(tmpdir(), 'opv-qualification-'));
  try {
    const home = join(scratch, 'home'); mkdirSync(home);
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
      HOME: home, USERPROFILE: home, TMP: scratch, TEMP: scratch, TMPDIR: scratch, CI: 'true', OPV_AGENT: '1',
      NPM_CONFIG_USERCONFIG: join(home, '.npmrc'), NPM_CONFIG_CACHE: join(scratch, 'cache'), NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false', NPM_CONFIG_OFFLINE: 'true' };
    writeFileSync(env.NPM_CONFIG_USERCONFIG!, '');
    const execute = (exe: string, args: string[]) => {
      const result = spawnSync(exe, args, { cwd: scratch, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 });
      if (result.error || result.status !== 0) throw new Error(`Distribution check failed: ${args[0] ?? 'execute'}`);
      return result.stdout.trim();
    };
    writeFileSync(join(scratch, 'secrets.toml'), `[environments.dev]\n[products.app.local]\nsecrets_dir_env = "APP_SECRET_FILES"\n[products.app.keys.AGE_IDENTITY]\nkind = "secret"\nsource = "generated"\nrules = { age_identity = true }\n[products.app.keys.SIGNING_IDENTITY]\nkind = "secret"\nsource = "generated"\nfile = "signing-key"\nrules = { ssh_ed25519 = true }\n`);
    const native = join(scratch, process.platform === 'win32' ? 'opv.exe' : 'opv');
    const source = join(root, `dist/opv-${platforms[platform]}`); copyFileSync(source, native); chmodSync(native, 0o755);
    const probe = (exe: string, prefix: string[], scope: string) => {
      const call = (args: string[]) => execute(exe, [...prefix, '--config', join(scratch, 'secrets.toml'), ...args]);
      if (call(['--version']) !== `opv ${input.version}`) throw new Error(`${scope} version mismatch`);
      const contract = JSON.parse(call(['contract', '--json']));
      if (!JSON.stringify(contract).includes('SIGNING_IDENTITY') || !JSON.stringify(contract).includes('AGE_IDENTITY')) throw new Error('Generated contract capabilities missing');
      const help = call(['propose', 'generate', '--help']);
      const schema = call(['schema']); const guide = call(['guide', 'agent']);
      for (const token of ['age_identity', 'ssh_ed25519']) if (![help, schema, guide].every(text => text.includes(token))) throw new Error('Help/schema/skill capability mismatch');
      const project = join(scratch, scope); mkdirSync(project);
      call(['skill', 'install', '--project', project, '--target', 'codex']);
      const skill = readFileSync(join(project, '.agents/skills/opv/SKILL.md'), 'utf8');
      if (!skill.includes(`opv-skill ${input.version} sha256:`) || !skill.includes('ssh_ed25519')) throw new Error('Installed skill version/capability mismatch');
      return { schema, guide, skill };
    };
    const nativeResults = probe(native, [], 'native');
    const tarballs = readdirSync(join(root, 'npm'));
    const platformTarball = tarballs.filter(p => p === `matthew-cochran-opv-${platform}-${input.version}.tgz`);
    const mainTarball = tarballs.filter(p => p === `matthew-cochran-opv-${input.version}.tgz`);
    if (platformTarball.length !== 1 || mainTarball.length !== 1) throw new Error('Exact candidate npm packages missing');
    // Both tarballs are actual npm install inputs. Offline mode forbids fetching candidate
    // versions or dependencies from a registry; unrelated optional platforms are skipped.
    const npmPrefix = join(scratch, 'npm-prefix'); mkdirSync(npmPrefix);
    const npmEntry = [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
      join(dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')].find(existsSync);
    if (!npmEntry) throw new Error('Native npm CLI is unavailable');
    execute(process.execPath, [npmEntry, 'install', '--prefix', npmPrefix, '--offline', '--no-audit', '--no-fund', ...[...platformTarball, ...mainTarball].map(p => join(root, 'npm', p))]);
    const npmRoot = join(npmPrefix, 'node_modules/@matthew-cochran');
    const installedBinary = join(npmRoot, `opv-${platform}`, 'bin', process.platform === 'win32' ? 'opv.exe' : 'opv');
    if (hash(readFileSync(installedBinary)) !== hash(readFileSync(native))) throw new Error('Installed npm binary differs from retained native asset');
    const npmResults = probe(process.execPath, [join(npmRoot, 'opv/bin/opv.js')], 'npm');
    if (JSON.stringify(nativeResults) !== JSON.stringify(npmResults)) throw new Error('Native/npm embedded capability parity mismatch');
    const result: Qualification = { schema: 1, platform, version: input.version, source_sha: input.source_sha, tree: input.tree,
      run_id: input.run_id, run_attempt: input.run_attempt, input_sha256: hash(JSON.stringify(input)), binary_sha256: hash(readFileSync(native)), checks };
    validateQualification(result, input, platform);
    mkdirSync(join(root, 'qualification'), { recursive: true });
    writeFileSync(join(root, 'qualification', `${platform}.json`), `${JSON.stringify(result)}\n`, { flag: 'wx' });
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { qualify(process.argv[2]); } catch (error) { console.error(error instanceof Error ? error.message : 'Distribution qualification failed'); process.exit(1); }
}
