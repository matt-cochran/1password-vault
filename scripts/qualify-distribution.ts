// Execute retained release bytes on their native host, without registry or 1Password access.
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statfsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
export const platforms = {
  'linux-x64': 'x86_64-unknown-linux-musl', 'linux-arm64': 'aarch64-unknown-linux-musl',
  'darwin-x64': 'x86_64-apple-darwin', 'darwin-arm64': 'aarch64-apple-darwin',
  'win32-x64': 'x86_64-pc-windows-msvc.exe', 'win32-arm64': 'aarch64-pc-windows-msvc.exe',
};
export const checks = ['native-version', 'native-contract', 'native-help-schema-skill', 'npm-install', 'npm-binary-parity', 'npm-version', 'npm-contract', 'npm-help-schema-skill'];
// File delivery (#136, #294) is Linux-only by design: there the installed binary must deliver
// a disposable Ed25519 key into a RAM-backed private file; elsewhere it must refuse to.
// install.sh (Linux and macOS) must install the retained asset byte for byte.
export function checksFor(platform: string): string[] {
  return [...checks, platform.startsWith('linux-') ? 'native-ed25519-file-delivery' : 'native-ed25519-file-delivery-refused',
    ...(platform.startsWith('win32-') ? [] : ['install-script'])];
}
// Run the repository's install.sh against the retained dist/ served as a file:// release (its
// test-only OPV_INSTALL_BASE_URL), then check the installed bytes and version.
export function qualifyInstallScript(root: string, scratch: string, version: string, native: string, env: NodeJS.ProcessEnv): void {
  const tagDir = join(scratch, 'release', 'releases', 'download', `v${version}`); mkdirSync(tagDir, { recursive: true });
  for (const name of readdirSync(join(root, 'dist'))) copyFileSync(join(root, 'dist', name), join(tagDir, name));
  const dir = join(scratch, 'install-script-bin');
  const script = fileURLToPath(new URL('../install.sh', import.meta.url));
  const result = spawnSync('sh', [script, '--version', `v${version}`, '--dir', dir, '--no-skill'],
    { cwd: scratch, env: { ...env, OPV_INSTALL_BASE_URL: pathToFileURL(join(scratch, 'release')).href }, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error('install.sh failed against the retained release assets');
  const installed = join(dir, 'opv');
  if (hash(readFileSync(installed)) !== hash(readFileSync(native))) throw new Error('install.sh installed different bytes than the retained native asset');
  const probe = spawnSync(installed, ['--version'], { cwd: scratch, env, encoding: 'utf8', timeout: 120_000 });
  if (probe.status !== 0 || probe.stdout.trim() !== `opv ${version}`) throw new Error('install.sh-installed binary version mismatch');
}
export const hash = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
// A fresh, unencrypted OpenSSH Ed25519 private key, as `ssh-keygen -t ed25519 -N ''` writes it.
export function disposableEd25519Key(): string {
  const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  const pub = Buffer.from(jwk.x!, 'base64url'); const seed = Buffer.from(jwk.d!, 'base64url');
  const str = (b: Buffer | string) => { const v = Buffer.from(b); const n = Buffer.alloc(4); n.writeUInt32BE(v.length); return Buffer.concat([n, v]); };
  const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const publicBlob = Buffer.concat([str('ssh-ed25519'), str(pub)]);
  const check = randomBytes(4);
  let secret = Buffer.concat([check, check, str('ssh-ed25519'), str(pub), str(Buffer.concat([seed, pub])), str('opv-qualification')]);
  for (let pad = 1; secret.length % 8 !== 0; pad++) secret = Buffer.concat([secret, Buffer.from([pad])]);
  const body = Buffer.concat([Buffer.from('openssh-key-v1\0'), str('none'), str('none'), str(''), u32(1), str(publicBlob), str(secret)]).toString('base64');
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${body.match(/.{1,70}/g)!.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}
// Whether the captured output of a delivery shows any part of the key: the whole key or any
// line of its base64 body.
export function revealsKey(output: string, key: string): boolean {
  return output.includes(key) || key.split('\n').filter(line => line.length >= 16 && !line.startsWith('-----')).some(line => output.includes(line));
}
const tmpfsMagic = 0x01021994;
// The installed binary's hidden local-delivery step, driven as `opv run` drives it under
// `op run`: the resolved key travels only in the child environment, never in argv. The app it
// starts (node) compares the delivered file against a digest and prints a verdict, never bytes.
export function qualifyFileDelivery(native: string, scratch: string, platform: string): void {
  const key = disposableEd25519Key();
  const linux = platform.startsWith('linux-');
  let runtime: string | undefined;
  if (linux) {
    // A private directory on /dev/shm stands in for $XDG_RUNTIME_DIR: user-owned, 0700, tmpfs.
    // No RAM-backed directory fails qualification; it is never skipped.
    try { runtime = mkdtempSync('/dev/shm/opv-qualification-'); } catch { throw new Error('No RAM-backed directory (/dev/shm) for Ed25519 file delivery qualification'); }
    if (Number(statfsSync(runtime).type) !== tmpfsMagic) { rmSync(runtime, { recursive: true, force: true }); throw new Error('/dev/shm is not tmpfs: Ed25519 file delivery cannot qualify'); }
  }
  try {
    const app = "const fs=require('fs'),c=require('crypto'),p=require('path');const d=process.env.APP_SECRET_FILES;"
      + "if(!d){console.log(JSON.stringify({started:true}));process.exit(0)}const f=p.join(d,'ssh/signing-key');"
      + "console.log(JSON.stringify({started:true,dir:d,match:c.createHash('sha256').update(fs.readFileSync(f)).digest('hex')===process.env.EXPECTED_SHA256,mode:fs.statSync(f).mode&0o777}))";
    const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
      HOME: join(scratch, 'home'), USERPROFILE: join(scratch, 'home'), TMP: scratch, TEMP: scratch, TMPDIR: scratch,
      SIGNING_IDENTITY: key, EXPECTED_SHA256: hash(key), ...(runtime ? { XDG_RUNTIME_DIR: runtime } : {}) };
    const result = spawnSync(native, ['local-delivery', '--key', 'SIGNING_IDENTITY', '--file', 'SIGNING_IDENTITY=ssh/signing-key', '--key', 'EXPECTED_SHA256',
      '--dir-env', 'APP_SECRET_FILES', '--declared-only', '--', process.execPath, '-e', app], { cwd: scratch, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 });
    if (result.error) throw new Error('Ed25519 file delivery check could not start the installed binary');
    if (revealsKey(`${result.stdout}${result.stderr}`, key)) throw new Error('Ed25519 file delivery printed the private key');
    if (!linux) {
      // Only the RAM-folder refusal counts: any other failure is not the documented behaviour.
      if (result.status === 0 || result.stdout.includes('"started"') || !result.stderr.includes('no in-memory folder')) throw new Error(`Ed25519 file delivery was not refused for want of a RAM-backed folder on ${platform}`);
      return;
    }
    if (result.status !== 0) throw new Error('Ed25519 file delivery failed on a RAM-backed directory');
    const verdict = JSON.parse(result.stdout.trim().split('\n').pop() ?? '{}');
    if (verdict.match !== true) throw new Error('Delivered Ed25519 key file bytes differ from the resolved key');
    if (typeof verdict.mode !== 'number' || (verdict.mode & 0o077) !== 0) throw new Error('Delivered Ed25519 key file is readable by group or others');
    if (typeof verdict.dir !== 'string' || !verdict.dir.startsWith(runtime!) || existsSync(verdict.dir)) throw new Error('Ed25519 delivery directory outside the RAM-backed directory or left behind');
  } finally { if (runtime) rmSync(runtime, { recursive: true, force: true }); }
}
export type Qualification = { schema: 1; platform: string; version: string; source_sha: string; tree: string; run_id: number; run_attempt: number; input_sha256: string; binary_sha256: string; checks: string[] };
export function validateQualification(q: Qualification, input: any, platform: string): void {
  if (q.schema !== 1 || q.platform !== platform || q.version !== input.version || q.source_sha !== input.source_sha || q.tree !== input.tree
      || q.run_id !== input.run_id || q.run_attempt !== input.run_attempt || q.input_sha256 !== hash(JSON.stringify(input))
      || q.binary_sha256 !== input.files[`dist/opv-${platforms[platform as keyof typeof platforms]}`]
      || JSON.stringify(q.checks) !== JSON.stringify(checksFor(platform))) throw new Error('Distribution qualification binding or required checks mismatch');
}
export function validateNpmMetadata(main: any, native: any, version: string, platform: string): void {
  const expected = Object.fromEntries(Object.keys(platforms).map(p => [`@matthew-cochran/opv-${p}`, version]));
  if (main.name !== '@matthew-cochran/opv' || main.version !== version
      || native.name !== `@matthew-cochran/opv-${platform}` || native.version !== version
      || JSON.stringify(Object.entries(main.optionalDependencies ?? {}).sort()) !== JSON.stringify(Object.entries(expected).sort())
      || JSON.stringify(native.os) !== JSON.stringify([platform.split('-')[0]])
      || JSON.stringify(native.cpu) !== JSON.stringify([platform.split('-')[1]])) throw new Error('Candidate npm package metadata/dependency version mismatch');
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
      if (result.error || result.status !== 0) throw new Error(`Distribution check failed: ${args.filter(arg => !arg.startsWith(scratch)).join(' ')}`);
      return result.stdout.trim();
    };
    writeFileSync(join(scratch, 'secrets.toml'), `[environments.dev]\nboundaries.app = {}\n[environments.dev.targets.github-fixture]\nproducts = ["app"]\ngithub.repo = "example-org/app"\ngithub.environment = "fixture"\n[products.app.local]\nsecrets_dir_env = "APP_SECRET_FILES"\n[products.app.keys.AGE_IDENTITY]\nkind = "secret"\nsource = "generated"\nrules = { age_identity = true }\n[products.app.keys.SIGNING_IDENTITY]\nkind = "secret"\nsource = "generated"\nfile = "signing-key"\nrules = { ssh_ed25519 = true }\n`);
    writeFileSync(join(scratch, 'secrets.bindings.toml'), 'environments.dev.boundaries.app.vault_id = "fixture-vault"\nenvironments.dev.boundaries.app.item_id = "fixture-item"\n');
    const native = join(scratch, process.platform === 'win32' ? 'opv.exe' : 'opv');
    const source = join(root, `dist/opv-${platforms[platform]}`); copyFileSync(source, native); chmodSync(native, 0o755);
    const probe = (exe: string, prefix: string[], scope: string) => {
      const call = (args: string[]) => execute(exe, [...prefix, '--config', join(scratch, 'secrets.toml'), ...args]);
      if (call(['--version']) !== `opv ${input.version}`) throw new Error(`${scope} version mismatch`);
      const contract = JSON.parse(call(['contract', '--json']));
      if (!JSON.stringify(contract).includes('SIGNING_IDENTITY') || !JSON.stringify(contract).includes('AGE_IDENTITY')) throw new Error('Generated contract capabilities missing');
      const github = JSON.parse(call(['explain', '--target', 'github-fixture', '--env', 'dev', '--json']));
      if (github.file_delivery?.channel !== 'secret_api' || github.file_delivery?.utf8_verbatim !== true || github.file_delivery?.filesystem !== false) throw new Error('Native GitHub UTF-8 API-secret file capability missing');
      const help = call(['propose', 'generate', '--help']);
      const schema = call(['schema']); const guide = call(['guide', 'agent']);
      for (const token of ['age_identity', 'ssh_ed25519']) for (const [surface, text] of Object.entries({ help, schema, guide })) if (!text.includes(token)) throw new Error(`Missing ${token} in ${scope} ${surface}`);
      const project = join(scratch, scope); mkdirSync(project);
      call(['skill', 'install', '--project', project, '--target', 'codex']);
      const skill = readFileSync(join(project, '.agents/skills/opv/SKILL.md'), 'utf8');
      if (!skill.includes(`opv-skill ${input.version} sha256:`) || !skill.includes('ssh_ed25519')) throw new Error('Installed skill version/capability mismatch');
      return { schema, guide, skill };
    };
    const nativeResults = probe(native, [], 'native');
    qualifyFileDelivery(native, scratch, platform);
    if (!platform.startsWith('win32-')) qualifyInstallScript(root, scratch, input.version, native, env);
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
    execute(process.execPath, [npmEntry, 'install', '--global', '--prefix', npmPrefix, '--offline', '--no-audit', '--no-fund', ...[...platformTarball, ...mainTarball].map(p => join(root, 'npm', p))]);
    const npmRoot = join(npmPrefix, process.platform === 'win32' ? 'node_modules' : 'lib/node_modules', '@matthew-cochran');
    validateNpmMetadata(JSON.parse(readFileSync(join(npmRoot, 'opv/package.json'), 'utf8')),
      JSON.parse(readFileSync(join(npmRoot, `opv-${platform}/package.json`), 'utf8')), input.version, platform);
    const installedBinary = join(npmRoot, `opv-${platform}`, 'bin', process.platform === 'win32' ? 'opv.exe' : 'opv');
    if (hash(readFileSync(installedBinary)) !== hash(readFileSync(native))) throw new Error('Installed npm binary differs from retained native asset');
    const canonical = process.platform === 'win32' ? join(home, 'AppData/Local/Programs/opv/opv.exe') : join(home, '.local/bin/opv');
    if (hash(readFileSync(canonical)) !== hash(readFileSync(native))) throw new Error('Global npm postinstall did not preserve exact candidate binary bytes');
    env.npm_config_global = 'true';
    const npmResults = probe(process.execPath, [join(npmRoot, 'opv/bin/opv.js')], 'npm');
    if (JSON.stringify(nativeResults) !== JSON.stringify(npmResults)) throw new Error('Native/npm embedded capability parity mismatch');
    const result: Qualification = { schema: 1, platform, version: input.version, source_sha: input.source_sha, tree: input.tree,
      run_id: input.run_id, run_attempt: input.run_attempt, input_sha256: hash(JSON.stringify(input)), binary_sha256: hash(readFileSync(native)), checks: checksFor(platform) };
    validateQualification(result, input, platform);
    mkdirSync(join(root, 'qualification'), { recursive: true });
    writeFileSync(join(root, 'qualification', `${platform}.json`), `${JSON.stringify(result)}\n`, { flag: 'wx' });
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { qualify(process.argv[2]); } catch (error) { console.error(error instanceof Error ? error.message : 'Distribution qualification failed'); process.exit(1); }
}
