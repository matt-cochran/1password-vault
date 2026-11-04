# Sealed target: read 1Password at release time, never at runtime (#271)

Status: design for the owner's review, 2026-11-04. Nothing here is built. Not yet vetted by the
DESIGN-FMECA procedure; §9 is the author's own self-vet. Branch `v0180/design`, cut from `dev` at
opv 0.17.2 (`7cc0b6dd`).

Evidence for the claims in this document:

- the code at `7cc0b6dd`, with file:line references;
- dependency probes run for this design in a scratch crate against this repository's `deny.toml`
  (cargo-deny 0.20.2, 2026-11-04), reported in §6.4;
- the issue text (#271) and the designs it builds on: `multi-cloud-targets.md` (§3 ports, §11 the
  plug-in contract), `http-target.md` (the most recent new target), `local-delivery.md`,
  `remote-delivery.md` and `delivery-receipts.md`.

## 1. Problem

A runtime that calls `opv run` (or `op`) each time a process starts, or on a drift timer, makes
1Password a live runtime dependency. A 1Password service account's request budget is per
account: 1,000 requests per 24 hours on a Families or individual account (Teams 5,000, Business
50,000, as #271 reports). In production, a self-managed host ran
`opv run <env> --product <p> -- docker run …` for every container start, plus a 5-minute
fingerprint poll per product. One day of deploys and rollbacks used up the account's budget.
Then 6 of 8 services on one environment could not start for about 20 hours, while the owner's
interactive sessions still worked.

opv's model is that 1Password is read when values **change**, not while systems run. For
platforms that have their own secret store (Fly, Key Vault, Kubernetes, GitHub, an application's
store over HTTPS), opv already works that way: `sync` writes the store once, and the platform
injects the values at start. The gap is a runtime with **no secret store of its own**: a plain
Docker host, a VM, systemd units, an on-prem box. For these, the only option today is a 1Password
identity on the runtime, and with it the request budget.

### 1.1 What the issue asks for (acceptance, #271)

1. `kind = "sealed"` is validated by `opv config check`: recipients and signers well formed,
   environments distinct.
2. Sealing does at most one 1Password read per scope (tested with a counting fake) and never
   exposes a value.
3. `unseal` rejects a bad or missing signature, the wrong environment or product, and a revision
   below the floor, all **before decrypting**.
4. `unseal --exec` and the library deliver variables or tmpfs files with zero network calls.
5. A staleness check reports by names and digests only.
6. A recipient change marks bundles stale, with a documented rotation flow.
7. Docs cover the trust boundary, per-platform bootstrap of the runtime identity, and migration
   from runtime `opv run`.

A downstream platform is building the same shape locally, so the **bundle format is a contract**
from the first release (§5).

## 2. Summary of the design

- **A sealed target is a registered provider** (`[environments.<env>.targets.<name>]` with
  `sealed.*` fields, FR-56), delivered by the ordinary `opv sync`. What `sync` writes is one file
  per product: a **sealed bundle**. It is encrypted with **age** (X25519) to the environment's
  recipients and signed with an **SSH signature** (SSHSIG, ed25519, namespace `opv-sealed`) by the
  target's signing key. Plan, status, the plan id, `--expect-plan`, `--confirm`, receipts,
  `delivery verify` and `opv changed` all work without new commands.
- **`opv unseal`** is the runtime side. It needs no configuration file, no `op`, no network and no
  1Password identity. It verifies the signature, checks scope and revision, then decrypts, and
  either prints names only or execs the app with the values. It replaces
  `opv run <env> --product <p> -- cmd` at container start.
- **Every key lives in 1Password, so vault access stays the only permission system.**
  - The signing key is the target's `deploy_credentials` item: a 1Password SSH Key item.
  - The runtime's age identity is an ordinary opv-managed secret, generated into 1Password by
    `opv generate`. It is delivered once to the runtime by an existing target or by the platform.
  - Only public keys are in the configuration.
- **Budget:**
  - Sealing one product makes the same `op` calls as a sync to any other target: one read of each
    boundary item the product needs (FR-57), plus the deploy-credential read and the state-item
    evidence. `--json` reports them as `op_calls`.
  - The runtime makes zero calls.
  - `opv changed` (two calls per vault, existing) replaces the drift poll and runs where the
    owner chooses, not on the runtime.

## 3. Configuration contract

```toml
[environments.prod.targets.box]
products = ["api", "worker"]
state_vault_id = "…"                                         # FR-58, required on every target
deploy_credentials = "op://Ops Prod/opv-sealed-prod-signer"  # 1Password SSH Key item (§6.2)

sealed.out = "sealed/prod/{product}.opv-sealed"   # relative to the configuration file
sealed.env_name = "{KEY}"                         # the delivered variable name, as other targets
sealed.recipients = [
  "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqysmtzj5f",   # prod runtime identity
]
sealed.signer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… opv-sealed-prod"
```

Differences from the issue's sketch, and why:

| Issue sketch | Here | Why |
|---|---|---|
| `[targets.<name>] kind = "sealed"` | `[environments.<env>.targets.<name>]` with `sealed.*` | FR-56: targets are per environment and a target holds one provider's `<section>.*` options. The section name is the kind. One form only (FR-60). |
| `signers = [...]` | `sealed.signer` (one, the key this target signs with) | The configuration names the key this target **signs** with, and `sync` checks the deploy credential's public key against it before writing. The set of keys a runtime **accepts** belongs to the runtime (`unseal --signers`, an `allowed_signers` file), so it can hold old and new during rotation (§7.3). |
| `delivery = "env" \| "files"` | per-key `file = "<path>"` and the product's `secrets_dir_env` (FR-62) | These already exist. The bundle records each key's destination. A second switch for the same thing would break FR-60. |
| `out = …` or stdout | `sealed.out` only | `sync` writes files atomically and records evidence about them, which stdout cannot carry. Publishing is the caller's job (§5.6). |

### 3.1 Load rules (`opv config check`; messages name the field and rule, never a value)

1. `sealed.recipients` is non-empty, and each entry parses as an age X25519 recipient (`age1…`,
   bech32). Duplicates are an error. Other recipient types (`ssh-ed25519`/`ssh-rsa` age recipients,
   plugin recipients, `age1pq…`, `age1tag…`) are refused in v1 (§6.1).
2. **Environments do not share recipients.** A recipient listed by sealed targets in two different
   environments is a configuration error (`sealed_recipient_shared`) that names both
   `<env>/<target>`. This makes "staging can't decrypt production" a load rule instead of a habit.
3. `sealed.signer` is one `ssh-ed25519` public key in OpenSSH format. RSA, ECDSA and `sk-*` keys
   are refused.
4. `sealed.out` is relative, with no `..` component and no absolute or home prefix. It contains
   `{product}` when the target delivers more than one product. After rendering, no two placements
   in the whole configuration share an output path.
5. `sealed.env_name` follows the existing template rules (FR-8, FR-30). Rendered names must match
   `^[A-Za-z_][A-Za-z0-9_]*$` and may not be `OP_*` (as for `run`, FR-35).
6. `deploy_credentials` is required. Without a signing key the target cannot write a bundle, and
   a refusal at load is better than one at sync.
7. A secret value containing a NUL byte that is delivered as a variable is a `Store::refusal`
   (`plan` shows it, `sync` refuses before writing), since no runtime can export it. File keys
   may hold any bytes.

### 3.2 Channels (the all-providers contract, `src/provider.rs:764-833`)

| Channel | Value |
|---|---|
| `secret` | `Channel::Store { label: "sealed bundle" }` |
| `config` | `Channel::Store { label: "sealed bundle" }`: config keys travel in the bundle too, because the runtime has no other channel |
| `files` | `FileCapability::Native { dir: "<secrets_dir_env> on the runtime" }`: `unseal --exec` writes them to a RAM directory (§5.5) |

The lane checks that `Channel::Store` is accepted for `config`, since every provider today uses
`RuntimeEnv`, `Variables` or `Declined` there. If it is not, the provider declares `RuntimeEnv`,
which describes the runtime equally well.

## 4. CLI

### 4.1 Sealing: `opv sync`

```sh
opv plan prod --target box [--product api]            # what would be (re)sealed, and why
opv sync prod --target box [--product api] [--confirm prod] [--json]
opv changed prod --target box                         # source items changed since the last seal? exit 10
opv delivery verify prod --product api --target box   # the bundle at sealed.out is the one recorded
```

There is **no separate `opv seal` command** (owner decision D1). Each command's sealed-target
behaviour:

| Command | Calls | Result |
|---|---|---|
| `plan`, `status` | 1Password reads as for any target; the bundle's header is read from `sealed.out` (local file, no network) | each name `same` / `would_change` / `not_delivered`, plus one whole-bundle row when the bundle is stale for a reason that is not one name's value (§5.3) |
| `sync` | the same reads, the signing-key read, evidence write | a new bundle with every desired name, written atomically, whenever anything changed (§5.3) |
| `delivery verify` | evidence read | `verified` when the bundle at `sealed.out` has the recorded revision and digest |
| `changed` | `op read` of the delivery item's `source versions` field plus `op item list` per vault (existing) | `changed` (exit 10) when a source item moved since the bundle was sealed |
| retire / prune | none | a name dropped from configuration is absent from the next bundle; nothing to remove remotely |

`--json` on `sync`, `plan`, `status` and `changed` gains `op_calls: {reads, writes}`, counted by
the runner for every `op` invocation of the command. The issue asks for this so callers can assert
a budget. It is generic: every target reports it.

### 4.2 The runtime: `opv unseal`

```sh
opv unseal <bundle> --env <env> --product <p> --signers <allowed_signers>
           [--identity-file <path> | --identity-env <VAR>]
           [--min-revision <N>] [--ratchet <path>] [--json]
           [--exec -- <command> [args…]]
opv unseal <bundle> --env <env> --product <p> --signers <allowed_signers> --verify-only [--json]
```

- `--env` and `--product` are **required**. They must equal the signed header's environment and
  product. A bundle copied to the wrong service is refused even if its key could decrypt it.
- `--signers` is an OpenSSH `allowed_signers` file. Only ed25519 lines whose `namespaces=`
  includes `opv-sealed` are considered (a line without `namespaces=` is refused, so a general
  git-signing file is never trusted by accident).
- The identity comes from `--identity-file` (preferred: a platform secret file, a Kubernetes
  secret volume, a Docker secret under `/run/secrets`) or `--identity-env VAR` (for platforms
  whose only secret channel is the environment, such as Fly today). With `--identity-env`, `VAR` is
  removed from the child's environment. The identity is never an argument (SR-3).
- `--verify-only` checks the signature, header and revision and needs no identity, so a deploy
  pipeline can check a bundle before shipping it.
- Without `--exec`, it verifies, decrypts in memory, checks the payload, and prints names,
  destinations and the header. No values.
- With `--exec`, it delivers to the command (§5.5). The exit code is the command's own, as with
  `opv run` (FR-10).

`unseal` makes no runner call, loads no `secrets.toml`, needs no `op` and opens no socket. Refusals
happen before anything is decrypted or started:

| Condition | `error.code` | Exit | Checked |
|---|---|---|---|
| file missing, over size limits, not `opv-sealed v1`, malformed armor/header/payload | `sealed_malformed` | 6 | before the signature |
| signature does not verify, wrong namespace or hash, signer not in `--signers` | `sealed_signature_invalid` | 6 | before the header is trusted |
| header environment or product differs from the flags | `sealed_scope_mismatch` | 6 | after the signature, before decryption |
| revision below `--min-revision` or the ratchet | `sealed_revision_below_floor` | 6 | before decryption |
| identity not readable, not an `AGE-SECRET-KEY-1…` | `sealed_identity_unusable` | 2 | before decryption |
| the identity's recipient is not in the header's recipient list, or age finds no matching stanza | `sealed_not_a_recipient` | 7 | the list before decryption; the stanza by age |
| decrypted payload's header digest or name list differs from the header | `sealed_payload_mismatch` | 6 | after decryption, before delivery |
| a bundle name already set in the inherited environment | `sealed_name_collision` | 6 | before exec |
| file keys without a RAM-backed runtime directory | `ram_dir_unavailable` (existing) | 6 | before any file |
| ratchet file unreadable or unwritable | `sealed_ratchet_unusable` | 6 | before decryption (read), before exec (write) |
| command cannot start | `child_start_failed` (existing) | 3 | |

`--json` (schema `opv.unseal/1`) looks like this:

```json
{"schema": "opv.unseal/1", "ok": true,
 "bundle": {"format": "opv-sealed/1", "project": "fleet", "environment": "prod", "product": "api",
            "target": "box", "revision": 1793795000, "created_at": "2026-11-04T12:00:00Z",
            "opv_version": "0.18.0", "plan_id": "7f3c9a1e", "contract_digest": "sha256:…",
            "signer": "SHA256:Xb…", "recipient": "sha256:4be1…", "source_versions": [{"item_id": "…", "version": 41}]},
 "names": [{"name": "DATABASE_URL", "destination": "env:DATABASE_URL"},
           {"name": "GITHUB_APP_KEY", "destination": "file:github-app/private-key"}],
 "op_calls": 0}
```

Errors use the existing FR-22 shape (`ok: false`, `error.code`, fixed guidance). No value, no
value-derived digest, no identity and no recipient string appear in any output. Only fingerprints
appear.

### 4.3 MCP and assistants (parity)

The MCP surface stays at five tools (`tests/surface_contract.rs`).

- `opv_state`, `opv_next` and `opv_explain` cover sealed placements like any other target:
  state, staleness and next step, value-free.
- `opv_propose` can propose a sealed target section through the provider's `init_fields` /
  `init_section` (`src/provider.rs:70-81`).
- **No MCP tool runs `unseal`.** Delivering values to a process is not an assistant action, the
  same rule as remote delivery (FR-63).
- `opv unseal --verify-only --json` is value-free and safe for an assistant to run in a shell.

## 5. Bundle format, `opv-sealed/1`

### 5.1 Layout

One UTF-8 text file. Each block is on its own lines:

```text
opv-sealed v1
{"contract_digest":"sha256:…","created_at":"…","environment":"prod",…}      ← header, canonical JSON, one line
-----BEGIN AGE ENCRYPTED FILE-----
…age armored ciphertext of the payload…
-----END AGE ENCRYPTED FILE-----
-----BEGIN SSH SIGNATURE-----
…SSHSIG over every byte above this line, namespace "opv-sealed", hash sha512…
-----END SSH SIGNATURE-----
```

- **One file** carries header, ciphertext and signature. Three files (`.age`, `.json`, `.sig`)
  could be shipped out of step, which is a failure mode with no upside.
- The armored age block is a standard age file: `age -d -i id.txt` decrypts it after the block is
  cut out. The signature is a standard SSHSIG: `ssh-keygen -Y verify -n opv-sealed -f allowed_signers
  -I <principal> -s sig.txt < signed.txt` verifies it. The downstream platform can therefore check
  the format with stock tools.
- The extension is `.opv-sealed`, not `.age`: the file is not an age file as a whole, and `age -d`
  on it would fail confusingly.

### 5.2 Header (signed, plaintext, value-free)

| Field | Content |
|---|---|
| `format` | `"opv-sealed/1"` (also the first line, so a reader refuses other versions before parsing JSON) |
| `project`, `environment`, `product`, `target` | the placement (FR-58) |
| `revision` | unsigned integer, strictly increasing per placement (§5.4) |
| `created_at` | RFC 3339 UTC |
| `opv_version` | the sealing opv |
| `plan_id` | the plan id of the sync that sealed it (FR-41) |
| `contract_digest` | `sha256:` over the canonical JSON of everything in configuration that shapes the bundle: the sorted `(name, destination)` list, `secrets_dir_env`, the recipients and the signer (§5.3) |
| `recipients` | `sha256:<16 hex>` fingerprint of each recipient string, sorted |
| `signer` | the signing key's OpenSSH fingerprint (`SHA256:…`) |
| `names` | sorted `[{name, destination}]`, where destination is `env:<NAME>` or `file:<relative path>` |
| `secrets_dir_env` | the variable that names the file directory, when the product has file keys |
| `source_versions` | `[{item_id, version}]` of each 1Password item read (the C2 lines of `delivery-receipts.md`) |

Canonical JSON means keys sorted, no insignificant whitespace, UTF-8, integers only. The parser
refuses unknown fields (`deny_unknown_fields`). A header is at most 64 KiB.

**Exposure:** key names, item ids and item versions are readable by anyone holding the bundle.
Names and ids are already in the committed configuration. Versions show how often items change.
No value, length or value digest is in the header.

### 5.3 Payload (inside age)

Binary framing in the style of the remote-delivery payload (`src/app/remote_delivery.rs:165-230`),
not JSON, so values are never `String`s:

```text
OPV-SEALED-PAYLOAD 1\n
<32 bytes: sha256 of the header line's exact bytes>
<u32 BE count>
repeat count: <u16 BE name len><name><u32 BE value len><value bytes>
END\n
```

Limits: at most 256 names, each value at most 1 MiB, the whole bundle at most 8 MiB. Those are the
remote payload's limits plus room for armor. Every value is read into a `Zeroizing<Vec<u8>>`. The
payload's header digest must equal the digest of the header actually verified, and its names must
equal the header's `names`, in order. That binds the plaintext to the signed header, independently
of the signature.

**Staleness and the "whole set" rule.** A bundle is rewritten whole, because opv cannot read the
previous bundle's values (it holds no runtime identity, by design). The store tells `sync` that a
change to any one name means re-sealing every name (§8.2). The store also reports **whole-bundle
staleness** when the header's `contract_digest` differs from the configuration's. This happens
when a recipient, the signer, a destination or the name set changed. `plan` shows that as one row
with the reason (`recipients changed`, `signer changed`, `names changed`), and `sync` re-seals.
This meets acceptance 6: a recipient change marks every bundle of that target stale, with no
separate `keys` command.

### 5.4 Revision and rollback

`revision = max(previous + 1, now as Unix seconds)`. `previous` is the revision in the header of
the bundle currently at `sealed.out`, and the revision recorded in the placement's evidence line,
when either exists.

- The rule needs **no new state**: a fresh CI checkout without the old bundle still produces a
  higher revision as long as its clock is not behind the last sealer's.
- A sealer whose clock is behind fails closed and visibly: the runtime refuses the bundle as below
  its floor.
- Two sealers in the same second still increase, through `previous + 1`, when they see each
  other's output. Two concurrent seals of one placement that do not see each other can both
  pick `now`. The rename makes the last one win, and its evidence line then disagrees with the
  file, which `delivery verify` reports. Lane P3 checks whether sync already serializes a
  placement's writes. If it does not, P3 adds an exclusive lock file next to `sealed.out`.

The runtime's floor comes from up to two sources, and the higher one wins:

1. `--min-revision N`, set by the deploy. The release that sealed revision N deploys the runtime
   with `--min-revision N`. This is the build-once-deploy-twice shape: the pipeline knows the
   revision it shipped.
2. `--ratchet <path>`, an optional local file holding the highest revision this runtime accepted.
   It is read before decryption and written (atomically, 0600, not secret) after a successful
   verify and before exec. This protects long-lived hosts whose deploy does not pass a floor.
   On an ephemeral container filesystem it resets, so the deploy floor is the primary control.

**No expiry by default** (owner decision D5). An expiring bundle turns a missed re-seal into the
same outage this design removes.

### 5.5 Delivery to the child (`--exec`)

- **Variables only (no file keys):** opv builds the child's environment and calls `execve`
  (`CommandExt::exec`). opv's process image is replaced. No opv process stays resident with values
  in memory, signals reach the app directly, and the app is PID 1 in a container as it would have
  been. Before exec, opv zeroizes its own copies. The values exist only in the new image's
  environment, as they do under `op run` today.
- **With file keys:** opv stays as the parent. It reuses local delivery's private directory unchanged:
  - `runtime_dir_support` (`src/app/local_delivery.rs:201-216`);
  - `PrivateDir`, `OpenDir::open_private` and `write_file` (`:278-352`): a 0700 directory on
    tmpfs/ramfs under `$XDG_RUNTIME_DIR`, files 0400, `O_EXCL|O_NOFOLLOW`, no disk fallback;
  - the sweep on start, removal on exit and on signal;
  - the RAM-directory refusals (`local-delivery.md`, Platforms and limits);
  - signal forwarding to the child and the same exit-code pass-through.
- **The child's environment** is the inherited environment, minus the `--identity-env` variable,
  minus every `OP_*` variable, plus the bundle's variables and `secrets_dir_env`.
  - A bundle name already present in the inherited environment is refused
    (`sealed_name_collision`) rather than silently shadowed or overridden. During migration that
    catches a platform secret left behind under the same name.
  - `declared_only` (FR-62) applies when the product sets it, and the header records the mode.
- **Hardening, same as the remote receiver:** non-dumpable and zero core limit at start
  (`src/hardening.rs:9`), and `cloexec_inherited()` just before exec or spawn (`:24`).

### 5.6 Where bundles go (first slice: a file)

`sync` writes `sealed.out`: a temporary file in the same directory, `fsync`, `rename`, `fsync` of
the directory. Publishing is the caller's job. The patterns the docs give, smallest first:

1. **Commit the bundles** (they are ciphertext) and bake **every environment's** bundle into the
   one image. Each runtime can open only its own environment's bundle. This fits build once,
   deploy twice: the same image goes to staging and production. Rotation means re-seal, commit
   and redeploy.
2. **Ship beside the image:** a Kubernetes ConfigMap (ciphertext is fine there), a volume, or an
   object-store fetch in the deploy script.
3. Later, if a consumer needs it: `sealed.publish` to an OCI artifact or an HTTP PUT through the
   runner's HTTPS effect. This is not in this design's slices.

### 5.7 Library form

A small crate (`opv-sealed`: verify → decrypt → `Zeroizing` map) for long-running consumers that
want no exec. It needs a Cargo workspace, which the repository does not have today (single
`[package]`, `Cargo.toml:1`). It is deferred to a second slice (D7). The first slice's
`src/bundle/` module (§8.1) is written with no dependency on the rest of opv, so it can move into
that crate unchanged.

## 6. Cryptography and dependencies

### 6.1 Encryption: age, X25519 recipients only

- age is the issue's choice and has a stable, specified format, interoperable CLIs (`age`,
  `rage`) and a maintained Rust crate (`age` 0.12.1, MIT OR Apache-2.0). It is authenticated
  encryption (ChaCha20-Poly1305 STREAM), so truncation and modification are detected without the
  signature too.
- Encrypting is in process, through `age::Encryptor::with_recipients` and the armored writer.
  Decrypting is through `age::Decryptor` with exactly one `x25519::Identity`. No scrypt
  (passphrase) identity is ever offered, so a passphrase stanza cannot be used to downgrade.
- **v1 accepts X25519 recipients only.** SSH-key recipients (the `ssh` feature) would add RSA and
  AES-CBC code. Plugin recipients would execute plugin binaries. Hybrid post-quantum recipients
  (`age1pq…`) are a candidate for `opv-sealed/2`: bundles may sit in git or registries for years,
  so harvest-now-decrypt-later is a real concern, recorded in §11.
- **age is not a signature.** Anyone who has a recipient's public key, and recipients are public,
  can make a ciphertext the runtime would decrypt. The signature is therefore mandatory, and is
  checked first.

### 6.2 Signing: SSHSIG with ed25519, in process

| Option | For | Against | Verdict |
|---|---|---|---|
| **SSHSIG, ed25519** (`ssh-key` 0.6 crate, `ed25519` feature) | issue's choice; 1Password stores and generates SSH keys natively (an SSH Key item); `ssh-keygen -Y verify` can check it; `allowed_signers` is a known format; 28 crates, all already-licensed families, `cargo deny` clean (§6.4) | none significant | **recommended** |
| minisign | tiny verifier (`minisign-verify`, 2 crates) | signing needs the heavier `minisign` crate (scrypt); a key format 1Password does not manage; a second key ecosystem | rejected |
| an age plugin for signing | none exists; age has no signing | | not an option |
| shell out to `ssh-keygen -Y sign` with the person's agent | the issue's wording; no new signing code | needs OpenSSH on the sealer; under CI there is no agent, so the key would be loaded from 1Password into a file or an agent, which is worse; an extra failure surface | rejected as the mechanism, but the **output is the same SSHSIG bytes**, so the format is unaffected |

- **The signing key is the target's `deploy_credentials` item** (FR-40): a 1Password SSH Key item.
  1Password can generate the key itself (`op item create --category "SSH Key" --ssh-generate-key
  ed25519`), so the private key never passes through opv at creation.
- At sync, opv reads it like any deploy credential, as a zeroizing `SecretValue`, and checks that
  its public key equals `sealed.signer` before reading any value. A mismatch is
  `CredentialRejected { DeployCredentials }` (exit 7), so a staging signer cannot sign a production
  bundle.
- Signing is done **as a runner effect**, the way HTTPS is in `http-target.md` §5. The key stays
  with the run's `DeployLogin` (`src/provider.rs:183-194`), and the adapter asks the runner to sign
  bytes. `FakeRunner` and the sim sign with a fixture key, so the tested path is the shipped path.
- To confirm in the spike (lane S0): the shape `op item get --format json` returns for an SSH Key
  item's private key. It may be PKCS#8 PEM for ed25519 with an OpenSSH form beside it. `ssh-key`
  parses OpenSSH, and `ed25519-dalek`'s `pkcs8` feature parses PKCS#8.

Verification uses `ssh_key::PublicKey::verify(namespace, msg, &SshSig)`, which runs
`ed25519-dalek` strict verification. Only `ssh-ed25519` keys, the `sha512` hash and namespace
`opv-sealed` are accepted. Anything else is `sealed_signature_invalid`.

### 6.3 Memory hygiene and constant time (SR-2, SR-8)

- **Values:** read from 1Password into `SecretValue` (existing), framed into a
  `Zeroizing<Vec<u8>>` payload, streamed into the age writer. At unseal, read from the age reader
  into one `Zeroizing<Vec<u8>>`, then split into zeroizing slices.
- **Identity:** read into `Zeroizing<String>`, parsed into `age::x25519::Identity`. That type
  wraps `x25519_dalek::StaticSecret`, which zeroizes on drop. The lane confirms the feature is on
  in the resolved tree.
- **Signing key:** `ssh_key::PrivateKey` zeroizes its key data on drop (crate behaviour; the lane
  confirms it).
- **Residual:** age's STREAM reader and writer keep 64 KiB chunk buffers internally. The spike
  checks whether they are zeroized. If not, this is recorded as a known residual, bounded to the
  life of the unseal process, which `exec` replaces at once in variable-only mode.
- **Constant time:** signature verification is `ed25519-dalek`'s. No secret comparison is made
  by opv code in `unseal`. Header fields, revisions and fingerprints are public. Evidence
  fingerprints at sync are compared with `subtle` (already a dependency, FR-54).
- No value is ever in a panic message. The codec returns typed refusals whose `Display` names
  fields, never bytes (the remote payload's `Refusal` pattern).

### 6.4 Dependency weight and `cargo deny` (measured 2026-11-04)

Probe: a scratch crate per candidate, `cargo tree -e normal`, and
`cargo deny check licenses advisories` with this repository's `deny.toml`.

| Crate (features) | Unique crates | Release size of a minimal binary | Licences | Advisories |
|---|---|---|---|---|
| `age 0.12.1` (no default features) | 127 (with duplicates of `digest`, `sha2`, `hybrid-array`, `rand_core`: multiple-version warnings) | +0.8 MB (1.28 MB vs 0.46 MB baseline) | ok | **2 errors:** `basic-toml` unmaintained (RUSTSEC-2026-0374), through `i18n-config` used only by the `i18n-embed-fl`/`i18n-embed-impl` proc macros at build time; `crypto-bigint 0.5.5` timing variability (RUSTSEC-2026-0387), through `elliptic-curve`/`p256`/`hpke`, used only by the p256-tag and hybrid recipient types. Fixed upstream in 0.7.6, which `elliptic-curve 0.13` cannot take, so `cargo update` does not clear it |
| `age 0.11.5` | 117 | (similar) | ok | 2 errors: `basic-toml`, `proc-macro-error2` unmaintained (RUSTSEC-2026-0173), both build-time |
| `ssh-key 0.6.7` (`ed25519`, `alloc`) | 28 | | ok | clean |
| `minisign-verify 0.3` | 2 | | ok | clean |

Neither age advisory is reachable from opv's use:

- `basic-toml` runs at compile time only.
- `crypto-bigint` sits on the p256 path, which X25519-only recipients never execute.

The repository's `deny.toml` has no `[advisories] ignore` list today, so adopting age means adding
the first two entries, each with this justification and a review date. age also brings an
i18n/fluent stack (localized error strings, embedded with `rust-embed`) that opv never shows.

This is owner decision **D2**:

- age crate in process with two documented ignores;
- the `age` CLI as a runtime dependency;
- or waiting for an age release without those advisories.

**Recommendation:** the crate, pinned to `=0.12.1`, X25519 only, ignores dated to the next minor.

## 7. Keys, identity and the permission model

### 7.1 Where each key lives

| Key | Secret? | Lives in | Who can use it | How it gets there |
|---|---|---|---|---|
| runtime age identity (`AGE-SECRET-KEY-1…`), one per environment, or per environment and product | yes | a 1Password field: a key declared for that environment's runtime, for example `OPV_SEALED_IDENTITY`, `kind = "secret"`, with a new generator rule `age_identity = true` | whoever can read that boundary vault, and the runtime | `opv generate <env> <product/KEY>` (person's session, never printed, `src/app/generate.rs`), which prints the matching `age1…` recipient for the configuration; delivered **once** to the runtime by an existing target (a Fly secret, a Kubernetes Secret, a file through `opv run` local delivery) or by the platform's own secret mechanism |
| its recipient (`age1…`) | no | `sealed.recipients` | anyone | committed |
| signing key (ed25519) | yes | the target's `deploy_credentials` 1Password SSH Key item | whoever can read that vault: a person, or the CI deploy identity (FR-40, FR-59) | `op item create --category "SSH Key" --ssh-generate-key ed25519` |
| signer public key | no | `sealed.signer`; the runtime's `allowed_signers` | anyone | committed or baked into the image |

### 7.2 What changes in the security model (honestly)

Today a runtime that calls `opv run` holds a **1Password service-account token**. That token is
scoped to vaults, revocable centrally at once, audited by 1Password on every read, and rate
limited. With sealed delivery the runtime holds an **age identity** instead:

- **No central revocation.** The identity decrypts, offline and forever, every bundle ever sealed
  to it, including old copies in git history, registries and caches. "Revoking" it means removing
  its recipient and re-sealing. That stops **future** bundles only. If the identity leaks, every
  value in any bundle sealed to it must be treated as exposed and rotated at its provider.
- **No per-read audit.** 1Password logs the seal (one read per release), not each process start.
  Runtime reads become invisible to 1Password, which is the point, and also a loss.
- **A narrower blast radius in one way.** The identity opens only the bundles sealed to it: one
  environment, and one product when identities are per product. It never reads another value in
  the vault. A leaked service-account token reads the whole vault until it is revoked.
- **Integrity now rests on the signing key.** Whoever holds it can make the runtime start with
  values of their choice (for example a `DATABASE_URL` pointing elsewhere). It lives in 1Password
  behind vault access and is used only at sync.

**How this fits "1Password vault access is the only permission system":** opv defines no roles
here either.

- **Who can seal** = who can read the boundary vaults and the signing key's vault.
- **Who can make a runtime identity** = who can write that boundary (a person, through
  `opv generate`).
- **Who can run with the values** = who holds the identity, which was itself delivered from
  1Password by vault access.
- `sealed.recipients` and `sealed.signer` in the configuration are **trust anchors, not
  permissions**: public keys that pin where values may go and who may sign, like a remote
  profile's `host_key` (FR-63). They are reviewed like any configuration change.
- CI still never writes a value to 1Password. It reads values and the signing key, and writes only
  delivery evidence to the state vault, as for every target (FR-58).

### 7.3 Rotation flows

**Runtime identity:**

1. `opv generate` a new identity into a new field or key.
2. Add its recipient beside the old one in `sealed.recipients`.
3. `opv sync` re-seals to both (contract digest changed, §5.3).
4. Deliver the new identity to the runtime and deploy.
5. Remove the old recipient and `opv sync` again.
6. Delete the old field.
7. If the old identity leaked: also rotate every value it could open.

**Signing key:**

1. Create a new SSH Key item.
2. Add its public key to the runtime's `allowed_signers` and deploy.
3. Point `deploy_credentials` and `sealed.signer` at the new key and `opv sync`.
4. Remove the old line from `allowed_signers` and deploy.

**Values:** a rotation in 1Password makes `opv changed` exit 10. `opv sync` re-seals, and the
deploy ships the bundle with `--min-revision` at the new revision, so the old bundle (holding the
revoked value) is refused.

### 7.4 Per-platform bootstrap of the identity (documented, not built)

| Platform | Identity channel | `unseal` flag |
|---|---|---|
| Docker host / Compose | Docker secret or a bind-mounted file from `opv run` local delivery (tmpfs) | `--identity-file /run/secrets/opv_identity` |
| systemd | `LoadCredential=` / `systemd-creds` (encrypted at rest by the host) | `--identity-file $CREDENTIALS_DIRECTORY/opv_identity` |
| Kubernetes | Secret delivered by opv's Kubernetes target, mounted as a volume | `--identity-file /var/run/opv/identity` |
| Fly | Fly secret delivered by opv's Fly target (environment only today) | `--identity-env OPV_SEALED_IDENTITY` |

## 8. Implementation: where the target is wired

### 8.1 Modules

- `src/bundle/`: the format and the crypto (§5, §6), with no dependency on the configuration,
  runner or adapters.
  - `format.rs`: envelope and header canonical form, payload framing, limits.
  - `crypto.rs`: age and SSHSIG wrappers, recipient, identity and signer parsing.
  - Used by the adapter (seal) and by `src/app/unseal.rs` (unseal), and the future library crate.
  - It is a codec, not a target adapter, so `src/app` may name it. FR-12's guard
    (`use_cases_name_no_target_adapter`, `src/app/mod.rs:2128`) and FR-37's
    (`core_modules_name_no_provider`, `:2313`) stay green.
  - Add `adapters::sealed` and `sealedtarget` to `provider_named`'s words (`:2281-2298`), so core
    can never name the adapter.
- `src/adapters/sealed/`:
  - `mod.rs`, `config.rs`: `sealed.*` parse and the §3.1 rules.
  - `provider.rs`: `Provider` and `TargetConfig`.
  - `store.rs`: `StagedStore` (list = read the header at `sealed.out`; write = build, sign and
    atomically write the bundle), with `StagedRuntime::live() == true` like GitHub and HTTP.
  - `login.rs`: the SSH Key deploy credential, signing as a runner effect.
- `src/app/unseal.rs`: verify, decrypt, refusals, JSON, ratchet, and the exec/supervise delivery,
  reusing `local_delivery`'s directory primitives and `hardening`.

### 8.2 Registration points and the places a new target must be wired

| # | Where | Change |
|---|---|---|
| 1 | `src/adapters/mod.rs:16` (beside `pub mod http;`) | `pub mod sealed;` |
| 2 | `src/adapters/registry.rs:4`, `:8-14` | import and one line in `PROVIDERS`; the test at `:95-97` lists `"sealed"` |
| 3 | `src/provider.rs:695-747` | a `[environments.prod.targets.sealed]` table in `ALL_PROVIDERS` |
| 4 | `src/provider.rs:764-833` | its row in `the_contract_lists_every_providers_channels` (§3.2) |
| 5 | `src/provider.rs:679-687` `system_of` | a `"sealed"` arm, plus `System::Sealed` in `src/cause/subject.rs:94-124` with label `"sealed bundle"`. **Found while reading:** `system_of` has no `"http"` arm either, so the HTTP provider is labelled `System::GitHub` by its `_` fallback. Fix both in the same lane |
| 6 | `src/ports.rs:37-55` `StagedStore` | one defaulted method, `fn whole_set(&self) -> Option<WholeSet> { None }`, where `WholeSet { stale: Option<&'static str> }`: this store rewrites every name together, and why it is stale as a whole |
| 7 | `src/app/sync.rs:1006-1066` (`prepare_staged`), `:1096-1128` (batch, `write`, `confirm`) | when `whole_set()` is `Some` and the plan stages anything or `stale` is set, the batch is every desired name with its value (from the same read; no extra `op` call), and the plan shows the reason row |
| 8 | `src/app/mod.rs:2281-2298` | guard words (§8.1) |
| 9 | `tests/observed_seal.rs:44-82` | **unchanged**: the sealed adapter makes no CLI call of its own, so there is no new `lost_call` caller (J7). The lane asserts the list is the same |
| 10 | `src/cause/mod.rs` (codes near `:2047`, `exit_code` `:2066-2165`) | the `sealed_*` causes of §4.2 |
| 11 | `src/main.rs`: `Cmd` enum (near `Run`, `:814`) | `Unseal`, dispatched early without loading configuration, like `RemoteReceive` (`:1050`, `:2688`); the exhaustive matches near `:4774-4788` |
| 12 | `tests/e2e/expected/surface.json` | an `unseal` CLI entry; MCP list unchanged |
| 13 | `tests/cli_ux.rs:92-99` | the exit-code help line "5 target (Fly, Azure, Kubernetes, GitHub, HTTPS, sealed bundle)" built from `labels()`; `tools()` is empty, so the "3 dependency" line is unchanged |
| 14 | `src/schema.rs:520` | capability `sealed_bundles/1` and the new cause codes |
| 15 | `src/app/generate.rs:28-31` `Recipe` and the key-rule parser (`src/domain/catalog.rs`) | `AgeIdentity`, printing the recipient |
| 16 | `src/runner.rs` and `src/app/mod.rs:2665` (`op_calls` test helper) | the `op_calls` count in `--json`; the signing effect |
| 17 | `tests/e2e/app/secrets.toml`, `world.json`, `tests/e2e/scenarios/` | a sealed target in the e2e app and its scenarios; fault-matrix cells or `UNREACHABLE` entries for each new cause |
| 18 | `deny.toml`, `Cargo.toml` | `[advisories] ignore` (D2), `age`, `ssh-key` |
| 19 | docs: `docs/usage.md`, `opv guide agent`, the agent skill, `docs/design/requirements.md` (new FR-64), CHANGELOG | `tests/docs_commands.rs` parses every documented `opv …` line |

### 8.3 Composition with what exists

- **sync / plan / status:** a staged, live target. `Store::list` reads the header from the local
  file, so plan never needs the runtime.
- **Receipts and evidence (FR-58, `delivery-receipts.md`):** the per-name store version is
  `r<revision>.<first 16 hex of sha256(bundle file)>`. It is a digest of ciphertext under a random
  age file key, so it is not value-derived (`versions_reveal_values() == false`). Evidence lines,
  revisions and `delivery verify` work unchanged. A bundle replaced on disk outside opv is
  `drifted_on_target`, and a missing one is `missing_on_target`.
- **`opv changed`:** unchanged. It already compares recorded `source versions` with
  `op item list` (`src/app/changed.rs:1-21`). This is the issue's `seal --check`: names and
  versions only.
- **`run --product`:** unchanged. `opv run` stays the developer path through `op run`, and
  `unseal --exec` is the runtime path. They share the delivery primitives, not the command (D6).
- **Roles (`--role`, local-delivery §Process roles):** a sealed target may declare `roles` like any
  target, and the bundle then holds that role's selection. Two roles mean two targets, so a
  migration job's bundle never reaches the server.

## 9. Self-vet

### 9.1 Poka-yoke (mistakes made impossible or loud)

| Mistake | Guard |
|---|---|
| a production bundle sealed to a staging recipient, or the reverse | load rule: no recipient in two environments (§3.1-2) |
| a staging signer used for production | sync refuses unless the credential's public key equals `sealed.signer` (§6.2) |
| the wrong bundle shipped to a service | `--env` and `--product` required and checked against the signed header |
| an old bundle (revoked value) redeployed | revision floor from the deploy, and the ratchet |
| forgetting to re-seal after a rotation | `opv changed` exit 10, which a scheduled CI job or `opv ready` surfaces; not a runtime poll |
| recipients changed but bundles not | contract digest makes every bundle of the target stale in `plan` (§5.3) |
| a platform secret left with the same name during migration | `sealed_name_collision` |
| an `allowed_signers` file meant for git commits trusted for bundles | lines without `namespaces="opv-sealed"` are ignored, and a file with no such line is refused |
| three-file bundles out of step | one file (§5.1) |
| a format change read by an old runtime | the first line names the version; an unknown version is refused, never guessed |

### 9.2 Security checklist

- **Values never in argv:** sealing reads through the existing `op` paths (stdin/JSON). `unseal`'s
  argv holds paths, names and numbers. The child's argv is the person's command. Test: argv and
  environment scan with marker values (as `tests/security.rs`).
- **Never in opv's own environment:** values are never exported into opv's process environment.
  In `--exec` they are placed only in the `execve` environment of the child, or the supervised
  child's `Command::envs`. The `--identity-env` mode is the one place a **key** arrives through
  opv's environment, because the platform has no other channel. It is removed from the child.
- **Never in files or logs:** the bundle is ciphertext (SR-4 is about plaintext). File keys go
  only to the RAM directory. Every refusal is built from fixed text and field names.
  `--verbose` never prints a header field that is not in `--json`.
- **Plaintext never at rest:** no temporary plaintext file at seal (payload in memory, streamed
  into age), none at unseal. Swap is the host's residual, as in `local-delivery.md`.
- **Verify before decrypt:** the parse order is fixed and tested:
  1. size bounds;
  2. format line;
  3. split blocks;
  4. SSHSIG verify over the exact signed bytes;
  5. header parse;
  6. scope, revision and recipient checks;
  7. decrypt;
  8. payload binding;
  9. delivery.

  The file is read once into memory, so there is no time-of-check/time-of-use gap between steps.
- **Downgrade attacks:**
  - format version pinned (v1 only);
  - signature algorithm pinned (ed25519, sha512, namespace);
  - age stanzas limited to X25519 by offering only an X25519 identity (a scrypt stanza is never
    tried; age refuses a scrypt stanza mixed with others);
  - recipient types refused at load (§3.1-1);
  - no fallback to `op` or to an unsigned bundle anywhere.
- **Key compromise:**
  - identity: §7.2–7.3, rotate the identity **and** the values it opened;
  - signing key: an attacker can make runtimes accept chosen values until the key is removed from
    `allowed_signers`, so keep it in a vault only the deploy identity and owners read;
  - recipient list in configuration: a malicious edit adds an attacker's recipient. It is a
    reviewed configuration change, and the contract digest makes it visible as `recipients
    changed` in `plan`.
- **Denial of service:** bounded sizes before any crypto. Signature verification costs one SHA-512
  over at most 8 MiB plus one ed25519 verification.
- **Trust boundary (stated in the docs):** root on the runtime host, or any process of the same
  user while the app runs, can read the values (the same residual as `local-delivery.md`). The
  identity on the host decrypts every bundle sealed to it.

### 9.3 Architecture guards

- FR-12 and FR-37: the adapter is under `src/adapters/sealed/`, and core uses ports and
  `TargetConfig` only. `src/bundle/` is a codec. Guard words are extended (§8.2-8).
- J7: no new `lost_call` caller.
- Golden surfaces: `surface.json`, the exit-code help, and the all-providers channel contract are
  each updated in the lane that changes them (§10), never left to a later lane.
- FR-60: no `opv seal` alias beside `sync`, no `delivery =` switch beside per-key `file`, one
  bundle format.

## 10. Test plan

Each test is one behavioural assertion. Fixtures use marker values and test-only keys under
`tests/fixtures/sealed/`, with a README saying they are test keys.

**Known-answer vectors (S0 produces them with stock tools):**

1. A fixture bundle made with the `age` CLI and `ssh-keygen -Y sign` from fixed keys is accepted by
   `unseal` with the exact names and bytes. This proves interoperability in one direction.
2. A bundle `opv` seals decrypts with `age -d` (armor block cut out) and verifies with
   `ssh-keygen -Y verify`: a one-off check in S0, recorded. In CI, the same check runs through the
   crates against the fixture keys.
3. The canonical header of a fixed placement serializes to fixed bytes with a fixed sha256.
4. ed25519 signing is deterministic: a fixed key and message give the fixture SSHSIG byte for
   byte.
5. The payload framing of a fixed name and value set gives fixed bytes; decoding them round-trips
   PEM, binary and empty values exactly.

**Codec refusals (unit, `src/bundle/`)**, one test each, each asserting decryption was never
attempted (a counting identity):

- a bundle with no signature block is refused;
- a signature by a key not in `allowed_signers` is refused;
- a signature in another namespace is refused;
- an RSA signer line is ignored;
- one flipped header byte fails the signature;
- one flipped ciphertext byte fails the signature;
- a format line `opv-sealed v2` is refused;
- an unknown header field is refused;
- a header over 64 KiB is refused before verification;
- a wrong environment is refused before decryption;
- a wrong product is refused before decryption;
- revision N-1 under floor N is refused before decryption;
- an identity whose recipient is not listed is refused before decryption;
- a payload whose header digest differs is refused after decryption, before delivery;
- an `OP_*` name in a payload is refused;
- a truncated armor block is refused.

**Adapter and config (unit, `FakeRunner`):**

- each §3.1 rule, one test per rule;
- `list` on a missing file gives no entries;
- `list` reads names and versions from a fixture header;
- one changed value stages every name (whole set);
- a recipients change marks the bundle stale with reason `recipients changed`;
- a signer mismatch refuses before any value read;
- the write is atomic (an interrupted write leaves the old bundle);
- **a counting fake: sealing one product makes exactly one `op item get` per boundary item it
  needs** (acceptance 2), using `op_calls` (`src/app/mod.rs:2665`);
- `--json` reports `op_calls`.

**Unseal (unit and `tests/sealed_unseal.rs` on the real binary):**

- with no `op` on `PATH` and `OPV_SIM_WORLD` unset, unseal succeeds (no runner use);
- a source guard asserts `src/app/unseal.rs` and `src/bundle/` name no `CommandRunner`, `ureq` or
  `std::net`;
- `--exec` with variables only: the child sees exact values, and no `OP_*` variable and no
  identity variable;
- `--exec` with variables only replaces the process (the child's pid equals unseal's);
- `--exec` with file keys writes 0400 files in a 0700 RAM directory, removed after exit;
- a SIGTERM to the parent removes the directory;
- a name collision is refused before exec;
- the ratchet rises after a successful run;
- the ratchet refuses a lower revision;
- an unwritable ratchet refuses;
- `--verify-only` needs no identity;
- no output, error or `--json` contains a marker value, the identity or a recipient string.

**e2e through opv-sim (`tests/e2e/scenarios/sealed.rs`)**, with a sealed target in
`tests/e2e/app/secrets.toml` and the signer item in `world.json`:

- first sync writes a bundle;
- a second sync writes nothing;
- a rotated value re-seals with a higher revision;
- `opv changed` exits 10 after a rotation and 0 after the re-seal;
- `delivery verify` is `verified`, and `drifted_on_target` after the file is replaced;
- `unseal --exec` of the synced bundle delivers the marker values;
- every new cause is a fault-matrix cell or an `UNREACHABLE` entry with its reason.

**Gates:** golden surfaces updated; `cargo deny check` green with the D2 ignores; the release gate
under `CI=true` (memory: release gate under CI).

## 11. Alternatives considered

| Alternative | What it would do | Why not (or not now) |
|---|---|---|
| **Cache `op` sessions or values on the host** | fewer reads per start | the runtime still holds a 1Password identity; a cold start or cache expiry still calls; a value cache is plaintext somewhere (SR-4) |
| **1Password Connect server** | a self-hosted cache with its own request budget | another always-on server holding a vault token, so still a live runtime identity; Connect's availability on Families accounts needs confirming (believed Teams/Business); it moves the dependency instead of removing it |
| **A bigger 1Password plan** | a 5–50× budget | the budget still caps restarts; the dependency remains |
| **The target's own secret store** | already opv's answer where one exists (Fly, Key Vault, Kubernetes, GitHub, HTTP) | the gap is hosts **without** one. A `systemd-creds` target (host-bound, TPM) or Docker Swarm secrets could cover some, but each is one platform; a sealed bundle is portable and composes with them (§7.4 uses them for the identity) |
| **SOPS (with age)** | encrypted YAML/JSON with names in clear | no signature (its MAC is made with the data key, so any recipient-key holder can forge a file); a Go binary or immature Rust port at runtime; per-value ciphertext shows value lengths; a second format to own |
| **`op inject` to a file at deploy** | no runtime calls | plaintext at rest (SR-4) |
| **Shell out to the `age` CLI** | no age crate in the tree | every runtime image and sealer needs the binary; values through a pipe to another program; still needs SSHSIG. This is the fallback if D2 rejects the crate |
| **Symmetric key in 1Password instead of age** | smaller dependency | per-environment separation and rotation become opv's own key management; "no custom cryptography" |
| **Bundle expiry** | bounds how long a stolen bundle stays useful | a missed re-seal becomes an outage again (D5) |
| **Post-quantum hybrid recipients (`age1pq…`)** | protects archived bundles against future quantum decryption | larger keys, newer code paths (the `hpke`/`ml-kem` stack whose `crypto-bigint` advisory is open), and the downstream's tooling must support it; a candidate for `opv-sealed/2` |

## 12. Owner decisions

Each decision can be read on its own.

### D1. Seal through `opv sync` (a target), or a separate `opv seal` command?

**Situation.** The issue proposes `opv seal`. opv already has one command that reads 1Password
once and writes to a delivery target: `sync`. It brings plan ids, `--expect-plan`, `--confirm`,
receipts, `delivery verify`, `opv changed`, access checks and MCP state.

**Options:**

- **(a) A target delivered by `sync`.** Every existing guarantee applies. The downstream calls
  `opv sync <env> --target <t>` instead of `opv seal`; the file format is identical.
- **(b) A new `opv seal`.** It matches the issue's wording, but repeats or skips sync's plan,
  confirm and evidence. FR-60 forbids two ways to deliver.

**Recommendation: (a).** One way, and every safety check opv has already built applies to the
new target for free.

### D2. Which cryptographic dependency?

**Situation.** The age crate is the standard implementation. Measured today:

- it adds about 127 crates and about 0.8 MB to the binary;
- it fails this repository's `cargo deny` on two advisories, neither reachable from opv's use
  (§6.4): one unmaintained build-time crate, and one timing issue on a recipient type opv refuses.

**Options:**

- **(a) The crate, pinned, X25519 only,** with two dated `deny.toml` ignores.
- **(b) The `age` CLI** on every sealer and runtime.
- **(c) Wait** for an age release without the advisories.

**Recommendation: (a).** In-process is testable and needs nothing on runtime images, and the
ignores are narrow and justified. Signing uses `ssh-key` (28 crates, clean) whichever is chosen.

### D3. Where the signing key lives and how it signs

**Situation.** The issue says `ssh-keygen -Y sign` with the caller's key or agent. CI has no agent.

**Options:**

- **(a) The target's `deploy_credentials` is a 1Password SSH Key item,** read at sync and used
  in process (a runner effect).
- **(b) `ssh-keygen` with an agent.**

**Recommendation: (a).** Vault access decides who can seal, for people and CI alike; there is no
OpenSSH dependency; and the signature bytes are the same SSHSIG either way, so the format and the
downstream's verifier are unaffected.

### D4. How the runtime gets its age identity

**Situation.** The identity replaces the runtime's 1Password token. Some platforms deliver
secrets as files, but Fly today delivers them only as environment variables.

**Options:**

- **(a) Files only** (`--identity-file`).
- **(b) Files, plus `--identity-env VAR`** for environment-only platforms. opv removes the
  variable from the app's environment.

**Recommendation: (b), documenting file as preferred.** In both, the identity is generated into
1Password by `opv generate` and delivered once by an existing target, so it is never typed or
pasted.

### D5. Rollback protection: what sets the revision floor, and do bundles expire?

**Options:**

- **(a) The deploy passes `--min-revision`,** plus an optional local `--ratchet` file, and there
  is **no expiry**.
- **(b) Add an optional `sealed.max_age`** that the runtime enforces.

**What changes.** Expiry limits how long a stolen old bundle works, but a missed re-seal then
stops services, which is the outage this issue is about.

**Recommendation: (a).** Revisit expiry only with a scheduled re-seal in place.

### D6. Runtime command: `opv unseal --exec`, or `opv run --sealed <bundle>`?

**Situation.** `opv run` loads configuration and drives `op run`. The runtime has neither.

**Options:**

- **(a) `opv unseal … --exec -- cmd`:** configuration-free, network-free, with its own flags.
- **(b) A `--sealed` mode of `run`,** with a different set of required inputs and none of `run`'s
  checks.

**Recommendation: (a).** Different inputs and trust mean a different command. They share the
delivery code.

### D7. Ship the library crate in the first release?

**Options:**

- **(a) Defer.** `unseal --exec` covers process start, and `src/bundle/` is written so it can
  move into a crate unchanged.
- **(b) Build now.** This means turning the repository into a Cargo workspace and publishing a
  second crate.

**Recommendation: (a).** No consumer has asked for in-process use yet.

### D8. Names in the clear header?

**Situation.** `plan` and `status` read the header to know what a bundle holds without
decrypting it. opv never can decrypt it.

**Options:**

- **(a) Names in the clear.** They are in the committed configuration anyway.
- **(b) Names only inside the ciphertext.** `plan` then sees "a bundle, revision N" and must
  trust evidence lines alone.

**Recommendation: (a).** Values, lengths and value digests are never in the header.

## 13. Delivery steps

Hours are estimates for one agent. **Broad** = reads across the codebase (→ Claude agent).
**File-scoped** = a bounded change in owned files (→ commodity worker through Junior). Each lane
stays under about 400 changed lines.

| Id | Lane | Files owned | Prereqs | Hours | Owner type | First slice |
|---|---|---|---|---|---|---|
| S0 | Spike: age and ssh-key API checks, zeroize of age chunk buffers, `op` JSON shape of an SSH Key item, stock-tool interop; produce KAT fixtures; `deny.toml` ignores and `Cargo.toml` deps | `tests/fixtures/sealed/*`, `deny.toml`, `Cargo.toml`, `Cargo.lock` | D2, D3 | 3 | Broad (Claude) | ✔ |
| B1 | Bundle format: envelope, canonical header, payload framing, limits, refusals (no crypto) | `src/bundle/mod.rs`, `src/bundle/format.rs`, `src/bundle/format_tests.rs` | S0 | 4 | File-scoped (commodity) | ✔ |
| B2 | Bundle crypto: age encrypt/decrypt, SSHSIG sign/verify, recipient/identity/signer/allowed_signers parsing, verify-before-decrypt `open()` | `src/bundle/crypto.rs`, `src/bundle/crypto_tests.rs` | S0, B1 | 5 | File-scoped (commodity) | ✔ |
| P1 | Sealed provider: config and §3.1 rules, `Provider`/`TargetConfig`, channels; registry; all-providers fixture and contract; `System::Sealed` and the `system_of` fix (with `http`); exit-code help; guard words | `src/adapters/sealed/{mod,config,config_tests,provider}.rs`, `src/adapters/mod.rs`, `src/adapters/registry.rs`, `src/provider.rs`, `src/cause/subject.rs`, `src/app/mod.rs` (guard words only), `tests/cli_ux.rs` | B1 | 5 | Broad (Claude) | ✔ |
| P2 | Signing as a runner effect and the SSH Key deploy login; FakeRunner/sim signing with the fixture key | `src/adapters/sealed/login.rs`, `src/runner.rs` (effect), runner fake | B2, P1 | 4 | Broad (Claude) | ✔ |
| P3 | Sealed store: `list` from header, `write` builds/signs/atomic-writes the whole set, version string, contract-digest staleness, NUL refusal | `src/adapters/sealed/store.rs`, `store_tests.rs` | B2, P1, P2 | 4 | File-scoped (commodity) | ✔ |
| C1 | Core whole-set port: `StagedStore::whole_set`, sync batch = every desired name, plan reason row | `src/ports.rs`, `src/app/sync.rs`, plan rows in `src/app/mod.rs` | P1 | 5 | Broad (Claude) | ✔ |
| C2 | `op_calls` in `--json` of sync/plan/status/changed; counting-fake test of one read per scope | `src/runner.rs` (counter only), `src/app/{sync,status,changed}.rs` report fields | C1 (sync.rs order) | 3 | Broad (Claude) | ✔ |
| U1 | `opv unseal` verify/inspect: CLI wiring (early dispatch), causes and exit codes, `--json` schema, ratchet, `--verify-only`; surface golden; schema capability | `src/app/unseal.rs`, `src/main.rs`, `src/cause/mod.rs`, `src/schema.rs`, `tests/e2e/expected/surface.json` | B2 | 5 | Broad (Claude) | ✔ |
| U2 | `unseal --exec`: exec for variables, supervised RAM directory for file keys, collision rule, `OP_*` and identity scrub, hardening | `src/app/unseal_exec.rs`, `tests/sealed_unseal.rs` | U1 | 4 | Broad (Claude) | ✔ |
| G1 | `opv generate` recipe `age_identity` (prints the recipient) | `src/app/generate.rs`, `src/domain/catalog.rs`, their tests | B2 | 2 | File-scoped (commodity) | ✔ |
| E1 | e2e: sealed target in the e2e app, `world.json` signer item, scenarios, fault-matrix cells and `UNREACHABLE` entries | `tests/e2e/app/*`, `tests/e2e/scenarios/sealed.rs`, matrix coverage | P3, C1, U2 | 5 | Broad (Claude) | ✔ |
| D1d | Docs: `docs/sealed-delivery.md` (trust boundary, per-platform bootstrap §7.4, rotation §7.3, migration from runtime `opv run`), usage, guide agent, skill, FR-64 in requirements, CHANGELOG | `docs/**`, skill files | E1 | 3 | Broad (Claude) | ✔ |
| R1 | `opv propose target sealed` (`init_fields`/`init_section`) | `src/adapters/sealed/provider.rs` (init only), propose tests | P1 | 2 | File-scoped (commodity) | later |
| L1 | Library crate `opv-sealed` (workspace, move `src/bundle/`, public API, docs) | `Cargo.toml` workspace, `crates/opv-sealed/**` | first slice shipped, D7 | 6 | Broad (Claude) | later |
| X1 | Publishing (`sealed.publish`: OCI or HTTP PUT) if a consumer asks | TBD | first slice | — | — | later |

**First slice** (all ✔): about 52 hours of work. Critical path:

```text
S0 → B1 → B2 → P2 → P3 → E1 → D1d
         ↘ P1 → C1 → C2
         ↘ U1 → U2 ↗
```

- B1 and P1 can overlap once the format types are fixed.
- U1/U2 run in parallel with P1–P3 and C1–C2, since they share only `src/bundle/`.
- `src/app/sync.rs` is touched by C1 then C2 in that order. That is the only shared file between
  lanes, and the reason C2 follows C1.

**Migration for the downstream (in D1d):**

1. Add the sealed target and generate the identity.
2. Deliver the identity once.
3. `opv sync` and publish the bundle.
4. Change the entrypoint from `opv run <env> --product <p> -- cmd` to
   `opv unseal <bundle> --env <env> --product <p> --signers … --identity-… --min-revision <N> --exec -- cmd`.
5. Delete the 5-minute fingerprint poll, and run `opv changed` in CI on a schedule instead.
6. Revoke the runtime's service-account token.
