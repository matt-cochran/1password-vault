# Sealed delivery: read 1Password at release time, never at runtime

A **sealed target** turns a product's values into one signed, encrypted file, a **sealed
bundle**, when you release. The runtime opens it with `opv unseal`: no configuration, no `op`,
no network and no 1Password identity. 1Password is read when values change, not every time a
process starts.

From opv 0.18.0 (#271, #275). Design: [sealed target](design/sealed-target.md).

## When to use it

A runtime that calls `opv run` (or `op`) at every container start, or on a drift timer, makes
1Password a live dependency of production. A service account's request budget is per account
(1,000 requests a day on a Families or individual plan, 5,000 on Teams, 50,000 on Business).
In the case that led to #271, one day of deploys and rollbacks plus a 5-minute poll per product
used up a Families budget, and 6 of 8 services on one environment could not start for about 20
hours.

| The runtime | Use |
|---|---|
| Has its own secret store (Fly, Key Vault, Kubernetes, GitHub, an [application's store](http-target.md)) | that store's target: `opv sync` writes it once, the platform injects at start |
| Has no secret store: a plain Docker host, a VM, systemd units, a supervisor that starts containers | a sealed target |
| A developer's machine | `opv run`, unchanged |

## What changes in the security model

Today a runtime that calls `opv run` holds a 1Password service-account token: scoped to vaults,
revocable at once, audited on every read, rate limited. With sealed delivery the runtime holds
an **age identity** instead.

- **The trust boundary.** Whoever holds a runtime identity can decrypt that runtime's bundles.
  Whoever holds a signing key can choose the values its environment's runtimes start with. Both
  private keys live in 1Password; only public keys appear in configuration and on the runtime.
- **No central revocation (R-U2, accepted by the owner).** A leaked runtime identity decrypts,
  offline and for ever, every bundle sealed to it, including copies in git history, images and
  registries. It cannot be revoked centrally. Removing its recipient and re-sealing protects
  only future bundles. **Recovery is rotating the identity and every value it could open**
  ([rotation](#rotation)). Removing the risk would need an online check at every start, which
  is the dependency this target removes.
- **No per-read audit.** 1Password records the seal, not each process start.
- **A narrower reach.** An identity opens only the bundles sealed to it (by default one
  environment and one product), never anything else in the vault. A leaked token reads the
  whole vault until it is revoked.
- **A signer is bound to one environment.** `sync` refuses a signing key that does not match
  `sealed.signer`; `config check` refuses a signer shared across trust groups; `unseal` accepts
  a signature only from an `allowed_signers` line whose principals include the bundle's
  environment. A staging key never signs for production.
- **Vault access stays the only permission system.**

  | Action | Who can do it |
  |---|---|
  | seal | whoever can read the boundary vaults and the signing key's item |
  | make an identity | whoever can write the identity's boundary |
  | run with the values | whoever holds the identity, delivered from 1Password by vault access |

- **Trust anchors are code.** `sealed.recipients`, `sealed.signer` and the runtime's
  `allowed_signers` are public keys and grant nothing by themselves. But approving an
  `allowed_signers` change approves **who may set that environment's values**: review it like
  code.
- Removing a person's vault access does not invalidate an identity they once read. The same is
  true of any value they once read, but a bundle is a durable copy they can decrypt again.
- CI still never writes a value to 1Password. It reads the values and the signing key, and
  writes only evidence to the state vault.

## Configuration

```toml
[environments.prod.targets.box]
products = ["api", "worker"]
roles = ["serve"]
deploy_credentials = "op://Ops Prod/opv-sealed-prod-signer"   # a 1Password SSH Key item

sealed.out = "sealed/prod/{product}.opv-sealed"   # relative to the configuration file
sealed.env_name = "{KEY}"                         # the variable name the runtime sees
sealed.recipients = [
  "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqysmtzj5f",   # prod runtime identity
]
sealed.signer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleEx opv-sealed-prod"
sealed.trust_group = "platform-prod"              # optional
```

| Field | Meaning |
|---|---|
| `sealed.out` | where `sync` writes each product's bundle, relative to the configuration file: no `..`, no absolute or `~` path, no placeholder but `{product}`. It must hold `{product}` when the target delivers more than one product, and every rendered path is unique across the configuration |
| `sealed.env_name` | the delivered variable name; holds `{KEY}`, may hold `{PRODUCT}`, never renders an `OP_*` name |
| `sealed.recipients` | one or more distinct age X25519 recipients (`age1…`). Other recipient types are refused |
| `sealed.signer` | one `ssh-ed25519` OpenSSH public key: the key in `deploy_credentials`. RSA, ECDSA and `sk-*` keys are refused |
| `sealed.trust_group` | optional; lower-case letters, digits and `-`. Targets of one group may share recipients and a signer ([below](#trust-groups)) |
| `deploy_credentials` | required: a **1Password SSH Key item** holding the signing key. `sync` signs in process with it; there is no `ssh-agent` or `ssh-keygen` |

A hand-written target leaves `state_vault_id` out: run `opv propose structure`, and the
person's `opv apply` creates the state vault and records it in `secrets.bindings.toml`.

Config keys travel in the bundle with the secrets. A key with `file = "<path>"` is delivered as
a file in the runtime's RAM directory, named by the product's `secrets_dir_env`; the path is
relative, at most four parts, each `^[a-z0-9]+(-[a-z0-9]+)*$`.

### Load rules

`opv config check` and every command that loads the configuration apply these. Each refusal
names the field and the rule; a recipient or signer is named by its fingerprint, never a value.

- **No recipient or signer is shared across trust groups**: `sealed_recipient_shared`,
  `sealed_signer_shared` (exit 2), naming both targets.
- **`deploy_credentials` is required.** Without a signing key nothing can be sealed.
- **The runtime identity is never sealed.** A key whose rules say `age_identity = true` is
  refused on a sealed target: a bundle cannot carry the key that opens it.
- **The signing key is never sealed.** A key read from the item named by `deploy_credentials`
  is refused.
- **No infrastructure key (#275).** A key with `source = "infrastructure"` is supplied at sync
  and never stored in 1Password, so there is nothing to seal: `config_invalid`, naming
  `<product>/<KEY>` and the target. Deliver it through a target with its own store.
- A variable whose value holds a NUL byte is shown by `plan` and refused by `sync` before
  anything is written. A file key may hold any bytes.
- Limits: 256 names per bundle, 1 MiB per value, 8 MiB per bundle.

### Trust groups

Without `sealed.trust_group`, a target's group is its environment: a recipient or signer may be
shared only by targets of one environment. A supervisor that holds one identity for many
products, each its own opv environment (`staging-api`, `staging-worker`, ...), names one group
on each of those targets, and they may then share one recipient and one signer. A key is never
shared across groups, so give staging and production different groups.

The signature's principal is still the environment. The runtime's `allowed_signers` line lists
every environment of the group (see [`--signers`](#the-runtime-opv-unseal)).

## Sealing: `opv sync`

There is no separate seal command. A sealed target is delivered by `opv sync` like any other,
with plan ids, `--expect-plan`, `--confirm`, receipts, `delivery verify` and `opv changed`:

```sh
opv plan prod --target box                          # what would be sealed again, and the plan id
opv sync prod --target box --confirm prod           # seal and write the bundles
opv changed prod --target box                       # exit 10: a source item moved since the seal
opv delivery verify prod --product api --target box # the bundle is the one recorded
```

- **Budget.** A seal makes the same 1Password reads as a sync to any target: one read per
  boundary item, one read of the signing key, the evidence write. The runtime makes none.
- **Whole set.** opv holds no runtime identity, so it cannot read a previous bundle's values.
  Any change (a written name, a pruned or retired name, a version that differs from the
  ledger) re-seals the whole bundle with every desired name. A retired key leaves the next
  bundle.
- **Nothing changed, nothing written.** A second `sync` with no change writes 0 names and
  leaves the file as it was.
- **Stale as a whole.** When the recipients, the signer or the name set change, every name is
  `would_change`, and the plan prints one line: `stale as a whole (recipients changed): every
  name is sealed again`.
- **Checked before any value read.** `plan` and `sync` verify the existing bundle's signature
  with `sealed.signer` first, before any value is read. A tampered bundle refuses (`input_invalid`) and is left alone; a
  bundle signed by another key is drift and never sets the revision. A signing key that does
  not match `sealed.signer` refuses (`input_invalid`, exit 2) before any value is read.
- **Atomic.** The file is written to a temporary file beside it, synced and renamed, under a
  lock on `<bundle>.lock`; a second seal of the same bundle while the lock is held refuses with
  `local_io_failed` (`subject.op` `seal_lock`: "another opv run is sealing <bundle>; retry when
  it finishes") and writes nothing.
- **Revision.** Each bundle carries `revision = max(previous + 1, now in Unix seconds)`, the
  previous one taken only from a bundle that verified with `sealed.signer`. A sealer whose clock
  is behind fails visibly, at the runtime's floor.
- **`opv changed` replaces the drift poll.** Run it on a schedule in CI, not on the runtime.

### Bundles in another repository: `--sealed-root`

`sealed.out` is relative to the configuration file. When the bundles live in another checkout
(a manifest or release repository), pass its path for this run; the flag is hidden from
`--help`:

```sh
opv sync prod --target box --confirm prod --sealed-root ../platform-manifests
```

The bundles are written under that folder at `sealed.out`, and nothing beside the
configuration. Commit and push them there. `plan`, `status` and `delivery verify` take the same
flag and read the bundles under that folder, so `opv plan --sealed-root <dir>` gives the plan id
the rooted sync checks, and its `Next:` line carries the flag.

### Committing bundles

Bundles are ciphertext; committing them is the first-class pattern. The signature covers exact
bytes, and `core.autocrlf` would add CRs on a Windows checkout, which `unseal` refuses as
`sealed_malformed`. Add to `.gitattributes`:

```text
*.opv-sealed binary
```

Bake every environment's bundle into one image if you like: each runtime opens only its own
environment's, and accepts only that environment's signer. A bundle shipped beside the image (a
volume, an object-store fetch) works too; away from the sealing checkout, `status` reports its
names absent.

## The bundle format: `opv-sealed/1`

One UTF-8 file, **LF line endings only**:

```text
opv-sealed v1
{"contract_digest":"sha256:…","created_at":"…","environment":"prod",…}   ← the header, one line
-----BEGIN AGE ENCRYPTED FILE-----
…age armored ciphertext of the payload…
-----END AGE ENCRYPTED FILE-----
-----BEGIN SSH SIGNATURE-----
…SSHSIG over every byte above this line, namespace opv-sealed…
-----END SSH SIGNATURE-----
```

- **The header is signed, plaintext and value-free**: canonical JSON (sorted keys, no
  whitespace) with `format`, `project`, `environment`, `product`, `target`, `revision`,
  `created_at`, `opv_version`, `plan_id`, `contract_digest`, `recipients` (fingerprints),
  `signer` (fingerprint), `names` (`[{name, destination}]`, `env:<NAME>` or
  `file:<path>`) and, with file keys, `secrets_dir_env`. Unknown fields are refused. Key names
  and the placement are readable by anyone holding the file; they are already in committed
  configuration.
- **Encrypt, then sign.** The payload (the values, bound to the header by its digest) is
  encrypted with age to the recipients; the signature covers the format line, the header and
  the ciphertext. `unseal` verifies before it decrypts.
- **Stock tools can check each part.** The signature is a standard SSHSIG, and the age block a
  standard age file:

  ```sh
  sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' api.opv-sealed > message
  sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p' api.opv-sealed > message.sig
  ssh-keygen -Y verify -f allowed_signers -I prod -n opv-sealed -s message.sig < message
  sed -n '/^-----BEGIN AGE/,/^-----END AGE/p' api.opv-sealed | age -d -i identity.txt > /dev/null
  ```

  `age -d` prints the framed payload, values included: send it nowhere but `/dev/null`.

## The runtime: `opv unseal`

```sh
opv unseal sealed/prod/api.opv-sealed --env prod --product api --signers /etc/opv/allowed_signers --verify-only
opv unseal sealed/prod/api.opv-sealed --env prod --product api --signers /etc/opv/allowed_signers --identity-file /run/secrets/opv_identity --json
opv unseal sealed/prod/api.opv-sealed --env prod --product api --signers /etc/opv/allowed_signers --identity-file /run/secrets/opv_identity --min-revision 1793795000 --exec -- ./server
```

`unseal` reads the bundle, the `allowed_signers` file and the identity, and nothing else. In
order it checks the signature, then the header's environment and product against `--env` and
`--product`, then the revision against `--min-revision`, then that the identity is a
recipient, and only then decrypts. One stderr line names what it opened:
`opv unseal: prod/api revision 1793795000 signer SHA256:… 7 names`.

| Mode | What it does |
|---|---|
| `--verify-only` | checks signature, header and revision, decrypts nothing. With an identity it also checks that the identity is a listed recipient; when the bundle has file keys it checks the RAM directory. No identity is needed. Use it as a staging smoke test and in release jobs |
| no mode (inspect) | also decrypts in memory and checks the payload against the signed header; prints the header and the names with their destinations, never a value |
| `--exec -- <cmd>` | delivers the values to the command; opv's exit code is the command's |

`--json` (not with `--exec`) prints one `opv.unseal/1` document: the bundle's header fields,
`names`, what was `checked` and `overridden`. It holds names and fingerprints only. An assistant
may run `--verify-only` and inspect; it never sees a value.

**`--signers`** is a strict subset of OpenSSH `allowed_signers`. The only line form is:

```text
prod namespaces="opv-sealed" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleEx opv-sealed-prod
staging-api,staging-worker namespaces="opv-sealed" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleStagingExampleStagingExampleSt opv-sealed-staging
```

The principals are environment names, comma-separated for a [trust group](#trust-groups);
patterns (`*`, `?`, `!`), other options (`cert-authority`, `valid-before`, ...), a missing
`namespaces=` and other key types are refused with the line number, and the whole file with
them. A signature counts only when it verifies with a line whose principals include the
bundle's environment.

**The identity** comes from `--identity-file <path>` (preferred: a platform secret file, a
Kubernetes volume, a root-owned 0400 file) or `--identity-env <VAR>` (environment-only
platforms such as Fly). It is never an argument, and the variable never reaches the command.
One of them is required except with `--verify-only`.

**`--min-revision <N>`** is the rollback floor, set by the deploy: the release that sealed
revision N deploys the runtime with `--min-revision N`, so an older bundle (which may hold a
revoked value) is refused before decryption. Read N in the release job with
`opv unseal … --verify-only --json` (`bundle.revision`). There is no local ratchet and no
expiry: a missed re-seal never becomes an outage.

**The command's environment** (`--exec`):

- the inherited environment, minus every `OP_*` and the `--identity-env` variable;
- plus the bundle's variables and, with file keys, the product's `secrets_dir_env`;
- **the bundle wins** over an inherited variable of the same name (an image's `ENV PORT`, a
  platform secret left from migration), with one stderr line naming it, never the value:
  `opv unseal: PORT from the bundle replaces the inherited value`.

With variables only, on Unix, opv replaces itself with the command: no process keeps the
values, signals reach the app, and the app is PID 1 in a container.

### File keys need a RAM directory

With file keys (Linux only), opv stays the parent: it writes the files into a private 0700
directory under `$XDG_RUNTIME_DIR` (files 0400, never disk), forwards signals, passes the exit
code through and removes the directory when the command exits. `$XDG_RUNTIME_DIR` must be an
absolute path to a directory owned by the app's user, on tmpfs or ramfs, and not writable by
others; otherwise nothing is written or started (`ram_dir_unavailable`). A stock container has
none, so mount one, and run with an init (`docker run --init` or tini), since opv is not one.
Here the app runs as uid 10001, which also owns the 0400 identity file on the host:

```sh
docker run --init \
  --tmpfs /run/opv:mode=0700,uid=10001 -e XDG_RUNTIME_DIR=/run/opv \
  -v /etc/opv/identity:/run/secrets/opv_identity:ro \
  --user 10001 example/api:1.4.0 \
  opv unseal /app/sealed/prod/api.opv-sealed --env prod --product api \
    --signers /app/allowed_signers --identity-file /run/secrets/opv_identity \
    --min-revision 1793795000 --exec -- ./server
```

On Kubernetes, mount an `emptyDir` with `medium: Memory` and point `XDG_RUNTIME_DIR` at a
directory the app's user creates in it (`mkdir -m 0700 /run/opv/rt`), since the volume's own
root is shared. `opv unseal --verify-only` on staging reports `runtime dir RAM-backed`, or the
refusal, before production starts.

### Refusals

Each stops before anything is decrypted or started, unless noted.

| `error.code` | Exit | When |
|---|---|---|
| `sealed_malformed` | 6 | missing file, over a limit, not `opv-sealed v1`, a CR byte, a malformed part, a header that is not canonical, an unsafe file path |
| `sealed_signature_invalid` | 6 | the signature fails, or no `allowed_signers` line for the bundle's environment, or the signers file is refused |
| `sealed_scope_mismatch` | 6 | the header's environment or product is not `--env` / `--product` |
| `sealed_revision_below_floor` | 6 | the revision is below `--min-revision` |
| `sealed_identity_unusable` | 2 | the identity cannot be read, or is not one `AGE-SECRET-KEY-1…` line |
| `sealed_not_a_recipient` | 7 | the identity is not a recipient of this bundle |
| `sealed_payload_mismatch` | 6 | after decryption: the payload does not match the signed header; nothing is delivered |
| `ram_dir_unavailable` | 6 | file keys without a RAM-backed `$XDG_RUNTIME_DIR` |
| `child_start_failed` | 3 | the command cannot start |

## The runtime identity: generate it into 1Password

The identity is an opv-managed secret like any other, in a product the sealed target does not
deliver:

```toml
[products.runtime]
boundary = "platform"

[products.runtime.keys.OPV_SEALED_IDENTITY]
kind = "secret"
environments = ["prod"]
rules = { age_identity = true }
```

```sh
opv propose generate prod runtime/OPV_SEALED_IDENTITY
opv apply <plan_id>
```

The person's `opv apply` makes a fresh X25519 identity, writes it straight into the empty
1Password field and prints only its public `age1…` recipient, which goes into
`sealed.recipients`. The identity is never shown. Use one identity per environment and product
unless a trust group shares one.

Deliver the identity to the runtime **once**, by a target with its own store or by the platform:

| Platform | Identity at rest | `unseal` flag |
|---|---|---|
| Docker host, Compose | a 0400 file on the host, owned by root or by the app's user, mounted read-only (Compose `secrets:` are such files). Plaintext at rest, inside the trust boundary "root on the host" | `--identity-file /run/secrets/opv_identity` |
| systemd | `systemd-creds` (encrypted at rest, TPM-bound where available) with `LoadCredentialEncrypted=` | `--identity-file $CREDENTIALS_DIRECTORY/opv_identity` |
| Kubernetes | a Secret delivered by opv's Kubernetes target, mounted as a volume | `--identity-file /var/run/opv/identity` |
| Fly | a Fly secret delivered by opv's Fly target (environment only) | `--identity-env OPV_SEALED_IDENTITY` |

Never fetch the identity with `opv run` at boot: that brings back the runtime dependency.

## Rotation

**Runtime identity:**

1. Generate a new identity (`opv propose generate`, then `opv apply`) into a new key.
2. Add its recipient beside the old one; `opv sync` re-seals to both (the bundle is stale as a
   whole).
3. Deliver the new identity and deploy.
4. Remove the old recipient; `opv sync` again.
5. Delete the old field.
6. **If the identity leaked, also rotate every value it could open** (R-U2): the old bundles in
   git history stay readable with it.

**Signing key** (environment `prod`):

1. Create a new SSH Key item in 1Password.
2. Add `prod namespaces="opv-sealed" ssh-ed25519 <new key>` to the runtime's `allowed_signers`
   and deploy.
3. Point `deploy_credentials` and `sealed.signer` at the new key; `opv sync`.
4. Remove the old line and deploy.

**Values:**

1. A change in 1Password makes `opv changed` exit 10.
2. `opv sync` re-seals.
3. The deploy passes `--min-revision` set to the new revision, so the old bundle, holding the
   revoked value, is refused.

## Migrating a platform from `opv run`

For a runtime that runs `opv run <env> --product <p> -- <cmd>` at every start, or a supervisor
that keeps its own bundle format:

1. Add the sealed target(s): one recipient and one signer per trust group, the signing key as
   an SSH Key item in `deploy_credentials`, `.gitattributes` with `*.opv-sealed binary`.
2. Generate the runtime identity and deliver it once.
3. **Re-seal every scope once:** `opv sync <env> --target <t>` for every environment and
   product, with `--sealed-root` when the bundles live in another repository; commit and push
   them.
4. Rebuild the runtime image with `allowed_signers`: one line per signer, its principals the
   environments it signs for.
5. **Dual-read cutover.** The runtime prefers the bundle and keeps `opv run` as the fallback; a
   supervisor with its own format picks the reader by the first line (`opv-sealed v1`).
   Run `opv unseal --verify-only` per bundle, staging first, with the identity.
6. Change the entrypoint to `opv unseal <bundle> --env <env> --product <p> --signers …
   --identity-file … --min-revision <N> --exec -- <cmd>`, or have the supervisor read the
   documented format.
7. Replace the drift poll with a scheduled `opv changed` in CI.
8. Once every scope starts from a bundle, remove the fallback and any old sealing script.
9. **After one full release cycle on bundles, revoke the runtime's service-account tokens.**
   Until then, they are the way back.
