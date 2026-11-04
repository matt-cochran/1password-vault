# DESIGN-FMECA vet: sealed target (#271), `docs/design/sealed-target.md`

Reviewer: independent; did not write the design. Date: 2026-11-04. Method: the owner's
DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal requirements, three
phases, output format, verification checklist), applied as written.

Owner question: **is this design sound, secure and right-sized?**

**Short answer.** The shape is right: a staged, live target delivered by `opv sync`, one file
holding a value-free header, an age X25519 ciphertext and an SSHSIG over both, verified before
anything is decrypted. The crypto construction is sound in what it signs (format line, header
**and** ciphertext, exact bytes) and in what it pins (format v1, ed25519, sha512, namespace,
X25519-only identity). **As written it is not safe to ship, for one security reason and several
feasibility reasons:**

- **Signers are not bound to an environment.** `unseal` accepts any `allowed_signers` line in the
  `opv-sealed` namespace and never ties it to `--env`. With the design's own build-once pattern
  (every environment's bundle in one image, §5.6-1), a single baked `allowed_signers` lists the
  staging and production signers, and anyone who can read the **staging** signing key can sign a
  bundle that says `environment: prod`, encrypted to the public prod recipient, and choose prod's
  `DATABASE_URL`. That breaks "staging can't touch production" through the integrity side.
- **The signer-mismatch cause cannot be built.** `CredentialRejected` carries `seen: Observed`,
  which only the runner may construct (`tests/observed_seal.rs`); a local key comparison has no
  failed call. Use `InputInvalid { kind: DeployCredentials }` (exit 2), as the HTTP login does.
- **The whole-set rule misses a prune-only change.** A name retired from configuration with
  nothing else changed stages nothing, so the old bundle (holding a possibly revoked credential)
  stays deliverable.
- **Two products with file keys on one sealed target fail `config check`**, because the declared
  `FileCapability::Native` directory is a constant string and `check_file_mounts` refuses two
  products rendering the same directory.
- **`write_file` follows `..`**, and in `unseal` the file paths come from the bundle header.
- **The bundle format is called a contract with a downstream platform, but the design does not
  start from that platform's format.** It invents one.

Two runtime choices turn a mistake into the outage this issue exists to remove: refusing a name
already in the inherited environment, and the ratchet file (which blocks a legitimate rollback).
File keys need a RAM directory that a default Docker container does not have.

All of this is fixable with small changes that reuse existing structures. With the changes and
the scope cut below, no High risk remains. One Medium remains by construction (offline delivery
has no central revocation, U2); removing it would bring back the runtime dependency the issue
removes. The first slice drops from **~52 h / 13 lanes to ~43 h / 12 lanes** (≈40 h if file keys
wait).

Evidence levels: **Proven** (industry standard, or shown in code here), **Adapted** (reasonable,
not proven here), **Speculative** (assumed). Paths are relative to
`/home/mc/.cache/lanes/opv-0180-design` (rev `9b4f7b9b`, design commit on `7cc0b6dd`). Crate
facts were checked in a scratch crate (`/tmp/claude-1000/sealed-probe/p`) with this repository's
`deny.toml`, cargo-deny 0.20.2, and the fetched sources of `age 0.12.1` and `ssh-key 0.6.7`.

---

## 0. Claims checked against the code and crates (summary)

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| A staged target with `live() == true`, as GitHub and HTTP (§8.1) | **Holds** | `src/ports.rs:93-102` |
| Config travels in the bundle via `Channel::Store`; "every provider today uses `RuntimeEnv`, `Variables` or `Declined` there" (§3.2) | **Premise wrong, conclusion right.** Fly (`fly.config = "secrets"`), Kubernetes and Azure already use `Channel::Store` for config. When config and secret share one store label and the target has no `runtime_subject`, config is **staged like a secret**, which is exactly what sealed needs. The `RuntimeEnv` fallback would be wrong: config would not be staged, and a config key with `file` would be refused (`ConfigFileNeedsObject`) | `src/adapters/fly/config.rs:289-306`; `src/adapters/kubernetes/config.rs:458-466`; `src/adapters/azure/config.rs:547-549`; `src/domain/plan.rs:468-484`; `src/config.rs:1521-1528` |
| Files: `FileCapability::Native { dir: "<secrets_dir_env> on the runtime" }` (§3.2) | **Breaks `config check`** when two products with file keys share the target: the constant `dir` renders the same for both, a `Collision` that points at a nonexistent `sealed.secrets_dir` | `src/config.rs:1483-1565` (render `:1551`, refusal `:1553-1561`) |
| Signer mismatch is `CredentialRejected { DeployCredentials }`, exit 7 (§6.2) | **Infeasible**: the variant needs `seen: Observed`; only the runner builds one. The precedent for a local credential mismatch is `InputInvalid { kind: DeployCredentials }` (exit 2) | `src/cause/mod.rs:691-696`, `:2095`; `tests/observed_seal.rs:76-95`; `src/adapters/http/login.rs:39-48,115` |
| "No new `lost_call` caller" (§8.2-9, J7) | **Holds if T2 is applied**. The list is `fly/mod.rs`, `kubernetes/mod.rs`, `host.rs`, not one caller per adapter. Building `CredentialRejected` would push a fourth caller in | `tests/observed_seal.rs:44-75` |
| Signing "as a runner effect" (§6.2) | **Justified (Adapted)**: `DeployLogin` reaches calls only through `EnvRunner`'s per-program env (the store never holds the login), so a store cannot reach the key any other way. No retries or observation are needed: signing is pure and cannot fail on a remote side | `src/provider.rs:183-194`; `src/app/signin.rs:156-164,421-437` |
| `system_of` mislabels `http` as GitHub (§8.2-5) | **Confirmed.** Arms: `fly`, `azure`, `kubernetes`, `_ => GitHub`; the HTTP provider's section is `"http"`. `System::Https` **already exists**, so the fix is one arm, not a new variant. It reaches users through `SecretNotStored` (minted deploy token) and `Guard::ProviderHidesValues` (`import`) | `src/provider.rs:679-687`; `src/adapters/http/provider.rs:89`; `src/cause/subject.rs:107-108`; `src/app/target_credentials.rs:268`; `src/app/import.rs:211` |
| FR-12 and FR-37 guards stay green (§8.1) | **Hold.** FR-12's needles are only `fly::`/`adapters::fly`. Adding `adapters::sealed` and `sealedtarget` to `provider_named` works with its `\b…\b` regex. **Side finding:** the word list has no HTTP entry, so core could name the HTTP adapter unguarded | `src/app/mod.rs:2128-2145,2281-2306,2313-2335` |
| Registration points 1-4, 11-14 | **Hold** at the cited lines | `src/adapters/mod.rs`; `src/adapters/registry.rs:4,8-14,95-97`; `src/main.rs:1051,2688,4788`; `tests/cli_ux.rs:92-99`; `src/schema.rs:520` |
| The 19 wiring points are complete | **Missing:** every new `Cause` needs an entry in `cause::codes::one_of_each()`, a retry class and human flag, the generated `docs/usage.md` error-code table (checked by `tests/docs_commands.rs`) and `agent_guidance`'s `error_codes` | `src/cause/codes.rs:455`; `src/schema.rs:801-835`; `tests/docs_commands.rs:400-420`; `tests/agent_guidance.rs:158-169` |
| The whole-set batch triggers "when the plan stages anything or `stale` is set" (§8.2-7) | **Incomplete**: a prune-only change and immutable-held keys are not covered (`plan.prune`, `plan.held_immutable` sit beside `plan.stage`) | `src/domain/plan.rs:169-185`; `src/app/sync.rs:1100-1128` |
| Reusing local delivery's RAM directory (§5.5) | **Holds as code; fails as a default in containers**: it requires `$XDG_RUNTIME_DIR`, user-owned, on tmpfs/ramfs, Linux only. A stock container has none | `src/app/local_delivery.rs:201-216` |
| `write_file` is a safe destination writer (§5.5) | **Only for validated paths**: it splits on `/` and `mkdirat`/`openat`s each part; a `..` part is a real directory, so it escapes the private directory. Local delivery's paths come from validated configuration; `unseal`'s would come from the bundle | `src/app/local_delivery.rs:313-352` |
| Hardening at `:9`, `cloexec_inherited` at `:24` (§5.5) | **Holds** | `src/hardening.rs:9,24` |
| `age` 0.12.1: two `cargo deny` errors, neither reachable (§6.4) | **Holds.** `basic-toml` (RUSTSEC-2026-0374) is only under the `i18n-embed-fl` proc macro. `crypto-bigint 0.5.5` (RUSTSEC-2026-0387) comes in via `p256`, an **unconditional** dependency of age and of `hpke`, and runs only for p256-tag/hybrid stanzas | probe `cargo deny check advisories`; `cargo tree -i crypto-bigint` |
| "127 crates" (§6.4, D2) | **Overstated for opv**: age plus ssh-key resolve to 135 crates, of which **~87 are new** to opv's `Cargo.lock`. The tree also brings `scrypt`, `ml-kem` and a pre-release `kem 0.3.0-pre.0` | probe `cargo tree` vs `Cargo.lock` |
| x25519 identity zeroizes (§6.3) | **Holds**: `x25519-dalek` resolves with `zeroize` and `static_secrets` | probe `cargo tree -e features -i x25519-dalek` |
| age chunk buffers: "spike checks" (§6.3) | **Resolved: not zeroized.** Only `PayloadKey` has a zeroizing `Drop`. `StreamWriter`/`StreamReader` hold a plain `chunk: Vec<u8>` | `age-0.12.1/src/primitives/stream.rs:26-34,222-226` |
| `ssh-key` 0.6.7 does SSHSIG sign and verify (§6.2) | **Holds** (`PrivateKey::sign`, `PublicKey::verify`). **It has no `allowed_signers` parser** (only `authorized_keys`, `known_hosts`), so opv must write one | `ssh-key-0.6.7/src/private.rs:314`, `public.rs:213`, `src/` listing |
| The SSH Key item's private key shape (§6.2, S0) | **Adapted, unverified here**: `op` returns PKCS#8 for ed25519 by default, and an OpenSSH form is available (`?ssh-format=openssh` on `op read`). `ssh-key` parses only OpenSSH | — |
| Payload limits (256 names, 1 MiB per value) as the remote payload (§5.3) | **Holds** | `src/app/remote_delivery.rs:165-230` |

---

## Phase 1: Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1. Sealed provider delivered by `sync` (D1) | Plan, confirm, receipts, `delivery verify`, `changed` for free | **Essential** (Proven shape: GitHub/HTTP staged-live) | FR-60 one way; reuses every guard | — | A second delivery path |
| C2. One-file bundle: format line, header, age armor, SSHSIG | Ship ciphertext with its integrity | **Essential** (Adapted) | One artifact cannot drift; stock tools can check each part | — | Out-of-step files |
| C3. age, X25519 only, crate in process | Confidentiality to per-env recipients | **Essential** (Proven) | Standard format, AEAD | `age` CLI (D2-b) puts a binary on every image | No encryption |
| C4. SSHSIG ed25519, `ssh-key` crate | Integrity and origin | **Essential** (Proven) | age is not a signature (§6.1, correct) | minisign (second key ecosystem) | Anyone with a public recipient forges bundles |
| C5. `allowed_signers` on the runtime | Which signers a runtime accepts | **Essential, under-specified** (Adapted: hand parser) | Needed for rotation overlap | A strict subset parser **with principal = environment** (T1) | — |
| C6. Signing key = `deploy_credentials` SSH Key item; sign via `EnvRunner` | Vault access decides who seals | **Essential** (Adapted) | Only channel from a login to a store's effect (`signin.rs:421-437`) | — | Keys outside 1Password |
| C7. Whole-set port on `StagedStore` | Rewrite every name when any changes | **Essential, simplify** | opv cannot read old values | `fn whole_set(&self) -> bool` (default false); expansion in `prepare_staged` **before** the plan id; triggers on stage ∪ prune ∪ list mismatch | Partial bundles |
| C8. Contract digest plus a plan "reason row" | Recipient/signer/name change marks stale | **Digest Essential; reason row Useful** | Acceptance 6 | `list()` returns versions that cannot match the ledger when the digest differs (every name `would_change`), and `preflight` prints one warning line with the reason: an existing channel, no new plan row type | Recipient change silently ignored |
| C9. Revision `max(prev+1, now)` | Monotone, stateless across checkouts | **Essential** (Adapted) | Cheap | Keep; `prev` from evidence and **signature-verified** header only, `checked_add` | Replay of old bundles |
| C10. `--min-revision` deploy floor | Rollback protection | **Essential** (cheap) | Build-once-deploy-twice knows the revision | — | Old bundle with revoked value accepted |
| C11. `--ratchet` file | Floor on long-lived hosts | **Speculative → remove from slice** | No consumer asked. It blocks legitimate rollbacks (R4). One cause, three tests, a file format | Deploy floor | Low (deploy floor remains) |
| C12. `unseal` verify/inspect, `--verify-only`, `--json` | Runtime and pipeline check | **Essential** | Acceptance 3 | — | — |
| C13. `--exec` variables by `execve` | Replace `opv run` at start | **Essential** (Proven: `CommandExt::exec`) | Acceptance 4 | — | — |
| C14. `--exec` file keys, supervised RAM directory | tmpfs files | **Useful** (acceptance 4 names it) | Reuses local delivery | Defer if the downstream has no file keys (owner) | Apps needing files use variables |
| C15. `--identity-env` (D4-b) | Env-only platforms (Fly) | **Useful** | Fly has no file secrets | — | Fly runtimes excluded |
| C16. `sealed_name_collision` refusal | Catch a leftover platform secret | **Unjustified as a refusal** | Turns a migration leftover or an image `ENV PORT` into a start outage, discovered at the worst time | Bundle wins, plus one names-only stderr notice | Silent shadowing (mitigated by the notice) |
| C17. Payload header-digest binding | Plaintext bound to the verified header | **Useful** (cheap defense in depth) | Guards the library/downstream path | — | — |
| C18. `op_calls` in every command's `--json` (C2 lane) | Budget assertion | **Useful → demote** | Acceptance 2 asks for a counting **test**, which `test_support::op_calls` already gives (`src/app/mod.rs:2665`) | Counting-fake test now, JSON field later (generic, its own issue) | None for acceptance |
| C19. `opv generate` `age_identity` recipe (G1) | Value-safe bootstrap of the identity | **Essential** (Adapted) | Without it a person runs `age-keygen` to a disk file or passes the key to `op item create` in argv | — | Identity on disk or in argv |
| C20. Header `source_versions`, `opv_version` | Diagnostics | **Speculative** | `opv changed` reads source versions from the delivery item, not the header. They widen a frozen contract and expose item churn | Drop `source_versions`; keep `plan_id`, `revision`, `created_at` | None |
| C21. Library crate (D7), publishing (X1), `propose` (R1) | Later consumers | **Demoted** (agree with the design) | No consumer yet | — | Acceptance 4's "library" unmet (owner) |
| C22. `system_of` fix | Correct labels | **Essential, separate** | A bug today, not a sealed feature | Make it a required `Provider::system()` method so a new provider cannot fall through | Mislabelled HTTP causes |

### Revised Architecture

- **Retained:** C1, C2, C3, C4, C6, C9, C10, C12, C13, C15, C17, C19.
- **Simplified:**
  - C5: strict `allowed_signers` subset with **principal = environment**.
  - C7: boolean whole-set flag, expanded in `prepare_staged` before the plan id.
  - C8: staleness through `list()` plus a preflight line, no new plan row type.
  - C16: refusal becomes override plus notice.
  - C18: test only.
  - C20: smaller header.
- **Removed from the slice:** C11 ratchet.
- **Demoted:** C14 (owner: ship or defer file keys), C21.
- **Moved out:** C22 is a stand-alone fix PR now (plus HTTP words in `provider_named`).

---

## Phase 2: FMECA + poka-yoke + TRIZ

Risk = Severity × Probability: H×H, H×M, M×H are **High**; H×L, L×H, M×M **Medium**; M×L, L×L
**Low**. Ids: T technical, R runtime, U UX, P project.

### Iteration 1 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Technical | Cross-environment forgery | `--signers` lines are filtered by namespace only (§4.2); signer not bound to `--env`; §5.6-1 bakes all environments into one image | A holder of the staging signer sets production values (`DATABASE_URL` to an attacker host) | High | Medium | **Prevention:** an `allowed_signers` line counts only if its principals include the header's `environment` exactly (`ssh-keygen -Y verify -I prod -n opv-sealed` semantics). Plus load rule `sealed_signer_shared`: one signer per environment, like recipients. Unit test: a staging-signed `prod` header is refused before decryption | `sealed_signature_invalid` with "no opv-sealed signer for principal prod"; `--verify-only` in the deploy pipeline | #1 Segmentation: one trust anchor per environment inside one file | Low | Low |
| T2 | Technical | Signer-mismatch cause cannot compile | `CredentialRejected` needs `Observed` (`src/cause/mod.rs:691-696`); only the runner builds it (`tests/observed_seal.rs:76-95`) | Guard failure, a forged observation, or a new `lost_call` caller | Medium | High | Use `InputInvalid { kind: DeployCredentials, field: "public key" }` (exit 2), as `http/login.rs:39-48` | Code `input_invalid` names the item field | Reuse the existing precedent | Low | Low |
| T3 | Technical | Retired name stays in the bundle | Whole-set trigger is "stages anything or stale" (§8.2-7); a prune-only plan stages nothing | A revoked credential remains deliverable | High | Medium | Expansion triggers on `stage ∪ prune ∪ list-version mismatch`, includes `held_immutable` values; `remove()` is unreachable for whole-set stores (`Bug` if called). Test: drop one name, nothing else changes, the next sync re-seals without it | `plan` shows `would_prune`; `unseal --json` names list | #2 Taking out: a whole-set store has no per-name remove | Low | Low |
| T4 | Technical | Plan id differs from what sync writes | Expansion done in `run_staged` after `target_id` (`src/app/sync.rs:1056`) | `--expect-plan` passes but more is written | Medium | Medium | Expand in `prepare_staged` before `c.target_id` | `plan_changed` would fire otherwise; test pins id | #10 Preliminary action | Low | Low |
| T5 | Technical | `config check` refuses multi-product file keys | Constant `Native { dir }` collides (`src/config.rs:1551-1561`) | Valid configuration refused, error points at a nonexistent field | Medium | Medium | `dir` carries `{product}` (e.g. `"$<secrets_dir_env> on the runtime ({product})"`); test with two products | `config check` | — | Low | Low |
| T6 | Technical | Path traversal on unseal | Header `file:<path>` from the bundle; `write_file` follows `..` (`local_delivery.rs:317-339`) | A file written outside the private directory | High | Low | Codec refuses absolute paths, `.`/`..`/empty parts and NUL, with the configuration's own rule; `write_file` also rejects them (fail fast for every caller) | `sealed_malformed` naming the field | — | Low | Low |
| T7 | Project | Format contract mismatch with the downstream | §1.1 says the downstream already builds "the same shape"; the design invents a layout (plaintext header, encrypt-then-sign; the issue says the **signed payload** holds the map and header fields) | The downstream cannot switch, or a v2 in the first month | High | Medium | Before B1: obtain the downstream's format or fixture; owner decides (new **D9**) which side adapts. S0 KATs include one downstream-made bundle | KAT 1 passes on a downstream fixture | #23 Feedback before freezing | Low | Low |
| T8 | Technical | Committed bundles fail on Windows checkouts | Signature over exact bytes; `core.autocrlf` rewrites LF | Every start refused after a Windows commit | Medium | Medium | Format is LF-only; a CR anywhere is `sealed_malformed` with the fix ("add `*.opv-sealed binary` to `.gitattributes`"); docs pattern 1 includes the line | Distinct refusal text | — | Low | Low |
| T9 | Technical | Two parsers read one header differently | JSON duplicate keys or non-canonical forms; downstream reimplements | A signer-produced header means two things | Medium | Low | Parser re-serializes canonically and requires byte equality with the signed line; first line and `format` must agree | `sealed_malformed` | — | Low | Low |
| T10 | Technical | Planted header drives the revision | `prev` read from the file at `sealed.out` (§5.4) | Overflow, or revisions pinned far in the future | Medium | Low | Use `prev` from the evidence line and from the header **only after** verifying it with `sealed.signer`; `checked_add` | A foreign file is `drifted_on_target` | — | Low | Low |
| T11 | Technical | `deny.toml` ignore masks a future reachable path | cargo-deny ignores are global per advisory id | A later crate makes `crypto-bigint` timing reachable | Medium | Low | Two dated ignores with reasons **and** `[bans] deny = [{ crate = "p256", wrappers = ["age", "hpke"] }]`; parse recipients only with `age::x25519::Recipient::from_str`, never a generic parser | `cargo deny` fails if any other crate pulls p256 | #24 Intermediary: a ban fences the ignore | Low | Low |
| T12 | Technical | Plaintext in freed memory | age's `StreamReader`/`StreamWriter` `chunk: Vec<u8>` is not zeroized (verified) | Up to 64 KiB of values linger in heap | Low | High | Accept with existing hardening (non-dumpable, `RLIMIT_CORE` 0, `src/hardening.rs:9`); variables mode `exec`s at once; record as a known residual in docs | — | — | Low | Medium |
| T13 | Technical | `allowed_signers` misparsed | No parser in `ssh-key` 0.6.7; options like `cert-authority`, `valid-before` | A line trusted more widely than meant | Medium | Medium | Strict subset: `principals namespaces="opv-sealed" ssh-ed25519 <b64> [comment]`; any other option refused with its name; KAT against `ssh-keygen -Y verify` in S0 | `sealed_signature_invalid` names the line number | — | Low | Low |
| T14 | Technical | Identity sealed into its own bundle | `OPV_SEALED_IDENTITY` declared in a product the sealed target delivers (§7.1) | Bootstrap impossible; confusing | Medium | Medium | Load rule: a key with `age_identity = true` is never delivered by a sealed target | `config check` names the key | — | Low | Low |
| T15 | Technical | Wrong config channel fallback | §3.2's `RuntimeEnv` fallback | Config not in the bundle; `file` config refused | Medium | Low | Declare `Channel::Store { label: "sealed bundle" }` for both secret and config (proven `config_as_secret` path) and drop the fallback | Channel contract test row | — | Low | Low |
| T16 | Technical | Signing key format unreadable | PKCS#8 vs OpenSSH from `op` | Every seal fails | Medium | Medium | S0 KAT on a real SSH Key item; read the OpenSSH form; refusal names the field | `input_invalid` names the field | — | Low | Low |
| R1 | Runtime | Start refused for an inherited name | `sealed_name_collision` (§4.2, §5.5); images set `ENV PORT`, `NODE_ENV` | Service does not start; same outage class as #271 | High | Medium | Bundle wins; one stderr line per overridden **name**; `declared_only` still applies | stderr notice in container logs | #22 Turn harm into benefit: the signal without the outage | Low | Low |
| R2 | Runtime | File keys refused in containers | No `$XDG_RUNTIME_DIR` tmpfs in a stock container (`local_delivery.rs:201-216`) | `ram_dir_unavailable` at every start | High | High | Docs per platform: `--tmpfs /run/opv:mode=0700,uid=<app>` and `XDG_RUNTIME_DIR=/run/opv`. `--verify-only` also runs the RAM-directory check when the bundle has file keys, so staging smoke catches it | `ram_dir_unavailable` at verify time | #11 Beforehand cushioning | Medium | Low |
| R3 | Runtime | Zombies or lost signals as PID 1 | Supervised mode keeps opv as parent | Orphans accumulate; slow stop | Medium | Medium | Docs: `docker run --init` (or tini). Test: SIGTERM forwarded, exit code passed through | Container exit codes | — | Low | Low |
| R4 | Runtime | Rollback blocked | Ratchet written before exec (§5.4) | Rolling back a bad deploy refused on a long-lived host | High | Medium | **Remove** the ratchet from the slice; the deploy floor remains | — | Simplification | — | — |
| R5 | Runtime | Undefined Windows behaviour | `CommandExt::exec` is Unix-only; RAM directory Linux-only | Divergent or untested path | Low | Medium | Specify: off Unix, `--exec` spawns, waits and passes the exit code; file keys refused with the existing cause | Unit test on Windows CI | — | Low | Low |
| R6 | Runtime | Identity readable via the parent's environment | `--identity-env` with supervised mode: `/proc/<pid>/environ` keeps the original strings | Same-user process reads the identity | Medium | Low | Existing non-dumpable hardening makes `/proc/<pid>/environ` root-only; document `--identity-file` as preferred | — | — | Low | Low |
| R7 | Runtime | Bundle written, evidence not recorded | Write is a local file, not a runner write (`src/runner.rs:441-444`) | `BudgetSpent` says no write started; next plan reports drift on opv's own bundle | Medium | Low | `list()` verifies the header against `sealed.signer`: an opv-signed bundle without evidence is the existing `not_recorded` state, a foreign one is drift | Row state `not_recorded` | — | Low | Low |
| U1 | UX | Every name "missing" away from the sealer | `Store::list` reads a local file; pattern 2 bundles are not in the checkout | `status` alarms; CI re-seals every run (revision churn) | Medium | High | v1 documents pattern 1 (commit bundles; sync where they live). A missing file is `absent` with a note "bundle not in this checkout", never drift | Status note | — | Low | Low |
| U2 | UX / security | No central revocation of a runtime identity | Offline decryption by design (§7.2, honest) | A leaked identity opens every bundle ever sealed to it, including git history | High | Low | Per environment **and product** identity by default; rotation runbook (§7.3); `--min-revision` stops old bundles at deploy; docs state "rotate the values it opened" | `opv changed` after rotation; header recipient fingerprints | Contradiction: offline availability vs central revocation. #15 Dynamics only partly applies; removing the risk restores the runtime dependency | High | Low |
| U3 | UX | Identity at rest on a plain Docker host | §7.4 "Docker secret or a bind-mounted file from `opv run` local delivery (tmpfs)": compose secrets are host files; the tmpfs path needs `op` at every boot | Hidden plaintext key, or the dependency returns at reboot | Medium | High | Docs say it plainly: a root-owned 0400 file (inside the stated trust boundary "root on the host"), or `systemd-creds` (TPM). Drop the tmpfs-from-`opv run` row | — | — | Low | Low |
| U4 | UX | Wrong identity found only at start | `--verify-only` takes no identity | Start-time `sealed_not_a_recipient` | Medium | Medium | `--verify-only` optionally takes the identity, derives its public recipient and checks membership against the header fingerprints, with no decryption | Pipeline exit 7 | — | Low | Low |
| P1 | Project | Over-scoped first slice | Ratchet, `op_calls` on four commands, a reason row, a collision refusal, header extras | ~52 h; more golden surfaces and causes to own | Medium | Medium | The cuts in "Recommended first slice" | Plan hours | Simplification | Low | Low |
| P2 | Project | Wiring points missed | Table §8.2 omits `one_of_each`, usage.md error table, agent guidance | Red CI late in the lane | Low | High | Add them to U1's file list | `tests/docs_commands.rs`, `tests/agent_guidance.rs` | — | Low | Low |
| P3 | Project | Acceptance 4 "and the library" unmet | D7 defers the crate | Issue cannot close as written | Low | High | Owner amends acceptance or accepts the deferral explicitly | Issue checklist | — | Low | Low |

### Remaining Risks After Iteration 1

- **High:** none.
- **Medium:** U2 (constrained). T12 is Low×Medium = Low.
- **Low:** all others. R4 eliminated.

### Iteration Summary (1)

- **Key mitigations:**
  - T1: signer bound to the environment through `allowed_signers` principals;
  - T2: `InputInvalid` instead of `CredentialRejected`;
  - T3/T4: complete the whole-set trigger, before the plan id;
  - T6: path validation;
  - T7: format reconciliation before B1;
  - R1: override plus notice;
  - R2: RAM directory checked at verify time.
- **Simplifications:** ratchet removed; reason row replaced by `list()` and a preflight line;
  `op_calls` JSON deferred; header trimmed; `system_of` moved out.
- **Trade-offs introduced:**
  - The principal requirement makes `allowed_signers` stricter than a git-signing file. That is
    intended, and `--verify-only` catches a wrong file before shipping.
  - Override-plus-notice gives up a hard stop at migration time.
- **Continue?** One more pass over the new mechanisms.

### Iteration 2 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1b | UX | Runtime refuses after a correct seal | `allowed_signers` lacks the principal line | Start refused | High | Medium | Docs and `opv guide` give the exact line; `unseal` error prints the expected principal and namespace; the deploy pipeline runs `--verify-only` | `sealed_signature_invalid`, pipeline fails before ship | #11 Beforehand cushioning | Low | Low |
| R1b | Runtime | Override hides a wrong platform value | Bundle wins silently except for stderr | A stale platform secret is ignored, which is the desired result; a deliberate platform override no longer works | Low | Medium | Notice names it; docs: put the value in 1Password | stderr | — | Low | Low |
| C7b | Technical | Expansion forgets a key kind | Config-as-secret keys and immutable keys come from different plan fields | Partial bundle | Medium | Low | One function builds the batch from `plan.rows` (every desired, delivered row) and asserts it equals the header `names` before signing | Unit test; `sealed_payload_mismatch` impossible by construction | — | Low | Low |

### Remaining Risks After Iteration 2

- **High:** none. **Medium:** U2 (constrained, see Final Outcome). **Low:** all others.

### Iteration Summary (2)

No new High or Medium risks. Stop.

---

## The security trade-off against "1Password vault access is the only permission system"

The design's account (§7.2) is honest and I agree with its framing, with three corrections.

1. **Who can seal, generate and run** is still decided by vault access, and opv adds no roles.
   This holds.
2. **New trust anchors live outside 1Password:** `sealed.recipients`, `sealed.signer` and, after
   T1, the runtime's `allowed_signers`. They are public keys, reviewed like code, so they do not
   grant access. But a reviewer who approves an `allowed_signers` change approves **who may set
   production values**. The docs must say so. After T1, each line is scoped to one environment.
3. **Revocation stops being a 1Password action.** Removing a person's vault access no longer
   stops a runtime identity they once read. The same is true today of any value they once read,
   but a bundle is a durable, **re-decryptable** copy of every value, kept in git history. The
   honest rule (§7.3-7) is the only one: a leaked identity means rotating the values it opened.
   Per environment-and-product identities shrink that set. This is U2's constrained residual.
   The owner should accept it explicitly, because it is the price of removing the runtime
   dependency.

---

## Phase 3: Systemic Risk Review

- **Calibration risk:** no scores or confidences are computed. The trust signals are binary
  (signature, scope, floor). The calibration that matters is the KAT set: interoperability with
  `age`/`ssh-keygen` in S0, **and one downstream-produced bundle** (T7). The hours are the
  design's own and are unvalidated. My revisions are relative, not measured.
- **Observability risk:**
  - Sealer side: plan rows, receipts and `delivery verify` are existing and adequate.
  - Runtime side: today a start leaves no trace in 1Password, by design. **Add one stderr line at
    `unseal --exec` start**, for example `opv unseal: prod/api revision N signer SHA256:… k
    names`. Container logs then show which bundle started, and a rollback or stale bundle can be
    seen without values.
  - Bad decisions (a wrong signer file, a missing RAM directory) are caught at `--verify-only` in
    the pipeline (T1b, R2), not at start.
- **Complexity vs utility:** 52 h is more than the acceptance needs. The ratchet, the four-command
  `op_calls` field, the plan reason row and the collision refusal add causes, golden updates and
  tests without serving an acceptance item. The cuts below keep every acceptance item except the
  library (D7).
- **Oversimplification check:** the following are **not** cut, because each removes a real
  failure:
  - the whole-set port (C1 is needed: the store has no values for unchanged names);
  - G1 (it is the only value-safe way to mint the identity: no disk file, no argv);
  - signature-before-decrypt;
  - the deploy floor;
  - the recipient and signer uniqueness rules.

  `--identity-env` stays for Fly. File keys are the one item where cutting is a real loss
  (acceptance 4), so it is the owner's call.
- **Incremental delivery and rollback:** the slices are additive: a new provider, a new command
  and one defaulted port method. Rollback means removing the target section, and the runtime goes
  back to `opv run`. Migration steps §13 are sound. Step 6 (revoke the runtime token) should come
  only after one full release cycle on bundles.

### Recommended first slice

| Lane | Change vs design | Hours |
|---|---|---|
| S0 spike | + downstream format/fixture (T7), SSH Key item format (T16), `[bans]` wrapper (T11), `allowed_signers` KAT (T13) | 3 |
| B1 format | + path rule (T6), LF-only (T8), canonical re-serialize (T9), header without `source_versions` | 4 |
| B2 crypto | + strict `allowed_signers` subset with principal = environment (T1, T13) | 5 |
| P1 provider | − `system_of` (moved out); + `sealed_signer_shared`, identity-not-sealed rule (T14), `{product}` file dir (T5), `Store`/`Store` channels (T15) | 4 |
| P2 sign via `EnvRunner` + SSH Key login | pure effect, no retries; mismatch is `InputInvalid` (T2) | 3 |
| P3 store | + verified-header `prev` (T10), `not_recorded` for opv-signed unrecorded bundles (R7); + counting-fake test (was C2) | 4 |
| C1 whole-set | `whole_set() -> bool`; expansion in `prepare_staged` on stage ∪ prune ∪ mismatch (T3, T4); staleness via `list()` + preflight line | 3 |
| C2 `op_calls` JSON | **deferred** (generic issue) | 0 |
| U1 unseal verify | − ratchet; + identity membership in `--verify-only` (U4), cause catalog wiring (P2), start line | 4 |
| U2 exec | override plus notice (R1); RAM check at verify (R2); Windows spawn (R5) | 4 |
| G1 generate | unchanged | 2 |
| E1 e2e | fewer causes | 4 |
| D1d docs | + `.gitattributes`, principal lines, `--init`, tmpfs mount, identity-at-rest honesty (U3) | 3 |

**Total ≈ 43 h, 12 lanes** (was ~52 h, 13). If the owner defers file keys: U2 becomes about 2.5 h
and E1 about 3 h, **≈ 40.5 h**. Critical path: S0 → B1 → B2 → P2 → P3 → E1 → D1d ≈ 26 h.

A separate fix PR now, outside 0.18:
- `system_of` gets `"http" => System::Https`;
- better: replace `system_of` with a required `Provider::system()`, so no provider can fall
  through to GitHub;
- add HTTP words to `provider_named`.

About 1 h.

### Final Outcome

- **High risks:** 9 in Iteration 1 (T1, T3, T7, R1, R2, R4, U1, U3, and T2 as M×H). **0** at
  the end.
- **Medium risks:** 14 in Iteration 1 (Low: 7). **1** at the end: U2, no central revocation of an offline
  identity. Lowering it further would need an online check at start, which is the 1Password
  runtime dependency the issue removes. That violates the objective, so it stays Medium and is
  recorded for explicit owner acceptance.
- **Verdict:**
  - **Secure:** yes, with T1 (environment-bound signers) and T6 (path rule). The construction
    (sign over header and ciphertext, verify before decrypt, pinned algorithms, X25519-only
    identity, scope in the signed header) is sound.
  - **Feasible:** yes, with T2, T3, T5 and T15 corrected. The `deny.toml` ignores are
    acceptable, provided they are fenced by a `[bans]` wrapper and the recipient parser is
    type-specific.

Verification checklist (method):
- architecture judged before mitigation ✔;
- components classified ✔;
- simplification used as mitigation (C11, C16, C18, C20, C8) ✔;
- all four domains ✔;
- full FMECA fields ✔;
- observability per mitigation ✔;
- iterated to the stop condition ✔;
- no unnecessary complexity added (one strict parser rule, one flag reduced to a bool) ✔;
- no fabricated numbers (hours are the design's, adjusted relatively; crate counts measured) ✔;
- no critical capability lost (file keys left to the owner) ✔.

---

## Conflicts with the design's recommended owner decisions

1. **D1 (sync target):** agree.
2. **D2 (age crate, two ignores):** agree, with conditions:
   - add a `[bans]` wrapper so `p256` enters only through `age`/`hpke`;
   - parse recipients only with `age::x25519::Recipient`;
   - correct the weight to about 87 new crates (135 resolved);
   - note `scrypt`, `ml-kem` and a pre-release `kem` in the tree.
3. **D3 (SSH Key item, in process):** agree. The mismatch cause must be `InputInvalid` (exit 2),
   not `CredentialRejected` (exit 7). Read the OpenSSH form.
4. **D4 (file plus env identity):** agree.
5. **D5 (deploy floor, ratchet, no expiry):** **partial conflict.** Keep the floor and no expiry.
   **Drop the ratchet** from the slice (R4).
6. **D6 (`unseal --exec`):** agree.
7. **D7 (defer the library):** agree. It leaves acceptance 4's "and the library" unmet, so the
   owner amends the issue.
8. **D8 (names in the clear):** agree for names. **Drop `source_versions`** (item ids and versions)
   from the header (C20).
9. **New D9, the format owner:** the downstream already builds this format. Reconcile before B1
   (T7), including the issue's "signed payload" wording against the design's
   encrypt-then-sign-with-plain-header.
10. **New D10, collision behaviour:** override plus notice (recommended), against the design's
    refusal (R1).

---

## Required design changes

1. **(T1)** `unseal` accepts a signature only from an `allowed_signers` line whose principals
   include the header's environment; add the `sealed_signer_shared` load rule; update §4.2, §7.3,
   §9.1 and the tests.
2. **(T2)** §6.2: signer mismatch is `InputInvalid { kind: DeployCredentials, field: "public key" }`.
3. **(T3, T4, C7b)** §8.2-6/7: `whole_set() -> bool`; one batch builder from `plan.rows` in
   `prepare_staged`, before the plan id, triggered by stage, prune or list mismatch; `remove()`
   unreachable for whole-set stores.
4. **(T5, T15)** §3.2: `Channel::Store { label: "sealed bundle" }` for secret and config (no
   fallback); file `dir` carries `{product}`.
5. **(T6, T8, T9)** §5: path rule in the codec and in `write_file`; LF-only; canonical header
   re-serialization check.
6. **(T7)** §1.1/§5: reconcile with the downstream's format before B1 (D9).
7. **(T10, R7)** §5.4/§8.3: trust the previous revision only from evidence or a verified header;
   `checked_add`; `not_recorded` for opv-signed unrecorded bundles.
8. **(T11)** §6.4: `[bans]` wrapper for `p256`; correct the crate count.
9. **(T12)** §6.3: record the age chunk buffers as a verified, non-zeroized residual.
10. **(T13)** §4.2: specify the strict `allowed_signers` subset.
11. **(T14)** §3.1: a key with `age_identity = true` is never delivered by a sealed target.
12. **(R1)** §4.2/§5.5: replace `sealed_name_collision` with override plus a names-only notice.
13. **(R2, R3, R5, U3)** §5.5/§7.4: RAM-directory check at `--verify-only`; container tmpfs and
    `--init` docs; Windows spawn semantics; honest identity-at-rest rows.
14. **(R4, C11)** §5.4: remove the ratchet and `sealed_ratchet_unusable`.
15. **(U4)** §4.2: `--verify-only` optionally checks identity membership without decrypting.
16. **(P2)** §8.2: add `cause::codes::one_of_each`, the usage.md error table, and agent guidance
    `error_codes` to the wiring list.
17. **(C18, C20)** §4.1/§5.2: defer `op_calls` JSON; drop `source_versions` from the header.
18. **(C22)** §8.2-5: move the `system_of` fix out (it is `System::Https`, which exists), ideally
    as a required `Provider::system()`.
