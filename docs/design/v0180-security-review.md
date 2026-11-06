# opv 0.18.0 security review (secreview-0180)

Independent review of the integrated 0.18.0 tree (`v0180/integrate` 498e6a14, diff against
0.17.4 `1a37ea3f`), reading the code rather than the designs. Scope: the sealed target's
crypto and runtime (`src/bundle/*`, `src/adapters/sealed/*`, `src/app/unseal*.rs`),
provision custody (`src/app/provision.rs`, `produce_doc.rs`, the produce effect in
`src/runner.rs`, `src/app/import.rs` `write_item`), sign-in and readiness (`src/app/run.rs`
preflight and replay, account choices, `.opv config =`, the MCP `accounts` section), and run
scoping (D4-B).

Verdict: **ship after the fix in this branch** (S1). No High finding. The remaining findings
are Low, defence in depth, and can follow in a patch; S2, S3, S4 and S9 were fixed before the
release (`v0180/sec-lows`).

## Findings

| id | severity | file:line | issue | fix |
|---|---|---|---|---|
| S1 | Medium (fixed) | `src/adapters/sealed/config.rs:364` | G4 ("a sealed target never seals its own signing key") compares the target's `deploy_credentials` with the product's boundary **by ids** (`b.vault_id == signer_item.vault && b.item_id == signer_item.item`). `deploy_credentials` is usually written by name (`op://Ops Prod/opv-sealed-prod-signer`, as in the store's own test fixture) while boundaries are ids, so the check never fires for a name reference. The design's downstream case (G3: the staging signing key is a field of the product's item) would then seal the private signing key to every runtime recipient, and any runtime host could forge bundles for that environment. | **Fixed:** `crypto::seal` refuses any batch value that parses as the bundle's own signing key (same public key, OpenSSH or PKCS#8 form) with `CryptoError::SealsSigningKey(<name>)`; the sealed store maps it to `input_invalid` with `SealedDeliversSigner`, naming the key and the target, and writes nothing. Value-based, so it holds whatever the reference form. Tests: `bundle::crypto_tests::seal_refuses_a_value_that_is_its_own_signing_key`, `seal_keeps_a_value_that_is_another_signing_key`, `adapters::sealed::store_tests::a_value_that_is_the_signing_key_is_never_sealed`. The config-time id check stays as the early warning. |
| S2 | Low (fixed) | `src/bundle/format.rs:223`, `src/app/unseal_exec.rs:208` | An `env:` destination's variable name is not checked: a validly signed bundle may deliver `env:OP_SESSION_x`, `env:<identity var>` or a name unrelated to the payload name. `OP_*` is stripped only from the inherited environment, after which the bundle's variables are added. opv itself always writes `env:<name>` and refuses `OP_*` names, so this needs a crafted bundle signed by a trusted key. | **Fixed (`v0180/sec-lows`, "security: 0.18.0 — validate bundle variable names, --project, re-check producer pin"):** `format::check_variable` (`^[A-Za-z_][A-Za-z0-9_]*$`, never `OP_*` in any case) is applied to every `env:` destination by `check_destination`, so the codec refuses such a header on parse and `seal` cannot write one; `unseal::check_variables` re-checks after verification (and `--exec` again before delivery) and also refuses the `--identity-env` variable, as `sealed_malformed`, before anything is decrypted or started. The sealing side already refuses `OP_*` and non-`[A-Z][A-Z0-9_]*` key names at config load. Tests: `bundle::format_tests::an_op_session_destination_is_refused`, `a_lowercase_op_destination_is_refused`, `app::unseal::unseal_tests::a_bundle_naming_an_op_session_variable_is_refused_before_exec`, `a_bundle_naming_a_lowercase_op_variable_is_refused_before_exec`, `a_bundle_naming_the_identity_variable_is_refused_before_exec`. |
| S3 | Low (fixed) | `src/bundle/format.rs:72` (`secrets_dir_env`) | `secrets_dir_env` is not validated (could be `OP_*`, `LD_PRELOAD`, contain `=`). Signed, so trusted-signer only. | **Fixed (`v0180/sec-lows`, "security: 0.18.0 — validate bundle variable names, --project, re-check producer pin"):** `check_header` applies `check_variable` to `secrets_dir_env`, and the runtime check covers it with the identity variable too (config load already refuses `OP_*`, `PATH`, `HOME`, `XDG_CONFIG_HOME`). Test: `bundle::format_tests::a_bad_secrets_dir_env_is_refused`. |
| S4 | Low (fixed) | `src/bundle/crypto.rs:396` (`Expect`) | The runtime checks environment, product and revision but not `project` (or `target`). Principals are environment names, so a downstream `allowed_signers` that trusts two projects' keys for the same principal (`prod`) would accept project B's bundle for project A's product of the same name. | **Fixed (`v0180/sec-lows`, "security: 0.18.0 — validate bundle variable names, --project, re-check producer pin"):** `opv unseal --project <name>` (optional, `Expect::project`) refuses a header for another project with `sealed_scope_mismatch` before decryption; `docs/sealed-delivery.md` says per-project signing keys plus `--project` bind a bundle to one project. Without the flag nothing changes. Test: `app::unseal::unseal_tests::a_project_mismatch_is_refused`. |
| S5 | Low (fixed) | `src/app/unseal_exec.rs` (no `declared_only`) | `declared_only` is not applied to sealed bundles: the child inherits the whole runtime environment minus `OP_*` and the identity variable. Impact is limited: the runtime host owns that environment, the bundle never adds undeclared values, and the identity is removed when given by `--identity-env` (an identity file is never in the environment). An identity also exported under another name, or orchestrator-injected credentials, would reach the app. | Carry the product's `environment` policy in the signed header (a header field is a format change, so `opv-sealed/2` or a reserved optional field) and apply it in `child_env`; until then document it in the runtime guide. **Fixed (0.18.1, #279, `v0181/fu-a`):** the `opv-sealed/1` header carries an optional, signed `child_environment` (`inherit`/`declared_only`) sealed from the product's `local.environment`; `declared_only` also enters the contract digest (an `inherit` contract keeps its 0.18.0 digest), so changing it re-seals ("environment changed"). `unseal --exec` applies it in `child_env` as local delivery does: only the bundle's variables and `host::is_basic_env`. A bundle without the field inherits. Tests: `tests/sealed_unseal.rs` `a_declared_only_bundle_gives_the_child_no_inherited_undeclared_variable`, `a_bundle_without_the_environment_field_still_inherits`; `bundle::format_tests` `a_header_without_child_environment_parses_as_inherit` (fixture header and contract digest regenerated deliberately). |
| S6 | Low (fixed) | `src/app/unseal_exec.rs:94`, `:294` | With file keys opv stays the parent: `std::process::Command` keeps its own copies of the values (env map and the materialized `envp`) until `run_with` returns, freed unzeroized. The signal forwarder is installed only after the files are written, so a SIGTERM in that window kills opv with default action and leaves the RAM directory until the next run's sweep. The process is non-dumpable and the directory is 0700 on tmpfs, so exposure is local-root only. | Install the forwarder before `private_dir`, and `drop(cmd)` right after `spawn` (the child holds its own copy). **Fixed (0.18.1, #279, `v0181/fu-a`):** the forwarder is installed before `private_dir`; a signal that arrives before the spawn starts nothing (exit 128 + signal) and the directory is removed. On Linux the `Command` never holds the environment: it is built as `NAME=value\0` buffers in `Zeroizing`, the forked child points `environ` at them in `pre_exec`, and they are zeroized right after `spawn` (the inherited and child env vectors are wiped, as before). Std's own `envp` copy no longer exists on this path. Tests: `app::unseal_exec::tests` `a_sigterm_while_the_files_are_written_ends_the_command_with_143`, `…_leaves_no_directory`, `the_command_holds_no_copy_of_the_environment`. |
| S7 | Low (documented) | `src/bundle/crypto.rs:245`, `parse_identity`, `parse_signing_key` | Zeroization rests partly on library internals: age's stream reader/writer chunk buffers, bech32 decoding of the identity, and ssh-key's OpenSSH PEM decoding are not audited here. The PKCS#8 base64 body grew by reallocation and left unzeroized copies of the key's base64 behind. | **Documented (0.18.1, #279):** audited `age 0.12.1`/`age-core`/`x25519-dalek`/`chacha20poly1305` and `ssh-key 0.6.7`/`ssh-encoding`/`base64ct` as locked; `docs/design/sealed-target.md` §6.3 tables what each zeroizes. Keys (`StaticSecret`, `FileKey`, `PayloadKey`, `HmacKey`, `Ed25519PrivateKey`, dalek `SigningKey`) and decrypted chunks (`SecretSlice`) are zeroized; bech32 and OpenSSH key decoding leave no heap copy. Residual: age's `StreamWriter` plaintext `chunk` (up to 64 KiB), a possible realloc copy of a decrypted chunk, stack HKDF output and ChaCha20 state, base64ct's 3-byte block buffer. No cheap mitigation from opv (needs a fork); covered by exec, non-dumpable and zero core limit. |
| S8 | Low (fixed) | `src/app/provision.rs:1273` | A producer's `open_url` notice is printed to the terminal. Hosts are allow-listed and userinfo is refused, but a producer (which receives its inputs, values included, on stdin) could put an input in the query string. Inputs come from the item read, whose values are registered with the scrubber, so a literal echo is masked by the output guard; a percent- or base64-encoded one is not. The producer is owner-declared and sha256-pinned, so this is a trust-of-producer limit, not a bypass. | **Fixed (0.18.1, #279):** the `opv.produce/1` parser now also refuses an `open_url` whose query and fragment exceed 512 bytes (`OpenUrlProblem::QueryTooLong`) or that holds any input value of 4 bytes or more raw, percent-decoded (with and without `+`) or base64 (`OpenUrlProblem::CarriesInput`); `produce_doc::Context::inputs` carries the values in memory, compared only. Refused as `OpenUrlRefused`, never opened or shown. Tests: `app::produce_doc::tests::an_open_url_carrying_an_input_value_percent_encoded_is_refused`, `an_open_url_with_a_query_longer_than_its_limit_is_refused`. |
| S9 | Low (fixed) | `src/config/sets.rs:613` | The producer's sha256 pin is checked when the contract is loaded, not immediately before spawn, and covers one project file only (not the interpreter, its imports or `sh -c` bodies). The design calls this an honest limit; the window is the confirmation prompt. | **Fixed (`v0180/sec-lows`, "security: 0.18.0 — validate bundle variable names, --project, re-check producer pin"):** `config::recheck_pin` re-hashes the pinned project file in `provision`'s `produce`, immediately before the runner spawns it, and refuses with `ProducerChanged` (also when a file appears without a pin, or a pinned argument now names a path outside the project); nothing is spawned. The interpreter, imports and `sh -c` bodies stay an honest limit. Tests: `app::provision::tests::a_producer_file_changed_after_load_is_refused_as_changed`, `a_producer_file_changed_after_load_is_never_spawned`. |
| S10 | Low (fixed) | `src/config_store.rs:891` | Re-writing `.opv` formats `config = "{c}"` without TOML escaping; `is_relative_in_repo` does not refuse `"` or newlines, so a `.opv` whose `config` holds an escaped quote is rewritten with injected keys. The `.opv` is already attacker-controlled in that case and the path is re-checked on use, so there is no gain. | **Fixed (0.18.1, #279):** `record_account` writes `project`, `config` and `account` as TOML basic strings via `toml::Value::String(..).to_string()`, so a `config` holding `"` round-trips unchanged and injects no key (`\` is already refused by `is_relative_in_repo`). Test: `config_store::tests::recording_the_account_keeps_a_config_path_with_a_quote_unchanged`. |

## Verified OK

- **Signature coverage:** `Envelope::signed` is every byte above `-----BEGIN SSH SIGNATURE-----`
  (format line, header line, age block); `seal` signs exactly that; trailing data after the
  signature block, a second header and CR bytes are refused; `MAX_BUNDLE` bounds input.
- **Verify before decrypt:** the only decrypt call is `open_with`, after `verify_bundle`
  (signature, header signer = verifying key, environment, product, revision floor) and the
  header-recipient check. The store's listing verifies and never decrypts.
- **Signer bound to environment:** the SSHSIG is looked up with the header's environment as
  principal, by exact equality; principal patterns (`*?!`), quotes, `cert-authority` and every
  other option, non-ed25519 keys, wrong namespace and non-sha512 hashes are refused; the
  header's environment must then equal `--env`.
- **Recipients and identities:** only `age1…` X25519 recipients (SSH, plugin and PQ refused by
  kind); the identity file must hold exactly one `AGE-SECRET-KEY-1` line; scrypt stanzas are
  refused before decryption.
- **Format/downgrade:** one exact format line and `format == "opv-sealed/1"`; canonical-JSON
  header must re-serialize byte-identical; unknown and duplicate fields refused.
- **Revision:** `max(previous+1, now)`, previous only from a header verified with
  `sealed.signer` (foreign bundles never set it); runtime floor via `--min-revision`.
- **Path traversal:** codec path rule (`[a-z0-9-]` parts, ≤4, no `.`/`..`/absolute/NUL/`\`)
  and, independently, `write_file`'s `safe_relative_path` plus `mkdirat`/`openat` relative to
  an fstat-checked 0700 directory handle, `O_EXCL|O_NOFOLLOW`, files 0400.
- **Signing key custody:** the PEM stays a `SecretValue` in `SealedLogin`; `SealCall.env` holds
  a borrowed `&str` (no copy); `seal::run` parses it into a zeroize-on-drop `PrivateKey` for one
  seal; `SealCall`'s `Debug` prints names and `signed_in` only; the fake records env names only.
  The key joins only the pseudo-program `opv-seal`, which is never spawned.
- **`unseal --exec`:** `env_clear` then the filtered environment (no `OP_*`, no identity
  variable); override notices name variables only; values and the environment copy are wiped
  before `exec`; descriptors are close-on-exec; `unseal` is dispatched before opv's global
  signal handler, so its own forwarder owns the child; the private directory is removed on
  every return path and swept on start.
- **Producer custody:** environment cleared to `ENV_BASICS` (no `OP_SESSION_*`,
  `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_*`, `BROWSER`, `DISPLAY`); `RLIMIT_CORE` 0 in
  `pre_exec`; own process group, group SIGTERM→SIGKILL on every exit path and on opv's
  signals; stderr counted and wiped unread; stdout parsed line by line into zeroizing buffers;
  refusals name line numbers and declared output names, never producer text; `op`/`opv`
  refused as `command[0]`; secret-looking argv refused; request built in a pre-sized zeroizing
  buffer and written to stdin only.
- **Provision refusals:** agent marker, CI, no TTY, Windows with producers, production with a
  shell session or token (D6), and service accounts (`require_person_on`) are all refused
  before the item is read; prod/staging distinctness is a constant-time compare against each
  other environment's item; receipts and plans carry names, states and versions only.
- **`write_item`:** values only in the template on `op item edit` stdin; read-back compared in
  constant time; concurrent edits detected (not prevented), as documented.
- **Sign-in replay:** `mark_child_started` is set before `op run` and `may_replay` refuses after
  it, so a run's child never starts twice; the session from `sign_in_here` is held in a
  `SecretValue` and added only to `op` children's environment, and the local delivery step
  strips `OP_*` before the app starts.
- **`.opv config =`:** form check refuses `..`, roots, drives, backslash and NUL; on use both the
  `.opv` folder and the file are canonicalized and the file must sit inside the repository
  (symlinks resolved), and the resolved path is what is read.
- **MCP `accounts`:** reuses `account::document` (account names, emails, signed-in state);
  no values, no session data.
- **D4-B (run scoping):** only names declared solely as `source = "infrastructure"` are kept
  from the parent environment; a name any product stores is still cleared, no 1Password value
  is ever exported under an infrastructure name, and `declared_only` still filters the child.
  The child receives only what the user's shell already holds, as for any undeclared variable;
  a names-only note says which were kept. No leak.

## Tests run

`cargo nextest run --features fake,mcp -E 'binary(security) | test(canary) | test(custody)'`
(local, the devbox builder was unreachable): 722 passed on the integrated tree. With the fixes,
the same filter widened to `bundle::`, `adapters::sealed::`, `unseal` and `cause::`: 1369
passed, including the three new S1 tests.
