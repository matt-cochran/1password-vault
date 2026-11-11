# CI reader grant evidence

`opv access ENV --verify-reader` verifies a protected, owner-approved issuance
receipt against the job's current native service-account identity and readable vault
set. It does not inspect retrospective effective grants. Old identities without a
trusted issuance receipt remain unverified. No secret value or token hash enters the
receipt or command output.

## Provider evidence and trust boundary

The [native CLI service-account reference](https://developer.1password.com/docs/cli/reference/management-commands/service-account/)
documents `create` and `ratelimit`, explicit `--vault UUID:read_items` permissions,
optional `--can-create-vaults`, `--expires-in` and `--raw`. It does not document a
service-account grant-inspection command. A vault-user listing requires privileges
that a restricted reader may lack; it cannot establish absence of other authority.
Do not increase a CI reader to Manage or attempt writes to prove denial.

1Password's [service-account management documentation](https://developer.1password.com/docs/service-accounts/manage-service-accounts/)
says you cannot “add additional vaults or edit any vault permissions” after creation,
and cannot “change its ability to create new vaults”. Changing authority requires a
new service account. This makes a closed native creation request, bound to the actual
new immutable account and service-account UUIDs, an upper bound on that identity's
authority. An owner can revoke it or disable vault access; this narrows availability.
The verifier checks current vault-read visibility separately and rejects narrowing.

The owner command trusts its host, the installed native CLI, and the reviewed OPV
binary. The routine job trusts the independently approved receipt bytes, protected
configuration, and native metadata returned under its explicitly selected token. A
receipt hash detects changes; it does not authenticate who issued the receipt. Never
hash a file from an untrusted PR and use that same hash as approval. Store the approved
SHA256 in protected source or equivalent trusted configuration, outside the PR's
control. An attacker controlling both receipt and approved hash can forge this proof.

## One-time owner issuance

Use a local configuration whose environment `account` and boundary `vault_id` fields
are immutable native UUIDs. A CI reader receives `read_items` on every boundary of
that environment, and no target-state vault grants. The owner runs the existing
confirmed access flow in their own terminal:

```sh
opv --config secrets.toml access staging --create --github org/app --github-env staging --grant-receipt staging-reader.json
```

`--grant-receipt` is opt-in and supports only a new read-only reader with `--create`.
It conflicts with `--target` and `--rotate`; existing deploy and rotation semantics
are preserved. The receipt path must be new and its parent must already exist.
No receipt is retroactively made from a manifest's `readonly` flag or a reader name.
An owner replacing an old unproven identity explicitly creates a new one, approves
its receipt, qualifies the new CI reader, then revokes the old account in 1Password.

Before creating anything, OPV checks that the requested vault set equals the access
contract and every grant is read-only. Its fixed native create request explicitly
names UUID/read_items pairs, omits create-vault permission, and requests 90 days.
The token remains in zeroizing memory and is used for a token-only native `whoami`
call before GitHub delivery. The returned `user_type` must be `SERVICE_ACCOUNT`, and
native account UUID must equal the committed environment account UUID. A fresh
native vault listing must also match the exact requested UUID set before token storage;
a mutable name shaped like an ID is insufficient. The resulting
`user_uuid` binds the receipt; the mutable service-account name is never authority.
If identity verification fails, no receipt or GitHub token is stored; the owner must
remove the new account before trying again. Native creates are never retried.

After successful GitHub token storage, OPV writes the public receipt and prints its
SHA256. Review and commit the receipt, and independently pin that exact digest in the
protected job's configuration. Creation, native read failure, GitHub failure or local
receipt-write failure never becomes a grant-proof success. If the token was delivered
but local receipt writing failed, CI stays blocked until the owner resolves issuance.

## Routine restricted CI verification

Verification requires a local `--config PATH` (or `OPV_CONFIG`) file; missing local
configuration is a typed refusal before any account or manifest discovery. There is
no fallback to a remote manifest or a person's selected account. Trusted CI supplies only its own `OP_SERVICE_ACCOUNT_TOKEN` through its existing secret
delivery. The agent never obtains it. Use a protected local configuration and receipt:

```sh
opv --config secrets.toml access staging --verify-reader --grant-receipt staging-reader.json --grant-receipt-sha256 0000000000000000000000000000000000000000000000000000000000000000 --json
```

The zero digest above is a placeholder that fails verification; use the separately
approved digest. `--verify-reader` requires an environment, receipt, digest and no
`--target`/`--project`/creation flags. Only exit 0 with `ok: true`,
`reader_grants.status: verified`, `proof: native_immutable_issuance`, and
`current_read_access: verified` is success.

Fresh native calls use `op whoami --format json`, then `op vault list --format json`.
The runner clears inherited credentials and owner sessions, ignores owner account
selection and Connect, disables desktop integration and native caching, and supplies
only the selected token plus noncredential process/network basics. The native
[service-account usage documentation](https://developer.1password.com/docs/service-accounts/use-with-1password-cli/)
warns that Connect credentials otherwise take precedence. No item values, user lists,
write probes, service-account creation or owner login are used by verification.

The account/user UUID and exact current readable UUID vault set must match. Native
refusal, malformed/partial output, missing/extra/duplicate vault, human authentication,
wrong identity, wrong account, unknown receipt schema/revision/fields, wrong contract,
write/share/unknown permissions, create capability, future/expired evidence or evidence
validity over 90 days fails closed. A provider error never implies denied permissions
or proof of a safe identity.

## Stable metadata contract

Receipt schema and revision are both 1. Every struct rejects unknown fields. The
receipt contains exactly `receipt_schema`, `revision`, `proof`, `service_account_id`,
`contract`, `contract_sha256`, `issued_at`, `not_after`. All timestamps are Unix seconds.
`proof` is `native_immutable_issuance`.

The contract's serialization order is `environment`, `role`, `account_id`, `vaults`,
`can_create_vaults`. `role` is `ci_reader`; vault entries are lexically sorted and
deduplicated, each `{vault_id, permissions: ["read_items"]}`; `can_create_vaults` is
false. `contract_sha256` hashes its compact serde_json UTF-8 serialization without a
newline. This binds only native authority, not manifest formatting, secret key lists,
values or delivery revisions. An ordinary release or new key within the same vault
retains the proof. A true account/environment/role/vault authority change requires a
new identity and reviewed receipt; editing receipt fields cannot renew it.

`opv schema` documents the JSON body `reader_grants`:

| Field | Values |
|---|---|
| `status` | `verified`, `not_verified` |
| `proof` | `native_immutable_issuance` |
| `finding` | null on success; stable reason below on failure |
| `retrospective_effective_grants` | `not_supported` |
| `current_read_access` | `verified`, `not_verified` |
| `credential_expiry`, `delivery` | `not_verified` |
| `receipt_sha256` | approved receipt SHA256 on success; null on failure (never hashes an arbitrary input file in public output) |
| `contract_sha256` | public expected-authority SHA256, lowercase hex |
| `contract` | expected access contract described above |
| `service_account_id`, `issued_at`, `not_after` | verified receipt metadata; null on failure |
| `checked_at` | current Unix seconds |

A verification failure writes this body then exits 8 with standard JSON error code
`reader_grants_unverified`; the common schema-4 frame includes `ok: false`,
`exit_code: 8`, typed `next` and `do`. Failures before verification begins use the
usual OPV error envelope. Consumers must branch on typed status/code, never prose.

Verification reasons: `untrusted_or_tampered_receipt`, `receipt_invalid`,
`receipt_not_supported`, `contract_mismatch`, `immutable_identity_required`,
`receipt_stale_or_future`, `native_identity_unverified`, `native_identity_mismatch`,
`native_access_incomplete`, `native_vault_set_mismatch`.

`not_after` limits issuance evidence to 90 days. It is not independently observed
native credential expiry. Fresh authenticated metadata proves the token can currently
read the listed vaults, not how much credential lifetime remains. Token rotation for
the same immutable user and permissions does not renew this receipt. Secret delivery
requires its own `opv delivery verify` evidence and is never asserted here.

## Owner and CI qualification

Fake-provider tests establish parser, policy and failure behavior. They are not a live
provider qualification. Before first activation, the owner/trusted CI should:

1. Pin the reviewed OPV binary and native CLI versions; retain only those version
   strings and public UUID/schema evidence.
2. Use the owner command above for an already authorized fixture-only boundary; do not
   add runtime/signing/provider-write vaults. Review the complete printed native grants
   and receipt against the native service-account overview.
3. Confirm native `whoami` JSON exposes `user_uuid`, `account_uuid`,
   `user_type: SERVICE_ACCOUNT`; retain a projection of those public fields only.
   Unexpected native schema is a blocker, never a field-name guessing workaround.
4. Approve receipt and independent digest through protected source, then run the CI
   verifier using the delivered reader. Confirm no owner/Connect/desktop authentication
   is available to the job and no item/secret reads precede the verifier.
5. Exercise wrong approved hash, wrong expected account/vault and replaced identity;
   require exit 8/typed rejection. Owner-controlled revocation or vault access changes
   are optional qualification steps only in a dedicated authorized environment, never
   destructive probes from this verifier or an agent.
6. Keep the names-only receipts and CI results. Treat provider read failures and all
   unsupported evidence as a release blocker. Do not enable runtime materialization
   solely because a requested manifest grant or GitHub secret name exists.

No live vaults, service accounts, tokens or provider writes were used to develop the
fake-provider tests. This source change does not claim production qualification.

The synthetic wire fixtures in `tests/fixtures/reader_grants/` are emitted by the actual
Rust receipt/report/frame serializers at a fixed clock, using only fake native metadata.
The fixture test locks their exact bytes. To reproduce the public files locally, run
`OPV_304_CONSUMER_GOLDEN_DIR=/tmp/opv-304-consumer-golden cargo test --locked --features fake --lib consumer_wire_golden`.
These fixtures are format qualification, never provider grant or delivery evidence.
