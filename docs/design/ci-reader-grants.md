# Verifying a CI reader's grants (#304, FR-70)

Status: design for 0.20.0. Evidence: [spike-304-findings.md](spike-304-findings.md) (recorded
replies `tests/fixtures/op/success/s30`–`s35`); TRIZ analysis `.triz/ci-reader-grants.result.json`.

## Problem

A CI job must prove, before it materialises any fixture, that its 1Password reader token has
exactly the grants its committed contract expects: the right account, exactly the expected
vaults, read only, nothing more. It must do so without an owner session, without reading an
item and without a destructive test write.

The spike settled what 1Password can show:

| View | Shows | Does not show |
|---|---|---|
| The token's own `op whoami` (s30) | service-account user id, account id, `user_type: SERVICE_ACCOUNT` | permissions |
| The token's own `op vault list` (s31) | exactly the vaults it can open | permission level per vault |
| The owner's `op vault user list` (s32) | people and groups only | service accounts at all |

So **no view, owner or token, shows a service account's permission level after the fact.** The
only moment its permissions are known is when it is created: `op service-account create
--vault <id>:<permission>` states them.

## Design (TRIZ: separate by time and by system level; bypass the unknowable)

1. **Issue by construction.** Only opv's owner commands create CI readers (`opv access <env>
   [--target <t>] --create` and `--rotate`, which already compute the least-privilege grants
   and run `op service-account create`). Right after the token verifies, opv runs `op whoami`
   with the new token in the child's environment (never argv) and records an **issuance
   receipt**.
2. **Record the receipt where expiry is already recorded:** the value-free sibling bindings
   file (`secrets.bindings.toml`, beside the contract), at
   `environments.<env>.ci_reader.receipt` or `environments.<env>.targets.<t>.ci_identity.receipt`.
   It is committed and reviewed like the contract. A project whose configuration lives in a
   1Password manifest has no sibling file: there every check below is `not_supported`, and
   `--create` says so (this mirrors 0.19.0's expiry records).
3. **Verify in CI with the token's own view only:** `opv access <env> [--target <t>] --verify
   [--json]`, run under the reader's `OP_SERVICE_ACCOUNT_TOKEN`. It reads `op whoami`,
   `op vault list` and the committed receipt and contract. Nothing else: no item read, no
   write, no owner session.

### Receipt (names and IDs only)

```toml
[environments.prod.ci_reader.receipt]
schema = "opv.grant-receipt/1"
account_id = "<ACCOUNT_UUID>"
service_account_user_id = "<USER_UUID>"   # from whoami under the new token
service_account_name = "p-ci-ci-20261111"
vaults = [{ id = "<VAULT_ID>", permissions = ["read_items"] }]
issued_at = "2026-11-11T10:24:11Z"
issued_by = "access --create"             # or "access --rotate"
expires_on = "2027-02-09"
contract_grants = "sha256:<hex>"          # digest of the canonical grant table opv computed
```

`contract_grants` is a digest of the computed grant table (vault IDs and permission names in a
fixed order). It contains no secret, and it is not a hash of any secret.

### Checks and findings

Each check reports `verified`, `not_verified` (with a fixed reason) or `not_supported`. An
unknown answer is never `verified`.

| Check | Verified when | `not_verified` reasons |
|---|---|---|
| `receipt` | a `opv.grant-receipt/1` receipt exists for this identity | `receipt_missing`, `receipt_invalid` |
| `identity` | whoami type is `SERVICE_ACCOUNT` and its account id and user id equal the receipt's | `not_a_service_account`, `wrong_account`, `identity_mismatch`, `provider_read_incomplete` |
| `vault_set` | the token's `vault list` IDs equal the receipt's vault IDs, which equal the contract's required vaults | `extra_vault`, `missing_vault`, `provider_read_incomplete` |
| `contract` | the digest of the grants opv computes now equals `contract_grants` | `contract_changed` (stale receipt) |
| `permissions_issued` | every receipt permission equals the contract's (a CI reader: read only; no write, create or manage) | `write_permission`, `permission_mismatch` |
| `permissions_live` | always `not_supported` | (1Password shows no permission level for a service account, spike Q2/Q3) |
| `freshness` | `expires_on` is after today | `expired` |

`--verify` exits 0 only when every check except `permissions_live` is `verified`; otherwise it
exits with the policy code and `Next:` names the owner's re-issue command (`opv access <env>
--rotate --github …`). `permissions_live` is reported, never waived silently: the JSON and the
text both say permission levels are proven only at issuance.

### What this proves, and what it cannot

- **Proven on every CI run:** the token is the service account opv issued, in the right
  account, and it can open exactly the contract's vaults, no more.
- **Proven at issuance only:** the permission level per vault. opv asked for it and 1Password
  accepted it; nothing can re-read it later.
- **Not proven:** a permission raised on an already-granted vault after issuance. Whether
  1Password allows changing a service account's grants after creation is still open (spike
  Q5). An *added* vault is caught by `vault_set` on every run whatever the answer.
- **Existing gap made explicit:** `opv access`'s reader audit reads `op vault user list`, where
  service accounts never appear (Q3). For a service-account reader it reports
  `not_supported` instead of `no_ci_reader`.

## Non-goals

No automatic issuance or rotation, no widening of grants, no new secrets platform state: the
receipt holds IDs, names, dates and a digest, like the expiry records beside it. A token issued
before 0.20.0 has no receipt and is `not_verified (receipt_missing)` until the owner rotates it.
