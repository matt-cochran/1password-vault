# Spike #304: what 1Password shows about a service account's grants

Owner-run, about 1.5 h. It settles the facts the #304 design rests on
(`docs/design/placements-and-access-boundaries-review.md` F17, F18, and the unconfirmed
`SERVICE_ACCOUNT` type string in `src/domain/access.rs`). Everything uses two throwaway vaults
and a throwaway service account that expires in one day. No real vault, item or value is
involved, and nothing here writes a token to disk.

**Run it as one script:** sign in (`eval "$(op signin --account <account>)"`), then
`scripts/spikes/spike-304.sh <account>`. It does sections 1–3 below, refuses to copy anything
if a token-shaped string or an identifier survives the scrub, deletes both vaults on exit and
prints the scrubbed replies for section 4. The sections below are what it runs.

Use op 2.40.0 or later, signed in as yourself to the project account, and the `rec` helper and
scrub script from [`tests/fixtures/op/success/RECORD.md`](../../tests/fixtures/op/success/RECORD.md)
(sections 1 and 2).

## 1. Set up (owner session)

```bash
set -u
A=<the project account ID>
OUT=$(mktemp -d); cd "$OUT"
rec() { n=$1; shift; "$@" </dev/null >"$n.stdout" 2>"$n.stderr"; echo $? >"$n.exit"; echo "$n exit $(cat "$n.exit")"; }
op vault create opv-spike-304-a --account "$A" --format json </dev/null | jq -r .id   # → VA
op vault create opv-spike-304-b --account "$A" --format json </dev/null | jq -r .id   # → VB
VA=<id printed above>; VB=<id printed above>
# The token stays in this shell variable only: never echo it, never write it to a file.
T=$(op service-account create opv-spike-304 --account "$A" --vault "$VA":read_items --expires-in 1d --raw </dev/null)
```

## 2. Record

```bash
# Under the service account (its own view)
OP_SERVICE_ACCOUNT_TOKEN="$T" rec s30-whoami-service-account op whoami --format json
OP_SERVICE_ACCOUNT_TOKEN="$T" rec s31-vault-list-service-account op vault list --format json
# In your owner session (the owner's view of the same grants)
rec s32-vault-user-list-granted  op vault user list "$VA" --account "$A" --format json
rec s33-vault-user-list-other    op vault user list "$VB" --account "$A" --format json
# F17: can a grant be added after creation? (SA_USER = the user id in s30's stdout)
rec s34-grant-after-create op vault user grant --vault "$VB" --user "$SA_USER" --permissions read_items --account "$A"
OP_SERVICE_ACCOUNT_TOKEN="$T" rec s35-vault-list-after-grant op vault list --format json
unset T
```

## 3. Scrub, check, clean up

1. Run the RECORD.md section 2 scrub over `$OUT` and copy the `s3*` files into
   `tests/fixtures/op/success/`. Grep them for the vault IDs, your email and `ops_`: nothing may
   match.
2. `op vault delete "$VA"` and `op vault delete "$VB"`, then revoke `opv-spike-304` in
   1Password (Developer → Service accounts). opv cannot delete a service account.

## 4. Findings (recorded 2026-11-11, op 2.40.0, a Teams-tier account)

| # | Question | Evidence | Answer |
|---|---|---|---|
| Q1 | Does `whoami` under a token name a stable user id and account id, and is its type exactly `SERVICE_ACCOUNT`? | s30 | **Yes.** `user_uuid`, `account_uuid`, `user_type: "SERVICE_ACCOUNT"` (also `ServiceAccountType: "SERVICE_ACCOUNT"`). The type string in `src/domain/access.rs` is confirmed for `whoami`. |
| Q2 | (F18) Does `vault list` under the token show exactly the granted vaults? | s31 | **Yes.** Only vault A (granted `read_items` at creation); vault B is absent. It shows no permission level. |
| Q3 | Does the owner's `vault user list` show the service account and its permissions? | s32 | **No.** The granted vault lists only the owner (`type: "MEMBER"`). Service accounts do not appear in `op vault user list` at all. Permission names on this tier are `allow_viewing`, `allow_editing`, `allow_managing`, not `read_items`. |
| Q4 | Is the service account absent from a vault it was not granted? | s33 | Yes, trivially: it is absent from both (see Q3). |
| Q5 | (F17) Can a service account's grants change after creation? | s34, s35; 1Password docs | **No, per 1Password.** The recorded `vault user grant … --permissions read_items` failed only because `read_items` is not a valid name on this tier, so the recording itself does not decide it; 1Password's [service-account management documentation](https://developer.1password.com/docs/service-accounts/manage-service-accounts/) states that vaults and vault permissions cannot be added or edited after creation (cited by `docs/reader-grants.md`). |

## 5. What this can and cannot prove

- **The token's own view proves identity and vault set.** `whoami` (Q1) binds a run to one
  service-account user in one account, and `vault list` (Q2) shows exactly the vaults it can
  open, so an extra vault is detectable from CI without any owner session.
- **Nothing shows a service account's permission level after the fact** (Q2, Q3). Permission
  levels are only knowable from the creation request; with grants immutable after creation
  (Q5), that request is an upper bound on the identity's authority.
- **Shipped as:** `opv access <env> --create … --grant-receipt` and
  `opv access <env> --verify-reader` (PR #310, [reader grants](../reader-grants.md)), which
  rest on exactly these facts.
- **Follow-up:** `opv access`'s audit reads `op vault user list`, where service accounts never
  appear (Q3), so it cannot see a CI reader or deploy identity there (#314).
