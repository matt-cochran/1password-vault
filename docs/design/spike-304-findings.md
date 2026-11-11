# Spike #304: what 1Password shows about a service account's grants

Owner-run, about 1.5 h. It settles the facts the #304 design rests on
(`docs/design/placements-and-access-boundaries-review.md` F17, F18, and the unconfirmed
`SERVICE_ACCOUNT` type string in `src/domain/access.rs`). Everything uses two throwaway vaults
and a throwaway service account that expires in one day. No real vault, item or value is
involved, and nothing here writes a token to disk.

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

## 4. Findings (fill in)

| # | Question | Evidence | Answer |
|---|---|---|---|
| Q1 | Does `whoami` under a token name a stable user id and account id, and is its type exactly `SERVICE_ACCOUNT`? | s30 | |
| Q2 | (F18) Does `vault list` under the token show exactly the granted vaults (VA, not VB)? | s31 | |
| Q3 | Does the owner's `vault user list` show the service account, its type string and permission names (`read_items`, …)? | s32 | |
| Q4 | Is the service account absent from a vault it was not granted? | s33 | |
| Q5 | (F17) Can a service account's grants change after creation? Exit code and message. | s34, s35 | |

## 5. What this can and cannot prove

Fill in once the replies are recorded. At minimum: the token's own view (Q1, Q2) shows identity
and vault visibility but not permission levels; only the owner's view (Q3) shows permission
names. If Q5 shows grants can change after creation, a receipt is only as fresh as its last
owner audit, and the design's freshness window has to account for that.
