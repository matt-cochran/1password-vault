# Recorded op failure output

Recorded by the owner with `op` 2.40.0 on Linux/WSL (native `op`), on 2026-10-16, using `.delivery/v0100/record-op-failures.sh`. Every call ran with stdin closed. Identifiers are replaced by markers:
- `<ACCOUNT_n>`, `<USER_n>` and `<EMAIL_n>` are the accounts on the machine. `<ACCOUNT_2>` is the project's account (A); `<ACCOUNT_1>` is the other account (B). Both use the same sign-in address.
- `<ADDRESS>` is the sign-in address.
- `<VAULT_B>` is a vault in account B.

`cases.tsv` lists each case's command and exit code. No secret value was read: the only item lookup was for an item that doesn't exist.

| Case | What it shows | Design §4 cause |
|---|---|---|
| 01 | `op --version` | — |
| 02 | `whoami --account <unknown>`: "no account found for filter" | `AccountNotOnMachine` |
| 03 | an invalid `OP_SERVICE_ACCOUNT_TOKEN` (exit 9) | `CredentialRejected{ServiceAccountToken}` |
| 04 | `OP_ACCOUNT` set + `signout --all`: "You can't use both the '--all' and '--account' flags" | `CredentialRejected{OverriddenByEnvironment{OP_ACCOUNT}}` (an environment override, not the person's flags) |
| 05–07 | signed out: whoami / vault list / item get | `NotSignedIn{SignedOut}` |
| 08 | vault ID not found in a signed-in account | `NotFound{Vault}`, or `InOtherAccount` after `opv vault locate` |
| 09 | item not found | `NotFound{Item}` (`item_not_found`) |
| 10 | `whoami` success (shape) | — |
| 11 | `whoami --account B` with only A signed in: "no active session found for account B" | `NotSignedIn{state: OtherAccount{live: A}}` (#160): the probe that tells a live session for another account apart |
| 12 | `vault list --account B` with only A signed in: "You are not currently signed in" | `NotSignedIn` (#160) |
| 13 | `op signin --account B` while `OP_SESSION_*` for A is set and `OP_ACCOUNT` is unset: **succeeded** (exit 0, no stderr) | none. The #153 sign-in failure did not reproduce with op 2.40.0 when `OP_ACCOUNT` is unset |
| 14–15 | a vault of account B asked for in account A: "isn't a vault in this account" | `InOtherAccount` (#157) |
| 16 | `op read` of a field the item doesn't have: "does not have a field" (recorded in the #136 live run, 2026-10-21) | `changed`: no record (#218) |
| 17 | a deleted service account's token: "(403) Forbidden (Service Account Deleted)" (#136 live run) | `CredentialRejected{ServiceAccountToken}` (#221) |
