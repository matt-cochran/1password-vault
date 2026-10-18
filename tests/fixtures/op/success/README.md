# op success replies (recorded)

Recorded by the owner on 2026-10-16 with op 2.40.0 (Linux/WSL, the CLI's own sign-in), all
reads, through `.delivery/v0100/owner/record.sh` (the commands in `RECORD.md` §1 plus two
`whoami` calls). The project account is `<ACCOUNT_2>`; the vault is a staging vault of it.
Scrubbed with `RECORD.md` §2: every ID, name, title, tag, email, address, shorthand,
description and time is a numbered marker; only op's fixed values (`SECURE_NOTE`, `ACTIVE`,
`MEMBER`, `USER_CREATED`, `HUMAN` and the permission names) are left as op printed them. No
item field or value is in any of these replies.

| File | Command | Exit |
|---|---|---|
| `s01-account-list` | `op account list --format json` | 0 |
| `s02-vault-list` | `op vault list --account <ACCOUNT_2> --format json` | 0 |
| `s03-vault-get` | `op vault get <V> --account <ACCOUNT_2> --format json` | 0 |
| `s04-vault-user-list` | `op vault user list <V> --account <ACCOUNT_2> --format json` | 0 |
| `s05-item-list` | `op item list --vault <V> --account <ACCOUNT_2> --format json` | 0 |
| `s06-whoami-a` | `op whoami --account <ACCOUNT_2> --format json` | 0 |
| `s07-whoami-default` | `op whoami --format json` | 0 |

Markers used:

| Marker | Occurrences |
|---|---|
| `<ACCOUNT_n>` | 4 |
| `<ADDRESS_n>` | 4 |
| `<DESCRIPTION_n>` | 1 |
| `<EMAIL_n>` | 5 |
| `<ID_n>` | 10 |
| `<INFO_n>` | 1 |
| `<NAME_n>` | 10 |
| `<SHORTHAND_n>` | 4 |
| `<TAG_n>` | 1 |
| `<TIME_n>` | 18 |
| `<TITLE_n>` | 1 |
| `<USER_n>` | 6 |

## 0.12.0 capability replies (s20–s23)

Recorded by the owner on 2026-10-18 through `.delivery/v0120/record-capability.sh`, all reads,
scrubbed by that script (named markers `<ACCOUNT_A>`, `<EMAIL_A>`, `<USER_A>`, `<ADDRESS_A>`,
`<VAULT_WRITER>`, numbered `<NAME_n>`/`<SHORTHAND_n>`). The owner skipped the read-only-member and
non-member cases (`cases.tsv` lists them as skipped); the non-member refusal is covered by
`failures/14-vault-in-other-account` and `failures/15-vault-user-list-in-other-account`.

| File | Command | Exit |
|---|---|---|
| `s20-whoami` | `op whoami --account <ACCOUNT_A> --format json` | 0 |
| `s21-vault-list` | `op vault list --account <ACCOUNT_A> --format json` | 0 |
| `s22-writer-vault-get` | `op vault get <VAULT_WRITER> --account <ACCOUNT_A> --format json` | 0 |
| `s23-writer-vault-user-list` | `op vault user list <VAULT_WRITER> --account <ACCOUNT_A> --format json` | 0 |

read-only member: no recording; owner-accepted assumption, 2026-10-18.
