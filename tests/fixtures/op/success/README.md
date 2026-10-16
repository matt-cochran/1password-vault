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
