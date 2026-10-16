# flyctl success recordings

Real flyctl output, recorded 2026-10-16 with **flyctl v0.4.111 linux/amd64** (commit 95b7f3e) for the simulator (`tests/sim/fly.rs`). Read-only, with the owner's approval, using the owner's existing `flyctl auth login`: nothing was set, unset, imported, deployed or created. Every call ran with stdin closed and `FLY_NO_UPDATE_CHECK=1 NO_COLOR=1`. Each case has `.stdout`, `.stderr` (empty in every case) and `.exit`.

| Case | Command | Exit |
|---|---|---|
| 01-secrets-list-deployed | `flyctl secrets list -a <APP> --json`, an app whose one secret is deployed | 0 |
| 02-secrets-list-staged | the same, an app with four staged secrets | 0 |
| 03-secrets-list-empty | the same, an app with no secrets: `[]` | 0 |
| 04-auth-whoami | `flyctl auth whoami` | 0 |

Markers: `<APP>` is the app (not in any output), `<SECRET_n>` each secret name, in order, `<EMAIL>` the login's email. Only the names were replaced; layout, digests and statuses are byte for byte as flyctl printed them. The digests are Fly's (16 lowercase hex, keyed server-side, see `docs/design/spike-d0-findings.md` Q4); they are not secrets and identify nothing.

Observed across all 23 apps the login can read: every app's list was all `Deployed` or all `Staged`; no app showed a mix, so a mixed list is not recorded.
