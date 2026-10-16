# flyctl failure recordings

Real flyctl output for the Fly diagnosis strategy (`docs/design/error-catalog.md` §5). Recorded 2026-10-15 with **flyctl v0.4.111 linux/amd64** (commit 95b7f3e, built 2026-09-30) on Linux (WSL2). Nothing was created, changed or deleted at Fly; every call is a read.

Each case has `NN-<case>.stderr`, `.stdout` (only when non-empty) and `.exit`. Every command ran with stdin closed (`</dev/null`), with `FLY_API_TOKEN` and `FLY_ACCESS_TOKEN` unset unless the command sets one, and with opv's pinned environment `FLY_NO_UPDATE_CHECK=1 NO_COLOR=1`.

Markers in the commands:

- `<EMPTY_DIR>`: a fresh `mktemp -d`, so flyctl sees no login (isolated config).
- `<INVALID_TOKEN>`: `FlyV1 fm2_invalidrecordingtoken0000000000000000`, a made-up token in Fly's format that Fly rejects.
- `<RANDOM>`: random hex, so the app name cannot exist.
- "owner's login": the owner's own `flyctl auth login` in `~/.fly`, confirmed present (`flyctl auth whoami` exits 0; its output was not recorded).

No recorded file contains an email, org, user id, app name or token, so no `<EMAIL>`/`<ORG>`/`<APP>`/`<TOKEN>` substitution was needed. The `Request ID` values are Fly's per-request ids and are kept as recorded.

| # | Case | Command | Exit | Cause (design §4) |
|---|---|---|---|---|
| 01 | signed out | `FLY_CONFIG_DIR=<EMPTY_DIR> flyctl auth whoami` | 1 | `NotSignedIn{Fly, SignedOut}` |
| 02 | signed out | `FLY_CONFIG_DIR=<EMPTY_DIR> flyctl secrets list -a opv-recording-nonexistent-app --json` | 1 | `NotSignedIn{Fly, SignedOut}` |
| 03 | invalid token, no login | `FLY_CONFIG_DIR=<EMPTY_DIR> FLY_API_TOKEN='<INVALID_TOKEN>' flyctl auth whoami` | 1 | `CredentialRejected{ShellToken{FLY_API_TOKEN}, Rejected}` |
| 04 | invalid token, no login | `FLY_CONFIG_DIR=<EMPTY_DIR> FLY_API_TOKEN='<INVALID_TOKEN>' flyctl secrets list -a opv-recording-nonexistent-app --json` | 1 | `CredentialRejected{ShellToken{FLY_API_TOKEN}, Rejected}` |
| 05 | shell token overrides the login | owner's login present; `FLY_API_TOKEN='<INVALID_TOKEN>' flyctl auth whoami` | 1 | `CredentialRejected{ShellToken{FLY_API_TOKEN}, Rejected}`, never `NotSignedIn` |
| 06 | app not found | owner's login; `flyctl secrets list -a opv-recording-nonexistent-app-<RANDOM> --json` | 1 | `NotFound{Fly, app, Missing}` |
| 07 | forbidden (app in another org) | not recorded: **owner to record** | – | `MissingRight{Fly, Person, app}` |
| 08 | network down, signed out | `FLY_CONFIG_DIR=<EMPTY_DIR> HTTPS_PROXY=http://127.0.0.1:9 flyctl auth whoami` | 1 | `NotSignedIn{Fly, SignedOut}` (flyctl checks for a token before any network call) |
| 09 | network down (connection refused) | `FLY_CONFIG_DIR=<EMPTY_DIR> HTTPS_PROXY=http://127.0.0.1:9 FLY_API_TOKEN='<INVALID_TOKEN>' flyctl auth whoami` | 1 | `Unavailable{Fly, Network}` |
| 10 | network down (connection refused) | `FLY_CONFIG_DIR=<EMPTY_DIR> HTTPS_PROXY=http://127.0.0.1:9 FLY_API_TOKEN='<INVALID_TOKEN>' flyctl secrets list -a opv-recording-nonexistent-app --json` | 1 | `Unavailable{Fly, Network}` |
| 11 | timeout (proxy accepts, never answers) | `FLY_CONFIG_DIR=<EMPTY_DIR> HTTPS_PROXY=http://127.0.0.1:18999 FLY_API_TOKEN='<INVALID_TOKEN>' timeout 60 flyctl auth whoami` | 124 | `Unavailable{Fly, Timeout}` |
| 12 | version | `flyctl version` | 0 | – (stdout read by `doctor`) |

Notes for the diagnosis:

- **Signed out (01, 02, 08):** `Error: no access token available. Please login with 'flyctl auth login'`. flyctl fails before any network call, so a network fault cannot be seen while signed out.
- **Rejected token (03, 04, 05):** the wording depends on the API the call uses. `auth whoami` (GraphQL) says `You must be authenticated to view this.`; `secrets list` (Machines API) says `Authenticate: token validation error`. Case 05 has the same text as 03: with a login present, an invalid `FLY_API_TOKEN` still wins, and nothing in the reply mentions the variable. Only the runner knows a shell token was in effect (§5, "The principal is known").
- **Not found (06):** `failed to list app secrets: app not found`.
- **Network (09, 10):** `proxyconnect tcp: dial tcp …: connect: connection refused`, after `Post "https://api.fly.io/graphql"` or `Get "https://api.machines.dev/v1/apps/<app>/secrets"`.
- **Timeout (11):** flyctl has no time limit of its own here; it waited until the outer `timeout 60` sent SIGTERM, then printed `terminated signal received` and exited with 124 (from `timeout`). opv's own budget has to end such a call.
- **Forbidden (07):** not recorded, because finding an app in another org would mean guessing other customers' app names. The owner can record it with an app in an org they are not a member of (or a deploy token scoped to a different app): `flyctl secrets list -a <APP> --json </dev/null`.
- Not covered: expired login, rate limiting (HTTP 429) and server errors (5xx), which cannot be produced on demand.
