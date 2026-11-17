# Spike S1 (#338): credential stores, WSL survival, op service-account facts

Date: 2026-11-17. Gates D2/D10 (`agent-identity.md` §10), slice S4 (crate and backends) and
whether slice S19 exists. Scope: evidence, not product code. Every output below is names-only:
the only value stored or read was the fixed dummy `spike-dummy-not-a-secret`, and the probes
print outcomes (`stored`, `present+match`, `absent`, `timeout`), never a value.

The owner part, which needs a 1Password session, is `docs/design/spike-338-owner.sh`. Its
results land in `docs/design/spike-338-owner-results.txt` and are folded in here afterwards
(§6).

## 1. Summary

| | Result |
|---|---|
| WSL store | **Persistent is possible, but not through any Linux-side store.** Windows Credential Manager, reached through WSL interop, stores and reads headless in 0.6 to 1.7 s and lives outside the WSL VM. The kernel keyring is volatile on WSL (RAM only, and the WSL kernel has no persistent keyrings). Secret Service has no provider on stock WSL, and a self-hosted one comes up **locked** at every VM start. |
| Recommendation | **Persistent: Windows Credential Manager through interop is the WSL store. Drop S19**, subject to the owner's reboot check (§6). Kernel `@u` stays as the fallback, with doctor `FAIL agent_store_volatile`, only when interop is off. |
| Crate (S4) | `keyring-core =1.0.1` with `apple-native-keyring-store =1.0.2` (`keychain`), `windows-native-keyring-store =1.1.0` (no default features), `zbus-secret-service-keyring-store =1.0.1` (`rt-async-io-crypto-rust`) plus `secret-service =5.2.0` for the lock check, and `linux-keyutils =0.2.5` directly. Not the `keyring` 4.2.0 facade, and not `linux-keyutils-keyring-store`. |
| Non-interactive with timeout | keyutils: verified (syscalls only, 0 ms). Secret Service: verified **that it hangs** without a bound and that a bound plus a lock pre-check work. WSL to Windows Credential Manager: verified (child process with `timeout`). Native Windows and macOS: still unknown here (S4 on CI). |

## 2. The machine

```
$ uname -r                       -> 6.18.58.1-microsoft-standard-WSL2
$ wsl.exe --version              -> WSL 3.0.5.0, kernel 6.18.58.1-1, WSLg 1.0.79
$ cat /etc/os-release            -> Ubuntu 24.04.4 LTS
$ cat /etc/wsl.conf              -> [boot] systemd=true; [user] default=mc
$ loginctl show-user mc -p Linger -> Linger=no
$ zcat /proc/config.gz | grep -E 'CONFIG_KEYS|PERSISTENT_KEYRINGS'
CONFIG_KEYS=y
# CONFIG_PERSISTENT_KEYRINGS is not set
$ ls /proc/sys/kernel/keys/persistent_keyring_expiry -> No such file or directory
$ which secret-tool keyctl gnome-keyring-daemon keepassxc -> none found
$ apt-cache policy keyutils libsecret-tools gnome-keyring -> Installed: (none) for all three
$ busctl --user list | grep -i secret -> nothing; no activatable org.freedesktop.secrets
```

Probe: a throwaway Rust program (scratch directory outside the repo, deleted after) on
`keyring-core 1.0.1`, `linux-keyutils-keyring-store 1.0.0`, `linux-keyutils 0.2.5`,
`zbus-secret-service-keyring-store 1.0.1` and `secret-service 5.2.0`. Every read ran on a worker
thread with `recv_timeout(5 s)`, the same bound opv would use (vet R6). Secret Service ran
against `oo7-daemon 0.7.1` (built from crates.io) on a **private** `dbus-daemon` with its own
`XDG_DATA_HOME`, so the owner's session bus and keyrings were not touched.

## 3. The §15 items

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | `keyring` crate: backends, versions, non-interactive mode, headless/WSL | **Verified** (Linux, WSL); macOS and Windows native **still unknown** at run time | §4, §5 |
| 2 | Kernel keyring and Secret Service survive a WSL VM stop; `@u` survives the uid's last process | Kernel keyring: **refuted** (does not survive; docs plus kernel config; owner reboot run confirms). Secret Service: survives on disk but comes back **locked** (verified by daemon restart). `@u` and last process: **refuted** by `user-keyring(7)`; not reproduced, since that would kill this session | §5.1, §5.2 |
| 3 | `op service-account ratelimit` under a token: argument, output | Argument: **verified optional** (help: `ratelimit [{ <serviceAccountName> \| <serviceAccountID> }]`). Output shape: documented as `TYPE ACTION LIMIT USED REMAINING RESET`; the run under a token is in the owner script | §7 |
| 4 | Service-account count limit per plan, and op's wording | **Partly verified**: 1Password docs say "You can create up to 100 service accounts", with no per-plan split. op's wording at the limit: **still unknown** | §7 |
| 5 | Activity reporting on every plan (FM7) | **Refuted as stated**: "Most reports are only available in 1Password Business"; Teams can trial reports and the audit log. Service-account usage reports are not promised on Teams or Families. FM7 detection must not rely on it | §7 |
| 6 | `op` accepts a token by any channel other than the env var | **Refuted**: only `OP_SERVICE_ACCOUNT_TOKEN`. No flag, file or fd channel (help plus binary strings) | §7 |
| 7 | `plan`/`status` causes under reader grants with `deploy_credentials` | **Still unknown**: not reachable from S1; S12 pins it with opv-sim | n/a |

Also listed for S1 in §14: `--expires-in 90d` is **syntactically valid** (help: "(s)econds,
(m)inutes, (h)ours, (d)ays, or (w)eeks"). Whether the server accepts 90 days is **still unknown**:
the docs give no maximum, and the owner script creates only one account, at 1 h. S16 checks it
with the real create.

## 4. Crate and backends for S4

crates.io, 2026-11-17:

| Crate | Latest | MSRV | Role |
|---|---|---|---|
| `keyring` | 4.2.0 (2026-08-29) | 1.88 | Facade. Default feature `v1` = Keychain + Windows + zbus Secret Service. Adds nothing opv needs, and its feature set picks stores implicitly. **Not used.** |
| `keyring-core` | 1.0.1 (2026-10-13) | 1.85 | `Entry`, `CredentialStoreApi`, `Error::{NoEntry, NoStorageAccess, PlatformFailure, ...}`. **Used.** |
| `apple-native-keyring-store` | 1.0.2 | 1.85 | macOS. Features `keychain` (login keychain) and `protected` (data-protection keychain). **Use `keychain`.** |
| `windows-native-keyring-store` | 1.1.0 | 1.88 | Windows Credential Manager (generic credentials). Default feature `search` pulls `regex`; **use `default-features = false`.** |
| `zbus-secret-service-keyring-store` | 1.0.1 | 1.88 | Secret Service, pure Rust (zbus 5, about 126 crates in its tree). **Use with `rt-async-io-crypto-rust`**, which ties nothing to opv's optional `tokio` and needs no OpenSSL. |
| `dbus-secret-service-keyring-store` | 1.0.1 | 1.88 | Same, but over libdbus (C, `libdbus-1-dev` to build). **Not used.** |
| `secret-service` | 5.2.0 (2026-11-06) | | Direct use for the no-prompt lock check (`Collection::is_locked`). Already in the tree via the zbus store. **Used.** |
| `linux-keyutils-keyring-store` | 1.0.0 | 1.85 | Stores in the **session** keyring and links the persistent keyring if the kernel has one. **Not used**: see §5.1. |
| `linux-keyutils` | 0.2.5 | | Raw keyctl. **Used directly** for `@u` with user-read permissions. |

```toml
# S4, Cargo.toml (exact pins; opv's MSRV 1.100 covers all of them)
keyring-core = "=1.0.1"
secret-service = { version = "=5.2.0", default-features = false, features = ["rt-async-io-crypto-rust"] }   # Linux
zbus-secret-service-keyring-store = { version = "=1.0.1", features = ["rt-async-io-crypto-rust"] }          # Linux
linux-keyutils = "=0.2.5"                                                                                    # Linux
apple-native-keyring-store = { version = "=1.0.2", features = ["keychain"] }                                 # macOS
windows-native-keyring-store = { version = "=1.1.0", default-features = false }                              # Windows
```

(Platform deps go under the matching `[target.'cfg(...)'.dependencies]` tables. The WSL source
in §5.3 needs no crate.)

Backend set by platform:

| Platform | Source | Fallback |
|---|---|---|
| macOS | Keychain (`apple-native-keyring-store`) | none |
| Windows | Credential Manager (`windows-native-keyring-store`) | none |
| WSL (detected by `/proc/sys/fs/binfmt_misc/WSLInterop` or `WSL_INTEROP`) | **Windows Credential Manager through interop** (§5.3) | `@u` with `agent_store_volatile` when interop is off |
| Linux desktop | Secret Service, only if a provider is on the bus **and** the default collection is unlocked | `@u` with `agent_store_volatile` |
| none | `agent_store_unavailable` | never a file |

## 5. Measurements

### 5.1 Kernel keyring

```
$ probe persistent                 -> persistent keyring: unavailable (OperationNotSupported)

# linux-keyutils-keyring-store (session keyring)
$ probe ku-set                     -> stored
$ probe ku-get                     -> present+match (0 ms)
$ bash -c 'probe ku-get'           -> present+match (0 ms)         # child process
$ setsid probe ku-get              -> present+match (0 ms)         # new process session, same keyring
$ wsl.exe -e probe ku-get          -> present+match (0 ms)         # new WSL process from Windows
$ probe ku-get-newsession          -> absent (0 ms)                # after KEYCTL_JOIN_SESSION_KEYRING
$ systemd-run --user --wait --pipe probe ku-get -> absent (0 ms)   # systemd user service

# linux-keyutils directly, @u, default permissions (possessor all, user view)
$ probe u-set ; probe u-get        -> stored in @u ; present+match (0 ms)
$ probe u-get-newsession           -> absent (AccessDenied)        # not possessed: user has view only

# @u with user view+read+search
$ probe u-set-userread             -> stored in @u with user read
$ probe u-get-newsession           -> present+match (0 ms)
$ systemd-run --user ... probe u-get-newsession -> present+match (0 ms)
$ wsl.exe -e probe u-get           -> present+match (0 ms)
$ probe u-del ; probe u-get        -> deleted ; absent (KeyDoesNotExist)
```

Conclusions:

- **The keyutils store is session-scoped, and on WSL nothing else.** With no persistent keyrings
  in the WSL kernel, `linux-keyutils-keyring-store`'s persistent link is silently skipped
  (`get_persistent(..).ok()` in its `cred.rs`). An agent started as a systemd user service, or in
  any new session keyring, reads `absent`. Hence S4 uses `@u` directly.
- **`@u` must be written with user read and search permission**, or a process outside the
  writer's session gets `AccessDenied`. This widens nothing beyond D11 (same uid).
- **Volatility.** keyutils is RAM-only (the store's own `persistence()` is `UntilReboot`).
  `user-keyring(7)`: the user keyring "remains pinned in existence so long as there are processes
  running with that real UID", and it "is destroyed when the UID record is destroyed when the last
  process pinning it exits". With `Linger=no`, closing the last WSL terminal ends the uid's
  processes, and WSL then idles the VM down. `@u` is therefore lost at every VM stop **and** when
  the last terminal closes. Not reproduced here, because ending every uid-1000 process would end
  this session. The owner script's reboot check stores a dummy in `@u` as the control.
- Reads never prompt and never block: 0 ms in every case.

### 5.2 Secret Service

```
# The owner's real session bus: no provider
$ probe ss-connect -> error:platform_failure(zbus error: org.freedesktop.DBus.Error.ServiceUnknown:
                      The name org.freedesktop.secrets was not provided by any .service) (6 ms)
# No bus at all
$ probe ss-get     -> error:platform_failure(... Failed to connect to address ... No such file) (0 ms)

# Private bus, oo7-daemon started without a password (as at a WSL VM start: no PAM login)
$ probe ss-lockstate        -> default collection locked=true (29 ms)
$ probe ss-set              -> timeout after 5000 ms        # waiting on an unlock prompt
$ timeout 30 probe ss-set-unbounded ; echo $? -> 124       # unbounded: hung until killed
  daemon log: "Prompt `/org/freedesktop/secrets/prompt/p0` created."

# oo7-daemon --login, unlocked with a dummy keyring password on stdin
$ probe ss-lockstate        -> default collection locked=false (11 ms)
$ probe ss-set              -> stored (92 ms)
$ probe ss-get              -> present+match (11 ms)
$ bash -c 'probe ss-get'    -> present+match (9 ms)
  on disk: keyrings/v1/login.keyring, 452 bytes, dummy not present in plaintext

# Daemon restarted with no password (simulates the next VM start)
$ probe ss-lockstate        -> default collection locked=true (9 ms)
$ probe ss-get              -> absent (74 ms)               # NOTE: locked reads as "absent" on oo7
```

Conclusions:

- **Vet R6 is real.** `keyring-core`'s Secret Service store unlocks as part of `get` and `set`
  (`Service::find_matching_items` calls `unlock_all`; `ensure_unlocked` on every item op), and the
  call blocks on the prompt for as long as nobody answers. The store API has no timeout.
- **Bounding works:** run the store call on a worker thread and `recv_timeout(5 s)`. On timeout
  the process must not reuse that store (its internal `Mutex` is held by the abandoned thread), so
  opv fails with `agent_store_locked` and exits, which matches the design.
- **Check the lock first.** `secret_service::blocking::Collection::is_locked()` answers in 9 to
  29 ms without prompting. Without it, oo7 reports a locked item as **absent** (it hides item
  attributes while locked), which opv would misreport as `agent_identity_not_installed`. With
  gnome-keyring, a locked item is returned as locked and the store prompts instead (from the code
  path; gnome-keyring was not installable here without sudo).
- **On WSL, Secret Service is persistent but not unattended.** The collection file survives, but
  every VM start needs an unlock with the keyring password (no PAM login unlocks it on WSL). That
  person step is no better than `--install`. A blank-password collection would be unattended, but
  gnome-keyring then stores it unencrypted on disk, which SR-4 rules out.

### 5.3 Windows Credential Manager through WSL interop

Not in the design's option list. It is the one store reachable from WSL that lives outside the
WSL VM. Tested with Windows PowerShell 5.1's WinRT `Windows.Security.Credentials.PasswordVault`,
the dummy passed on **stdin** (never argv) and read back on stdout:

```
$ printf '%s' "$dummy" | powershell.exe -NoProfile -NonInteractive -Command '<fixed script: read stdin, PasswordVault.Add>'
stored                            set ms=1701
$ got=$(powershell.exe -NoProfile -NonInteractive -Command '<fixed script: Retrieve, RetrievePassword, write>')
get ms=635 ; [ "$got" = "$dummy" ] -> match
$ powershell.exe ... '<Remove>'   -> deleted
# Same snippets as in the owner script, run with the dummy:
present_before: absent ; store: stored ; match ; present_after: present ; delete: deleted ; present_final: absent
```

Findings:

- Headless, no prompt, works under systemd and from the agent's shell. It is bounded by killing
  the child (`timeout`), so 5 s holds. The cost is 0.6 to 1.7 s of `powershell.exe` start-up once
  per opv process (identity resolves once per process, §4.3).
- It fits ADR-0001 R2 as written ("stdin or a pipe to a platform tool"). opv reads the child's
  stdout straight into a `SecretValue`, and the child's stderr is captured and scrubbed.
- It survives `wsl --shutdown` by construction, since the store is on the Windows side and
  unlocked whenever the Windows user is signed in. The owner's reboot check confirms this (§6).
- Residual: any process of the same **Windows** user can read it, in addition to the WSL shell.
  That is the same reach as native Windows (§4.4 row) and falls under D11.
- Fails closed: when interop is disabled (`[interop] enabled=false`) or PowerShell is blocked
  (Constrained Language Mode, AppLocker), the result is `agent_store_unavailable`, and `@u` is
  used only with doctor `FAIL agent_store_volatile`.
- Design note for S4: native Windows opv would use `windows-native-keyring-store` (generic
  credentials, `CredWrite`), and WSL opv uses `PasswordVault` (web credentials). They are
  different namespaces on the same Windows user, which fits D1 if the WSL distro counts as its own
  machine. Using `CredRead` from WSL instead needs `Add-Type` P/Invoke (slower start-up). It is an
  S4 choice, not a blocker.

## 6. WSL recommendation (D2/D10) and S19

**Recommendation: persistent.** Make Windows Credential Manager through interop the WSL store,
and **drop S19** (no Private-vault durable copy, no `--install --agent`). This rests on these
facts:

1. No Linux-side store is both persistent and unattended on stock WSL. keyutils is RAM-only and
   the WSL kernel lacks `CONFIG_PERSISTENT_KEYRINGS`. Secret Service needs a package install plus
   an unlock at every VM start.
2. Windows Credential Manager is reachable headless from WSL, needs no install, is unlocked
   whenever the Windows user is signed in, and lives outside the VM.

What changes in the design if the owner accepts this:

- §4.4 WSL row: "Windows Credential Manager through interop. `@u` fallback (FAIL
  `agent_store_volatile`) when interop is off. Secret Service only if running and unlocked."
- S4 gains the interop source (about 1 h more, within its 4 h).
- D10's "Secret Service with setup documented" path is not needed on WSL.
- S19 drops out (−4 h after the MVP).
- One fact for the Private-vault option, if it is ever revived: op says "You can't grant a service
  account access to your Personal or Private vault". The durable copy would therefore always be
  read by the person (as D10 assumed), never by the agent. Its vault is named Private, Personal or
  Employee depending on the account type (`op item create --help`, `--vault`). Address it by
  vault type, not by name. The owner script records the names and types.

**Gate:** this recommendation stands only if the owner's `--after-reboot` run shows
`windows_credential_manager_entry: present`. If it shows `absent`, the answer is volatile, S19
stays, and §5.2's lock behaviour decides the Secret Service documentation.

Owner results: *(pending: fold in `spike-338-owner-results.txt` after the owner runs the
script)*.

## 7. op 2.40.0 and 1Password facts

From help text (read-only, `op 2.40.0`):

- `op service-account create <name> [--vault <vault>:<perm>[,<perm>]]... [--expires-in duration]
  [--can-create-vaults] [--raw]`. Permissions: `read_items` (the default when none is given),
  `write_items` and `share_items` (both need `read_items`). `--expires-in`: "(s)econds,
  (m)inutes, (h)ours, (d)ays, or (w)eeks", for example `24h`. "You can't grant a service account
  access to your Personal or Private vault."
- `op service-account ratelimit [{ <serviceAccountName> | <serviceAccountID> }]` (alias
  `ratelimits`): "Retrieve hourly and daily rate limit usage". The argument is optional.
- Token channels: the help names only `OP_SERVICE_ACCOUNT_TOKEN`. `--session` is a person-session
  token. Every `OP_*` name in the binary (`strings op | grep -oE 'OP_[A-Z_]{3,}' | sort -u`):
  `OP_ACCOUNT OP_CACHE OP_CONNECT_HOST OP_CONNECT_TOKEN OP_DEBUG OP_DEVICE OP_FORMAT
  OP_INCLUDE_ARCHIVE OP_ISO_TIMESTAMPS OP_PLUGIN_ALIASES_SOURCED OP_SECRET_KEY
  OP_SERVICE_ACCOUNT_TOKEN OP_SESSION OP_SESSION_ OP_SOCK OP_UNREDACT_LOGS`. There is no file or
  fd variant, so F1 cannot pass the token by fd and the environment of `op` stays the only
  channel. (`OP_UNREDACT_LOGS` exists: opv should strip it from `op`'s environment.)
- `op item create --vault`: "Default: Private, Personal, or Employee, depending on your account
  type."

From 1Password docs (fetched 2026-11-17):

- [service-accounts](https://www.1password.dev/service-accounts/): "You can create up to 100
  service accounts." There is no per-plan split. Usage reports exist ("see what items a service
  account accesses by creating a usage report"), but the plan availability is not stated there.
- [rate-limits](https://www.1password.dev/service-accounts/rate-limits/): hourly, per token,
  reads and writes counted separately: Business 10,000 reads and 1,000 writes; 1Password, Families
  and Teams 1,000 reads and 100 writes. Daily, per **account**, reads and writes combined:
  Business 50,000, Teams 5,000, 1Password and Families 1,000. Errors are HTTP 429 "Too Many
  Requests: You've reached the maximum number of this type of requests this service account is
  allowed to make." (hourly) and "... this 1Password account is allowed to make." (daily). The
  `ratelimit` columns are `TYPE ACTION LIMIT USED REMAINING RESET`. For vet R7: the daily limit is
  shared with CI, and on a Families or individual plan it is only 1,000 requests. An agent loop
  can exhaust it in minutes, so S10's warning threshold matters most there.
- [reports](https://support.1password.com/reports/): "Most reports are only available in
  1Password Business." Teams can trial reports and the audit log.

## 8. Owner step

One command, in the owner's own terminal, signed in to 1Password:

```
! bash /home/mc/.cache/lanes/opv-0220-s1/docs/design/spike-338-owner.sh
```

It asks for an account (Enter for the default) and a vault name or id. It creates
`opv-spike-338-<date>-<time>` (read_items, 1 h) and prints names-only lines: whoami type and
account, vault names and count, `sa_item_create: refused (...)`, the ratelimit table,
`windows_credential_manager_readback: match`, and the `@u` control. It then prints the reboot
steps (`wsl --shutdown` from Windows, then `bash <same path> --after-reboot`, which prints
present or absent and deletes the entries) and how to delete the service account in the web app
(Developer > Service accounts). The script never deletes the account itself, and the token also
expires after 1 h. Checks run: `bash -n` and `shellcheck` are clean. The Windows store snippets
were exercised with the dummy. The script itself was not run: it needs the owner's session.
