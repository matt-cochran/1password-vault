# Installing opv

## Install

### Install script (Linux and macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/matt-cochran/1password-vault/main/install.sh | sh
```

`install.sh` installs or updates `opv` into `~/.local/bin` without `sudo` and without
npm, Homebrew or Rust. It picks the release asset for your OS and CPU (including
WSL and macOS under Rosetta), verifies the download against the release's
`SHA256SUMS`, and, when `gh` is available, runs
`gh attestation verify <file> --repo matt-cochran/1password-vault`. An unknown
platform, a missing checksum tool or a checksum mismatch fails closed.

```sh
sh install.sh --version v0.5.0   # install exactly this release (default: latest)
sh install.sh --dir /usr/local/bin
sh install.sh --check            # report what would happen, change nothing
```

When `opv` is already present in the target directory, the script compares
`opv --version` with the target version: it prints `opv <old> → <new>` when it
replaces the binary and `opv <version> is already installed` when it is already
current. `--check` prints the same intent without downloading or writing
anything. The binary is downloaded to a temporary file in the target directory
and moved into place only after verification, so an interrupted run never
leaves a broken `opv`. If the directory is not on `PATH`, the script prints the
`export PATH=...` line to add.

`OPV_INSTALL_BASE_URL` overrides the release base URL for the test harness only.

### Release binaries

Download the asset for your platform from the [latest release](https://github.com/matt-cochran/1password-vault/releases/latest), together with `SHA256SUMS`, and [verify it](#verify-a-download).

| Platform | Asset |
|---|---|
| Linux x86_64 (musl) | `opv-x86_64-unknown-linux-musl` (also published as `opv`, an alias of this file) |
| Linux aarch64 (musl) | `opv-aarch64-unknown-linux-musl` |
| macOS Intel | `opv-x86_64-apple-darwin` |
| macOS Apple Silicon | `opv-aarch64-apple-darwin` |
| Windows x86_64 | `opv-x86_64-pc-windows-msvc.exe` |
| Windows ARM64 | `opv-aarch64-pc-windows-msvc.exe` |

Linux and macOS:

```sh
chmod +x opv-aarch64-apple-darwin
# macOS only: remove the quarantine flag set on downloaded files
xattr -d com.apple.quarantine opv-aarch64-apple-darwin
mv opv-aarch64-apple-darwin /usr/local/bin/opv
```

Windows: rename the `.exe` to `opv.exe` and put it on your `PATH`.

### From source

```sh
cargo install --git https://github.com/matt-cochran/1password-vault --locked
```

The minimum supported Rust version is 1.88.

### npm

```sh
npm i -g @matthew-cochran/opv
npx @matthew-cochran/opv --version
```

The npm package is `@matthew-cochran/opv` (npm does not allow the unscoped name `opv`), published from v0.2.1; the installed command is `opv`. Through per-platform optional dependencies, npm picks the right prebuilt binary for your OS and CPU, and a postinstall script copies it to `~/.local/bin/opv` (`%LOCALAPPDATA%\Programs\opv\opv.exe` on Windows), the same place `install.sh` uses. It never replaces a file that is not an opv binary, and never writes into a home directory under `sudo`: run `npm i -g` without sudo. With `--ignore-scripts` the `opv` command still works from its bundled copy; run `npm rebuild -g @matthew-cochran/opv` to install the shared copy.

### One install location

The install script and npm put `opv` in the same place, so either one can install or update it and your shell never runs a stale copy:

| OS | Location |
|---|---|
| Linux, macOS, WSL | `~/.local/bin/opv` |
| Windows | `%LOCALAPPDATA%\Programs\opv\opv.exe` |

`npm i -g @matthew-cochran/opv` copies the binary there when it installs, and `npm uninstall -g` removes it only if opv put it there. It never overwrites a file that is not an opv binary. If you installed with `--ignore-scripts`, opv still runs and tells you once: `opv is not installed at ~/.local/bin; run: npm rebuild @matthew-cochran/opv`. If `~/.local/bin` is not on `PATH`, the installer prints the line to add.

`opv doctor` lists every `opv` it finds on `PATH` with its version. More than one different file is a warning with the command that removes the extra one. `cargo install` uses `~/.cargo/bin`, which is a different location: use it only if you do not use the others, then remove the extras:

```sh
type -a opv        # every opv on PATH; the first one runs
rm ~/.cargo/bin/opv   # or: cargo uninstall opv
hash -r
```

## Verify a download

Download the release asset you want and the `SHA256SUMS` file. Then, from the directory containing both, verify the checksum and the build provenance. Replace the asset name with the one you downloaded.

Linux:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

macOS (the `--ignore-missing` flag does not exist in `shasum`, so check the one line):

```sh
grep opv-aarch64-apple-darwin SHA256SUMS | shasum -a 256 -c
```

Windows PowerShell (compare the output with the matching line in `SHA256SUMS`):

```powershell
Get-FileHash .\opv-x86_64-pc-windows-msvc.exe -Algorithm SHA256
```

Provenance, on any platform with the GitHub CLI:

```sh
gh attestation verify opv-x86_64-unknown-linux-musl --repo matt-cochran/1password-vault
```

## Prerequisites

Install only what your target needs; `opv doctor` checks exactly that and prints the install command for your OS.

| Need | Version | For |
|---|---|---|
| 1Password CLI `op` | tested with 2.40.0 | everything |
| `flyctl` | tested with 0.4.112 and later 0.4.x patches | Fly targets |
| Azure CLI `az` | 2.60 or newer | Azure targets |
| `kubectl` | a version that matches your cluster (opv checks only that it runs) | Kubernetes targets |

`opv doctor` warns (exit code unchanged) when a version differs.

- **Azure on Windows:** works natively. Values reach `az` through a named pipe only your user can open (Linux, WSL and macOS use stdin).
- **Kubernetes:** opv uses the cluster context named in `secrets.toml`, not your current one. Your kubeconfig must contain it.
- **For CI:** a read-only 1Password service account (`OP_SERVICE_ACCOUNT_TOKEN`) with access to the environment's vault, plus the target's credentials: a `deploy_credentials` item in that vault (Fly or Azure), the CI provider's OIDC federation (such as `azure/login`), `FLY_API_TOKEN`, or a kubeconfig.
- **Locally:** `opv login <env>` (or the 1Password desktop app integration), plus `deploy_credentials` or `fly auth login`, `az login` or a working kubeconfig.
- **Writes to 1Password:** the layout tidy, `setup` and every manifest write (`init` in a new project, `add`, `config import`, `config edit`) need a person signed in with their own session; `item skeleton` needs an identity that may edit the item. A read-only service account is enough for everything else, CI included.
