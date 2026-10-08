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
sh install.sh --version v0.3.0   # install exactly this release (default: latest)
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

The npm package is `@matthew-cochran/opv` (npm does not allow the unscoped name `opv`), published from v0.2.1; the installed command is `opv`. It installs a tiny Node shim and, through per-platform optional dependencies, npm picks the right prebuilt binary for your OS and CPU automatically with no install scripts.

### Keep one install

Use one install method per machine. Each one puts `opv` in a different directory
(`install.sh` in `~/.local/bin`, npm in its global `bin`, `cargo install` in
`~/.cargo/bin`), and updating one leaves the others alone. The shell runs the
first `opv` on `PATH`, which may be an old copy:

```sh
type -a opv        # every opv on PATH; the first one runs
opv --version
```

If `type -a` lists more than one, remove the copies you do not update, for
example `rm ~/.local/bin/opv`, `npm uninstall -g @matthew-cochran/opv` or
`cargo uninstall opv`. Then run `hash -r` so the shell forgets the old path.

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

- The 1Password CLI `op`, tested with 2.40.0. The Fly CLI `flyctl`, tested with 0.4.112 and later 0.4.x patches. `opv doctor` warns (exit code unchanged) when a version differs.
- For CI: a read-only 1Password service account (`OP_SERVICE_ACCOUNT_TOKEN`) with access to the environment's vault, and `FLY_API_TOKEN`.
- Locally: the 1Password desktop app integration or `op signin`, and `fly auth login`.
- `item skeleton` is the only command that writes to 1Password; it needs a write-capable identity.
