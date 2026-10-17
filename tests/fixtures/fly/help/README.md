# flyctl help text

Recorded on 2026-10-17 with **flyctl v0.4.111 linux/amd64** (commit 95b7f3e; the same build as `../failures/12-version.stdout`). The command was `FLY_NO_UPDATE_CHECK=1 NO_COLOR=1 flyctl <cmd> --help </dev/null`. It is local help text only: no network call and no login used.

| Case | Command | Used for |
|---|---|---|
| machine-run | `flyctl machine run --help` | `--file-secret /path=SECRET` ("The content of the secret must be base64 encoded"), `--file-literal`, `--file-local`, `--rootfs-persist` |
| machine-update | `flyctl machine update --help` | `--file-secret` |
| deploy | `flyctl deploy --help` | `--file-secret` |

`fly.toml`'s `[[files]]` is not documented in this help. Where Fly writes the file, with what mode, and whether it lives in RAM, needs a live check (`docs/design/delivery-transports.md` §7.3).
