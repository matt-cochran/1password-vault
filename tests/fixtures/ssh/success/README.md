# OpenSSH success recordings (host key and fingerprint)

Real output, recorded 2026-10-16 against a throwaway user-mode sshd, set up as in `../failures/README.md`: `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` sshd extracted with `dpkg-deb -x` (with `libwrap0`, not installed), run unprivileged on `127.0.0.1:42222` with its own ed25519 host key generated for the recording and thrown away afterwards. Client `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19`. Each case has `.stdout`, `.stderr` and `.exit`.

| Case | Command | Exit | Output |
|---|---|---|---|
| 01-keyscan-ed25519 | `ssh-keyscan -t ed25519 -p <PORT> <HOST>` | 0 | stdout: the host's key line; stderr: the server banner comment |
| 02-keygen-fingerprint | `ssh-keygen -l -E sha256 -f <pin>`, the pin holding `opv-remote-<PROFILE> ssh-ed25519 AAAA…` (the key from 01, in opv's `known_hosts_line` format) | 0 | `256 SHA256:<43 chars> opv-remote-<PROFILE> (ED25519)` |

The same run also produced the mismatch banner (`../failures/01-host-key-mismatch`) with the pin holding a different key: its line `The fingerprint for the ED25519 key sent by the remote host is` was followed by exactly the `SHA256:…` value in 02, so the simulator fills that banner's `<FINGERPRINT>` with it.

Markers: `<HOST>` `127.0.0.1`, `<PORT>` 42222, `<PROFILE>` the profile name (`lab`). The key and fingerprint are kept as recorded: they belong to a host key generated for this recording and deleted.
