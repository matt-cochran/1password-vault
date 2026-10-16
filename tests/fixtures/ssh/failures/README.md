# OpenSSH client failure recordings (ssh diagnosis, #139)

Real output from the OpenSSH client, recorded on 2026-10-15 for the ssh diagnosis strategy (docs/design/error-catalog.md §5). Nothing here is invented. Each case has `NN-<case>.stderr` (verbatim stderr, with markers substituted) and `NN-<case>.exit` (the exit code). stdout was empty in every case, so it isn't saved.

## Versions

- Client: `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024` (`ssh -V`)
- Server: `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20` sshd, run as an unprivileged user on `127.0.0.1:42222`. The binary was extracted from the Ubuntu noble `openssh-server` package with `dpkg-deb -x`, not installed. It ran with its own throwaway ed25519 host keys and config in a temp dir (`UsePAM no`, `StrictModes no`, publickey only, `LogLevel VERBOSE`).
- Remote login shell: `/bin/bash` (cases 07 and 08 show bash's wording; other shells word it differently).
- Platform: Linux 6.18 (WSL2), Ubuntu 24.04.

All keys were generated for this recording and then thrown away. No real host or credential was used. `SSH_AUTH_SOCK` was unset, so no agent keys were offered.

## The command

Every case uses opv's exact option set (`ssh_args` in `src/app/remote_delivery.rs`, with `identity_file` set):

```
ssh -F none -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=<KNOWN_HOSTS> -o GlobalKnownHostsFile=/dev/null \
  -o HostKeyAlias=opv-remote-<PROFILE> -o UpdateHostKeys=no -o CheckHostIP=no \
  -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes \
  -o PermitLocalCommand=no -o ControlMaster=no -o ControlPath=none \
  -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
  -o IdentitiesOnly=yes -i <IDENTITY> \
  -p <PORT> -l <USER> -- <HOST> '<REMOTE_CMD>'
```

The pinned file holds one line, in the format opv writes (`known_hosts_line`): `opv-remote-<PROFILE> ssh-ed25519 AAAA…`. In the table, **[opts]** stands for every option above, from `-F none` through `ConnectTimeout`, `ServerAlive…` and `IdentitiesOnly=yes`.

## Markers

| Marker | Replaces |
|---|---|
| `<TMP>` | the temp lab directory |
| `<KNOWN_HOSTS>` | full path of the pinned known_hosts file |
| `<KNOWN_HOSTS_TRUNCATED_100>` | the same path, **cut by OpenSSH itself** to its first 100 characters (see note 1) |
| `<FINGERPRINT>` | `SHA256:<43 base64 chars>` |
| `<PROFILE>` | the remote profile name (`lab`) in `opv-remote-<PROFILE>` |
| `<USER>` | the login user |
| `<HOST>` | `127.0.0.1` |
| `<PORT>` | the lab port, 42222 |
| `<UNRESOLVABLE_HOST>` | `opv-lab-host.invalid` (RFC 6761 `.invalid`) |
| `<UNROUTABLE_HOST>` | `192.0.2.1` (RFC 5737 TEST-NET-1, which drops packets) |

## Cases

| # | Case | Command ([opts] as above) | Exit | Key stderr | Design §4 cause |
|---|---|---|---|---|---|
| 01 | Host key mismatch: the pin holds a different key than the host presents | `ssh [opts] -o UserKnownHostsFile=<KNOWN_HOSTS> -i <TMP>/cli/id_ed25519 -p <PORT> -l <USER> -- <HOST> '<TMP>/bin/opv remote-receive'` | 255 | `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` … `Host key for opv-remote-<PROFILE> has changed and you have requested strict checking.` / `Host key verification failed.` | `RemoteUnreachable` (pinned-key half of its hint). Before the handshake. |
| 02 | Host key unknown: the pin file is empty, so no key is pinned for the alias | same, with an empty `<KNOWN_HOSTS>` | 255 | `No ED25519 host key is known for opv-remote-<PROFILE> and you have requested strict checking.` / `Host key verification failed.` | `RemoteUnreachable`. If opv ever runs with an empty or missing pin file, that is opv's own state and might be better reported as a config cause (see note 3). |
| 03 | Authentication refused: the offered key isn't authorized (BatchMode, publickey only) | same, `-i <TMP>/cli/wrong_ed25519` | 255 | `<USER>@<HOST>: Permission denied (publickey).` | `CredentialRejected` (system ssh, problem Rejected). §4.3 has no `CredentialRef` for an SSH identity yet (see note 3). |
| 04 | Authentication refused: the identity file doesn't exist | same, `-i <TMP>/cli/no_such_key` | 255 | `Warning: Identity file <TMP>/cli/no_such_key not accessible: No such file or directory.` / `<USER>@<HOST>: Permission denied (publickey).` | `CredentialRejected` with problem Unreadable, since the warning line names the cause. Or `ConfigInvalid` on the profile's `identity_file`. |
| 05 | Connection refused: closed port (sshd stopped) | same, `-- <HOST>` | 255 | `ssh: connect to host <HOST> port <PORT>: Connection refused` | `RemoteUnreachable` |
| 06 | Name resolution failure | same, `-- <UNRESOLVABLE_HOST>` | 255 | `ssh: Could not resolve hostname <UNRESOLVABLE_HOST>: Name or service not known` | `RemoteUnreachable` |
| 07 | Remote command missing: opv path doesn't exist on the remote | same, remote cmd `'<TMP>/missing/opv remote-receive'` | 127 | `bash: line 1: <TMP>/missing/opv: No such file or directory` | `ChildStartFailed` (remote: check the profile's opv path). Exit 127 comes from the remote shell. |
| 08 | Remote command not on PATH | same, remote cmd `'opv-not-installed remote-receive'` | 127 | `bash: line 1: opv-not-installed: command not found` | `ChildStartFailed` (remote) |
| 09 | Connection drop mid-session: the per-connection sshd process tree (`sshd: <USER> [priv]`, `sshd: <USER>@notty`, the shell and `cat`) was SIGKILLed 3 s into a session. The client was streaming a payload on stdin, as opv does, and the remote was reading it with `cat >/dev/null`. | same, remote cmd `'cat >/dev/null'`, stdin fed one line per second | 255 | `Connection to <HOST> closed by remote host.` | After the session was established, so not a pre-handshake `RemoteUnreachable`. No §4 cause names an interrupted delivery: `Unrecognized` until the catalog adds one (see note 2). |
| 10 | Server stops answering mid-session: the session's sshd processes were SIGSTOPped. The client's `ServerAliveInterval=15` × `ServerAliveCountMax=3` gave up about 45 s later. | same, remote cmd `'sleep 120'` | 255 | `Timeout, server <HOST> not responding.` | Same as 09 (see note 2) |
| 11 | Success, for contrast | same, remote cmd `'/bin/true remote-receive'` | 0 | *(empty)* | none |
| 12 | Connect timeout: unroutable address, `ConnectTimeout=20` (took 20.05 s) | same, `-p 22 -- <UNROUTABLE_HOST>` | 255 | `ssh: connect to host <UNROUTABLE_HOST> port 22: Connection timed out` | `RemoteUnreachable` |

All six requested cases were produced. 02, 04, 10 and 12 are extra variants. Nothing requested was left unrecorded.

## Notes for the diagnosis

1. **OpenSSH truncates one path in the mismatch banner.** `Add correct host key in <path> to get rid of this message.` prints only the first 100 characters of the known_hosts path (here 100 of 126). The `Offending … key in <path>:<line>` and `ssh-keygen -f '<path>'` lines print it in full. A matcher must not expect the full pin path on the "Add correct host key" line. Match `Host key verification failed.` and `REMOTE HOST IDENTIFICATION HAS CHANGED` instead.
2. **Exit 255 after the handshake isn't always the remote app's.** §4.10 says "after the handshake, 255 is the remote app's own exit". Cases 09 and 10 show ssh itself also exits 255 after the session is up, and says so on stderr with `Connection to <host> closed by remote host.` or `Timeout, server <host> not responding.`. These lines name the host ssh connected to (`<HOST>`), not the `HostKeyAlias`. A diagnosis that sees 255 after the receiver's handshake should check for these lines before treating 255 as the app's exit.
3. **Catalog gaps these recordings show:** `CredentialRef` has no SSH identity variant (03, 04). An empty or missing pin file (02) shows up as an unknown host key, not a mismatch.
4. The host-key cases name the alias (`opv-remote-<PROFILE>`), never the real host. The auth case names `<USER>@<HOST>` with the real host. Connection-level errors name the real host and port.
5. Exit 127 (07, 08) is the remote shell's code. A remote app could also exit 127, so tell them apart by the shell's `No such file or directory` / `command not found` line and by whether the receiver's handshake happened.
