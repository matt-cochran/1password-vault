# Fly file secrets: live recordings (#136 A5, run `256debcd`)

These are real Fly outputs from the #136 live check, run `256debcd` on 2026-10-21 (UTC). The run used the throwaway app `opv-136-canary` in the owner's personal org, which held canaries only and has since been destroyed. The client was flyctl **v0.4.120** (the session's flyctl updated itself from 0.4.111; see runbook §8, Deviation 5). The image was `docker.io/library/debian@sha256:a29215f6…` (Fly resolved it to its mirror digest `918311b7…`).

The runbook is `docs/verification/v0.13.0-file-delivery.md`, and §5 and §8 explain how to read these files. The answers are in `docs/design/delivery-transports.md` §7.3.

**No values.** The files hold metadata and SHA-256 digests only. The secret `OPVCANARY_A5_FILE` held a canary file of 116 bytes, which is never recorded. Its digests are `a47df9d3…` for v1 and `3275eef6…` for v2. The canary scan of the whole capture set found zero hits.

Two machines, one per mechanism:
- **Machine A**, `8edd22dc379d68`, came from `fly deploy` with `fly.toml` `[[files]]`.
- **Machine B**, `48e7557a943068`, came from `fly machine run` with `--file-secret`.

| File | What it is | Shows |
|---|---|---|
| `machine-a.config.json`, `machine-b.config.json` | `flyctl machine status <id> -d`, third run (`/run` and `/opt`) | the machine configs: `files` entries `{guest_path, secret_name}`, init, restart policy |
| `machine-a.files.json`, `machine-b.files.json` | the `files` entries of the configs above, sorted | **F1:** identical |
| `run2-machine-a.files.json`, `run2-machine-b.files.json` | the same for the second run, which also had `/dev/shm` | F1 held with three paths too |
| `dev-shm-crashloop.log` | `flyctl logs --no-tail`, machine A of the second run, ANSI codes stripped | **F2:** init writes `/dev/shm/…`, its chown fails with ENOENT, the VM reboots, up to "max restart count of 10" |
| `f1-probe-a.txt`, `f1-probe-b.txt` | `canary/a5-probe.sh` in each machine, right after boot | **F2:** on `/` (`overlay`), mode 755 `root:root`, not in the env. **F3:** the v1 digest at every path |
| `f2p-probe-before.txt`, `f2p-probe-after.txt`, `f2p.txt` | machine B after `machine update --rootfs-persist always`, before and after `machine restart` | **F2p:** the sentinel persists; the files keep their inode, get a new mtime and stay on disk |
| `f4.txt` | the version at each path after `fly secrets deploy`, and whether the boot id changed | **F4:** A got v2 and rebooted; B kept v1 and didn't reboot |

The probe prints `fs=-` because `df -T` printed no type in the machine. The filesystem type comes from the `mount … fstype=` lines, which are read from `/proc/self/mountinfo`.

No test reads these files yet. They record Fly's behaviour for the design and for a future `[[files]]` adapter, and nothing here needs a live Fly.
