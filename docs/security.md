# Security: the value boundary and its limit

What opv protects, what it cannot, and the options for production work. Reporting,
errors and the JSON contract are in [usage](usage.md#security-model-and-limits).

## The value boundary

A secret value, or anything from which part of a value can be recovered, never appears
on a surface an assistant can read. That covers stdout, stderr, a JSON document, an MCP
response, a log, an error, a file opv writes outside a platform channel or the
application's runtime directory, and a command line. It also covers anything from which
part of a value can be recovered: its length, a prefix or suffix, a digest, an encoding,
an entropy figure and a comparison with a guess.

What may cross the boundary is a **value state**: a closed set of words that describes a
value without carrying any of it — `absent`, `empty`, `placeholder`, `malformed`, `set`,
`unreadable`, `not_wanted` and `supplied` (an infrastructure value, below).

## Filling a file key: `opv set --from-file`

A key declared with `file = "<path>"` holds bytes a paste cannot carry: a PEM's line
breaks and its trailing newline. The person names a file and opv reads it
(`opv set <[p/]KEY> --env <e> --from-file <PATH>`); the path is the only thing on the
command line, and the value reaches `op` on stdin like every other write, so it is never
in argv, a process list, a shell history, a log or an error.

- **A regular file, read and never followed.** A symbolic link is refused before it is
  followed, and so is anything that is not a regular file, a file larger than 64 KiB, and
  bytes that are not UTF-8. Each refusal names the path and the property that failed, never
  a byte or a length of the value.
- **A shared file is a warning, not a refusal.** A file a group or other users can read is
  still written, then named as readable by other users on the machine, with `chmod 600` or
  deleting it suggested. A file anyone can read is the person's risk to accept, as a pasted
  value would be.
- **A person, in a terminal.** An assistant and a non-TTY process are refused before the
  file is opened; an assistant hands the command over and never reads or writes the file
  ([the agent skill](agent-skill.md)).
- **The file stays.** opv does not write, rewrite, move or delete it, so removing the file
  is the person's step once the value is in 1Password. Until then the value exists in two
  places, and the file's mode and where it is stored are what protect the copy on disk.
- **A file key only.** A key without `file` is refused and handed the masked `opv set`, so
  this form never becomes a way to hand opv a value for an ordinary key.

## The honest limit

opv can make its own surfaces incapable of emitting a value. It is not a sandbox, and it
cannot stop an assistant that also has an unrestricted shell as the same OS user from
reaching whatever that user's sessions can reach:

- `op read` and `op item get` through the person's 1Password session;
- platform CLIs already logged in on the machine (`kubectl`, `az`, `flyctl`, `gh`);
- the running application and its logs, and deployed logs the person can read;
- a pull request that changes a CI workflow.

Three layers limit the damage, and none of them is a sandbox:

- opv's own surfaces are value-free by construction;
- 1Password vault permissions are the tier boundary: a developer's session reaches only
  local and dev vaults **where the team's vault groups are tight**, and opv reports when
  they are not;
- 1Password's own authorization prompt is defence in depth.

## Who can read a deployed tier

1Password offers no usable "write but not read". A spike (A-1) took viewing away from a
throwaway vault and kept write permissions: as soon as viewing went, the vault disappeared
from the app, and a hidden vault is not listed, so there is nowhere to create or edit an
item. Writing needs viewing.

Say it plainly: **anyone who can set a deployed tier's values can also read them.** opv
cannot narrow that, and the design does not try. The record is in
[Spike A-1](design/spike-a1-findings.md).

## The accepted residual, and the hardened option

A DevOps machine whose 1Password account can read production by design lets an assistant
in its shell read production too. The owner accepted this as a residual risk.

The hardened option is a separate 1Password admin account, used only for production work:

- production values are entered from that account, not the everyday one;
- the everyday account, and any assistant running in that person's shell, then has no
  access to production vaults.

opv reports when the current session can read a production-tier vault or holds a
production platform login: `opv doctor` and `opv access`. It is a finding, never a block,
with the admin-account setup as the fix.

## The courier invariant: how values reach platforms

Every transport hands a value to its platform tool on stdin, or through the private
user-only named pipe for the Azure CLI on Windows. A value never appears in argv, in a
file opv wrote, or in the rendered output. Local delivery hands the value to the
application through the child process's environment or a private tmpfs file.

`tests/courier.rs` drives every transport with a marker value and fails if the marker
reaches any other channel. What a tool does with a value after opv hands it over
correctly is out of scope; opv's scrubber still masks a value a tool echoes back, as
best-effort defence.

An [HTTP target](http-target.md) hands each value to the application's API as the bytes of one
pinned `string`/`bytes` request field; the request template cannot reference a credential, and no
other field is ever set from a value. The three credentials live only in the `deploy_credentials`
item and reach the runner as HTTPS header pairs, never argv, an error, a log or a file, and header
values are never printed (even `--verbose` prints only the RPC name, host, status and duration).
The destination is checked against both the item's `base_url` and the configuration's `http.host`,
so changing it takes a vault write and a reviewed configuration change. Like any TLS client,
request buffers inside the TLS library are not zeroized.

## Values opv never stores: infrastructure values

From 0.13.0 a key declared `source = "infrastructure"` holds a value that infrastructure
produces, such as a database URL from Terraform or a webhook signing secret. It is
delivered, never stored ([the guide](infra-generated-values.md)):

- **Never in 1Password.** opv keeps no 1Password field for the key. `opv set`, `opv open`,
  `opv import --replace` or `--rotate`, `opv propose generate` and an attestation refuse it,
  `opv import` reports a found value as `not_stored`, and a field that already exists for
  it refuses every sync until a person archives it. CI gets no new 1Password permission:
  the deploy identity reads the boundary vaults and writes the state vault, as before, and
  CI never writes a value to 1Password.
- **Standard input only.** The deploy job that produced the value pipes it to
  `opv sync <env> --supply-stdin`. A terminal on standard input is refused before a byte is
  read, and so is a run from an AI assistant: an assistant proposes the key, the deploy job
  supplies the value. The generated step (`opv ci workflow --supply`) moves values through
  a pipe, never argv, environment variables or files, and `opv ci workflow --supply-check`
  refuses a `${{ … }}` expression in that step's script, which GitHub would expand into the
  logged script.
- **Scrubbed as it is read.** Each value is registered with opv's scrubber as a secret while
  the stream is parsed, and must be at least 8 bytes so the scrubber can mask it. A parse
  error is reported by line and column, never quoting the input, and an entry that is not
  a declared key is reported by position (`document 2, entry 3`), because a mapping bug can
  put a value where a name belongs.
- **Evidence without the value.** The placement's delivery item records an `s1` line: the
  target's version, a keyed fingerprint of the value, the key, the producer's serial and
  the time. A lower serial, or the same serial with a different value, is refused unless the
  run names the key with `--rotate`, so an old value cannot be replayed by accident.

The residual is the producer itself: the Terraform state, the provider's console and the
job that runs them hold the value, and opv does not protect them.

## Attestation: evidence without a proof

From 0.12.3 a person may attest that a staged target (Fly) already holds 1Password's value
of a held immutable key that no sync can prove ([attesting a held immutable
key](attestation.md)). opv records the evidence at the target's current version without
writing the target. It is a person's `opv apply` in their own terminal, refused under CI
and agent mode, and every surface marks the name `attested`, never proven: receipts list it
under `attested`. opv cannot check an attestation; a wrong one is caught only when the app
fails, so attest only when you know where the target's value came from, and rotate
otherwise. An infrastructure key cannot be attested: there is no 1Password value to vouch
for.

## Local delivery hardening

`opv run` writes a file key to a fresh private directory on a RAM-backed
`$XDG_RUNTIME_DIR`. From 0.13.0:

- a runtime directory that other users can write (a group or other write bit without the
  sticky bit, such as WSLg's 0777 `/mnt/wslg/runtime-dir`) is refused before anything is
  written: `ram_dir_unavailable`, `why` `writable_by_others`;
- the private directory is opened once and checked through that handle, and every file is
  created relative to it (`O_NOFOLLOW`, `O_EXCL`), so renaming the entry afterwards cannot
  redirect a write;
- before the app starts, every descriptor above 2 is marked close-on-exec, so a descriptor
  inherited from `op run` does not reach the app.

What opv cannot enforce, such as another process of the same user, root and swap, is listed
with the code behind each claim in [platforms and
limits](design/local-delivery.md#platforms-and-limits).

## Harness guard rules

opv installs no guard rules. If your assistant runs in a harness that supports deny
rules, add your own to keep it away from value reads. They are a convenience, not the
control: a shell the assistant can use can bypass them, and 1Password's authorization
prompt is the real protection for writes.

Example deny rules, for a harness that takes command patterns:

```yaml
deny:
  - op read                  # a 1Password read through the person's session
  - op item get
  - op inject
  - opv run                  # hands values to the process you start
  - kubectl get secret
  - az keyvault secret show
  - flyctl secrets
  - gh secret
  - gh variable
```

Add the platform CLIs you have logged in against production. Ask the assistant to report
through opv's value-free states (`opv status`, `opv inventory`, `opv ready`), never by
reading a value.

Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
