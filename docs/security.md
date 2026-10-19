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
`unreadable` and `not_wanted`.

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
