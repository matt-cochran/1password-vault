# HTTP target: deliver to an application's own secret store

Some applications keep their own secrets in their own encrypted store, written through an admin
API and read at runtime from there. An **HTTP target** is one more delivery target, like Fly
secrets or a Kubernetes Secret: opv reads each value from 1Password, writes it to the store
through the application's API, records a value-free receipt and reports drift when the store
changes outside opv. **1Password stays the source of truth.** The application's store is only
another placement of the same values.

The store applies a write at once, so this is a staged target whose runtime is already live, the
shape of the GitHub Actions target. Nothing is deployed, and there is no separate release step.

The wire format is gRPC-Web from a descriptor set, client only: no server, no HTTP/2 and no code
generation. The JSON wire format is not supported.

## What the target does, per command

| Command | Calls | Result |
|---|---|---|
| `plan`, `status` | `list` | each managed name present or absent with its version; drift against the last receipt; the store's value rules are shown before any write |
| `sync` | `list`, one `put` per changed name, `list` again (`confirm`) | versions recorded from the confirming list; then the written names' statuses are checked |
| `delivery verify` | `list` | `verified` when each listed version equals the recorded one |
| `changed` | none (1Password only) | unchanged |
| `history` | `list` | the recorded and current versions |
| retire (pruning a managed name) | none | refused for this target, before any write; removing a key is a person's action in the application |

## Configuration

### The target section

An HTTP target is declared under `[environments.<env>.targets.<name>]`, like any other target.
The `http.*` keys describe the API calls; the target also carries `products`,
`deploy_credentials` and `state_vault_id` ([targets](configuration.md#targets-where-products-deploy)).

```toml
[environments.prod.targets.platform]
products = ["api"]                                # optional: without it, every non-source-only product
deploy_credentials = "op://Example Platform/opv-platform-prod"   # the item below

http.host = "central.example.com"                 # must equal the item's base_url host
http.descriptor = "deploy/opv/platform_console.binpb"
http.descriptor_sha256 = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445"

[environments.prod.targets.platform.http.names]   # delivered env name = remote name
OPENROUTER_API_KEY = "openrouter"
TAVILY_API_KEY     = "tavily"
STRIPE_SECRET_KEY  = "stripe"

[environments.prod.targets.platform.http.list]
call    = "portal.v1.PlatformConsoleService/ListPlatformConnections"
request = { operator_id = "<tenant uuid>" }        # literal fields, decoded against the request
items   = "connections"                            # descriptor field path to the repeated entry message
name    = "provider"                               # field paths within one entry
version = "version"
status  = "status"                                 # must be an enum field
absent   = ["CONNECTION_STATUS_NOT_CONFIGURED", "CONNECTION_STATUS_REVOKED"]
rejected = ["CONNECTION_STATUS_REJECTED"]

[environments.prod.targets.platform.http.put]
call     = "portal.v1.PlatformConsoleService/SavePlatformConnection"
request  = { operator_id = "<tenant uuid>", provider = "{name}", expected_version = "{version}" }
value    = { field = "secret_value", number = 3, type = "bytes" }
reply    = "connection"                            # field path to the written entry (list's roles apply)
conflict = ["ALREADY_EXISTS"]                      # gRPC codes that mean "changed since opv listed"
                                                   # state_vault_id: the bindings file
```

### Every field

| Field | Meaning |
|---|---|
| `products` | The products this target delivers. Without it, every non-source-only product with a key desired in the environment. |
| `deploy_credentials` | The `op://` item holding the destination and credentials ([below](#credentials-the-1password-item)). Required for this target. |
| `http.host` | The destination host, lowercase ASCII. It must equal the `base_url` host in the item ([below](#destination-two-keys-must-agree)). |
| `http.descriptor` | Path of the pinned `FileDescriptorSet` (a build artifact of the application), resolved beside the configuration file. |
| `http.descriptor_sha256` | The descriptor file's SHA-256. A mismatch is a load error. |
| `http.names` | One line per delivered environment name and the remote name it maps to. Every delivered name must be mapped, and no two names may map to one remote name. |
| `http.list.call` | The full gRPC method name (`package.Service/Method`) used to list the store. |
| `http.list.request` | A literal request object, decoded against the method's request message with unknown fields refused. |
| `http.list.items` | Field path to the repeated entry message in the reply. |
| `http.list.name` | Field path within one entry to the remote name (a string). |
| `http.list.version` | Field path within one entry to the version (an integer). |
| `http.list.status` | Field path within one entry to the status (an enum). |
| `http.list.absent` | Status values that mean "no value here"; an entry with one of them is reported absent. |
| `http.list.rejected` | Status values that mean "the application rejected this value". A written name with one fails the run after the receipt is recorded. |
| `http.put.call` | The full gRPC method name used to write one value. |
| `http.put.request` | A literal request object. A string leaf is a literal or exactly one whole-leaf placeholder, `{name}` or `{version}`. |
| `http.put.value` | The one singular `string` or `bytes` field of the request that receives the value: `field`, `number` and `type` must match the descriptor. |
| `http.put.reply` | Field path to the written entry in the reply; the same roles as `list` apply. |
| `http.put.conflict` | gRPC status names that mean "changed since opv listed"; empty means no code is treated as a conflict. |

### Load rules

The configuration fails fast at load; a message names the file, the field and the rule, never a
value.

1. **Descriptor pinned.** The file's SHA-256 equals `descriptor_sha256`, and every named method
   exists.
2. **One place for the value.** `put.value` names one singular `string` or `bytes` field of the
   request message, and its `number` and `type` must match the descriptor. A renumbered field can
   never receive the value silently.
3. **No templating of the value.** A request template is a literal object decoded against the
   request message with unknown fields refused. A string leaf may be a literal or exactly one of
   two whole-leaf placeholders, `{name}` or `{version}`. Partial substitution, any other
   placeholder and any reference to a credential are load errors. The template may not set the
   value field.
4. **Roles are typed field paths.** `items` is a repeated message field, `name` a string,
   `version` an integer and `status` an enum; every name in `absent` and `rejected` is one of its
   values. Nothing else in a reply is ever read: a masked tail of the value that the application
   returns is never decoded into opv memory.
5. **Every delivered name is mapped**, and no two environment names map to one remote name.
6. **`http.host`** is a lowercase ASCII hostname: not a URL, not an IP literal, no port, no
   trailing dot.
7. **`conflict`** lists gRPC status names; empty means no code is treated as a conflict.

### Value rules the store enforces

opv implements the application's fixed value rules so `plan` shows them and `sync` refuses before
writing. For the first consumer the trimmed value is 16 to 65 536 characters with no control
characters. Contract rules for a key's shape (for example a Stripe `sk_`/`rk_` mode or a `whsec_`
prefix) belong in the configuration too, so a test key is never written to a production slot.

## Credentials: the 1Password item

`deploy_credentials` names one item. Its fields are fixed for this target and **all four are
required**:

| Field | Kind | Use |
|---|---|---|
| `base_url` | text | `https://<host>[/<prefix>]`; the only place the destination is |
| `token` | concealed | sent as `Authorization: Bearer <token>`; opv adds the scheme |
| `cf_access_client_id` | concealed | sent as `CF-Access-Client-Id` |
| `cf_access_client_secret` | concealed | sent as `CF-Access-Client-Secret` |

A credential containing a control character is refused. Every credential is registered with
opv's scrubber, so it never reaches a log, an error or a file. Configuration cannot add headers.
opv cannot mint this credential, so `opv target credentials --create` refuses for this target: a
person creates the item, and vault access decides who may.

## Destination: two keys must agree

The destination is written twice and both must agree:

- `http.host` in the configuration, and
- the `base_url` host in the 1Password item.

`base_url` is parsed once: scheme `https`; no userinfo, port, query or fragment; host lowercase
ASCII, not an IP literal, no trailing dot; path prefix of `/`-separated `[A-Za-z0-9._-]`
segments. Its host must equal `http.host`, and the request URI is built from the same parsed
value, so the host that is checked is the host that is connected to.

Changing where values go therefore takes **both** a vault write and a reviewed configuration
change. A staging item used for production fails on the first call. The target locator is the
host plus the list request's literal fields, so a changed host is a new placement and no receipt
carries over.

## Transport rules

- **HTTPS only.** A redirect is never followed; a 3xx is a refusal naming the status code.
- **Deadlines from the runner.** `READ_TIMEOUT` applies to `list`, `WRITE_TIMEOUT` to `put`,
  under the run budget (`--timeout`).
- **OS trust store.** TLS roots come from the operating system's store, so the target works
  behind a TLS-inspecting proxy and no bundled-roots licence enters the tree. An empty OS store
  is a fixed, non-retried refusal.
- **Proxy.** `HTTPS_PROXY` and `NO_PROXY` are honoured; `--verbose` says "via proxy" when one is
  used.

## Versions, receipts, drift and status

The store has a per-name write counter, `version`, bumped by every value change (save, revoke)
and only by those, and no fingerprint of the stored value.

- `list` reports a name present only when its status is not in `absent`. An absent entry's version
  is kept inside the adapter, and unmapped remote names are dropped.
- `put` sends the version from that cached list as `expected_version` (`0` for a slot never
  saved).
- A write is accepted whatever the entry's status, so the version is recorded. After `confirm`
  re-lists, the receipt and evidence are written, and the written names' statuses are checked. A
  name in `rejected` fails the run (`target_unhealthy`, exit 5) after the receipt is recorded.
- **Drift.** A listed version different from the recorded one means the entry was changed outside
  opv since its last sync (`target_drift`, exit 8 under `--fail-on-drift`).
- **A conflict** on `put` (a code listed in `conflict`) is `target_changed` (exit 5), reachable
  end to end through a "version bumped before put" fault.

**What opv can prove.** The version counter detects that the stored value changed, and that the
application accepted a write. **What it cannot prove.** It cannot prove that the stored value
equals the 1Password value when nobody changed it through the API: the counter is accepted for
this version of the target. A server-side keyed digest can be added later. `versions_reveal_values()`
stays `false`, so no command can read a value back out of the store.

**A rejected key never displaces a usable one.** The application must verify a key with its
provider before committing it, or keep the previous key when the new one is rejected. opv reports
the rejection after the receipt is recorded, so the previous usable key is still in place.

Status appears only in `sync`'s check above, not in `plan`, `status`, `history` or
`delivery verify`.

## Generating the section from the application's schema

The `http` section is generated from the application's descriptor set rather than written by
hand:

```sh
opv propose target <env> <name> --provider http --http-host <host> --http-descriptor <file> --http-service <full.name> --http-names KEY=remote,KEY2=remote2
```

opv never guesses a remote name: `--http-names` gives the `http.names` mapping as
comma-separated `KEY=remote` pairs.

The generator reads the descriptor set and writes a proposal through the existing value-free
`propose`/`apply` flow, also reachable through MCP `opv_propose`:

- every RPC of the service with its request and reply field paths, numbers and types, sorted, in
  canonical form: the same descriptor always produces byte-identical output;
- `descriptor_sha256` filled in;
- `http.names` written from the `KEY=remote` pairs the person gave, sorted by environment name;
- suggestions, marked as such, for the decisions a person confirms: which RPC is `list` and
  `put`; which field receives the value (only singular `string`/`bytes` fields are offered, with
  number and type filled in); which fields are `items`, `name`, `version`, `status` (status only
  from enum fields) and which enum values are `absent` and `rejected`;
- no network call; the result passes the same load rules as a hand-written configuration.

The descriptor file is a build artifact of the application (`buf build -o` or
`protoc --include_imports --descriptor_set_out`), committed beside the configuration and pinned
by hash. Server reflection is not used.

## Errors

A new HTTPS system (labelled with `http.host`) uses the existing causes:

| Condition | Cause (exit) |
|---|---|
| item host ≠ `http.host`, malformed `base_url`, missing item field, descriptor hash or field mismatch | `ConfigInvalid` (2), before any call |
| `UNAUTHENTICATED`, `PERMISSION_DENIED`, HTTP 401/403 | `CredentialRejected { DeployCredentials }` (7) |
| 3xx | `TargetRefused` naming the status (5) |
| `list`: 5xx, `UNAVAILABLE`, connect, TLS or timeout | `Unavailable` (9), retried as a read |
| `put`: a declared `conflict` code | `ChangedBeforeWrite { Resource }`, `target_changed` (5) |
| `put`: `INVALID_ARGUMENT` | `TargetRefused` (5), status name and scrubbed message |
| `put`: anything else once the request was sent (5xx, `UNAVAILABLE`, `INTERNAL`, timeout, lost connection, unparseable reply) | `WriteOutcomeUnknown` (9); the next `list` shows what happened |
| reply missing a role field, wrong type, unknown status value | `TargetRefused` naming the field path (5), never the reply |
| written name's status in `rejected` | `TargetRefused { Unhealthy }`, `target_unhealthy` (5), after recording |

Server text (`grpc-message`, an error body) is percent-decoded, scrubbed of every registered
value, stripped of control characters and truncated to 200 characters, in that order. `--verbose`
prints one line per call: RPC name, host, status, duration; never a header or a body.

## What the application must provide

The application's API and non-interactive identity must satisfy these requirements:

- **Scoped TOTP exemption.** The non-interactive identity is accepted without aal2/TOTP only in
  the gate for the connection RPCs, never in the gate that also covers other roles.
- **Least privilege by method.** Only the list and save methods are exposed to the identity.
- **Credential properties.** Revocable server-side; bounded lifetime with a rotation runbook;
  stored only in 1Password; environment-scoped, so a staging token is rejected by production and
  a cross-environment mix-up fails closed; accepted from `Authorization: Bearer` alone.
- **Audited as itself**, distinct from any person.
- **No portal sign-in**, central host only.
- **A Cloudflare Access service token** per environment, scoped to the API host.
- **A rejected key never displaces a usable one:** verify with the provider before committing, or
  keep the previous key when the new one is rejected.
- **Stable wire contract:** a documented conflict code; error text never contains key material;
  field numbers never reused; the descriptor set published with every API change.
- **`version` semantics unchanged:** bumped by every value change and only by those.

## Memory

The value is appended directly to the request bytes from the `SecretValue`; it never passes
through JSON, a `String` or an unzeroized buffer of opv's own. Like any TLS client, request
buffers inside the TLS library are not zeroized, and opv cannot wipe those internal copies.
