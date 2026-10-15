# MCP interface

opv's MCP server, `opv mcp serve`, uses the official Rust MCP SDK (`rmcp`) over stdio. It
lets an assistant inspect a project, manage its declared structure, and prepare the
1Password structure it needs. A person keeps three things: signing in, approving
structural changes in their own terminal, and entering every secret value in 1Password.

| Tool | CLI | Input | Changes | Response |
|---|---|---|---|---|
| `opv_ready` | `opv ready` | optional declared environment | nothing | findings with their code, blocking flag, actor, effect and next step (an `opv` command or a 1Password item link), each target's state, and counts |
| `opv_configuration` | `opv config describe` | none | nothing | environment names, confirmation flags, product/key names and kinds, and each target's provider, delivered products and whether its state vault and deploy identity are declared |
| `opv_access` | `opv access` | optional environment and target | nothing | each CI or deploy identity's service-account name, vaults, permissions and state, findings with their next step, and for each identity missing a grant the person's `opv access … --create` command |
| `opv_deployment_plan` | `opv plan --json` | declared environment | nothing | each row's target, product, key and action (`write`, `unset`, `hold`, `none`), the `plan_id`, and the `approve_command` a person runs to approve it; no execution |
| `opv_declare_key` | `opv add` | product, key, kind, environments, rules, guidance, immutable | local `secrets.toml` | `changed` |
| `opv_declare_environment` | `opv env add` | environment | local `secrets.toml` | `changed` |
| `opv_declare_target` | `opv target add` | environment, target, provider, public provider options, products | local `secrets.toml` | `changed` |
| `opv_structure_plan` | `opv structure plan` | none | nothing | the structural plan and its `plan_id` |
| `opv_structure_apply` | `opv structure apply <PLAN_ID>` | `plan_id` | 1Password structure, then `secrets.toml` IDs | created public IDs, links for key entry, added field names |
| `opv_generate` | `opv generate <env> <product/KEY>…` | declared environment and 1–20 `product/KEY` names | 1Password values (empty fields only) | each generated key's product, key, `encoding` (`base64` or `hex`) and recipe `bytes`; never a value |
| `opv_sync` | `opv sync <env> --approved <PLAN_ID>` | environment, `plan_id`, optional targets and product, `deploy`, `prune`, `rotate` (`PRODUCT/KEY` entries) | the deployment target (exactly the approved plan, once; rotates only the immutable keys the person approved) | names written, pruned, pending and held, and whether it deployed; on refusal the `approve_command` to show the person |
| `opv_delivery_preview` | `opv run --preview --json` | declared environment, optional product and role | nothing | per delivered key its product, key, `source`, `destination` (`env:<NAME>` or `file:<relative path>`) and `roles`; the keys a role withholds (names only); environment mode, secrets directory variable, file-delivery support and the `op`/signed-in prerequisites (`unknown` when undeterminable); never a value |

Every tool has a CLI command with the same guarantee and the same `--json` document
(the command is also listed by `opv schema` under `mcp_tools`). The CLI apply and sync
still require the person's own `opv approve` first.

No tool accepts or returns a secret value, an arbitrary command, a file path, an
executable, or an approval boolean. Responses are built field by field from checked
identifiers; raw upstream JSON and diagnostic text are never returned. An error is its
stable `code` and a fixed `human_action` (and, for `stale_plan`, the new `plan_id`).

## Who does what

1. **The assistant owns declarations and structure.** It declares products, keys
   (kind, environments, validation rules, one line of guidance, `immutable`),
   environments and named targets with the `opv_declare_*` tools. These edit the local
   `secrets.toml` only: nothing in 1Password, no value. A generated configuration is
   never edited; declare in its generator's input instead.
2. **The assistant plans.** `opv_structure_plan` lists every boundary vault and item,
   state vault, delivery item and empty field the configuration needs in the project's
   1Password account, and returns a `plan_id`. It changes nothing.
3. **The person approves in their own terminal.** `opv approve <plan_id>` re-plans,
   shows each step by name, and asks them to type the plan id back. The approval is
   single use, lasts 15 minutes, and names the project and 1Password account.
4. **The assistant applies.** `opv_structure_apply` with the same `plan_id` re-plans,
   refuses a plan that changed (`stale_plan`) or has no unused approval
   (`approval_required`), then creates exactly the plan. The 1Password app asks the
   person to authorize the writes. It returns created IDs and 1Password links.
5. **The person enters values in 1Password** at those links, never in chat, files or
   arguments.
6. **The assistant checks readiness** with `opv_ready` and reports names and status only.

Not structural, and never through MCP: permission grants (CI reader or deploy
identities), deploy credentials, credential replacement, shared (`from`) and personal
keys, removals and changes to an existing target, sync, deploy, prune, rotation and
release. Each stays a separately approved command in the person's terminal.

## Authorization and its limits

The approval binds one `plan_id`, which is SHA-256 over the project, the 1Password
account ID, the configuration text and every planned step. A plan approved for another
project, account or configuration never applies, and any change after the review makes
the id stale. The approval file lives in the person's state directory
(`$XDG_STATE_HOME/opv/approvals`, else `~/.local/state/opv/approvals`; directory 0700,
file 0600, refused when it is a symlink or readable by others) and is claimed by an
atomic rename, so two applies cannot both use it.

`opv_structure_apply` refuses to run when an `op` session token (`OP_SESSION_*`), a
service account (`OP_SERVICE_ACCOUNT_TOKEN`) or Connect (`OP_CONNECT_*`) is in its
environment, and it checks that a person (not a service account) is signed in. Its
writes therefore go through the 1Password app's desktop integration, which asks the
person to authorize them, and the assistant process never holds a write credential.

What this does not do: an assistant that also has an unrestricted shell as the same OS
user can run `opv approve` in a pseudo-terminal, write an approval file, or run
`opv bootstrap` itself. The approval is a gate for assistants that act through MCP; the
1Password app's own authorization prompt on every write is the control that holds
against a process with a shell. Treat MCP as one boundary, not a sandbox.

Recorded IDs the selected account cannot see stop the plan (`ids_not_in_account`), and a
vault whose visibility cannot be told refuses it: structure is never recreated or rebound
around an access failure. Existing fields and values are never changed; fields are only
added. A run that stops part-way keeps the IDs it recorded; plan and approve again to
finish (objects already created are found again by title, never duplicated).

For a generated configuration, apply records nothing in the file and returns
`generator_ids`, the lines to add to the generator's input.

## Set up

The server is part of every released `opv` (npm, `install.sh`, the GitHub release); there
is nothing else to install. Register it for a project with your assistant (ask the person
first: it writes the assistant's configuration):

```sh
opv mcp install                      # this project (git top level), for Claude Code and Codex
opv mcp install --client claude      # only the project's .mcp.json
opv mcp install --client codex       # only ~/.codex/config.toml ($CODEX_HOME)
```

It registers `<absolute path of opv> mcp serve --project <absolute project path>` under the
name `opv` (`--name` for another). Each file is merged, never replaced: other servers and
settings are kept, a second run reports `unchanged`, and an existing `opv` entry that runs
something else is refused unless `--force`. No value, credential or environment variable
is written. For opv installed with npm it registers the shared copy (`~/.local/bin/opv`),
which upgrades keep in place. Restart the assistant to load it.

Sign in to 1Password in the desktop app (with Settings > Developer > Integrate with
1Password CLI on), and do not start the assistant from a terminal that holds an
`op signin` session. The server cannot switch projects at an assistant's request; use
trusted absolute paths and review the project configuration before connecting.

Any other client runs the same command, for example:

```json
{
  "mcpServers": {
    "opv": {
      "command": "/absolute/path/to/opv",
      "args": ["mcp", "serve", "--project", "/absolute/path/to/project"]
    }
  }
}
```

## Read-only inspection

`opv_ready`, `opv_configuration`, `opv_deployment_plan` and `opv_structure_plan` run on a
runner that refuses every write and inherited execution beneath the application code,
including layout tidying the CLI planning path would attempt. If an inspection needs such
a repair, the server returns `human_approval_required`. Tool annotations are descriptive
hints, not the enforcement mechanism.

## Without structural MCP (CLI fallback)

An opv older than 0.9.0 (whose MCP server was a separate `opv-mcp` binary built from source), or a client without MCP, uses the owner-terminal
commands: the person runs `opv bootstrap --dry-run`, then `opv bootstrap`, and
`opv target add` for each target. The assistant declares with `opv add` and
`opv init --add-env` once the configuration is bootstrapped. Report a missing MCP tool
as a capability gap; never work around it.

## Security and limits

opv internally reads items to find their fields; “never return values” is an MCP
response boundary, not a claim that no machine reads them. Names are still metadata: do
not give untrusted clients access to sensitive projects.

Inspection uses a 20-second runner budget (the structural plan 60 seconds, apply 300
seconds, for the 1Password app's prompts), runs serially, and clears its redaction
registry on completion. Vendor CLIs keep their own authentication and cache behavior. No
network listener or arbitrary shell execution is exposed.

The session readiness hook is separate and optional. Neither it nor MCP authorizes
deployment or prevents a separate unrestricted shell from reading secrets.

## Validation

```sh
cargo test --locked --features fake,mcp
cargo clippy --all-targets --features fake,mcp -- -D warnings
python3 tests/mcp_protocol.py target/debug/opv
```

Tests cover refusal before vendor writes, value-field suppression on success and on
hostile upstream output, approval replay, expiry and scope mismatch, stale plans,
credential-bearing environments, partial-failure recovery, idempotent re-runs, preserved
values, generated configurations, and a declare, plan, approve, apply flow over dev,
staging and prod with a shared boundary and independent Fly targets.
