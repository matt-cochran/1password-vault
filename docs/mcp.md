# Read-only MCP interface

The optional `opv-mcp` binary uses the official Rust MCP SDK (`rmcp`) over stdio.
It exposes three tools:

| Tool | Input | Response |
|---|---|---|
| `opv_ready` | declared environment | readiness counts, fixed human guidance |
| `opv_configuration` | none | environment names, confirmation flags, product/key names and kinds |
| `opv_deployment_plan` | declared environment | action metadata, plan ID when available; no execution |

No tool accepts a secret value, arbitrary command, file path, approval boolean, or
deployment flag. Configuration inspection does not export configuration values,
rules, mode values, vault IDs, or item IDs. Readiness does not forward messages,
health facts, or generated commands. Responses are constructed from allowlisted
fields; raw upstream JSON and diagnostic messages are never returned to the agent.

## Build and configure

```sh
cargo build --locked --features mcp --bin opv-mcp
```

The default CLI build does not enable MCP. Launch the server with an absolute
trusted project directory chosen by the human. Manually authenticate the vendor
CLIs in your own terminal first. Secrets are entered only in 1Password.

Example Claude Code configuration (merge with existing MCP servers):

```json
{
  "mcpServers": {
    "opv": {
      "command": "/absolute/path/to/opv-mcp",
      "args": ["--project", "/absolute/path/to/project"]
    }
  }
}
```

Use trusted absolute executable paths and review the project configuration before
connecting. The server cannot switch projects at an agent's request.

## Approval boundary

All exposed operations are read-only. There is deliberately no mutation tool.
An agent cannot approve itself with an `approved: true` argument or token.
Review the plan in the human's terminal and approve the specific change before
running the corresponding opv configuration, sync, deploy, rotate, or prune command.
No existing client configuration is installed or modified automatically.

The runner refuses writes and inherited execution below application orchestration,
including layout tidying attempted by the existing CLI planning path. If a plan
needs such a repair, the server returns `human_approval_required`; the human must
review and perform the repair separately. It does not silently grant permission.
Tool annotations are descriptive hints, not the enforcement mechanism.

## Security and limits

opv internally reads values to validate or compare them; “never return values” is
an MCP response boundary, not a claim that no machine reads credentials. Typed
allowlisted responses omit value-bearing fields and raw error text. Names are
still metadata: do not give untrusted clients access to sensitive projects.

Each operation uses a 20-second runner budget, runs serially, and clears its
redaction registry on completion. Vendor CLIs retain their own authentication and
cache behavior; MCP is not a sandbox for those tools or for other tools available
to the agent. No network listener or arbitrary shell execution is exposed.

The session readiness hook is separate and optional. MCP provides callable
inspection tools; the hook provides a session-start reminder. Neither authorizes
deployment or prevents a separate unrestricted shell from reading secrets.

## Validation

Run the feature-enabled suite and linter:

```sh
cargo test --locked --features fake,mcp
cargo clippy --all-targets --features fake,mcp -- -D warnings
```

Tests cover refusal before vendor writes, value-field suppression, and readiness
findings even on a successful receipt. A protocol smoke test should initialize the
stdio server, list tools, call configuration in a disposable fixture project, and
verify unknown mutation tools are rejected without vendor calls.
