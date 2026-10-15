# Architecture and review map

opv is an independent developer-tooling integration with 1Password. It delegates
authentication and value ownership to 1Password and deployment operations to
vendor CLIs. It adds configuration, validation, planning, delivery, and recovery
workflows. It is not a replacement vault or a sandbox for the application it runs.

## Follow one workflow

1. `src/main.rs` parses the CLI and dispatches commands.
2. `src/config.rs` and `src/config/locate.rs` load and locate configuration.
3. `src/domain/` contains planning, validation, and secret-value representations.
4. `src/app/` orchestrates commands; `ready.rs` assembles the readiness receipt and
   `sync.rs` coordinates delivery.
5. `src/provider.rs` and `src/ports.rs` define the boundaries to deployment targets.
6. `src/adapters/` implements vendor interactions.
7. `src/runner.rs` bounds subprocess execution, retries reads, and distinguishes
   uncertain writes. `src/scrub.rs` handles diagnostic redaction.

Read [multi-cloud design](design/multi-cloud-targets.md) and
[resilience design](design/resilience.md) for the decisions behind these boundaries.
Large files include inline tests; file length alone is not production-code size.

## Evidence to inspect

| Question | Starting point |
|---|---|
| Can a secret reach argv or diagnostics? | `tests/security.rs`, `src/scrub.rs`, adapter marker-value tests |
| What happens after a partial or uncertain write? | `src/app/sync.rs`, provider interruption tests, [failure handling](how-opv-handles-failures.md) |
| Does readiness modify a vault or deployment? | `src/app/ready.rs`, `src/app/ready_tests.rs`, inspect-only tidy mode |
| Can an agent use the CLI without receiving values? | `docs/agent-setup.md`, `opv schema`, JSON contract, `tests/agent_guidance.rs` |
| How is an agent lifecycle integration bounded? | [Claude readiness hook](../examples/claude-readiness-hook/README.md) and its fake-only subprocess tests |
| How are downloads verified? | `docs/install.md`, `install.sh`, `.github/workflows/release.yml` |

## Boundaries worth discussing

- `run` deliberately grants the child process access to its credentials.
- Scrubbing recognizes known values and patterns, not every possible leak.
- Zeroizing wrappers do not eliminate all parsing or external-process copies.
- Azure deploy credentials use a documented private vendor credential cache.
- Readiness can expose facts about configuration; it is not a public telemetry feed.
- Delivery is not a cross-service atomic transaction. Uncertain outcomes and
  provider-specific recovery limits matter; see the documented Fly pruning caveat.
- The optional readiness hook provides an advisory snapshot, not execution control.

## Reproduce checks

[CONTRIBUTING.md](../CONTRIBUTING.md) lists the required Rust, installation, and
packaging checks. The optional hook tests run without accounts or network access.
Provider tests use fakes and recorded output; passing them does not establish
compatibility with every future vendor CLI version or constitute a security audit.
