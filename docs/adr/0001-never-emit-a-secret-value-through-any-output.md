---
id: ADR-0001
title: Never emit a secret value through any output
status: accepted
date: 2026-11-17
supersedes: []
applies_to:
  - "src/**"
  - "docs/agent-setup.md"
  - "docs/agent-skill.md"
rules:
  - id: R1
    text: "opv never writes a secret value, any part of one, its length or a digest of it to stdout, stderr, a --json document, an MCP reply, a log, an error message, a panic message, a receipt or any file it writes for its own use."
  - id: R2
    text: "A value leaves opv only through a declared delivery channel to its consumer: a child's environment or a private RAM-backed file under opv run, stdin or a pipe to a platform tool, or the target's own API. Never argv, never a plaintext temporary file on disk."
  - id: R3
    text: "Every value opv reads is held in SecretValue (redacted Debug and Display, zeroized on drop) and registered with the scrubber before it can reach any output path."
  - id: R4
    text: "Child output that opv shows (captured op, flyctl, az and kubectl stderr, and opv run's child streams) passes the scrubber first, which masks the value and its known encodings. Masking is defense in depth and never the reason a path is considered safe."
  - id: R5
    text: "An identity used by an agent or by CI (a service account) reads values only to deliver them; it never writes values to 1Password, and opv never returns a value to the caller that holds it."
---

## Context

opv exists so that people, LLM agents and CI can orchestrate work that needs secrets without the values ever reaching them. An LLM agent is a special kind of output reader: anything opv prints to its terminal, `--json` or MCP reply enters the model's context and may be stored by the agent's host. The guarantee therefore has to cover every output channel, not only logs.

The rule is already implemented and tested, but it is spread over several requirements and has never been stated as one decision:

- Requirements SR-1 (no secret logging), SR-2 (secret-safe types), SR-3 (no secret CLI arguments), SR-4 (no plaintext temporary files) and SR-8 (memory hygiene) in `docs/design/requirements.md`, and NR-31 (child output scrubbing).
- `src/domain/secret.rs`: `SecretValue` redacts `Debug` and `Display`, zeroizes on drop and registers each value with the scrubber in its constructor.
- `src/scrub.rs`: the process-wide `Registry` masks registered values and their encodings (JSON, shell-escaped, percent-encoded), plus fixed token and assignment patterns.
- `src/output.rs`: `OutputGuard` wraps opv's own stdout and stderr. It is tested with canaries: registered secrets, token shapes, PEM blocks and values split across writes.

The 0.22.0 agent identity (#338) gives an LLM agent its own unattended, read-only 1Password identity. That makes this guarantee the main control between the agent and the values, so it is recorded here as a decision that every change is checked against.

## Decision

opv never emits a secret value through any output (rules R1–R5). A value reaches only the consumer it is delivered to, through a declared channel. Every value is typed as `SecretValue` and registered with the scrubber from the moment it is read. Output masking stays as a second line of defense, never the primary control. Agent and CI identities read only in order to deliver. They never write values, and opv never hands them a value.

The documented exception in SR-1 (#92, settings health) stays allowed: a finding may state equality or placeholder membership of a value, but never the value or any part of it.

## Consequences

- Every new command, target, MCP tool or diagnostic is checked against R1–R5 (`junior adr check --stage design|implementation`). A feature that must show a value to a person does so only in a human-only flow, such as 1Password's own UI, never through opv's output.
- An agent can be given an opv identity safely, because nothing opv returns to it contains a value. What a child process prints is the child's responsibility: opv masks known values in it but does not sandbox it.
- Tests keep the canary style of `src/output.rs`. A new output path needs a canary test showing that a registered value never appears in it.
- Debugging is harder: a support request never includes a value, only names, kinds and fixed causes.
