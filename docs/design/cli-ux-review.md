# CLI interaction review

Status: done (PR #63, shipped in 0.5.0). The baseline for the CLI surface; `opv session` shipped as `opv login`.

Scope: ergonomics of existing local settings and deployment workflows, plus the explicitly requested guided owner setup. Provider integration, including the independently developed Azure work, is outside this change.

## Design principles

Give each task one visible starting point. Explain the user's action before internal mechanics. Ask only for choices that matter. Use familiar labels in prompts while keeping exact identifiers in configuration. Every failure should identify what happened, what was preserved, and the next safe step. Automation keeps its stable contracts.

The journey is: choose project → sign in → set up missing settings → check → run. Deployment is a separate explicit journey: inspect → preview → sync, with deployment, deletion and rotation separately authorized by flags.

## Command sweep

| Interaction | User purpose | Review result |
|---|---|---|
| Root help | Find a starting point | Short quick-start groups setup, everyday use and deployment; advanced commands remain listed. |
| Command help | Find exact options | Plain task descriptions, examples and preserved advanced flags. |
| setup | Complete and resume onboarding | Recipe discovery, numbered product choice, native sign-in, hidden input, one save confirmation, existing values kept, partial progress saved. |
| login | Authenticate without shell expertise | `opv login <env>` signs in to that environment's account; no copied tokens or evaluated shell output; owner terminal or one child command, child exit code retained; sessions for several accounts coexist. |
| init | Connect an already prepared item | Preserved expert path, metadata-only configuration and explicit overwrite flag. |
| doctor | Diagnose installation and access | Existing checks and next-step output retained; guided entry points complement rather than silently prompt within doctor. |
| check | Know whether local settings are usable | Human findings include declaration guidance; product mistakes list choices. JSON stays unchanged. |
| run | Start the selected app | Missing product lists choices. Reference-only invocation, managed-variable cleanup and child status preserved. |
| status | Inspect source and deployed settings | Existing row states, guidance and JSON retained. A local-only environment points to check/run instead of an unexplained missing target. |
| plan | Preview deployment | Remains read-only with findings exit 8; no new prompts or inferred action. |
| sync | Apply explicit deployment policy | No changes to deploy, prune, immutable rotation or approval flags. |
| config export | Inspect configuration | Metadata-only machine output retained. |
| item skeleton | Prepare empty fields | Existing noninteractive advanced path retained. |
| explain | Understand one declaration | Existing offline reference, rules and guidance retained. |
| Errors/exit codes | Recover and automate | Existing categories retained; setup/login refusal is 6, partial progress is 8. No provider response or credential value echoed. |

## Walkthroughs used to vet the design

New owner: installation checked before requesting credentials; missing account leads to 1Password's own account prompts. Existing owner: working access skips sign-in. Expired session: fresh sign-in stays inside the owner process. Several products: select one and prompt only its missing settings. New item: collect values privately and confirm a concrete save once. Partial item: preserve filled fields and resume missing ones. Cancellation: save nothing. Legacy import: explain its scope, require consent, keep original, fall back to private entry if unsupported. Wrong account, duplicate names, wrong item type or conflicting output: stop with a specific recovery action rather than guess.

A filled field is called saved, not validated. Setup reports the next check command and distinguishes declaration readiness from provider authorization. Multiline values are never accepted through an unsafe line-by-line visible paste.

## Validation and limits

Tests use synthetic credentials and a fake vendor backend. They exercise sign-in recovery, missing items, resumability, final cancellation, duplicate vaults, conflicting configuration, wrong field types, product isolation, unique IDs, literal imports and session-response rejection. CLI tests verify headless refusal before any vendor call. The existing regression suite pins automation, secret safety and deployment policy.

Human terminal behavior and the real owner vault still need a live acceptance run after installation. No real credential migration or infrastructure provisioning was performed by the agent. This change does not alter CI runner selection or use Hetzner.

