# Design documents

For contributors. Users want the [README](../../README.md) and the guides in [docs/](..).

| Document | What it is | Status |
|---|---|---|
| [requirements.md](requirements.md) | concept of operations, functional (FR-1 to FR-63), security (SR-1 to SR-8) and resilience (NR-1 to NR-31) requirements, acceptance criteria. Normative: code and commits cite these IDs, and a change to a decision updates this file | current for 0.6.0; FR-56 to FR-60 adopted for 0.7.0 |
| [multi-cloud-targets.md](multi-cloud-targets.md) | targets beyond Fly (FR-28 to FR-33), the provider plug-in contract (FR-37), Kubernetes (FR-38), named stores and bindings (FR-39), delivery phases | as built for 0.5.0; App Service, AWS, GCP planned |
| [resilience.md](resilience.md) | why and how opv survives failing networks and CLIs (NR-1 to NR-31) | as built for 0.5.0 |
| [config-in-1password.md](config-in-1password.md) | the configuration as a project manifest in 1Password (FR-44) | as built for 0.5.0 |
| [self-healing-conventions.md](self-healing-conventions.md) | tolerant 1Password reads and the non-destructive tidy (FR-43) | as built for 0.5.0 |
| [cli-ux-review.md](cli-ux-review.md) | the CLI interaction baseline from PR #63 | done |
| [cli-ux-proposals-0.5.0.md](cli-ux-proposals-0.5.0.md), [cli-ux-pass2-0.5.0.md](cli-ux-pass2-0.5.0.md) | the two UX reviews behind 0.5.0's output contract | done (record) |
| [placements-and-access-boundaries.md](placements-and-access-boundaries.md), [review](placements-and-access-boundaries-review.md) | named targets per environment (#114), one vault per access boundary, evidence and access, one way only (FR-56 to FR-60); FMECA review record | draft 4, greenfield |
| [local-delivery.md](local-delivery.md) | `opv run` local delivery: declared-only environments and mounted secret files in a RAM directory (#136, #137); process roles and the metadata-only preview (0.9.0) | as built for 0.8.0/0.9.0 |
| [delivery-transports.md](delivery-transports.md) | one source of truth synced by CI: the channel model (secret, config and file channels per target), change detection (`opv changed`, exit 10) and the drift check with CI recipes, a README draft, Kubernetes ConfigMaps and mounted files, config on Fly, a Docker Swarm target, the local Compose recipe, GCP/AWS secret-manager targets with a portable VM startup step, verbatim file bytes, verification and the 0.11.0/0.12.0 plan (#136) | design for 0.11.0 and 0.12.0; Fly files, AWS and the Events API design only |
| [remote-delivery.md](remote-delivery.md) | `opv run --remote`: a product's selected keys to a reviewed, pinned SSH host and command, RAM-only on the remote side, stopped and cleaned on disconnect (#139) | as built for 0.10.0 |
| [error-catalog.md](error-catalog.md) | every failure as a typed cause (closed causes, typed subjects and evidence, typed Do/Next), one diagnosis per external tool, one renderer for CLI, `--json` and MCP, layered scrubbing, process hardening, and the end-to-end simulator that snapshots every message (#157, #159, #160) | design for review (0.10.0) |
| [assistant-guided-setup.md](assistant-guided-setup.md) | the North Star for assistant-guided configuration (an assistant guides setup from local to production with full structure and no values), what is deterministic in opv versus generative, the application × environment model, a gap analysis against 0.11.0, TRIZ contradictions, poka-yoke and a phased delivery (#173 to #179) | design for review (0.12.0+) |
| [plans/](plans/) | implementation plans, one per phase | P0 done (0.3.0), P1 done (0.5.0) |
| [spike-d0-findings.md](spike-d0-findings.md) | how `op` and `flyctl` behave; the Fly adapter's basis | done |
| [spike-p1-azure-findings.md](spike-p1-azure-findings.md), [spike-k8s-findings.md](spike-k8s-findings.md), [spike-eso-findings.md](spike-eso-findings.md) | live recon of Azure, Kubernetes and the External Secrets Operator; recorded outputs are test fixtures | done |
