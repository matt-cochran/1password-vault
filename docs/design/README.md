# Design documents

For contributors. Users want the [README](../../README.md) and the guides in [docs/](..).

| Document | What it is | Status |
|---|---|---|
| [requirements.md](requirements.md) | concept of operations, functional (FR-1 to FR-45), security (SR-1 to SR-8) and resilience (NR-1 to NR-31) requirements, acceptance criteria. Normative: code and commits cite these IDs, and a change to a decision updates this file | current for 0.5.0 |
| [multi-cloud-targets.md](multi-cloud-targets.md) | targets beyond Fly (FR-28 to FR-33), the provider plug-in contract (FR-37), Kubernetes (FR-38), named stores and bindings (FR-39), delivery phases | as built for 0.5.0; App Service, AWS, GCP planned |
| [resilience.md](resilience.md) | why and how opv survives failing networks and CLIs (NR-1 to NR-31) | as built for 0.5.0 |
| [config-in-1password.md](config-in-1password.md) | the configuration as a project manifest in 1Password (FR-44) | as built for 0.5.0 |
| [self-healing-conventions.md](self-healing-conventions.md) | tolerant 1Password reads and the non-destructive tidy (FR-43) | as built for 0.5.0 |
| [cli-ux-review.md](cli-ux-review.md) | the CLI interaction baseline from PR #63 | done |
| [cli-ux-proposals-0.5.0.md](cli-ux-proposals-0.5.0.md), [cli-ux-pass2-0.5.0.md](cli-ux-pass2-0.5.0.md) | the two UX reviews behind 0.5.0's output contract | done (record) |
| [plans/](plans/) | implementation plans, one per phase | P0 done (0.3.0), P1 done (0.5.0) |
| [spike-d0-findings.md](spike-d0-findings.md) | how `op` and `flyctl` behave; the Fly adapter's basis | done |
| [spike-p1-azure-findings.md](spike-p1-azure-findings.md), [spike-k8s-findings.md](spike-k8s-findings.md), [spike-eso-findings.md](spike-eso-findings.md) | live recon of Azure, Kubernetes and the External Secrets Operator; recorded outputs are test fixtures | done |
