# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a vulnerability.

Include the version (`opv --version`), what you did, and what you expected. Never include real secret values; use made-up ones.

## Scope

In scope: the `opv` CLI in this repository, in particular anything that exposes a secret value (in logs, errors, argv, files or output), runs a shell, or performs an unintended or unauthorized destructive change. Report deviations from the documented security model, including mishandling of the private Azure credential-cache exception.

Out of scope: vulnerabilities in upstream services and vendor tools themselves (including 1Password, Fly.io, Azure, Kubernetes, and GitHub), and misconfiguration of your own identities or deployment targets. A defect in how opv invokes or handles those tools is in scope.

Supported version: the latest release.

## Trust boundaries

See [security model and limits](docs/usage.md#security-model-and-limits) for runtime access to credentials, subprocess output redaction, transient memory copies, metadata disclosures, and Azure deploy-credential storage. This project is an independent integration with 1Password, not an official 1Password product or a third-party security audit.
