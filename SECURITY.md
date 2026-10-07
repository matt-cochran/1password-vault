# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a vulnerability.

Include the version (`opv --version`), what you did, and what you expected. Never include real secret values; use made-up ones.

## Scope

In scope: the `opv` CLI in this repository, in particular anything that exposes a secret value (in logs, errors, argv, files or output), runs a shell, or deletes or changes data without an explicit flag.

Out of scope: vulnerabilities in 1Password, `op`, Fly.io or `flyctl` themselves, and misconfiguration of your own vaults, tokens or Fly apps.

Supported version: the latest release.
