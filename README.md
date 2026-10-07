# 1password-vault

This repository ships the `secretctl` CLI.

## Verify a download

Download the release asset you want (for example `secretctl`) and the `SHA256SUMS` file from the release. Then, from the directory containing both files, verify the checksum and the build provenance:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify secretctl --repo matt-cochran/1password-vault
```

Note: replace `secretctl` with the downloaded asset name.
