# SSH signing key generation (#294)

Decision (owner, 2026-11-10): **one key**, not a stored private/public pair.

- A key declares `rules = { ssh_ed25519 = true }` (with `source = "generated"` or through
  `opv propose generate` and the person's `opv apply`). Its 1Password field holds the
  unencrypted OpenSSH Ed25519 private key, multiline, exactly as `ssh-keygen` writes it.
- The public key and its `SHA256:` fingerprint are derived from the private key, never
  stored as a second field, and are the only key material opv prints (like the `age1…`
  recipient of an `age_identity` key). There is therefore no partial or conflicting pair
  state; a stored value that does not parse as an Ed25519 OpenSSH private key fails the rule.
- Delivery uses the existing private file channel (`file = "<path>"`): bytes verbatim,
  trailing newline kept, private permissions.
- Generation follows the existing boundary: only a person's own 1Password session writes;
  agents propose, service accounts and CI never generate or replace. A nonempty field is
  never overwritten without an explicit replacement.
- Trust (an `allowed_signers` entry, a signing namespace) stays in the consumer's
  configuration; generating a key grants nothing.
