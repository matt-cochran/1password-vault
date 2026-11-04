# Sealed-target known-answer fixtures (TEST FIXTURES ONLY)

Every key in this directory is an **obviously fake test key**, generated on 2026-11-04 for
lane S0 of the sealed target (#271, design `docs/design/sealed-target.md` §6). None protects
anything; never use them for real data.

| File | Made by |
|---|---|
| `age-identity.txt`, `age-recipient.txt` | `age-keygen` (age 1.1.1); a `#` label line added |
| `plaintext.txt` | a non-secret test line |
| `ciphertext.age` | `age -a -r "$(cat age-recipient.txt)" -o ciphertext.age plaintext.txt` |
| `signer_ed25519`, `signer_ed25519.pub` | `ssh-keygen -t ed25519 -N '' -C opv-sealed-kat-TEST-FIXTURE-do-not-use` (OpenSSH 9.6p1) |
| `signer_ed25519.pkcs8.pem` | the same key's seed as RFC 8410 PKCS#8 DER (the form `op` returns by default, T16); `openssl pkey -pubout` gives the same public key |
| `message.txt`, `message.txt.sig` | `ssh-keygen -Y sign -n opv-sealed -f signer_ed25519 message.txt` |
| `allowed_signers` | one strict-subset line, principal `prod` (an environment name) |

Checked with the stock tool:

```text
ssh-keygen -Y verify -f allowed_signers -I prod    -n opv-sealed -s message.txt.sig < message.txt   # Good "opv-sealed" signature for prod
ssh-keygen -Y verify -f allowed_signers -I staging -n opv-sealed -s message.txt.sig < message.txt   # refused
ssh-keygen -Y verify -f allowed_signers -I prod    -n git        -s message.txt.sig < message.txt   # refused: namespace
```

`tests/sealed_kat.rs` loads these with the `age` and `ssh-key` crates. `.gitattributes` keeps
the bytes exact on any checkout.
