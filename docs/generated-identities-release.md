# Generated identities and the 0.18.3 release gate

0.18.2's age identity generator exists, but its contract loader rejects the documented
`source = "generated"` declaration because recipe detection recognizes only random byte
encodings. This is a source validation defect; a different published asset is not needed
to explain the reproduction. 0.18.3 fixes that loader/generator disagreement and adds
one explicitly file-delivered Ed25519 OpenSSH private-key recipe.

```toml
[environments.shared]
tier = "shared"

[environments.production]
tier = "production"

[products.app.local]
secrets_dir_env = "APP_SECRET_FILES"

[products.app.keys.RUNTIME_IDENTITY]
kind = "secret"
source = "generated"
file = "runtime-identity"
rules = { age_identity = true }

[products.app.keys.SIGNING_IDENTITY]
kind = "secret"
source = "generated"
file = "signing-identity"
rules = { ssh_ed25519 = true }
```

Declare each identity independently. Each key selects one recipe, with no provider
prefix, personal flag, `from` alias or infrastructure source. Shared/production *tiers*
allow owner-generated team values; the shared-key guard means a `from` alias. SSH keys
require file delivery. Generation does not grant signing trust or install an allowed
signer. Separate review of recipients and allowed signers remains necessary.

In the owner's own interactive session:

```sh
opv propose generate shared app/RUNTIME_IDENTITY app/SIGNING_IDENTITY
opv apply PLAN_ID --generate shared:app/RUNTIME_IDENTITY --generate shared:app/SIGNING_IDENTITY
```

Use the actual plan ID returned. Apply recomputes the same plan against current state,
shows its steps and asks `Apply this plan? [y/N]`. Production uses the same flow with
its environment name. This command has no `--confirm ENV` flag; that flag belongs to
other commands. CI, agents, service accounts, Connect and deploy credentials cannot run
this owner write. No `--yes`, rotation or overwrite option is introduced. Any requested
nonempty existing field refuses the generation batch before writes. If readback fails,
a retry preserves any fields already stored rather than replacing their identities.

Private material passes to the existing 1Password writer over stdin and stays in a
concealed field. Successful generation prints the public `age1...` recipient, or the
`ssh-ed25519 ...` public key followed by its SHA256 fingerprint. It never prints the
private identity. SSH multiline bytes and final newline are preserved in the declared
private file channel; environment-only delivery is refused.

## Qualification and publication

The release remains immutable and staging-built. The candidate version is 0.18.3;
0.18.2's published version and assets must not be replaced.

1. Review the source PR, including owner/session/no-overwrite tests, real disposable
   Ed25519 signing/verification, malformed-key validation and private-file bytes/mode.
2. Run normal dev → staging source CI and the Release workflow. Six native builds are
   packaged once into an unqualified `opv-inputs-TREE-ATTEMPT` artifact.
3. Each of six matching native runner architectures downloads those exact bytes, checks
   input hashes, executes the native command, and uses a clean offline npm install of
   the exact candidate main and matching platform tarballs. No registry fallback,
   1Password session or provider operation is used. Version, generated contract parsing,
   help/schema/guide/installed skill and native/npm binary-byte parity must all pass.
4. Only six positive bound receipts allow the final `opv-release-TREE-ATTEMPT` artifact.
   Its schema 2 manifest binds version, source tree/commit, original run/attempt, every
   binary/npm checksum and all six qualification records. Missing/skipped capabilities,
   changed bytes, source drift and schema 1 candidates are rejected. Successful original
   staging workflow completion is independently required when resolving/publishing.
5. Promote the identical full staging tree through normal source policy. The owner then
   reviews the concrete retained qualification before authorizing the version tag/release.
   Main/tag publication reuses retained bytes; it does not rebuild. Platform npm packages
   publish and become visible with exact integrity before the main package is advertised.
6. After publication, confirm the exact 0.18.3 registry integrities and fresh-install version
   and capabilities before adopting it. Suggested explicit update:
   `npm install --global @matthew-cochran/opv@0.18.3`.

The local source tests are not six-platform distribution qualification or an actual npm
release. The six native CI jobs, owner review, publication and post-publication fresh
install are pending until their real runs complete. No production secret is used in the
source tests or candidate qualification. The packaged-command checks exercise parsing
and embedded capability parity; owner apply/storage and generated cryptographic bytes
are exercised by the source test suite with the existing fake vendor, not a real account.

Runner labels are selected from GitHub's [official hosted runner documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
Linux x64/arm64, macOS Intel/arm64, Windows x64/arm64. Lack of an eligible runner fails
qualification rather than marking an unexecuted platform supported.
