# Manifest mirror

`opv-item.md` is the notes of the simulated 1Password manifest item for this project, the
way `opv` writes it: a short Markdown preamble, a fenced `toml` block holding the contract
(no ids, as in `../secrets.toml`), and a second block tagged `toml opv-bindings` holding the
1Password ids (as in `../secrets.bindings.toml`; D-G). The item itself is in `world.json`:

- title `opv · e2e-app`
- vault `e2e-manifest` (`vE2EMANIFEST00000000000001`)
- tags `opv-manifest` and `opv-repo:example.test|e2e-org|e2e-app`
- fields `project = "e2e-app"` and `convention = "1"`

It mirrors `../secrets.toml` and `../secrets.bindings.toml`, so the configuration-in-1Password route can load the same
project without a file. Because `../secrets.toml` is a parent of any directory under this
project, the route must be forced with `OPV_PROJECT`:

```
OPV_PROJECT=e2e-app OP_ACCOUNT=AE2EDEVACCOUNT000000000001 opv config describe --json
```

The account is required because the world signs in two accounts on one sign-in address;
the default account is `AE2EDEVACCOUNT000000000001`, which owns the manifest item.

If either file changes, regenerate this mirror (and the item's notes in `world.json`) so they
stay in step; `tests/e2e_app_loads.rs` checks all three.
