# opv

`opv` is a Rust CLI that syncs secrets from 1Password into runtime targets, with Fly.io as the first target. This npm package ships a small Node shim that delegates to the prebuilt `opv` binary for your operating system and CPU; the binary is pulled in as a per-platform optional dependency, so npm selects it automatically and no install scripts run.

```sh
npm i -g @matthew-cochran/opv
```

See the [GitHub README](https://github.com/matt-cochran/1password-vault#readme) for documentation.
