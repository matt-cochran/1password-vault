# opv

`opv` keeps your app's secrets and settings in 1Password and syncs them to where your apps run (Fly.io, GitHub Actions, Azure Key Vault + Container Apps, Kubernetes) or into a local command, without ever printing, logging or writing a value.

```sh
npm i -g @matthew-cochran/opv
opv --version
```

npm picks the prebuilt `opv` binary for your operating system and CPU through a per-platform optional dependency. A postinstall script also copies it to `~/.local/bin/opv` (`%LOCALAPPDATA%\Programs\opv\opv.exe` on Windows), the same place the install script uses; it never replaces a file that is not an opv binary. Run `npm i -g` without `sudo`. If your shell then says `~/.local/bin/opv: No such file or directory`, run `hash -r`.

- Website: [opv.dev](https://opv.dev)
- Documentation and source: [github.com/matt-cochran/1password-vault](https://github.com/matt-cochran/1password-vault#readme)
- Changes: [CHANGELOG](https://github.com/matt-cochran/1password-vault/blob/main/CHANGELOG.md)

opv is an independent project, not affiliated with or endorsed by 1Password.
