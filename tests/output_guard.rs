//! The output guard covers opv's own output only: `opv run`'s child writes to the inherited
//! terminal directly (it is the person's app, and `op run` masks it), so neither its escape
//! sequences nor a value the guard would mask are touched (design §8).

#[cfg(unix)]
mod run_child_bypasses_the_guard {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::OnceLock;

    const CFG: &str = "tests/fixtures/secrets.toml";
    /// A credential variable's value: registered as a secret, so the guard would mask it.
    const GUARDED: &str = "GuardCanaryToken-71xq";

    /// A PATH dir holding a fake `op` that execs the command after `--`; written once and
    /// closed before any test spawns it (no ETXTBSY).
    fn fake_op_dir() -> &'static PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("opv-output-guard-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let op = dir.join("op");
            std::fs::write(
                &op,
                "#!/bin/sh\ncase \"$1\" in\n  item) echo '{\"fields\":[]}'; exit 0 ;;\n  whoami) echo '{\"user_type\":\"SERVICE_ACCOUNT\"}'; exit 0 ;;\n  account) echo '[]'; exit 0 ;;\nesac\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
            dir
        })
    }

    /// `opv run staging -- sh -c <script>`'s stdout.
    fn run_child(script: &str) -> String {
        let dir = fake_op_dir();
        let out = Command::new(env!("CARGO_BIN_EXE_opv"))
            .env_remove("GITHUB_STEP_SUMMARY")
            .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
            .env_remove("OPV_CONFIG")
            .env_remove("OPV_PRODUCT")
            .env_remove("CI")
            .env_remove("GITHUB_ACTIONS")
            .env("GH_TOKEN", GUARDED)
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .args(["--config", CFG, "run", "staging", "--product", "allumata"])
            .args(["--", "sh", "-c", script])
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn run_childs_escape_sequences_reach_the_terminal_untouched() {
        assert_eq!(
            run_child(r"printf '\033[31mred\033[0m\n'"),
            "\x1b[31mred\x1b[0m\n"
        );
    }

    #[test]
    fn run_childs_output_is_not_masked_by_the_guard() {
        assert_eq!(
            run_child("printf '%s\\n' \"$GH_TOKEN\""),
            format!("{GUARDED}\n")
        );
    }
}
