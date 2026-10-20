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

// --- #136 A2: role-scoped file delivery never leaks a canary -------------------------------
//
// The real binary runs under a fake `op run` that resolves each reference into a test canary
// (the repo's S7MARKER pattern, never a real credential), so the delivery step receives
// values exactly as a real run would. A role's own secret is delivered only as a file, so
// its canary must stay off stdout, stderr, the step's command line and the child
// environment; and the step's argv, the child's environment, the private directory,
// `--preview --json` and the `opv_state` `delivery_preview` reply must never carry the other
// role's canary either.
#[cfg(target_os = "linux")]
mod role_canary_sweep {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;

    /// The `serve` role's canary value.
    const SERVE_CANARY: &str = "S7MARKER-serve-136";
    /// The `migrate` role's canary value.
    const MIGRATE_CANARY: &str = "S7MARKER-migrate-136";

    /// A product whose two roles each deliver one secret as a file.
    const CONFIG: &str = "\
[environments.dev]
boundaries.demo = {}

[products.demo.keys.SERVE_FILE]
kind = \"secret\"
environments = [\"dev\"]
roles = [\"serve\"]
file = \"serve/secret\"

[products.demo.keys.MIGRATE_FILE]
kind = \"secret\"
environments = [\"dev\"]
roles = [\"migrate\"]
file = \"migrate/secret\"

[products.demo.local]
environment = \"declared_only\"
secrets_dir_env = \"APP_SECRETS_DIR\"
";

    const BINDINGS: &str = "environments.dev.boundaries.demo.item_id = \"idev\"\nenvironments.dev.boundaries.demo.vault_id = \"vdev\"\n";

    /// The project with the role-scoped contract, written once and closed before any test reads
    /// it.
    fn project() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("opv-role-canary-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("secrets.toml"), CONFIG).unwrap();
            std::fs::write(dir.join("secrets.bindings.toml"), BINDINGS).unwrap();
            dir
        })
    }

    /// The `--config` path of the role-scoped project.
    fn config() -> PathBuf {
        project().join("secrets.toml")
    }

    /// A PATH dir holding a fake `op` that answers discovery and then, as `op run` does,
    /// resolves every reference `opv run` gave it into the canary planted under `CANARY_<KEY>`
    /// before exec'ing the delivery step.
    fn op_dir() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("opv-role-op-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let op = dir.join("op");
            std::fs::write(
                &op,
                r#"#!/bin/sh
case "$1" in
  item) echo '{"fields":[]}'; exit 0 ;;
  whoami) echo '{"user_type":"SERVICE_ACCOUNT"}'; exit 0 ;;
  account) echo '[]'; exit 0 ;;
esac
while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "$1" = -- ] || exit 0
shift
for name in $(env | sed -n 's/^CANARY_\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'); do
  eval "v=\$CANARY_$name"
  [ -n "$v" ] && export "$name=$v"
done
exec "$@"
"#,
            )
            .unwrap();
            std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
            dir
        })
    }

    /// A private tmpfs `$XDG_RUNTIME_DIR`, so parallel tests never sweep each other's
    /// `opv-run.*` directories; `None` where the machine has no tmpfs to put one on.
    fn runtime_dir() -> Option<tempfile::TempDir> {
        let dir = tempfile::Builder::new().tempdir_in("/dev/shm").ok()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
        let st = rustix::fs::statfs(dir.path()).ok()?;
        #[allow(clippy::unnecessary_cast)]
        let magic = (st.f_type as u64) & 0xffff_ffff;
        (magic == 0x0102_1994).then_some(dir)
    }

    /// The common environment: the fake `op` on PATH and both roles' canaries planted for it
    /// to resolve, so a run that resolved every reference would hand the step both values.
    fn base() -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
        c.env_remove("GITHUB_STEP_SUMMARY")
            .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
            .env_remove("OPV_CONFIG")
            .env_remove("OPV_PRODUCT")
            .env_remove("CI")
            .env_remove("GITHUB_ACTIONS")
            .env("PATH", format!("{}:/usr/bin:/bin", op_dir().display()))
            .env("HOME", "/tmp")
            .env("OPV_TEST_BACKOFF_SCALE", "0")
            .env("CANARY_SERVE_FILE", SERVE_CANARY)
            .env("CANARY_MIGRATE_FILE", MIGRATE_CANARY);
        c
    }

    /// `opv run --role <role> -- sh -c <script>` under a private runtime directory: exit code,
    /// stdout, stderr.
    fn role_run(role: &str, script: &str) -> Option<(Option<i32>, String, String)> {
        let rt = runtime_dir()?;
        let out = base()
            .args([
                "--config",
                config().to_str().unwrap(),
                "run",
                "dev",
                "--product",
                "demo",
                "--role",
                role,
            ])
            .args(["--", "sh", "-c", script])
            .env("XDG_RUNTIME_DIR", rt.path())
            .output()
            .unwrap();
        Some((
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    /// `opv run --role <role> --preview --json` under a private runtime directory: both streams.
    fn preview_json(role: &str) -> Option<String> {
        let rt = runtime_dir()?;
        let out = base()
            .args([
                "--config",
                config().to_str().unwrap(),
                "run",
                "dev",
                "--product",
                "demo",
                "--role",
                role,
                "--preview",
                "--json",
            ])
            .env("XDG_RUNTIME_DIR", rt.path())
            .output()
            .unwrap();
        Some(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }

    #[test]
    fn a_serve_run_prints_no_migrate_canary() {
        let Some((_, stdout, stderr)) = role_run("serve", "true") else {
            return;
        };
        assert!(
            !stdout.contains(MIGRATE_CANARY) && !stderr.contains(MIGRATE_CANARY),
            "{stdout}{stderr}"
        );
    }

    #[test]
    fn a_serve_run_hands_no_migrate_canary_to_its_child() {
        let Some((_, stdout, _)) = role_run("serve", "env") else {
            return;
        };
        assert!(!stdout.contains(MIGRATE_CANARY), "{stdout}");
    }

    #[test]
    fn a_serve_run_keeps_no_migrate_canary_in_the_step_command_line() {
        let Some((_, stdout, _)) = role_run("serve", r#"tr '\0' ' ' < /proc/$PPID/cmdline"#) else {
            return;
        };
        assert!(!stdout.contains(MIGRATE_CANARY), "{stdout}");
    }

    #[test]
    fn a_serve_run_writes_only_its_own_canary_into_the_directory() {
        let Some((_, stdout, _)) =
            role_run("serve", r#"find "$APP_SECRETS_DIR" -type f -exec cat {} +"#)
        else {
            return;
        };
        assert_eq!(stdout.trim(), SERVE_CANARY, "{stdout}");
    }

    #[test]
    fn the_serve_preview_holds_no_migrate_canary() {
        let Some(out) = preview_json("serve") else {
            return;
        };
        assert!(!out.contains(MIGRATE_CANARY), "{out}");
    }

    #[test]
    fn a_migrate_run_prints_no_serve_canary() {
        let Some((_, stdout, stderr)) = role_run("migrate", "true") else {
            return;
        };
        assert!(
            !stdout.contains(SERVE_CANARY) && !stderr.contains(SERVE_CANARY),
            "{stdout}{stderr}"
        );
    }

    #[test]
    fn a_migrate_run_hands_no_serve_canary_to_its_child() {
        let Some((_, stdout, _)) = role_run("migrate", "env") else {
            return;
        };
        assert!(!stdout.contains(SERVE_CANARY), "{stdout}");
    }

    #[test]
    fn a_migrate_run_keeps_no_serve_canary_in_the_step_command_line() {
        let Some((_, stdout, _)) = role_run("migrate", r#"tr '\0' ' ' < /proc/$PPID/cmdline"#)
        else {
            return;
        };
        assert!(!stdout.contains(SERVE_CANARY), "{stdout}");
    }

    #[test]
    fn a_migrate_run_writes_only_its_own_canary_into_the_directory() {
        let Some((_, stdout, _)) = role_run(
            "migrate",
            r#"find "$APP_SECRETS_DIR" -type f -exec cat {} +"#,
        ) else {
            return;
        };
        assert_eq!(stdout.trim(), MIGRATE_CANARY, "{stdout}");
    }

    #[test]
    fn the_migrate_preview_holds_no_serve_canary() {
        let Some(out) = preview_json("migrate") else {
            return;
        };
        assert!(!out.contains(SERVE_CANARY), "{out}");
    }

    // A role's own canary is delivered only as a file, so it must not surface on any other
    // channel of that role's run: stdout, stderr, the step's command line or the child
    // environment.

    #[test]
    fn a_serve_run_writes_no_own_canary_to_stdout() {
        let Some((_, stdout, _)) = role_run("serve", "true") else {
            return;
        };
        assert!(!stdout.contains(SERVE_CANARY), "{stdout}");
    }

    #[test]
    fn a_serve_run_writes_no_own_canary_to_stderr() {
        let Some((_, _, stderr)) = role_run("serve", "true") else {
            return;
        };
        assert!(!stderr.contains(SERVE_CANARY), "{stderr}");
    }

    #[test]
    fn a_serve_run_keeps_its_own_canary_out_of_the_step_command_line() {
        let Some((_, stdout, _)) = role_run("serve", r#"tr '\0' ' ' < /proc/$PPID/cmdline"#) else {
            return;
        };
        assert!(!stdout.contains(SERVE_CANARY), "{stdout}");
    }

    #[test]
    fn a_serve_run_keeps_its_own_canary_out_of_its_childs_environment() {
        let Some((_, stdout, _)) = role_run("serve", "env") else {
            return;
        };
        assert!(!stdout.contains(SERVE_CANARY), "{stdout}");
    }

    #[test]
    fn a_migrate_run_writes_no_own_canary_to_stdout() {
        let Some((_, stdout, _)) = role_run("migrate", "true") else {
            return;
        };
        assert!(!stdout.contains(MIGRATE_CANARY), "{stdout}");
    }

    #[test]
    fn a_migrate_run_writes_no_own_canary_to_stderr() {
        let Some((_, _, stderr)) = role_run("migrate", "true") else {
            return;
        };
        assert!(!stderr.contains(MIGRATE_CANARY), "{stderr}");
    }

    #[test]
    fn a_migrate_run_keeps_its_own_canary_out_of_the_step_command_line() {
        let Some((_, stdout, _)) = role_run("migrate", r#"tr '\0' ' ' < /proc/$PPID/cmdline"#)
        else {
            return;
        };
        assert!(!stdout.contains(MIGRATE_CANARY), "{stdout}");
    }

    #[test]
    fn a_migrate_run_keeps_its_own_canary_out_of_its_childs_environment() {
        let Some((_, stdout, _)) = role_run("migrate", "env") else {
            return;
        };
        assert!(!stdout.contains(MIGRATE_CANARY), "{stdout}");
    }

    #[cfg(feature = "mcp")]
    mod mcp {
        use super::*;
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Child, ChildStdin, ChildStdout, Stdio};

        /// A minimal MCP stdio client, as `tests/security.rs` uses.
        struct Mcp {
            child: Child,
            stdin: ChildStdin,
            stdout: BufReader<ChildStdout>,
            next: u64,
        }

        impl Mcp {
            fn start() -> Option<Mcp> {
                let rt = runtime_dir()?;
                let mut child = base()
                    .env("XDG_RUNTIME_DIR", rt.path())
                    .args(["mcp", "serve", "--project"])
                    .arg(project())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let stdin = child.stdin.take().unwrap();
                let stdout = BufReader::new(child.stdout.take().unwrap());
                let mut mcp = Mcp {
                    child,
                    stdin,
                    stdout,
                    next: 1,
                };
                let init = mcp.call(
                    "initialize",
                    serde_json::json!({"protocolVersion": "2025-11-25", "capabilities": {},
                        "clientInfo": {"name": "role-canary", "version": "1"}}),
                );
                assert!(init.get("result").is_some(), "{init}");
                mcp.notify("notifications/initialized");
                Some(mcp)
            }

            fn send(&mut self, message: serde_json::Value) {
                writeln!(self.stdin, "{message}").unwrap();
                self.stdin.flush().unwrap();
            }

            fn notify(&mut self, method: &str) {
                self.send(serde_json::json!({"jsonrpc": "2.0", "method": method, "params": {}}));
            }

            fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
                let id = self.next;
                self.next += 1;
                self.send(serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
                loop {
                    let mut line = String::new();
                    self.stdout.read_line(&mut line).unwrap();
                    let reply: serde_json::Value = serde_json::from_str(&line).unwrap();
                    if reply.get("id") == Some(&serde_json::json!(id)) {
                        return reply;
                    }
                }
            }

            /// The text of a `tools/call` result (the tool's one JSON document).
            fn tool_text(&mut self, name: &str, arguments: serde_json::Value) -> String {
                let reply = self.call(
                    "tools/call",
                    serde_json::json!({"name": name, "arguments": arguments}),
                );
                reply["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .to_string()
            }
        }

        impl Drop for Mcp {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        #[test]
        fn the_mcp_delivery_preview_holds_no_canary() {
            let Some(mut mcp) = Mcp::start() else {
                return;
            };
            let text = mcp.tool_text(
                "opv_state",
                serde_json::json!({"section": "delivery_preview", "env": "dev", "product": "demo"}),
            );
            assert!(
                !text.contains(SERVE_CANARY) && !text.contains(MIGRATE_CANARY),
                "{text}"
            );
        }
    }
}
