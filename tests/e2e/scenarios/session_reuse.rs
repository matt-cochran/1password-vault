//! Sign-in reuse across commands (#203, `docs/design/session-reuse.md` §8.2, §8.3): the real
//! `opv` binary in a real shell at a real terminal, against `opv-sim`, with the canary scan of
//! `docs/design/session-reuse-fmeca.md` "Canary channels".
//!
//! **The terminal.** Each case runs a shell script under `script(1)` (util-linux, owner
//! decision Q5): stdin and stderr are the PTY, and `$(…)` hands opv a pipe its parent holds,
//! as a person's shell does. The typescript is kept and scanned.
//!
//! **The session.** `opv-sim` models no CLI session and no `op run`, so a small `op` in front
//! of it does (§8.1): `op signin` prints `export OP_SESSION_<user>="<canary>g<n>"`, a fresh
//! token per sign-in, and every other call reaches the simulator signed in only when the
//! call's environment holds the token op issued last (else the simulator answers from a copy
//! of the world where nobody is signed in: op's own signed-out recordings). Modes: `token`,
//! `app` (the desktop app integration: `op signin` prints nothing and every call is signed
//! in), and `lenient` (#167: a stale variable still answers `whoami`). `op run` passes its
//! environment to its child, as real op does (FMECA H1). `flyctl`, `gh`, `kubectl` and `az`
//! are the simulator behind a wrapper that logs the `OP_*` names each call got. Every log
//! holds names and argv only; a token in any of them is a leak the scan finds.
//!
//! **The canary scan** ([`Lab::finish`]) searches every captured channel (each typescript,
//! each command's stdout and stderr, MCP answers, the tool logs) and every file under the
//! scenario's root, `TMPDIR` and the RAM folder for the canary, names the channel of every
//! hit, and fails when a channel the case expected was never produced, so it cannot pass on
//! nothing. The only allowed appearance is S2's capture of `opv login --shell`'s own lines.
//! The `op` that issues the canary lives outside the scanned root.
//!
//! Linux only: the M1 and M5 checks read `/proc`, and macOS's `script` takes other flags.
//! A case that needs fish or pwsh, absent from the machine, skips with its reason.

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["session_refusals", "session_shell_lines"];

/// The `Cause` variants this module's snapshots reach, as their text (opv login has no
/// `--json`): the snapshot, the variant, and the words only that variant's message has.
pub(crate) const REACHED: &[(&str, &str, &str)] = &[
    (
        "session_refusals",
        "ShellEvalRequired",
        "this prints a 1Password session for your shell to evaluate, so it only writes to a pipe",
    ),
    (
        "session_refusals",
        "ShellMismatch",
        "but the session lines asked for are for",
    ),
];

#[cfg(target_os = "linux")]
mod linux {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use crate::coverage::{Scenario, scenario_snapshots, updating};

    const OPV: &str = env!("CARGO_BIN_EXE_opv");
    /// The session variable op names after the dev account's user (§5.2).
    const VAR: &str = "OP_SESSION_UE2EDEVUSER000000000000001";
    const SIGNIN: &str = "op signin ";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        /// A CLI session: only the token op issued last signs a call in.
        Token,
        /// The desktop app integration: `op signin` prints nothing, every call is signed in.
        App,
        /// #167: a stale variable still answers `whoami`; a vault list needs the live token.
        Lenient,
    }

    impl Mode {
        fn word(self) -> &'static str {
            match self {
                Mode::Token => "token",
                Mode::App => "app",
                Mode::Lenient => "lenient",
            }
        }
    }

    /// `op` with CLI sessions, in front of opv-sim (module docs).
    const FAKE_OP: &str = r#"#!/bin/bash
ROOT='@ROOT@'; FAKE='@FAKE@'; CANARY='@CANARY@'
names=$(compgen -e | grep '^OP_' | sort | tr '\n' ' ')
valid=$(cat "$FAKE/valid" 2>/dev/null)
sess=none
for n in $(compgen -e | grep '^OP_SESSION'); do
  v="${!n}"; [ -z "$v" ] && continue
  if [ -n "$valid" ] && [ "$v" = "$valid" ]; then sess=issued
  elif [ "$sess" = none ]; then case "$v" in "$CANARY"*) sess=stale ;; *) sess=other ;; esac
  fi
done
mode=$(cat "$ROOT/world/session-mode")
printf '%s\n' "op $* | env: $names| session: $sess" >> "$ROOT/world/session.log"
if [ "$1" = signin ]; then
  [ "$mode" = app ] && exit 0
  n=$(( $(cat "$FAKE/generation" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$FAKE/generation"
  printf '%s' "${CANARY}g$n" > "$FAKE/valid"
  printf 'export @VAR@="%s"\n' "${CANARY}g$n"
  exit 0
fi
ok=0
case "$mode" in
  app) ok=1 ;;
  token) [ "$sess" = issued ] && ok=1 ;;
  lenient)
    if [ "$1" = whoami ]; then [ "$sess" != none ] && ok=1
    else [ "$sess" = issued ] && ok=1; fi ;;
esac
case "$1" in account|--version) ok=1 ;; esac
if [ "$1" = run ] && [ "$ok" = 1 ]; then
  while [ "$1" != -- ]; do shift; done
  shift
  exec "$@"
fi
if [ "$ok" = 1 ]; then exec "$ROOT/bin/op" "$@"; fi
OPV_SIM_WORLD="$ROOT/world-out" exec "$ROOT/bin/op" "$@"
"#;

    /// A non-op tool: the `OP_*` names it got, then the simulator.
    const FAKE_TOOL: &str = r#"#!/bin/bash
printf '%s\n' "@NAME@ $* | env: $(compgen -e | grep '^OP_' | sort | tr '\n' ' ')" >> '@ROOT@/world/env.log'
exec '@ROOT@/bin/@NAME@' "$@"
"#;

    /// `config edit`'s editor: the environment it inherited, then no change.
    const EDITOR: &str = "#!/bin/sh\nenv > '@ROOT@/out/editor.env'\n";

    /// A per-test session token prefix, in op's session charset (§5.3).
    fn new_canary() -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or_default();
        format!(
            "opvSESSIONCANARY{}x{}x{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            nanos
        )
    }

    fn write_exe(path: &Path, text: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, text).expect("write fake");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// `name`'s path, when it is installed (`command -v`).
    fn installed(name: &str) -> Option<String> {
        let out = Command::new("sh")
            .args(["-c", &format!("command -v {name}")])
            .output()
            .ok()?;
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !path.is_empty()).then_some(path)
    }

    /// A skipped case, said where `cargo nextest` shows it.
    fn skip(case: &str, why: &str) {
        eprintln!("skipped: {case}: {why}");
    }

    /// A RAM-backed folder for `XDG_RUNTIME_DIR` (local file delivery needs tmpfs), or why
    /// there is none.
    fn ram_dir() -> Result<tempfile::TempDir, String> {
        let shm = Path::new("/dev/shm");
        if !opv_ram_backed(shm) {
            return Err("/dev/shm is not tmpfs on this machine".into());
        }
        let dir = tempfile::Builder::new()
            .prefix("opv-e2e-ram.")
            .tempdir_in(shm)
            .map_err(|e| format!("cannot create a folder in /dev/shm: {e}"))?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        Ok(dir)
    }

    fn opv_ram_backed(path: &Path) -> bool {
        // TMPFS_MAGIC, as src/ramdir.rs reads it.
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
            return false;
        };
        // SAFETY: `statfs` on a NUL-terminated path; `st` is fully written on success.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
            return false;
        }
        #[allow(clippy::unnecessary_cast)]
        let magic = (st.f_type as u64) & 0xffff_ffff;
        magic == 0x0102_1994
    }

    /// One `script(1)` run.
    struct Pty {
        code: Option<i32>,
        /// The typescript: everything the terminal showed (opv's stderr, the shell's own).
        typescript: String,
    }

    /// One session scenario: the e2e scenario, the session `op` outside it, the canary, and
    /// every channel captured so far.
    struct Lab {
        s: Scenario,
        fake: tempfile::TempDir,
        ram: Option<tempfile::TempDir>,
        canary: String,
        channels: RefCell<Vec<(String, Vec<u8>)>>,
        /// Channels allowed to hold the canary, and how many times exactly (S2's capture).
        allowed: RefCell<Vec<(String, usize)>>,
    }

    impl Lab {
        fn new(mode: Mode) -> Self {
            Self::with(mode, |s| s, None)
        }

        fn with(
            mode: Mode,
            edit: impl FnOnce(Scenario) -> Scenario,
            ram: Option<tempfile::TempDir>,
        ) -> Self {
            let s = edit(Scenario::new());
            s.install();
            let fake = tempfile::tempdir().expect("fake dir");
            let canary = new_canary();
            let lab = Self {
                s,
                fake,
                ram,
                canary,
                channels: RefCell::new(Vec::new()),
                allowed: RefCell::new(Vec::new()),
            };
            for d in [
                "world-out",
                "tmp",
                "out",
                "cases",
                "tools",
                "xdg/config",
                "xdg/state",
                "xdg/cache",
                "xdg/data",
                "run",
            ] {
                std::fs::create_dir_all(lab.path(d)).expect("dir");
            }
            // The world where nobody is signed in: op's signed-out answers.
            let mut out: Value = serde_json::from_str(
                &std::fs::read_to_string(lab.path("world/world.json")).expect("world"),
            )
            .expect("world");
            for a in out["op"]["accounts"].as_array_mut().expect("accounts") {
                a["signed_in"] = Value::Bool(false);
            }
            std::fs::write(lab.path("world-out/world.json"), out.to_string()).expect("world");
            std::fs::write(lab.path("world-out/faults.toml"), "").expect("faults");
            lab.mode(mode);
            let root = lab.root().display().to_string();
            let fill = |t: &str| {
                t.replace("@ROOT@", &root)
                    .replace("@FAKE@", &lab.fake.path().display().to_string())
                    .replace("@CANARY@", &lab.canary)
                    .replace("@VAR@", VAR)
            };
            write_exe(&lab.fake.path().join("op"), &fill(FAKE_OP));
            for tool in ["flyctl", "fly", "gh", "kubectl", "az"] {
                write_exe(
                    &lab.fake.path().join(tool),
                    &fill(&FAKE_TOOL.replace("@NAME@", tool)),
                );
            }
            std::os::unix::fs::symlink(OPV, lab.fake.path().join("opv")).expect("opv link");
            // The session op issued ends (idle expiry, `op signout` elsewhere), mid-shell.
            write_exe(
                &lab.fake.path().join("e2e-expire-session"),
                &fill("#!/bin/sh\nprintf expired > '@FAKE@/valid'\n"),
            );
            write_exe(&lab.path("tools/editor"), &fill(EDITOR));
            lab
        }

        /// The MCP requests the `mcp` case pipes into `opv mcp serve`, and the `.env` its
        /// import names.
        fn with_mcp_requests(self) -> Self {
            std::fs::write(self.path("cases/mcp.in"), MCP_REQUESTS).expect("mcp.in");
            std::fs::write(self.path("project/.env"), "API_KEY=test-marker-e2e-mcp\n")
                .expect(".env");
            self
        }

        fn root(&self) -> PathBuf {
            self.s.path("world").parent().expect("root").to_path_buf()
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.s.path(rel)
        }

        fn mode(&self, mode: Mode) {
            std::fs::write(self.path("world/session-mode"), mode.word()).expect("mode");
        }

        fn env(&self, c: &mut Command, shell: &str) {
            let root = self.root();
            c.env_clear()
                .current_dir(self.path("project"))
                .env(
                    "PATH",
                    format!(
                        "{}:{}:/usr/bin:/bin",
                        self.fake.path().display(),
                        self.path("bin").display()
                    ),
                )
                .env("HOME", self.path("home"))
                .env("OPV_NO_SKILL", "1")
                .env("OPV_SIM_WORLD", self.path("world"))
                .env("OPV_TEST_SUID_DUMPABLE", "0")
                .env("TMPDIR", self.path("tmp"))
                .env("XDG_CONFIG_HOME", self.path("xdg/config"))
                .env("XDG_STATE_HOME", self.path("xdg/state"))
                .env("XDG_CACHE_HOME", self.path("xdg/cache"))
                .env("XDG_DATA_HOME", self.path("xdg/data"))
                .env(
                    "XDG_RUNTIME_DIR",
                    self.ram
                        .as_ref()
                        .map_or_else(|| self.path("run"), |r| r.path().to_path_buf()),
                )
                .env("SHELL", shell)
                .env("TERM", "dumb")
                .env("LANG", "C.UTF-8")
                .env("R", &root);
        }

        /// `body` in bash at a terminal: history on (`HISTFILE` under the root), `$R` the root.
        fn bash(&self, label: &str, body: &str) -> Pty {
            let text = format!(
                "HISTFILE=\"$R/home/.bash_history\"; set -o history\n{body}\nrc=$?\nhistory -a\nexit $rc\n"
            );
            self.pty("/bin/bash", "--noprofile --norc", label, &text)
        }

        /// `body` in dash (`sh`) at a terminal.
        fn dash(&self, label: &str, body: &str) -> Option<Pty> {
            let dash = installed("dash")?;
            Some(self.pty(&dash, "", label, body))
        }

        /// `body` in fish at a terminal, when fish is installed.
        fn fish(&self, label: &str, body: &str) -> Option<Pty> {
            let fish = installed("fish")?;
            Some(self.pty(&fish, "--no-config", label, body))
        }

        /// `body` in pwsh at a terminal, when pwsh is installed.
        fn pwsh(&self, label: &str, body: &str) -> Option<Pty> {
            let pwsh = installed("pwsh")?;
            Some(self.pty(&pwsh, "-NoProfile -NonInteractive -File", label, body))
        }

        fn pty(&self, shell: &str, flags: &str, label: &str, body: &str) -> Pty {
            let ext = if shell.ends_with("pwsh") { "ps1" } else { "sh" };
            let file = self.path(&format!("cases/{label}.{ext}"));
            std::fs::write(&file, body).expect("case script");
            let ts = self.path(&format!("out/{label}.typescript"));
            let mut c = Command::new("script");
            c.arg("-qfec")
                .arg(format!("{shell} {flags} {}", file.display()))
                .arg(&ts)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            self.env(&mut c, shell);
            let mut child = c.spawn().expect("script(1)");
            let deadline = Instant::now() + Duration::from_secs(120);
            let status = loop {
                if let Some(st) = child.try_wait().expect("wait") {
                    break st;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("{label}: the terminal never finished (a prompt waiting?)");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let out = child.wait_with_output().expect("output");
            self.capture(&format!("terminal:{label}"), out.stdout);
            self.capture(&format!("script stderr:{label}"), out.stderr);
            let typescript = std::fs::read(&ts)
                .unwrap_or_else(|_| panic!("{label}: script wrote no typescript"));
            self.capture(&format!("typescript:{label}"), typescript.clone());
            Pty {
                code: status.code(),
                typescript: String::from_utf8_lossy(&typescript).into_owned(),
            }
        }

        fn capture(&self, label: &str, bytes: Vec<u8>) {
            self.channels.borrow_mut().push((label.to_string(), bytes));
        }

        /// The file `out/<name>` a command wrote, as a channel; it must exist.
        fn out(&self, name: &str) -> String {
            self.read(&format!("out/{name}"))
        }

        /// The file `rel` under the root, as a channel; it must exist.
        fn read(&self, rel: &str) -> String {
            let bytes = std::fs::read(self.path(rel))
                .unwrap_or_else(|_| panic!("expected channel {rel} was not produced"));
            self.capture(rel, bytes.clone());
            String::from_utf8_lossy(&bytes).into_owned()
        }

        /// `out/<name>` as one JSON document.
        fn doc(&self, name: &str) -> Value {
            let text = self.out(name);
            serde_json::from_str(text.trim())
                .unwrap_or_else(|_| panic!("out/{name} is not one document: {text}"))
        }

        /// The session `op`'s log (argv and `OP_*` names), as a channel.
        fn op_log(&self) -> Vec<String> {
            let bytes = std::fs::read(self.path("world/session.log")).unwrap_or_default();
            self.capture("log:op argv and env names", bytes.clone());
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn signins(&self) -> usize {
            self.op_log()
                .iter()
                .filter(|l| l.starts_with(SIGNIN))
                .count()
        }

        /// The non-op tools' log, as a channel; it must exist (a tool was called).
        fn tool_log(&self) -> Vec<String> {
            let bytes = std::fs::read(self.path("world/env.log"))
                .expect("expected channel world/env.log was not produced: no non-op tool ran");
            self.capture("log:non-op tool env names", bytes.clone());
            String::from_utf8_lossy(&bytes)
                .lines()
                .map(str::to_string)
                .collect()
        }

        /// `label` may hold the canary exactly `n` times (S2's capture).
        fn allow(&self, label: &str, n: usize) {
            self.allowed.borrow_mut().push((label.to_string(), n));
        }

        /// What a snapshot may show: no root, no fake dir, no token, no PTY line ends, no
        /// `script` header.
        fn norm(&self, s: &str) -> String {
            let s = s.replace("\r\n", "\n").replace('\r', "");
            let s = s
                .lines()
                .filter(|l| {
                    !l.starts_with("Script started on ") && !l.starts_with("Script done on ")
                })
                .map(|l| format!("{l}\n"))
                .collect::<String>();
            let s = s.replace(&self.fake.path().display().to_string(), "<FAKE>");
            let token = regex::Regex::new(&format!("{}g[0-9]+", regex::escape(&self.canary)))
                .expect("regex");
            let s = token.replace_all(&s, "<SESSION>").into_owned();
            self.s.normalize(&s)
        }

        /// The canary scan: every captured channel and every file under the root (and the
        /// RAM folder). `expect` names channels the case must have produced. Panics naming
        /// every channel that holds the canary, beyond what [`Lab::allow`] lets through.
        fn finish(&self, expect: &[&str]) {
            let channels = self.channels.borrow();
            let missing: Vec<&&str> = expect
                .iter()
                .filter(|e| !channels.iter().any(|(l, _)| l == **e))
                .collect();
            assert!(
                missing.is_empty(),
                "channels the scan expected were not produced: {missing:?}"
            );
            let needle = self.canary.as_bytes();
            let count = |b: &[u8]| b.windows(needle.len()).filter(|w| *w == needle).count();
            let mut hits: Vec<(String, usize)> = channels
                .iter()
                .map(|(l, b)| (l.clone(), count(b)))
                .filter(|(_, n)| *n > 0)
                .collect();
            let mut files = 0usize;
            let mut roots = vec![(self.root(), "file:".to_string())];
            if let Some(r) = &self.ram {
                roots.push((r.path().to_path_buf(), "ram:".to_string()));
            }
            for (root, tag) in &roots {
                let mut stack = vec![root.clone()];
                while let Some(dir) = stack.pop() {
                    let Ok(entries) = std::fs::read_dir(&dir) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        let p = e.path();
                        let Ok(ft) = e.file_type() else { continue };
                        if ft.is_dir() {
                            stack.push(p);
                        } else if ft.is_file() {
                            files += 1;
                            let n = count(&std::fs::read(&p).unwrap_or_default());
                            if n > 0 {
                                let rel = p.strip_prefix(root).unwrap_or(&p).display();
                                hits.push((format!("{tag}{rel}"), n));
                            }
                        }
                    }
                }
            }
            assert!(files > 0, "the file scan found no file under the root");
            let allowed = self.allowed.borrow();
            for (label, n) in allowed.iter() {
                let got = hits.iter().find(|(l, _)| l == label).map_or(0, |(_, n)| *n);
                assert_eq!(
                    got, *n,
                    "{label} must hold the session exactly {n} time(s), holds it {got}"
                );
            }
            hits.retain(|(l, _)| !allowed.iter().any(|(a, _)| a == l));
            assert!(
                hits.is_empty(),
                "the session token leaked into: {hits:?} (channel, occurrences)"
            );
        }
    }

    /// The committed snapshot `name`, or its rewrite under `UPDATE_SNAPSHOTS=1`.
    fn snapshot(name: &str, got: &str) {
        let path = scenario_snapshots().join(format!("{name}.snap"));
        if updating() {
            std::fs::write(&path, got).expect("write snapshot");
            return;
        }
        let want = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            got,
            want,
            "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
            path.display()
        );
    }

    /// Every op call after the sign-in carried the token op issued (the eval'd line was not
    /// masked, FMECA H2), and the calls before it none.
    fn every_call_after_the_signin_is_signed_in(log: &[String]) {
        let at = log
            .iter()
            .position(|l| l.starts_with(SIGNIN))
            .expect("no op signin");
        let after: Vec<&String> = log[at + 1..]
            .iter()
            .filter(|l| !l.starts_with("op account ") && !l.starts_with("op --version"))
            .collect();
        assert!(!after.is_empty(), "no op call after the sign-in: {log:?}");
        for l in after {
            assert!(l.ends_with("session: issued"), "{l}");
        }
    }

    fn assert_no_session_names(what: &str, env: &str) {
        let names: Vec<&str> = env
            .lines()
            .filter_map(|l| l.split('=').next())
            .filter(|n| n.starts_with("OP_SESSION"))
            .collect();
        assert!(names.is_empty(), "{what} holds {names:?}");
    }

    // --- S1, S1b, S11: eval once, then commands reuse it ------------------------------------

    /// Channels 1, 2, 3, 6 and 7: one sign-in, then `inventory`, `next`, `account list`,
    /// `doctor` (text and `--json`) and a `--verbose` run all reuse it. The shell's own
    /// environment holds no session (H4); its history holds no token.
    #[test]
    fn s1_one_eval_signs_in_once_and_every_command_reuses_it() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "s1",
            r#"eval "$(opv login --shell)"
echo "function: $(type -t opv)"
env > "$R/out/shell.env"
opv inventory --json > "$R/out/inventory.json" 2> "$R/out/inventory.err"; echo "inventory=$?"
opv inventory > "$R/out/inventory.txt" 2> "$R/out/inventory-text.err"; echo "inventory-text=$?"
opv next --json > "$R/out/next.json" 2> "$R/out/next.err"; echo "next=$?"
opv account list --json > "$R/out/accounts.json" 2> "$R/out/accounts.err"; echo "accounts=$?"
opv doctor > "$R/out/doctor.txt" 2> "$R/out/doctor.err"; echo "doctor=$?"
opv doctor --json > "$R/out/doctor.json" 2> "$R/out/doctor-json.err"; echo "doctor-json=$?"
opv --verbose inventory --json > "$R/out/verbose.json" 2> "$R/out/verbose.err"; echo "verbose=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        for ok in [
            "function: function",
            "inventory=0",
            "inventory-text=0",
            "next=0",
            "accounts=0",
            "doctor-json=0",
            "verbose=0",
        ] {
            assert!(t.typescript.contains(ok), "{ok}: {}", t.typescript);
        }
        assert!(
            t.typescript
                .contains("Signed in to dev@example.com in this shell")
        );
        assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
        every_call_after_the_signin_is_signed_in(&lab.op_log());
        // H4: the session lives in the shell, never in its environment.
        assert_no_session_names("the eval'd shell's environment", &lab.out("shell.env"));
        // S11: doctor names the variable, live, never its value.
        let doctor = lab.doc("doctor.json");
        let row = doctor["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .find(|c| c["name"] == "op shell session")
            .cloned()
            .unwrap_or_else(|| panic!("no op shell session row: {doctor}"));
        assert_eq!(row["state"], "live", "{row}");
        assert!(row["detail"].as_str().unwrap_or_default().contains(VAR));
        assert!(lab.doc("inventory.json")["ok"] == Value::Bool(true));
        // History is written (so the check means something) and holds the typed line only.
        let history = lab.read("home/.bash_history");
        assert!(history.contains("opv login --shell"), "{history}");
        for f in [
            "inventory.err",
            "inventory.txt",
            "inventory-text.err",
            "next.json",
            "next.err",
            "accounts.json",
            "accounts.err",
            "doctor.txt",
            "doctor.err",
            "doctor-json.err",
            "verbose.json",
            "verbose.err",
        ] {
            lab.out(f);
        }
        lab.finish(&[
            "typescript:s1",
            "out/shell.env",
            "out/inventory.json",
            "out/verbose.err",
            "out/doctor.json",
            "home/.bash_history",
            "log:op argv and env names",
        ]);
    }

    // --- S2: the lines themselves, into a capture pipe --------------------------------------

    /// Channel 1's one allowed appearance: the lines `opv login --shell` prints, captured
    /// by the shell (a pipe it holds) instead of evaluated. Golden per shell; fish runs under
    /// fish and powershell under pwsh where installed.
    #[test]
    fn s2_the_shell_lines_hold_the_session_once_and_only_in_the_capture() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "s2_posix",
            r#"lines="$(opv login --shell=posix)"; rc=$?
printf '%s' "$lines" > "$R/out/capture.posix"
exit $rc"#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        let posix = lab.out("capture.posix");
        lab.allow("out/capture.posix", 1);
        lab.allow("file:out/capture.posix", 1);
        let golden = format!("# posix\n{}\n", lab.norm(&posix));
        match lab.fish(
            "s2_fish",
            "opv login --shell=fish | string collect > \"$R/out/capture.fish\"\n",
        ) {
            Some(t) => {
                assert_eq!(t.code, Some(0), "{}", t.typescript);
                let fish = lab.out("capture.fish");
                lab.allow("out/capture.fish", 1);
                lab.allow("file:out/capture.fish", 1);
                // Not in the snapshot, which must not depend on what the machine has.
                assert_eq!(
                    lab.norm(&fish),
                    format!(
                        "set -g __opv_session_UE2EDEVUSER000000000000001 <SESSION>; function opv; \
                         {VAR}=$__opv_session_UE2EDEVUSER000000000000001 command opv $argv; end\n"
                    )
                );
            }
            None => skip("s2 fish", "fish is not installed (command -v fish)"),
        }
        match lab.pwsh(
            "s2_pwsh",
            "$l = opv login --shell=powershell | Out-String\n\
             Set-Content -NoNewline -Path \"$env:R/out/capture.pwsh\" -Value $l\n\
             exit $LASTEXITCODE\n",
        ) {
            // H5: withheld; refused before any sign-in, nothing printed.
            // pwsh reports a native command's exit through `| Out-String` unreliably (1 on
            // GitHub's runners), so the refusal is checked by its text and its empty capture.
            Some(t) => {
                assert!(
                    t.code != Some(0)
                        && t.typescript
                            .contains("this command needs --shell, one of posix, fish"),
                    "{}",
                    t.typescript
                );
                assert_eq!(lab.out("capture.pwsh"), "");
            }
            None => skip("s2 powershell", "pwsh is not installed (command -v pwsh)"),
        }
        snapshot("session_shell_lines", &golden);
        assert!(
            posix.starts_with("__opv_session_UE2EDEVUSER000000000000001=")
                && posix.contains(&format!(
                    "opv() {{ {VAR}=\"$__opv_session_UE2EDEVUSER000000000000001\" command opv \"$@\"; }}"
                )),
            "{}",
            lab.norm(&posix)
        );
        lab.finish(&["typescript:s2_posix", "out/capture.posix"]);
    }

    // --- S3, S4: an expired session ---------------------------------------------------------

    /// An expired shell session as every command reports it (session-reuse §4.3):
    /// `expired`, the refresh as the step.
    fn assert_expired_with_the_refresh(name: &str, doc: &Value) {
        assert_eq!(doc["error"]["code"], "op_not_signed_in", "{name}: {doc}");
        assert_eq!(
            doc["error"]["subject"]["state"]["state"], "expired",
            "{name}: {doc}"
        );
        assert_eq!(
            doc["next"]["command"], r#"eval "$(opv login --shell)""#,
            "{name}: {doc}"
        );
    }

    /// Channels 2 and 3 (S3): an expired session under `--json` (stdout and stderr files,
    /// so no prompt) is `op_not_signed_in`, `expired`, with the refresh as the step, in
    /// every command: those that check the session first (`ready`, `access`) and those that
    /// read op's signed-out reply (`inventory`, `next`). `--verbose` included.
    #[test]
    fn s3_an_expired_session_under_json_names_the_refresh() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "s3",
            r#"eval "$(opv login --shell)"
e2e-expire-session
for c in ready access inventory next; do
  if [ $c = ready ]; then a="ready dev"; else a=$c; fi
  opv $a --json > "$R/out/$c.json" 2> "$R/out/$c.err"; echo "$c=$?"
done
opv --verbose ready dev --json > "$R/out/verbose.json" 2> "$R/out/verbose.err"; echo "verbose=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        for c in ["ready", "access", "inventory", "next", "verbose"] {
            assert!(
                t.typescript.contains(&format!("{c}=7")),
                "{c}: {}",
                t.typescript
            );
        }
        assert_expired_with_the_refresh("ready", &lab.doc("ready.json"));
        assert_expired_with_the_refresh("access", &lab.doc("access.json"));
        assert_expired_with_the_refresh("inventory", &lab.doc("inventory.json"));
        assert_expired_with_the_refresh("next", &lab.doc("next.json"));
        assert_expired_with_the_refresh("ready --verbose", &lab.doc("verbose.json"));
        // No prompt without a terminal on stderr: the sign-in stays the eval's one.
        assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
        for c in ["ready", "access", "inventory", "next", "verbose"] {
            lab.out(&format!("{c}.err"));
        }
        lab.finish(&[
            "typescript:s3",
            "out/ready.json",
            "out/inventory.json",
            "out/next.json",
            "out/ready.err",
            "out/verbose.err",
        ]);
    }

    /// Channels 2 and 3 (S4): an expired session at the terminal signs in once inside the
    /// command, which then goes on; stderr names the session variable (never its value) and
    /// the refresh. `--verbose` included.
    #[test]
    fn s4_an_expired_session_at_the_terminal_signs_in_once_in_the_command() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "s4",
            r#"eval "$(opv login --shell)"
e2e-expire-session
opv inventory > "$R/out/s4.out"; echo "inventory=$?"
opv --verbose inventory > "$R/out/s4-verbose.out"; echo "verbose=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        assert!(t.typescript.contains("inventory=0"), "{}", t.typescript);
        assert!(t.typescript.contains("verbose=0"), "{}", t.typescript);
        assert!(
            t.typescript.contains(
                r#"to stay signed in across commands in this shell, run eval "$(opv login --shell)""#
            ),
            "{}",
            t.typescript
        );
        // The variable is named, twice (one notice per command), by name only.
        let named = t
            .typescript
            .matches("This shell's 1Password session (OP_SESSION_")
            .count();
        assert_eq!(named, 2, "{}", t.typescript);
        assert!(
            t.typescript
                .lines()
                .filter(|l| l.contains("This shell's 1Password session ("))
                .all(|l| l.contains(") expired.") && !l.contains('=')),
            "{}",
            t.typescript
        );
        // The eval's sign-in, then one in each command (the shell's variable stays stale).
        assert_eq!(lab.signins(), 3, "{:?}", lab.op_log());
        lab.out("s4.out");
        lab.out("s4-verbose.out");
        lab.finish(&["typescript:s4", "out/s4.out", "out/s4-verbose.out"]);
    }

    // --- S5, S6, S6b: the app, a live session, a stale one ----------------------------------

    /// S5: with the app integration on, `--shell` prints nothing and says so; later commands
    /// sign nothing in and carry no session.
    #[test]
    fn s5_the_app_integration_needs_nothing_set() {
        let lab = Lab::new(Mode::App);
        let t = lab.bash(
            "s5",
            r#"lines="$(opv login --shell)"; echo "login=$? bytes=${#lines}"; eval "$lines"
opv inventory --json > "$R/out/app1.json"; echo "inventory=$?"
opv next --json > "$R/out/app2.json"; echo "next=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        for ok in ["login=0 bytes=0", "inventory=0", "next=0", "Nothing to set"] {
            assert!(t.typescript.contains(ok), "{ok}: {}", t.typescript);
        }
        let log = lab.op_log();
        // The app answered, so nothing was signed in: not by the login, not by a command.
        assert_eq!(lab.signins(), 0, "{log:?}");
        assert!(
            log.iter().all(|l| !l.contains("OP_SESSION")),
            "a session variable reached op: {log:?}"
        );
        lab.out("app1.json");
        lab.out("app2.json");
        lab.finish(&["typescript:s5", "out/app1.json", "out/app2.json"]);
    }

    /// S6: a shell whose session is live refreshes with no prompt and no sign-in.
    #[test]
    fn s6_a_live_session_is_set_again_without_a_sign_in() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "s6",
            r#"eval "$(opv login --shell)"
eval "$(opv login --shell)"; echo "again=$?"
opv inventory --json > "$R/out/s6.json"; echo "inventory=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        for ok in ["Already signed in in this shell", "again=0", "inventory=0"] {
            assert!(t.typescript.contains(ok), "{ok}: {}", t.typescript);
        }
        assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
        lab.out("s6.json");
        lab.finish(&["typescript:s6", "out/s6.json"]);
    }

    /// S6b (FMECA H3, #167): a stale variable whose `whoami` still answers is not "live":
    /// doctor says expired, and `--shell` signs in again and prints a new line.
    #[test]
    fn s6b_a_stale_session_whoami_still_answers_is_signed_in_again() {
        let lab = Lab::new(Mode::Lenient);
        let t = lab.bash(
            "s6b",
            r#"eval "$(opv login --shell)"
e2e-expire-session
opv doctor --json > "$R/out/stale.json"
eval "$(opv login --shell)"; echo "refresh=$?"
opv doctor --json > "$R/out/fresh.json"
opv inventory --json > "$R/out/s6b.json"; echo "inventory=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        assert!(t.typescript.contains("inventory=0"), "{}", t.typescript);
        assert!(
            !t.typescript.contains("Already signed in"),
            "{}",
            t.typescript
        );
        let state = |name: &str| {
            let d = lab.doc(name);
            d["checks"]
                .as_array()
                .expect("checks")
                .iter()
                .find(|c| c["name"] == "op shell session")
                .map(|c| c["state"].clone())
                .unwrap_or(Value::Null)
        };
        assert_eq!(state("stale.json"), "expired");
        assert_eq!(state("fresh.json"), "live");
        let log = lab.op_log();
        assert_eq!(lab.signins(), 2, "{log:?}");
        assert!(
            log.iter()
                .any(|l| l.starts_with("op whoami") && l.ends_with("session: stale")),
            "the stale variable never answered whoami: {log:?}"
        );
        lab.out("s6b.json");
        lab.finish(&["typescript:s6b", "out/stale.json", "out/fresh.json"]);
    }

    // --- S7, M1, M5: refusals ---------------------------------------------------------------

    /// One refusal: its label, the shell line, the exit, words of its message, and whether
    /// its stdout is captured to `out/<label>.stdout` (else it went to the terminal).
    struct Refusal {
        label: &'static str,
        line: String,
        exit: i32,
        says: &'static str,
        stdout_file: bool,
    }

    /// `o="$(<cmd>)"`: the shell's own capture, kept as a file for the check.
    fn captured(label: &'static str, cmd: &str, exit: i32, says: &'static str) -> Refusal {
        Refusal {
            label,
            line: format!(
                "o=\"$({cmd})\"; rc=$?; printf '%s' \"$o\" > \"$R/out/{label}.stdout\"; exit $rc"
            ),
            exit,
            says,
            stdout_file: true,
        }
    }

    fn raw(label: &'static str, line: &str, exit: i32, says: &'static str, file: bool) -> Refusal {
        Refusal {
            label,
            line: line.to_string(),
            exit,
            says,
            stdout_file: file,
        }
    }

    const NOT_A_PIPE: &str = "only writes to a pipe; stdout here is not a pipe";

    /// §5.5 in order, plus M1's other readers and M5's other syntax.
    fn refusals() -> Vec<Refusal> {
        vec![
            captured(
                "usage_shell_value",
                "opv login --shell=dev",
                2,
                "invalid value 'dev'",
            ),
            captured(
                "usage_with_command",
                "opv login --shell -- opv inventory",
                2,
                "cannot be used with",
            ),
            captured("ci", "CI=true opv login --shell", 6, "this is a CI run"),
            captured(
                "github_actions",
                "GITHUB_ACTIONS=true opv login --shell",
                6,
                "this is a CI run",
            ),
            captured(
                "no_tty",
                "opv login --shell </dev/null",
                6,
                "needs a person at a terminal, and there is none",
            ),
            captured(
                "service_account",
                "OP_SERVICE_ACCOUNT_TOKEN=ops_e2e_not_a_token opv login --shell",
                7,
                "not as the token in OP_SERVICE_ACCOUNT_TOKEN",
            ),
            captured(
                "agent",
                "CLAUDECODE=1 opv login --shell",
                6,
                "this shell looks like an assistant (CLAUDECODE)",
            ),
            raw(
                "stdout_terminal",
                "opv login --shell; exit $?",
                6,
                "only writes to a pipe; stdout here is the terminal",
                false,
            ),
            raw(
                "stdout_file",
                "opv login --shell > \"$R/out/stdout_file.stdout\"; exit $?",
                6,
                "only writes to a pipe; stdout here is a file",
                true,
            ),
            // M1: a pipe whose reader is not the shell.
            raw(
                "m1_cat",
                "opv login --shell | cat; exit ${PIPESTATUS[0]}",
                6,
                NOT_A_PIPE,
                false,
            ),
            raw(
                "m1_tee",
                "opv login --shell | tee \"$R/out/m1_tee.stdout\"; exit ${PIPESTATUS[0]}",
                6,
                NOT_A_PIPE,
                true,
            ),
            raw(
                "m1_fifo",
                "mkfifo \"$R/out/m1.fifo\"; cat \"$R/out/m1.fifo\" > \"$R/out/m1_fifo.stdout\" &\n\
                 opv login --shell > \"$R/out/m1.fifo\"; rc=$?; wait; exit $rc",
                6,
                NOT_A_PIPE,
                true,
            ),
            raw(
                "m1_process_substitution",
                "opv login --shell > >(cat > \"$R/out/m1_process_substitution.stdout\"); rc=$?; wait; exit $rc",
                6,
                NOT_A_PIPE,
                true,
            ),
            // M5: another shell's syntax than the running one's.
            captured(
                "m5_fish_under_bash",
                "opv login --shell=fish",
                2,
                "this shell is a POSIX shell (bash, zsh, sh) but the session lines asked for are for fish",
            ),
            captured(
                "m5_powershell_under_bash",
                "opv login --shell=powershell",
                2,
                "but the session lines asked for are for PowerShell",
            ),
        ]
    }

    fn check_refusal(lab: &Lab, r: &Refusal, t: &Pty) -> String {
        assert_eq!(t.code, Some(r.exit), "{}: {}", r.label, t.typescript);
        assert!(
            t.typescript.contains(r.says),
            "{}: {}",
            r.label,
            t.typescript
        );
        if r.stdout_file {
            let stdout = lab.out(&format!("{}.stdout", r.label));
            assert_eq!(stdout, "", "{}: stdout is not empty", r.label);
        }
        format!(
            "## {}: {}\nexit: {}\n{}",
            r.label,
            r.line,
            r.exit,
            lab.norm(&t.typescript)
        )
    }

    /// Channels 1, 3, 7, 9 and 10, and the snapshot `session_refusals`: each refusal of
    /// §5.5, M1's pipes to another reader and M5's other syntax under bash, before any `op`
    /// call, with nothing on stdout. Then M1's positive control: the eval's own pipe signs
    /// in once, and the next command reuses it with no second prompt.
    #[test]
    fn s7_m1_m5_refusals_print_nothing_and_call_no_op() {
        let lab = Lab::new(Mode::Token);
        let mut snap = String::from("# opv login --shell refusals (bash under script(1))\n");
        let mut expect: Vec<String> = Vec::new();
        for r in refusals() {
            let t = lab.bash(r.label, &r.line);
            snap.push_str(&check_refusal(&lab, &r, &t));
            assert!(
                lab.op_log().is_empty(),
                "{}: op was called before the refusal: {:?}",
                r.label,
                lab.op_log()
            );
            expect.push(format!("typescript:{}", r.label));
        }
        // §5.5 `choice_required`: PowerShell asked for, or no syntax for `$SHELL`, under a
        // parent that is no shell (it holds the pipe, so stdout is the eval's).
        match installed("python3") {
            Some(_) => {
                for (label, args, shell) in [
                    ("choice_powershell", "'--shell=powershell'", "/bin/bash"),
                    (
                        "choice_unknown_shell",
                        "'--shell'",
                        "/usr/bin/e2e-no-such-shell",
                    ),
                ] {
                    let line = format!(
                        "SHELL={shell} python3 -c 'import subprocess,sys; p=subprocess.run([\"opv\",\"login\",{args}], stdout=subprocess.PIPE); open(sys.argv[1],\"wb\").write(p.stdout); sys.exit(p.returncode)' \"$R/out/{label}.stdout\"; exit $?",
                        args = args.replace('\'', "\"")
                    );
                    let r = raw(label, &line, 2, "--shell", true);
                    let t = lab.bash(r.label, &r.line);
                    snap.push_str(&check_refusal(&lab, &r, &t));
                    assert!(lab.op_log().is_empty(), "{label}: {:?}", lab.op_log());
                    expect.push(format!("typescript:{label}"));
                }
            }
            None => skip(
                "choice_required refusals",
                "python3 is not installed (command -v python3): no non-shell parent to hold the pipe",
            ),
        }
        if installed("python3").is_some() {
            snapshot("session_refusals", &snap);
        } else {
            skip(
                "the session_refusals snapshot",
                "it holds the python3 cases",
            );
        }
        // M1's positive control: the shell's own pipe.
        let t = lab.bash(
            "m1_control",
            r#"eval "$(opv login --shell)"
opv inventory --json > "$R/out/m1_control.json"; echo "inventory=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        assert!(t.typescript.contains("inventory=0"), "{}", t.typescript);
        assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
        every_call_after_the_signin_is_signed_in(&lab.op_log());
        lab.out("m1_control.json");
        expect.push("typescript:m1_control".into());
        expect.push("out/m1_tee.stdout".into());
        expect.push("out/m1_fifo.stdout".into());
        let expect: Vec<&str> = expect.iter().map(String::as_str).collect();
        lab.finish(&expect);
    }

    /// Channel 10 (M5) beyond bash: `--shell=posix` under fish and under pwsh is refused
    /// before any sign-in, and the shell's own stderr (the typescript) holds no token. The
    /// positive controls: the matching syntax evaluates with no shell error under bash, sh
    /// and fish, and the next command reuses the session with no second prompt.
    #[test]
    fn m5_the_running_shells_own_syntax_evaluates_and_any_other_is_refused() {
        // bash, explicit `--shell=posix`.
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "m5_bash_control",
            r#"eval "$(opv login --shell=posix)"; echo "eval=$?"
opv inventory --json > "$R/out/bash.json"; echo "inventory=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        for bad in ["syntax error", "command not found", "unexpected"] {
            assert!(!t.typescript.contains(bad), "{bad}: {}", t.typescript);
        }
        assert!(t.typescript.contains("inventory=0"), "{}", t.typescript);
        assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
        every_call_after_the_signin_is_signed_in(&lab.op_log());
        lab.out("bash.json");
        lab.finish(&["typescript:m5_bash_control", "out/bash.json"]);

        // sh (dash, Debian's /bin/sh), the automatic choice.
        let lab = Lab::new(Mode::Token);
        match lab.dash(
            "m5_sh_control",
            "eval \"$(opv login --shell)\"; echo \"eval=$?\"\n\
             opv inventory --json > \"$R/out/sh.json\"; echo \"inventory=$?\"\n",
        ) {
            Some(t) => {
                assert_eq!(t.code, Some(0), "{}", t.typescript);
                assert!(t.typescript.contains("inventory=0"), "{}", t.typescript);
                assert!(!t.typescript.contains("not found"), "{}", t.typescript);
                assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
                every_call_after_the_signin_is_signed_in(&lab.op_log());
                lab.out("sh.json");
                lab.finish(&["typescript:m5_sh_control", "out/sh.json"]);
            }
            None => skip("m5 sh control", "dash is not installed (command -v dash)"),
        }

        // fish: posix syntax refused; its own evaluates.
        let lab = Lab::new(Mode::Token);
        match lab.fish(
            "m5_posix_under_fish",
            "opv login --shell=posix | source\n\
             echo \"refused=$pipestatus[1]\"\n\
             opv login --shell=fish | source\n\
             opv inventory --json > \"$R/out/fish.json\"; echo \"inventory=$status\"\n",
        ) {
            Some(t) => {
                assert!(t.typescript.contains("refused=2"), "{}", t.typescript);
                assert!(
                    t.typescript
                        .contains("but the session lines asked for are for a POSIX"),
                    "{}",
                    t.typescript
                );
                assert!(t.typescript.contains("inventory=0"), "{}", t.typescript);
                assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
                lab.out("fish.json");
                lab.finish(&["typescript:m5_posix_under_fish", "out/fish.json"]);
            }
            None => skip("m5 under fish", "fish is not installed (command -v fish)"),
        }

        // pwsh: posix syntax refused (PowerShell itself is withheld, H5: no control).
        let lab = Lab::new(Mode::Token);
        match lab.pwsh(
            "m5_posix_under_pwsh",
            "opv login --shell=posix | Out-String | Invoke-Expression\n\
             Write-Output \"refused=$LASTEXITCODE\"\n",
        ) {
            Some(t) => {
                assert!(t.typescript.contains("refused=2"), "{}", t.typescript);
                assert_eq!(lab.signins(), 0, "{:?}", lab.op_log());
                lab.finish(&["typescript:m5_posix_under_pwsh"]);
            }
            None => skip("m5 under pwsh", "pwsh is not installed (command -v pwsh)"),
        }
    }

    // --- S8, M6: children of opv hold no session --------------------------------------------

    /// The contract without `[products.web.local]` (and so without its file keys).
    fn without_local(s: Scenario) -> Scenario {
        let p = s.path("project/secrets.toml");
        let text = std::fs::read_to_string(&p).expect("config");
        let text = text.replace(
            "[products.web.local]\nenvironment = \"declared_only\"\nsecrets_dir_env = \"WEB_SECRETS_DIR\"\n",
            "",
        );
        assert!(!text.contains("[products.web.local]"));
        s.file("project/secrets.toml", &text)
    }

    /// Channels 2, 5, 6 and 8 (S8, H1, M6), and the editor of `config edit`: under the `opv`
    /// function opv holds the session, and none of its children does: not the app of
    /// `opv run` (with and without `[products.<p>.local]`), not `flyctl`, `gh` or `kubectl`,
    /// not the editor. Only `op` gets it.
    fn run_children(local: bool) {
        let ram = if local {
            match ram_dir() {
                Ok(r) => Some(r),
                Err(why) => {
                    skip("s8 with [products.web.local]", &why);
                    return;
                }
            }
        } else {
            None
        };
        let lab = if local {
            Lab::with(Mode::Token, |s| s, ram)
        } else {
            Lab::with(Mode::Token, without_local, None)
        };
        let label = if local { "s8_local" } else { "s8_inherit" };
        let t = lab.bash(
            label,
            r#"eval "$(opv login --shell)"
opv run dev --product web --role serve -- sh -c 'env; for f in $(find "${WEB_SECRETS_DIR:-/nonexistent}" -type f 2>/dev/null); do echo "file $f"; done' > "$R/out/app.out" 2> "$R/out/app.err"; echo "run=$?"
opv status prod --json > "$R/out/status.json" 2> "$R/out/status.err"; echo "status=$?"
EDITOR="$R/tools/editor" opv config edit; echo "edit=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        assert!(t.typescript.contains("run=0"), "{}", t.typescript);
        assert!(t.typescript.contains("edit=0"), "{}", t.typescript);
        let app = lab.out("app.out");
        assert!(app.contains("API_KEY="), "the app never ran: {app}");
        let op_names: Vec<&str> = app
            .lines()
            .filter_map(|l| l.split('=').next())
            .filter(|n| n.starts_with("OP_"))
            .collect();
        assert!(op_names.is_empty(), "the app got {op_names:?}");
        if local {
            assert!(
                app.lines().any(|l| l.starts_with("file ")),
                "no file was delivered into the RAM folder, so it was never scanned: {app}"
            );
        }
        let log = lab.op_log();
        let run = log
            .iter()
            .find(|l| l.starts_with("op run "))
            .unwrap_or_else(|| panic!("no op run: {log:?}"));
        assert!(
            run.contains("opv local-delivery"),
            "the app ran without the step: {run}"
        );
        assert!(run.ends_with("session: issued"), "{run}");
        let tools = lab.tool_log();
        assert!(!tools.is_empty());
        for l in &tools {
            assert!(!l.contains("OP_SESSION"), "{l}");
        }
        assert_no_session_names("config edit's editor", &lab.out("editor.env"));
        assert_eq!(lab.signins(), 1, "{log:?}");
        lab.out("app.err");
        lab.out("status.json");
        lab.out("status.err");
        lab.finish(&[
            &format!("typescript:{label}"),
            "out/app.out",
            "out/editor.env",
            "out/status.json",
            "log:non-op tool env names",
            "log:op argv and env names",
        ]);
    }

    #[test]
    fn s8_opv_run_without_a_local_section_gives_the_app_no_session() {
        run_children(false);
    }

    #[test]
    fn s8_opv_run_with_a_local_section_gives_the_app_no_session() {
        run_children(true);
    }

    // --- S9, S10 ----------------------------------------------------------------------------

    /// S9: with no `.opv`, `--account X --shell` records X only after the sign-in; with
    /// `--no-record`, `.opv` stays absent. The refresh then names the account.
    #[test]
    fn s9_the_account_is_recorded_only_after_the_sign_in() {
        let account = crate::coverage::DEV_ACCOUNT;
        let lab = Lab::with(Mode::Token, |s| s.dot_opv(None).git_checkout(), None);
        let t = lab.bash(
            "s9_no_record",
            &format!(
                "eval \"$(opv login --shell --account {account} --no-record)\"; echo \"eval=$?\""
            ),
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        assert!(!lab.path("project/.opv").exists(), "--no-record wrote .opv");
        assert!(
            t.typescript.contains(&format!(
                "eval \"$(opv login --shell --account {account})\""
            )),
            "{}",
            t.typescript
        );
        let t = lab.bash(
            "s9_record",
            &format!("eval \"$(opv login --shell --account {account})\"; echo \"eval=$?\""),
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        let dot = lab.read("project/.opv");
        assert!(dot.contains(account), "{dot}");
        assert_eq!(lab.signins(), 2, "{:?}", lab.op_log());
        lab.finish(&[
            "typescript:s9_no_record",
            "typescript:s9_record",
            "project/.opv",
        ]);
    }

    /// Channel 2 (S10): `opv login -- opv inventory --json` is unchanged: one sign-in, the
    /// child reuses it, its stdout holds no token, and the shell stays signed out.
    #[test]
    fn s10_login_with_a_command_is_unchanged() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash(
            "s10",
            r#"opv login -- opv inventory --json > "$R/out/s10.json"; echo "login=$?"
env > "$R/out/shell.env""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        assert!(t.typescript.contains("login=0"), "{}", t.typescript);
        assert_eq!(lab.doc("s10.json")["ok"], true);
        assert_eq!(lab.signins(), 1, "{:?}", lab.op_log());
        every_call_after_the_signin_is_signed_in(&lab.op_log());
        assert_no_session_names("the shell after opv login --", &lab.out("shell.env"));
        lab.finish(&["typescript:s10", "out/s10.json"]);
    }

    // --- MCP ------------------------------------------------------------------------------

    const MCP_REQUESTS: &str = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"session-e2e","version":"1"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"opv_next","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"opv_state","arguments":{"section":"contract"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"opv_import_local","arguments":{"env":"dev","file":".env"}}}"#,
        "\n",
    );

    /// The answer to request `id`: the tool's document.
    fn mcp_answer(out: &str, id: u64) -> Value {
        let msg = out
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|m| m["id"] == id)
            .unwrap_or_else(|| panic!("no answer to {id}: {out}"));
        let text = msg
            .pointer("/result/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no tool text for {id}: {msg}"));
        serde_json::from_str(text).unwrap_or_else(|_| panic!("not a document: {text}"))
    }

    /// Channel 4: `opv mcp serve` started from the eval'd shell's environment holds no
    /// session (H4); started through the `opv` function it does, and still refuses a
    /// 1Password write, naming the variable and never its value.
    #[test]
    fn mcp_answers_hold_no_session_and_a_write_under_one_is_refused() {
        let lab = Lab::new(Mode::Token).with_mcp_requests();
        let t = lab.bash(
            "mcp",
            r#"eval "$(opv login --shell)"
command opv mcp serve --project "$R/project" < "$R/cases/mcp.in" > "$R/out/mcp-shell.out" 2> "$R/out/mcp-shell.err"; echo "shell=$?"
opv mcp serve --project "$R/project" < "$R/cases/mcp.in" > "$R/out/mcp-function.out" 2> "$R/out/mcp-function.err"; echo "function=$?""#,
        );
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        let shell = lab.out("mcp-shell.out");
        let function = lab.out("mcp-function.out");
        lab.out("mcp-shell.err");
        lab.out("mcp-function.err");
        // From the shell's environment: no credential in it, so no own-session refusal.
        let write = mcp_answer(&shell, 4);
        assert_ne!(write["error"]["code"], "own_session_required", "{write}");
        mcp_answer(&shell, 2);
        mcp_answer(&shell, 3);
        // Through the function: the session is there, and a write is refused naming it.
        let write = mcp_answer(&function, 4);
        assert_eq!(write["error"]["code"], "own_session_required", "{write}");
        assert!(write.to_string().contains(VAR), "{write}");
        let next = mcp_answer(&function, 2);
        assert_eq!(next["ok"], true, "{next}");
        mcp_answer(&function, 3);
        lab.finish(&[
            "typescript:mcp",
            "out/mcp-shell.out",
            "out/mcp-function.out",
            "out/mcp-function.err",
        ]);
    }

    // --- the scan itself ------------------------------------------------------------------

    /// The scan is not vacuous: a token written into any file under the root, or into a
    /// captured channel, fails it and names where.
    #[test]
    fn the_canary_scan_names_the_channel_of_a_leak() {
        let lab = Lab::new(Mode::Token);
        let t = lab.bash("scan", r#"eval "$(opv login --shell)"; echo "$__opv_session_UE2EDEVUSER000000000000001" > "$R/home/leak""#);
        assert_eq!(t.code, Some(0), "{}", t.typescript);
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lab.finish(&["typescript:scan"])
        }))
        .expect_err("the scan missed a leak");
        let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(msg.contains("file:home/leak"), "{msg}");
        let missing = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lab.finish(&["out/never-written"])
        }))
        .expect_err("the scan passed with an expected channel missing");
        let msg = missing
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default();
        assert!(msg.contains("out/never-written"), "{msg}");
    }
}
