//! The fake HTTPS attempt (design `http-target` §5).
//!
//! There is no separate code path here: under the `fake` feature, and only when
//! `OPV_SIM_WORLD` is set, the runner's HTTPS call is the `https` program spawned from
//! `PATH` like any other external call, so the fault matrix discovers and faults it too.
//! A release build has no fake attempt and never spawns a program named `https`; see
//! [`crate::runner_https`] and the process engine in [`crate::runner`].
//!
//! Selection happens in [`crate::runner`] (design §5): `ProcessRunner`'s `attempt` sends an
//! HTTPS call to [`crate::runner_https::real_attempt`] unless `https_fake_attempt` is true,
//! which requires the `fake` feature and `OPV_SIM_WORLD`. Only then does the call go through
//! the process engine and the `https` program on `PATH`. The tests below drive that
//! selection end to end through [`crate::runner::CommandRunner::https_read`], with an
//! `https` script that writes a known reply envelope ([`crate::runner_https::encode_reply`]).

mod tests {
    // The fake attempt is a script on `PATH`, which only a Unix-like system can exec here;
    // the e2e suite ships its own simulator for every other platform.
    #![cfg(all(test, feature = "fake"))]
    #![cfg(unix)]

    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    use zeroize::Zeroizing;

    use crate::domain::secret::SecretValue;
    use crate::runner::{CommandRunner, ProcessRunner};
    use crate::runner_https::{HttpsReply, HttpsRequest, encode_reply};

    /// The header value the fake `https` script must never see in its argv. A canary, so a
    /// leak in a test is harmless; the script records only `LEAK`/`CLEAN`, never this value.
    const CANARY_HEADER: &str = "CANARY-HTTPS-HEADER-VALUE";

    /// The reply body the fake `https` script writes, so a test can tell its reply from any
    /// other.
    const CANARY_REPLY: &[u8] = b"CANARY-HTTPS-REPLY";

    /// Serializes the tests that set the process environment. nextest runs each test in its
    /// own process, so the lock is uncontended there; it also keeps a plain `cargo test` run
    /// from letting two tests race on `PATH` and `OPV_SIM_WORLD`.
    static ENV: Mutex<()> = Mutex::new(());

    /// A reply envelope with obvious canaries in every field.
    fn scripted_reply() -> HttpsReply {
        HttpsReply {
            status: 200,
            content_type: Some("application/grpc-web+proto".to_string()),
            grpc_status: Some(0),
            grpc_message: Some("CANARY-HTTPS-GRPC-MESSAGE".to_string()),
            body: Zeroizing::new(CANARY_REPLY.to_vec()),
        }
    }

    /// A request whose header value is the canary the script's argv must never carry.
    fn request() -> HttpsRequest {
        HttpsRequest {
            method: "POST",
            uri: "central.zonetico.com/portal.v1.PlatformConsoleService/List".to_string(),
            headers: vec![(
                "authorization".to_string(),
                SecretValue::new(CANARY_HEADER.to_string()),
            )],
            body: Zeroizing::new(Vec::new()),
        }
    }

    /// Writes an executable `https` into `dir`: the script touches `ran`, records `CLEAN` or
    /// `LEAK` in `argv` (never the value itself) and prints `envelope` on stdout. That is the
    /// fake attempt the runner spawns from `PATH` under the `fake` feature and a sim world.
    fn write_https_script(dir: &Path, envelope: &[u8], argv: &Path, ran: &Path) {
        let envelope_path = dir.join("envelope.bin");
        fs::write(&envelope_path, envelope).expect("write the reply envelope");
        let script = format!(
            "#!/bin/sh\n\
             touch '{ran}'\n\
             case \"$*\" in\n\
             *{canary}*) printf 'LEAK' > '{argv}' ;;\n\
             *) printf 'CLEAN' > '{argv}' ;;\n\
             esac\n\
             cat '{envelope}'\n",
            ran = ran.display(),
            canary = CANARY_HEADER,
            argv = argv.display(),
            envelope = envelope_path.display(),
        );
        let path = dir.join("https");
        fs::write(&path, script).expect("write the https script");
        let mut perms = fs::metadata(&path)
            .expect("the script's mode")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("make the script executable");
    }

    /// `PATH` and `OPV_SIM_WORLD` for the duration of a test, restored on drop. Holding the
    /// lock keeps another test from seeing the change.
    struct SimEnv {
        _lock: MutexGuard<'static, ()>,
        path: Option<OsString>,
        sim: Option<OsString>,
    }

    impl SimEnv {
        /// Puts `dir` first on `PATH` and, when `world` is `Some`, points `OPV_SIM_WORLD` at
        /// it; when `None`, removes `OPV_SIM_WORLD` so the real attempt is selected.
        fn enter(dir: &Path, world: Option<&Path>) -> Self {
            let lock = ENV.lock().unwrap_or_else(|e| e.into_inner());
            let path = std::env::var_os("PATH");
            let sim = std::env::var_os("OPV_SIM_WORLD");
            let mut dirs = vec![dir.to_path_buf()];
            if let Some(rest) = &path {
                dirs.extend(std::env::split_paths(rest));
            }
            // SAFETY: the tests hold `ENV`, so no other test thread reads or writes the
            // process environment while the change is in force (nextest also gives each
            // test its own process).
            unsafe { std::env::set_var("PATH", std::env::join_paths(dirs).expect("join PATH")) };
            match world {
                Some(world) => unsafe { std::env::set_var("OPV_SIM_WORLD", world) },
                None => unsafe { std::env::remove_var("OPV_SIM_WORLD") },
            }
            Self {
                _lock: lock,
                path,
                sim,
            }
        }
    }

    impl Drop for SimEnv {
        fn drop(&mut self) {
            // SAFETY: as in `enter`, the lock is held until after these restores.
            unsafe {
                match &self.path {
                    Some(path) => std::env::set_var("PATH", path),
                    None => std::env::remove_var("PATH"),
                }
                match &self.sim {
                    Some(sim) => std::env::set_var("OPV_SIM_WORLD", sim),
                    None => std::env::remove_var("OPV_SIM_WORLD"),
                }
            }
        }
    }

    /// With a sim world and the fake `https` on `PATH`, the runner's HTTPS read is the
    /// script's reply envelope: the fake attempt, not the real one.
    #[test]
    fn https_read_returns_the_scripted_reply_under_a_sim_world() {
        let dir = tempfile::tempdir().expect("temp dir");
        let reply = scripted_reply();
        write_https_script(
            dir.path(),
            &encode_reply(&reply),
            &dir.path().join("argv"),
            &dir.path().join("ran"),
        );
        let _env = SimEnv::enter(dir.path(), Some(dir.path()));

        let got = ProcessRunner::default()
            .https_read(&request())
            .expect("the script's reply");

        assert_eq!(got.body.as_slice(), CANARY_REPLY);
    }

    /// The fake `https` script never receives the request's header value in argv; it reads
    /// the header pairs from the environment.
    #[test]
    fn the_https_script_sees_no_header_value_in_argv() {
        let dir = tempfile::tempdir().expect("temp dir");
        let argv = dir.path().join("argv");
        write_https_script(
            dir.path(),
            &encode_reply(&scripted_reply()),
            &argv,
            &dir.path().join("ran"),
        );
        let _env = SimEnv::enter(dir.path(), Some(dir.path()));

        let _ = ProcessRunner::default().https_read(&request());

        assert_eq!(
            fs::read_to_string(&argv).expect("the script's argv marker"),
            "CLEAN"
        );
    }

    /// Without a sim world the real attempt runs, so the fake `https` script is never
    /// started: its `ran` marker stays absent.
    #[test]
    fn the_https_script_is_not_run_without_a_sim_world() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ran = dir.path().join("ran");
        write_https_script(
            dir.path(),
            &encode_reply(&scripted_reply()),
            &dir.path().join("argv"),
            &ran,
        );
        let _env = SimEnv::enter(dir.path(), None);

        let _ = ProcessRunner::default().https_read(&request());

        assert!(!ran.exists(), "the fake script ran without a sim world");
    }

    /// Without a sim world the real attempt is selected and fails offline, as designed: no
    /// fake script, no reply.
    #[test]
    fn https_read_fails_offline_without_a_sim_world() {
        let dir = tempfile::tempdir().expect("temp dir");
        write_https_script(
            dir.path(),
            &encode_reply(&scripted_reply()),
            &dir.path().join("argv"),
            &dir.path().join("ran"),
        );
        let _env = SimEnv::enter(dir.path(), None);

        let result = ProcessRunner::default().https_read(&request());

        assert!(result.is_err(), "the real attempt should fail offline");
    }
}
