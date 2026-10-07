//! Subprocess seam for adapters (`op`, `flyctl`). Adapters depend on [`CommandRunner`], so
//! tests can substitute [`fake::FakeRunner`] and assert what was (and was not) passed.
//!
//! Contract (SR-3, SR-7): secret values go in `stdin` only, never in `args`; programs are
//! invoked directly, never through a shell. `env` is for configuration such as tokens.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

/// Result of a finished process. `stdout` may contain secret values, so `Debug` prints only
/// its length.
pub struct Output {
    /// Exit status; `-1` when the process was terminated by a signal.
    pub status: i32,
    pub stdout: Vec<u8>,
}

impl Output {
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 0,
            stdout: stdout.into(),
        }
    }

    pub fn failure(status: i32) -> Self {
        Self {
            status,
            stdout: Vec::new(),
        }
    }
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output")
            .field("status", &self.status)
            .field("stdout_len", &self.stdout.len())
            .finish()
    }
}

pub trait CommandRunner {
    /// Never pass secret values in `args`; they go in `stdin` only.
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        env: &[(&str, &str)],
    ) -> io::Result<Output>;
}

/// Runs real processes with `std::process::Command`. Child stderr is discarded because it
/// may echo values (SR-1); callers map a non-zero status to a typed error.
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
        env: &[(&str, &str)],
    ) -> io::Result<Output> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .envs(env.iter().copied())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn()?;
        let mut child_stdin = child.stdin.take();
        let mut child_stdout = child.stdout.take().expect("stdout is piped");

        // Write stdin on a scoped thread while reading stdout, so neither pipe can fill up
        // and deadlock; the borrowed input is never copied.
        let (write_res, read_res) = std::thread::scope(|s| {
            let writer = s.spawn(move || -> io::Result<()> {
                if let (Some(pipe), Some(data)) = (child_stdin.as_mut(), stdin) {
                    match pipe.write_all(data) {
                        // The child may exit without reading all input; that is its call.
                        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {}
                        other => other?,
                    }
                }
                drop(child_stdin); // close the pipe so the child sees EOF
                Ok(())
            });
            let mut out = Vec::new();
            let read_res = child_stdout.read_to_end(&mut out).map(|_| out);
            (writer.join().expect("stdin writer panicked"), read_res)
        });
        let status = child.wait()?;
        write_res?;
        Ok(Output {
            status: status.code().unwrap_or(-1),
            stdout: read_res?,
        })
    }
}

#[cfg(any(test, feature = "fake"))]
pub mod fake {
    //! Recording runner for tests. Enable with `--features fake` outside this crate.

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io;

    use super::{CommandRunner, Output};

    /// One recorded invocation. `Debug` shows argv but redacts stdin and env values.
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub stdin: Option<Vec<u8>>,
        pub env: Vec<(String, String)>,
    }

    impl std::fmt::Debug for Call {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let env: Vec<&str> = self.env.iter().map(|(k, _)| k.as_str()).collect();
            f.debug_struct("Call")
                .field("program", &self.program)
                .field("args", &self.args)
                .field("stdin_len", &self.stdin.as_ref().map(Vec::len))
                .field("env_names", &env)
                .finish()
        }
    }

    /// Returns queued responses in order and records every call.
    #[derive(Default)]
    pub struct FakeRunner {
        pub calls: RefCell<Vec<Call>>,
        pub responses: RefCell<VecDeque<io::Result<Output>>>,
    }

    impl FakeRunner {
        pub fn new(responses: impl IntoIterator<Item = Output>) -> Self {
            Self {
                calls: RefCell::default(),
                responses: RefCell::new(responses.into_iter().map(Ok).collect()),
            }
        }

        /// Queue a spawn failure, e.g. `NotFound` for a missing binary.
        pub fn push_io_error(&self, kind: io::ErrorKind) {
            self.responses
                .borrow_mut()
                .push_back(Err(io::Error::from(kind)));
        }

        /// True if `needle` occurs in any recorded program name or argument (SR-3 checks).
        pub fn argv_contains(&self, needle: &str) -> bool {
            self.calls
                .borrow()
                .iter()
                .any(|c| c.program.contains(needle) || c.args.iter().any(|a| a.contains(needle)))
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
            env: &[(&str, &str)],
        ) -> io::Result<Output> {
            self.calls.borrow_mut().push(Call {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                stdin: stdin.map(<[u8]>::to_vec),
                env: env
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            });
            match self.responses.borrow_mut().pop_front() {
                Some(r) => r,
                None => panic!("FakeRunner: no response queued for call to {program}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeRunner;
    use super::*;

    #[test]
    fn output_debug_hides_stdout() {
        let o = Output::success(b"{\"value\":\"sk-live-123\"}".to_vec());
        let d = format!("{o:?}");
        assert!(!d.contains("sk-live"), "{d}");
        assert!(d.contains("stdout_len"));
    }

    #[test]
    fn fake_records_calls_and_returns_responses_in_order() {
        let r = FakeRunner::new([Output::success("one"), Output::failure(7)]);
        let a = r
            .run(
                "op",
                &["item", "get"],
                Some(b"sk-live-123"),
                &[("OP_TOKEN", "tok-secret")],
            )
            .unwrap();
        assert_eq!((a.status, a.stdout.as_slice()), (0, &b"one"[..]));
        assert_eq!(
            r.run("flyctl", &["secrets", "list"], None, &[])
                .unwrap()
                .status,
            7
        );

        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, vec!["item", "get"]);
        assert_eq!(calls[0].stdin.as_deref(), Some(&b"sk-live-123"[..]));
        assert_eq!(calls[0].env, vec![("OP_TOKEN".into(), "tok-secret".into())]);
        let d = format!("{:?}", calls[0]);
        assert!(!d.contains("sk-live") && !d.contains("tok-secret"), "{d}");
        drop(calls);

        assert!(r.argv_contains("secrets"));
        assert!(!r.argv_contains("sk-live"), "stdin must not count as argv");
    }

    #[test]
    fn fake_can_simulate_spawn_failure() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = r.run("op", &["--version"], None, &[]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_pipes_stdin_to_stdout() {
        let o = ProcessRunner.run("cat", &[], Some(b"hello"), &[]).unwrap();
        assert_eq!(o.status, 0);
        assert_eq!(o.stdout, b"hello");
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_handles_large_stdin_without_deadlock() {
        let big = vec![b'x'; 4 * 1024 * 1024];
        let o = ProcessRunner.run("cat", &[], Some(&big), &[]).unwrap();
        assert_eq!(o.stdout.len(), big.len());
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_passes_env_and_reports_status_and_drops_stderr() {
        let o = ProcessRunner
            .run(
                "printenv",
                &["SECRETCTL_TEST_VAR"],
                None,
                &[("SECRETCTL_TEST_VAR", "v1")],
            )
            .unwrap();
        assert_eq!((o.status, o.stdout.as_slice()), (0, &b"v1\n"[..]));

        // A child that writes to stderr and fails: status propagated, stderr not captured.
        let o = ProcessRunner
            .run("sh", &["-c", "echo leaked-value >&2; exit 3"], None, &[])
            .unwrap();
        assert_eq!(o.status, 3);
        assert!(o.stdout.is_empty());
    }

    #[test]
    fn process_runner_missing_binary_is_io_error() {
        let e = ProcessRunner
            .run("secretctl-definitely-not-installed", &[], None, &[])
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
