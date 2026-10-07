//! Subprocess seam for adapters (`op`, `flyctl`). Adapters depend on [`CommandRunner`], so
//! tests can substitute [`fake::FakeRunner`] and assert what was (and was not) passed.
//!
//! Contract (SR-3, SR-7): secret values go in `stdin` only, never in `args`; programs are
//! invoked directly, never through a shell. `env` is for configuration such as tokens.

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};

use zeroize::{Zeroize, Zeroizing};

/// Result of a finished process. `stdout` may contain secret values, so it is zeroized on
/// drop (SR-8) and `Debug` prints only its length.
pub struct Output {
    /// Exit status; `-1` when the process was terminated by a signal.
    pub status: i32,
    pub stdout: Zeroizing<Vec<u8>>,
}

impl Output {
    pub fn success(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 0,
            stdout: Zeroizing::new(stdout.into()),
        }
    }

    pub fn failure(status: i32) -> Self {
        Self {
            status,
            stdout: Zeroizing::new(Vec::new()),
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

    /// Run `program` with inherited stdin/stdout/stderr and the given extra `env`, wait, and
    /// return its exit code (`128 + signal` if it was killed by a signal). Used by `run`
    /// (FR-4) to spawn `op run -- <cmd>`. Same contract: no secret values in `args`.
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32>;
}

fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    status.code().unwrap_or(-1)
}

/// Read to EOF into a buffer that is zeroized on drop. Growth copies into a fresh
/// `Zeroizing` allocation, so no unzeroized copy of the data is left behind by `realloc`.
fn read_to_end_zeroizing(mut r: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(8 * 1024));
    let mut chunk = [0u8; 8 * 1024];
    let res = loop {
        match r.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if out.len() + n > out.capacity() {
                    let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + n) * 2));
                    bigger.extend_from_slice(&out);
                    out = bigger;
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    chunk.zeroize();
    res.map(|()| out)
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
            let read_res = read_to_end_zeroizing(&mut child_stdout);
            (writer.join().expect("stdin writer panicked"), read_res)
        });
        let status = child.wait()?;
        write_res?;
        Ok(Output {
            status: exit_code(status),
            stdout: read_res?,
        })
    }

    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        let status = Command::new(program)
            .args(args)
            .envs(env.iter().copied())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        Ok(exit_code(status))
    }
}

#[cfg(any(test, feature = "fake"))]
pub mod fake {
    //! Recording runner for tests. Enable with `--features fake` outside this crate.

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::io;

    use super::{CommandRunner, Output};

    /// One recorded invocation, including env names and values so tests can assert what
    /// reached env versus argv. `Debug` shows argv but redacts stdin and env values.
    pub struct Call {
        pub program: String,
        pub args: Vec<String>,
        pub stdin: Option<Vec<u8>>,
        pub env: Vec<(String, String)>,
        /// True for `run_inherited` calls.
        pub inherited: bool,
    }

    impl std::fmt::Debug for Call {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let env: Vec<&str> = self.env.iter().map(|(k, _)| k.as_str()).collect();
            f.debug_struct("Call")
                .field("program", &self.program)
                .field("args", &self.args)
                .field("stdin_len", &self.stdin.as_ref().map(Vec::len))
                .field("env_names", &env)
                .field("inherited", &self.inherited)
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

        fn record(
            &self,
            program: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
            env: &[(&str, &str)],
            inherited: bool,
        ) -> io::Result<Output> {
            self.calls.borrow_mut().push(Call {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
                stdin: stdin.map(<[u8]>::to_vec),
                env: env
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                inherited,
            });
            match self.responses.borrow_mut().pop_front() {
                Some(r) => r,
                None => panic!("FakeRunner: no response queued for call to {program}"),
            }
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
            self.record(program, args, stdin, env, false)
        }

        /// Returns the queued response's `status` as the exit code.
        fn run_inherited(
            &self,
            program: &str,
            args: &[&str],
            env: &[(&str, &str)],
        ) -> io::Result<i32> {
            self.record(program, args, None, env, true)
                .map(|o| o.status)
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
        assert_eq!(o.stdout.as_slice(), b"hello");
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
    fn read_to_end_zeroizing_reads_across_growth() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let out = read_to_end_zeroizing(&data[..]).unwrap();
        assert_eq!(out.as_slice(), data.as_slice());
        assert!(read_to_end_zeroizing(&b""[..]).unwrap().is_empty());
    }

    #[test]
    fn fake_run_inherited_records_env_values_and_returns_status() {
        let r = FakeRunner::new([Output::failure(9)]);
        let code = r
            .run_inherited(
                "op",
                &["run", "--", "server"],
                &[("OPENAI_API_KEY", "op://vprd/iprd/allumata/OPENAI_API_KEY")],
            )
            .unwrap();
        assert_eq!(code, 9);
        let calls = r.calls.borrow();
        assert!(calls[0].inherited && calls[0].stdin.is_none());
        assert_eq!(calls[0].args, vec!["run", "--", "server"]);
        assert_eq!(
            calls[0].env,
            vec![(
                "OPENAI_API_KEY".to_string(),
                "op://vprd/iprd/allumata/OPENAI_API_KEY".to_string()
            )]
        );
        assert!(!format!("{:?}", calls[0]).contains("op://"));
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_run_inherited_returns_exit_code_and_applies_env() {
        let code = ProcessRunner
            .run_inherited("sh", &["-c", "exit 5"], &[])
            .unwrap();
        assert_eq!(code, 5);
        let code = ProcessRunner
            .run_inherited(
                "sh",
                &["-c", "test \"$SECRETCTL_TEST_VAR\" = v2"],
                &[("SECRETCTL_TEST_VAR", "v2")],
            )
            .unwrap();
        assert_eq!(code, 0);
        let code = ProcessRunner
            .run_inherited("sh", &["-c", "kill -TERM $$"], &[])
            .unwrap();
        assert_eq!(code, 128 + 15);
    }

    #[test]
    fn process_runner_run_inherited_missing_binary_is_io_error() {
        let e = ProcessRunner
            .run_inherited("secretctl-definitely-not-installed", &[], &[])
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn process_runner_missing_binary_is_io_error() {
        let e = ProcessRunner
            .run("secretctl-definitely-not-installed", &[], None, &[])
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }
}
