//! Process hardening (design `docs/design/error-catalog.md` §9.2): the first statement of
//! `main`, for every command, separate from signal handling (`runner::signals`).
//!
//! A value opv holds in memory must not reach a core dump or another same-user process.
//! Every step is best effort: a failure never stops the command. Only the **soft**
//! `RLIMIT_CORE` is touched, so `opv run`'s child keeps its own core-dump behaviour.

/// Harden the process before anything else runs. Best effort; never fails.
pub fn harden() {
    #[cfg(target_os = "linux")]
    linux();
    #[cfg(target_os = "macos")]
    macos();
    #[cfg(windows)]
    windows();
}

/// Mark every descriptor above stdio close-on-exec, so a descriptor this process inherited
/// without `FD_CLOEXEC` (from `op run`, or whoever started it) does not reach a program it
/// starts. Nothing is closed: this process keeps every descriptor it uses, and stdin,
/// stdout and stderr still pass. Linux: `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`, falling
/// back to each entry of `/proc/self/fd` (kernels before 5.11); other Unix: each entry of
/// `/dev/fd`. Best effort; never fails. Windows handles are not inherited unless marked.
pub fn cloexec_inherited() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a plain syscall with integer arguments; it only sets flags.
        let r = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        };
        if r == 0 {
            return;
        }
        cloexec_listed("/proc/self/fd");
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    cloexec_listed("/dev/fd");
}

/// Set `FD_CLOEXEC` on each descriptor above 2 listed in `dir`.
#[cfg(unix)]
fn cloexec_listed(dir: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let fds: Vec<i32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    for fd in fds {
        // SAFETY: fcntl on a descriptor number; one that was closed meanwhile (the
        // listing's own) fails with EBADF, which is ignored.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
}

/// Linux: non-dumpable and a zero soft core limit (hard untouched).
#[cfg(target_os = "linux")]
fn linux() {
    // Stops core dumps through a pipe handler (systemd-coredump, apport, WSL's capture),
    // ptrace and /proc/<pid>/mem access by other same-user processes.
    // SAFETY: a plain prctl with integer arguments.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    soft_core_limit_zero();
}

/// macOS: a zero soft core limit (hard untouched) and `PT_DENY_ATTACH`.
#[cfg(target_os = "macos")]
fn macos() {
    soft_core_limit_zero();
    // Refuse a debugger attaching after this point.
    // SAFETY: a plain ptrace with a null address; the pid is ignored for PT_DENY_ATTACH.
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

/// Set only the soft core limit to 0, keeping the hard limit, so `opv run`'s child (and any
/// other child) inherits the host's own core-dump behaviour.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn soft_core_limit_zero() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid, initialised `rlimit`; a plain getrlimit/setrlimit pair.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) != 0 {
            return;
        }
        limit.rlim_cur = 0;
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

/// Windows: no critical-error or GPF dialogs, and no heap in a Windows Error Reporting
/// dump of this process.
#[cfg(windows)]
fn windows() {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    use windows_sys::Win32::System::ErrorReporting::{
        WER_FAULT_REPORTING_FLAG_NOHEAP, WerSetFlags,
    };
    // SAFETY: plain calls with integer flags; both are documented process-wide settings.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        // Documented opt-out (`WerSetFlags`) from heap/memory collection in a WER dump.
        WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    /// `harden` leaves `opv run`'s child its own core-dump behaviour: the soft limit is 0
    /// while the hard limit is untouched. Forked so `harden`'s process-wide effect cannot
    /// reach the test harness.
    #[test]
    fn harden_zeroes_the_soft_core_limit_and_keeps_the_hard_limit() {
        let mut before = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `before` is a valid, initialised `rlimit`.
        unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut before) };

        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid two-element array for `pipe`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        // SAFETY: the child only makes syscalls and writes to the pipe, so it is safe after
        // `fork`; it never returns into the test harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // Start from a non-zero soft limit so this test observes `harden` rather than
            // an inherited host setting.
            let mut start = before;
            start.rlim_cur = start.rlim_max;
            // SAFETY: a plain `setrlimit` with a valid struct.
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &start) };

            super::harden();

            let mut after = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            // SAFETY: `after` is a valid, initialised `rlimit`.
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut after) };
            let hardened = (after.rlim_cur == 0 && after.rlim_max == before.rlim_max) as u8;
            // SAFETY: one byte to the pipe read end's peer; nothing else runs in the child.
            unsafe {
                let _ = libc::write(
                    fds[1],
                    std::ptr::from_ref(&hardened).cast::<libc::c_void>(),
                    1,
                );
                libc::_exit(0);
            }
        }

        // SAFETY: the parent owns both ends of the pipe; the child does not race it here.
        let mut byte = 0u8;
        // SAFETY: `byte` is a valid one-byte buffer.
        unsafe {
            libc::close(fds[1]);
            libc::read(fds[0], std::ptr::from_mut(&mut byte).cast(), 1);
            libc::close(fds[0]);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        assert_eq!(
            byte, 1,
            "soft core limit 0 and hard limit {:?} preserved",
            before.rlim_max
        );
    }
}
