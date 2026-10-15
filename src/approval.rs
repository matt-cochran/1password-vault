//! The single-use, short-lived local record of a person's terminal approval of one
//! structural plan (#133).
//!
//! A record proves that a person at *this* terminal reviewed this exact plan for this
//! project and 1Password account, and nothing more. It is a local gate, not a
//! cryptographic signature: an agent with shell access as the same OS user could forge a
//! file. The binding control remains the 1Password app's own authorization prompt on every
//! write, which an approval cannot bypass.

use std::path::{Path, PathBuf};

use crate::error::{Code, Error};

/// How long a recorded approval stays usable: fifteen minutes from `now`.
pub const TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// One approval: which plan, for which project and 1Password account, until when (unix
/// seconds).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Approval {
    pub plan_id: String,
    pub project: String,
    pub account: String,
    pub expires_at: u64,
}

/// The directory approvals live in: `$XDG_STATE_HOME/opv/approvals`, else
/// `$HOME/.local/state/opv/approvals`; on Windows `%LOCALAPPDATA%\opv\approvals`. No
/// variable of opv's own moves it, so whoever configures the MCP server cannot point it at
/// a directory of their making.
pub fn dir() -> Result<PathBuf, Error> {
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local).join("opv").join("approvals"));
        }
    }
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(state).join("opv").join("approvals"));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::Config(
            "cannot locate the approvals directory: neither XDG_STATE_HOME nor HOME is set".into(),
        )
    })?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("opv")
        .join("approvals"))
}

/// Record an approval in `dir`, expiring at `now + TTL`. Replaces any earlier unused
/// approval for the same `plan_id`.
pub fn record_in(
    dir: &Path,
    plan_id: &str,
    project: &str,
    account: &str,
    now: u64,
) -> Result<(), Error> {
    validate_plan_id(plan_id)?;
    ensure_dir(dir)?;
    // A new approval of this plan replaces any earlier one, used or not.
    let _ = std::fs::remove_file(dir.join(format!("{plan_id}.claim")));
    let approval = Approval {
        plan_id: plan_id.to_string(),
        project: project.to_string(),
        account: account.to_string(),
        expires_at: now.saturating_add(TTL.as_secs()),
    };
    write_record(dir, &approval)
}

/// Use up the approval for `plan_id`: `Ok` only when one exists in `dir`, is unused,
/// unexpired (`now < expires_at`), and its project and account equal the given ones.
///
/// The claim is an exclusive create of `<plan_id>.claim` (`O_CREAT|O_EXCL`, `CREATE_NEW` on
/// Windows), which has exactly one winner on every platform, even for concurrent claims in
/// one process. Only the winner reads the record, and it removes the record whatever the
/// verdict, so a refused or used approval is never usable again. A claim file left by a
/// crash keeps the approval unusable (fail closed) until a person approves again
/// ([`record_in`] clears it).
pub fn consume_in(
    dir: &Path,
    plan_id: &str,
    project: &str,
    account: &str,
    now: u64,
) -> Result<(), Error> {
    validate_plan_id(plan_id)?;
    ensure_dir(dir)?;
    let source = dir.join(format!("{plan_id}.json"));
    let lock = dir.join(format!("{plan_id}.claim"));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    match opts.open(&lock) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(refusal(plan_id, "already used or being used"));
        }
        Err(e) => return Err(refusal(plan_id, format_args!("cannot claim record: {e}"))),
    }
    let outcome = match std::fs::symlink_metadata(&source) {
        Ok(m) if m.file_type().is_file() => read_claimed(&source, plan_id, project, account, now),
        Ok(_) => Err(refusal(plan_id, "malformed record")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(refusal(plan_id, "no approval recorded"))
        }
        Err(e) => Err(refusal(plan_id, format_args!("cannot read record: {e}"))),
    };
    // The record is spent whatever the verdict; the claim file stays, so the same id can
    // never be claimed again until a new approval replaces it.
    let _ = std::fs::remove_file(&source);
    outcome
}

/// [`record_in`] in [`dir`].
pub fn record(plan_id: &str, project: &str, account: &str, now: u64) -> Result<(), Error> {
    record_in(&dir()?, plan_id, project, account, now)
}

/// [`consume_in`] in [`dir`].
pub fn consume(plan_id: &str, project: &str, account: &str, now: u64) -> Result<(), Error> {
    consume_in(&dir()?, plan_id, project, account, now)
}

/// A plan id is `sp-` followed by exactly sixteen lowercase hex digits.
fn validate_plan_id(plan_id: &str) -> Result<(), Error> {
    if crate::app::structure::is_plan_id(plan_id) {
        Ok(())
    } else {
        Err(Error::Config(
            format!("not a plan id: {plan_id} (want sp- followed by 16 lowercase hex digits)")
                .into(),
        )
        .with_code(Code::Usage))
    }
}

/// A consume refusal: `approval_required`, with the command a person runs to approve.
fn refusal(plan_id: &str, why: impl std::fmt::Display) -> Error {
    Error::Policy(format!("no usable approval for plan {plan_id}: {why}").into())
        .with_code(Code::ApprovalRequired)
        .with_next(format!("opv approve {plan_id}"))
}

/// A record or directory refusal: `policy_refused`.
fn dir_refusal(path: &Path, why: impl std::fmt::Display) -> Error {
    Error::Policy(format!("cannot use approvals directory {}: {why}", path.display()).into())
        .with_code(Code::PolicyRefused)
}

/// Create `dir` (and parents) if it does not exist; otherwise refuse a symlink, a
/// non-directory, or, on unix, a directory not owned by the current user or accessible by
/// group/others.
fn ensure_dir(dir: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => check_dir(dir, &meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(dir)?;
            let meta = std::fs::symlink_metadata(dir).map_err(|e| dir_refusal(dir, e))?;
            check_dir(dir, &meta)
        }
        Err(e) => Err(dir_refusal(dir, e)),
    }
}

fn create_private_dir(dir: &Path) -> Result<(), Error> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| dir_refusal(dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| dir_refusal(dir, e))?;
    }
    Ok(())
}

fn check_dir(dir: &Path, meta: &std::fs::Metadata) -> Result<(), Error> {
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(dir_refusal(dir, "it is a symlink or not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(dir_refusal(dir, "it is not owned by the current user"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(dir_refusal(dir, "it is accessible by group or others"));
        }
    }
    Ok(())
}

/// Write `approval` to a `0600` temp file in `dir`, then rename it into place over any
/// earlier record. `O_NOFOLLOW | O_CREAT | O_EXCL` on unix.
fn write_record(dir: &Path, approval: &Approval) -> Result<(), Error> {
    let text = serde_json::to_string(approval)
        .map_err(|e| dir_refusal(dir, format_args!("cannot encode the record: {e}")))?;
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        approval.plan_id,
        std::process::id(),
        temp_seq()
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let written = opts.open(&tmp).and_then(|mut file| {
        use std::io::Write as _;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(dir_refusal(
            dir,
            format_args!("cannot write the record: {e}"),
        ));
    }
    let dest = dir.join(format!("{}.json", approval.plan_id));
    if let Err(e) = replace(&tmp, &dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(dir_refusal(
            dir,
            format_args!("cannot place the record: {e}"),
        ));
    }
    Ok(())
}

/// Rename `from` over `to`. Unix `rename` replaces atomically; Windows needs the
/// destination removed first.
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match std::fs::remove_file(to) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    std::fs::rename(from, to)
}

fn temp_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Read a claimed file and enforce every condition; the caller removes it afterwards.
fn read_claimed(
    path: &Path,
    plan_id: &str,
    project: &str,
    account: &str,
    now: u64,
) -> Result<(), Error> {
    let bytes = std::fs::read(path)
        .map_err(|e| refusal(plan_id, format_args!("cannot read record: {e}")))?;
    let approval: Approval =
        serde_json::from_slice(&bytes).map_err(|_| refusal(plan_id, "malformed record"))?;
    if approval.plan_id != plan_id {
        return Err(refusal(plan_id, "record names another plan"));
    }
    if approval.expires_at <= now {
        return Err(refusal(plan_id, "expired"));
    }
    if approval.project != project {
        return Err(refusal(plan_id, "recorded for another project"));
    }
    if approval.account != account {
        return Err(refusal(plan_id, "recorded for another account"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
