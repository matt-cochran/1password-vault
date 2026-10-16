//! The single-use, short-lived local record of a person's terminal approval of one
//! structural plan (#133).
//!
//! A record proves that a person at *this* terminal reviewed this exact plan for this
//! project and 1Password account, and nothing more. It is a local gate, not a
//! cryptographic signature: an agent with shell access as the same OS user could forge a
//! file. The binding control remains the 1Password app's own authorization prompt on every
//! write, which an approval cannot bypass.

use std::path::{Path, PathBuf};

use crate::cause::{
    Cause, EnvName, IoKind, KeyName, PlanId, PlanScope, ProductKey, ProductName, TargetName,
    UsageProblem,
};
use crate::error::Error;

/// How long a recorded approval stays usable: fifteen minutes from `now`.
pub const TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// One approval: which plan, for which project and 1Password account, until when (unix
/// seconds).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Approval {
    pub plan_id: String,
    /// What the approval covers beyond the plan id (0.9.0): empty for a structural plan,
    /// else e.g. `sync prod targets=web product=- deploy prune`. It must match exactly when
    /// the approval is used, so an approval never stretches to another scope or flag.
    #[serde(default)]
    pub scope: String,
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
    // Neither XDG_STATE_HOME nor HOME: there is no private folder to keep approvals in.
    let home = std::env::var_os("HOME").ok_or_else(|| -> Error {
        Cause::PrivateDirFailed {
            dir: PathBuf::from("$HOME/.local/state/opv/approvals"),
            io: IoKind::NotFound,
        }
        .into()
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
    record_scoped_in(dir, plan_id, "", project, account, now)
}

/// [`record_in`] for an approval that covers `scope` too (a sync plan's environment,
/// targets, product and flags).
pub fn record_scoped_in(
    dir: &Path,
    plan_id: &str,
    scope: &str,
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
        scope: scope.to_string(),
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
    consume_scoped_in(dir, plan_id, "", project, account, now)
}

/// [`consume_in`] for an approval of `scope`, which must equal the recorded scope exactly.
pub fn consume_scoped_in(
    dir: &Path,
    plan_id: &str,
    scope: &str,
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
        // Used (or being used): it never applies again, and the read of what remains is the
        // next step, never the approval (X4).
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Cause::ApprovalUsed {
                plan: PlanId::new(plan_id),
                scope: plan_scope(scope),
                partial: false,
            }
            .into());
        }
        Err(e) => return Err(dir_refusal(dir, &e)),
    }
    let outcome = match std::fs::symlink_metadata(&source) {
        Ok(m) if m.file_type().is_file() => {
            read_claimed(&source, plan_id, scope, project, account, now)
        }
        Ok(_) => Err(refusal(plan_id, scope)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(refusal(plan_id, scope)),
        Err(e) => Err(dir_refusal(dir, &e)),
    };
    // The record is spent whatever the verdict; the claim file stays, so the same id can
    // never be claimed again until a new approval replaces it.
    let _ = std::fs::remove_file(&source);
    outcome
}

/// [`record_scoped_in`] in [`dir`].
pub fn record_scoped(
    plan_id: &str,
    scope: &str,
    project: &str,
    account: &str,
    now: u64,
) -> Result<(), Error> {
    record_scoped_in(&dir()?, plan_id, scope, project, account, now)
}

/// [`consume_scoped_in`] in [`dir`].
pub fn consume_scoped(
    plan_id: &str,
    scope: &str,
    project: &str,
    account: &str,
    now: u64,
) -> Result<(), Error> {
    consume_scoped_in(&dir()?, plan_id, scope, project, account, now)
}

/// [`record_in`] in [`dir`].
pub fn record(plan_id: &str, project: &str, account: &str, now: u64) -> Result<(), Error> {
    record_in(&dir()?, plan_id, project, account, now)
}

/// [`consume_in`] in [`dir`].
pub fn consume(plan_id: &str, project: &str, account: &str, now: u64) -> Result<(), Error> {
    consume_in(&dir()?, plan_id, project, account, now)
}

/// A plan id is `sp-` and sixteen lowercase hex digits (structural), or eight lowercase hex
/// digits (sync).
fn validate_plan_id(plan_id: &str) -> Result<(), Error> {
    if crate::app::structure::is_plan_id(plan_id) || is_sync_id(plan_id) {
        Ok(())
    } else {
        Err(Cause::Usage {
            problem: UsageProblem::ValueFormat {
                flag: "the plan id".into(),
                format: PLAN_ID_FORMAT,
            },
        }
        .into())
    }
}

/// Both plan id forms, in words (05.36).
pub const PLAN_ID_FORMAT: &str = "sp- and 16 hex digits (structural) or 8 hex digits (sync)";

/// True for a sync plan id: eight lowercase hex digits.
pub fn is_sync_id(plan_id: &str) -> bool {
    plan_id.len() == crate::domain::provenance::PLAN_ID_LEN
        && plan_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The typed scope of an approval's scope key: empty is a structural plan, else the sync
/// key [`crate::app::approve::SyncScope::key`] writes, so a refusal's step carries every
/// scope flag the approval was made with (X1).
pub fn plan_scope(key: &str) -> PlanScope {
    let mut words = key.split(' ').filter(|w| !w.is_empty());
    if words.next() != Some("sync") {
        return PlanScope::Structural;
    }
    let mut scope = PlanScope::Sync {
        env: EnvName::new(words.next().unwrap_or_default()),
        targets: Vec::new(),
        product: None,
        deploy: false,
        prune: false,
        rotate: Vec::new(),
    };
    let PlanScope::Sync {
        targets,
        product,
        deploy,
        prune,
        rotate,
        ..
    } = &mut scope
    else {
        unreachable!("built as a sync scope above")
    };
    for w in words {
        match w.split_once('=') {
            Some(("targets", "*")) | Some(("product", "*")) => {}
            Some(("targets", list)) => targets.extend(list.split(',').map(TargetName::new)),
            Some(("product", p)) => *product = Some(ProductName::new(p)),
            Some(("rotate", list)) => rotate.extend(list.split(',').filter_map(|k| {
                k.split_once('/').map(|(p, k)| ProductKey {
                    product: ProductName::new(p),
                    key: KeyName::new(k),
                })
            })),
            _ if w == "deploy" => *deploy = true,
            _ if w == "prune" => *prune = true,
            _ => {}
        }
    }
    scope
}

/// A consume refusal: the plan is not approved (no usable record), so a person approves it,
/// with every scope flag (`approval_required`).
fn refusal(plan_id: &str, scope: &str) -> Error {
    Cause::ApprovalMissing {
        plan: PlanId::new(plan_id),
        scope: plan_scope(scope),
    }
    .into()
}

/// The approvals directory cannot be used.
fn dir_refusal(path: &Path, e: &std::io::Error) -> Error {
    Cause::PrivateDirFailed {
        dir: path.to_path_buf(),
        io: e.kind().into(),
    }
    .into()
}

/// Create `dir` (and parents) if it does not exist; otherwise refuse a symlink, a
/// non-directory, or, on unix, a directory not owned by the current user or accessible by
/// group/others.
fn ensure_dir(dir: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => check_dir(dir, &meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_private_dir(dir)?;
            let meta = std::fs::symlink_metadata(dir).map_err(|e| dir_refusal(dir, &e))?;
            check_dir(dir, &meta)
        }
        Err(e) => Err(dir_refusal(dir, &e)),
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
    builder.create(dir).map_err(|e| dir_refusal(dir, &e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| dir_refusal(dir, &e))?;
    }
    Ok(())
}

fn check_dir(dir: &Path, meta: &std::fs::Metadata) -> Result<(), Error> {
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(Cause::PrivateDirFailed {
            dir: dir.to_path_buf(),
            io: IoKind::Other,
        }
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(Cause::PrivateDirFailed {
                dir: dir.to_path_buf(),
                io: IoKind::PermissionDenied,
            }
            .into());
        }
        if meta.mode() & 0o077 != 0 {
            // 05.36: the fix is the mode, and the step says it (chmod 700).
            return Err(Cause::LocalFileTooOpen {
                path: dir.to_path_buf(),
                mode: meta.mode() & 0o777,
                want: 0o700,
            }
            .into());
        }
    }
    Ok(())
}

/// Write `approval` to a `0600` temp file in `dir`, then rename it into place over any
/// earlier record. `O_NOFOLLOW | O_CREAT | O_EXCL` on unix.
/// Whether `plan_id` was ever approved here: an approval is recorded for it, or one was
/// claimed (used). Names only; nothing is read or changed (C2: an id never approved is
/// `PlanUnknown`, not a plan that changed since its approval).
pub fn ever_approved(plan_id: &str) -> bool {
    validate_plan_id(plan_id).is_ok()
        && dir().is_ok_and(|d| {
            d.join(format!("{plan_id}.json")).exists()
                || d.join(format!("{plan_id}.claim")).exists()
        })
}

fn write_record(dir: &Path, approval: &Approval) -> Result<(), Error> {
    let text = serde_json::to_string(approval).map_err(|_| -> Error {
        Cause::Bug {
            site: "approval: a fixed record failed to encode",
        }
        .into()
    })?;
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
        return Err(dir_refusal(dir, &e));
    }
    let dest = dir.join(format!("{}.json", approval.plan_id));
    if let Err(e) = replace(&tmp, &dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(dir_refusal(dir, &e));
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
    scope: &str,
    project: &str,
    account: &str,
    now: u64,
) -> Result<(), Error> {
    // Unreadable, malformed, another plan or scope, expired, another project or account:
    // this plan is not approved here, and a person approves it again.
    let refused = || refusal(plan_id, scope);
    let bytes = std::fs::read(path).map_err(|_| refused())?;
    let approval: Approval = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    if approval.plan_id != plan_id {
        return Err(refused());
    }
    if approval.scope != scope {
        return Err(refused());
    }
    if approval.expires_at <= now {
        return Err(refused());
    }
    if approval.project != project {
        return Err(refused());
    }
    if approval.account != account {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
