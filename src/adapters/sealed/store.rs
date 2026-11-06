//! The sealed target's store (design `sealed-target` §5.2 to §5.6, §8.1, §8.3; FMECA T3, T4,
//! T10, R7): one signed, encrypted bundle per product at `sealed.out`.
//!
//! - **Whole set.** [`SealedStore::whole_set`] is true: each write carries every desired,
//!   delivered name of the run's scope and replaces the bundle; [`SealedStore::remove`] is
//!   never called and is `Bug`.
//! - **Listing.** `list` reads each product's bundle locally and verifies its SSHSIG against
//!   `sealed.signer` before trusting anything in its header. A verified bundle lists its
//!   names at `r<revision>.<16 hex of sha256(file)>`, a digest of ciphertext under a random
//!   file key, never of a value. A bundle whose contract digest differs from the
//!   configuration's (recipients, signer, destinations) lists every name at a version that
//!   cannot match the ledger, so the whole bundle is re-sealed (C8); preflight prints one
//!   line with the reason. A bundle signed by another key is drift (`foreign.<hex>`) and never
//!   sets the revision (T10); a tampered one (unparseable, or a bad signature of
//!   `sealed.signer`'s key) refuses. An absent bundle lists nothing; one that cannot be read
//!   lists its configured names at `unreadable`. `sync` runs the same verification
//!   ([`StagedStore::check_local`]) when it opens the target, before it reads any value from
//!   1Password, so a tampered bundle costs no values read.
//! - **Writing.** The header is built here (placement, revision, signer and recipient
//!   fingerprints, contract digest, opv version, plan id), sealed and signed by the runner's
//!   seal effect, and written atomically under an OS advisory lock on a file beside the bundle (released when its holder dies): a
//!   temporary file in the same directory, `fsync`, `rename`, `fsync` of the directory (§5.6).
//!   `revision = max(previous + 1, now)` in Unix seconds, `previous` from a verified header
//!   only (§5.4, D5: no ratchet file).
//!
//! No value is ever logged, listed or put in an error (SR-3).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use super::config::SealedTarget;
use super::provider::LABEL;
use crate::bundle::allowed_signers::AllowedSigners;
use crate::bundle::crypto::{self, CryptoError, SignatureRefusal};
use crate::bundle::format::{self, FORMAT, Header, MAX_NAMES, MAX_VALUE, NAMESPACE, Name};
use crate::cause::{Cause, FieldRule, InputKind, IoKind, LocalOp};
use crate::domain::{SecretValue, StoreEntry};
use crate::error::Error;
use crate::ports::{StagedRuntime, StagedStore, Store, VariableStore, WriteRun};
use crate::provider::{Check, PlacedProduct, Verdict};
use crate::runner::{CommandRunner, SealCall, SealFailure};

/// The rule a value over the bundle's per-value limit breaks (§5.3).
pub const VALUE_TOO_LARGE: &str = "sealed_value_too_large";
/// The rule a file key whose path breaks the bundle's path rule breaks (§5.2, T6).
pub const PATH_RULE: &str = "sealed_file_path";
/// The version suffix of a bundle that is stale as a whole (§5.3, C8).
const STALE: &str = ".stale";

/// The sealed target's whole-set store over `target`'s bundles.
pub struct SealedStore<'a> {
    target: &'a SealedTarget,
    env: &'a str,
    r: &'a dyn CommandRunner,
    /// The current time in Unix seconds (a seam for the revision tests).
    now: fn() -> u64,
}

/// What `sealed.out` holds for one product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Found {
    Absent,
    /// The file exists but could not be read.
    Unreadable,
    /// Signed by `sealed.signer` for this environment and product.
    Ours {
        header: Box<Header>,
        /// `r<revision>.<16 hex>`.
        version: String,
        /// Why the bundle is stale as a whole; empty when it is current.
        stale: Vec<&'static str>,
    },
    /// Signed by another key, or for another placement: drift, never trusted.
    Foreign {
        version: String,
    },
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn bug(site: &'static str) -> Error {
    Cause::Bug { site }.into()
}

fn local_io(op: LocalOp, path: &Path, e: &std::io::Error) -> Error {
    Cause::LocalIo {
        op,
        path: path.to_path_buf(),
        io: e.kind().into(),
        delivery: None,
    }
    .into()
}

/// A bundle at `path` that opv can neither trust nor replace blindly: unparseable, or
/// signed with `sealed.signer`'s key but not over these bytes (T8, T10). Names the rule,
/// never a byte.
fn tampered(path: &Path, why: String) -> Error {
    Cause::InputInvalid {
        path: path.to_path_buf(),
        kind: InputKind::SealedBundle,
        at: None,
        field: format!("its content ({why})"),
        rule: FieldRule::Type {
            expected: "an unchanged opv-sealed/1 bundle signed by sealed.signer (mark *.opv-sealed binary in .gitattributes, or delete the file and sync again)",
        },
    }
    .into()
}

/// The 16 hex digits of sha256 over `bytes` that identify one bundle file.
fn file_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))[..16].to_string()
}

/// `name`'s destination in a bundle: `file:<path>` for a file key, else `env:<name>`.
fn destination(name: &str, file: Option<&String>) -> String {
    match file {
        Some(path) => format!("file:{path}"),
        None => format!("env:{name}"),
    }
}

/// `secrets_dir_env` for a bundle of `names`: the product's, when a name is a file (§5.2).
fn secrets_dir_env(names: &[Name], placed: Option<&PlacedProduct>) -> Option<String> {
    names
        .iter()
        .any(|n| n.destination.starts_with("file:"))
        .then(|| placed.and_then(|p| p.secrets_dir_env.clone()))
        .flatten()
}

impl SealedTarget {
    /// The recipients' fingerprints, sorted as a header holds them.
    fn sorted_recipients(&self) -> Vec<String> {
        let mut fps = self.recipient_fingerprints.clone();
        fps.sort();
        fps
    }

    /// The configuration's contract digest for a bundle that holds `names`, each at the
    /// destination the configuration gives it now (§5.2, C8). The name set itself is the
    /// plan's: a name added or removed is staged or pruned.
    fn expected_contract(&self, product: &str, names: &[Name]) -> (Vec<Name>, Option<String>) {
        let placed = self.placement.products.get(product);
        let names: Vec<Name> = names
            .iter()
            .map(|n| Name {
                name: n.name.clone(),
                destination: match placed.and_then(|p| p.names.get(&n.name)) {
                    Some(file) => destination(&n.name, file.as_ref()),
                    None => n.destination.clone(),
                },
            })
            .collect();
        let sde = secrets_dir_env(&names, placed);
        (names, sde)
    }

    /// Why `header` is stale as a whole against the configuration; empty when current.
    fn stale_reasons(&self, header: &Header) -> Vec<&'static str> {
        let recipients = self.sorted_recipients();
        let (names, sde) = self.expected_contract(&header.product, &header.names);
        let expected = format::contract_digest(
            &names,
            sde.as_deref(),
            &recipients,
            &self.signer_fingerprint,
        );
        if expected == header.contract_digest {
            return Vec::new();
        }
        let mut why = Vec::new();
        if header.recipients != recipients {
            why.push("recipients changed");
        }
        if header.signer != self.signer_fingerprint {
            why.push("signer changed");
        }
        if names != header.names || sde != header.secrets_dir_env {
            why.push("names changed");
        }
        if why.is_empty() {
            why.push("contract changed");
        }
        why
    }

    /// The `allowed_signers` of this target: `sealed.signer` for the environment only.
    fn signers(&self, env: &str) -> Result<AllowedSigners, Error> {
        let line = format!("{env} namespaces=\"{NAMESPACE}\" {}\n", self.signer_key);
        AllowedSigners::parse(line.as_bytes())
            .map_err(|_| bug("sealed: sealed.signer does not form an allowed_signers line"))
    }

    /// Read and verify `product`'s bundle (T10, R7).
    pub(super) fn found(&self, env: &str, product: &str) -> Result<Found, Error> {
        let path = self.written_path(product);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Found::Absent),
            Err(_) => return Ok(Found::Unreadable),
        };
        let digest = file_digest(&bytes);
        let envelope =
            format::parse_envelope(&bytes).map_err(|e| tampered(&path, e.to_string()))?;
        let header = envelope.header;
        let foreign = || {
            Ok(Found::Foreign {
                version: format!("foreign.{digest}"),
            })
        };
        let key = match crypto::verify(
            &self.signers(env)?,
            &header.environment,
            &envelope.signed,
            &envelope.signature,
        ) {
            Ok(key) => key,
            Err(SignatureRefusal::NotListed { .. } | SignatureRefusal::OtherPrincipal { .. }) => {
                return foreign();
            }
            Err(why) => return Err(tampered(&path, why.to_string())),
        };
        if crypto::signer_fingerprint(&key) != header.signer {
            return Err(tampered(
                &path,
                SignatureRefusal::SignerMismatch.to_string(),
            ));
        }
        if header.environment != env || header.product != product {
            return foreign();
        }
        let stale = self.stale_reasons(&header);
        let mut version = format!("r{}.{digest}", header.revision);
        if !stale.is_empty() {
            version.push_str(STALE);
        }
        Ok(Found::Ours {
            header: Box::new(header),
            version,
            stale,
        })
    }
}

/// The preflight lines of `target` (§5.3, C8): one warning per bundle that is stale as a
/// whole, naming the reason. A tampered bundle refuses.
pub fn stale_checks(target: &SealedTarget) -> Result<Vec<Check>, Error> {
    let mut checks = Vec::new();
    for product in target.placement.products.keys() {
        if let Found::Ours { stale, .. } = target.found(&target.env, product)?
            && !stale.is_empty()
        {
            checks.push(Check {
                name: format!("{LABEL} {}", target.out_of(product)).into(),
                outcome: Ok(Verdict::Warn(format!(
                    "stale as a whole ({}): every name is sealed again",
                    stale.join(", ")
                ))),
            });
        }
    }
    Ok(checks)
}

impl<'a> SealedStore<'a> {
    pub fn new(target: &'a SealedTarget, env: &'a str, r: &'a dyn CommandRunner) -> Self {
        Self {
            target,
            env,
            r,
            now: unix_now,
        }
    }

    /// The store with `now` as its clock (tests).
    #[cfg(test)]
    pub(super) fn with_clock(mut self, now: fn() -> u64) -> Self {
        self.now = now;
        self
    }

    /// The product whose bundle holds env name `name`.
    fn product_of(&self, name: &str) -> Option<&'a str> {
        self.target
            .placement
            .products
            .iter()
            .find(|(_, p)| p.names.contains_key(name))
            .map(|(p, _)| p.as_str())
    }

    /// The configured file path of `name`, when it is a file key.
    fn file_of(&self, name: &str) -> Option<&'a String> {
        self.target
            .placement
            .products
            .values()
            .find_map(|p| p.names.get(name))
            .and_then(Option::as_ref)
    }

    /// The project the header names: the configuration directory's name (§5.2).
    fn project(&self) -> String {
        crate::config_store::default_project(None, None, &self.target.config_dir)
            .unwrap_or_else(|_| "project".to_string())
    }

    /// Seal `entries` (sorted by name) as `product`'s bundle and write it atomically.
    fn seal_one(
        &self,
        product: &str,
        entries: &[(&str, &SecretValue)],
        plan_id: &str,
    ) -> Result<(), Error> {
        let path = self.target.written_path(product);
        let dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).map_err(|e| local_io(LocalOp::CreateDir, &dir, &e))?;
        let _lock = Lock::take(&path)?;
        // §5.4, T10: only a header verified with `sealed.signer` sets the previous revision.
        let previous = match self.target.found(self.env, product)? {
            Found::Ours { header, .. } => header.revision,
            Found::Absent | Found::Unreadable | Found::Foreign { .. } => 0,
        };
        let now = (self.now)();
        let revision = previous
            .checked_add(1)
            .ok_or_else(|| bug("sealed: the revision overflowed"))?
            .max(now);
        let names: Vec<Name> = entries
            .iter()
            .map(|(n, _)| Name {
                name: n.to_string(),
                destination: destination(n, self.file_of(n)),
            })
            .collect();
        let sde = secrets_dir_env(&names, self.target.placement.products.get(product));
        let recipients = self.target.sorted_recipients();
        let header = Header {
            format: FORMAT.to_string(),
            project: self.project(),
            environment: self.env.to_string(),
            product: product.to_string(),
            target: self.target.placement.target.clone(),
            revision,
            created_at: crate::domain::provenance::utc(now),
            opv_version: env!("CARGO_PKG_VERSION").to_string(),
            plan_id: plan_id.to_string(),
            contract_digest: format::contract_digest(
                &names,
                sde.as_deref(),
                &recipients,
                &self.target.signer_fingerprint,
            ),
            recipients,
            signer: self.target.signer_fingerprint.clone(),
            names,
            secrets_dir_env: sde,
        };
        let keys = self
            .target
            .recipients
            .iter()
            .map(|r| crypto::parse_recipient(r))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| bug("sealed: a parsed recipient no longer parses"))?;
        let values: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, v)| (*n, v.expose().as_bytes()))
            .collect();
        let bundle = self
            .r
            .seal_bundle(&SealCall::new(&header, &values, &keys))
            .map_err(|f| seal_failure(f, &self.target.placement.target))?;
        write_atomically(&path, &bundle)
    }
}

/// A seal that did not happen, as the catalog's cause (§6.2): a signing key the codec
/// refuses is the deploy credential's field; any other codec refusal is a batch the plan
/// should never have passed.
fn seal_failure(f: SealFailure, target: &str) -> Error {
    match f {
        SealFailure::NotSignedIn(e) => e,
        // G4 by value: a key whose value is the signing key, whatever reference reads it.
        SealFailure::Codec(CryptoError::SealsSigningKey(name)) => Cause::InputInvalid {
            path: PathBuf::new(),
            kind: InputKind::DeployCredentials,
            at: None,
            field: name,
            rule: FieldRule::Check {
                check: crate::cause::ConfigCheck::SealedDeliversSigner {
                    target: target.to_string(),
                },
            },
        }
        .into(),
        SealFailure::Codec(CryptoError::SigningKeyInvalid(expected)) => Cause::InputInvalid {
            path: PathBuf::new(),
            kind: InputKind::DeployCredentials,
            at: None,
            field: "private key".to_string(),
            rule: FieldRule::Type { expected },
        }
        .into(),
        SealFailure::Codec(_) => bug("sealed: the codec refused a batch the plan passed"),
    }
}

/// The exclusive lock beside a bundle while it is written (§5.4: two seals of one placement
/// never interleave): an OS advisory lock on `<bundle>.lock` (`flock` on Unix, `LockFileEx`
/// on Windows), which the kernel releases when its holder exits, however it exits. A file
/// left by a killed run has no holder and blocks nothing. The file is removed while the lock
/// is still held, and a lock taken on a file that was meanwhile removed or replaced is taken
/// again, so two runs never both hold a lock.
struct Lock {
    path: PathBuf,
    // Held for the lock: closing it releases the lock.
    _file: std::fs::File,
}

impl Lock {
    fn take(bundle: &Path) -> Result<Self, Error> {
        let mut name = bundle.as_os_str().to_os_string();
        name.push(".lock");
        let path = PathBuf::from(name);
        // A removal between our open and our lock is another run finishing: a few tries.
        for _ in 0..8 {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|e| local_io(LocalOp::Write, &path, &e))?;
            match try_lock_exclusive(&file) {
                Ok(()) => {}
                Err(e) if held_elsewhere(&e) => return Err(sealing_elsewhere(bundle)),
                Err(e) => return Err(local_io(LocalOp::Write, &path, &e)),
            }
            if still_at(&file, &path) {
                return Ok(Lock { path, _file: file });
            }
        }
        // The lock file kept being replaced: other runs kept sealing this bundle.
        Err(sealing_elsewhere(bundle))
    }
}

/// Another opv run holds the lock beside `bundle` (§5.4): names the bundle, nothing else.
fn sealing_elsewhere(bundle: &Path) -> Error {
    Cause::LocalIo {
        op: LocalOp::SealLock,
        path: bundle.to_path_buf(),
        io: IoKind::WouldBlock,
        delivery: None,
    }
    .into()
}

/// Whether a lock attempt failed because another process holds the lock: `EWOULDBLOCK` on
/// Unix, `ERROR_LOCK_VIOLATION` (33) on Windows.
fn held_elsewhere(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::WouldBlock || (cfg!(windows) && e.raw_os_error() == Some(33))
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Removed before the handle closes, so no run locks the removed file afterwards
        // without seeing it gone ([`still_at`]).
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An exclusive lock on `file` without waiting: `WouldBlock` while another holds it.
#[cfg(unix)]
fn try_lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(std::io::Error::from)
}

/// An exclusive lock on `file` without waiting: an error while another holds it.
#[cfg(windows)]
fn try_lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    // SAFETY: an all-zero OVERLAPPED is valid (offset 0, no event); the handle is owned by
    // `file`, which outlives the call.
    let ok = unsafe {
        let mut overlapped: OVERLAPPED = std::mem::zeroed();
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether `path` still names the file `file` has open, and not one created after a holder
/// removed it.
#[cfg(unix)]
fn still_at(file: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), std::fs::metadata(path)) {
        (Ok(held), Ok(named)) => held.dev() == named.dev() && held.ino() == named.ino(),
        _ => false,
    }
}

/// Whether `path` still names a file: a holder removes it before releasing its lock.
#[cfg(windows)]
fn still_at(_file: &std::fs::File, path: &Path) -> bool {
    path.exists()
}

/// `bytes` to `path` atomically (§5.6): a temporary file in the same directory, `fsync`,
/// `rename`, `fsync` of the directory. On any failure the temporary file is removed and the
/// previous bundle is untouched.
pub(super) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".tmp-{}", std::process::id()));
    let tmp = dir.join(name);
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(local_io(LocalOp::Write, path, &e));
    }
    // The rename is durable once the directory is (POSIX); Windows has no directory fsync.
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(&dir) {
        d.sync_all()
            .map_err(|e| local_io(LocalOp::Write, &dir, &e))?;
    }
    Ok(())
}

impl Store for SealedStore<'_> {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        let entry = |name: &str, version: &str| StoreEntry {
            name: name.to_string(),
            version: Some(version.to_string()),
            pending: false,
            stamp: None,
        };
        let mut out = Vec::new();
        for (product, placed) in &self.target.placement.products {
            match self.target.found(self.env, product)? {
                Found::Absent => {}
                Found::Ours {
                    header, version, ..
                } => out.extend(header.names.iter().map(|n| entry(&n.name, &version))),
                Found::Foreign { version } => {
                    out.extend(placed.names.keys().map(|n| entry(n, &version)));
                }
                Found::Unreadable => {
                    out.extend(placed.names.keys().map(|n| entry(n, "unreadable")));
                }
            }
        }
        Ok(out)
    }

    /// A value over 1 MiB, or a file key whose path breaks the bundle's path rule. An empty
    /// value is the plan's (`not_delivered`), never a refusal of the bundle (§5.8.4 G6).
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        if value.expose().len() > MAX_VALUE {
            return Some((
                VALUE_TOO_LARGE,
                "the value is larger than 1 MiB, a sealed bundle's limit",
            ));
        }
        if let Some(path) = self.file_of(name)
            && format::check_file_path(path).is_err()
        {
            return Some((
                PATH_RULE,
                "the file path is not lower-case letters, digits and - in at most four parts",
            ));
        }
        None
    }
}

impl StagedStore for SealedStore<'_> {
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        if batch.iter().any(|(n, v)| self.refusal(n, v).is_some()) {
            return Err(bug("sealed: a value the plan passed breaks a bundle rule"));
        }
        let mut per_product: BTreeMap<&str, usize> = BTreeMap::new();
        for (name, _) in batch {
            let product = self
                .product_of(name)
                .ok_or_else(|| bug("sealed: a staged name belongs to no delivered product"))?;
            *per_product.entry(product).or_default() += 1;
        }
        if per_product.values().any(|n| *n > MAX_NAMES) {
            return Err(bug("sealed: a bundle would hold more than 256 names"));
        }
        Ok(())
    }

    /// Never called by `sync`, which writes through [`StagedStore::write_run`] so the header
    /// carries the plan id.
    fn write(&self, _batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        Err(bug("sealed: write without the run's plan id"))
    }

    /// One bundle per product in the run's scope, holding exactly that product's names of
    /// `batch` (the complete desired set). A product with no name left is sealed empty when
    /// its bundle exists, so a retired name leaves it (T3); one with no bundle and no name
    /// is left alone.
    fn write_run(&self, batch: &[(String, &SecretValue)], run: &WriteRun<'_>) -> Result<(), Error> {
        let mut groups: BTreeMap<&str, Vec<(&str, &SecretValue)>> = BTreeMap::new();
        for (name, value) in batch {
            let product = self
                .product_of(name)
                .ok_or_else(|| bug("sealed: a staged name belongs to no delivered product"))?;
            if run.product.is_some_and(|p| p != product) {
                return Err(bug("sealed: a staged name is outside the run's product"));
            }
            groups
                .entry(product)
                .or_default()
                .push((name.as_str(), *value));
        }
        let products: Vec<&str> = match run.product {
            Some(p) => vec![p],
            None => self
                .target
                .placement
                .products
                .keys()
                .map(String::as_str)
                .collect(),
        };
        for product in products {
            let mut entries = groups.remove(product).unwrap_or_default();
            if entries.is_empty() && !self.target.written_path(product).exists() {
                continue;
            }
            entries.sort_by(|a, b| a.0.cmp(b.0));
            self.seal_one(product, &entries, run.plan_id)?;
        }
        Ok(())
    }

    /// A whole-set store is never pruned name by name (§5.3, T3).
    fn remove(&self, _names: &[String]) -> Result<(), Error> {
        Err(bug("sealed: remove on a whole-set store"))
    }

    fn whole_set(&self) -> bool {
        true
    }

    /// Every product's bundle read and verified as [`Store::list`] does, so a tampered one
    /// refuses before `sync` reads any value from 1Password (T10).
    fn check_local(&self) -> Result<(), Error> {
        for product in self.target.placement.products.keys() {
            self.target.found(self.env, product)?;
        }
        Ok(())
    }

    /// Config travels in the bundle like a secret (T15).
    fn variables(&self) -> Option<&dyn VariableStore> {
        None
    }
}

/// The sealed target's runtime: every write is live, nothing deploys (§8.1).
pub struct SealedRuntime;

impl StagedRuntime for SealedRuntime {
    fn deploy(&self) -> Result<(), Error> {
        Err(bug("sealed: deploy on a live target"))
    }

    fn live(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
