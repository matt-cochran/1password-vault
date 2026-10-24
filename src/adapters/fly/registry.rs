//! `registry-push` (#234, `docs/design/provider-operations.md` §2, §5.3, D1b′): push an image
//! already in the local docker daemon to the target's Fly registry under its own deploy token.
//!
//! `docker push` reads registry auth only from its configuration directory, so the token
//! goes through one: a fresh private directory in the RAM runtime directory
//! ([`PrivateDir`], mode 0700), seeded with a secret-free `config.json` whose placeholder
//! `auths` entry stops docker's credential-helper detection. `docker login --password-stdin`
//! then takes the token on stdin (never argv or env) and docker writes the auth into that
//! file; opv checks the file's shape after the login (no `credsStore`, no `credHelpers`), and
//! the directory is removed on every exit path (drop, and the signal handler).
//!
//! Every docker call carries `DOCKER_CONFIG=<dir>` and `DOCKER_HOST=<endpoint>`, the
//! `unix://` endpoint admission resolved (P9), so the fresh configuration cannot send the
//! push to another daemon. `FlyLogin` is not used: its environment stays flyctl-only.
//!
//! Failures by step (§4): a login refused with docker's `unauthorized` reply is the deploy
//! credentials' rejection (exit 7); any other failed login is `Unavailable` (exit 9); a push
//! that fails is `WriteOutcomeUnknown` (exit 9, never retried); a push that exits 0 without a
//! `digest: sha256:<hex>` line is `UnexpectedOutput` of an applied write.

use std::path::Path;

use base64::Engine as _;
use serde::Deserialize;
use serde::de::IgnoredAny;
use zeroize::Zeroizing;

use crate::adapters::probe::probe_failure;
use crate::cause::{
    Cause, CredentialProblem, CredentialRef, During, EnvName, Guard, ItemId, OperationRefusal,
    OutputProblem, Principal, System, TargetName, Unanswered, Upstream, VaultId,
};
use crate::domain::ItemRef;
use crate::error::Error;
use crate::host::{DOCKER, Host};
use crate::ramdir::{PrivateDir, sweep};
use crate::runner::{Call, CommandRunner, Failure, Outcome};

/// The registry every Fly app's repository lives in.
pub const REGISTRY: &str = "registry.fly.io";

/// The prefix of the private configuration directories (swept when their run is gone).
const DIR_PREFIX: &str = "opv-docker.";

/// The secret-free seed: an `auths` entry keeps `docker login` in this file (§5.3 step 3).
const SEED: &[u8] = br#"{"auths":{"opv.invalid":{}}}"#;

/// `docker login registry.fly.io -u x --password-stdin`: the token on stdin only (O2).
pub const LOGIN_ARGS: [&str; 5] = ["login", REGISTRY, "-u", "x", "--password-stdin"];

/// One `registry-push`, as admission bound it: names, the validated image, the endpoint P9
/// resolved and the RAM runtime directory P8 checked. No value.
#[derive(Debug, Clone, Copy)]
pub struct PushRequest<'a> {
    pub env: &'a str,
    pub target: &'a str,
    /// The target's `fly.app`.
    pub app: &'a str,
    /// The target's `deploy_credentials` item.
    pub item: &'a ItemRef,
    /// `registry.fly.io/<app>:<tag>`, validated (P6) and local (P10).
    pub image: &'a str,
    /// The local daemon's `unix://` endpoint (P9).
    pub endpoint: &'a str,
    /// The user-owned RAM `$XDG_RUNTIME_DIR` (P8).
    pub runtime: &'a Path,
}

/// Push `p.image` (§5.3) and return the digest the registry reported (`sha256:<64 hex>`).
/// Reads the deploy item once under its principal; isolated like every operation child.
pub fn registry_push(r: &dyn CommandRunner, p: &PushRequest) -> Result<String, Error> {
    crate::runner::isolated_env(|| push_isolated(r, p))
}

fn push_isolated(r: &dyn CommandRunner, p: &PushRequest) -> Result<String, Error> {
    sweep(p.runtime, DIR_PREFIX);
    let dir = PrivateDir::create(p.runtime, DIR_PREFIX).map_err(|e| dir_failed(p.runtime, e))?;
    let config = dir.path().join("config.json");
    write_seed(&config).map_err(|e| dir_failed(dir.path(), e))?;
    let principal = Principal::DeployCredentials {
        vault: VaultId::new(p.item.vault.as_str()),
        item: ItemId::new(p.item.item.as_str()),
        env: EnvName::new(p.env),
        target: TargetName::new(p.target),
    };
    let mut values = crate::adapters::onepassword::read_deploy_credentials(
        r,
        p.item,
        super::login::FIELDS,
        Some(&principal),
    )?;
    let token = values.remove(super::login::TOKEN_FIELD).ok_or(Cause::Bug {
        site: "fly: deploy credentials read without their declared field",
    })?;
    // docker's file holds base64("x:<token>"): scrub that composite in every reply (X7).
    let pair = Zeroizing::new(format!("x:{}", token.expose()));
    let encoded = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()));
    for v in [token.expose(), pair.as_str(), encoded.as_str()] {
        crate::scrub::register_secret(v);
    }
    let env = [("DOCKER_CONFIG", dir.utf8()), ("DOCKER_HOST", p.endpoint)];
    crate::runner::under_deploy(principal, || {
        login(r, &env, token.expose().as_bytes(), p)?;
        drop(token);
        // The directory is removed as this function returns, on this path too.
        if !file_store_only(&config) {
            return Err(escaped(p));
        }
        push(r, &env, p)
    })
}

/// §5.3 step 5: `docker login`, a read refused with exit 1 (nothing was pushed).
fn login(
    r: &dyn CommandRunner,
    env: &[(&str, &str)],
    token: &[u8],
    p: &PushRequest,
) -> Result<(), Error> {
    let stdin = Zeroizing::new(token.to_vec());
    let call = Call {
        env,
        ..Call::new(DOCKER.program, &LOGIN_ARGS)
    }
    .with_stdin(Some(&stdin));
    match r.read(&call, &[1]) {
        Ok(Outcome::Done(_)) => Ok(()),
        Ok(Outcome::Refused(_)) => match crate::runner::take_failure() {
            Some(failed) if failed.stderr().contains("unauthorized") => {
                let cause = Cause::CredentialRejected {
                    system: System::Docker,
                    credential: CredentialRef::DeployCredentials {
                        vault: VaultId::new(p.item.vault.as_str()),
                        item: ItemId::new(p.item.item.as_str()),
                        env: EnvName::new(p.env),
                        target: TargetName::new(p.target),
                    },
                    problem: CredentialProblem::Rejected { needs: Vec::new() },
                    seen: failed.seen.clone(),
                };
                Err(with_reply(cause, failed))
            }
            Some(failed) => {
                let cause = Cause::Unavailable {
                    system: System::Docker,
                    why: failed
                        .seen
                        .exit()
                        .unanswered()
                        .unwrap_or(Unanswered::Network),
                    attempts: failed.seen.attempts(),
                    seen: failed.seen.clone(),
                };
                Err(with_reply(cause, failed))
            }
            None => Err(unobserved()),
        },
        Ok(Outcome::Unknown { .. }) => Err(DOCKER.unanswered(r, "docker login")),
        Err(e) => Err(call_error(r, &e)),
    }
}

/// §5.3 step 7: `docker push <image>`, a write never retried; its digest is the report.
fn push(r: &dyn CommandRunner, env: &[(&str, &str)], p: &PushRequest) -> Result<String, Error> {
    let args = ["push", p.image];
    let call = Call {
        env,
        ..Call::new(DOCKER.program, &args)
    }
    .rollout();
    match r.write(&call) {
        Ok(Outcome::Done(out)) => {
            pushed_digest(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
                match crate::runner::take_unusable_reply(&Call::new(DOCKER.program, &args)) {
                    Some(seen) => Cause::UnexpectedOutput {
                        system: System::Docker,
                        at: None,
                        problem: OutputProblem::Empty {
                            what: "pushed digest",
                        },
                        during: During::AppliedWrite,
                        seen,
                    }
                    .into(),
                    None => unobserved(),
                }
            })
        }
        Ok(Outcome::Refused(_) | Outcome::Unknown { .. }) => match crate::runner::take_failure() {
            Some(failed) => {
                let cause = Cause::WriteOutcomeUnknown {
                    system: System::Docker,
                    subject: super::app_ref(p.app),
                    seen: failed.seen.clone(),
                };
                Err(with_reply(cause, failed))
            }
            None => Err(unobserved()),
        },
        Err(e) => Err(call_error(r, &e)),
    }
}

/// The `sha256:<64 hex>` of docker push's final `<tag>: digest: sha256:<hex> size: <n>` line.
pub fn pushed_digest(stdout: &str) -> Option<String> {
    stdout.lines().rev().find_map(|line| {
        let hex = line.split("digest: sha256:").nth(1)?.get(..64)?;
        hex.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            .then(|| format!("sha256:{hex}"))
    })
}

/// docker's `config.json` after the login, projected: entry names and the presence of the
/// keys that would move the auth elsewhere. Values are skipped unread.
#[derive(Deserialize)]
struct DockerConfig {
    #[serde(default)]
    auths: std::collections::BTreeMap<String, AuthEntry>,
    #[serde(rename = "credsStore")]
    creds_store: Option<IgnoredAny>,
    #[serde(rename = "credHelpers")]
    cred_helpers: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct AuthEntry {
    auth: Option<IgnoredAny>,
}

/// §5.3 step 6: the auth is in this file for the registry, and no helper holds it.
fn file_store_only(config: &Path) -> bool {
    let Ok(raw) = std::fs::read(config).map(Zeroizing::new) else {
        return false;
    };
    serde_json::from_slice::<DockerConfig>(&raw).is_ok_and(|c| {
        c.creds_store.is_none()
            && c.cred_helpers.is_none()
            && c.auths.get(REGISTRY).is_some_and(|e| e.auth.is_some())
    })
}

/// The seed `config.json`: a fresh file (never an existing path or a link), mode 0600.
#[cfg(unix)]
fn write_seed(path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?
        .write_all(SEED)
}

/// `registry-push` is Linux-only (D7): admission refuses it elsewhere (P8).
#[cfg(not(unix))]
fn write_seed(path: &Path) -> std::io::Result<()> {
    let _ = (path, SEED);
    Err(std::io::ErrorKind::Unsupported.into())
}

fn dir_failed(dir: &Path, e: std::io::Error) -> Error {
    Cause::PrivateDirFailed {
        dir: dir.to_path_buf(),
        io: e.kind().into(),
    }
    .into()
}

fn escaped(p: &PushRequest) -> Error {
    Cause::Guard {
        guard: Guard::OperationRefused {
            env: EnvName::new(p.env),
            target: TargetName::new(p.target),
            operation: "registry-push",
            reason: OperationRefusal::CredentialStoreEscaped,
        },
    }
    .into()
}

/// A docker call that returned an error instead of an outcome: a spent run budget, or a
/// program that could not be started (nothing ran).
fn call_error(r: &dyn CommandRunner, e: &std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::TimedOut {
        return DOCKER.budget_spent(r, e);
    }
    probe_failure(&DOCKER, e, &|| Host::detect())
}

fn unobserved() -> Error {
    Cause::Bug {
        site: "fly: a failed docker call left no observation",
    }
    .into()
}

/// `cause` with the failed call's scrubbed reply as evidence, when it wrote one.
fn with_reply(cause: Cause, failed: Failure) -> Error {
    let exit = failed.seen.exit();
    let (said, truncated) = crate::scrub::Excerpt::parts(failed.excerpt);
    if said.is_empty() {
        return cause.into();
    }
    Error::with_evidence(
        cause,
        Upstream {
            source: System::Docker,
            tool: "docker CLI".to_string(),
            version: None,
            exit,
            said,
            removed_advice: false,
            truncated,
            untrusted: true,
        },
    )
}

#[cfg(all(test, unix))]
#[path = "registry_tests.rs"]
mod tests;
