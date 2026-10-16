//! The GitHub provider: a target's `github` section parsing and validation, GitHub name
//! rules, doctor, preflight and the port wiring (FR-46). Which products a target delivers
//! is the target's `products` (FR-48, FR-56), not this provider's.
//!
//! The section is read with [`Section::deserialize`], so a shape error points at its line;
//! the rules the TOML shape cannot express (exactly one of `repo`/`repos`, repository
//! spelling, GitHub environment names) are checked here and worded like the Fly provider
//! (`environment <env>: github.<field> ...`).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::io;

use serde::Deserialize;

use super::{CREDENTIAL_VARS, PROGRAM};
use crate::adapters::probe::{parse_version, version_in};
use crate::cause::{Cause, DiagnoseContext};
use crate::config::check_ident;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Check, InitField, NameRules, Preflight, PreflightMode, Provider, Section, TargetConfig,
    Verdict, eq_as, init_lines,
};
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The registered GitHub provider.
pub static PROVIDER: GithubProvider = GithubProvider;

/// The GitHub provider (section `github`).
#[derive(Debug)]
pub struct GithubProvider;

/// The GitHub Actions target of one environment (FR-46).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubTarget {
    /// `owner/name` of every repository written, from `repo` or `repos`; at least one, no
    /// duplicates (case-insensitive, as GitHub treats them).
    pub repos: Vec<String>,
    /// The GitHub environment whose secrets and variables are written; `None`: repository
    /// secrets and variables.
    pub environment: Option<String>,
    /// Name template with `{KEY}` and optionally `{PRODUCT}`; default `{KEY}`.
    pub secret_name_template: String,
}

/// The section as written. `deny_unknown_fields` makes a typo a TOML error at its line.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGithub {
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    repos: Option<Vec<String>>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    secret_name: Option<String>,
}

/// `opv target add` options of the GitHub provider (H3), in the order they are written. `repos` is not
/// offered: `repo` names the one repository most environments use; edit the file for more.
static INIT_FIELDS: [InitField; 3] = [
    InitField {
        field: "repo",
        help: "GitHub repository as owner/name (not looked up; gh is not called)",
        required: true,
    },
    InitField {
        field: "environment",
        help: "GitHub environment whose secrets and variables are written (optional)",
        required: false,
    },
    InitField {
        field: "secret_name",
        help: "Secret name template (default {KEY})",
        required: false,
    },
];

/// An `owner/name` repository as GitHub writes it: `^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`.
fn is_repo(s: &str) -> bool {
    match s.split_once('/') {
        Some((owner, name)) => {
            !owner.is_empty()
                && !name.is_empty()
                && !name.contains('/')
                && owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        }
        None => false,
    }
}

/// A GitHub environment name: `^[A-Za-z0-9._ -]{1,255}$`, no leading or trailing space.
fn is_environment(s: &str) -> bool {
    (1..=255).contains(&s.chars().count())
        && s.trim() == s
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ' ' | '-'))
}

impl Provider for GithubProvider {
    fn section(&self) -> &'static str {
        "github"
    }
    fn label(&self) -> &'static str {
        "GitHub"
    }
    fn tools(&self) -> &'static [&'static crate::host::Tool] {
        &[&super::GH]
    }
    fn parse(&self, section: &Section<'_>) -> Result<Box<dyn TargetConfig>, Error> {
        let env = section.env();
        let raw: RawGithub = section.deserialize()?;
        let (repos, field) = match (raw.repo, raw.repos) {
            (Some(repo), None) => (vec![repo], "github.repo"),
            (None, Some(repos)) => (repos, "github.repos"),
            (Some(_), Some(_)) => {
                return Err(Error::Config(
                    format!(
                        "environment {env}: github.repo and github.repos are mutually \
                         exclusive; give exactly one"
                    )
                    .into(),
                ));
            }
            (None, None) => {
                return Err(Error::Config(
                    format!(
                        "environment {env}: github.repo or github.repos is required; give \
                         exactly one"
                    )
                    .into(),
                ));
            }
        };
        if repos.is_empty() {
            return Err(Error::Config(
                format!("environment {env}: github.repos must list at least one repository").into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for repo in &repos {
            check_ident(env, field, repo, is_repo, "^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")?;
            if !seen.insert(repo.to_ascii_lowercase()) {
                return Err(Error::Config(
                    format!(
                        "environment {env}: github repos list {repo:?} more than once \
                         (GitHub repository names are case-insensitive)"
                    )
                    .into(),
                ));
            }
        }
        if let Some(environment) = &raw.environment {
            check_ident(
                env,
                "github.environment",
                environment,
                is_environment,
                "^[A-Za-z0-9._ -]{1,255}$",
            )?;
        }
        let secret_name_template = raw.secret_name.unwrap_or_else(|| "{KEY}".into());
        if !secret_name_template.contains("{KEY}") {
            return Err(Error::Config(
                format!(
                    "environment {env}: github.secret_name {secret_name_template:?} must \
                     contain {{KEY}}"
                )
                .into(),
            ));
        }
        Ok(Box::new(GithubTarget {
            repos,
            environment: raw.environment,
            secret_name_template,
        }))
    }
    fn doctor_checks(&self) -> &'static [&'static str] {
        &["gh", "gh auth"]
    }

    fn ci_setup_step(&self) -> Option<&'static str> {
        None
    }
    fn credential_vars(&self) -> &'static [&'static str] {
        CREDENTIAL_VARS
    }
    fn deploy_credential_fields(
        &self,
    ) -> Result<&'static [crate::provider::CredentialField], String> {
        Ok(super::login::FIELDS)
    }
    fn deploy_login(&self) -> Result<Box<dyn crate::provider::DeployLogin>, Error> {
        Ok(Box::<super::login::GithubLogin>::default())
    }
    fn setup_hint(&self) -> String {
        "configure github.repo".into()
    }
    fn init_fields(&self) -> &'static [InitField] {
        &INIT_FIELDS
    }
    fn init_section(&self, values: &BTreeMap<&str, String>) -> Option<String> {
        let mut out = String::new();
        if let Some(repo) = values.get("repo") {
            out.push_str(&init_lines("github", [("repo", repo.as_str())]));
        }
        if let Some(environment) = values.get("environment") {
            out.push_str(&init_lines(
                "github",
                [("environment", environment.as_str())],
            ));
        }
        if let Some(secret_name) = values.get("secret_name") {
            out.push_str(&init_lines(
                "github",
                [("secret_name", secret_name.as_str())],
            ));
        }
        Some(out)
    }
}

impl GithubTarget {
    /// GitHub name for `product`/`key`: `{PRODUCT}` becomes the upper-cased product with
    /// `-` replaced by `_`, `{KEY}` becomes the key verbatim (like [`FlyTarget`]).
    ///
    /// [`FlyTarget`]: crate::adapters::fly::FlyTarget
    pub fn target_name(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.secret_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }
}

impl GithubTarget {
    /// `explain` lines: the name, how a workflow reads it, and where it is written.
    fn lines(
        &self,
        product: &str,
        key: &str,
        kind: &str,
        context: &str,
    ) -> Vec<(&'static str, String)> {
        let name = self.target_name(product, key);
        let mut lines = vec![
            ("github as", format!("{kind}: ${{{{ {context}.{name} }}}}")),
            ("github name", name),
            ("github repos", self.repos.join(", ")),
        ];
        if let Some(environment) = &self.environment {
            lines.push(("github environment", environment.clone()));
        }
        lines
    }
}

impl TargetConfig for GithubTarget {
    fn target_locator(&self) -> String {
        let mut repos: Vec<String> = self.repos.iter().map(|r| r.to_ascii_lowercase()).collect();
        repos.sort();
        match &self.environment {
            Some(e) => format!("repos {} environment {e}", repos.join(",")),
            None => format!("repos {}", repos.join(",")),
        }
    }

    fn provider(&self) -> &'static dyn Provider {
        &PROVIDER
    }
    fn env_name(&self, product: &str, key: &str) -> String {
        self.target_name(product, key)
    }
    fn store_name(&self, env_name: &str) -> String {
        env_name.to_string()
    }
    fn name_rules(&self) -> NameRules {
        NameRules {
            env_label: "GitHub name",
            store: None,
        }
    }
    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<GithubTarget>()
            .is_some_and(|o| {
                self.environment == o.environment
                    && self.secret_name_template == o.secret_name_template
                    && self
                        .repos
                        .iter()
                        .any(|r| o.repos.iter().any(|s| s.eq_ignore_ascii_case(r)))
            })
    }
    fn shared_target_error(&self, first: &str, second: &str) -> String {
        let repos: Vec<String> = self.repos.iter().map(|r| format!("{r:?}")).collect();
        format!(
            "environments {first} and {second} both write GitHub repositories {}; each would \
             prune what the other stages",
            repos.join(", ")
        )
    }
    fn open<'a>(
        &'a self,
        _env: &'a str,
        _managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        let gh = || super::Github {
            runner: r,
            scope: super::Scope {
                repos: &self.repos,
                environment: self.environment.as_deref(),
            },
        };
        Ok(Ports::Staged {
            store: Box::new(gh()),
            runtime: Box::new(gh()),
        })
    }
    fn preflight(&self, r: &dyn CommandRunner, mode: PreflightMode) -> Result<Preflight, Error> {
        match mode {
            // A read command diagnoses each gh call on its own (FR-26); no extra call.
            PreflightMode::Read => Ok(Preflight::default()),
            PreflightMode::Mutate => {
                if let Some(environment) = &self.environment {
                    for repo in &self.repos {
                        let names = super::gh::environments(r, repo)?;
                        if !names.iter().any(|n| n == environment) {
                            return Err(super::gh::missing_environment_error(repo, environment));
                        }
                    }
                }
                Ok(Preflight::default())
            }
        }
    }
    fn doctor(&self, r: &dyn CommandRunner, _host: &dyn Fn() -> Host) -> Vec<Check> {
        vec![
            Check {
                name: "gh".into(),
                outcome: gh_version(r),
            },
            Check {
                name: "gh auth".into(),
                outcome: gh_auth(
                    r,
                    super::gh::token_needs(&self.repos, self.environment.as_deref()),
                ),
            },
        ]
    }
    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        self.lines(product, key, "Actions secret", "secrets")
    }
    fn explain_config(&self, product: &str, key: &str) -> Option<Vec<(&'static str, String)>> {
        Some(self.lines(product, key, "Actions variable", "vars"))
    }
    fn eq_dyn(&self, other: &dyn TargetConfig) -> bool {
        eq_as(self, other)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn clone_box(&self) -> Box<dyn TargetConfig> {
        Box::new(self.clone())
    }
}

/// The oldest gh opv can read with: the first release with `gh variable list --json`,
/// v2.43.0 (31 Jan 2024; cli/cli#8516, "Add option --json for gh variable list" in its
/// release notes). `gh secret list --json` came earlier, in v2.36.0 (cli/cli#8081).
/// `doctor` warns below it (06.21, C3: verified, not guessed).
pub const GH_TESTED_MIN: (u64, u64, u64) = (2, 43, 0);

/// `gh --version`: present, and which version (only a strict version token is printed); a
/// release older than [`GH_TESTED_MIN`] is a warning.
fn gh_version(r: &dyn CommandRunner) -> Result<Verdict, Error> {
    let o = r
        .probe(&Call::new(PROGRAM, &["--version"]), PROBE_TIMEOUT)
        .map_err(spawn_failure)?;
    if o.status != 0 {
        return Err(probe_failure(Vec::new()));
    }
    let (a, b, c) = GH_TESTED_MIN;
    let version = version_in(&o.stdout).and_then(|v| parse_version(&v).map(|n| (v, n)));
    Ok(match version {
        Some((v, n)) if n >= GH_TESTED_MIN => Verdict::Ok(format!("version {v}")),
        Some((v, _)) => Verdict::Warn(format!(
            "version {v}; opv needs gh {a}.{b}.{c} or later (older releases lack \
             `gh variable list --json`, and their refusals read as missing rights)"
        )),
        None => Verdict::Warn(format!(
            "present, version not recognised; opv needs gh {a}.{b}.{c} or later"
        )),
    })
}

/// The `gh auth` check: `gh auth status` (any token type, exit status only). When it fails,
/// the failure is diagnosed (design §5): under deploy credentials or a shell token the
/// rejected credential is named, never `gh auth login` (06.01). `gh auth status` words its
/// refusal in text no recording covers, so an unrecognised one is diagnosed again from the
/// read-only `gh api user`, whose refusals are recorded.
fn gh_auth(r: &dyn CommandRunner, needs: Vec<String>) -> Result<Verdict, Error> {
    match super::gh::auth_status(r) {
        Ok(true) => return Ok(Verdict::Ok("signed in".into())),
        Ok(false) => {}
        Err(e) => return Err(spawn_failure(e)),
    }
    let first = probe_failure(needs.clone());
    if !matches!(first.cause(), Some((Cause::Unrecognized { .. }, _))) {
        return Err(first);
    }
    match super::gh::user_probe(r) {
        Ok(false) => match super::gh::diagnosed(&DiagnoseContext::default(), needs) {
            Some(e) if !matches!(e.cause(), Some((Cause::Unrecognized { .. }, _))) => Err(e),
            _ => Err(first),
        },
        _ => Err(first),
    }
}

/// A gh probe that could not start: gh missing, a probe that ran out of time (diagnosed:
/// GitHub unavailable), or gh unusable.
fn spawn_failure(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => super::gh::tool_missing(),
        kind => super::gh::diagnosed(&DiagnoseContext::default(), Vec::new())
            .unwrap_or_else(|| super::gh::tool_unusable(kind)),
    }
}

/// A gh probe that exited non-zero, diagnosed (design §5).
fn probe_failure(needs: Vec<String>) -> Error {
    super::gh::diagnosed(&DiagnoseContext::default(), needs).unwrap_or_else(|| {
        Cause::Bug {
            site: "github doctor: a failed gh probe left no observation",
        }
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    /// Parse an inline `github` section body.
    fn parse_body(body: &str) -> Result<Box<dyn TargetConfig>, Error> {
        let text = format!("{{ {} }}", body.replace('\n', ", "));
        let value = toml::de::DeValue::parse(&text).expect("inline table parses");
        PROVIDER.parse(&Section::new("dev", &value, &text))
    }

    fn target_of(body: &str) -> GithubTarget {
        parse_body(body)
            .expect("section parses")
            .as_any()
            .downcast_ref::<GithubTarget>()
            .expect("github target")
            .clone()
    }

    /// The `Error::Config` text of a refused section body.
    fn config_error(body: &str) -> String {
        match parse_body(body) {
            Err(Error::Config(m)) => m.to_string(),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    // parse ------------------------------------------------------------------------------

    #[test]
    fn parse_refuses_an_environment_with_a_trailing_space() {
        assert!(
            config_error("repo = \"org/r\"\nenvironment = \"staging \"")
                .contains("github.environment")
        );
    }

    #[test]
    fn parse_reads_a_single_repo() {
        assert_eq!(target_of(r#"repo = "org/r""#).repos, ["org/r"]);
    }

    #[test]
    fn parse_reads_a_repos_list() {
        assert_eq!(
            target_of(r#"repos = ["org/a", "org/b"]"#).repos,
            ["org/a", "org/b"]
        );
    }

    #[test]
    fn parse_defaults_secret_name_to_key() {
        assert_eq!(target_of(r#"repo = "org/r""#).secret_name_template, "{KEY}");
    }

    #[test]
    fn parse_reads_the_environment() {
        assert_eq!(
            target_of(
                r#"repo = "org/r"
environment = "staging""#
            )
            .environment
            .as_deref(),
            Some("staging")
        );
    }

    #[test]
    fn parse_refuses_repo_and_repos_together() {
        let e = config_error(
            r#"repo = "org/r"
repos = ["org/a"]"#,
        );
        assert!(
            e.contains("github.repo") && e.contains("github.repos"),
            "{e}"
        );
    }

    #[test]
    fn parse_refuses_a_missing_repo() {
        let e = config_error(r#"environment = "staging""#);
        assert!(
            e.contains("github.repo") && e.contains("github.repos"),
            "{e}"
        );
    }

    #[test]
    fn parse_refuses_an_empty_repos_list() {
        assert!(config_error("repos = []").contains("at least one repository"));
    }

    #[test]
    fn parse_refuses_a_repo_without_an_owner() {
        assert!(config_error(r#"repo = "just-a-name""#).contains("github.repo"));
    }

    #[test]
    fn parse_refuses_a_repo_with_a_forbidden_character() {
        assert!(config_error(r#"repo = "org/r x""#).contains("github.repo"));
    }

    #[test]
    fn parse_refuses_case_insensitive_duplicate_repos() {
        let e = config_error(r#"repos = ["Org/R", "org/r"]"#);
        assert!(e.contains("more than once"), "{e}");
    }

    #[test]
    fn parse_refuses_a_padded_environment() {
        assert!(
            config_error("repo = \"org/r\"\nenvironment = \" staging\"").contains("whitespace")
        );
    }

    #[test]
    fn parse_refuses_an_environment_with_a_forbidden_character() {
        assert!(
            config_error("repo = \"org/r\"\nenvironment = \"sta/ging\"")
                .contains("github.environment")
        );
    }

    #[test]
    fn parse_refuses_an_over_long_environment() {
        let long = "e".repeat(256);
        assert!(
            config_error(&format!("repo = \"org/r\"\nenvironment = \"{long}\""))
                .contains("github.environment")
        );
    }

    #[test]
    fn parse_refuses_secret_name_without_key() {
        let e = config_error(
            r#"repo = "org/r"
secret_name = "STATIC""#,
        );
        assert!(
            e.contains("github.secret_name") && e.contains("{KEY}"),
            "{e}"
        );
    }

    #[test]
    fn parse_refuses_an_unknown_field() {
        assert!(config_error("repo = \"org/r\"\nrepository = \"org/r\"").contains("unknown field"));
    }

    // rendering --------------------------------------------------------------------------

    #[test]
    fn env_name_upper_cases_the_product_and_replaces_dash() {
        let t = target_of("repo = \"org/r\"\nsecret_name = \"CI__{PRODUCT}__{KEY}\"");
        assert_eq!(t.env_name("my-app", "API_KEY"), "CI__MY_APP__API_KEY");
    }

    #[test]
    fn env_name_is_the_key_when_the_template_has_no_product() {
        let t = target_of("repo = \"org/r\"\nsecret_name = \"{KEY}\"");
        assert_eq!(t.env_name("my-app", "API_KEY"), "API_KEY");
    }

    // same_target ------------------------------------------------------------------------

    #[test]
    fn same_target_matches_repository_case_insensitively() {
        let a = target_of(r#"repo = "org/r""#);
        let b = target_of(r#"repo = "ORG/R""#);
        assert!(a.same_target(&b));
    }

    #[test]
    fn same_target_requires_the_same_environment() {
        let a = target_of("repo = \"org/r\"\nenvironment = \"staging\"");
        let b = target_of("repo = \"org/r\"\nenvironment = \"prod\"");
        assert!(!a.same_target(&b));
    }

    #[test]
    fn same_target_requires_the_same_template() {
        let a = target_of("repo = \"org/r\"\nsecret_name = \"{PRODUCT}_{KEY}\"");
        let b = target_of("repo = \"org/r\"\nsecret_name = \"{KEY}\"");
        assert!(!a.same_target(&b));
    }

    #[test]
    fn same_target_is_false_without_a_shared_repository() {
        let a = target_of(r#"repo = "org/a""#);
        let b = target_of(r#"repo = "org/b""#);
        assert!(!a.same_target(&b));
    }

    #[test]
    fn same_target_is_true_when_any_repository_is_shared() {
        let a = target_of(r#"repos = ["org/a", "org/b"]"#);
        let b = target_of(r#"repos = ["org/c", "org/B"]"#);
        assert!(a.same_target(&b));
    }

    #[test]
    fn shared_target_error_names_both_environments_and_the_repository() {
        let t = target_of(r#"repo = "org/r""#);
        let e = t.shared_target_error("dev", "prod");
        assert!(
            e.contains("dev") && e.contains("prod") && e.contains("org/r"),
            "{e}"
        );
    }

    // preflight --------------------------------------------------------------------------

    #[test]
    fn read_preflight_makes_no_calls() {
        let t = target_of(r#"repo = "org/r""#);
        let r = FakeRunner::default();
        let _ = t.preflight(&r, PreflightMode::Read);
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn mutate_preflight_without_an_environment_makes_no_calls() {
        let t = target_of(r#"repo = "org/r""#);
        let r = FakeRunner::default();
        let _ = t.preflight(&r, PreflightMode::Mutate);
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn missing_environment_error_names_repository_and_environment() {
        let e = crate::adapters::github::gh::missing_environment_error("org/r", "staging");
        assert!(
            rendered(&e).contains("GitHub environment staging in org/r"),
            "{}",
            rendered(&e)
        );
    }

    #[test]
    fn missing_environment_error_is_owner_setup_required() {
        let e = crate::adapters::github::gh::missing_environment_error("org/r", "staging");
        assert_eq!(e.code_str(), "owner_setup_required");
    }

    #[test]
    fn missing_environment_error_needs_a_human() {
        let e = crate::adapters::github::gh::missing_environment_error("org/r", "staging");
        assert!(e.human_required());
    }

    // doctor -----------------------------------------------------------------------------

    /// The whole terminal report of `e`, as a person reads it.
    fn rendered(e: &Error) -> String {
        crate::error::report(e, "opv doctor", None)
    }

    /// The recorded `Bad credentials` reply (`tests/fixtures/github/failures/02`).
    const BAD_CREDENTIALS: &str = "gh: Bad credentials (HTTP 401)\n";

    /// The recorded signed-out reply (`tests/fixtures/github/failures/01`).
    const SIGNED_OUT: &str = "To get started with GitHub CLI, please run:  gh auth login\n\
                              Alternatively, populate the GH_TOKEN environment variable with a \
                              GitHub API authentication token.\n";

    fn deploy() -> crate::cause::Principal {
        crate::cause::Principal::DeployCredentials {
            vault: crate::cause::VaultId::new("vlt-deploy"),
            item: crate::cause::ItemId::new("gh-deploy"),
            env: crate::cause::EnvName::new("prod"),
            target: crate::cause::TargetName::new("ci"),
        }
    }

    /// `gh auth` under the target's deploy credentials, gh answering `stderr` (exit 1).
    fn auth_under_deploy(stderr: &str) -> Error {
        let r = FakeRunner::default();
        r.push_with_stderr(Output::failure(1), stderr);
        crate::runner::under_deploy(deploy(), || gh_auth(&r, vec!["Secrets write".into()]))
            .unwrap_err()
    }

    #[test]
    fn gh_version_reports_the_version() {
        let r = FakeRunner::new([Output::success("gh version 2.102.0 (2026-09-30)\n")]);
        assert_eq!(
            gh_version(&r).unwrap(),
            Verdict::Ok("version 2.102.0".into())
        );
    }

    #[test]
    fn gh_version_below_the_minimum_is_a_warning() {
        let r = FakeRunner::new([Output::success("gh version 2.40.0 (2024-01-01)\n")]);
        assert!(matches!(gh_version(&r).unwrap(), Verdict::Warn(_)));
    }

    #[test]
    fn gh_version_with_variable_list_json_is_no_warning() {
        // C3: 2.43.0 is the first release with `gh variable list --json` (cli/cli#8516).
        let r = FakeRunner::new([Output::success("gh version 2.43.0 (2024-01-31)\n")]);
        assert_eq!(
            gh_version(&r).unwrap(),
            Verdict::Ok("version 2.43.0".into())
        );
    }

    #[test]
    fn gh_version_missing_is_dependency_missing() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert_eq!(gh_version(&r).unwrap_err().code_str(), "dependency_missing");
    }

    #[test]
    fn gh_auth_accepts_a_signed_in_session() {
        let r = FakeRunner::new([Output::success("")]);
        assert_eq!(
            gh_auth(&r, Vec::new()).unwrap(),
            Verdict::Ok("signed in".into())
        );
    }

    #[test]
    fn gh_auth_rejected_deploy_credentials_are_deploy_credentials_failed() {
        assert_eq!(
            auth_under_deploy(BAD_CREDENTIALS).code_str(),
            "deploy_credentials_failed"
        );
    }

    #[test]
    fn gh_auth_rejected_deploy_credentials_never_offer_gh_auth_login() {
        assert!(!rendered(&auth_under_deploy(BAD_CREDENTIALS)).contains("gh auth login"));
    }

    #[test]
    fn gh_auth_an_unrecognised_status_is_diagnosed_from_gh_api_user() {
        let r = FakeRunner::default();
        r.push_with_stderr(
            Output::failure(1),
            "You are not logged into any GitHub hosts.\n",
        );
        r.push_with_stderr(Output::failure(4), SIGNED_OUT);
        assert_eq!(
            gh_auth(&r, Vec::new()).unwrap_err().code_str(),
            "target_not_signed_in"
        );
    }

    #[test]
    fn gh_auth_missing_gh_is_dependency_missing() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert_eq!(
            gh_auth(&r, Vec::new()).unwrap_err().code_str(),
            "dependency_missing"
        );
    }

    #[test]
    fn doctor_check_names_match_the_provider_list() {
        assert_eq!(PROVIDER.doctor_checks(), ["gh", "gh auth"]);
    }

    // explain ----------------------------------------------------------------------------

    #[test]
    fn explain_names_the_rendered_name_and_repositories() {
        let t = target_of("repo = \"org/r\"\nsecret_name = \"CI__{KEY}\"");
        assert_eq!(
            t.explain("api", "TOKEN"),
            [
                (
                    "github as",
                    "Actions secret: ${{ secrets.CI__TOKEN }}".to_string()
                ),
                ("github name", "CI__TOKEN".to_string()),
                ("github repos", "org/r".to_string()),
            ]
        );
    }

    #[test]
    fn explain_adds_the_environment_when_set() {
        let t = target_of("repo = \"org/r\"\nenvironment = \"staging\"");
        assert_eq!(
            t.explain("api", "TOKEN"),
            [
                (
                    "github as",
                    "Actions secret: ${{ secrets.TOKEN }}".to_string()
                ),
                ("github name", "TOKEN".to_string()),
                ("github repos", "org/r".to_string()),
                ("github environment", "staging".to_string()),
            ]
        );
    }

    #[test]
    fn explain_config_names_the_variable_expression() {
        let t = target_of("repo = \"org/r\"");
        assert_eq!(
            t.explain_config("api", "TOKEN").map(|l| l[0].1.clone()),
            Some("Actions variable: ${{ vars.TOKEN }}".to_string())
        );
    }

    // credentials and init ---------------------------------------------------------------

    #[test]
    fn credential_vars_are_the_github_tokens() {
        assert_eq!(PROVIDER.credential_vars(), ["GH_TOKEN", "GITHUB_TOKEN"]);
    }

    #[test]
    fn deploy_credential_fields_hold_one_concealed_token() {
        assert_eq!(
            PROVIDER.deploy_credential_fields().unwrap(),
            super::super::login::FIELDS
        );
    }

    #[test]
    fn deploy_login_returns_a_github_login() {
        assert!(PROVIDER.deploy_login().is_ok());
    }

    #[test]
    fn init_offers_repo_but_not_repos() {
        let fields: Vec<&str> = PROVIDER.init_fields().iter().map(|f| f.field).collect();
        assert!(fields.contains(&"repo") && !fields.contains(&"repos"));
    }

    #[test]
    fn init_requires_repo() {
        let repo = PROVIDER
            .init_fields()
            .iter()
            .find(|f| f.field == "repo")
            .unwrap();
        assert!(repo.required);
    }

    #[test]
    fn init_section_writes_the_repo() {
        assert_eq!(
            PROVIDER
                .init_section(&BTreeMap::from([("repo", "org/r".to_string())]))
                .as_deref(),
            Some("github.repo = \"org/r\"\n")
        );
    }
}
