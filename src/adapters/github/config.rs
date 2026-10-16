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

use super::{CREDENTIAL_VARS, GH, PROGRAM};
use crate::adapters::probe::{spawn_tool, version_in};
use crate::config::check_ident;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Check, InitField, NameRules, Preflight, PreflightMode, Provider, Section, TargetConfig,
    Verdict, eq_as, init_lines,
};
use crate::runner::CommandRunner;

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
                            return Err(super::missing_environment_error(repo, environment));
                        }
                    }
                }
                Ok(Preflight::default())
            }
        }
    }
    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
        vec![
            Check {
                name: "gh".into(),
                outcome: gh_version(r, host),
            },
            Check {
                name: "gh auth".into(),
                outcome: auth_outcome(
                    super::gh::auth_status(r),
                    host().token(CREDENTIAL_VARS),
                    &host().install_hint(GH),
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

/// `gh --version`: present, and which version (only a strict version token is printed).
fn gh_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Verdict, Error> {
    let o = spawn_tool(r, GH, host, &["--version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(
            format!("{PROGRAM} --version failed (exit {})", o.status).into(),
        ));
    }
    Ok(match version_in(&o.stdout) {
        Some(v) => Verdict::Ok(format!("version {v}")),
        None => Verdict::Ok("present, version not recognised".into()),
    })
}

/// The `gh auth` verdict from [`super::gh::auth_status`]: signed in, rejected credential
/// variable, or no session. Extracted so the branches are testable while `gh.rs` is being
/// implemented in parallel.
fn auth_outcome(
    status: io::Result<bool>,
    token: Option<&str>,
    install_hint: &str,
) -> Result<Verdict, Error> {
    match status {
        Ok(true) => Ok(Verdict::Ok("signed in".into())),
        Ok(false) => Err(match token {
            Some(var) => Error::Auth(
                format!(
                    "not signed in to GitHub ({var} is set but was rejected)\n  next: replace \
                     {var} with a valid fine-grained token, or unset it and run `{PROGRAM} auth \
                     login`"
                )
                .into(),
            ),
            None => Error::Auth(
                format!(
                    "not signed in to GitHub ({PROGRAM} auth status failed)\n  next: \
                     {PROGRAM} auth login"
                )
                .into(),
            ),
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Dependency(
            format!("{PROGRAM} not found on PATH\n  {install_hint}").into(),
        )),
        Err(e) => Err(Error::Dependency(
            format!("failed to run {PROGRAM} ({})", e.kind()).into(),
        )),
    }
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

    fn host() -> Host {
        Host::from_env(&crate::host::FakeEnv::new("macos"))
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
        let e = crate::adapters::github::missing_environment_error("org/r", "staging");
        assert!(e.mentions("org/r") && e.mentions("staging"), "{e}");
    }

    #[test]
    fn missing_environment_error_leaves_the_create_command_to_a_person() {
        let e = crate::adapters::github::missing_environment_error("org/r", "staging");
        assert!(
            e.action()
                .is_some_and(|a| a.contains("gh api -X PUT repos/org/r/environments/staging")),
            "{e:?}"
        );
    }

    #[test]
    fn missing_environment_error_needs_a_human() {
        let e = crate::adapters::github::missing_environment_error("org/r", "staging");
        assert!(e.code().human_required());
    }

    #[test]
    fn missing_environment_error_says_opv_never_creates_environments() {
        let e = crate::adapters::github::missing_environment_error("org/r", "staging");
        assert!(e.mentions("opv never creates GitHub environments"), "{e}");
    }

    // doctor -----------------------------------------------------------------------------

    #[test]
    fn gh_version_reports_the_version() {
        let r = FakeRunner::new([Output::success("gh version 2.40.0 (2024-01-01)\n")]);
        assert_eq!(
            gh_version(&r, &host).unwrap(),
            Verdict::Ok("version 2.40.0".into())
        );
    }

    #[test]
    fn gh_version_names_the_install_command_when_missing() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        let e = gh_version(&r, &host).unwrap_err();
        assert!(e.mentions("install: brew install gh"), "{e}");
    }

    #[test]
    fn auth_outcome_accepts_a_signed_in_session() {
        assert_eq!(
            auth_outcome(Ok(true), None, "").unwrap(),
            Verdict::Ok("signed in".into())
        );
    }

    #[test]
    fn auth_outcome_names_a_rejected_token_variable() {
        let e = auth_outcome(Ok(false), Some("GH_TOKEN"), "").unwrap_err();
        assert!(e.mentions("GH_TOKEN") && e.mentions("rejected"), "{e}");
    }

    #[test]
    fn auth_outcome_offers_gh_auth_login_without_a_token() {
        let e = auth_outcome(Ok(false), None, "").unwrap_err();
        assert_eq!(e.next_step(), Some("gh auth login"));
    }

    #[test]
    fn auth_outcome_reports_a_missing_gh_with_the_install_hint() {
        let e = auth_outcome(
            Err(io::ErrorKind::NotFound.into()),
            None,
            "install: brew install gh",
        )
        .unwrap_err();
        assert!(e.mentions("install: brew install gh"), "{e}");
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
