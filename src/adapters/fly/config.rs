//! The Fly provider: a target's `fly` section parsing, Fly name rules, doctor checks and
//! the port wiring (FR-37, §10.3). Failed flyctl calls are diagnosed in `diagnose.rs` (§5).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::{CREDENTIAL_VARS, FLYCTL, Fly, PROGRAM, auth_whoami};
use crate::adapters::probe::{parse_version, spawn_tool, version_in};
use crate::cause::{Cause, DiagnoseContext, Unusable};
use crate::config::{check_ident, is_id};
use crate::domain::SecretValue;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Check, InitField, NameRules, Preflight, PreflightMode, Provider, Section, TargetConfig,
    Verdict, eq_as, init_lines,
};
use crate::runner::CommandRunner;

/// The `flyctl` release opv is tested with (its import parser is ported, see `mod.rs`).
/// Later patches of the same minor pass without a warning; another minor or an older patch
/// warns.
pub const FLYCTL_TESTED: (u64, u64, u64) = (0, 4, 112);

/// The fleet Fly name template `opv init` writes (§10.2, the fixture's template).
pub const FLEET_TEMPLATE: &str = "FLEET__{PRODUCT}__{KEY}";

/// The registered Fly provider.
pub static PROVIDER: FlyProvider = FlyProvider;

/// The Fly provider (section `fly`).
#[derive(Debug)]
pub struct FlyProvider;

/// The Fly.io target of one environment (§10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlyTarget {
    pub app: String,
    /// Fly secret name template containing `{KEY}` and optionally `{PRODUCT}`; defines the
    /// managed set (FR-8). Two keys rendering one name are refused at load (FR-30).
    pub secret_name_template: String,
}

impl FlyTarget {
    /// Fly secret name for `product`/`key`: `{PRODUCT}` becomes the upper-cased product with
    /// `-` replaced by `_`, `{KEY}` becomes the key verbatim.
    pub fn target_name(&self, product: &str, key: &str) -> String {
        let product = product.to_ascii_uppercase().replace('-', "_");
        self.secret_name_template
            .replace("{PRODUCT}", &product)
            .replace("{KEY}", key)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFly {
    app: String,
    secret_name: String,
}

impl Provider for FlyProvider {
    fn section(&self) -> &'static str {
        "fly"
    }

    fn label(&self) -> &'static str {
        "Fly"
    }

    /// `fly secrets list` reports a digest of each value (D0 spike: 16 hex characters,
    /// equal for equal values).
    fn versions_reveal_values(&self) -> bool {
        true
    }

    fn tools(&self) -> &'static [&'static crate::host::Tool] {
        &[&FLYCTL]
    }

    fn parse(&self, section: &Section<'_>) -> Result<Box<dyn TargetConfig>, Error> {
        let env = section.env();
        let f: RawFly = section.deserialize()?;
        check_app(env, &f.app)?;
        let t = &f.secret_name;
        if !t.contains("{KEY}") {
            return Err(Error::Config(
                format!("environment {env}: fly.secret_name {t:?} must contain {{KEY}}").into(),
            ));
        }
        Ok(Box::new(FlyTarget {
            app: f.app,
            secret_name_template: f.secret_name,
        }))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &["flyctl", "fly auth"]
    }

    /// The Fly CLI action pinned in the GitHub Actions example (`docs/usage.md`).
    fn ci_setup_step(&self) -> Option<&'static str> {
        Some("      - name: Install flyctl\n        uses: superfly/flyctl-actions/setup-flyctl@1.6")
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
        Ok(Box::<super::login::FlyLogin>::default())
    }

    fn mint_deploy_credential(
        &self,
        target: &dyn TargetConfig,
        name: &str,
        r: &dyn CommandRunner,
    ) -> Option<Result<BTreeMap<String, SecretValue>, Error>> {
        let t = target.as_any().downcast_ref::<FlyTarget>()?;
        Some(super::login::mint_deploy_credential(r, &t.app, name))
    }

    fn mint_preflight(&self, r: &dyn CommandRunner) -> Option<Result<(), Error>> {
        Some(super::login::mint_preflight(r))
    }

    fn mint_cleanup_hint(&self) -> Option<&'static str> {
        Some(super::login::CLEANUP_HINT)
    }

    /// C21 (A22): `flyctl tokens list --app <app>` shows the token opv minted.
    fn mint_refind(&self, target: &dyn TargetConfig) -> Option<crate::cause::VendorCmd> {
        let t = target.as_any().downcast_ref::<FlyTarget>()?;
        Some(crate::cause::VendorCmd {
            program: "flyctl".into(),
            args: ["tokens", "list", "--app", t.app.as_str()]
                .map(str::to_string)
                .to_vec(),
        })
    }

    fn setup_hint(&self) -> String {
        "configure fly.app and fly.secret_name".into()
    }

    fn init_fields(&self) -> &'static [InitField] {
        &INIT_FIELDS
    }

    fn init_section(&self, values: &BTreeMap<&str, String>) -> Option<String> {
        let template = values
            .get("secret_name")
            .map_or(FLEET_TEMPLATE, String::as_str);
        let lines = [
            ("app", values.get("app")?.as_str()),
            ("secret_name", template),
        ];
        Some(init_lines("fly", lines))
    }
}

/// `opv target add` options of the Fly provider (H3): `--fly-app` and `--fly-secret-name`.
static INIT_FIELDS: [InitField; 2] = [
    InitField {
        field: "app",
        help: "Fly app of the environment (not looked up; flyctl is not called)",
        required: true,
    },
    InitField {
        field: "secret_name",
        help: "Fly secret name template (default FLEET__{PRODUCT}__{KEY}; {KEY} for bare names)",
        required: false,
    },
];

/// The app name goes into argv: non-empty, unpadded, never read as a flag.
fn check_app(env: &str, app: &str) -> Result<(), Error> {
    check_ident(env, "fly.app", app, is_id, "^[A-Za-z0-9][A-Za-z0-9._-]*$")
}

impl TargetConfig for FlyTarget {
    fn target_locator(&self) -> String {
        format!("app {}", self.app)
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
            env_label: "Fly name",
            store: None,
        }
    }

    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        other.as_any().downcast_ref::<FlyTarget>().is_some_and(|o| {
            o.app == self.app && o.secret_name_template == self.secret_name_template
        })
    }

    fn shared_target_error(&self, first: &str, second: &str) -> String {
        format!(
            "environments {first} and {second} both use Fly app {:?} with fly.secret_name {:?}",
            self.app, self.secret_name_template
        )
    }

    fn open<'a>(
        &'a self,
        _env: &'a str,
        _managed: BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        let fly = || Fly {
            runner: r,
            app: &self.app,
        };
        Ok(Ports::Staged {
            store: Box::new(fly()),
            runtime: Box::new(fly()),
        })
    }

    fn preflight(&self, r: &dyn CommandRunner, mode: PreflightMode) -> Result<Preflight, Error> {
        match mode {
            // The app's state matters only to writes; a read command's flyctl calls are
            // diagnosed one by one (FR-26), so it makes no extra call.
            PreflightMode::Read => Ok(Preflight::default()),
            PreflightMode::Mutate => super::preflight(r, &self.app),
        }
    }

    fn doctor(&self, r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Vec<Check> {
        vec![
            Check {
                name: "flyctl".into(),
                outcome: flyctl_version(r, host),
            },
            Check {
                name: "fly auth".into(),
                outcome: fly_auth(r, host),
            },
        ]
    }

    fn explain(&self, product: &str, key: &str) -> Vec<(&'static str, String)> {
        vec![("fly name", self.target_name(product, key))]
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

/// Same major and minor as [`FLYCTL_TESTED`], at or above its patch.
fn flyctl_tested(v: (u64, u64, u64)) -> bool {
    let (a, b, c) = FLYCTL_TESTED;
    v.0 == a && v.1 == b && v.2 >= c
}

fn flyctl_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Verdict, Error> {
    let o = spawn_tool(r, FLYCTL, host, &["version"])?;
    if o.status != 0 {
        let _ = crate::runner::take_failure_excerpt();
        return Err(Cause::ToolUnusable {
            tool: PROGRAM.to_string(),
            why: Unusable::VersionUnreadable,
        }
        .into());
    }
    let (a, b, c) = FLYCTL_TESTED;
    Ok(match version_in(&o.stdout) {
        Some(v) if parse_version(&v).is_some_and(flyctl_tested) => {
            Verdict::Ok(format!("version {v}"))
        }
        Some(v) => Verdict::Warn(format!(
            "version {v}; opv is tested with flyctl {a}.{b}.{c} or a later {a}.{b}.x patch (its secrets import format may differ)\n  {}",
            host().install_hint(FLYCTL)
        )),
        None => Verdict::Warn(format!(
            "present, version not recognised; opv is tested with flyctl {a}.{b}.{c} or a later {a}.{b}.x patch\n  {}",
            host().install_hint(FLYCTL)
        )),
    })
}

/// `flyctl auth whoami`: exit status only, via the same check a failed flyctl call uses
/// (FR-26). Its stdout names the account (an email), so it is dropped unread.
fn fly_auth(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Verdict, Error> {
    match auth_whoami(r) {
        Ok(true) => Ok(Verdict::Ok("signed in".into())),
        // FR-26: app-scoped deploy tokens cannot run `auth whoami`, so with a Fly token in
        // the environment a failure here is not proof of being logged out.
        Ok(false) if r.deploy_signed_in() => Ok(Verdict::Warn(format!(
            "{PROGRAM} auth whoami failed under the environment's deploy_credentials (an \
             app-scoped deploy token cannot run it); fly commands will show whether the token \
             can access the app"
        ))),
        Ok(false) => match host().token(CREDENTIAL_VARS) {
            Some(var) => Ok(Verdict::Warn(format!(
                "{PROGRAM} auth whoami failed with {var} set (an app-scoped deploy token cannot \
                 run it); fly commands will show whether the token can access the app"
            ))),
            // The reply says why (design §5): signed out, a rejected session, or Fly not
            // answering, never assumed (06.11).
            None => Err(super::failed_call(&DiagnoseContext::default())),
        },
        Err(e) => Err(super::call_error(r, host, &e, &DiagnoseContext::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    fn fleet_target(template: &str) -> FlyTarget {
        FlyTarget {
            app: "a".into(),
            secret_name_template: template.into(),
        }
    }

    #[test]
    fn target_name_normalizes_product() {
        assert_eq!(
            fleet_target("FLEET__{PRODUCT}__{KEY}").env_name("my-app", "API_KEY"),
            "FLEET__MY_APP__API_KEY"
        );
    }

    #[test]
    fn key_template_renders_the_key_name_itself() {
        assert_eq!(fleet_target("{KEY}").env_name("web", "JWT_KEY"), "JWT_KEY");
    }

    #[test]
    fn fly_target_opens_staged_ports() {
        let t = fleet_target("FLEET__{PRODUCT}__{KEY}");
        let r = FakeRunner::new([]);
        assert!(matches!(
            t.open("prod", BTreeSet::new(), &r),
            Ok(Ports::Staged { .. })
        ));
    }

    #[test]
    fn init_section_writes_the_fleet_template() {
        assert_eq!(
            PROVIDER
                .init_section(&BTreeMap::from([("app", "my-app".to_string())]))
                .as_deref(),
            Some("fly.app = \"my-app\"\nfly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n")
        );
    }

    /// Under deploy credentials a failed `auth whoami` is expected, not a sign-out.
    #[test]
    fn whoami_failing_under_deploy_credentials_is_a_warning() {
        let fake = FakeRunner::new([crate::runner::Output::failure(1)]);
        let r = super::super::tests::UnderDeployCredentials(&fake);
        let host = || Host::from_env(&crate::host::FakeEnv::new("macos"));
        assert!(matches!(fly_auth(&r, &host), Ok(Verdict::Warn(_))));
    }
}
