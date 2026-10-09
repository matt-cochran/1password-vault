//! The Fly provider: `[environments.<env>.fly]` parsing, Fly name rules, doctor checks and
//! the port wiring (FR-37, §10.3). Every user-visible Fly message is unchanged from 0.4.

use std::any::Any;
use std::io;

use serde::Deserialize;

use super::{CREDENTIAL_VARS, FLYCTL, Fly, PROGRAM, auth_whoami, not_logged_in};
use crate::adapters::probe::{parse_version, spawn_tool, version_in};
use crate::config::{check_ident, is_id};
use crate::domain::{Profile, SIMPLE_TEMPLATE};
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Check, NameRules, Preflight, Provider, Section, TargetConfig, Verdict, eq_as,
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
    /// Fly secret name template containing `{PRODUCT}` and `{KEY}` (`{KEY}` under the
    /// simple profile); defines the managed set (FR-8).
    pub secret_name_template: String,
    pub profile: Profile,
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

/// `secret_name` is accepted only so that validation can reject it naming the profile.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSimpleFly {
    app: String,
    #[serde(default)]
    secret_name: Option<toml::Value>,
}

impl Provider for FlyProvider {
    fn section(&self) -> &'static str {
        "fly"
    }

    fn label(&self) -> &'static str {
        "Fly"
    }

    fn parse(
        &self,
        section: &Section<'_>,
        profile: Profile,
    ) -> Result<Box<dyn TargetConfig>, Error> {
        let env = section.env();
        let target = match profile {
            Profile::Fleet => {
                let f: RawFly = section.deserialize()?;
                check_app(env, &f.app)?;
                let t = &f.secret_name;
                if !t.contains("{PRODUCT}") || !t.contains("{KEY}") {
                    return Err(Error::Config(format!(
                        "environment {env}: fly.secret_name {t:?} must contain {{PRODUCT}} and {{KEY}}"
                    )));
                }
                FlyTarget {
                    app: f.app,
                    secret_name_template: f.secret_name,
                    profile,
                }
            }
            Profile::Simple => {
                let f: RawSimpleFly = section.deserialize()?;
                check_app(env, &f.app)?;
                if f.secret_name.is_some() {
                    return Err(Error::Config(format!(
                        "environment {env}: fly.secret_name is not allowed under the simple \
                         profile (the Fly name is the key name)"
                    )));
                }
                FlyTarget {
                    app: f.app,
                    secret_name_template: SIMPLE_TEMPLATE.into(),
                    profile,
                }
            }
        };
        Ok(Box::new(target))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &["flyctl", "fly auth"]
    }

    fn credential_vars(&self) -> &'static [&'static str] {
        CREDENTIAL_VARS
    }

    fn setup_hint(&self, profile: Profile) -> String {
        match profile {
            Profile::Simple => "configure fly.app".into(),
            Profile::Fleet => "configure fly.app and fly.secret_name".into(),
        }
    }

    fn init_section(&self, app: &str, profile: Profile) -> Option<String> {
        let quoted = |s: &str| toml::Value::String(s.to_string()).to_string();
        let mut s = format!("fly.app = {}\n", quoted(app));
        if profile == Profile::Fleet {
            s.push_str(&format!("fly.secret_name = {}\n", quoted(FLEET_TEMPLATE)));
        }
        Some(s)
    }
}

/// The app name goes into argv: non-empty, unpadded, never read as a flag.
fn check_app(env: &str, app: &str) -> Result<(), Error> {
    check_ident(env, "fly.app", app, is_id, "^[A-Za-z0-9][A-Za-z0-9._-]*$")
}

impl TargetConfig for FlyTarget {
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
        match self.profile {
            Profile::Simple => format!(
                "environments {first} and {second} both use Fly app {:?}; under the simple \
                 profile each environment needs its own app",
                self.app
            ),
            Profile::Fleet => format!(
                "environments {first} and {second} both use Fly app {:?} with fly.secret_name {:?}",
                self.app, self.secret_name_template
            ),
        }
    }

    fn open<'a>(&'a self, _env: &'a str, r: &'a dyn CommandRunner) -> Result<Ports<'a>, Error> {
        let fly = || Fly {
            runner: r,
            app: &self.app,
        };
        Ok(Ports::Staged {
            store: Box::new(fly()),
            runtime: Box::new(fly()),
        })
    }

    fn preflight(&self, r: &dyn CommandRunner) -> Result<Preflight, Error> {
        super::preflight(r, &self.app)
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
        return Err(Error::Dependency(format!(
            "{PROGRAM} version failed (exit {})",
            o.status
        )));
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
        Ok(false) => match host().token(CREDENTIAL_VARS) {
            Some(var) => Ok(Verdict::Warn(format!(
                "{PROGRAM} auth whoami failed with {var} set (an app-scoped deploy token cannot \
                 run it); fly commands will show whether the token can access the app"
            ))),
            None => Err(not_logged_in(&host(), None)),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Dependency(format!(
            "{PROGRAM} not found on PATH\n  {}",
            host().install_hint(FLYCTL)
        ))),
        Err(e) => Err(Error::Dependency(format!(
            "failed to run {PROGRAM} ({})",
            e.kind()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SIMPLE_PRODUCT;
    use crate::runner::fake::FakeRunner;

    fn fleet_target(template: &str) -> FlyTarget {
        FlyTarget {
            app: "a".into(),
            secret_name_template: template.into(),
            profile: Profile::Fleet,
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
    fn simple_template_renders_the_key_name_itself() {
        let t = FlyTarget {
            profile: Profile::Simple,
            ..fleet_target(SIMPLE_TEMPLATE)
        };
        assert_eq!(t.env_name(SIMPLE_PRODUCT, "JWT_KEY"), "JWT_KEY");
    }

    #[test]
    fn fly_target_opens_staged_ports() {
        let t = fleet_target("FLEET__{PRODUCT}__{KEY}");
        let r = FakeRunner::new([]);
        assert!(matches!(t.open("prod", &r), Ok(Ports::Staged { .. })));
    }

    #[test]
    fn init_section_writes_the_fleet_template() {
        assert_eq!(
            PROVIDER.init_section("my-app", Profile::Fleet).as_deref(),
            Some("fly.app = \"my-app\"\nfly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n")
        );
    }
}
