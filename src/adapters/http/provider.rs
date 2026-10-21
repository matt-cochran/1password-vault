//! The HTTP target's provider (design `http-target` §3, §4, §7): parses the `http` section
//! against the pinned descriptor, opens the store and runtime, and hands the deploy sign-in
//! the host its item's `base_url` must agree with.
//!
//! [`Provider`] is implemented for a host-carrying [`HttpProvider`]: the registered
//! [`PROVIDER`] carries no host (it only parses sections), while a parsed target keeps a
//! per-host provider so [`Provider::deploy_login`] can build the login without the core
//! passing a target to it. Providers are interned per host, so a long-lived process leaks at
//! most one small value per distinct host.

use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use prost_reflect::DescriptorPool;

use super::descriptor;
use super::model::HttpTarget;
use super::store::{HttpRuntime, HttpStore};
use super::url::Destination;
use crate::cause::FieldRule;
use crate::config::section_invalid;
use crate::domain::runtime::FileMount;
use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use crate::provider::{
    Channel, Channels, Check, FileCapability, InitField, NameRules, Preflight, PreflightMode,
    Provider, Section, TargetConfig,
};
use crate::runner::CommandRunner;

/// The `opv target add` options of the `http` provider (design §7).
const INIT_FIELDS: [InitField; 2] = [
    InitField {
        field: "descriptor",
        help: "path of the pinned FileDescriptorSet",
        required: true,
    },
    InitField {
        field: "service",
        help: "full name of the gRPC service to generate a section for",
        required: true,
    },
];

/// The registered `http` provider: parses sections only, so it carries no host.
pub static PROVIDER: HttpProvider = HttpProvider {
    host: String::new(),
};

/// The HTTP target's provider. `host` is the configuration's `http.host`; it is empty on
/// [`PROVIDER`] and set on the per-target provider a parsed [`HttpConfig`] keeps.
#[derive(Debug)]
pub struct HttpProvider {
    host: String,
}

/// A parsed and validated `http` target, with the pinned descriptor already loaded.
pub struct HttpConfig {
    target: HttpTarget,
    pool: DescriptorPool,
    provider: &'static HttpProvider,
}

impl std::fmt::Debug for HttpConfig {
    /// The target and the host; never a descriptor byte or a secret (there is none here).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConfig")
            .field("target", &self.target)
            .field("host", &self.provider.host)
            .finish()
    }
}

impl Provider for HttpProvider {
    fn section(&self) -> &'static str {
        "http"
    }

    fn label(&self) -> &'static str {
        "HTTPS target"
    }

    fn tools(&self) -> &'static [&'static crate::host::Tool] {
        // The call is made in process over the runner's HTTPS effect, never a vendor CLI.
        &[]
    }

    fn parse(&self, section: &Section<'_>) -> Result<Box<dyn TargetConfig>, Error> {
        let table: toml::Table = section.deserialize()?;
        let read: RefCell<Option<Vec<u8>>> = RefCell::new(None);
        let target = super::config::parse(&table, |path| {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("descriptor could not be read: {e}"))?;
            *read.borrow_mut() = Some(bytes.clone());
            Ok(bytes)
        })
        .map_err(|errors| {
            let (field, rule) = errors
                .into_iter()
                .next()
                .unwrap_or_else(|| ("http".to_string(), "missing".to_string()));
            section_invalid(&field, field_rule(&rule))
        })?;
        let bytes = read.into_inner().unwrap_or_default();
        let pool = descriptor::load(&bytes, &target.descriptor_sha256).map_err(|_| {
            section_invalid(
                "http.descriptor",
                FieldRule::Type {
                    expected: "the pinned descriptor file",
                },
            )
        })?;
        let provider = provider_for(&target.host);
        Ok(Box::new(HttpConfig {
            target,
            pool,
            provider,
        }))
    }

    fn doctor_checks(&self) -> &'static [&'static str] {
        &[]
    }

    fn setup_hint(&self) -> String {
        "configure http.host and http.descriptor".to_string()
    }

    fn init_fields(&self) -> &'static [InitField] {
        &INIT_FIELDS
    }

    fn init_section(&self, values: &BTreeMap<&str, String>) -> Option<String> {
        let descriptor = values.get("descriptor")?;
        let service = values.get("service")?;
        let bytes = std::fs::read(descriptor).ok()?;
        super::propose::section(&bytes, descriptor, service).ok()
    }

    fn deploy_credential_fields(&self) -> Result<&'static [crate::provider::CredentialField], String> {
        Ok(super::login::FIELDS)
    }

    fn deploy_login(&self) -> Result<Box<dyn crate::provider::DeployLogin>, Error> {
        Ok(Box::new(super::login::HttpLogin::new(self.host.clone())))
    }
}

impl TargetConfig for HttpConfig {
    fn provider(&self) -> &'static dyn Provider {
        self.provider
    }

    fn env_name(&self, _product: &str, key: &str) -> String {
        // The `[names]` table already spells the delivered env name, so the key is it.
        key.to_string()
    }

    fn target_locator(&self) -> String {
        let mut parts = vec![format!("host {}", self.target.host)];
        if let toml::Value::Table(table) = &self.target.list.request {
            let mut keys: Vec<&String> = table.keys().collect();
            keys.sort();
            for key in keys {
                parts.push(format!("{key} {}", table[key]));
            }
        }
        parts.join(" ")
    }

    fn store_name(&self, env_name: &str) -> String {
        self.target
            .names
            .get(env_name)
            .cloned()
            .unwrap_or_else(|| env_name.to_string())
    }

    fn name_rules(&self) -> NameRules {
        // The remote name is the application's own; the design states no pattern for it, so
        // only the delivered env name (the `[names]` key) is checked generically.
        NameRules {
            env_label: "HTTP env name",
            store: None,
        }
    }

    fn same_target(&self, other: &dyn TargetConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<HttpConfig>()
            .is_some_and(|o| self.target_locator() == o.target_locator())
    }

    fn shared_target_error(&self, first: &str, second: &str) -> String {
        format!(
            "environments {first} and {second} both write the HTTP target {}; each would \
             prune what the other stages",
            self.target_locator()
        )
    }

    /// Today: secrets written through the application's own API. Config is not delivered,
    /// and a file key goes on the secret channel by name (design §1.1).
    fn channels(&self) -> Channels {
        Channels {
            secret: Channel::Store {
                label: "HTTP target",
            },
            config: Channel::Declined {
                why: "the HTTP target delivers secrets only",
            },
            files: FileCapability::None,
        }
    }

    fn open<'a>(
        &'a self,
        _env: &'a str,
        _managed: BTreeSet<String>,
        _files: &BTreeMap<String, FileMount>,
        _config: &BTreeSet<String>,
        r: &'a dyn CommandRunner,
    ) -> Result<Ports<'a>, Error> {
        // The request host is the configuration's `http.host`; the item's `base_url` path
        // prefix is added by the sign-in (design §4.2) and is a known gap here.
        let destination = Destination {
            host: self.target.host.clone(),
            prefix: String::new(),
        };
        let store = HttpStore::new(r, self.pool.clone(), self.target.clone(), destination);
        Ok(Ports::Staged {
            store: Box::new(store),
            runtime: Box::new(HttpRuntime),
        })
    }

    fn preflight(&self, _r: &dyn CommandRunner, _mode: PreflightMode) -> Result<Preflight, Error> {
        Ok(Preflight::default())
    }

    fn doctor(&self, _r: &dyn CommandRunner, _host: &dyn Fn() -> Host) -> Vec<Check> {
        Vec::new()
    }

    fn explain(&self, _product: &str, key: &str) -> Vec<(&'static str, String)> {
        vec![
            ("http host", self.target.host.clone()),
            ("http env name", key.to_string()),
            ("http remote name", self.store_name(key)),
        ]
    }

    fn eq_dyn(&self, other: &dyn TargetConfig) -> bool {
        other
            .as_any()
            .downcast_ref::<HttpConfig>()
            .is_some_and(|o| self.target == o.target)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn clone_box(&self) -> Box<dyn TargetConfig> {
        Box::new(HttpConfig {
            target: self.target.clone(),
            pool: self.pool.clone(),
            provider: self.provider,
        })
    }
}

/// The per-host provider of `host`, interned so a process leaks at most one per distinct
/// host.
fn provider_for(host: &str) -> &'static HttpProvider {
    static CACHE: OnceLock<Mutex<BTreeMap<String, &'static HttpProvider>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(provider) = cache.get(host) {
        return provider;
    }
    let provider: &'static HttpProvider = Box::leak(Box::new(HttpProvider {
        host: host.to_string(),
    }));
    cache.insert(host.to_string(), provider);
    provider
}

/// The `FieldRule` for one `config::parse` rule string. `config::parse` reports a rule as
/// text (it never quotes a value); the loader's typed cause wants a `FieldRule`, so each
/// known rule maps to one and an unknown one falls back to a type error.
fn field_rule(rule: &str) -> FieldRule {
    match rule {
        "missing" | "missing or not a table" => FieldRule::Missing,
        "must be a table" | "request template must be a table" => FieldRule::Type {
            expected: "a table",
        },
        "must be an array" | "must be an array of strings" => FieldRule::Type {
            expected: "an array of strings",
        },
        "must be a string" | "remote name must be a string" => FieldRule::Type {
            expected: "a string",
        },
        "must be an integer" => FieldRule::Type {
            expected: "an integer",
        },
        "must be a number" => FieldRule::Type {
            expected: "a number",
        },
        "must be a boolean" => FieldRule::Type {
            expected: "a boolean",
        },
        "must be a value of the enum" => FieldRule::Type {
            expected: "a value of the enum",
        },
        "not a gRPC status name" => FieldRule::Type {
            expected: "a gRPC status name",
        },
        "type must be string or bytes" => FieldRule::Type {
            expected: "string or bytes",
        },
        "method not found in descriptor" => FieldRule::Type {
            expected: "a method in the pinned descriptor",
        },
        "value field number does not match the descriptor" => FieldRule::Type {
            expected: "the descriptor's field number",
        },
        "value field type does not match the descriptor" => FieldRule::Type {
            expected: "the descriptor's field type",
        },
        "value field must be a singular string or bytes field" => FieldRule::Type {
            expected: "a singular string or bytes field",
        },
        "value field not found in the request message" => FieldRule::Type {
            expected: "a field of the request message",
        },
        "unknown field in request template" => FieldRule::Type {
            expected: "a field of the request message",
        },
        "request template may not set the value field" => FieldRule::Type {
            expected: "a request template that leaves the value field to opv",
        },
        "items must be a repeated message field" => FieldRule::Type {
            expected: "a repeated message field",
        },
        "reply must be a message field" => FieldRule::Type {
            expected: "a message field",
        },
        "path not found in the entry message" => FieldRule::Type {
            expected: "a field path in the entry message",
        },
        "items path not found in the reply message" | "reply path not found in the reply message" => {
            FieldRule::Type {
                expected: "a field path in the reply message",
            }
        }
        "status value is not a value of the status enum" => FieldRule::Type {
            expected: "a value of the status enum",
        },
        "remote name must not be empty" => FieldRule::Empty,
        "must map at least one name" => FieldRule::Empty,
        "descriptor_sha256 does not match the descriptor file" => FieldRule::Type {
            expected: "the pinned descriptor file",
        },
        "must be a lowercase ASCII hostname, not a URL, IP literal, port or trailing dot" => {
            FieldRule::Type {
                expected: "a lowercase ASCII hostname",
            }
        }
        other if other.starts_with("descriptor could not be read") => FieldRule::Type {
            expected: "a readable descriptor file",
        },
        other if other.starts_with("two env names map to one remote name") => FieldRule::Type {
            expected: "one remote name per env name",
        },
        _ => FieldRule::Type {
            expected: "a value the http target accepts",
        },
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
