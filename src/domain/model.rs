//! Fleet configuration model (§10.2). Holds names, IDs and rules; never values (FR-1).
//!
//! Since 0.7.0 (FR-24, FR-60) there is one way to write each rule: the `pattern` rule is
//! removed and a file that sets it fails at load (see `crate::config`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::provider::TargetConfig;

/// Field kind. In 1Password a concealed field is a secret and a text field is config (FR-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Secret,
    Config,
}

/// Declarative validation rules for one key (FR-15). Every rule is optional.
/// Evaluated by the rules engine (`domain::rules`); this type only carries them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub prefix: Option<String>,
    pub not_prefix: Option<OneOrMany>,
    /// Accept the value with or without this prefix and stage exactly one occurrence (FR-24).
    pub ensure_prefix: Option<String>,
    pub regex: Option<String>,
    #[serde(rename = "enum")]
    pub r#enum: Option<Vec<String>>,
    pub base64_bytes: Option<usize>,
    pub hex_bytes: Option<usize>,
    pub email_list: bool,
    pub https_url: bool,
    pub prefix_by_mode: Option<PrefixByMode>,
    pub refuse_in: Vec<String>,
    pub transform: Option<String>,
}

/// A string or a list of strings in TOML (`x = "a"` or `x = ["a", "b"]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        let (one, many): (Option<&str>, &[String]) = match self {
            Self::One(s) => (Some(s.as_str()), &[]),
            Self::Many(v) => (None, v.as_slice()),
        };
        one.into_iter().chain(many.iter().map(String::as_str))
    }

    /// True when the value starts with any listed prefix.
    pub fn any_prefix_of(&self, v: &str) -> bool {
        self.iter().any(|p| v.starts_with(p))
    }

    /// Config validation: at least one entry, none empty.
    pub fn is_valid(&self) -> bool {
        self.iter().next().is_some() && self.iter().all(|s| !s.is_empty())
    }
}

/// Required prefix chosen by an environment mode, e.g. `payments = "test"` → `sk_test_`.
/// Modes listed in `skip` mean the key is not required in that environment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixByMode {
    pub mode: String,
    pub values: BTreeMap<String, OneOrMany>,
    #[serde(default)]
    pub skip: Vec<String>,
}

/// One declared key of a product.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeySpec {
    pub kind: Kind,
    pub environments: Vec<String>,
    #[serde(default)]
    pub rules: Rules,
    /// Staged only when absent on the target unless explicitly rotated (FR-16).
    #[serde(default)]
    pub immutable: bool,
    #[serde(default)]
    pub guidance: String,
    /// Shared key (FR-45): `"<product>/<KEY>"` names the key whose field holds the value, in
    /// the source product's boundary item of the same environment (FR-57). The key then has
    /// no field of its own. Validated at load: see [`KeySpec::source`].
    #[serde(default)]
    pub from: Option<String>,
    /// Personal key (FR-55): each person keeps their own value in their own item (a
    /// developer's own LLM API key); only in environments without a target.
    #[serde(default)]
    pub personal: bool,
    /// The same value in several environments is intended (#92): silences the
    /// `same_value_across_environments` health finding for this key.
    #[serde(default)]
    pub allow_same_value: bool,
    /// Local file delivery (#136): under `opv run`, the value is a file at this relative
    /// path (`github-app/private-key`) in the product's private secrets directory
    /// ([`Local::secrets_dir_env`]) instead of a variable. Targets are unaffected.
    #[serde(default)]
    pub file: Option<String>,
    /// Process roles (#136): under `opv run`, the key is delivered only when `--role`
    /// names one of these (and never to a run without `--role`). Absent: delivered to
    /// every role. An empty list fails at load; each name matches `^[a-z0-9-]{1,32}$`.
    /// Roles apply to local `run` delivery only, never to sync or a target.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

impl KeySpec {
    /// The source `(product, key)` of a shared key (FR-45), or `None` for a key with its
    /// own field. `from` is always `"<product>/<KEY>"` (FR-60: a bare `"<KEY>"` fails at
    /// load). Only meaningful after `config` validated the reference.
    pub fn source(&self) -> Option<(&str, &str)> {
        self.from.as_deref()?.split_once('/')
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// Canonical values only (FR-47): its keys render no target name anywhere, are never
    /// written, managed or pruned, and `run --product <name>` refuses it. Default `false`.
    #[serde(default)]
    pub source_only: bool,
    /// The access boundary this product's values live in (FR-57): a group name shared by
    /// several products (`boundary = "<group>"`). `None`: the product is its own boundary.
    /// See [`Fleet::boundary_of`].
    #[serde(default)]
    pub boundary: Option<String>,
    /// Declared keys. Defaulted so a source-only product without keys reaches validation's
    /// own error (FR-47) instead of a bare serde `missing field` message.
    #[serde(default)]
    pub keys: BTreeMap<String, KeySpec>,
    /// How `opv run` delivers this product's values locally (#136, #137); `None`: every
    /// key as a variable in the inherited environment.
    #[serde(default)]
    pub local: Option<Local>,
    /// Reviewed remote execution profiles (#139): `opv run --remote <name>` delivers this
    /// product's selected keys to the pinned host over SSH and runs the pinned command
    /// there. Empty: the product has no remote delivery.
    #[serde(default)]
    pub remotes: BTreeMap<String, Remote>,
}

/// `[products.<p>.remotes.<name>]`: one reviewed remote execution profile (#139). Every
/// field is pinned in the configuration; nothing about the host, the transport or the
/// command can be chosen at run time, from the command line or from MCP.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    /// The SSH host name or address.
    pub host: String,
    /// The SSH port. Default 22.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// The remote account the app runs as.
    pub user: String,
    /// The host's public key, pinned (`<type> <base64>`, as in `known_hosts`). The
    /// connection fails unless the host presents exactly this key.
    pub host_key: String,
    /// The environments whose values may go to this host. At least one.
    pub environments: Vec<String>,
    /// The process roles that may run there; `None`: every role the product declares.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    /// The absolute path of the opv binary on the remote host.
    pub opv: String,
    /// The absolute working directory on the remote host.
    pub workdir: String,
    /// The pinned command and its arguments.
    pub command: Vec<String>,
    /// A local SSH private key file to authenticate with; `None`: the SSH agent.
    #[serde(default)]
    pub identity_file: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

/// `[products.<p>.local]`: local delivery under `opv run` (#136, #137).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    /// `inherit` (the default) or `declared_only`: the app's environment is the product's
    /// declared keys and a fixed set of basics (PATH, HOME, locale, terminal), nothing else
    /// inherited (#137: a Worker's bindings stay the declared scope).
    #[serde(default)]
    pub environment: LocalEnvironment,
    /// The variable naming the private directory that holds the keys with `file` (#136).
    #[serde(default)]
    pub secrets_dir_env: Option<String>,
}

/// What `opv run` passes on from the environment it was started in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEnvironment {
    #[default]
    Inherit,
    DeclaredOnly,
}

/// One recorded access boundary of an environment (FR-57): the vault holding exactly one
/// opv values item, and that item, by IDs (FR-13). Written by `opv bootstrap`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Boundary {
    pub vault_id: String,
    pub item_id: String,
}

/// One named deployment target of an environment (FR-56): one provider's options, the
/// products it delivers, its deploy identity and its state vault.
#[derive(Debug)]
pub struct Target {
    /// The target's name in the configuration (`^[a-z][a-z0-9-]*$`, chosen by a person).
    pub name: String,
    /// The provider's validated section (FR-28, FR-37).
    pub config: Box<dyn TargetConfig>,
    /// The products this target delivers (FR-48); `None`: every non-source-only product
    /// with a key desired in the environment. See [`Fleet::delivers`].
    pub products: Option<Vec<String>>,
    /// The item holding this target's least-privilege deploy identity (FR-40), read by
    /// `status`, `plan` and `sync` to sign the target CLI in for the run only.
    pub deploy_credentials: Option<ItemRef>,
    /// The vault holding this target's delivery evidence (FR-58, D12): one item per
    /// placement, written by the deploy identity after a confirmed sync. Required.
    pub state_vault_id: String,
    /// product → the ID of its placement's delivery item in the state vault
    /// (`delivery_items`, FR-58), recorded by `opv bootstrap` when it creates the item, so
    /// nothing looks a state item up by title (FR-13). A product with none has no evidence.
    pub delivery_items: BTreeMap<String, String>,
}

// By hand: a derive compares and clones `Box<dyn TargetConfig>` through the box's
// contents, which a trait object cannot be moved out of.
impl PartialEq for Target {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.config.eq_dyn(other.config.as_ref())
            && self.products == other.products
            && self.deploy_credentials == other.deploy_credentials
            && self.state_vault_id == other.state_vault_id
            && self.delivery_items == other.delivery_items
    }
}

impl Eq for Target {}

impl Clone for Target {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            config: self.config.clone_box(),
            products: self.products.clone(),
            deploy_credentials: self.deploy_credentials.clone(),
            state_vault_id: self.state_vault_id.clone(),
            delivery_items: self.delivery_items.clone(),
        }
    }
}

/// One deployment environment: its access boundaries (FR-57) and its named targets
/// (FR-56). An environment with no target is run-only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// The environment's name in the configuration (for messages: `opv login <name>`).
    pub name: String,
    /// boundary name → recorded vault and item (FR-57); see [`Fleet::boundary`].
    pub boundaries: BTreeMap<String, Boundary>,
    /// target name → target (FR-56), in name order.
    pub targets: BTreeMap<String, Target>,
    /// product → mode name → mode value, e.g. `allumata.payments = "off"`.
    pub modes: BTreeMap<String, BTreeMap<String, String>>,
    /// `confirm_env = true`: `sync` refuses without `--confirm <env>` (NR-20).
    pub confirm_env: bool,
    /// The 1Password account every `op` call for this environment uses (FR-40): a sign-in
    /// address or account ID. `None`: op's default (or the service account in CI).
    pub account: Option<String>,
    /// The `.opv` file the account in [`Environment::account`] came from, when the
    /// configuration named none (FR-40). The diagnosis then names that file, not the
    /// environment; `None` means the account was declared in the configuration.
    pub account_from: Option<PathBuf>,
    /// Display name for people (`opv ui`, `ready`); the key stays `name` (FR-55).
    pub title: Option<String>,
    /// Who the environment is for (free text, e.g. `devops`): a person who cannot open it is
    /// told so, not shown an error (FR-55).
    pub audience: Option<String>,
    /// Display order in grids; `None`: configuration order (FR-55).
    pub order: Option<i64>,
    /// Title of the vault holding each person's personal item (FR-55); `None`: the person's
    /// own Private (Employee) vault.
    pub personal_vault: Option<String>,
    /// Title of each person's personal item (FR-55); `None`: the shared item's title plus
    /// ` (personal)`.
    pub personal_item: Option<String>,
}

impl Environment {
    /// The display name: [`Environment::title`], else the key.
    pub fn display(&self) -> &str {
        self.title.as_deref().unwrap_or(&self.name)
    }
}

/// An `op://<vault>/<item>` reference to a whole item, by IDs or names (FR-40).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub vault: String,
    pub item: String,
}

impl std::fmt::Display for ItemRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "op://{}/{}", self.vault, self.item)
    }
}

impl ItemRef {
    /// Parse `op://<vault>/<item>`: exactly a vault and an item, each non-empty, unpadded,
    /// free of control characters and not starting with `-` (safe as an argument). A field,
    /// a query (`?attribute=`) or any other form is refused with the reason.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let rest = s
            .strip_prefix("op://")
            .ok_or("must be an op://<vault>/<item> reference")?;
        if rest.contains('?') {
            return Err("must name an item, without a query (op://<vault>/<item>)");
        }
        let parts: Vec<&str> = rest.split('/').collect();
        let [vault, item] = parts.as_slice() else {
            return Err("must name exactly a vault and an item (op://<vault>/<item>), not a field");
        };
        for part in [vault, item] {
            if part.is_empty() {
                return Err("needs a non-empty vault and item (op://<vault>/<item>)");
            }
            if part.trim() != *part {
                return Err("has leading or trailing whitespace in the vault or item");
            }
            if part.starts_with('-') || part.chars().any(char::is_control) {
                return Err("vault and item may not start with - or hold control characters");
            }
        }
        Ok(Self {
            vault: (*vault).to_string(),
            item: (*item).to_string(),
        })
    }
}

/// The user-facing name of `product`/`key`: `product/KEY` (FR-20 removed, FR-60).
pub fn key_label(product: &str, key: &str) -> String {
    format!("{product}/{key}")
}

/// `product`'s boundary not being recorded in `env` (FR-57, audit 03.02): the catalog cause,
/// whose Next is source-aware (`opv bootstrap` for a file, the structure plan for a
/// manifest).
pub fn boundary_missing(
    env: &str,
    product: &str,
    source: crate::cause::ConfigSource,
) -> crate::cause::Cause {
    crate::cause::Cause::BoundaryMissing {
        env: crate::cause::EnvName::new(env),
        product: crate::cause::ProductName::new(product),
        source,
    }
}

/// Where a [`Fleet`] was read from, for the causes it reports (X16). Wording only: two fleets
/// read from different places compare equal when they say the same.
#[derive(Debug, Clone)]
pub struct ReadFrom(pub crate::cause::ConfigSource);

impl PartialEq for ReadFrom {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for ReadFrom {}

impl Default for ReadFrom {
    /// A text parsed without a source: named as `secrets.toml`, the file it stands for.
    fn default() -> Self {
        Self(crate::cause::ConfigSource::File {
            path: "secrets.toml".into(),
            given_by: crate::cause::GivenBy::Discovered,
        })
    }
}

/// A validated configuration. Build it with `config::load` or `config::parse`. There is one
/// form (FR-60): products, boundaries and named targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fleet {
    pub environments: BTreeMap<String, Environment>,
    pub products: BTreeMap<String, Product>,
    /// Where the configuration was read from, for wording only (FR-44).
    pub origin: Origin,
    /// The configuration's source, for the causes a later lookup reports (X16).
    pub read_from: ReadFrom,
}

/// Where a configuration was read from (FR-44). Wording only: the plan id and every other
/// result depend on what the configuration says, never on where it lives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Origin {
    /// A `secrets.toml` (or `--config`) file.
    #[default]
    File,
    /// A project manifest in 1Password.
    Manifest,
}

impl Origin {
    /// How messages name it: `secrets.toml` or `the manifest`.
    pub fn noun(self) -> &'static str {
        match self {
            Origin::File => "secrets.toml",
            Origin::Manifest => "the manifest",
        }
    }
}

impl Fleet {
    /// Look up an environment by a (possibly user-supplied) name.
    ///
    /// An unknown name is [`crate::cause::Cause::NotDeclared`]: it lists the declared ones,
    /// and its step substitutes only a unique close match (X2, audit 03.02).
    pub fn environment(&self, env: &str) -> Result<&Environment, Error> {
        self.environments.get(env).ok_or_else(|| {
            let known: Vec<&str> = self.environments.keys().map(String::as_str).collect();
            let close = crate::app::suggest::close(env, known.iter().copied());
            crate::cause::Cause::NotDeclared {
                kind: crate::cause::NameKind::Environment,
                given: env.to_string(),
                candidates: known.iter().map(|k| k.to_string()).collect(),
                closest: crate::cause::Closest::unique(&close),
            }
            .into()
        })
    }

    /// The declared keys of `product` that are sources of shared keys (FR-45): each
    /// `(source product, source key)` a key of `product` reads its value from. Empty for an
    /// undeclared product.
    pub fn sources_of(&self, product: &str) -> std::collections::BTreeSet<(String, String)> {
        self.products
            .get(product)
            .into_iter()
            .flat_map(|p| p.keys.values())
            .filter_map(KeySpec::source)
            .map(|(p, k)| (p.to_string(), k.to_string()))
            .collect()
    }

    /// The keys declared for `env_name` that share the value of `product`/`key` (FR-45), as
    /// `(product, key)`.
    pub fn shared_by(&self, env_name: &str, product: &str, key: &str) -> Vec<(String, String)> {
        self.products
            .iter()
            .flat_map(|(p, prod)| prod.keys.iter().map(move |(k, s)| (p, k, s)))
            .filter(|(_, _, s)| {
                s.source() == Some((product, key)) && s.environments.iter().any(|e| e == env_name)
            })
            .map(|(p, k, _)| (p.clone(), k.clone()))
            .collect()
    }

    /// The access boundary `product`'s values live in (FR-57): its `boundary`, else its own
    /// name.
    pub fn boundary_of<'a>(&'a self, product: &'a str) -> &'a str {
        self.products
            .get(product)
            .and_then(|p| p.boundary.as_deref())
            .unwrap_or(product)
    }

    /// Every boundary `env` needs (FR-57, FR-55), each with the product that first needs it:
    /// the boundary of each product with a team (non-personal) key desired in `env`, and of
    /// every source such a key reads with `from`. Personal keys live in each person's own
    /// item, so a product whose keys in `env` are all personal needs none. The one rule the
    /// loader, the tidy and every reader use.
    pub fn needed_boundaries<'a>(&'a self, env: &str) -> BTreeMap<&'a str, &'a str> {
        let mut out = BTreeMap::new();
        for (product, p) in &self.products {
            let team: Vec<&KeySpec> = p
                .keys
                .values()
                .filter(|k| !k.personal && k.environments.iter().any(|e| e == env))
                .collect();
            if team.is_empty() {
                continue;
            }
            let sources = team.iter().filter_map(|k| k.source()).map(|(sp, _)| sp);
            for needer in std::iter::once(product.as_str()).chain(sources) {
                out.entry(self.boundary_of(needer)).or_insert(needer);
            }
        }
        out
    }

    /// The recorded boundary of `product` in `env` (FR-57): the vault and item its values
    /// live in. An undefined environment is [`Fleet::environment`]'s error; a boundary not
    /// recorded is `boundary_missing` (load refuses that for every product with a key
    /// desired in the environment, so only an undesired product reaches it).
    pub fn boundary(&self, env: &str, product: &str) -> Result<&Boundary, Error> {
        let name = self.boundary_of(product);
        self.environment(env)?
            .boundaries
            .get(name)
            .ok_or_else(|| boundary_missing(env, product, self.read_from.0.clone()).into())
    }

    /// Target name (runtime env var name) for `product`/`key` on target `target` of `env`.
    ///
    /// # Panics
    /// If `env` is not a defined environment with that target. Callers resolve it first.
    pub fn target_name(&self, env: &str, target: &str, product: &str, key: &str) -> String {
        match self
            .environments
            .get(env)
            .and_then(|e| e.targets.get(target))
        {
            Some(t) => t.config.env_name(product, key),
            None => panic!("target_name: environment {env:?} has no target {target:?}"),
        }
    }

    /// Whether target `target` of `env` delivers keys of `product` (FR-47, FR-48, FR-56):
    /// never a source-only or undeclared product; a target with `products` delivers exactly
    /// those; one without delivers every product with a key desired in `env`. An
    /// undelivered product's keys render no target name there: never written, never in the
    /// managed set, never pruned and exempt from the name collision check.
    pub fn delivers(&self, env: &str, target: &str, product: &str) -> bool {
        let Some(t) = self
            .environments
            .get(env)
            .and_then(|e| e.targets.get(target))
        else {
            return false;
        };
        let Some(p) = self.products.get(product) else {
            return false;
        };
        if p.source_only {
            return false;
        }
        match &t.products {
            Some(listed) => listed.iter().any(|l| l == product),
            None => p
                .keys
                .values()
                .any(|k| k.environments.iter().any(|e| e == env)),
        }
    }

    /// The first product (by name) that reads any key of `product` with `from` (FR-45), or
    /// `None`. Used to point at a runnable product when `product` is source-only (FR-47).
    pub fn referencing_product(&self, product: &str) -> Option<&str> {
        self.products.iter().find_map(|(q, p)| {
            p.keys
                .values()
                .any(|k| k.source().is_some_and(|(sp, _)| sp == product))
                .then_some(q.as_str())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_label_always_names_the_product() {
        assert_eq!(key_label("api", "JWT_KEY"), "api/JWT_KEY");
    }
}
