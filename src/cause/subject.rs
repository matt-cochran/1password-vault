//! Typed subjects of a [`Cause`](super::Cause): what a failure is about (design
//! `docs/design/error-catalog.md` §2, §4). Every field is a name, an ID, a path, a number or
//! a closed enum, never free text from outside opv. Each name type is distinct, so a vault ID
//! can never be passed where an environment is meant (audit 07.10).

use std::fmt;
use std::path::PathBuf;

/// A name or ID that opv validated at its source (configuration, a typed flag, a parsed
/// reply), shown as it is. Distinct types per kind; the inner text is never a value.
macro_rules! name_type {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {$(
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wrap a name opv already validated at its source.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    )*};
}

name_type!(
    /// An environment declared in the configuration.
    EnvName,
    /// A deployment target of an environment.
    TargetName,
    /// A declared product.
    ProductName,
    /// A key name (`OPENAI_API_KEY`), never its value.
    KeyName,
    /// A process role (`serve`, `migrate`).
    RoleName,
    /// A remote execution profile (#139).
    ProfileName,
    /// A 1Password vault ID.
    VaultId,
    /// A 1Password item ID.
    ItemId,
    /// A 1Password account ID (never an email in rendered evidence).
    AccountId,
    /// A plan id (`sp-…` or a sync plan id).
    PlanId,
    /// A provider resource name (app, Key Vault, namespace, repository, context).
    ResourceName,
    /// An environment variable name (never its value).
    VarName,
    /// A field of a 1Password item or a configuration field label.
    FieldName,
);

/// How a person refers to an account they named: by ID, email or shorthand.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "by", content = "value", rename_all = "snake_case")]
pub enum AccountRef {
    Id(AccountId),
    Email(String),
    Shorthand(String),
    /// No account was named: the person is adding one, or none is on this machine.
    Unnamed,
    /// No 1Password account at all is on this machine: any account will do.
    Any,
}

/// Where the account in effect was chosen (`Argument`: a positional argument, as in
/// `opv account use <who>`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum AccountSource {
    DotOpv { path: PathBuf },
    EnvVar { var: VarName },
    Flag,
    Environment { env: EnvName },
    OpDefault,
    Argument,
}

/// An external system opv talks to (each has one diagnosis strategy, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum System {
    OnePassword,
    Fly,
    Azure,
    Kubernetes,
    GitHub,
    Ssh,
    /// opv on a remote host (#139).
    RemoteOpv,
}

impl System {
    /// How messages name it.
    pub fn label(self) -> &'static str {
        match self {
            System::OnePassword => "1Password",
            System::Fly => "Fly",
            System::Azure => "Azure",
            System::Kubernetes => "Kubernetes",
            System::GitHub => "GitHub",
            System::Ssh => "ssh",
            System::RemoteOpv => "opv on the remote host",
        }
    }
}

/// A position in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Location {
    pub line: u32,
    pub col: u32,
}

/// A dotted configuration path (`environments.prod.targets.web.fly.app`), as the validator
/// names it (never parsed back from a line, 03.01).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct DottedPath(pub Vec<String>);

impl fmt::Display for DottedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("."))
    }
}

/// Where the configuration came from (X16: messages are source-aware).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigSource {
    File {
        path: PathBuf,
        given_by: GivenBy,
    },
    Manifest {
        title: String,
        vault: VaultId,
        project: String,
    },
}

/// How a path or value reached opv.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "via", rename_all = "snake_case")]
pub enum GivenBy {
    Flag { flag: String },
    EnvVar { var: VarName },
    Discovered,
}

/// What kind of declared name a `NotDeclared`/`Ambiguous` is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    Environment,
    Target,
    Product,
    Key,
    Role,
    RemoteProfile,
    Mode,
    HelpTopic,
}

/// A unique close match for a misspelt name. Only [`Closest::unique`] builds one, from a
/// candidate list in which exactly one name is close (X2: never a guessed candidate).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct Closest(String);

impl Closest {
    /// `Some` only when exactly one of `close` was found close to the given name.
    pub fn unique(close: &[&str]) -> Option<Self> {
        match close {
            [one] => Some(Self((*one).to_string())),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A resource at a provider or in 1Password.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ResourceRef {
    pub kind: ResourceKind,
    pub name: ResourceName,
    /// Where it lives: account, subscription, kube context and namespace, repository.
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Vault,
    Item,
    PersonalVault,
    FlyApp,
    KeyVault,
    ContainerApp,
    Namespace,
    Deployment,
    KubeContext,
    Repository,
    GitHubEnvironment,
    ExternalStore,
    /// A secret in a Key Vault (`scope`: the vault's name).
    KeyVaultSecret,
    /// An Azure subscription.
    Subscription,
}

/// Who acted: the advice addresses this principal (X22).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    Person {
        account: Option<AccountId>,
    },
    ServiceAccount {
        name: String,
    },
    ServicePrincipal {
        client_id: String,
    },
    AppIdentity {
        name: String,
    },
    StoreIdentity {
        name: String,
    },
    DeployCredentials {
        item: ItemId,
        env: EnvName,
        target: TargetName,
    },
    ShellToken {
        var: VarName,
    },
}

/// A right that was missing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Right {
    Read,
    Write,
    Edit,
    List,
    Manage,
    CreateServiceAccount,
    EnvironmentsWrite,
    SecretsWrite,
    /// A Kubernetes verb on a resource kind (`create secrets`).
    Verb {
        verb: String,
        resource: String,
    },
}

/// How a missing right is granted, so the Do names the exact grant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum GrantModel {
    Rbac {
        role: String,
        scope: String,
    },
    AccessPolicy {
        permissions: Vec<String>,
    },
    NetworkRule,
    VaultPermission,
    RepoPermission,
    K8sRbac {
        verb: String,
        resource: String,
        namespace: Option<String>,
    },
    OnePasswordRole,
}

/// A credential opv used, by reference (never its value).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialRef {
    ServiceAccountToken {
        var: VarName,
    },
    Connect {
        host_var: VarName,
        token_var: VarName,
    },
    DeployCredentials {
        vault: VaultId,
        item: ItemId,
        env: EnvName,
        target: TargetName,
    },
    /// A token in the shell that overrides a vendor sign-in (FLY_API_TOKEN, GH_TOKEN, …).
    ShellToken {
        var: VarName,
    },
    StoreAuth {
        store: ResourceName,
    },
    /// An SSH private key a remote profile names (`identity_file`); `None`: the SSH agent.
    SshIdentity {
        path: Option<PathBuf>,
    },
}

/// An object whose edit can conflict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreObject {
    File {
        path: PathBuf,
    },
    Manifest {
        title: String,
        vault: VaultId,
    },
    Item {
        vault: VaultId,
        item: ItemId,
    },
    /// A target's object (a deployment) that changed before opv's write.
    Resource {
        resource: ResourceRef,
    },
}

/// What a non-idempotent create makes (X5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateKind {
    Vault,
    Item,
    ItemWithSecrets,
    Manifest,
    ServiceAccount,
    DeployToken,
    GitHubEnvironment,
}

impl CreateKind {
    /// True when the created object carries a secret, so an orphan must be revoked.
    pub fn secret_bearing(self) -> bool {
        matches!(
            self,
            CreateKind::ItemWithSecrets | CreateKind::ServiceAccount | CreateKind::DeployToken
        )
    }
}

/// A command opv itself implements, named in messages.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct CommandId(pub String);

/// A product's key, as `--rotate` names it (`PRODUCT/KEY`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProductKey {
    pub product: ProductName,
    pub key: KeyName,
}

impl fmt::Display for ProductKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.product, self.key)
    }
}

/// What a plan covers, so an approval handoff and the read that replaces a used or changed
/// plan carry every scope flag the plan was made with (X1: never a dropped `--target`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanScope {
    /// A deployment (sync) plan of one environment.
    Sync {
        env: EnvName,
        targets: Vec<TargetName>,
        product: Option<ProductName>,
        deploy: bool,
        prune: bool,
        rotate: Vec<ProductKey>,
    },
    /// A structural plan (`opv structure plan`).
    Structural,
}

/// Where the name of a resource that was not found came from, so the Do says where to fix it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum NamedBy {
    /// A configuration field (`environments.prod.targets.web.fly.app`).
    ConfigField { path: DottedPath },
    /// A command-line flag (`--fly-app`).
    Flag { flag: String },
}

/// A configuration naming rule (§4.12). Each has plain words ([`PatternId::words`]); a
/// regular expression is never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternId {
    /// `[stores.<name>]`.
    StoreName,
    /// A target name (FR-56).
    TargetName,
    /// A product name, and a boundary name.
    ProductName,
    /// Vault, item and state vault IDs, and app names that go into argv.
    Id,
    /// A key name, and every name a target renders (an environment variable name).
    KeyName,
    /// A process role.
    RoleName,
    /// A remote profile's name.
    RemoteName,
    /// A remote profile's host.
    RemoteHost,
    /// A remote profile's user.
    RemoteUser,
    /// A remote profile's pinned path (command, workdir, opv path).
    RemotePath,
    /// A remote profile's `host_key`.
    HostKey,
    /// A key's `file` under `[products.<p>.local]`.
    LocalFile,
    /// An environment's 1Password `account`.
    Account,
}

impl PatternId {
    /// The rule in plain words, as a reader would say it.
    pub fn words(self) -> &'static str {
        match self {
            PatternId::StoreName => {
                "lower-case letters, digits and -, starting and ending with a letter or digit, at most 63 characters"
            }
            PatternId::TargetName => "lower-case letters, digits and -, starting with a letter",
            PatternId::ProductName => "lower-case letters, digits, _ and -, starting with a letter",
            PatternId::Id => "letters, digits, ., _ and -, starting with a letter or digit",
            PatternId::KeyName => "upper-case letters, digits and _, starting with a letter",
            PatternId::RoleName => "1 to 32 lower-case letters, digits and -",
            PatternId::RemoteName => {
                "lower-case letters, digits and -, starting with a letter, at most 32 characters"
            }
            PatternId::RemoteHost => {
                "a host name or address: letters, digits, ., - and :, not starting with -"
            }
            PatternId::RemoteUser => {
                "lower-case letters, digits, _, . and -, starting with a letter or _, at most 32 characters"
            }
            PatternId::RemotePath => {
                "an absolute path of letters, digits, ., _, /, + and -, without .."
            }
            PatternId::HostKey => "the host's public key, as <type> <base64>",
            PatternId::LocalFile => {
                "a relative path of at most four parts separated by /, each of lower-case letters and digits with - only between them"
            }
            PatternId::Account => {
                "a 1Password sign-in address (my.1password.com), an email or an account ID"
            }
        }
    }
}
