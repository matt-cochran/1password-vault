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
}

/// Where the account in effect was chosen.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum AccountSource {
    DotOpv { path: PathBuf },
    EnvVar { var: VarName },
    Flag,
    Environment { env: EnvName },
    OpDefault,
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
    File { path: PathBuf },
    Manifest { title: String, vault: VaultId },
    Item { vault: VaultId, item: ItemId },
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
