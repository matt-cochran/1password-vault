//! The configuration checks between fields (design §4.12, audit 03.01): what the validator
//! checked, typed, so the problem and the fix are words filled from the check and the field
//! the validator named, never derived from a message or a line. Each check is
//! [`super::FieldRule::Check`]; names only, never a value.

use super::PatternId;

/// Which declared name a configuration value refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Declared {
    Environment,
    Product,
    Key,
    Role,
    Store,
    /// A `[producers.X]` of the contract (#253).
    Producer,
}

impl Declared {
    fn noun(self) -> &'static str {
        match self {
            Declared::Environment => "environment",
            Declared::Product => "product",
            Declared::Key => "key",
            Declared::Role => "role",
            Declared::Store => "store",
            Declared::Producer => "producer",
        }
    }
}

/// Why a rendered store name is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum StoreNameProblem {
    Empty,
    TooLong { len: usize, max: usize },
    Character,
    Edge,
}

/// A check the configuration validator makes (§4.12).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum ConfigCheck {
    /// The value names something that is not declared.
    Undeclared {
        kind: Declared,
        name: String,
        declared: Vec<String>,
        /// The unique close declared name, when there is one.
        closest: Option<String>,
    },
    /// The value is outside a closed set (`kind = "secert"`).
    NotOneOf {
        allowed: Vec<String>,
        closest: Option<String>,
    },
    /// Leading or trailing whitespace.
    Whitespace,
    /// `products = []` on a target.
    EmptyProducts,
    /// `roles = []` on a key.
    EmptyRoles,
    /// `roles = []` on a remote profile.
    EmptyRemoteRoles,
    /// `environments = []` on a remote profile.
    EmptyRemoteEnvironments,
    /// A remote profile names an environment that has a deployment target (O9): its values
    /// must reach the host only through the CI sync, so a profile may name only target-less
    /// environments.
    RemoteEnvironmentHasTarget {
        profile: String,
        env: String,
        target: String,
    },
    /// A key with `file` under a target whose `config = "env"` delivers config as
    /// environment variables: only a config object (a ConfigMap) can carry a file.
    ConfigFileNeedsObject { key: String },
    /// A target with no provider section.
    NoProvider { known: Vec<String> },
    /// A store with no kind.
    NoStoreKind { known: Vec<String> },
    /// `secrets_in` names a store the provider cannot keep its secrets in.
    StoreBinding {
        section: String,
        kind: String,
        supported: Vec<String>,
    },
    /// `deploy_credentials` is not an `op://<vault>/<item>` reference.
    DeployCredentialsRef,
    /// The target's provider signs in without `deploy_credentials`.
    DeployCredentialsUnsupported { provider: String },
    /// `source_only = true` on a product without keys.
    SourceOnlyWithoutKeys { product: String },
    /// A target lists a source-only product.
    SourceOnlyListed { product: String },
    /// A recorded boundary no product with a key in the environment lives in. `products`
    /// are the products that live in it (their keys are not declared for `env`).
    BoundaryUnused { env: String, products: Vec<String> },
    /// A delivery item for a product the target does not deliver.
    DeliveryItemUndelivered { product: String },
    /// A personal key declared for an environment with a deployment target.
    PersonalOnTarget { env: String },
    /// A personal key reads a team value, or a team key a personal value.
    PersonalMix { source: String, personal: bool },
    /// `from` crosses environments.
    FromCrossEnvironment,
    /// `from` is not `"<product>/<KEY>"`.
    FromShape,
    /// `from` names the key itself.
    FromSelf,
    /// `from` names a key that is shared from this one.
    FromCycle { source: String },
    /// `from` names a key that is itself shared.
    FromChain { source: String, its_from: String },
    /// `from` names a key of the other kind.
    FromKind {
        source: String,
        source_kind: &'static str,
        kind: &'static str,
    },
    /// `from` names a key not declared for an environment this key uses.
    FromEnvironment { source: String, env: String },
    /// `refuse_in` refuses an environment the source provides the value in.
    FromRefused { source: String, env: String },
    /// `local.secrets_dir_env` is set but no key has a `file`.
    DirEnvWithoutFiles,
    /// A remote command argument is too long or holds control characters.
    CommandArguments,
    /// Two targets of one environment deliver to the same place.
    SameTarget {
        label: String,
        locator: String,
        other: String,
        /// The shared place is a job a target lists as a companion (#252); absent from the
        /// JSON when false.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        job: bool,
    },
    /// Targets of two environments manage the same names in one place.
    SharedAcrossEnvironments {
        label: String,
        locator: String,
        other_env: String,
        other_target: String,
        /// The shared place is a job a target lists as a companion (#252), which no
        /// template can tell apart; absent from the JSON when false.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        job: bool,
    },
    /// The template renders a name the target cannot hold.
    RenderedName {
        owner: String,
        label: String,
        rendered: String,
        pattern: PatternId,
    },
    /// The template renders a store name the store cannot hold.
    RenderedStoreName {
        owner: String,
        label: String,
        problem: StoreNameProblem,
    },
    /// Two keys of one target render the same name.
    NameTaken {
        owner: String,
        other: String,
        label: String,
        name: String,
    },
    /// Two environments keep the same name in one store.
    StoreShared {
        owner: String,
        label: String,
        name: String,
        store: String,
        other_env: String,
        other_owner: String,
    },
    // provision (#253, `docs/design/owner-value-ingestion.md` §3.2): `[sets]`, `[producers]`
    /// A set member is not a key wanted in one of the set's environments.
    SetMemberNotWanted { member: String, env: String },
    /// A set's members live in more than one 1Password item (access boundary) in `env`:
    /// 1Password writes one item atomically, never several (D1).
    SetSpansBoundaries {
        env: String,
        boundaries: Vec<String>,
    },
    /// A key is a member of more than one set (D13).
    MemberOfTwoSets { member: String, sets: Vec<String> },
    /// A set member is not a team value stored in 1Password: `personal`, `from`, or
    /// `source = "infrastructure"`.
    SetMemberNotStored { member: String, why: &'static str },
    /// `generate = "rules"` on a key whose rules give no recipe.
    GenerateNoRecipe { member: String },
    /// A `hex_bytes`/`base64_bytes` size outside 16..=1024.
    GenerateBytes { bytes: u64 },
    /// `output` is not one of the producer's declared `outputs`.
    ProducerOutputUndeclared {
        producer: String,
        output: String,
        outputs: Vec<String>,
    },
    /// A producer's declared output no member or template uses.
    ProducerOutputUnused { producer: String, output: String },
    /// A producer's `command[0]` is `op` or `opv`: a producer never gets `op`'s
    /// environment (vet F6).
    ProducerIsOp { program: String },
    /// A producer's argument at `index` (0-based) looks like a secret value.
    ProducerArgumentSecret { index: usize },
    /// A producer's command names project file `file`, and the contract pins no `sha256`.
    ProducerShaMissing { file: String },
    /// A producer input names a key outside the set's own boundary or environment.
    ProducerInputOutside { input: String, key: String },
    /// A producer `timeout` over the cap (vet F10).
    ProducerTimeoutCap { max: &'static str },
    /// An `open_url_hosts` entry is not a host name.
    OpenUrlHost { host: String },
    // end provision
    // sealed target (#271, `docs/design/sealed-target.md` §3.1)
    /// A sealed target's recipient is also a recipient of a sealed target in another trust
    /// group (`sealed_recipient_shared`). `recipient` is its fingerprint, never the key.
    SealedRecipientShared {
        recipient: String,
        other_env: String,
        other_target: String,
    },
    /// A sealed target's signer also signs for a sealed target in another trust group
    /// (`sealed_signer_shared`, T1). `signer` is its fingerprint.
    SealedSignerShared {
        signer: String,
        other_env: String,
        other_target: String,
    },
    /// A key a sealed target delivers holds an age identity (`age_identity = true`, T14).
    SealedDeliversIdentity { target: String },
    /// A key a sealed target delivers is read from the item of the target's own
    /// `deploy_credentials`, its signing key (G4).
    SealedDeliversSigner { target: String },
    /// A key a sealed target delivers is `source = "infrastructure"` (#206): supplied at
    /// sync, never stored in 1Password, so there is no value to seal (#275).
    SealedDeliversInfrastructure {
        product: String,
        key: String,
        target: String,
    },
    // end sealed target
}

fn list(items: &[String]) -> String {
    items.join(", ")
}

impl ConfigCheck {
    /// What is wrong, as `<field> <problem>`.
    pub fn problem(&self, field: &str) -> String {
        use ConfigCheck::*;
        let p = match self {
            Undeclared {
                kind,
                name,
                declared,
                ..
            } => {
                let k = kind.noun();
                if declared.is_empty() {
                    format!("names {k} {name}, which is not declared (no {k} is)")
                } else {
                    format!(
                        "names {k} {name}, which is not declared (declared: {})",
                        list(declared)
                    )
                }
            }
            NotOneOf { allowed, .. } => format!("must be one of {}", list(allowed)),
            Whitespace => "has leading or trailing whitespace".into(),
            EmptyProducts | EmptyRoles | EmptyRemoteRoles | EmptyRemoteEnvironments => {
                "is an empty list".into()
            }
            RemoteEnvironmentHasTarget {
                profile,
                env,
                target,
            } => format!(
                "lists environment {env}, which has deployment target {target}; remote profile \
                 {profile} may only name environments with no deployment target"
            ),
            ConfigFileNeedsObject { key } => format!(
                "is \"env\", but key {key} sets file; a config key with a file needs config = \
                 \"configmap\""
            ),
            NoProvider { known } => {
                format!("names no provider (one of {})", list(known))
            }
            NoStoreKind { known } => format!("names no store kind (one of {})", list(known)),
            StoreBinding {
                section,
                kind,
                supported,
            } => format!(
                "names a {kind} store, which a {section} target cannot keep its secrets in \
                 (supported pairs: {})",
                supported.join("; ")
            ),
            DeployCredentialsRef => "must name an item as op://<vault>/<item>".into(),
            DeployCredentialsUnsupported { provider } => {
                format!("is not supported on a {provider} target")
            }
            SourceOnlyWithoutKeys { product } => {
                format!("is true, but product {product} declares no key")
            }
            SourceOnlyListed { product } => {
                format!("lists product {product}, which is source-only and never delivered")
            }
            BoundaryUnused { env, .. } => {
                format!("is recorded, but no product with a key in {env} lives in it")
            }
            DeliveryItemUndelivered { product } => {
                format!(
                    "records a delivery item for product {product}, which the target does not deliver"
                )
            }
            PersonalOnTarget { env } => format!(
                "is true, but environment {env} has a deployment target, and a person's own value \
                 is never deployed"
            ),
            PersonalMix { source, personal } => {
                if *personal {
                    format!("makes a personal key read {source}, a team value")
                } else {
                    format!("makes a team key read {source}, a personal value")
                }
            }
            FromCrossEnvironment => {
                "names a key outside this environment; a shared key reads another key of the \
                 same environment"
                    .into()
            }
            FromShape => "must be \"<product>/<KEY>\"".into(),
            FromSelf => "names the key itself (a cycle)".into(),
            FromCycle { source } => {
                format!("names {source}, which is shared from this key (a cycle)")
            }
            FromChain { source, its_from } => {
                format!("names {source}, which is itself shared from {its_from} (no chains)")
            }
            FromKind {
                source,
                source_kind,
                kind,
            } => format!("names {source}, a {source_kind} key, from a {kind} key"),
            FromEnvironment { source, env } => {
                format!("names {source}, which is not declared for environment {env}")
            }
            FromRefused { source, env } => {
                format!("refuses environment {env}, where {source} provides the value")
            }
            DirEnvWithoutFiles => "is set, but no key of the product has file = \"<path>\"".into(),
            CommandArguments => {
                "has an argument longer than 4096 characters or with control characters".into()
            }
            SameTarget {
                label,
                locator,
                other,
                ..
            } => format!(
                "delivers to {label} {locator}, as target {other} of the same environment does; \
                 within one environment, {label} {locator} can belong to only one target"
            ),
            SharedAcrossEnvironments {
                label,
                locator,
                other_env,
                other_target,
                ..
            } => format!(
                "manages the same names on {label} {locator} as target {other_target} of \
                 environment {other_env}, so each would prune the other's"
            ),
            RenderedName {
                owner,
                label,
                rendered,
                pattern,
            } => format!(
                "renders {label} {rendered} for {owner}, which must be {}",
                pattern.words()
            ),
            RenderedStoreName {
                owner,
                label,
                problem,
            } => {
                let why = match problem {
                    StoreNameProblem::Empty => "empty".to_string(),
                    StoreNameProblem::TooLong { len, max } => {
                        format!("{len} characters long, over the {max} allowed")
                    }
                    StoreNameProblem::Character => format!("holding a character a {label} cannot"),
                    StoreNameProblem::Edge => {
                        "not starting and ending with a letter or digit".to_string()
                    }
                };
                format!("renders a {label} for {owner} that is {why}")
            }
            NameTaken {
                owner,
                other,
                label,
                name,
            } => format!("renders {label} {name} for both {other} and {owner}"),
            StoreShared {
                owner,
                label,
                name,
                store,
                other_env,
                other_owner,
            } => format!(
                "keeps {label} {name} for {owner} in {store}, where environment {other_env} keeps \
                 it for {other_owner}; each would overwrite and prune the other's value"
            ),
            // provision (#253)
            SetMemberNotWanted { member, env } => {
                format!("names {member}, which is not declared for environment {env}")
            }
            SetSpansBoundaries { env, boundaries } => format!(
                "has members in {} 1Password items in environment {env} ({}); a set fills one item",
                boundaries.len(),
                list(boundaries)
            ),
            MemberOfTwoSets { member, sets } => {
                format!(
                    "makes {member} a member of more than one set ({})",
                    list(sets)
                )
            }
            SetMemberNotStored { member, why } => format!(
                "names {member}, which is {why}; a set member is a team value stored in 1Password"
            ),
            GenerateNoRecipe { member } => {
                format!("is \"rules\", but the rules of {member} give no byte recipe")
            }
            GenerateBytes { bytes } => format!("asks for {bytes} bytes; it must be 16 to 1024"),
            ProducerOutputUndeclared {
                producer, output, ..
            } => format!("names output {output}, which producer {producer} does not declare"),
            ProducerOutputUnused { producer, output } => {
                format!("declares output {output} of producer {producer}, which no member uses")
            }
            ProducerIsOp { program } => format!(
                "starts {program}; a producer is never op or opv, which would get your 1Password session"
            ),
            ProducerArgumentSecret { index } => {
                format!("has argument {index} that looks like a secret value")
            }
            ProducerShaMissing { file } => {
                format!("runs project file {file}, but pins no sha256 of it")
            }
            ProducerInputOutside { input, key } => format!(
                "has input {input} reading {key}, outside the set's own item and environment"
            ),
            ProducerTimeoutCap { max } => format!("is longer than {max}"),
            OpenUrlHost { host } => format!("lists {host}, which is not a host name"),
            // end provision
            SealedRecipientShared {
                recipient,
                other_env,
                other_target,
            } => format!(
                "lists recipient {recipient}, which target {other_target} of environment \
                 {other_env} also seals to, in another trust group"
            ),
            SealedSignerShared {
                signer,
                other_env,
                other_target,
            } => format!(
                "is signer {signer}, which also signs for target {other_target} of environment \
                 {other_env}, in another trust group"
            ),
            SealedDeliversIdentity { target } => format!(
                "is an age identity (age_identity = true), and sealed target {target} delivers \
                 it; a bundle cannot carry the key that opens it"
            ),
            SealedDeliversSigner { target } => format!(
                "is read from the item of sealed target {target}'s deploy_credentials, its \
                 signing key, and a sealed target never delivers its own signing key"
            ),
            SealedDeliversInfrastructure {
                product,
                key,
                target,
            } => format!(
                "is {product}/{key}, supplied at sync (source = \"infrastructure\") and never \
                 stored in 1Password, so sealed target {target} has no value to seal"
            ),
        };
        format!("{field} {p}")
    }

    /// The edit that fixes it when the field is in opv's proposed change, not in the file
    /// (R2-4): only what the person can change, never the proposed field itself. `None` when
    /// [`ConfigCheck::fix`] already names only that.
    pub fn proposal_fix(&self, field: &str) -> Option<String> {
        match self {
            ConfigCheck::BoundaryUnused { env, products } => {
                let leaf = field.rsplit('.').next().unwrap_or(field);
                Some(match products.as_slice() {
                    [] => format!("declare keys for {env} in a product whose boundary is {leaf}"),
                    [one] => format!(
                        "declare product {one}'s keys for {env}: add \"{env}\" to their environments"
                    ),
                    many => format!(
                        "declare the keys of product {} for {env}: add \"{env}\" to their environments",
                        super::render::one_of(many)
                    ),
                })
            }
            _ => None,
        }
    }

    /// The edit that fixes it.
    pub fn fix(&self, field: &str) -> String {
        use ConfigCheck::*;
        let leaf = field.rsplit('.').next().unwrap_or(field);
        match self {
            Undeclared {
                kind,
                name,
                declared,
                closest,
            } => match (closest, declared.is_empty()) {
                (Some(c), _) => format!("change {name} to {c} in {field}"),
                (None, true) => format!("declare {} {name}", kind.noun()),
                (None, false) => format!(
                    "use {} in {field}, or declare {} {name}",
                    super::render::one_of(declared),
                    kind.noun()
                ),
            },
            NotOneOf { allowed, closest } => match closest {
                Some(c) => format!("set {leaf} = \"{c}\""),
                None => format!("set {leaf} to one of {}", list(allowed)),
            },
            Whitespace => format!("remove the spaces around the value of {field}"),
            EmptyProducts => format!(
                "remove {field} to deliver every product with a key in the environment, or list \
                 the products"
            ),
            EmptyRoles => format!(
                "remove {field} to deliver the key to every role, or list roles like [\"serve\"]"
            ),
            EmptyRemoteRoles => {
                format!("list the roles that may run there in {field}, or remove {field}")
            }
            EmptyRemoteEnvironments => {
                format!("list in {field} the environments whose values may go to this host")
            }
            RemoteEnvironmentHasTarget { env, target, .. } => format!(
                "remove {env} from {field}, or remove target {target} from environment {env}"
            ),
            ConfigFileNeedsObject { .. } => "set config = \"configmap\"".to_string(),
            NoProvider { known } => {
                format!("add one provider section ({}) under [{field}]", list(known))
            }
            NoStoreKind { known } => format!("add one of {} under [{field}]", list(known)),
            StoreBinding { .. } => format!("name a store this target supports in {field}"),
            DeployCredentialsRef => format!("write {leaf} = \"op://<vault>/<item>\""),
            DeployCredentialsUnsupported { .. } => format!("remove {field}"),
            SourceOnlyWithoutKeys { product } => {
                format!("declare a key under [products.{product}.keys], or remove {field}")
            }
            SourceOnlyListed { product } => format!(
                "remove {product} from {field}; list the products whose keys point at it with \
                 from"
            ),
            BoundaryUnused { env, .. } => {
                format!("remove {field}, or declare that product's keys for {env}")
            }
            DeliveryItemUndelivered { .. } => format!("remove {field}"),
            PersonalOnTarget { env } => {
                format!("declare a team key for {env}, or remove {env} from the key's environments")
            }
            PersonalMix { .. } => format!(
                "point {field} at a key that is personal when this one is, and team when it is \
                 not"
            ),
            FromCrossEnvironment | FromShape => format!("write {leaf} = \"<product>/<KEY>\""),
            FromSelf => format!("remove {field}"),
            FromCycle { .. } => "keep from on only one of the two keys".into(),
            FromChain { its_from, .. } => format!("write {leaf} = \"{its_from}\""),
            FromKind { source_kind, .. } => format!(
                "give this key kind = \"{source_kind}\", or point {field} at a key of this key's kind"
            ),
            FromEnvironment { source, env } => {
                format!("add \"{env}\" to the environments of {source}")
            }
            FromRefused { env, .. } => format!("remove \"{env}\" from {field}"),
            DirEnvWithoutFiles => {
                format!("add file to the keys the app reads from that directory, or remove {field}")
            }
            CommandArguments => {
                format!("shorten the arguments of {field} and remove control characters")
            }
            SameTarget { job: true, .. } | SharedAcrossEnvironments { job: true, .. } => {
                "list the job on one target only".into()
            }
            SameTarget { .. } => {
                "merge the two targets into one, with products listing what it delivers".into()
            }
            SharedAcrossEnvironments { .. } => {
                format!("give one of the targets another place, or set {field} so the names differ")
            }
            RenderedName {
                owner,
                label,
                pattern,
                ..
            } => format!(
                "change the key name or {field} so {owner} renders a {label} of {}",
                pattern.words()
            ),
            RenderedStoreName { owner, label, .. } => {
                format!("change the key name or {field} so {owner} renders a valid {label}")
            }
            NameTaken { .. } => format!(
                "set {field} with {{PRODUCT}} so the names differ, or deliver one product from a \
                 target of its own (products = [...])"
            ),
            StoreShared { .. } => {
                format!("give one of them its own store, or set {field} so the names differ")
            }
            // provision (#253)
            SetMemberNotWanted { member, env } => {
                format!("add \"{env}\" to the environments of {member}, or remove it from {field}")
            }
            SetSpansBoundaries { .. } => {
                "keep a set's members in one product boundary; other products read them with from"
                    .into()
            }
            MemberOfTwoSets { member, .. } => format!("keep {member} in one set only"),
            SetMemberNotStored { member, .. } => format!("remove {member} from {field}"),
            GenerateNoRecipe { .. } => {
                format!("write {leaf} = {{ hex_bytes = 32 }} or {{ base64_bytes = 32 }}")
            }
            GenerateBytes { .. } => format!("set {field} to a size from 16 to 1024"),
            ProducerOutputUndeclared { outputs, .. } => {
                format!("set {field} to one of {}", list(outputs))
            }
            ProducerOutputUnused { output, .. } => {
                format!("remove {output} from {field}, or make a member of it")
            }
            ProducerIsOp { .. } => {
                format!("make {field} start the producer's own program, such as python3")
            }
            ProducerArgumentSecret { index } => format!(
                "remove argument {index} from {field}; a producer receives its inputs on standard input"
            ),
            ProducerShaMissing { file } => {
                format!("add sha256 = \"<SHA-256 of {file}>\" next to {field}")
            }
            ProducerInputOutside { input, .. } => {
                format!("point input {input} at a key of the set's own item and environment")
            }
            ProducerTimeoutCap { max } => format!("set {leaf} to at most {max}"),
            OpenUrlHost { host } => {
                format!("write {host} as a host name only, such as accounts.example.com")
            }
            SealedRecipientShared { other_target, .. }
            | SealedSignerShared { other_target, .. } => {
                format!(
                    "give this target its own key in {field}, or set the same sealed.trust_group \
                     on it and on target {other_target}"
                )
            }
            SealedDeliversIdentity { target } | SealedDeliversSigner { target } => format!(
                "remove the product of {field} from target {target}'s products, or deliver this \
                 key from another target"
            ),
            SealedDeliversInfrastructure { target, .. } => format!(
                "remove the product of {field} from target {target}'s products and deliver it \
                 from a target that is not sealed, or store the value in 1Password (drop \
                 source = \"infrastructure\")"
            ),
        }
    }
}
