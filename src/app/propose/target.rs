//! `opv propose target` (design Part V, row `propose-target`): the contract diff a
//! categorical [`Intent::Target`] implies, with the relaxations it makes against the
//! default branch listed first and a content-addressed plan id.
//!
//! Folds 0.11.0's `opv target add`: the provider options are validated exactly as
//! [`crate::app::target_cmd`] validates them, through that module's own functions, so the
//! provider tables live in one place. Pure: [`propose`] reads no file and runs no command.
//!
//! No secret value, length, digest or prefix is ever carried: an option is a public name or
//! identifier, screened where the intent is parsed, and the diff holds names and rules only.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::Proposal;
use crate::app::target_cmd;
use crate::cause::{Cause, UsageProblem};
use crate::config;
use crate::config::bindings::Bindings;
use crate::domain::intent::Intent;
use crate::domain::{Fleet, relaxation};
use crate::error::Error;

fn usage(problem: UsageProblem) -> Error {
    Cause::Usage { problem }.into()
}

/// The target a proposal inserts: the intent's own fields, kept separate from [`Intent`]
/// so `declare`'s many-role declaration and the single-role intent both reach the same
/// builder.
pub(crate) struct TargetSpec {
    /// The declared environment.
    pub env: String,
    /// The new target name.
    pub name: String,
    /// `fly`, `azure`, `kubernetes` or `github`; `None` infers it from the options.
    pub provider: Option<String>,
    /// The provider's options by flag name (`fly-app`).
    pub fields: BTreeMap<String, String>,
    /// The products it delivers; empty means every product.
    pub products: Vec<String>,
    /// The process roles it delivers; names only. Empty: no `roles` line.
    pub roles: Vec<String>,
    /// The deploy identity, an `op://<vault>/<item>` reference (FR-40).
    pub deploy_credentials: Option<String>,
}

/// The proposal an `Intent::Target` implies for `contract_text`, against the default-branch
/// contract `base` (whose relaxations the proposal lists first). `bindings` are the ids of
/// `secrets.bindings.toml`, used only to validate; the diff never holds an id.
pub fn propose(
    contract_text: &str,
    bindings: &Bindings,
    base: Option<&Fleet>,
    intent: &Intent,
) -> Result<Proposal, Error> {
    // The contract carries no ids (D-G): validate it with its bindings filled in. A new
    // target has no `state_vault_id` yet, so the text is judged as it will load once the
    // approved structural plan records the missing ids (the same trial a declaration uses).
    let fleet = trial(&config::bindings::merge(contract_text, bindings))?;
    let proposed = target_text(contract_text, &fleet, &spec(intent)?)?;
    // A proposal that would not load is refused before anything is written.
    let proposed_fleet = trial(&config::bindings::merge(&proposed, bindings))?;
    let diff = crate::app::config_cmd::diff(contract_text, &proposed);
    let relaxations = base
        .map(|base| relaxation::relaxations(base, &proposed_fleet))
        .unwrap_or_default();
    Ok(Proposal {
        kind: "target",
        relaxations,
        diff,
        questions: Vec::new(),
        plan_id: plan_id("target", &proposed),
        contract_after: proposed,
    })
}

/// `text` parsed as it will load once the structural plan records the ids still missing
/// (a declaration's own trial). Nothing is asked of 1Password.
fn trial(text: &str) -> Result<Fleet, Error> {
    config::parse(&crate::app::structure::trial_text(text)?)
}

/// The [`TargetSpec`] an `Intent::Target` names. Any other intent is refused: this module
/// only proposes targets.
fn spec(intent: &Intent) -> Result<TargetSpec, Error> {
    let Intent::Target {
        env,
        name,
        provider,
        products,
        role,
        deploy_credentials,
        options,
        ..
    } = intent
    else {
        return Err(usage(UsageProblem::ValueFormat {
            flag: "kind".into(),
            format: "target",
        }));
    };
    Ok(TargetSpec {
        env: env.to_string(),
        name: name.to_string(),
        provider: provider.clone(),
        fields: options.clone(),
        products: products.iter().map(|p| p.to_string()).collect(),
        roles: role.iter().cloned().collect(),
        deploy_credentials: deploy_credentials.clone(),
    })
}

/// `contract_text` with `spec`'s target inserted, keeping every comment and line. The
/// provider options are validated against [`target_cmd`]'s table, exactly as `opv target
/// add` does; `fleet` names the declared products and environments.
pub(crate) fn target_text(
    contract_text: &str,
    fleet: &Fleet,
    spec: &TargetSpec,
) -> Result<String, Error> {
    if !crate::config::is_target_name(&spec.name) {
        return Err(usage(UsageProblem::ValueFormat {
            flag: "the target name".into(),
            format: "^[a-z][a-z0-9-]*$",
        }));
    }
    let (provider, values) =
        target_cmd::provider_and_values(spec.provider.as_deref(), &spec.fields)?;
    let section = provider.init_section(&values).ok_or_else(|| {
        usage(UsageProblem::ValueFormat {
            flag: "the target".into(),
            format: "a provider opv can write for (opv propose target --help lists them)",
        })
    })?;
    let products = target_cmd::checked_products(fleet, &spec.products)?;
    let body = target_cmd::target_table(
        &spec.env,
        &spec.name,
        &section,
        &products,
        &spec.roles,
        spec.deploy_credentials.as_deref(),
        None,
        &[],
    );
    let comment = format!(
        "# deploy target {} in {}; declared through opv's MCP tools (its state vault comes from the approved structural plan)",
        spec.name, spec.env
    );
    target_cmd::insert_target(contract_text, &spec.env, &spec.name, &body, &comment)
}

/// The content-addressed plan id: lowercase hex SHA-256 of the kind and the proposed
/// contract text.
fn plan_id(kind: &str, proposed: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(proposed.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod tests;
