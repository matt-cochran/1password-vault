//! `opv propose` (design Part V, row `propose-key`): the contract diff a categorical intent
//! implies, with the relaxations it makes against the default branch listed first, the
//! categorical questions it asks, and a content-addressed plan id.
//!
//! Pure: a proposal reads no file and runs no command. Only [`key::write`] touches the
//! contract file, and only when a caller asks it to.

pub mod key;
pub mod setup;
pub mod structure;
pub mod target;

use serde::Serialize;

use crate::domain::relaxation::{Relaxation, RelaxationKind};

/// One categorical question the plan asks the person, by environment
/// (`a value, or except?` for a production-tier environment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Question {
    /// The environment the question is about.
    pub env: String,
    /// The question itself, a fixed sentence.
    pub ask: String,
}

/// A proposed contract change: the relaxations it makes against the default branch
/// (listed first), the contract diff, the questions it asks, and a content-addressed
/// `plan_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Proposal {
    /// The intent kind (`key`, `env` or `retire`).
    pub kind: &'static str,
    /// The relaxations of the proposed contract against the default branch, listed first.
    #[serde(serialize_with = "relaxations_json")]
    pub relaxations: Vec<Relaxation>,
    /// A unified line diff of the contract file: names and rules only, never a value.
    pub diff: String,
    /// The categorical questions the plan asks, by environment.
    pub questions: Vec<Question>,
    /// Lowercase hex SHA-256 of the kind and the proposed contract text.
    pub plan_id: String,
    /// The proposed contract text itself (names and rules only, never an id or a value):
    /// what `--write` saves. Not part of the wire document, which carries the diff.
    #[serde(skip)]
    pub contract_after: String,
}

impl Proposal {
    /// The proposal as text, with the relaxations listed before the diff.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.relaxations.is_empty() {
            out.push_str("relaxations: none\n");
        } else {
            out.push_str("relaxations:\n");
            for r in &self.relaxations {
                let at = match &r.env {
                    Some(env) => format!("{}/{} ({env})", r.product, r.key),
                    None => format!("{}/{}", r.product, r.key),
                };
                out.push_str(&format!("  {at}: {}\n", r.reason));
            }
        }
        out.push_str("diff:\n");
        out.push_str(&self.diff);
        if !self.diff.is_empty() && !self.diff.ends_with('\n') {
            out.push('\n');
        }
        for q in &self.questions {
            out.push_str(&format!("{}: {}\n", q.env, q.ask));
        }
        out.push_str(&format!("plan_id: {}\n", self.plan_id));
        out
    }
}

/// FR-52 (#184): opv never edits a generated configuration (one whose first line starts
/// with `# generated`); its generator is. The refusal a `--write` of `proposal` meets on
/// the configuration `source`: it carries the proposal's diff, the edit to make in the
/// generator, and steps to `opv propose structure` once the generator emits it.
pub fn generated_refusal(
    source: crate::cause::ConfigSource,
    proposal: &Proposal,
) -> crate::cause::Cause {
    crate::cause::Cause::ConfigNotEditable {
        source,
        reason: crate::cause::NotEditable::Generated {
            generator: None,
            diff: Some(proposal.diff.clone()),
        },
    }
}

/// The `next` of a read-only proposal on a generated configuration (the CLI's and the MCP
/// tool's alike): never the `--write` that [`generated_refusal`] refuses, but that
/// refusal's own step under `inv`, the structure once the generator emits the change.
pub fn generated_next(
    source: crate::cause::ConfigSource,
    proposal: &Proposal,
    inv: &crate::cause::Invocation,
) -> serde_json::Value {
    let next = generated_refusal(source, proposal).step(inv).1;
    crate::cause::render::next_value(&next, inv)
}

/// The line a read-only proposal on a generated configuration prints before its `Next:`.
pub const GENERATED_ROUTE: &str = "generated: make this diff in the configuration's generator, never in the configuration; once the generator emits it, opv propose structure, then opv apply, returns the ids (generator_ids) for the generator to record";

/// Serialize the relaxations (which carry no `Serialize` of their own) as objects, so the
/// wire form names the product, key, environment, kind and fixed reason only.
fn relaxations_json<S>(relaxations: &[Relaxation], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(relaxations.len()))?;
    for r in relaxations {
        seq.serialize_element(&RelaxationView {
            product: &r.product,
            key: &r.key,
            env: r.env.as_deref(),
            kind: relaxation_kind_name(r.kind),
            reason: r.reason,
        })?;
    }
    seq.end()
}

#[derive(Serialize)]
struct RelaxationView<'a> {
    product: &'a str,
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<&'a str>,
    kind: &'a str,
    reason: &'a str,
}

/// One relaxation as its wire object: product, key, environment, kind and fixed reason.
pub fn relaxation_json(r: &Relaxation) -> serde_json::Value {
    serde_json::to_value(RelaxationView {
        product: &r.product,
        key: &r.key,
        env: r.env.as_deref(),
        kind: relaxation_kind_name(r.kind),
        reason: r.reason,
    })
    .unwrap_or(serde_json::Value::Null)
}

/// The wire name of a relaxation kind.
fn relaxation_kind_name(kind: RelaxationKind) -> &'static str {
    match kind {
        RelaxationKind::AllowSameValueAdded => "allow_same_value_added",
        RelaxationKind::ExceptProduction => "except_production",
        RelaxationKind::PresenceNarrowed => "presence_narrowed",
        RelaxationKind::RuleRemoved => "rule_removed",
        RelaxationKind::SecretToConfig => "secret_to_config",
    }
}
