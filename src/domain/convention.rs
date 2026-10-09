//! Self-healing 1Password conventions (FR-43). Pure: no `op`, no I/O, no clock.
//!
//! The convention: vault → item → section `<product>` → field `<KEY>` (the simple profile:
//! unsectioned fields); concealed = secret, text = config. Users never have to lay the item
//! out by hand, and a layout that differs never blocks a command:
//!
//! - [`resolve`] finds each declared key wherever its field actually is (tolerant reads,
//!   TRIZ #3 local quality): labels match ignoring case, spaces, `-` and `_`; a field in the
//!   wrong section is found; duplicates are chosen deterministically.
//! - [`plan`] is the tidy plan a signed-in person's run applies (FR-43): create missing
//!   sections and empty fields, conceal secrets stored as text, rename labels, move fields
//!   home, keep duplicates, normalized originals and old labels in [`KEPT_SECTION`] (TRIZ
//!   #24 intermediary). Nothing is ever deleted.
//!
//! Field choice among several candidates for one key: a filled field in the right section,
//! then any filled field, then an empty field in the right section, then any empty field;
//! ties go to the field later in the item (1Password lists newer fields later; it exposes no
//! per-field edit time). An empty field never shadows a filled one.
//!
//! Which fields may be claimed: fields in the product's own section (label matched ignoring
//! case, spaces, `-` and `_`), unsectioned fields, and fields in sections whose label is not
//! product-shaped (`^[a-z][a-z0-9_-]*$`, e.g. "Secrets" or "API keys"). A product-shaped
//! section belongs to some product, possibly one another configuration manages in the same
//! item, so its fields are never moved out of it. Under the simple profile any section is
//! fair game. A field two declared keys could both claim is left alone.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::domain::model::{Fleet, KeySpec, Kind, SIMPLE_PRODUCT, key_label};
use crate::domain::plan::ItemField;
use crate::domain::rules;
use crate::domain::secret::SecretValue;

/// Section that keeps everything a tidy displaced or replaced (FR-43).
pub const KEPT_SECTION: &str = "opv · kept";
/// opv's own section, holding [`MARKER_FIELD`].
pub const MARKER_SECTION: &str = "opv";
/// Text field recording the convention version, for future migrations.
pub const MARKER_FIELD: &str = "convention";
/// The convention version this build writes.
pub const CONVENTION: &str = "1";

/// Field types whose value is a plain string a key can hold.
const VALUE_TYPES: [&str; 5] = ["CONCEALED", "STRING", "URL", "EMAIL", "PHONE"];

/// One section of the item: its id and label (the label may be empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub id: String,
    pub label: String,
}

/// One field of the item as found. `Debug` never prints the value.
pub struct Found {
    pub id: String,
    /// The section the field is in; `None` at the top level.
    pub section: Option<Section>,
    /// The 1Password field type (`CONCEALED`, `STRING`, ...).
    pub ty: String,
    pub label: String,
    /// A built-in field (with a `purpose`: notes, username, password). Never a key.
    pub builtin: bool,
    pub value: SecretValue,
}

impl fmt::Debug for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Found")
            .field("id", &self.id)
            .field("section", &self.section)
            .field("ty", &self.ty)
            .field("label", &self.label)
            .field("value", &"<REDACTED>")
            .finish()
    }
}

impl Found {
    /// The section label, `None` at the top level or in a section without a label.
    pub fn section_label(&self) -> Option<&str> {
        self.section
            .as_ref()
            .map(|s| s.label.as_str())
            .filter(|l| !l.is_empty())
    }

    fn reserved(&self) -> bool {
        self.builtin
            || self.label.is_empty()
            || !VALUE_TYPES.contains(&self.ty.as_str())
            || self.section_label() == Some(KEPT_SECTION)
            || self.is_marker()
    }

    fn is_marker(&self) -> bool {
        self.section_label() == Some(MARKER_SECTION) && self.label == MARKER_FIELD
    }

    fn filled(&self) -> bool {
        !self.value.expose().is_empty()
    }
}

/// The whole item, in its own order. `fields[i]` is the item's i-th field.
#[derive(Debug, Default)]
pub struct Layout {
    pub sections: Vec<Section>,
    pub fields: Vec<Found>,
}

/// A label or name compared the convention's way: case, whitespace, `-` and `_` ignored.
pub fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn product_shaped(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('a'..='z'))
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

fn key_shaped(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('A'..='Z'))
        && c.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

/// (product, key) of a declared key.
pub type KeyId = (String, String);

/// Where each declared key's field is.
#[derive(Debug, Default)]
pub struct Resolution {
    /// The chosen field (index into [`Layout::fields`]) of each key that has one.
    pub chosen: BTreeMap<KeyId, usize>,
    /// The other fields claimed by each key, in item order.
    pub duplicates: BTreeMap<KeyId, Vec<usize>>,
}

impl Resolution {
    fn claimed(&self) -> BTreeSet<usize> {
        self.chosen
            .values()
            .copied()
            .chain(self.duplicates.values().flatten().copied())
            .collect()
    }
}

/// Whether `f` sits in `product`'s section, by label (the simple profile: top level).
fn in_home(f: &Found, product: &str) -> bool {
    if product == SIMPLE_PRODUCT {
        f.section_label().is_none()
    } else {
        f.section_label().is_some_and(|l| norm(l) == norm(product))
    }
}

/// Find each declared key's field (see the module docs). Pure and deterministic.
pub fn resolve(layout: &Layout, fleet: &Fleet) -> Resolution {
    let decls: Vec<(&str, &str)> = fleet
        .products
        .iter()
        .flat_map(|(p, prod)| prod.keys.keys().map(move |k| (p.as_str(), k.as_str())))
        .collect();
    let mut claims: BTreeMap<KeyId, Vec<usize>> = BTreeMap::new();
    for (i, f) in layout.fields.iter().enumerate() {
        if f.reserved() {
            continue;
        }
        let n = norm(&f.label);
        let cands: Vec<(&str, &str)> = decls
            .iter()
            .copied()
            .filter(|(_, k)| norm(k) == n)
            .collect();
        if cands.is_empty() {
            continue;
        }
        let one = |list: &[(&str, &str)]| -> Option<(String, String)> {
            let pick = match list {
                [only] => Some(*only),
                _ => {
                    let exact: Vec<_> = list.iter().filter(|(_, k)| *k == f.label).collect();
                    match exact.as_slice() {
                        [only] => Some(**only),
                        _ => None,
                    }
                }
            };
            pick.map(|(p, k)| (p.to_string(), k.to_string()))
        };
        let home: Vec<(&str, &str)> = cands
            .iter()
            .copied()
            .filter(|(p, _)| in_home(f, p))
            .collect();
        let raidable = fleet.is_simple() || f.section_label().is_none_or(|l| !product_shaped(l));
        let claim = one(&home).or_else(|| if raidable { one(&cands) } else { None });
        if let Some(id) = claim {
            claims.entry(id).or_default().push(i);
        }
    }
    let mut res = Resolution::default();
    for (id, fields) in claims {
        let best = *fields
            .iter()
            .max_by_key(|&&i| {
                let f = &layout.fields[i];
                (f.filled(), in_home(f, &id.0), i)
            })
            .expect("a claim has a field");
        let rest: Vec<usize> = fields.into_iter().filter(|&i| i != best).collect();
        if !rest.is_empty() {
            res.duplicates.insert(id.clone(), rest);
        }
        res.chosen.insert(id, best);
    }
    res
}

/// What a value normalization did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fix {
    /// A trailing newline, CR or space removed.
    Trimmed,
    /// The missing `ensure_prefix` added.
    Prefixed,
    Both,
}

/// The intended form of `value`, when the key's rules make it unambiguous: a trailing
/// newline/CR/space is removed only when the value fails its rules and the trimmed one
/// passes; a missing `ensure_prefix` is added when the result passes. `None`: keep as is.
/// Keys with a `transform` are never normalized (the transform owns their shape).
pub fn normalized(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    key: &str,
    spec: &KeySpec,
    value: &SecretValue,
) -> Option<(SecretValue, Fix)> {
    let env = fleet.environments.get(env_name)?;
    let v = value.expose();
    if v.is_empty() || spec.rules.transform.is_some() {
        return None;
    }
    let passes = |s: &SecretValue| {
        matches!(
            rules::check(product, key, spec, env_name, env, s),
            Ok(Some(_))
        )
    };
    let original_passes = match rules::check(product, key, spec, env_name, env, value) {
        Ok(None) => return None,
        Ok(Some(_)) => true,
        Err(_) => false,
    };
    let trimmed = v.trim_end_matches(['\n', '\r', ' ']);
    let trim = !original_passes && trimmed.len() != v.len() && !trimmed.is_empty();
    let base = if trim { trimmed } else { v };
    let prefix = spec
        .rules
        .ensure_prefix
        .as_deref()
        .filter(|p| !p.is_empty() && !base.starts_with(p));
    let candidate = SecretValue::new(format!("{}{base}", prefix.unwrap_or("")));
    let fix = match (trim, prefix.is_some()) {
        (false, false) => return None,
        (true, false) => Fix::Trimmed,
        (false, true) => Fix::Prefixed,
        (true, true) => Fix::Both,
    };
    passes(&candidate).then_some((candidate, fix))
}

/// The declared keys' fields as the planner reads them (tolerant reads, FR-43): each
/// resolved key under its own section and label, with its declared kind (a secret stored as
/// text and config stored as concealed are read, not refused) and its normalized value;
/// then every unclaimed field the profile's reader would see, once per (section, label), so
/// extras are still reported. opv's own sections are never read.
pub fn read_fields(layout: &Layout, fleet: &Fleet, env_name: &str) -> Vec<ItemField> {
    let res = resolve(layout, fleet);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (product, prod) in &fleet.products {
        for (key, spec) in &prod.keys {
            let id = (product.clone(), key.clone());
            let Some(&i) = res.chosen.get(&id) else {
                continue;
            };
            let f = &layout.fields[i];
            let value = match normalized(fleet, env_name, product, key, spec, &f.value) {
                Some((v, _)) => v,
                None => SecretValue::new(f.value.expose().to_string()),
            };
            seen.insert(id);
            out.push(ItemField {
                section: product.clone(),
                label: key.clone(),
                kind: spec.kind,
                value,
            });
        }
    }
    let claimed = res.claimed();
    for (i, f) in layout.fields.iter().enumerate() {
        if claimed.contains(&i) || f.reserved() || !matches!(f.ty.as_str(), "CONCEALED" | "STRING")
        {
            continue;
        }
        let section = match (fleet.is_simple(), f.section_label()) {
            (false, Some(l)) if l != MARKER_SECTION => l.to_string(),
            (true, None) if key_shaped(&f.label) => SIMPLE_PRODUCT.to_string(),
            _ => continue,
        };
        if !seen.insert((section.clone(), f.label.clone())) {
            continue;
        }
        out.push(ItemField {
            section,
            label: f.label.clone(),
            kind: if f.ty == "CONCEALED" {
                Kind::Secret
            } else {
                Kind::Config
            },
            value: SecretValue::new(f.value.expose().to_string()),
        });
    }
    out
}

/// One edit of the tidy plan. Sections are named by label; the applier reuses the first
/// section with that label or creates it. Indices are into [`Layout::fields`] of the
/// snapshot the plan was made from: no edit removes a field, so they stay valid.
pub enum Op {
    /// Relabel section `id` (and every field's copy of its label).
    RenameSection { id: String, to: String },
    /// Put field `index` in `section` (`None`: top level) under `label`; make it concealed
    /// when `conceal`, otherwise keep its type.
    Place {
        index: usize,
        section: Option<String>,
        label: String,
        conceal: bool,
    },
    /// Replace field `index`'s value (a normalization; the original is kept by an `Add`).
    SetValue { index: usize, value: SecretValue },
    /// Append a field. `value` `None` is an empty field.
    Add {
        section: Option<String>,
        label: String,
        concealed: bool,
        value: Option<SecretValue>,
    },
}

impl fmt::Debug for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::RenameSection { id, to } => write!(f, "RenameSection({id} -> {to})"),
            Op::Place {
                index,
                section,
                label,
                conceal,
            } => write!(
                f,
                "Place({index} -> {section:?}/{label}, conceal={conceal})"
            ),
            Op::SetValue { index, .. } => write!(f, "SetValue({index}, <REDACTED>)"),
            Op::Add {
                section,
                label,
                concealed,
                ..
            } => write!(f, "Add({section:?}/{label}, concealed={concealed})"),
        }
    }
}

/// One change a tidy made, names only (SR-1): shown on the tidy line and in `--json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    CreatedSection(String),
    RenamedSection {
        from: String,
        to: String,
    },
    /// An empty field created for a declared key; its value is still a human action.
    CreatedField(String),
    MadeConcealed(String),
    Renamed {
        field: String,
        from: String,
    },
    Moved {
        field: String,
        from: String,
    },
    KeptDuplicate(String),
    Normalized {
        field: String,
        fix: Fix,
    },
}

impl Change {
    /// The stable action word for `--json`.
    pub fn action(&self) -> &'static str {
        match self {
            Change::CreatedSection(_) => "created_section",
            Change::RenamedSection { .. } => "renamed_section",
            Change::CreatedField(_) => "created_field",
            Change::MadeConcealed(_) => "made_concealed",
            Change::Renamed { .. } => "renamed_field",
            Change::Moved { .. } => "moved_field",
            Change::KeptDuplicate(_) => "kept_duplicate",
            Change::Normalized { .. } => "normalized_value",
        }
    }

    /// The field or section the change is about (`product/KEY`, `KEY`, or a section).
    pub fn subject(&self) -> &str {
        match self {
            Change::CreatedSection(s) | Change::RenamedSection { to: s, .. } => s,
            Change::CreatedField(f)
            | Change::MadeConcealed(f)
            | Change::KeptDuplicate(f)
            | Change::Renamed { field: f, .. }
            | Change::Moved { field: f, .. }
            | Change::Normalized { field: f, .. } => f,
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Change::CreatedSection(s) => write!(f, "created section {s}"),
            Change::RenamedSection { from, to } => write!(f, "renamed section {from:?} to {to}"),
            Change::CreatedField(k) => write!(f, "created {k} (empty)"),
            Change::MadeConcealed(k) => write!(f, "made {k} concealed"),
            Change::Renamed { field, from } => write!(f, "renamed {from:?} to {field}"),
            Change::Moved { field, from } => write!(f, "moved {field} from {from}"),
            Change::KeptDuplicate(k) => write!(f, "set aside a duplicate of {k}"),
            Change::Normalized { field, fix } => match fix {
                Fix::Trimmed => write!(f, "removed trailing whitespace from {field}"),
                Fix::Prefixed => write!(f, "added the required prefix to {field}"),
                Fix::Both => write!(
                    f,
                    "removed trailing whitespace from and added the required prefix to {field}"
                ),
            },
        }
    }
}

/// The tidy plan for one item (FR-43). Empty when the item already follows the convention.
#[derive(Debug, Default)]
pub struct TidyPlan {
    pub ops: Vec<Op>,
    pub changes: Vec<Change>,
    /// Something went to [`KEPT_SECTION`].
    pub kept: bool,
}

impl TidyPlan {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// See [`summary`].
    pub fn summary(&self) -> String {
        summary(&self.changes)
    }
}

/// `created section api; made api/X concealed; kept old copies in "opv · kept"`: the tidy
/// line's text, names only.
pub fn summary(changes: &[Change]) -> String {
    let mut parts: Vec<String> = changes.iter().map(ToString::to_string).collect();
    if changes.iter().any(|c| {
        matches!(
            c,
            Change::KeptDuplicate(_) | Change::Normalized { .. } | Change::Renamed { .. }
        )
    }) {
        parts.push(format!("kept old copies in \"{KEPT_SECTION}\""));
    }
    parts.join("; ")
}

fn where_from(f: &Found) -> String {
    f.section_label().unwrap_or("top level").to_string()
}

/// The tidy plan (pure): see the module docs. `date` is today's UTC date (`YYYY-MM-DD`),
/// used in the labels of kept copies. Missing fields are created only for keys declared for
/// `env_name` (mode-skipped keys included, like `item skeleton`); every claimed field is
/// tidied, and a value is normalized only where its rules apply in `env_name`.
pub fn plan(layout: &Layout, fleet: &Fleet, env_name: &str, date: &str) -> TidyPlan {
    let res = resolve(layout, fleet);
    let mut p = TidyPlan::default();
    let mut labels: BTreeSet<String> = layout
        .sections
        .iter()
        .map(|s| s.label.clone())
        .filter(|l| !l.is_empty())
        .collect();
    let mut kept_labels: BTreeSet<String> = layout
        .fields
        .iter()
        .filter(|f| f.section_label() == Some(KEPT_SECTION))
        .map(|f| f.label.clone())
        .collect();
    let mut kept_label = |base: String| -> String {
        let mut candidate = base.clone();
        let mut n = 2;
        while !kept_labels.insert(candidate.clone()) {
            candidate = format!("{base} #{n}");
            n += 1;
        }
        candidate
    };

    // A product section spelled differently ("API" for `api`) is relabelled, when it holds
    // a field of that product and no section has the exact label.
    for product in fleet.products.keys() {
        if product == SIMPLE_PRODUCT || labels.contains(product) {
            continue;
        }
        let holds = |s: &Section| {
            res.chosen
                .iter()
                .any(|((p, _), &i)| p == product && layout.fields[i].section.as_ref() == Some(s))
        };
        if let Some(s) = layout
            .sections
            .iter()
            .find(|s| norm(&s.label) == norm(product) && holds(s))
        {
            p.ops.push(Op::RenameSection {
                id: s.id.clone(),
                to: product.clone(),
            });
            p.changes.push(Change::RenamedSection {
                from: s.label.clone(),
                to: product.clone(),
            });
            labels.insert(product.clone());
        }
    }
    let renamed: BTreeMap<String, String> = p
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::RenameSection { id, to } => Some((id.clone(), to.clone())),
            _ => None,
        })
        .collect();
    // The section id a product's fields belong in: the first section with its label.
    let home_id = |product: &str| -> Option<String> {
        layout
            .sections
            .iter()
            .find(|s| renamed.get(&s.id).map_or(s.label.as_str(), String::as_str) == product)
            .map(|s| s.id.clone())
    };
    let mut ensure_section = |p: &mut TidyPlan, label: &str| {
        if labels.insert(label.to_string()) && label != KEPT_SECTION && label != MARKER_SECTION {
            p.changes.push(Change::CreatedSection(label.to_string()));
        }
    };

    for (product, prod) in &fleet.products {
        let home = (product != SIMPLE_PRODUCT).then(|| product.clone());
        for (key, spec) in &prod.keys {
            let name = key_label(product, key);
            let id = (product.clone(), key.clone());
            let here = spec.environments.iter().any(|e| e == env_name);
            let Some(&c) = res.chosen.get(&id) else {
                if here {
                    if let Some(h) = &home {
                        ensure_section(&mut p, h);
                    }
                    p.ops.push(Op::Add {
                        section: home.clone(),
                        label: key.clone(),
                        concealed: spec.kind == Kind::Secret,
                        value: None,
                    });
                    p.changes.push(Change::CreatedField(name));
                }
                continue;
            };
            let f = &layout.fields[c];
            let at_home = match &home {
                None => f.section_label().is_none(),
                Some(h) => {
                    let sid = f.section.as_ref().map(|s| s.id.clone());
                    sid.is_some() && sid == home_id(h)
                }
            };
            let renamed_label = f.label != *key;
            let conceal = spec.kind == Kind::Secret && f.ty != "CONCEALED";
            if !at_home || renamed_label || conceal {
                if let Some(h) = &home {
                    ensure_section(&mut p, h);
                }
                p.ops.push(Op::Place {
                    index: c,
                    section: home.clone(),
                    label: key.clone(),
                    conceal,
                });
            }
            if !at_home {
                p.changes.push(Change::Moved {
                    field: name.clone(),
                    from: where_from(f),
                });
            }
            if renamed_label {
                // The old label is information too: an empty breadcrumb keeps it.
                ensure_section(&mut p, KEPT_SECTION);
                p.ops.push(Op::Add {
                    section: Some(KEPT_SECTION.to_string()),
                    label: kept_label(format!("{} (renamed to {name}, {date})", f.label)),
                    concealed: false,
                    value: None,
                });
                p.kept = true;
                p.changes.push(Change::Renamed {
                    field: name.clone(),
                    from: f.label.clone(),
                });
            }
            if conceal {
                p.changes.push(Change::MadeConcealed(name.clone()));
            }
            if here
                && let Some((v, fix)) = normalized(fleet, env_name, product, key, spec, &f.value)
            {
                ensure_section(&mut p, KEPT_SECTION);
                p.ops.push(Op::SetValue { index: c, value: v });
                p.ops.push(Op::Add {
                    section: Some(KEPT_SECTION.to_string()),
                    label: kept_label(format!("{key} (from {}, {date})", where_from(f))),
                    concealed: true,
                    value: Some(SecretValue::new(f.value.expose().to_string())),
                });
                p.changes.push(Change::Normalized {
                    field: name.clone(),
                    fix,
                });
                p.kept = true;
            }
            for &d in res.duplicates.get(&id).into_iter().flatten() {
                let dup = &layout.fields[d];
                ensure_section(&mut p, KEPT_SECTION);
                p.ops.push(Op::Place {
                    index: d,
                    section: Some(KEPT_SECTION.to_string()),
                    label: kept_label(format!("{} (from {}, {date})", dup.label, where_from(dup))),
                    conceal: spec.kind == Kind::Secret && dup.ty != "CONCEALED",
                });
                p.changes.push(Change::KeptDuplicate(name.clone()));
                p.kept = true;
            }
        }
    }
    if !p.is_empty() && !layout.fields.iter().any(Found::is_marker) {
        ensure_section(&mut p, MARKER_SECTION);
        p.ops.push(Op::Add {
            section: Some(MARKER_SECTION.to_string()),
            label: MARKER_FIELD.to_string(),
            concealed: false,
            value: Some(SecretValue::new(CONVENTION.to_string())),
        });
    }
    p
}

#[cfg(test)]
#[path = "convention_tests.rs"]
mod tests;
