//! `opv schema` (A4): a machine-readable description of the installed binary.
//!
//! Commands, arguments and flags come from the clap definitions passed in, the exit and
//! error codes from [`crate::error::Code`], so neither can drift from the code. What clap
//! cannot know (what a command changes, whether it needs a person's terminal, whether to
//! ask the user first) is the [`EFFECTS`] table; a test fails when a command has no entry.

use serde_json::{Value, json};

use crate::error::Code;
use crate::json::SCHEMA_VERSION;

/// What running a command can change.
#[derive(Debug, Clone, Copy)]
pub struct Effect {
    /// The command path, as typed after `opv` (`config export`).
    pub command: &'static str,
    /// `none`, `reads`, `writes_config` (secrets.toml or the project's manifest in
    /// 1Password), `writes_1password`, `writes_target`, `runs_command`, `opens_browser` or
    /// `interactive`.
    pub effect: &'static str,
    /// Needs the user's own interactive terminal (an agent hands it to the user).
    pub needs_terminal: bool,
    /// Puts secret values somewhere other than 1Password (the target, or a child process).
    pub handles_values: bool,
    /// An agent asks the user before running it.
    pub ask_user_first: bool,
}

/// The effect of every command (see the module docs).
pub const EFFECTS: &[Effect] = &[
    Effect {
        command: "setup",
        effect: "interactive",
        needs_terminal: true,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "login",
        effect: "interactive",
        needs_terminal: true,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "doctor",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "check",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "status",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "projects",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "run",
        effect: "runs_command",
        needs_terminal: false,
        handles_values: true,
        ask_user_first: true,
    },
    Effect {
        command: "plan",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "sync",
        effect: "writes_target",
        needs_terminal: false,
        handles_values: true,
        ask_user_first: true,
    },
    Effect {
        command: "config export",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "config import",
        effect: "writes_1password",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "config edit",
        effect: "interactive",
        needs_terminal: true,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "config check",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "item skeleton",
        effect: "writes_1password",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "explain",
        effect: "none",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "open",
        effect: "opens_browser",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "help",
        effect: "none",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "init",
        effect: "writes_config",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "add",
        effect: "writes_config",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "completions",
        effect: "none",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "schema",
        effect: "none",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "guide",
        effect: "none",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
];

/// What a flag adds to its command's effect: (command, long flag, effect). Every one of
/// these needs the user's yes for the run.
pub const FLAG_EFFECTS: [(&str, &str, &str); 6] = [
    ("sync", "deploy", "deploys"),
    ("sync", "prune", "deletes"),
    ("sync", "rotate", "replaces_immutable"),
    ("sync", "prune-immutable", "deletes_immutable"),
    ("sync", "confirm", "confirms_guarded_environment"),
    ("init", "force", "overwrites_file"),
];

/// Commands whose only output is JSON, with or without `--json`.
const JSON_ONLY: [&str; 1] = ["schema"];

/// The `opv schema` document for the command tree `root` of version `version`.
pub fn describe(root: &clap::Command, version: &str) -> Value {
    let mut commands = Vec::new();
    for sub in root.get_subcommands() {
        leaf_commands(sub, String::new(), &mut commands);
    }
    let global: Vec<Value> = root
        .get_arguments()
        .filter(|a| a.is_global_set() && !a.is_hide_set())
        .map(flag)
        .collect();
    json!({
        "schema_version": SCHEMA_VERSION,
        "opv_version": version,
        "conventions": {
            "json": "with --json (and always for schema and config export <env>) stdout is one JSON document; human text goes to stderr",
            "ok": "true on success; false on failure, with exit_code and error",
            "next": "a command that runs as typed, or null; on failure always set",
            "do": "an action only a person can take (fill a value in 1Password, sign in), or null; shown before next",
            "retry": "safe: re-run the same command now; after_fix: re-run it once `do` is done; never: run `next` instead",
            "human_required": "true when an agent must hand `do` and `next` to the user instead of acting",
            "text": "every failure ends with an optional `Do: <action>` line and exactly one `Next: <command>` line, the last line on stderr",
            "values": "no document ever contains a secret value; config export prints config-kind values only",
            "tidy": "any command that reads the 1Password item, run by a signed-in person (opv login), may tidy its layout in one non-destructive edit (nothing deleted; listed in `tidy`); service accounts, Connect, CI, runs under deploy credentials and the project manifest item are never written",
            "plan_id": "plan --json prints plan_id when the plan is clean; sync --expect-plan <plan_id> applies exactly that plan or fails with stale_plan (exit 6) and changes nothing",
            "run": "run always passes op:// references to op run, so op run masks values in the child's output; a value needing a fix a person's tidy would make is warned about on stderr, never injected",
            "schema_version": "stays 1 while fields are only added; changes when a field changes meaning",
        },
        "global_flags": global,
        "commands": commands,
        "exit_codes": exit_codes(),
        "error_codes": Code::ALL.iter().map(|c| json!({
            "code": c.as_str(),
            "exit_code": c.exit_code(),
            "retry": c.retry().as_str(),
            "human_required": c.human_required(),
            "meaning": c.meaning(),
        })).collect::<Vec<_>>(),
        "states": {
            "row_state": ["saved", "missing", "wrong_kind", "failing_rule", "skipped", "source_blocked"],
            "row_kind": ["secret", "config"],
            "row_target": ["present", "absent", "would_change", null],
            "row_action": ["would_stage", "would_prune", "held", null],
            "row_binding": ["current", "stale", "unbound"],
            "doctor_status": ["ok", "warn", "fail", "skip"],
            "overview_state": ["checked", "run_only", "not_checked"],
            "changes": ["none", "some", "unknown"],
            "tidy_action": [
                "created_section", "renamed_section", "created_field", "made_concealed",
                "renamed_field", "moved_field", "kept_duplicate", "normalized_value"
            ],
            "text_target": ["new", "same", "changed", "unknown", "pending", "held", "extra", "drift", "n/a"],
        },
        "documents": documents(),
        "deprecated": [
            {"field": "fly_name", "in": ["status", "plan", "check"], "use": "target_name"},
        ],
    })
}

/// Every runnable command under `cmd` (`config export`, not `config`), with `prefix` its
/// parent path.
fn leaf_commands(cmd: &clap::Command, prefix: String, out: &mut Vec<Value>) {
    let path = if prefix.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{prefix} {}", cmd.get_name())
    };
    if cmd.has_subcommands() {
        for sub in cmd.get_subcommands() {
            leaf_commands(sub, path.clone(), out);
        }
        return;
    }
    let effect = EFFECTS.iter().find(|e| e.command == path);
    let args: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| a.is_positional() && !a.is_hide_set())
        .map(|a| {
            json!({
                "name": a.get_id().as_str(),
                "value_name": a.get_value_names().and_then(|v| v.first()).map(|v| v.as_str()),
                "required": a.is_required_set(),
                "multiple": a.get_num_args().is_some_and(|n| n.max_values() > 1),
                "help": first_line(a.get_help()),
            })
        })
        .collect();
    let flags: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_positional() && !a.is_global_set() && !a.is_hide_set())
        .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
        .map(|a| {
            let mut f = flag(a);
            let long = a.get_long().unwrap_or_default();
            f["effect"] = FLAG_EFFECTS
                .iter()
                .find(|(c, l, _)| *c == path && *l == long)
                .map(|(_, _, e)| Value::from(*e))
                .unwrap_or(Value::Null);
            f
        })
        .collect();
    let json = JSON_ONLY.contains(&path.as_str())
        || cmd.get_arguments().any(|a| a.get_long() == Some("json"));
    out.push(json!({
        "name": path,
        "about": first_line(cmd.get_about()),
        "args": args,
        "flags": flags,
        "json": json,
        "effect": effect.map(|e| e.effect),
        "needs_terminal": effect.map(|e| e.needs_terminal),
        "handles_values": effect.map(|e| e.handles_values),
        "ask_user_first": effect.map(|e| e.ask_user_first),
    }));
}

fn flag(a: &clap::Arg) -> Value {
    let takes_value = a.get_action().takes_values();
    json!({
        "name": format!("--{}", a.get_long().unwrap_or(a.get_id().as_str())),
        "value_name": takes_value
            .then(|| a.get_value_names().and_then(|v| v.first()).map(|v| v.as_str().to_string()))
            .flatten()
            .or_else(|| takes_value.then(|| a.get_id().as_str().to_ascii_uppercase())),
        "takes_value": takes_value,
        "repeatable": matches!(a.get_action(), clap::ArgAction::Append),
        "possible_values": a.get_possible_values().iter().map(|v| v.get_name().to_string()).collect::<Vec<_>>(),
        "env": a.get_env().map(|e| e.to_string_lossy().into_owned()),
        "help": first_line(a.get_help()),
    })
}

fn first_line(s: Option<&clap::builder::StyledStr>) -> Option<String> {
    s.map(|s| s.to_string().lines().next().unwrap_or_default().to_string())
}

/// Exit code → meaning and retry advice (FR-10).
fn exit_codes() -> Value {
    json!({
        "0": {"meaning": "ok", "retry": null},
        "2": {"meaning": "configuration or command-line usage", "retry": "after_fix"},
        "3": {"meaning": "dependency: op or the target CLI missing or unusable", "retry": "after_fix"},
        "4": {"meaning": "1Password (source)", "retry": "after_fix"},
        "5": {"meaning": format!("target ({})", crate::adapters::registry::labels().join(", ")), "retry": "after_fix"},
        "6": {"meaning": "refused by policy (blocking keys, --confirm, needs a terminal, refused values)", "retry": "after_fix"},
        "7": {"meaning": "authentication (1Password or the target)", "retry": "after_fix"},
        "8": {"meaning": "findings: status, plan or check found blocking keys", "retry": "after_fix"},
        "9": {"meaning": "outcome unknown, or a provider did not answer; nothing is known to be broken", "retry": "safe"},
        "130": {"meaning": "interrupted (SIGINT)", "retry": "safe"},
        "143": {"meaning": "interrupted (SIGTERM)", "retry": "safe"},
        "run": "opv run exits with the child's own code",
    })
}

/// The top-level fields of each JSON document, in order. `frame` fields come first
/// (`schema_version`, `ok`, `exit_code` on failure) and last (`next`, `do`, `error`).
fn documents() -> Value {
    let row = json!([
        "product",
        "key",
        "kind",
        "state",
        "rule",
        "reason",
        "target_name",
        "fly_name",
        "target",
        "action",
        "binding?",
        "pending_deploy?",
        "drift?",
        "chain?",
        "open_url?",
        "shared_from?"
    ]);
    let key_ref = json!(["product", "key", "target_name"]);
    json!({
        "frame": {
            "head": ["schema_version", "ok", "exit_code (failure only)"],
            "tail": ["next", "do", "error (failure only)"],
        },
        "row": row,
        "key_ref": key_ref,
        "error": ["code", "category", "message", "detail", "retry", "human_required", "do", "next"],
        "tidy": ["action", "name"],
        "status": [
            "environment", "product", "changes", "rows", "extras", "tidy?", "tidy_error?", "stage",
            "held", "prune", "totals",
            "provenance? ({opv_version, written, plan_id}: the latest stamp on a pinned target)"
        ],
        "status_overview": [
            "product",
            "environments: [{name, target, state, keys, saved, skipped, findings, error_code, error}]",
            "totals"
        ],
        "plan": [
            "environment", "product", "changes", "rows", "extras", "tidy?", "tidy_error?", "stage",
            "held", "prune", "totals", "plan_id? (a clean plan only)"
        ],
        "check": [
            "environment", "product", "target_checked", "rows", "findings", "totals", "tidy?",
            "tidy_error?"
        ],
        "sync": [
            "environment", "provider", "product", "written", "unchanged", "held", "deployed",
            "revision", "deploy_reason", "deployed_names", "pruned", "kept", "pending",
            "skipped", "written_names", "plan_id"
        ],
        "doctor": ["config_source", "checks: [{name, status, detail, next, do}]"],
        "explain": [
            "environment", "product", "key", "reference", "kind", "field", "target: [{label, value}]",
            "rules", "immutable", "guidance", "required_here", "inspect", "shared_from", "shared_by"
        ],
        "init": [
            "path", "manifest", "environment", "profile", "target", "vault_id", "item_id",
            "created", "keys: [{product, key, kind}]", "skipped"
        ],
        "init --add-env": [
            "environment", "target", "saved_in", "vault_id", "item_id", "added", "absent",
            "undeclared"
        ],
        "add": ["product", "key", "kind", "environments", "saved_in", "changed"],
        "projects": [
            "projects: [{project, title, vault, vault_id, item_id, account, repos, paths, environments?, error?}]",
            "notes"
        ],
        "status --all": [
            "projects: [{project, vault, environments: [status_overview environment], error_code, error}]",
            "notes"
        ],
        "item skeleton": ["environment", "added: [{product, key, kind}]"],
        "open": ["environment", "product", "key", "section", "field", "open_url"],
        "config export": "with <ENV>: the config-kind values, {KEY: value} (simple profile) or {product: {KEY: value}}; with --json and no <ENV>: the configuration itself (IDs, names, kinds, rules); no frame on success",
        "schema": "this document",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_is_listed_once() {
        let mut slugs: Vec<&str> = Code::ALL.iter().map(|c| c.as_str()).collect();
        let n = slugs.len();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), n);
    }

    #[test]
    fn every_effect_names_a_distinct_command() {
        let mut names: Vec<&str> = EFFECTS.iter().map(|e| e.command).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n);
    }
}
