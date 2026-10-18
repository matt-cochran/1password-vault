//! `opv schema` (A4): a machine-readable description of the installed binary.
//!
//! Commands, arguments and flags come from the clap definitions passed in, the exit and
//! error codes from the catalog ([`crate::cause::codes::table`]), so neither can drift from the code. What clap
//! cannot know (what a command changes, whether it needs a person's terminal, whether to
//! ask the user first) is the [`EFFECTS`] table; a test fails when a command has no entry.

use serde_json::{Value, json};

use crate::json::SCHEMA_VERSION;

/// Every MCP tool mapped to the CLI command that gives the same guarantee, in tool order
/// (j8). The parity test on the MCP server (src/mcp.rs) fails when a registered tool is
/// missing here; the test below fails when a mapped command has no [`EFFECTS`] entry.
/// `opv schema` exposes this as `mcp_tools`.
pub const MCP_TOOLS: &[(&str, &str)] = &[
    ("opv_ready", "ready"),
    ("opv_configuration", "contract"),
    ("opv_access", "access"),
    ("opv_deployment_plan", "plan"),
    ("opv_changed", "changed"),
    ("opv_structure_plan", "propose structure"),
    ("opv_delivery_preview", "run --preview"),
    ("opv_propose", "propose"),
    ("opv_import_local", "import"),
    ("opv_explain", "explain"),
];

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
        command: "ui",
        effect: "interactive",
        needs_terminal: true,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "history",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "delivery verify",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "changed",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "ci workflow",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "access",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "ready",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "vault locate",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "mcp serve",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "mcp install",
        effect: "writes_config",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "version",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "account list",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "account use",
        effect: "writes_config",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "run",
        effect: "runs_command",
        needs_terminal: false,
        handles_values: true,
        ask_user_first: true,
    },
    Effect {
        command: "run --preview",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
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
    Effect {
        command: "skill install",
        effect: "writes_config",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "skill status",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "target list",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    // `target credentials --create` mints the provider token (handling a value only in
    // memory) and stores it in 1Password; the owner runs it in their own terminal (FR-40).
    Effect {
        command: "target credentials",
        effect: "writes_1password",
        needs_terminal: true,
        handles_values: true,
        ask_user_first: true,
    },
    Effect {
        command: "needs",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "contract",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    // `inventory` and `next` read each item once to classify its fields; neither prints a
    // value nor tidies.
    Effect {
        command: "inventory",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "next",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    // A proposal writes nothing; `--write` writes the contract file (FLAG_EFFECTS).
    Effect {
        command: "propose",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose key",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose env",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose target",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose retire",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose setup",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose structure",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    Effect {
        command: "propose generate",
        effect: "reads",
        needs_terminal: false,
        handles_values: false,
        ask_user_first: false,
    },
    // `apply` creates vaults, items and fields, generates values and records their ids
    // (secrets.bindings.toml, the apply record): a person in their own terminal.
    Effect {
        command: "apply",
        effect: "writes_1password",
        needs_terminal: true,
        handles_values: false,
        ask_user_first: true,
    },
    Effect {
        command: "set",
        effect: "writes_1password",
        needs_terminal: true,
        handles_values: false,
        ask_user_first: true,
    },
    // `import` reads values from a file or a target and writes them into 1Password.
    Effect {
        command: "import",
        effect: "writes_1password",
        needs_terminal: false,
        handles_values: true,
        ask_user_first: true,
    },
];

/// The commands whose item read tidies the 1Password layout when a signed-in person runs
/// them (FR-43, [`crate::app`]'s `tidy::read`): one verified, non-destructive edit, never
/// under a service account, Connect, CI or deploy credentials. Their effect stays `reads`
/// (no value changes); `tidies_1password` says so. `doctor` and `ready` are not here: they
/// never write (#113).
pub const TIDIES_1PASSWORD: [&str; 10] = [
    "setup",
    "status",
    "projects",
    "import",
    "ui",
    "history",
    "run",
    "plan",
    "sync",
    "config export",
];

/// Commands that also create 1Password vaults or items with no flag asking for it, beside
/// their own `effect` (02.16). None since 0.12.0: a proposal writes nothing in 1Password and
/// `opv apply` says `writes_1password`. `opv schema` still marks each command
/// `also_writes_1password`.
pub const ALSO_WRITES_1PASSWORD: [&str; 0] = [];

/// What a flag adds to its command's effect: (command, long flag, effect). Every one of
/// these needs the user's yes for the run.
pub const FLAG_EFFECTS: [(&str, &str, &str); 14] = [
    ("sync", "deploy", "deploys"),
    ("sync", "prune", "deletes"),
    ("sync", "rotate", "replaces_immutable"),
    ("sync", "prune-immutable", "deletes_immutable"),
    ("sync", "confirm", "confirms_guarded_environment"),
    // `--write` writes the contract file (or the project's manifest), nothing else.
    ("propose", "write", "writes_config"),
    ("propose key", "write", "writes_config"),
    ("propose env", "write", "writes_config"),
    ("propose target", "write", "writes_config"),
    ("propose retire", "write", "writes_config"),
    ("propose setup", "write", "writes_config"),
    ("import", "replace", "replaces_value"),
    ("import", "rotate", "replaces_immutable"),
    // 0.9.0: creates a service account and stores its token as a GitHub secret (the owner,
    // in their own terminal; the token is never shown).
    ("access", "create", "creates_credential"),
];

/// Commands whose only output is JSON, with or without `--json`.
const JSON_ONLY: [&str; 1] = ["schema"];

/// The `opv schema` document for the command tree `root` of version `version`.
pub fn describe(root: &clap::Command, version: &str) -> Value {
    let mut commands = Vec::new();
    // A hidden command is opv's own internal step (`local-delivery`), not for callers.
    for sub in root.get_subcommands().filter(|s| !s.is_hide_set()) {
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
            "next": "{kind (run|apply|enter_value|authorize|wait_ci|none), actor (assistant|person|ci), command or null}: what runs next; on failure always set",
            "do": "what to do before `next`, or null; shown before next. Only a person can do it when human_required is true (fill a value in 1Password, approve, sign in)",
            "retry": "safe: re-run the same command now; after_fix: re-run it once `do` is done; never: run `next` instead",
            "human_required": "true when an agent must hand `do` and `next` to the user instead of acting",
            "text": "every failure ends with an optional `Do: <action>` line and exactly one `Next: <command>` line, the last line on stderr",
            "values": "no document ever contains a secret value; config export prints config-kind values only",
            "tidy": "a command with tidies_1password true, run by a signed-in person (opv login), may tidy the item's layout in one non-destructive edit (nothing deleted; listed in `tidy`); service accounts, Connect, CI, runs under deploy credentials and the project manifest item are never written. doctor and ready never write 1Password, whoever runs them: they are the safe readiness checks (doctor --env <env> --json, ready --json). a signed-in person's opv config export <env> tidies an item explicitly",
            "plan_id": "plan --json prints plan_id when the plan is clean; it covers exactly the targets planned (every target of the environment, or those --target names); sync --expect-plan <plan_id> applies exactly that plan to the same targets or fails with stale_plan (exit 6) and changes nothing",
            "targets": "status, plan and sync cover every target of the environment in name order, or only those --target names (repeatable); every row and key reference names its target",
            "run": "run always passes op:// references to op run, so op run masks values in the child's output; a value needing a fix a person's tidy would make is warned about on stderr, never injected",
            "schema_version": "3 since 0.12.0 (next became the typed {kind, actor, command} object); stays 3 while fields are only added; changes when a field changes meaning",
        },
        "global_flags": global,
        "commands": commands,
        "mcp_tools": MCP_TOOLS.iter().map(|(tool, cli)| json!({"tool": tool, "cli": cli})).collect::<Vec<_>>(),
        "exit_codes": exit_codes(),
        "error_codes": error_codes(),
        "states": {
            "row_state": ["saved", "missing", "failing_rule", "skipped", "source_blocked"],
            "row_kind": ["secret", "config"],
            "row_target_state": ["present", "absent", "would_change", null],
            "row_action": ["would_stage", "would_prune", "held", null],
            "row_binding": ["current", "stale", "unbound"],
            "doctor_status": ["ok", "warn", "fail", "skip"],
            "overview_state": ["checked", "run_only", "not_checked"],
            "changes": ["none", "some", "unknown"],
            "tidy_action": [
                "created_section", "renamed_section", "created_field", "made_concealed",
                "renamed_field", "moved_field", "kept_duplicate", "normalized_value"
            ],
            "text_on_target": ["new", "same", "changed", "unknown", "pending", "held", "rotate", "extra", "drift", "n/a"],
        },
        "documents": documents(),
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
        // A parent that also runs on its own flags (`propose --intent <file>`) is a command
        // of its own, listed before its subcommands.
        if own_flags(cmd) {
            out.push(command_entry(cmd, &path));
        }
        for sub in cmd.get_subcommands() {
            leaf_commands(sub, path.clone(), out);
        }
        return;
    }
    out.push(command_entry(cmd, &path));
}

/// Whether `cmd` takes a flag of its own (not a global, not `--help`/`--version`).
fn own_flags(cmd: &clap::Command) -> bool {
    cmd.get_arguments().any(|a| {
        !a.is_positional()
            && !a.is_global_set()
            && !matches!(a.get_id().as_str(), "help" | "version")
    })
}

/// The schema entry of the command `cmd` at `path`.
fn command_entry(cmd: &clap::Command, path: &str) -> Value {
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
    // `target add`'s provider options are hidden from --help (one summary line per
    // provider) but listed here, each with its provider and whether that provider's target
    // needs it (I6).
    let flags: Vec<Value> = cmd
        .get_arguments()
        .filter(|a| !a.is_positional() && !a.is_global_set())
        .filter(|a| !a.is_hide_set() || provider_option(a.get_long().unwrap_or_default()).is_some())
        .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
        .map(|a| {
            let mut f = flag(a);
            let long = a.get_long().unwrap_or_default();
            if let Some((provider, required)) = provider_option(long) {
                f["provider"] = Value::from(provider);
                f["required_for_provider"] = Value::from(required);
            }
            f["effect"] = FLAG_EFFECTS
                .iter()
                .find(|(c, l, _)| *c == path && *l == long)
                .map(|(_, _, e)| Value::from(*e))
                .unwrap_or(Value::Null);
            f
        })
        .collect();
    let json =
        JSON_ONLY.contains(&path) || cmd.get_arguments().any(|a| a.get_long() == Some("json"));
    json!({
        "name": path,
        "about": first_line(cmd.get_about()),
        "args": args,
        "flags": flags,
        "json": json,
        "effect": effect.map(|e| e.effect),
        "needs_terminal": effect.map(|e| e.needs_terminal),
        "handles_values": effect.map(|e| e.handles_values),
        "ask_user_first": effect.map(|e| e.ask_user_first),
        "tidies_1password": effect.map(|_| TIDIES_1PASSWORD.contains(&path)),
        "also_writes_1password": effect.map(|_| ALSO_WRITES_1PASSWORD.contains(&path)),
    })
}

/// `(provider section, required)` when `long` is a provider's `opv target add` option
/// (`azure-key-vault`).
fn provider_option(long: &str) -> Option<(&'static str, bool)> {
    crate::adapters::registry::PROVIDERS.iter().find_map(|p| {
        p.init_fields()
            .iter()
            .find(|f| crate::provider::init_flag(*p, f) == long)
            .map(|f| (p.section(), f.required))
    })
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
        "70": {"meaning": "internal error: an opv bug (report it)", "retry": "never"},
        "129": {"meaning": "interrupted (SIGHUP)", "retry": "safe"},
        "130": {"meaning": "interrupted (SIGINT)", "retry": "safe"},
        "131": {"meaning": "interrupted (SIGQUIT)", "retry": "safe"},
        "143": {"meaning": "interrupted (SIGTERM)", "retry": "safe"},
        "run": "opv run exits with the child's own code",
    })
}

/// The top-level fields of each JSON document, in order. `frame` fields come first
/// (`schema_version`, `ok`, `exit_code` on failure) and last (`next`, `do`, `error`).
fn documents() -> Value {
    let row = json!([
        "target",
        "product",
        "key",
        "kind",
        "channel",
        "via?",
        "delivered_as?",
        "form?",
        "path?",
        "state",
        "rule",
        "reason",
        "target_name",
        "target_state",
        "action",
        "binding?",
        "pending_deploy?",
        "drift?",
        "chain?",
        "open_url?",
        "shared_from?"
    ]);
    let key_ref = json!(["target", "product", "key", "target_name"]);
    json!({
        "frame": {
            "head": ["schema_version", "ok", "exit_code (failure only)"],
            "tail": ["next", "do", "error (failure only)"],
        },
        "row": row,
        "key_ref": key_ref,
        "error": error_fields(),
        "tidy": ["action", "name"],
        "status": [
            "environment", "product", "changes", "rows", "extras", "undelivered?", "unreferenced_sources?", "drift?", "tidy?", "tidy_error?", "stage",
            "held", "prune", "totals",
            "provenance? ({opv_version, written, plan_id}: the latest stamp on a pinned target)"
        ],
        "status_overview": [
            "product",
            "environments: [{name, target, state, keys, saved, skipped, findings, error_code, error, next}]",
            "totals"
        ],
        "plan": [
            "environment", "product", "changes", "rows", "extras", "undelivered?", "unreferenced_sources?", "drift?", "tidy?", "tidy_error?", "stage",
            "held", "prune", "totals", "plan_id? (a clean plan only)"
        ],
        "sync": [
            "environment", "product", "targets: [{target, provider, deployed, revision}]",
            "written", "unchanged", "held", "deployed", "deploy_reason", "deployed_names",
            "pending", "pruned", "kept", "skipped", "written_names", "plan_id",
            "delivery? ({minted: [{target, product, revision}], not_minted: [{target, product, reason}]})"
        ],
        "doctor": ["config_source", "checks: [{name, status, detail, next, do}]"],
        "explain": [
            "environment", "product", "key", "kind", "field", "source", "personal",
            "boundary: {name, vault_id, item_id}", "environments",
            "targets: [{name, provider, rendered_name, details: [{label, value}]}]",
            "delivered_to: [{environment, target, product, item, item_id, records}]",
            "rules", "immutable", "guidance", "required_here", "shared_from", "shared_by",
            "reference", "inspect", "readers: {deploy: [service account], ci}",
            "explain --target: {environment, target, provider, locator, products, deploy_credentials, state_vault_id, deploy_account}"
        ],
        "version": [
            "opv: {version}",
            "tools: [{program, vendor, status: installed | missing | unknown, version, reason, providers, configured}]",
            "providers: [{section, configured, tools}]",
            "config: {source: file | manifest | none, path, read}"
        ],
        "projects": [
            "scope: selected | all | default",
            "complete: true only when every account asked was listed (else exit 4, inventory_incomplete)",
            "accounts: [{account_id, sign_in, shorthand, status: listed | failed, manifests, error_code, reason}]",
            "projects: [{project, title, vault, vault_id, item_id, account, account_id, repos, paths, environments?, error?}]",
            "notes"
        ],
        "status --all": [
            "scope",
            "complete",
            "accounts",
            "projects: [{project, vault, environments: [status_overview environment], error_code, error}]",
            "notes"
        ],
        "open": ["environment", "product", "key", "section", "field", "open_url"],
        "propose": "{kind, relaxations [{product, key, env?, kind, reason}], diff, questions [{env, ask}], plan_id, written}: the contract diff (names and rules, never a value or an id); propose setup adds structure_steps and bindings_after; propose structure and generate print {plan_id, steps [{step, ...}], structure, contract_after, bindings_after}",
        "apply": "{plan_id, confirmed, steps_run, created, fields_added, generated [{environment, product, key}], record_written, config_written}: names and public ids only",
        "set": "{key, environment, state}: the key's value state after the entry (a word, never the value)",
        "import": "{environment, applied, rows [{found, product, key, action, rule}], writes, decisions_needed, next}: per key imported or skipped, names only, never a value",
        "needs": "{rows [{name, state (undeclared|declared_unobserved|ambiguous|declared), files, product, annotation_stale}], coverage}: names and file:line only",
        "contract": "{components [{name, environments [{name, keys [{name, kind, shape, required}]}]}], contract_digest}; --relaxations: {base, relaxations}",
        "ready": "{receipt_id, opv_version, config {source}, account ({account_id, by} or null), matrix [{environment, product, target, keys, saved, findings, delivered}], targets [{environment, name, provider, locator, state (ready|grants_missing), reason?, evidence_write (not_verified: an open state vault does not prove delivery evidence can be written; a sync checked with opv delivery verify does)}], findings [{code (an error code, an account finding, or key_missing|key_empty|key_failed_rule|key_wrong_kind), scope {account?, environment?, product?, key?}, blocking, actor (owner|agent|ci), effect (none|signs_in|writes_1password|writes_target|writes_config), prerequisite, verify}], next ({kind, actor, command} or null)}: names, IDs and codes only. A target whose deploy credentials, state vault or boundaries cannot be opened is `grants_missing` in the matrix, naming what could not be opened",
        "access": "{environments: [{environment, report: {checks: [{grant: {principal: {kind (deploy|ci_reader), environment, target?}, service_account, vault_id, permission (read|read_write)}, state (present|missing|read_only_needed|not_visible)}], extra: [{vault_id, service_account}], checked, unclassified}, commands: [string]}]}: who needs each boundary and target and the owner's exact commands for the missing grants; --target narrows to one target; read-only, never says clean",
        "account list": "{discovery (ok|unavailable|op_missing|credential: a service account or Connect decides the account), platform, cli_accounts_only, selected ({account_id, by (flag|env|pointer|manifest|only), source} or null), accounts [{account_id, user_id, email, address, shorthand, source, signed_in (true|false|null), selected}], findings [{code (no_accounts|selected_account_absent|account_ambiguous|selected_signed_out|discovery_unavailable|op_missing), human_required, message, next}], next}: account metadata only, never a credential, session or field value",
        "account use": "{account_id, path}: the .opv file written",
        "config export": "with <ENV>: the config-kind values, always {product: {KEY: value}}; with --json and no <ENV>: the configuration itself (IDs, names, kinds, rules); no frame on success",
        "delivery verify": "{environment, placements: [{product, target, revision, state, reason, names: [{name, state}], deployed, receipt_revision?}]}: every placement of the product, each with its target and state; --target narrows to one placement; a receipt kept from sync --receipt must be the current delivery",
        "changed": "{environment, changed, placements: [{product, target, state (unchanged|changed|no_record), items?: [{item_id, recorded, current?}]}], next, do}: each placement's recorded source versions against the item's current version (item IDs and version numbers only, never a value); exit 10 when something changed, with ok true",
        "schema": "this document",
        "skill install": "{written: [{target, path}], kept: [{target, path, reason}]}",
        "skill status": "{copies: [{scope, target, path, version, edited, current}]}",
    })
}

/// `documents.error`: the top-level keys of the real `error` object, generated from the
/// catalog's one example of every cause (as [`error_codes`] is from the code table), so the
/// published list cannot drift from the object. A key only some causes carry is marked `?`.
fn error_fields() -> Vec<String> {
    let inv =
        crate::cause::Invocation::from_cli(&["opv".to_string(), "status".into(), "prod".into()]);
    let docs: Vec<Vec<String>> = crate::cause::codes::one_of_each()
        .iter()
        .map(|cause| crate::error::document_keys(cause, &inv))
        .collect();
    let mut fields: Vec<String> = Vec::new();
    for doc in &docs {
        for key in doc {
            if !fields.iter().any(|f| f.trim_end_matches('?') == key) {
                let every = docs.iter().all(|d| d.contains(key));
                fields.push(if every {
                    key.clone()
                } else {
                    format!("{key}?")
                });
            }
        }
    }
    fields
}

/// The public error codes, generated from the catalog ([`crate::cause::codes::table`]):
/// `exit_code`, `retry` and `human_required` are the code's first (its lowest exit code),
/// and `exit_codes` and `retry_classes` list every one its causes have.
fn error_codes() -> Vec<serde_json::Value> {
    crate::cause::codes::table()
        .iter()
        .map(|r| {
            json!({
                "code": r.code,
                "exit_code": r.exits[0],
                "exit_codes": r.exits,
                "retry": r.retry[0].as_str(),
                "retry_classes": r.retry.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "human_required": r.human_required.contains(&true),
                "meaning": r.meaning,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_is_the_catalogs() {
        let listed: Vec<String> = error_codes()
            .iter()
            .map(|c| c["code"].as_str().unwrap_or_default().to_string())
            .collect();
        let catalog: Vec<String> = crate::cause::codes::table()
            .iter()
            .map(|r| r.code.to_string())
            .collect();
        assert_eq!(listed, catalog);
    }

    #[test]
    fn every_effect_names_a_distinct_command() {
        let mut names: Vec<&str> = EFFECTS.iter().map(|e| e.command).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n);
    }

    #[test]
    fn every_mcp_tool_cli_command_has_an_effect_entry() {
        let names: Vec<&str> = EFFECTS.iter().map(|e| e.command).collect();
        let missing: Vec<&str> = MCP_TOOLS
            .iter()
            .map(|(_, cli)| *cli)
            .filter(|cli| !names.contains(cli))
            .collect();
        assert!(missing.is_empty(), "MCP tools without EFFECTS: {missing:?}");
    }

    /// #166: the `error` list is generated from the real object, so a field added to or
    /// removed from the error document fails here.
    #[test]
    fn schema_error_fields_match_every_causes_error_object() {
        let doc = describe(&clap::Command::new("opv"), "test");
        let listed: std::collections::BTreeSet<String> = doc["documents"]["error"]
            .as_array()
            .expect("documents.error is a list")
            .iter()
            .map(|v| {
                v.as_str()
                    .unwrap_or_default()
                    .trim_end_matches('?')
                    .to_string()
            })
            .collect();
        let inv = crate::cause::Invocation::from_cli(&[
            "opv".to_string(),
            "status".into(),
            "prod".into(),
        ]);
        let differing: Vec<&str> = crate::cause::codes::one_of_each()
            .iter()
            .filter(|cause| {
                let keys: std::collections::BTreeSet<String> =
                    crate::cause::render::document(cause, None, &inv, false)
                        .as_object()
                        .expect("the error document is an object")
                        .keys()
                        .cloned()
                        .collect();
                keys != listed
            })
            .map(|cause| cause.code())
            .collect();
        assert!(
            differing.is_empty(),
            "causes whose error keys differ from documents.error: {differing:?}"
        );
    }

    /// #166: the error object has no `detail`; the schema must not list one.
    #[test]
    fn schema_error_fields_do_not_include_detail() {
        let doc = describe(&clap::Command::new("opv"), "test");
        let lists_detail = doc["documents"]["error"]
            .as_array()
            .expect("documents.error is a list")
            .iter()
            .any(|v| v.as_str() == Some("detail"));
        assert!(
            !lists_detail,
            "documents.error still lists detail: {}",
            doc["documents"]["error"]
        );
    }

    #[test]
    fn the_schema_lists_every_mcp_tool_with_its_cli_command() {
        let doc = describe(&clap::Command::new("opv"), "test");
        let tools: Vec<(&str, &str)> = doc["mcp_tools"]
            .as_array()
            .expect("mcp_tools array")
            .iter()
            .map(|e| (e["tool"].as_str().unwrap(), e["cli"].as_str().unwrap()))
            .collect();
        assert_eq!(tools.as_slice(), MCP_TOOLS);
    }
}
