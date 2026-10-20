//! `opv ci workflow` (j7): print a ready-to-commit GitHub Actions workflow (YAML) that
//! syncs one target, so an assistant never writes the workflow from scratch.
//!
//! Read-only output. The target's provider contributes its own CI setup step through
//! [`TargetConfig::provider`], so this module names no provider; the job references no
//! secret besides the 1Password service-account token it reads as
//! `secrets.OP_SERVICE_ACCOUNT_TOKEN`. The deploy identity the token belongs to is created
//! by a person with `opv access ... --create --github ...`, named in the header comment.
//! When the job cannot sign in to the target as printed (no deploy credentials recorded, or
//! a provider that takes none and has no CI setup step), the header says so and names the
//! command that fixes it (06.24): a workflow is never printed as ready when it is not.
//!
//! An unknown environment or target is a usage error and nothing is printed.

use std::io::Write;

use super::write_err;
use crate::cause::render::cmd_text;
use crate::cause::{Cause, Cmd, UsageProblem};
use crate::domain::{Environment, Fleet};
use crate::error::Error;
use crate::provider::Provider;

/// Print the workflow for target `target` of `env`, or refuse before writing anything.
pub fn run(
    fleet: &Fleet,
    env: &str,
    target: &str,
    github_env: Option<&str>,
    deploy: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // An unknown environment or target is `NotDeclared` (exit 2, C14), resolved before a
    // byte is written.
    let (e, t) = super::target(fleet, env, target)?;
    let recorded = e
        .targets
        .get(target)
        .is_some_and(|t| t.deploy_credentials.is_some());
    let job = Job {
        env,
        target,
        github_env,
        deploy,
        confirm: e.confirm_env,
    };
    let mut yaml = sign_in_note(&job, t.provider(), recorded).unwrap_or_default();
    yaml.push_str(&workflow(&job, t.provider().ci_setup_step()));
    out.write_all(yaml.as_bytes()).map_err(write_err)
}

/// Print §2.5's change-detection workflow (`--on-change`): every environment that has a
/// target, planned when `confirm_env` is set and synced directly otherwise, checked every
/// `every` minutes. Read-only output.
pub fn run_on_change(fleet: &Fleet, every: u8, out: &mut dyn Write) -> Result<(), Error> {
    let envs = recipe_envs(fleet)?;
    out.write_all(on_change(&envs, every).as_bytes())
        .map_err(write_err)
}

/// Print §2.5's nightly drift-check workflow (`--drift`) for the same environments.
/// Read-only output.
pub fn run_drift(fleet: &Fleet, out: &mut dyn Write) -> Result<(), Error> {
    let envs = recipe_envs(fleet)?;
    out.write_all(drift(&envs).as_bytes()).map_err(write_err)
}

/// The environments the two recipes cover: each with at least one target, in the
/// configuration's order (`order`, then name), as `access` and `ready` order them. A name
/// that is not a valid GitHub job/output identifier is a usage error (a word could not
/// name a job or an `outputs` key).
fn recipe_envs(fleet: &Fleet) -> Result<Vec<&Environment>, Error> {
    let mut ordered: Vec<&Environment> = fleet
        .environments
        .values()
        .filter(|e| !e.targets.is_empty())
        .collect();
    ordered.sort_by_key(|e| (e.order.unwrap_or(i64::MAX), e.name.clone()));
    for e in &ordered {
        if !e
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Cause::Usage {
                problem: UsageProblem::ValueFormat {
                    flag: format!("environment {}", e.name),
                    format: "letters, digits, '-' or '_'",
                },
            }
            .into());
        }
    }
    Ok(ordered)
}

/// The change-detection run block of §2.5 (FM-11, FM-12): 0 / 10 / other, and one retry
/// after a typed rate-limit reply's `retry_after_seconds` (30 s when it names none), capped
/// at 120 s. `$ENV` comes from the step's `env:`, never from a `${{ }}` interpolation.
const DETECT: &str = "\
set +e; opv changed \"$ENV\" --json > changed.json; rc=$?; set -e
if [ \"$rc\" -eq 9 ]; then
  wait=$(jq -r '[.. | .retry_after_seconds? // empty][0] // 30' changed.json)
  [ \"$wait\" -gt 120 ] && wait=120
  sleep \"$wait\"
  set +e; opv changed \"$ENV\" --json > changed.json; rc=$?; set -e
fi
case $rc in
  0)  echo \"$ENV=no\"  >> \"$GITHUB_OUTPUT\" ;;
  10) echo \"$ENV=yes\" >> \"$GITHUB_OUTPUT\" ;;
  *)  exit \"$rc\" ;;
esac";

/// `text` with every line prefixed by `n` spaces, as the body of a YAML block scalar.
fn indented(text: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    let mut out = String::new();
    for line in text.lines() {
        out.push_str(&pad);
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The whole change workflow: a `detect` job over `envs`' matrix, then each environment's
/// plan (when `confirm_env`) and sync jobs. FM-06: one `concurrency` group holds every
/// sync job, so two runs never sync at once.
fn on_change(envs: &[&Environment], every: u8) -> String {
    let names: Vec<&str> = envs.iter().map(|e| e.name.as_str()).collect();
    let matrix = names.join(", ");
    let mut s = String::new();
    s.push_str("# .github/workflows/opv-sync-on-change.yml\n");
    s.push_str("name: \"opv: sync when 1Password changes\"\n");
    s.push_str("on:\n");
    s.push_str(&format!("  schedule: [{{cron: \"*/{every} * * * *\"}}]\n"));
    s.push_str("  push: {branches: [main], paths: [secrets.toml]}\n");
    s.push_str("  workflow_dispatch:\n");
    s.push_str("permissions: {contents: read}\n");
    s.push_str("concurrency: {group: opv-sync, cancel-in-progress: false}\n");
    s.push_str("jobs:\n");
    s.push_str("  detect:\n");
    s.push_str("    runs-on: ubuntu-latest\n");
    s.push_str(&format!("    strategy: {{matrix: {{env: [{matrix}]}}}}\n"));
    s.push_str("    outputs:\n");
    for n in &names {
        s.push_str(&format!("      {n}: ${{{{ steps.c.outputs.{n} }}}}\n"));
    }
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n");
    s.push_str("      - uses: ./.github/actions/install-opv\n");
    s.push_str("      - id: c\n");
    s.push_str("        env:\n");
    s.push_str("          OP_SERVICE_ACCOUNT_TOKEN: \"${{ secrets.OPV_READER_TOKEN }}\"\n");
    s.push_str("          ENV: ${{ matrix.env }}\n");
    s.push_str("        run: |\n");
    s.push_str(&indented(DETECT, 10));
    for e in envs {
        append_plan_and_sync(&mut s, e);
    }
    s
}

/// One environment's jobs: `plan-<env>` then `sync-<env>` when `confirm_env`, else only a
/// direct `sync-<env>`. The sync's `if:` gates it on `detect`'s output for the environment.
fn append_plan_and_sync(s: &mut String, e: &Environment) {
    let name = e.name.as_str();
    let condition = format!("needs.detect.outputs.{name} == 'yes' || github.event_name == 'push'");
    if e.confirm_env {
        s.push_str(&format!("  plan-{name}:\n"));
        s.push_str("    needs: detect\n");
        s.push_str(&format!("    if: {condition}\n"));
        s.push_str("    runs-on: ubuntu-latest\n");
        s.push_str("    outputs: {plan_id: \"${{ steps.p.outputs.plan_id }}\"}\n");
        s.push_str("    steps:\n");
        s.push_str("      - uses: actions/checkout@v4\n");
        s.push_str("      - uses: ./.github/actions/install-opv\n");
        s.push_str("      - id: p\n");
        s.push_str("        env:\n");
        s.push_str("          OP_SERVICE_ACCOUNT_TOKEN: \"${{ secrets.OPV_READER_TOKEN }}\"\n");
        s.push_str("        run: |\n");
        s.push_str(&format!("          opv plan {name} > plan.txt\n"));
        s.push_str("          cat plan.txt >> \"$GITHUB_STEP_SUMMARY\"\n");
        s.push_str(&format!(
            "          echo \"plan_id=$(opv plan {name} --json | jq -r .plan_id)\" >> \"$GITHUB_OUTPUT\"\n"
        ));
    }
    s.push_str(&format!("  sync-{name}:\n"));
    if e.confirm_env {
        s.push_str(&format!("    needs: [detect, plan-{name}]\n"));
    } else {
        s.push_str("    needs: detect\n");
    }
    s.push_str(&format!("    if: {condition}\n"));
    s.push_str("    runs-on: ubuntu-latest\n");
    s.push_str(&format!("    environment: {name}\n"));
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n");
    s.push_str("      - uses: ./.github/actions/install-opv\n");
    for step in provider_setup(e) {
        s.push_str(step);
        s.push('\n');
    }
    s.push_str("      - env:\n");
    s.push_str("          OP_SERVICE_ACCOUNT_TOKEN: \"${{ secrets.OPV_DEPLOY_TOKEN }}\"\n");
    let expect = if e.confirm_env {
        format!(" --expect-plan ${{{{ needs.plan-{name}.outputs.plan_id }}}}")
    } else {
        String::new()
    };
    s.push_str(&format!("        run: opv sync {name} --deploy{expect}\n"));
}

/// The CI setup step of every distinct provider among `e`'s targets, in target name order
/// (each provider once), as [`workflow`] prints it.
fn provider_setup(e: &Environment) -> Vec<&'static str> {
    let mut seen: Vec<&'static str> = Vec::new();
    let mut steps = Vec::new();
    for t in e.targets.values() {
        let p = t.config.provider();
        if seen.contains(&p.section()) {
            continue;
        }
        seen.push(p.section());
        if let Some(step) = p.ci_setup_step() {
            steps.push(step);
        }
    }
    steps
}

/// The whole drift workflow: one `drift` job over `envs`' matrix. `--fail-on-drift` names
/// `target_drift`, `delivery verify --json` names `delivery_unverified` (both exit 8).
fn drift(envs: &[&Environment]) -> String {
    let names: Vec<&str> = envs.iter().map(|e| e.name.as_str()).collect();
    let matrix = names.join(", ");
    let mut s = String::new();
    s.push_str("# .github/workflows/opv-drift.yml\n");
    s.push_str("name: \"opv: drift check\"\n");
    s.push_str("on: {schedule: [{cron: \"23 4 * * *\"}], workflow_dispatch: {}}\n");
    s.push_str("permissions: {contents: read}\n");
    s.push_str("jobs:\n");
    s.push_str("  drift:\n");
    s.push_str("    runs-on: ubuntu-latest\n");
    s.push_str(&format!(
        "    strategy: {{fail-fast: false, matrix: {{env: [{matrix}]}}}}\n"
    ));
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n");
    s.push_str("      - uses: ./.github/actions/install-opv\n");
    s.push_str("      - env:\n");
    s.push_str("          OP_SERVICE_ACCOUNT_TOKEN: \"${{ secrets.OPV_READER_TOKEN }}\"\n");
    s.push_str("          ENV: ${{ matrix.env }}\n");
    s.push_str("        run: |\n");
    s.push_str(
        "          opv status \"$ENV\" --fail-on-drift      # exit 8 target_drift on drift\n",
    );
    s.push_str(
        "          opv delivery verify \"$ENV\" --json       # exit 8 delivery_unverified\n",
    );
    s
}

/// What the job syncs.
struct Job<'a> {
    env: &'a str,
    target: &'a str,
    github_env: Option<&'a str>,
    deploy: bool,
    /// The environment has `confirm_env = true`: the sync names it with `--confirm`.
    confirm: bool,
}

/// The header lines that say the job cannot sign in to the target as printed, and what a
/// person runs first (06.24); `None` when it can: the target's deploy credentials are
/// recorded, or its provider's CI setup step signs the job in.
fn sign_in_note(job: &Job<'_>, provider: &dyn Provider, recorded: bool) -> Option<String> {
    let (env, target, label) = (job.env, job.target, provider.label());
    if recorded {
        return None;
    }
    if provider.deploy_credential_fields().is_err() {
        if provider.ci_setup_step().is_some() {
            return None;
        }
        return Some(format!(
            "# {label} targets take no deploy credentials, so this job cannot sign in to \
             {label} as printed:\n\
             #   add the step that signs it in before \"Sync secrets to {target}\"\n"
        ));
    }
    // Only a provider that can mint one says how to revoke it (`mint_cleanup_hint`).
    let first = if provider.mint_cleanup_hint().is_some() {
        Cmd {
            command: vec!["target".into(), "credentials".into()],
            args: vec![
                env.to_string(),
                "--target".into(),
                target.to_string(),
                "--create".into(),
            ],
        }
    } else {
        Cmd {
            command: vec!["config".into(), "edit".into()],
            args: Vec::new(),
        }
    };
    Some(format!(
        "# this job signs in to {label} with target {target}'s deploy credentials, which are not \
         recorded yet; a person adds them first with:\n\
         #   {}\n",
        cmd_text(&first)
    ))
}

/// The whole workflow as text. `setup` is the target provider's CI setup step, indented as
/// a `steps:` entry, or `None` when the provider needs none.
fn workflow(job: &Job<'_>, setup: Option<&str>) -> String {
    let (env, target, github_env) = (job.env, job.target, job.github_env);
    let version = env!("CARGO_PKG_VERSION");
    let id = format!("sync-{env}-{target}");
    let mut s = String::new();
    let github_env_flag = github_env
        .map(|g| format!(" --github-env {g}"))
        .unwrap_or_default();
    s.push_str(&format!(
        "# secrets.OP_SERVICE_ACCOUNT_TOKEN is created once, by a person in their own terminal, \
         with:\n\
         #   opv access {env} --target {target} --create --github <owner/repo>{github_env_flag}\n"
    ));
    s.push_str(&format!("name: {id}\n\n"));
    s.push_str("on:\n  pull_request:\n  pull_request_review:\n    types: [submitted]\n  workflow_dispatch:\n\n");
    s.push_str("permissions:\n  contents: read\n\n");
    s.push_str(&format!("jobs:\n  {id}:\n"));
    s.push_str("    if: github.event_name == 'workflow_dispatch'\n");
    s.push_str("    runs-on: ubuntu-latest\n");
    if let Some(g) = github_env {
        s.push_str(&format!("    environment: {g}\n"));
    }
    s.push_str("    env:\n");
    s.push_str("      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}\n");
    s.push_str("      OP_CACHE: \"false\"\n");
    s.push_str(&format!(
        "      OPV_VERSION: v{version}   # pin the release you tested; bump it deliberately\n"
    ));
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n");
    s.push_str("      - name: Install the 1Password CLI\n");
    s.push_str("        uses: 1password/install-cli-action@v1\n");
    if let Some(step) = setup {
        s.push_str(step);
        s.push('\n');
    }
    s.push_str("      - name: Install opv\n");
    s.push_str("        run: |\n");
    s.push_str(
        "          base=https://github.com/matt-cochran/1password-vault/releases/download/$OPV_VERSION\n",
    );
    s.push_str("          curl -fsSLO \"$base/opv-x86_64-unknown-linux-musl\"\n");
    s.push_str("          curl -fsSLO \"$base/SHA256SUMS\"\n");
    s.push_str("          sha256sum -c SHA256SUMS --ignore-missing\n");
    s.push_str("          install -m 0755 opv-x86_64-unknown-linux-musl /usr/local/bin/opv\n");
    s.push_str(&format!("      - name: Sync secrets to {target}\n"));
    let confirm = if job.confirm {
        format!(" --confirm {env}")
    } else {
        String::new()
    };
    let deploy = if job.deploy { " --deploy" } else { "" };
    s.push_str(&format!(
        "        run: opv sync {env} --target {target}{confirm} --receipt {target}.receipt.json{deploy}\n"
    ));
    s.push_str("      - uses: actions/upload-artifact@v4\n");
    s.push_str(&format!(
        "        with: {{ name: {target}-delivery, path: {target}.receipt.json }}\n"
    ));
    s.push_str(&format!("      - name: Verify {target}'s delivery\n"));
    s.push_str(&format!(
        "        run: opv delivery verify {env} --target {target} --receipt {target}.receipt.json\n"
    ));
    s.push_str(&pull_request_jobs(job));
    s
}

/// The pull-request checks a single-target workflow runs: a `checks-<env>-<target>` job with
/// the `needs --gate`, `contract --check` and `ready --gate` steps, and the separate
/// `opv/relaxations` status (its job id is `relaxations`) that fails while the working
/// contract relaxes the default branch and the pull request's head has no approving review.
/// The sync job runs only on `workflow_dispatch`; these jobs only on `pull_request`.
fn pull_request_jobs(job: &Job<'_>) -> String {
    let (env, target) = (job.env, job.target);
    let version = env!("CARGO_PKG_VERSION");
    let id = format!("checks-{env}-{target}");
    let mut s = String::new();
    s.push_str(&format!("  {id}:\n"));
    s.push_str("    if: github.event_name == 'pull_request'\n");
    s.push_str("    runs-on: ubuntu-latest\n");
    s.push_str("    env:\n");
    s.push_str("      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}\n");
    s.push_str("      OP_CACHE: \"false\"\n");
    s.push_str(&format!(
        "      OPV_VERSION: v{version}   # pin the release you tested; bump it deliberately\n"
    ));
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0   # the default branch, for needs and relaxations\n");
    s.push_str("      - name: Install the 1Password CLI\n");
    s.push_str("        uses: 1password/install-cli-action@v1\n");
    s.push_str(&install_opv());
    s.push_str("      - name: Fail on a name the code reads but the contract does not declare\n");
    s.push_str("        run: opv needs --gate\n");
    s.push_str("      - name: Fail on a stale committed contract\n");
    s.push_str("        run: opv contract --check contract.json\n");
    s.push_str(&format!(
        "      - name: Fail unless {env} passes the promotion gate\n"
    ));
    s.push_str(&format!("        run: opv ready {env} --gate\n"));
    s.push_str(&relaxations_job());
    s
}

/// An `Install opv` step, indented as a `steps:` entry: the same pinned, checksum-verified
/// install every generated job uses.
fn install_opv() -> String {
    let mut s = String::new();
    s.push_str("      - name: Install opv\n");
    s.push_str("        run: |\n");
    s.push_str(
        "          base=https://github.com/matt-cochran/1password-vault/releases/download/$OPV_VERSION\n",
    );
    s.push_str("          curl -fsSLO \"$base/opv-x86_64-unknown-linux-musl\"\n");
    s.push_str("          curl -fsSLO \"$base/SHA256SUMS\"\n");
    s.push_str("          sha256sum -c SHA256SUMS --ignore-missing\n");
    s.push_str("          install -m 0755 opv-x86_64-unknown-linux-musl /usr/local/bin/opv\n");
    s
}

/// The separate `opv/relaxations` required status: list the working contract's relaxations
/// against the default branch and fail while any is unapproved at the pull request's head
/// SHA. It reads the GitHub token the workflow already has and no 1Password secret, and it
/// prints names and reasons only.
fn relaxations_job() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let mut s = String::new();
    s.push_str("  relaxations:\n");
    s.push_str("    name: opv/relaxations\n");
    s.push_str("    if: github.event_name == 'pull_request' || github.event_name == 'pull_request_review'\n");
    s.push_str("    runs-on: ubuntu-latest\n");
    s.push_str("    permissions: {contents: read, pull-requests: read}\n");
    s.push_str("    env:\n");
    s.push_str("      GH_TOKEN: ${{ github.token }}\n");
    s.push_str("      OP_CACHE: \"false\"\n");
    s.push_str(&format!(
        "      OPV_VERSION: v{version}   # pin the release you tested; bump it deliberately\n"
    ));
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0   # the default branch, for needs and relaxations\n");
    s.push_str(&install_opv());
    s.push_str("      - name: Fail on an unapproved contract relaxation\n");
    s.push_str("        env:\n");
    s.push_str("          BASE: origin/${{ github.event.repository.default_branch }}\n");
    s.push_str("          PR: ${{ github.event.pull_request.number }}\n");
    s.push_str("          REPO: ${{ github.repository }}\n");
    s.push_str("        run: |\n");
    s.push_str("          relaxations=$(opv contract --relaxations --base \"$BASE\" --json)\n");
    s.push_str("          count=$(jq 'if type == \"array\" then length else (.relaxations // [] | length) end' <<<\"$relaxations\")\n");
    s.push_str("          if [ \"$count\" -eq 0 ]; then\n");
    s.push_str("            echo \"no contract relaxations\"\n");
    s.push_str("            exit 0\n");
    s.push_str("          fi\n");
    s.push_str("          api=\"https://api.github.com/repos/$REPO/pulls/$PR\"\n");
    s.push_str("          auth=\"Authorization: Bearer $GH_TOKEN\"\n");
    s.push_str("          head=$(curl -fsSL -H \"$auth\" \"$api\" | jq -r .head.sha)\n");
    s.push_str("          approved=$(curl -fsSL -H \"$auth\" \"$api/reviews\" | jq --arg head \"$head\" '[.[] | select(.state == \"APPROVED\" and .commit_id == $head)] | length')\n");
    s.push_str("          if [ \"$approved\" -eq 0 ]; then\n");
    s.push_str("            echo \"contract relaxations need an approving review at $head:\"\n");
    s.push_str("            jq . <<<\"$relaxations\"\n");
    s.push_str("            exit 1\n");
    s.push_str("          fi\n");
    s.push_str("          echo \"contract relaxations approved at $head\"\n");
    s
}

// --- #206: deliver-only infrastructure values ---------------------------------------------

/// The infrastructure keys target `target` of `env` delivers (#206, §2.3): its supplied
/// bindings, as `(product/KEY, name on the target)`, sorted by key.
fn supplied_keys(fleet: &Fleet, env: &str, target: &str) -> Result<Vec<(String, String)>, Error> {
    let mut out = Vec::new();
    for product in fleet.products.keys() {
        for b in super::delivery::bindings(fleet, env, target, product)? {
            if b.source.item_id == crate::domain::delivery::SUPPLIED {
                out.push((b.source.field, b.name));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The output name a key's jq mapping reads, as a placeholder for the producer's own
/// output: `api/DATABASE_URL` reads `.database_url`.
fn output_name(label: &str) -> String {
    label
        .rsplit('/')
        .next()
        .unwrap_or(label)
        .to_ascii_lowercase()
}

/// Print the step that delivers target `target`'s infrastructure values (#206, §8.1), to
/// paste into the job that produced them (the Terraform apply job), never a job of its own
/// and with no concurrency group: `set -euo pipefail`, one jq mapping per key whose error
/// is a fixed message (S4), and the supplying sync. It never adds `--rotate` (S5). It is
/// followed by the pull-request job that checks the workflow file with `--supply-check`.
pub fn run_supply(
    fleet: &Fleet,
    env: &str,
    target: &str,
    deploy: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (e, _) = super::target(fleet, env, target)?;
    let keys = supplied_keys(fleet, env, target)?;
    if keys.is_empty() {
        return Err(Cause::Usage {
            problem: UsageProblem::EntryFormat {
                flag: "--supply".into(),
                entry: target.to_string(),
                format: "a target that delivers an infrastructure key (source = \"infrastructure\")",
            },
        }
        .into());
    }
    out.write_all(supply_step(env, target, &keys, deploy, e.confirm_env).as_bytes())
        .map_err(write_err)
}

/// The text of [`run_supply`].
fn supply_step(
    env: &str,
    target: &str,
    keys: &[(String, String)],
    deploy: bool,
    confirm: bool,
) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "# opv: deliver {target}'s infrastructure values ({env}). Paste this step into the job\n"
    ));
    s.push_str(
        "# that produced them (the job that runs terraform apply), after that step, in the\n",
    );
    s.push_str(
        "# job's own concurrency group. The job needs opv, the 1Password CLI and the target's\n",
    );
    s.push_str(&format!(
        "# CLI: see opv ci workflow {env} --target {target} for those steps.\n"
    ));
    s.push_str("# Map each output below to your producer's own output name.\n");
    s.push_str("# Never put ${{ ... }} in the script: GitHub expands it into the logged script.\n");
    s.push_str("# Pass values through the step's env: instead (checked by opv ci workflow --supply-check).\n");
    s.push_str(&format!(
        "      - name: Deliver infrastructure values to {target} through opv\n"
    ));
    s.push_str("        env:\n");
    s.push_str("          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}\n");
    s.push_str("        run: |\n");
    s.push_str("          set -euo pipefail\n");
    s.push_str(
        "          # the producer's own serial (Terraform's state serial), never a CI counter\n",
    );
    s.push_str("          serial=$(terraform state pull | jq -e '.serial')\n");
    s.push_str(&format!(
        "          terraform output -json | jq -ce --argjson s \"$serial\" '{{schema: \"opv.supply/1\", env: \"{env}\", serial: $s, values: {{\n"
    ));
    let last = keys.len().saturating_sub(1);
    for (i, (label, _)) in keys.iter().enumerate() {
        let o = output_name(label);
        let sep = if i == last { "}}'" } else { "," };
        s.push_str(&format!(
            "            \"{label}\": (.{o}.value | strings // error(\"{o} missing\")){sep}\n"
        ));
    }
    let deploy = if deploy { " --deploy" } else { "" };
    let confirm = if confirm {
        format!(" --confirm {env}")
    } else {
        String::new()
    };
    s.push_str(&format!(
        "            | opv sync {env} --target {target} --supply-stdin{deploy} --receipt {target}.receipt.json{confirm}\n"
    ));
    s.push_str(&format!(
        "          opv delivery verify {env} --target {target} --receipt {target}.receipt.json\n"
    ));
    s.push('\n');
    s.push_str(
        "# And this job, in a workflow that runs on pull_request, to keep the step value-safe:\n",
    );
    s.push_str("  opv-supply-check:\n");
    s.push_str("    if: github.event_name == 'pull_request'\n");
    s.push_str("    runs-on: ubuntu-latest\n");
    s.push_str("    env:\n");
    s.push_str(&format!(
        "      OPV_VERSION: v{}   # pin the release you tested; bump it deliberately\n",
        env!("CARGO_PKG_VERSION")
    ));
    s.push_str("    steps:\n");
    s.push_str("      - uses: actions/checkout@v4\n");
    s.push_str(&install_opv());
    s.push_str("      - name: Fail on an expression in a step that pipes into --supply-stdin\n");
    s.push_str("        run: opv ci workflow --supply-check .github/workflows/apply.yml\n");
    s
}

/// `opv ci workflow --supply-check <file>` (#206 §8.1, S4): refuse a workflow file in which
/// a step whose `run:` script pipes into `--supply-stdin` uses a `${{ … }}` expression other
/// than `github.*` in that script, since GitHub expands it into the step's logged script.
/// The step's `env:` is not its script and may use any expression. Read-only; prints one
/// line when the file passes.
pub fn run_supply_check(path: &std::path::Path, out: &mut dyn Write) -> Result<(), Error> {
    let text = std::fs::read_to_string(path).map_err(|e| -> Error {
        Cause::InputUnreadable {
            path: path.to_path_buf(),
            kind: crate::cause::InputKind::Workflow,
            io: e.kind().into(),
        }
        .into()
    })?;
    if let Some((line, col)) = expression_in_supply_step(&text) {
        return Err(Cause::InputInvalid {
            path: path.to_path_buf(),
            kind: crate::cause::InputKind::Workflow,
            at: Some(crate::cause::Location { line, col }),
            field: "the run: script of a step that pipes into --supply-stdin".into(),
            rule: crate::cause::FieldRule::Supply {
                supply: crate::cause::SupplyRule::ExpressionInSupplyStep { line },
            },
        }
        .into());
    }
    writeln!(
        out,
        "{}: no step that pipes into --supply-stdin expands a ${{{{ }}}} expression other than github.*",
        path.display()
    )
    .map_err(write_err)
}

/// One `run:` script of a workflow file: its lines with their 1-based line numbers.
struct Script {
    lines: Vec<(u32, String)>,
}

/// Every `run:` script of `text`: an inline `run: <command>`, or a block scalar (`run: |`
/// or `run: >`, with chomping or indentation indicators) whose lines are indented deeper
/// than the key. A YAML-shaped scan: no YAML parser, so a script is what GitHub runs.
fn scripts(text: &str) -> Vec<Script> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let body = trimmed.strip_prefix("- ").map_or(trimmed, str::trim_start);
        let Some(rest) = body.strip_prefix("run:") else {
            i += 1;
            continue;
        };
        let key_indent = line.len() - body.len();
        let rest = rest.trim();
        let number = |n: usize| u32::try_from(n + 1).unwrap_or(u32::MAX);
        if rest.starts_with('|') || rest.starts_with('>') {
            let mut script = Script { lines: Vec::new() };
            let mut j = i + 1;
            while j < lines.len() {
                let l = lines[j];
                let indent = l.len() - l.trim_start().len();
                if !l.trim().is_empty() && indent <= key_indent {
                    break;
                }
                script.lines.push((number(j), l.to_string()));
                j += 1;
            }
            out.push(script);
            i = j;
        } else {
            out.push(Script {
                lines: vec![(number(i), line.to_string())],
            });
            i += 1;
        }
    }
    out
}

/// The line and column of the first `${{ … }}` expression other than `github.*` in a `run:`
/// script of `text` that pipes into `--supply-stdin`, or `None`.
fn expression_in_supply_step(text: &str) -> Option<(u32, u32)> {
    for script in scripts(text) {
        if !script
            .lines
            .iter()
            .any(|(_, l)| l.contains("--supply-stdin"))
        {
            continue;
        }
        for (n, l) in &script.lines {
            let mut from = 0;
            while let Some(at) = l[from..].find("${{") {
                let start = from + at;
                let inner_start = start + 3;
                let end = l[inner_start..]
                    .find("}}")
                    .map_or(l.len(), |e| inner_start + e);
                let expr = l[inner_start..end].trim();
                if !expr.starts_with("github.") {
                    let col = u32::try_from(start + 1).unwrap_or(u32::MAX);
                    return Some((*n, col));
                }
                from = end.min(l.len());
                if from == l.len() {
                    break;
                }
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "ci_workflow_tests.rs"]
mod tests;
