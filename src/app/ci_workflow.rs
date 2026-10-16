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
use crate::cause::Cmd;
use crate::cause::render::cmd_text;
use crate::domain::Fleet;
use crate::error::{Code, Error};
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
    // Both an unknown environment and an unknown target are usage errors (exit 2), and the
    // target is resolved before a byte is written.
    let (e, t) = super::target(fleet, env, target).map_err(|e| match e.code() {
        Code::UnknownEnv => e.with_code(Code::Usage),
        _ => e,
    })?;
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
    s.push_str("on:\n  workflow_dispatch:\n\n");
    s.push_str("permissions:\n  contents: read\n\n");
    s.push_str(&format!("jobs:\n  {id}:\n"));
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
    s
}

#[cfg(test)]
#[path = "ci_workflow_tests.rs"]
mod tests;
