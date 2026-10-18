//! Manifest scanner patterns (design Part V, row `scan-manifests`): `.env.example`,
//! Docker Compose, Kubernetes, `fly.toml` and GitHub Actions workflows.
//!
//! Every pattern is line-based (no YAML or TOML crate) and returns names only. A value is
//! dropped at the first `=`: it is never stored, returned, logged or rendered. A
//! `file:line` accompanies every name so the report can point at the source.

use super::{Kind, Observation, Pattern};

/// `.env.example` / `.env.sample` / `.env.template`: each `NAME=…` line gives the NAME.
pub struct DotEnv;

impl Pattern for DotEnv {
    fn language(&self) -> &'static str {
        "dotenv"
    }

    fn applies(&self, path: &str) -> bool {
        matches!(
            basename(path),
            ".env.example" | ".env.sample" | ".env.template"
        )
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Split at the first `=`: the right-hand side is dropped here, never kept.
            let Some((left, _value)) = line.split_once('=') else {
                continue;
            };
            let name = left.trim();
            if !name.is_empty() {
                out.push(observed(path, i + 1, name));
            }
        }
        out
    }
}

/// Docker Compose: `environment:` list items, map keys and `${NAME}` interpolations.
pub struct Compose;

impl Pattern for Compose {
    fn language(&self) -> &'static str {
        "compose"
    }

    fn applies(&self, path: &str) -> bool {
        let name = basename(path);
        let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
        yaml && (name.starts_with("docker-compose") || name.starts_with("compose"))
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        let mut env_indent: Option<usize> = None;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let indent = indent_of(raw);
            if let Some(env) = env_indent
                && indent <= env
            {
                env_indent = None;
            }
            for name in interpolations(line) {
                out.push(observed(path, i + 1, &name));
            }
            if line.starts_with("environment:") {
                env_indent = Some(indent);
                continue;
            }
            if let Some(env) = env_indent
                && indent > env
            {
                let name = if let Some(item) = line.strip_prefix("- ") {
                    item.split('=').next().unwrap_or_default().trim()
                } else {
                    line.split_once(':')
                        .map(|(key, _value)| key.trim())
                        .unwrap_or_default()
                };
                if !name.is_empty() {
                    out.push(observed(path, i + 1, name));
                }
            }
        }
        out
    }
}

/// Kubernetes manifests (a file with a `kind:`): `env:` items and referenced keys.
pub struct Kubernetes;

impl Pattern for Kubernetes {
    fn language(&self) -> &'static str {
        "kubernetes"
    }

    fn applies(&self, path: &str) -> bool {
        path.ends_with(".yaml") || path.ends_with(".yml")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        if !text
            .lines()
            .any(|line| line.trim_start().starts_with("kind:"))
        {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut env_indent: Option<usize> = None;
        let mut ref_indent: Option<usize> = None;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let indent = indent_of(raw);
            if let Some(env) = env_indent
                && indent <= env
            {
                env_indent = None;
            }
            if let Some(reference) = ref_indent
                && indent <= reference
            {
                ref_indent = None;
            }
            if line.starts_with("env:") {
                env_indent = Some(indent);
                continue;
            }
            if line.starts_with("secretKeyRef:") || line.starts_with("configMapKeyRef:") {
                ref_indent = Some(indent);
                continue;
            }
            if let Some(env) = env_indent
                && indent > env
                && let Some(item) = line.strip_prefix("- name:")
            {
                let name = item.trim();
                if !name.is_empty() {
                    out.push(observed(path, i + 1, name));
                }
            }
            if let Some(reference) = ref_indent
                && indent > reference
                && let Some(item) = line.strip_prefix("key:")
            {
                let name = item.trim();
                if !name.is_empty() {
                    out.push(observed(path, i + 1, name));
                }
            }
        }
        out
    }
}

/// `fly.toml`: the keys of the `[env]` table.
pub struct Fly;

impl Pattern for Fly {
    fn language(&self) -> &'static str {
        "fly"
    }

    fn applies(&self, path: &str) -> bool {
        basename(path) == "fly.toml"
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        let mut in_env = false;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                in_env = line == "[env]";
                continue;
            }
            if in_env && let Some((key, _value)) = line.split_once('=') {
                let key = key.trim();
                if !key.is_empty() {
                    out.push(observed(path, i + 1, key));
                }
            }
        }
        out
    }
}

/// GitHub Actions workflows: `secrets.NAME`, `vars.NAME` and `env:` map keys.
pub struct GithubActions;

impl Pattern for GithubActions {
    fn language(&self) -> &'static str {
        "github_actions"
    }

    fn applies(&self, path: &str) -> bool {
        (path.ends_with(".yml") || path.ends_with(".yaml")) && path.contains(".github/workflows/")
    }

    fn scan(&self, path: &str, text: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        let mut env_indent: Option<usize> = None;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let indent = indent_of(raw);
            if let Some(env) = env_indent
                && indent <= env
            {
                env_indent = None;
            }
            for name in expressions(line) {
                out.push(observed(path, i + 1, &name));
            }
            if line.starts_with("env:") {
                env_indent = Some(indent);
                continue;
            }
            if let Some(env) = env_indent
                && indent > env
                && let Some((key, _value)) = line.split_once(':')
            {
                let key = key.trim();
                if !key.is_empty() {
                    out.push(observed(path, i + 1, key));
                }
            }
        }
        out
    }
}

/// An observed name at `file:line`.
fn observed(path: &str, line: usize, name: &str) -> Observation {
    Observation {
        name: Some(name.to_string()),
        file: path.to_string(),
        line,
        kind: Kind::Observed,
    }
}

/// The final path component.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The number of leading spaces or tabs on `raw`.
fn indent_of(raw: &str) -> usize {
    raw.len() - raw.trim_start_matches([' ', '\t']).len()
}

/// The `NAME`s of `${NAME}` (or `${NAME:-default}`) interpolations on `line`.
fn interpolations(line: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let end = after.find(['}', ':']).unwrap_or(after.len());
        let name = after[..end].trim();
        if is_identifier(name) {
            names.push(name.to_string());
        }
        rest = &after[end..];
    }
    names
}

/// The `NAME`s of `${{ secrets.NAME }}` and `${{ vars.NAME }}` on `line`.
fn expressions(line: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else {
            break;
        };
        let inner = after[..end].trim();
        for prefix in ["secrets.", "vars."] {
            if let Some(name) = inner.strip_prefix(prefix) {
                let name = name.trim();
                if is_identifier(name) {
                    names.push(name.to_string());
                }
            }
        }
        rest = &after[end + 2..];
    }
    names
}

/// Whether `name` looks like an environment-variable identifier (the core validates the
/// final grammar; this only keeps shell fragments out).
fn is_identifier(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
#[path = "manifests_tests.rs"]
mod tests;
