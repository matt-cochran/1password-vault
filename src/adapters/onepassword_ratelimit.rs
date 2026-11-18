//! `op service-account ratelimit` under the agent identity's token (#338, design
//! `agent-identity.md` §7.4, vet R7; spike S1 `spike-338-findings.md` §6.1, §7).
//!
//! op prints one row per limit: the token's hourly `read` and `write` limits, and the
//! account's daily `read_write` limit, which every service account on the account shares (CI
//! included). `--format json` is an array of objects with the keys `type`, `action`, `limit`,
//! `used`, `remaining` and `reset`; the table has the columns `TYPE ACTION LIMIT USED
//! REMAINING RESET`. Both are read; anything else is unreadable (`None`), and the doctor row
//! then omits the figure (it never fails on it).
//!
//! Counts only: no name, id or value is kept from the output (ADR-0001 R1).

use serde_json::Value;

use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// Whose limit a row is (op's `type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Per token, hourly.
    Token,
    /// Per 1Password account, daily, shared by every service account on it.
    Account,
}

/// What a row counts (op's `action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    ReadWrite,
}

/// One limit: counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub scope: Scope,
    pub action: Action,
    pub limit: u64,
    pub used: u64,
    pub remaining: u64,
}

impl Limit {
    /// The share used, in whole percent (0 when the limit is 0).
    pub fn used_pct(&self) -> u64 {
        (self.used * 100).checked_div(self.limit).unwrap_or(0)
    }

    /// The share remaining, in whole percent (0 when the limit is 0).
    pub fn remaining_pct(&self) -> u64 {
        (self.remaining * 100).checked_div(self.limit).unwrap_or(0)
    }
}

/// Every limit op reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimits {
    pub limits: Vec<Limit>,
}

impl RateLimits {
    fn find(&self, scope: Scope, action: Action) -> Option<&Limit> {
        self.limits
            .iter()
            .find(|l| l.scope == scope && l.action == action)
    }

    /// The token's hourly read limit.
    pub fn token_read(&self) -> Option<&Limit> {
        self.find(Scope::Token, Action::Read)
    }

    /// The account's daily limit, reads and writes combined, shared with CI (spike §6.1).
    pub fn account_read_write(&self) -> Option<&Limit> {
        self.find(Scope::Account, Action::ReadWrite)
    }
}

fn scope(s: &str) -> Option<Scope> {
    match s.trim().to_ascii_lowercase().as_str() {
        "token" => Some(Scope::Token),
        "account" => Some(Scope::Account),
        _ => None,
    }
}

fn action(s: &str) -> Option<Action> {
    match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "read" => Some(Action::Read),
        "write" => Some(Action::Write),
        "read_write" | "readwrite" => Some(Action::ReadWrite),
        _ => None,
    }
}

fn count(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// The JSON form: an array of `{type, action, limit, used, remaining, reset}`. A row whose
/// type or action opv does not know is skipped; a known row with a missing count makes the
/// whole output unreadable.
pub fn parse_json(bytes: &[u8]) -> Option<RateLimits> {
    let rows: Vec<serde_json::Map<String, Value>> = serde_json::from_slice(bytes).ok()?;
    let mut limits = Vec::new();
    for row in &rows {
        let text = |k: &str| row.get(k).and_then(Value::as_str);
        let (Some(scope), Some(action)) = (
            text("type").and_then(scope),
            text("action").and_then(action),
        ) else {
            continue;
        };
        let n = |k: &str| row.get(k).and_then(count);
        limits.push(Limit {
            scope,
            action,
            limit: n("limit")?,
            used: n("used")?,
            remaining: n("remaining")?,
        });
    }
    (!limits.is_empty()).then_some(RateLimits { limits })
}

/// The table form: a `TYPE ACTION LIMIT USED REMAINING RESET` header, then one row per
/// limit (`RESET` is free text and ignored).
pub fn parse_table(text: &str) -> Option<RateLimits> {
    let mut lines = text.lines().skip_while(|l| l.trim().is_empty());
    let header: Vec<String> = lines
        .next()?
        .split_whitespace()
        .map(str::to_ascii_uppercase)
        .collect();
    if header.get(..5)? != ["TYPE", "ACTION", "LIMIT", "USED", "REMAINING"] {
        return None;
    }
    let mut limits = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let (Some(scope), Some(action)) = (
            cols.first().copied().and_then(scope),
            cols.get(1).copied().and_then(action),
        ) else {
            continue;
        };
        let n = |i: usize| cols.get(i)?.parse::<u64>().ok();
        limits.push(Limit {
            scope,
            action,
            limit: n(2)?,
            used: n(3)?,
            remaining: n(4)?,
        });
    }
    (!limits.is_empty()).then_some(RateLimits { limits })
}

/// [`parse_json`], else [`parse_table`].
pub fn parse(bytes: &[u8]) -> Option<RateLimits> {
    parse_json(bytes).or_else(|| parse_table(std::str::from_utf8(bytes).ok()?))
}

/// `op service-account ratelimit --format json` under this process's identity (the agent's
/// token, attached by the runner), bounded by [`PROBE_TIMEOUT`]. `None` when it fails or
/// prints something unreadable; the failure is expected and explains nothing later (NR-31).
pub fn read(r: &dyn CommandRunner) -> Option<RateLimits> {
    let call = Call::new(
        crate::adapters::onepassword::OP,
        &["service-account", "ratelimit", "--format", "json"],
    );
    match r.probe(&call, PROBE_TIMEOUT) {
        Ok(o) if o.status == 0 => parse(&o.stdout),
        _ => {
            let _ = crate::runner::take_failure();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    /// The spike's owner run (§6.1), in op's JSON shape.
    const JSON: &str = r#"[
        {"type":"token","action":"write","limit":100,"used":1,"remaining":99,"reset":3540},
        {"type":"token","action":"read","limit":1000,"used":2,"remaining":998,"reset":3540},
        {"type":"account","action":"read_write","limit":1000,"used":8,"remaining":992,"reset":46800}
    ]"#;

    /// The same figures as op's table.
    const TABLE: &str = "TYPE       ACTION        LIMIT    USED    REMAINING    RESET\n\
        token      write         100      1       99           59 minutes from now\n\
        token      read          1000     2       998          59 minutes from now\n\
        account    read_write    1000     8       992          13 hours from now\n";

    #[test]
    fn the_json_form_gives_the_account_read_write_limit() {
        let limits = parse(JSON.as_bytes()).unwrap();
        assert_eq!(
            limits.account_read_write().copied(),
            Some(Limit {
                scope: Scope::Account,
                action: Action::ReadWrite,
                limit: 1000,
                used: 8,
                remaining: 992,
            })
        );
    }

    #[test]
    fn the_json_form_gives_the_token_read_limit() {
        let limits = parse(JSON.as_bytes()).unwrap();
        assert_eq!(
            limits.token_read().map(|l| (l.limit, l.used)),
            Some((1000, 2))
        );
    }

    #[test]
    fn the_table_form_reads_as_the_json_form_does() {
        assert_eq!(parse(TABLE.as_bytes()), parse(JSON.as_bytes()));
    }

    #[test]
    fn counts_given_as_strings_are_read() {
        let json = r#"[{"type":"account","action":"read_write","limit":"1000","used":"950","remaining":"50","reset":"13 hours"}]"#;
        assert_eq!(
            parse(json.as_bytes()).and_then(|l| l.account_read_write().map(Limit::remaining_pct)),
            Some(5)
        );
    }

    #[test]
    fn unrelated_output_is_unreadable() {
        assert_eq!(parse(b"[ERROR] something went wrong\n"), None);
    }

    #[test]
    fn a_known_row_without_its_counts_is_unreadable() {
        assert_eq!(
            parse(br#"[{"type":"token","action":"read","limit":1000}]"#),
            None
        );
    }

    #[test]
    fn an_empty_list_is_unreadable() {
        assert_eq!(parse(b"[]"), None);
    }

    #[test]
    fn a_failed_ratelimit_call_is_unreadable() {
        let r = FakeRunner::new(vec![Output {
            status: 1,
            stdout: Vec::new().into(),
        }]);
        assert_eq!(read(&r), None);
    }

    #[test]
    fn the_call_is_the_ratelimit_command_in_json() {
        let r = FakeRunner::new(vec![Output::success(JSON.as_bytes().to_vec())]);
        let _ = read(&r);
        assert_eq!(
            r.calls.borrow()[0].args,
            ["service-account", "ratelimit", "--format", "json"]
        );
    }

    #[test]
    fn a_zero_limit_is_zero_percent_used() {
        let l = Limit {
            scope: Scope::Token,
            action: Action::Read,
            limit: 0,
            used: 5,
            remaining: 0,
        };
        assert_eq!(l.used_pct(), 0);
    }
}
