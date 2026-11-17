//! The value-free local index of agent identities on this machine (FR-59; design
//! `docs/design/agent-identity.md` §7.5).
//!
//! One [`AgentRecord`] per identity records only what is needed to enumerate identities
//! (`--rotate --agent` with no environment) and to read an expiry without opening the OS
//! store. It holds no token, value or digest (ADR-0001), and it lives outside the
//! repository. Pure data: the file that stores it is read and written elsewhere.

/// One agent identity recorded on this machine: its 1Password service-account name, where it
/// belongs, which OS store keeps its token, and its dates. No field is ever a value, a token
/// or a digest (ADR-0001, design `agent-identity.md` §7.5).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentRecord {
    /// The 1Password service-account name, `{project}-{environment}-agent-{machine}`.
    pub account_name: String,
    /// The environment the identity belongs to.
    pub environment: String,
    /// The machine part of the account name.
    pub machine: String,
    /// The OS store that keeps the token (for example `macos_keychain`).
    pub store: String,
    /// The date the identity was created, `YYYY-MM-DD`.
    pub created_on: String,
    /// The expiry date, `YYYY-MM-DD`.
    pub expires_on: String,
    /// While a rotation is pending, the successor account's name; `None` otherwise.
    pub rotation_successor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn record() -> AgentRecord {
        AgentRecord {
            account_name: "shop-dev-agent-laptop".to_string(),
            environment: "dev".to_string(),
            machine: "laptop".to_string(),
            store: "macos_keychain".to_string(),
            created_on: "2026-11-17".to_string(),
            expires_on: "2027-02-15".to_string(),
            rotation_successor: None,
        }
    }

    #[test]
    fn an_agent_record_serializes_exactly_its_value_free_fields() {
        let json = serde_json::to_value(record()).unwrap();
        let keys: BTreeSet<String> = json.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "account_name".to_string(),
                "environment".to_string(),
                "machine".to_string(),
                "store".to_string(),
                "created_on".to_string(),
                "expires_on".to_string(),
                "rotation_successor".to_string(),
            ])
        );
    }
}
