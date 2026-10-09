//! The registered deployment providers (FR-37). Adding a provider is one module under
//! `src/adapters/<provider>/` plus one line in [`PROVIDERS`].

use super::{azure, fly, kubernetes};
use crate::provider::Provider;

/// Every provider, in the order their sections are named in messages.
pub static PROVIDERS: &[&dyn Provider] = &[&fly::PROVIDER, &azure::PROVIDER, &kubernetes::PROVIDER];

/// The provider opv suggests when an environment has none, and the one `opv init` writes.
pub static DEFAULT: &dyn Provider = &fly::PROVIDER;

/// The provider registered under `section`.
pub fn find(section: &str) -> Option<&'static dyn Provider> {
    PROVIDERS.iter().copied().find(|p| p.section() == section)
}

/// Every provider's credential variable names, in registry order (see `Host::token`).
pub fn credential_vars() -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .flat_map(|p| p.credential_vars())
        .copied()
        .collect()
}

/// The provider that declares store kind `kind` (FR-39).
pub fn store_kind(kind: &str) -> Option<&'static dyn Provider> {
    PROVIDERS
        .iter()
        .copied()
        .find(|p| p.store_kinds().contains(&kind))
}

/// Every declared store kind, sorted, for "known: ..." messages.
pub fn store_kinds() -> Vec<&'static str> {
    let mut k: Vec<&str> = PROVIDERS
        .iter()
        .flat_map(|p| p.store_kinds())
        .copied()
        .collect();
    k.sort_unstable();
    k
}

/// Whether the runtime of `section` can keep its secrets in a store of `kind`.
pub fn binds(section: &str, kind: &str) -> bool {
    find(section).is_some_and(|p| p.bindings().iter().any(|b| b.store_kind == kind))
}

/// Every supported `secrets_in` pair, e.g. `azure_key_vault → kubernetes (External Secrets
/// Operator)`, in registry order.
pub fn supported_pairs() -> Vec<String> {
    PROVIDERS
        .iter()
        .flat_map(|p| {
            p.bindings()
                .iter()
                .map(move |b| format!("{} → {} ({})", b.store_kind, p.section(), b.via))
        })
        .collect()
}

/// Every provider's user-facing name, in registry order, for help and the schema.
pub fn labels() -> Vec<&'static str> {
    PROVIDERS.iter().map(|p| p.label()).collect()
}

/// Every provider's own CLI, in registry order, for help text.
pub fn programs() -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .filter_map(|p| p.tools().first().map(|t| t.program))
        .collect()
}

/// Every registered section name, sorted, for "known: ..." messages.
pub fn sections() -> Vec<&'static str> {
    let mut s: Vec<&str> = PROVIDERS.iter().map(|p| p.section()).collect();
    s.sort_unstable();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lists_azure_fly_and_kubernetes() {
        assert_eq!(sections(), ["azure", "fly", "kubernetes"]);
    }

    #[test]
    fn the_only_secrets_in_pair_is_key_vault_to_kubernetes() {
        assert_eq!(
            supported_pairs(),
            ["azure_key_vault → kubernetes (External Secrets Operator)"]
        );
    }

    #[test]
    fn azure_declares_the_key_vault_store_kind() {
        assert_eq!(
            store_kind("azure_key_vault").map(|p| p.section()),
            Some("azure")
        );
    }

    /// `Host` keeps one bit per credential variable.
    #[test]
    fn credential_vars_fit_the_host_bitset() {
        assert!(credential_vars().len() <= 64);
    }
}
