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

    /// `Host` keeps one bit per credential variable.
    #[test]
    fn credential_vars_fit_the_host_bitset() {
        assert!(credential_vars().len() <= 64);
    }
}
