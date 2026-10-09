//! The registered deployment providers (FR-37). Adding a provider is one module under
//! `src/adapters/<provider>/` plus one line in [`PROVIDERS`].

use super::{azure, fly};
use crate::provider::Provider;

/// Every provider, in the order their sections are named in messages.
pub static PROVIDERS: &[&dyn Provider] = &[&fly::PROVIDER, &azure::PROVIDER];

/// The provider opv suggests when an environment has none, and the one `opv init` writes.
pub static DEFAULT: &dyn Provider = &fly::PROVIDER;

/// The provider registered under `section`.
pub fn find(section: &str) -> Option<&'static dyn Provider> {
    PROVIDERS.iter().copied().find(|p| p.section() == section)
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
    fn registry_has_fly_and_azure() {
        assert_eq!(sections(), ["azure", "fly"]);
    }
}
