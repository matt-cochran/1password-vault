//! The sealed target (#271, `docs/design/sealed-target.md`): `opv sync` reads 1Password at
//! release time and writes one signed, encrypted bundle per product; the runtime opens it
//! with `opv unseal` and never reads 1Password.
//!
//! - [`config`]: the section and the §3.1 load rules, including the rules across targets
//!   (trust groups, D11) and the `sealed.out` resolver (D12).
//! - [`provider`]: the registered [`PROVIDER`] and the target's [`crate::provider::TargetConfig`].
//!
//! Later lanes add `store.rs` (P3, the `StagedStore`), `login.rs` (P2, the SSH Key deploy
//! credential and signing); until then the provider's `open` and `deploy_login` refuse as
//! an internal error naming the missing lane.

pub mod config;
pub mod provider;

pub use provider::PROVIDER;
