//! The sealed target (#271, `docs/design/sealed-target.md`): `opv sync` reads 1Password at
//! release time and writes one signed, encrypted bundle per product; the runtime opens it
//! with `opv unseal` and never reads 1Password.
//!
//! - [`config`]: the section and the §3.1 load rules, including the rules across targets
//!   (trust groups, D11) and the `sealed.out` resolver (D12).
//! - [`provider`]: the registered [`PROVIDER`] and the target's [`crate::provider::TargetConfig`].
//! - [`login`]: the SSH Key deploy credential (P2), checked against `sealed.signer` at sign-in
//!   and handed only to the runner's seal effect.
//!
//! - [`store`]: the whole-set `StagedStore` (P3): a verified, value-free listing, whole-bundle
//!   staleness, and the atomic write of one signed bundle per product.

pub mod config;
pub mod login;
pub mod provider;
pub mod store;

pub use provider::PROVIDER;
