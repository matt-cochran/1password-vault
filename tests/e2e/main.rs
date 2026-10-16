//! End-to-end scenarios (design §13.2): the real `opv` binary against `opv-sim`, on the
//! test application in `tests/e2e/app`. One module per scenario under `scenarios/`.
#![cfg(all(unix, feature = "fake"))]

mod scenarios {
    pub mod issue_159;
}
