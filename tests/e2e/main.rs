//! End-to-end scenarios (design §13.2): the real `opv` binary against `opv-sim`, on the
//! test application in `tests/e2e/app`. One module per scenario under `scenarios/`.
#![cfg(all(unix, feature = "fake"))]

mod coverage;

mod scenarios {
    pub mod assistant;
    pub mod changed;
    pub mod consistency;
    pub mod file_key_guidance;
    pub mod fixes_0141;
    pub mod fixes_0161;
    pub mod http_target_faults;
    pub mod http_target_sync;
    pub mod infrastructure_values;
    pub mod issue_159;
    pub mod issues;
    pub mod k8s_files;
    pub mod live_audit;
    pub mod session_reuse;
    pub mod set_from_file;
    pub mod wiring;
}
