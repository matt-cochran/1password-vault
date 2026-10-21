//! The fake HTTPS attempt (design `http-target` §5).
//!
//! There is no separate code path here: under the `fake` feature, and only when
//! `OPV_SIM_WORLD` is set, the runner's HTTPS call is the `https` program spawned from
//! `PATH` like any other external call, so the fault matrix discovers and faults it too.
//! A release build has no fake attempt and never spawns a program named `https`; see
//! [`crate::runner_https`] and the process engine in [`crate::runner`].
