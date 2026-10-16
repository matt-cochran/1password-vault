//! Non-idempotent creates are their own runner effect (design `docs/design/error-catalog.md`
//! §5 "Creates are their own runner effect", §4.6 `CreateOutcomeUnknown`, rule X5): a create
//! runs only through [`CommandRunner::create`](crate::runner::CommandRunner::create), so no
//! call site can label one idempotent, and an unknown outcome is never worded as "did not
//! create".

use std::io;

use crate::cause::Observed;

use super::{Call, Outcome, Output, take_observed};

/// What a non-idempotent create came to (X5, §4.6). A refused create definitely made
/// nothing; an unknown one may have made the object, so its caller checks, never re-creates.
#[derive(Debug)]
pub enum CreateOutcome {
    /// Exit 0: the object was made.
    Done(Output),
    /// A definite refusal (a non-zero exit): nothing was made.
    Refused(Output),
    /// The create may or may not have taken effect (a timeout, a kill, a lost reply, a spent
    /// budget or a signal). The [`Observed`] names the call and the principal in effect.
    OutcomeUnknown(Observed),
}

/// Classify the outcome of running `call` as a write for a create. A spent budget (the call
/// never started) is unknown too, never an error a call site could word as "did not create".
pub(super) fn from_write(res: io::Result<Outcome>, call: &Call) -> io::Result<CreateOutcome> {
    let outcome = match res {
        Ok(outcome) => outcome,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
            return Ok(CreateOutcome::OutcomeUnknown(observed(call)));
        }
        Err(e) => return Err(e),
    };
    Ok(match outcome {
        Outcome::Done(o) => CreateOutcome::Done(o),
        Outcome::Refused(o) => CreateOutcome::Refused(o),
        // A create that exited non-zero was definitively refused: nothing was made.
        Outcome::Unknown {
            status: Some(code), ..
        } => CreateOutcome::Refused(Output::failure(code)),
        Outcome::Unknown { .. } => CreateOutcome::OutcomeUnknown(observed(call)),
    })
}

/// The observation of the failed create, or one naming the call when the attempt left none
/// (a lost reply or output over the cap has no exit class of its own).
fn observed(call: &Call) -> Observed {
    take_observed().unwrap_or_else(|| {
        super::observe::failed(
            call,
            &Ok((super::Attempt::TimedOut, super::Stderr::default())),
        )
        .expect("a create call to an external system is observable")
    })
}

#[cfg(test)]
mod tests {
    use crate::cause::{CallId, CreateKind, System};
    use crate::runner::fake::FakeRunner;
    use crate::runner::{Call, CommandRunner, Output};

    use super::CreateOutcome;

    fn call() -> Call<'static> {
        Call::new("flyctl", &["secrets", "create", "API_KEY"])
    }

    fn create(r: &FakeRunner) -> CreateOutcome {
        r.create(&call(), CreateKind::Vault).unwrap()
    }

    #[test]
    fn successful_create_is_done() {
        let r = FakeRunner::new([Output::success("")]);
        assert!(matches!(create(&r), CreateOutcome::Done(_)));
    }

    #[test]
    fn refused_create_is_refused() {
        let r = FakeRunner::new([Output::failure(1)]);
        assert!(matches!(create(&r), CreateOutcome::Refused(_)));
    }

    #[test]
    fn timed_out_create_is_unknown_under_the_calls_id() {
        let r = FakeRunner::default();
        r.push_unknown("timeout");
        let seen = match create(&r) {
            CreateOutcome::OutcomeUnknown(seen) => seen,
            other => panic!("expected an unknown outcome, got {other:?}"),
        };
        assert_eq!(
            seen.call(),
            &CallId {
                system: System::Fly,
                program: "flyctl".into(),
                words: vec!["secrets".into(), "create".into(), "API_KEY".into()],
            }
        );
    }

    #[test]
    fn signalled_create_is_unknown() {
        let r = FakeRunner::default();
        r.push_unknown("killed");
        assert!(matches!(create(&r), CreateOutcome::OutcomeUnknown(_)));
    }
}
