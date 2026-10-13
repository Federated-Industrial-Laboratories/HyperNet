// SPDX-License-Identifier: MIT
// Result input validation retains the current verified state without widening its closure.
use super::*;
use crate::{
    authority_application::tests::{Fixture, state_parses},
    authority_objects::Class,
};
use std::sync::Arc;

#[test]
fn executed_inputs_preserves_verified_current_state_and_revalidates_changed_bytes() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    let committed = f.committed(&intent, 10000, 11251, 1);
    let execution = f
        .app
        .execute(&f.initial, &committed, &Resolved::default())
        .unwrap();
    let before = state_parses(&f.app);
    assert_eq!(before, 1);
    assert!(
        executed_inputs(&f.app, &f.initial, &committed.command, &execution.state)
            .unwrap()
            .is_empty()
    );
    assert_eq!(state_parses(&f.app), before + 1);
    f.app.validate_checkpoint(&execution.state, 1).unwrap();
    assert!(f.app.retained_inputs(&execution.state).unwrap().is_empty());
    assert_eq!(state_parses(&f.app), before + 1);

    let mut invalid_prior = f.initial.clone();
    *invalid_prior.last_mut().unwrap() ^= 1;
    assert!(executed_inputs(&f.app, &invalid_prior, &committed.command, &execution.state).is_err());
    let mut invalid_next = wire::decode_state(&execution.state).unwrap();
    let V::Array(fields) = &mut invalid_next else {
        unreachable!()
    };
    fields[2] = V::Bytes(vec![99; 32]);
    assert!(
        executed_inputs(
            &f.app,
            &f.initial,
            &committed.command,
            &wire::encode_state(&invalid_next).unwrap()
        )
        .is_err()
    );
}

struct Claims {
    application: Arc<dyn Application>,
    next: Vec<u8>,
    reference: InputReference,
    from_command: bool,
    from_prior: bool,
}
impl Application for Claims {
    fn command_inputs(&self, ordered: &[u8]) -> Result<Vec<InputReference>> {
        let mut references = self.application.command_inputs(ordered)?;
        if self.from_command {
            references.push(self.reference.clone());
        }
        Ok(references)
    }
    fn retained_inputs(&self, state: &[u8]) -> Result<Vec<InputReference>> {
        let mut references = self.application.retained_inputs(state)?;
        if state == self.next.as_slice() || self.from_prior {
            references.push(self.reference.clone());
        }
        Ok(references)
    }
    fn validate_checkpoint(&self, state: &[u8], height: u64) -> Result<()> {
        self.application.validate_checkpoint(state, height)
    }
    fn validate(
        &self,
        prior: &[u8],
        command: &[u8],
        evaluated_at: u64,
        inputs: &Resolved,
    ) -> Result<()> {
        self.application
            .validate(prior, command, evaluated_at, inputs)
    }
    fn execute(&self, prior: &[u8], committed: &Committed, inputs: &Resolved) -> Result<Execution> {
        self.application.execute(prior, committed, inputs)
    }
}

#[test]
fn executed_inputs_requires_each_result_reference_in_prior_or_command() {
    let f = Fixture::new();
    let intent = f.intent(1, &f.expected, 1);
    let committed = f.committed(&intent, 10000, 11251, 1);
    let execution = f
        .app
        .execute(&f.initial, &committed, &Resolved::default())
        .unwrap();
    let reference = InputReference::for_bytes(Class::PageSource, b"Retained page bytes").unwrap();
    let application: Arc<dyn Application> = Arc::new(f.app);
    for (from_prior, from_command) in [(false, false), (true, false), (false, true)] {
        let app = Claims {
            application: Arc::clone(&application),
            next: execution.state.clone(),
            reference: reference.clone(),
            from_command,
            from_prior,
        };
        let result = executed_inputs(&app, &f.initial, &committed.command, &execution.state);
        if from_prior || from_command {
            assert_eq!(result.unwrap(), vec![reference.clone()]);
        } else {
            assert!(result.is_err());
        }
    }
}
