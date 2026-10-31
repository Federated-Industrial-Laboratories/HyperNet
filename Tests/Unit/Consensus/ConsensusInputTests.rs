// SPDX-License-Identifier: MIT
//! Immutable bodies are available before votes and restored only under certified roots.
use super::super::super::{ExecutionOutput, application::Turn, repair};
use super::*;
use crate::authority_objects::{Class, Object, Reference as InputReference, Unavailable};

struct InputApplication {
    config: Configuration,
    references: Vec<InputReference>,
}
impl Application for InputApplication {
    fn result_inputs(&self, command: &[u8], result: &[u8]) -> Result<Vec<InputReference>> {
        let result = crate::authority_proof::OperationResult::parse(result)?;
        ensure!(
            result.disposition == crate::authority_proof::Disposition::Permit,
            "test object output requires a permit"
        );
        self.command_inputs(command)
    }
    fn command_inputs(&self, command: &[u8]) -> Result<Vec<InputReference>> {
        super::super::super::records::Command::parse(&self.config, command)?;
        Ok(self.references.clone())
    }
    fn retained_inputs(&self, state: &[u8]) -> Result<Vec<InputReference>> {
        if wire::digest(state) == self.config.genesis_governance {
            return Ok(vec![]);
        }
        let value = wire::decode_state(state)?;
        let fields = value.array(2)?;
        fields[1]
            .list(4096)?
            .iter()
            .map(InputReference::parse)
            .collect()
    }
    fn validate_checkpoint(&self, state: &[u8], height: u64) -> Result<()> {
        if height == 0 {
            ensure!(
                wire::digest(state) == self.config.genesis_governance,
                "wrong genesis"
            );
            return Ok(());
        }
        let value = wire::decode_state(state)?;
        ensure!(value.list(2)?[0].uint()? == height, "wrong height");
        crate::authority_objects::validate_references(&self.retained_inputs(state)?)
    }
    fn validate(&self, _: &[u8], command: &[u8], _: u64, inputs: &Resolved) -> Result<()> {
        for reference in self.command_inputs(command)? {
            inputs.get(&reference)?;
        }
        Ok(())
    }
    fn execute(&self, _: &[u8], position: &Committed, inputs: &Resolved) -> Result<Execution> {
        self.validate(&[], &position.command, position.evaluated_at, inputs)?;
        let mut result = fixtures::execution(&self.config, position);
        result.state = wire::encode(&V::Array(vec![
            V::Uint(position.height),
            V::Array(self.references.iter().map(InputReference::value).collect()),
        ]))?;
        if let ExecutionOutput::Result { attestation, .. } = &mut result.output {
            let mut fields = wire::decode(attestation)?.array(23)?.to_vec();
            fields[16] = V::Bytes(wire::digest(&result.state).to_vec());
            *attestation = wire::encode(&V::Array(fields))?;
        }
        Ok(result)
    }
}
fn objects() -> Resolved {
    // Exercise the supported source and bundle ceilings, not an artificial tiny capacity.
    let bodies = [
        (Class::PageSource, vec![b's'; 16384]),
        (Class::PageBundle, vec![b'b'; 57344]),
    ];
    let mut objects: Vec<_> = bodies
        .into_iter()
        .map(|(class, body)| {
            Object::verify(InputReference::for_bytes(class, &body).unwrap(), body).unwrap()
        })
        .collect();
    objects.sort_by(|a, b| a.reference().cmp(b.reference()));
    let refs: Vec<_> = objects.iter().map(|o| o.reference().clone()).collect();
    Resolved::exact(&refs, objects).unwrap()
}
fn commit_inputs(
    config: &Configuration,
    replicas: &mut [Engine],
    command: &[u8],
    inputs: &Resolved,
) -> Certificate {
    let proposal = replicas[0]
        .propose_with_inputs(command, 10000, inputs)
        .unwrap();
    let votes: Vec<_> = replicas
        .iter_mut()
        .map(|r| {
            SignedVote::parse(
                config,
                &r.prepare_with_inputs(&proposal, command, inputs, |_| Ok(()), |_, _| Ok(()))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let mut qc = Certificate::collect(config, &votes).unwrap();
    for _ in 0..2 {
        let votes: Vec<_> = replicas
            .iter_mut()
            .map(|r| SignedVote::parse(config, &r.advance_phase(&qc.bytes).unwrap()).unwrap())
            .collect();
        qc = Certificate::collect(config, &votes).unwrap();
    }
    qc
}
fn apply_inputs(engine: &mut Engine, app: &dyn Application) {
    for _ in 0..8 {
        let reader = engine.input_reader().unwrap();
        let turn = engine
            .apply_turn_with_inputs(|prior, position| {
                let resolved =
                    input_driver::evaluation_inputs(app, &reader, prior, &position.command, None)?;
                let execution = app.execute(prior, position, &resolved)?;
                let retained =
                    input_driver::executed_inputs(app, prior, &position.command, &execution.state)?;
                Ok((execution, retained))
            })
            .unwrap();
        if matches!(turn, Turn::Result(..) | Turn::Idle) {
            return;
        }
        assert!(!matches!(turn, Turn::Blocked(_) | Turn::Unavailable(_)));
    }
    panic!("application failed to progress");
}
#[test]
fn learned_quorum_remains_durable_while_missing_inputs_defer_its_vote() {
    let (configuration, keys) = fixture();
    let (directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let inputs = objects();
    let refs = inputs.references();
    let command = fixtures::request(&configuration, 75);
    commit_inputs(&configuration, &mut engines[..3], &command, &inputs);
    let source = &engines[0];
    let prepare = source
        .known_certificate(&source.snapshot.highest_prepare)
        .unwrap();
    let precommit = source.known_certificate(&source.snapshot.locked).unwrap();
    let required: Vec<_> = [
        (12, prepare.digest()),
        (14, prepare.node),
        (22, wire::digest(&command)),
    ]
    .into_iter()
    .map(|(kind, digest)| repair::Reference {
        kind,
        digest,
        signer: None,
    })
    .collect();
    let items = source.repair_export(&required).unwrap();
    let mut target = engines.pop().unwrap();
    target
        .repair_import_with_inputs(&required, &items, |_| Ok(refs.clone()))
        .unwrap();
    let lock = target.snapshot.locked;
    let generation = target.generation();
    target.receive_certificate(&precommit.bytes).unwrap();
    assert_eq!(target.generation(), generation + 1);
    assert_eq!(target.snapshot.locked, lock);
    assert!(target.snapshot.own_votes.is_empty());
    let error = target.advance_phase(&precommit.bytes).unwrap_err();
    assert!(error.downcast_ref::<Unavailable>().is_some());
    assert_eq!(target.generation(), generation + 1);
    drop(target);
    let mut target = Engine::open(
        &directories[3].0,
        configuration,
        keys[3].clone(),
        generation + 1,
    )
    .unwrap();
    assert_eq!(target.snapshot.highest_prepare, prepare.digest());
    assert_eq!(
        target.known_certificate(&precommit.digest()).unwrap().bytes,
        precommit.bytes
    );
    for object in inputs.objects() {
        target
            .import_certificate_input(precommit.digest(), object)
            .unwrap();
    }
    let generation = target.generation();
    target.receive_certificate(&precommit.bytes).unwrap();
    assert_eq!(target.generation(), generation + 1);
    assert_eq!(target.snapshot.locked, precommit.digest());
    target.advance_phase(&precommit.bytes).unwrap();
    assert_eq!(target.generation(), generation + 1);
}
#[test]
fn local_output_requires_quorum_and_exact_available_object_closure() {
    let (configuration, keys) = fixture();
    let (directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let inputs = objects();
    let refs = inputs.references();
    let app = Arc::new(InputApplication {
        config: configuration.clone(),
        references: refs.clone(),
    });
    let command = fixtures::request(&configuration, 76);
    let commit = commit_inputs(&configuration, &mut engines[..3], &command, &inputs);
    for engine in &mut engines[..3] {
        engine.decide(&commit.bytes).unwrap();
        apply_inputs(engine, app.as_ref());
    }
    let mut driver = repair_driver(
        engines.remove(0),
        &directories[0].0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    driver.application = app;
    let digest = wire::digest(&command);
    let pending = wire::decode(&driver.result(digest).unwrap()).unwrap();
    let pending = pending.array(10).unwrap();
    assert_eq!(pending[3].uint().unwrap(), 0);
    assert!(pending[9].array(0).is_ok());
    for engine in &engines[..2] {
        let node = engine.applied().unwrap();
        let result = engine.execution(node.digest().unwrap()).unwrap().unwrap();
        driver
            .collect_share(node.encode().unwrap(), result.attestation, result.result)
            .unwrap();
    }
    let complete = wire::decode(&driver.result(digest).unwrap()).unwrap();
    let complete = complete.array(10).unwrap();
    assert_eq!(complete[3].uint().unwrap(), 1);
    let output = Resolved::parse(&refs, &complete[9]).unwrap();
    for reference in &refs {
        assert_eq!(
            output.get(reference).unwrap(),
            inputs.get(reference).unwrap()
        );
    }
    let generation = driver.engine.generation();
    let retained = driver.engine.snapshot.inputs.clone();
    // A local availability failure must not turn a completed permit into an ordered refusal.
    driver.engine.snapshot.inputs = Default::default();
    let unavailable = wire::decode(&driver.result(digest).unwrap()).unwrap();
    let unavailable = unavailable.array(10).unwrap();
    assert_eq!(unavailable[3].uint().unwrap(), 2);
    assert_eq!(unavailable[4].uint().unwrap(), 1);
    assert!(unavailable[8].null().is_ok());
    assert!(unavailable[9].array(0).is_ok());
    assert_eq!(driver.engine.generation(), generation);
    driver.engine.snapshot.inputs = retained;
    let resumed = wire::decode(&driver.result(digest).unwrap()).unwrap();
    assert_eq!(resumed.array(10).unwrap(), complete);
}
#[test]
fn certified_input_repair_blocks_execution_and_survives_reopen() {
    let (configuration, keys) = fixture();
    let (directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let inputs = objects();
    let refs = inputs.references();
    let app = Arc::new(InputApplication {
        config: configuration.clone(),
        references: refs.clone(),
    });
    let command = fixtures::request(&configuration, 75);
    let commit = commit_inputs(&configuration, &mut engines[..3], &command, &inputs);
    let generation = engines[0].generation();
    drop(engines.remove(0));
    let source = Engine::open(
        &directories[0].0,
        configuration.clone(),
        keys[0].clone(),
        generation,
    )
    .unwrap();
    source.input_reader().unwrap().verify(&refs).unwrap();
    assert_eq!(
        source
            .retained_command_inputs(wire::digest(&command))
            .unwrap(),
        refs
    );
    let mut target = engines.pop().unwrap();
    let required: Vec<_> = source
        .snapshot
        .certificates
        .values()
        .map(|o| repair::Reference {
            kind: 12,
            digest: o.identity,
            signer: None,
        })
        .chain(source.snapshot.nodes.values().map(|o| repair::Reference {
            kind: 14,
            digest: o.identity,
            signer: None,
        }))
        .chain(
            source
                .snapshot
                .commands
                .values()
                .map(|o| repair::Reference {
                    kind: 22,
                    digest: o.identity,
                    signer: None,
                }),
        )
        .collect();
    let items = source.repair_export(&required).unwrap();
    target
        .repair_import_with_inputs(&required, &items, |_| Ok(refs.clone()))
        .unwrap();
    assert!(
        target
            .advance_phase(
                &source
                    .known_certificate(&target.snapshot.highest_prepare)
                    .unwrap()
                    .bytes
            )
            .is_err()
    );
    target.decide(&commit.bytes).unwrap();
    let requests = ingress::Mailbox::new();
    let responses = ingress::Mailbox::new();
    let mut target = repair_driver(
        target,
        &directories[3].0,
        &keys,
        configuration.voters[0],
        requests.clone(),
    );
    let mut source = repair_driver(
        source,
        &directories[0].0,
        &keys,
        configuration.voters[3],
        responses.clone(),
    );
    target.application = app.clone();
    source.application = app.clone();
    source.engine.decide(&commit.bytes).unwrap();
    apply_inputs(&mut source.engine, app.as_ref());
    assert_eq!(source.engine.applied().unwrap().height, 1);
    for _ in 0..8 {
        target.apply().unwrap();
        if target.input_flight.is_some() {
            break;
        }
    }
    assert_eq!(target.engine.applied().unwrap().height, 0);
    assert!(target.engine.snapshot.executed.is_empty());
    assert!(target.engine.snapshot.own_votes.is_empty());
    for _ in 0..2 {
        let request = loop {
            let bytes = requests.try_pop().unwrap().unwrap();
            let message = peer::decode(&configuration, configuration.voters[3], &bytes).unwrap();
            if matches!(message, Message::InputRequest(..)) {
                break message;
            }
        };
        let Message::InputRequest(id, anchor, reference) = request.clone() else {
            unreachable!()
        };
        let before = target.engine.generation();
        assert!(
            target
                .input_response(
                    configuration.voters[0],
                    [99; 32],
                    anchor.clone(),
                    reference.clone(),
                    Some(inputs.get(&reference).unwrap().to_vec())
                )
                .is_err()
        );
        assert!(
            target
                .input_response(
                    configuration.voters[0],
                    id,
                    anchor.clone(),
                    reference.clone(),
                    Some(b"changed".to_vec())
                )
                .is_err()
        );
        assert_eq!(target.engine.generation(), before);
        source.receive(configuration.voters[3], request).unwrap();
        let response = loop {
            let bytes = responses.try_pop().unwrap().unwrap();
            let message = peer::decode(&configuration, configuration.voters[0], &bytes).unwrap();
            if matches!(message, Message::InputResponse(..)) {
                break message;
            }
        };
        target.receive(configuration.voters[0], response).unwrap();
    }
    for _ in 0..4 {
        target.apply().unwrap();
    }
    assert_eq!(target.engine.applied().unwrap().height, 1);
    assert_eq!(target.engine.application(), source.engine.application());
    target.engine.validate_input_bindings(app.as_ref()).unwrap();
    let generation = target.engine.generation();
    drop(target);
    let reopened = Engine::open(
        &directories[3].0,
        configuration,
        keys[3].clone(),
        generation,
    )
    .unwrap();
    reopened.input_reader().unwrap().verify(&refs).unwrap();
    assert_eq!(reopened.applied().unwrap().height, 1);
}

#[test]
fn checkpoint_and_initial_journal_require_the_complete_nonempty_object_closure() {
    let (configuration, keys) = fixture();
    let inputs = objects();
    let refs = inputs.references();
    let missing = Directory::new();
    assert!(
        Engine::create_prepared_inputs(
            &missing.0,
            configuration.clone(),
            keys[0].clone(),
            initial(),
            None,
            &refs,
            |reference| {
                if reference == &refs[1] {
                    anyhow::bail!("withheld")
                }
                Ok(inputs.get(reference)?.to_vec())
            }
        )
        .is_err()
    );
    assert!(Engine::open(&missing.0, configuration.clone(), keys[0].clone(), 1).is_err());
    let initial_directory = Directory::new();
    let engine = Engine::create_prepared_inputs(
        &initial_directory.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
        None,
        &refs,
        |reference| Ok(inputs.get(reference)?.to_vec()),
    )
    .unwrap();
    let generation = engine.generation();
    drop(engine);
    let engine = Engine::open(
        &initial_directory.0,
        configuration.clone(),
        keys[0].clone(),
        generation,
    )
    .unwrap();
    engine.input_reader().unwrap().verify(&refs).unwrap();
    drop(engine);

    let source_directory = Directory::new();
    let mut source = Engine::create(
        &source_directory.0,
        configuration.clone(),
        keys[0].clone(),
        initial(),
    )
    .unwrap();
    let app = InputApplication {
        config: configuration.clone(),
        references: refs.clone(),
    };
    for serial in 1..=32 {
        for key in &keys[..3] {
            source
                .receive_wish(
                    &super::super::super::synchronizer::sign(&configuration, serial, key).unwrap(),
                )
                .unwrap();
        }
        let qc = source
            .known_certificate(&source.snapshot.highest_prepare)
            .unwrap();
        let parent = source.known_node(&qc.node).unwrap();
        let command = fixtures::request(&configuration, serial as u8);
        let node = Node {
            scope: configuration.scope.clone(),
            view: serial,
            height: parent.height + 1,
            parent: Some(qc.node),
            command: Some(wire::digest(&command)),
            evaluated_at: 10000,
            justify: Some(qc.digest()),
        };
        let leader = &keys[configuration
            .member(&configuration.leader(serial).unwrap())
            .unwrap()];
        let proposal = wire::sign_envelope(&node.encode().unwrap(), leader).unwrap();
        source
            .prepare_with_inputs(&proposal, &command, &inputs, |_| Ok(()), |_, _| Ok(()))
            .unwrap();
        for phase in [Phase::Prepare, Phase::PreCommit, Phase::Commit] {
            let votes = keys[..3]
                .iter()
                .map(|key| {
                    SignedVote::sign(
                        &configuration,
                        super::super::super::Vote {
                            scope: configuration.scope.clone(),
                            view: serial,
                            phase,
                            node: node.digest().unwrap(),
                        },
                        key,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let qc = Certificate::collect(&configuration, &votes).unwrap();
            if phase == Phase::Commit {
                source.decide(&qc.bytes).unwrap();
            } else {
                source.advance_phase(&qc.bytes).unwrap();
            }
        }
        apply_inputs(&mut source, &app);
    }
    let state = source.application().to_vec();
    let proof = super::super::super::checkpoint::tests::certify(&mut source, &keys);
    let target_directory = Directory::new();
    let mut target = Engine::create(
        &target_directory.0,
        configuration.clone(),
        keys[3].clone(),
        initial(),
    )
    .unwrap();
    let generation = target.generation();
    assert!(
        target
            .install_checkpoint_with_inputs(
                &proof,
                &state,
                &source.archive,
                &refs,
                |_, _| Ok(()),
                None
            )
            .unwrap_err()
            .downcast_ref::<Unavailable>()
            .is_some()
    );
    assert_eq!(target.generation(), generation);
    let transfer = [11; 32];
    target.reserve_checkpoint_inputs(transfer, &refs).unwrap();
    for object in inputs.objects() {
        target
            .import_checkpoint_input(transfer, &proof, &state, &refs, object)
            .unwrap();
    }
    target
        .install_checkpoint_with_inputs(&proof, &state, &source.archive, &refs, |_, _| Ok(()), None)
        .unwrap();
    target.unpin_checkpoint_inputs(&transfer);
    let generation = target.generation();
    drop(target);
    let target = Engine::open(
        &target_directory.0,
        configuration,
        keys[3].clone(),
        generation,
    )
    .unwrap();
    target.input_reader().unwrap().verify(&refs).unwrap();
    assert_eq!(target.applied().unwrap().height, 32);
    assert!(target.snapshot.inputs.objects().all(|o| o.kind == 4097));
}
