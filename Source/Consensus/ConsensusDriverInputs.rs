// SPDX-License-Identifier: MIT
//! Only declared immutable dependencies reach application evaluation.
use super::super::inputs::Reader;
use super::peer::InputAnchor;
use super::*;
use crate::authority_objects::{self as inputs, Reference as InputReference, Resolved};

#[derive(Clone)]
pub(super) struct Submission {
    pub command: Vec<u8>,
    pub inputs: Resolved,
}
impl Submission {
    pub fn parse(
        config: &Configuration,
        application: &dyn Application,
        encoded: &[u8],
    ) -> Result<Self> {
        let value = wire::decode(encoded)?;
        let fields = value.array(2)?;
        let command = fields[0].bytes()?;
        ensure!(
            command.len() < peer::MAX_PAYLOAD / 2,
            "request exceeds transport bound"
        );
        OrderedRequest::parse(config, command)?;
        let references = application.command_inputs(command)?;
        let inputs = Resolved::parse(&references, &fields[1])?;
        Ok(Self {
            command: command.to_vec(),
            inputs,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = wire::encode(&V::Array(vec![
            V::Bytes(self.command.clone()),
            self.inputs.value(),
        ]))?;
        ensure!(
            bytes.len() <= peer::MAX_PAYLOAD,
            "input submission exceeds transport bound"
        );
        Ok(bytes)
    }
}

pub(super) fn evaluation_inputs(
    application: &dyn Application,
    reader: &Reader,
    prior: &[u8],
    command: &[u8],
    staged: Option<&Resolved>,
) -> Result<Resolved> {
    let command_refs = application.command_inputs(command)?;
    let state_refs = application.retained_inputs(prior)?;
    let required = application.required_inputs(prior, command)?;
    inputs::validate_required(&required, &command_refs, &state_refs)?;
    if let Some(staged) = staged {
        ensure!(
            staged.references() == command_refs,
            "staged operation input closure differs"
        );
    }
    let mut resolved = Vec::with_capacity(required.len());
    for reference in &required {
        if let Some(staged) = staged
            && let Some(object) = staged
                .objects()
                .find(|object| object.reference() == reference)
        {
            resolved.push(object.clone());
        } else {
            resolved.extend(
                reader
                    .resolve(std::slice::from_ref(reference))?
                    .objects()
                    .cloned(),
            );
        }
    }
    Resolved::exact(&required, resolved)
}

pub(super) fn executed_inputs(
    application: &dyn Application,
    prior: &[u8],
    command: &[u8],
    next: &[u8],
) -> Result<Vec<InputReference>> {
    let command_refs = application.command_inputs(command)?;
    let prior_refs = application.retained_inputs(prior)?;
    let retained = application.retained_inputs(next)?;
    // Evaluation cannot create an object by naming bytes which were never admitted.
    inputs::validate_required(&retained, &command_refs, &prior_refs)?;
    Ok(retained)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Consensus/ConsensusDriverInputTests.rs"]
mod tests;

pub(super) struct Flight {
    id: Digest,
    certificate: Digest,
    reference: InputReference,
    deadline: Instant,
}
impl Driver {
    pub(super) fn wait_input(
        &mut self,
        sender: Key,
        message: Message,
        certificate: Digest,
        reference: InputReference,
    ) -> Result<()> {
        let identity = wire::digest(&message.payload()?);
        ensure!(
            self.input_waiting.contains_key(&identity) || self.input_waiting.len() < MAX_PENDING,
            "input dependency wait capacity exhausted"
        );
        self.input_waiting
            .entry(identity)
            .or_insert((sender, message));
        self.request_input(certificate, reference)
    }
    pub(super) fn request_input(
        &mut self,
        certificate: Digest,
        reference: InputReference,
    ) -> Result<()> {
        ensure!(
            self.engine
                .certificate_input_references(certificate)?
                .binary_search(&reference)
                .is_ok(),
            "missing input has no verified certificate root"
        );
        if self.input_flight.is_none() {
            self.input_flight = Some(Flight {
                id: rand::random(),
                certificate,
                reference,
                deadline: Instant::now() + peer::HTTP_TIMEOUT,
            });
        }
        self.input_tick()
    }
    pub(super) fn input_request_token(&self) -> Result<Option<Digest>> {
        self.input_flight
            .as_ref()
            .map(|flight| {
                Message::InputRequest(
                    flight.id,
                    InputAnchor::Certificate(flight.certificate),
                    flight.reference.clone(),
                )
                .payload()
                .map(|bytes| wire::digest(&bytes))
            })
            .transpose()
    }
    pub(super) fn input_tick(&mut self) -> Result<()> {
        let Some(flight) = &mut self.input_flight else {
            return Ok(());
        };
        match self
            .engine
            .input_reader()?
            .resolve(std::slice::from_ref(&flight.reference))
        {
            Ok(_) => {
                self.input_flight = None;
                return self.resume_inputs();
            }
            Err(error) if error.downcast_ref::<inputs::Unavailable>().is_some() => {}
            Err(error) => return Err(error),
        }
        if flight.deadline <= Instant::now() {
            flight.id = rand::random();
            flight.deadline = Instant::now() + peer::HTTP_TIMEOUT;
        }
        let request = Message::InputRequest(
            flight.id,
            InputAnchor::Certificate(flight.certificate),
            flight.reference.clone(),
        );
        for peer in self.senders.keys() {
            self.send(*peer, &request)?;
        }
        Ok(())
    }
    fn resume_inputs(&mut self) -> Result<()> {
        let waiting = std::mem::take(&mut self.input_waiting);
        for (_, (sender, message)) in waiting {
            // A new view may supersede the pending proposal while its bytes arrive.
            if let Err(error) = self.receive(sender, message) {
                diagnostic("input-resume", self.engine.view(), 18, &error);
            }
        }
        Ok(())
    }
    pub(super) fn input_request(
        &mut self,
        sender: Key,
        id: Digest,
        anchor: InputAnchor,
        reference: InputReference,
    ) -> Result<()> {
        let allowed = match anchor {
            InputAnchor::Certificate(certificate) => self
                .engine
                .certificate_input_references(certificate)?
                .binary_search(&reference)
                .is_ok(),
            InputAnchor::Checkpoint(checkpoint) => {
                self.checkpoint_input_allowed(sender, id, checkpoint, &reference)?
            }
        };
        ensure!(allowed, "requested input is outside its certified closure");
        let bytes = match self
            .engine
            .input_reader()?
            .resolve(std::slice::from_ref(&reference))
        {
            Ok(resolved) => Some(resolved.get(&reference)?.to_vec()),
            Err(error) if error.downcast_ref::<inputs::Unavailable>().is_some() => None,
            Err(error) => return Err(error),
        };
        self.send(
            sender,
            &Message::InputResponse(id, anchor, reference, bytes),
        )
    }
    pub(super) fn input_response(
        &mut self,
        sender: Key,
        id: Digest,
        anchor: InputAnchor,
        reference: InputReference,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        if let InputAnchor::Checkpoint(checkpoint) = anchor {
            return self.checkpoint_input_response(sender, id, checkpoint, reference, body);
        }
        let flight = self
            .input_flight
            .as_ref()
            .context("unsolicited immutable input response")?;
        ensure!(
            id == flight.id
                && anchor == InputAnchor::Certificate(flight.certificate)
                && reference == flight.reference
                && Instant::now() < flight.deadline,
            "immutable input response differs from active flight"
        );
        let Some(body) = body else {
            return Ok(());
        };
        let object = inputs::Object::verify(reference, body)?;
        self.engine
            .import_certificate_input(flight.certificate, &object)?;
        self.input_flight = None;
        self.resume_inputs()?;
        self.apply()
    }
}
