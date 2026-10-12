// SPDX-License-Identifier: MIT
// Local recipient challenges expire on a suspend-aware clock and require clock-health evidence.
use crate::{
    authority_proof::{Challenge, Digest, SignedRequest, VerifiedResult},
    trust_wire::{self as wire, Value as V},
};
use anyhow::{Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAXIMUM_DURATION_MS: u64 = 5000;
pub const FEDERATION_DURATION_MS: u64 = 15_000;
pub const DELTA_MS: u64 = 250;

/// Only finite, grant-free federation maintenance can use the longer profile.
/// This selects a freshness ceiling; the domain still verifies the exact service authority.
pub fn maximum_duration_ms(request: &SignedRequest) -> u64 {
    use crate::authority_domains::{Command, Operation, federation};
    let SignedRequest::Intent(intent) = request else {
        return MAXIMUM_DURATION_MS;
    };
    if !Operation::handles(&intent.action) {
        return MAXIMUM_DURATION_MS;
    }
    // Unsupported commands retain the ordinary finite refusal path, never the longer ceiling.
    let Ok(operation) = Operation::parse(intent) else {
        return MAXIMUM_DURATION_MS;
    };
    if operation.grant.is_none()
        && matches!(
            operation.command,
            Command::Federation(
                federation::Command::Admission { .. }
                    | federation::Command::Export { .. }
                    | federation::Command::Import { .. }
                    | federation::Command::MediaAuthorise { .. }
                    | federation::Command::MediaReceipt { .. }
            )
        )
    {
        FEDERATION_DURATION_MS
    } else {
        MAXIMUM_DURATION_MS
    }
}

pub fn boot_time_ms() -> Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } == 0,
        "suspend-aware clock unavailable"
    );
    let value = unsafe { value.assume_init() };
    ensure!(
        value.tv_nsec >= 0 && value.tv_nsec < 1_000_000_000,
        "invalid boot clock precision"
    );
    let seconds = u64::try_from(value.tv_sec)?;
    seconds
        .checked_mul(1000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| anyhow::anyhow!("boot clock overflow"))
}
fn wall_time_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

#[derive(Clone, Copy, Debug)]
pub struct ClockHealth {
    sample_wall_ms: u64,
    sample_boot_ms: u64,
    valid_until_boot_ms: u64,
    maximum_error_ms: u64,
    #[cfg(test)]
    test_observation: Option<Observation>,
}
impl ClockHealth {
    /// The provider must establish the stated error bound; construction is not a clock-health measurement.
    pub fn new(
        sample_wall_ms: u64,
        sample_boot_ms: u64,
        valid_until_boot_ms: u64,
        maximum_error_ms: u64,
    ) -> Result<Self> {
        ensure!(
            maximum_error_ms <= DELTA_MS && valid_until_boot_ms >= sample_boot_ms,
            "clock error bound or validity is unsupported"
        );
        Ok(Self {
            sample_wall_ms,
            sample_boot_ms,
            valid_until_boot_ms,
            maximum_error_ms,
            #[cfg(test)]
            test_observation: None,
        })
    }
    fn observe_at(&self, wall: u64, boot: u64) -> Result<Observation> {
        ensure!(
            boot >= self.sample_boot_ms && boot < self.valid_until_boot_ms,
            "clock health is stale or invalid"
        );
        let predicted = self
            .sample_wall_ms
            .checked_add(boot - self.sample_boot_ms)
            .ok_or_else(|| anyhow::anyhow!("clock progression overflow"))?;
        ensure!(
            self.maximum_error_ms
                .checked_add(wall.abs_diff(predicted))
                .is_some_and(|e| e <= DELTA_MS),
            "clock progression exceeds the established error bound"
        );
        Ok(Observation {
            wall_ms: wall,
            boot_ms: boot,
        })
    }
    #[cfg(test)]
    pub(crate) fn frozen(mut self) -> Self {
        self.test_observation = Some(Observation {
            wall_ms: self.sample_wall_ms,
            boot_ms: self.sample_boot_ms,
        });
        self
    }
    pub fn observe(&self) -> Result<Observation> {
        #[cfg(test)]
        if let Some(now) = self.test_observation {
            return self.observe_at(now.wall_ms, now.boot_ms);
        }
        self.observe_at(wall_time_ms()?, boot_time_ms()?)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub wall_ms: u64,
    pub boot_ms: u64,
}
fn random_id() -> Result<Digest> {
    let mut value = [0; 32];
    OsRng.try_fill_bytes(&mut value)?;
    ensure!(value != [0; 32], "random identifier generation failed");
    Ok(value)
}
struct Live {
    digest: Digest,
    intent: Digest,
    issue_boot_ms: u64,
    deadline_boot_ms: u64,
}
/// A removed challenge can validate one final return, but cannot authorise another handler.
pub(crate) struct Consumption {
    challenge: Challenge,
    live: Live,
    expires_at_ms: u64,
    not_before_ms: u64,
}
pub struct Session {
    boot_id: Digest,
    process_id: libc::pid_t,
    challenges: BTreeMap<Digest, Live>,
    last_wall_ms: u64,
    last_boot_ms: u64,
}
impl Session {
    pub fn new() -> Result<Self> {
        Ok(Self {
            boot_id: random_id()?,
            process_id: unsafe { libc::getpid() },
            challenges: BTreeMap::new(),
            last_wall_ms: 0,
            last_boot_ms: 0,
        })
    }
    fn observation(&mut self, health: ClockHealth) -> Result<Observation> {
        ensure!(
            self.process_id == unsafe { libc::getpid() },
            "recipient session cannot be inherited by another process"
        );
        let now = health.observe()?;
        ensure!(
            now.wall_ms >= self.last_wall_ms && now.boot_ms >= self.last_boot_ms,
            "clock moved backwards during the recipient session"
        );
        self.last_wall_ms = now.wall_ms;
        self.last_boot_ms = now.boot_ms;
        Ok(now)
    }
    /// The private recipient key signs a fresh challenge for an already immutable signed intent.
    pub fn issue(
        &mut self,
        intent_envelope: &[u8],
        recipient: &SigningKey,
        client_nonce: Digest,
        duration_ms: u64,
        health: ClockHealth,
    ) -> Result<Vec<u8>> {
        let request = SignedRequest::from_signed(intent_envelope)?;
        ensure!(
            client_nonce != [0; 32] && (1..=maximum_duration_ms(&request)).contains(&duration_ms),
            "invalid client nonce or challenge duration"
        );
        let now = self.observation(health)?;
        self.challenges
            .retain(|_, c| now.boot_ms < c.deadline_boot_ms);
        ensure!(
            self.challenges.len() < 128,
            "recipient challenge capacity reached"
        );
        let nonce = random_id()?;
        ensure!(
            !self.challenges.contains_key(&nonce),
            "duplicate random challenge identifier"
        );
        let expires = now
            .wall_ms
            .checked_add(duration_ms)
            .ok_or_else(|| anyhow::anyhow!("challenge expiry overflow"))?;
        let deadline = now
            .boot_ms
            .checked_add(duration_ms)
            .ok_or_else(|| anyhow::anyhow!("challenge deadline overflow"))?;
        let payload = wire::encode(&V::Array(vec![
            V::Uint(21),
            V::Uint(1),
            V::Bytes(request.network().to_vec()),
            V::Bytes(request.incarnation().to_vec()),
            V::Bytes(recipient.verifying_key().to_bytes().to_vec()),
            V::Bytes(self.boot_id.to_vec()),
            V::Bytes(nonce.to_vec()),
            V::Bytes(request.digest().to_vec()),
            V::Bytes(client_nonce.to_vec()),
            V::Uint(now.wall_ms),
            V::Uint(expires),
            V::Uint(duration_ms),
        ]))?;
        let envelope = wire::sign_envelope(&payload, recipient)?;
        self.challenges.insert(
            nonce,
            Live {
                digest: wire::digest(&payload),
                intent: request.digest(),
                issue_boot_ms: now.boot_ms,
                deadline_boot_ms: deadline,
            },
        );
        Ok(envelope)
    }
    fn check_at(
        &self,
        challenge: &Challenge,
        expires_at_ms: u64,
        not_before_ms: u64,
        now: Observation,
    ) -> Result<()> {
        let live = self
            .challenges
            .get(&challenge.nonce)
            .ok_or_else(|| anyhow::anyhow!("challenge is absent or consumed"))?;
        self.check_live_at(challenge, live, expires_at_ms, not_before_ms, now)
    }
    fn check_live_at(
        &self,
        challenge: &Challenge,
        live: &Live,
        expires_at_ms: u64,
        not_before_ms: u64,
        now: Observation,
    ) -> Result<()> {
        ensure!(
            challenge.boot_id == self.boot_id,
            "challenge belongs to another recipient session"
        );
        ensure!(
            live.digest == challenge.digest
                && live.intent == challenge.intent
                && now.boot_ms >= live.issue_boot_ms
                && now.boot_ms < live.deadline_boot_ms
                && live.deadline_boot_ms
                    <= live
                        .issue_boot_ms
                        .checked_add(challenge.maximum_duration_ms)
                        .ok_or_else(|| anyhow::anyhow!("challenge deadline overflow"))?,
            "challenge context or deadline is invalid"
        );
        let lower = now
            .wall_ms
            .checked_sub(DELTA_MS)
            .ok_or_else(|| anyhow::anyhow!("wall clock below minimum bound"))?;
        let upper = now
            .wall_ms
            .checked_add(DELTA_MS)
            .ok_or_else(|| anyhow::anyhow!("wall clock overflow"))?;
        ensure!(
            lower >= not_before_ms && upper < expires_at_ms.min(challenge.expires_at_ms),
            "authority effect is outside its conservative absolute validity interval"
        );
        Ok(())
    }
    pub(crate) fn check(
        &mut self,
        result: &VerifiedResult,
        not_before_ms: u64,
        health: ClockHealth,
    ) -> Result<Observation> {
        let now = self.observation(health)?;
        self.check_at(
            &result.challenge,
            result.executed.expires_at_ms,
            not_before_ms,
            now,
        )?;
        Ok(now)
    }
    pub(crate) fn consume(
        &mut self,
        result: &VerifiedResult,
        not_before_ms: u64,
        health: ClockHealth,
    ) -> Result<Consumption> {
        self.check(result, not_before_ms, health)?;
        let live = self
            .challenges
            .remove(&result.challenge.nonce)
            .ok_or_else(|| anyhow::anyhow!("challenge was already consumed"))?;
        Ok(Consumption {
            challenge: result.challenge.clone(),
            live,
            expires_at_ms: result.executed.expires_at_ms,
            not_before_ms,
        })
    }
    /// Consumes the return check; it never restores the challenge or grants another effect.
    pub(crate) fn finish_consumption(
        &mut self,
        consumption: Consumption,
        health: ClockHealth,
    ) -> Result<Observation> {
        let now = self.observation(health)?;
        self.check_live_at(
            &consumption.challenge,
            &consumption.live,
            consumption.expires_at_ms,
            consumption.not_before_ms,
            now,
        )?;
        Ok(now)
    }
    pub fn discard(&mut self, challenge_envelope: &[u8]) -> Result<()> {
        let c = Challenge::from_signed(challenge_envelope)?;
        ensure!(
            c.boot_id == self.boot_id,
            "challenge belongs to another recipient session"
        );
        if let Some(live) = self.challenges.get(&c.nonce) {
            ensure!(live.digest == c.digest, "challenge identifier collision");
            self.challenges.remove(&c.nonce);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "AuthorityChallengeProfileTests.rs"]
pub(crate) mod profile_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_error_budget_does_not_add_another_uncertainty_allowance() {
        let health = ClockHealth::new(1000, 20, 100, 250).unwrap();
        assert!(health.observe_at(1001, 21).is_ok());
        assert!(health.observe_at(1002, 21).is_err());
        assert!(health.observe_at(1000, 21).is_err());
        assert!(health.observe_at(1080, 100).is_err());
        assert!(ClockHealth::new(1000, 20, 100, 251).is_err());
    }
    #[test]
    fn challenges_expire_at_original_boot_deadline_and_strict_absolute_boundary() {
        let mut session = Session::new().unwrap();
        let challenge = Challenge {
            network: [1; 32],
            incarnation: [2; 32],
            recipient: [3; 32],
            boot_id: session.boot_id,
            nonce: [4; 32],
            intent: [5; 32],
            created_at_ms: 10000,
            expires_at_ms: 15000,
            maximum_duration_ms: 5000,
            digest: [7; 32],
        };
        session.challenges.insert(
            challenge.nonce,
            Live {
                digest: challenge.digest,
                intent: challenge.intent,
                issue_boot_ms: 100,
                deadline_boot_ms: 5100,
            },
        );
        assert!(
            session
                .check_at(
                    &challenge,
                    15000,
                    10000,
                    Observation {
                        wall_ms: 10250,
                        boot_ms: 350
                    }
                )
                .is_ok()
        );
        assert!(
            session
                .check_at(
                    &challenge,
                    15000,
                    10000,
                    Observation {
                        wall_ms: 14750,
                        boot_ms: 4850
                    }
                )
                .is_err()
        );
        assert!(
            session
                .check_at(
                    &challenge,
                    15000,
                    10000,
                    Observation {
                        wall_ms: 10250,
                        boot_ms: 5100
                    }
                )
                .is_err()
        );
        assert!(
            Session::new()
                .unwrap()
                .check_at(
                    &challenge,
                    15000,
                    10000,
                    Observation {
                        wall_ms: 10250,
                        boot_ms: 350
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn immediate_results_preserve_independent_credential_start_and_original_deadline() {
        let mut session = Session::new().unwrap();
        let issued = ClockHealth::new(10000, 100, 6000, 0).unwrap().frozen();
        let mut fixture = crate::authority_proof::tests::Fixture::new(10000);
        fixture.challenge = session
            .issue(&fixture.intent, &fixture.recipient, [92; 32], 5000, issued)
            .unwrap();
        fixture.rebuild();
        let result = fixture.verify().unwrap();
        let current = ClockHealth::new(10100, 200, 6000, 0).unwrap().frozen();
        assert!(session.check(&result, 0, current).is_ok());
        assert!(session.check(&result, 9850, current).is_ok());
        assert!(session.check(&result, 9851, current).is_err());
        let expired = ClockHealth::new(10100, 5100, 7000, 0).unwrap().frozen();
        assert!(session.check(&result, 0, expired).is_err());
    }
    fn consumed() -> (Session, Consumption) {
        let mut session = Session::new().unwrap();
        let health = ClockHealth::new(10000, 100, 6000, 0).unwrap().frozen();
        let mut fixture = crate::authority_proof::tests::Fixture::new(10000);
        fixture.challenge = session
            .issue(&fixture.intent, &fixture.recipient, [91; 32], 5000, health)
            .unwrap();
        fixture.rebuild();
        let result = fixture.verify().unwrap();
        let consumed = session.consume(&result, 9750, health).unwrap();
        assert!(session.check(&result, 9750, health).is_err());
        (session, consumed)
    }
    #[test]
    fn consumed_return_keeps_original_deadlines_and_cannot_restore_the_challenge() {
        let (mut session, token) = consumed();
        let nonce = token.challenge.nonce;
        let now = ClockHealth::new(13499, 3599, 7000, 0).unwrap().frozen();
        session.finish_consumption(token, now).unwrap();
        assert!(!session.challenges.contains_key(&nonce));
        let (mut session, token) = consumed();
        let absolute_boundary = ClockHealth::new(13500, 3600, 7000, 0).unwrap().frozen();
        assert!(
            session
                .finish_consumption(token, absolute_boundary)
                .is_err()
        );
        let (mut session, token) = consumed();
        let boot_boundary = ClockHealth::new(13000, 5100, 7000, 0).unwrap().frozen();
        assert!(session.finish_consumption(token, boot_boundary).is_err());
        let (_session, token) = consumed();
        assert!(
            Session::new()
                .unwrap()
                .finish_consumption(token, now)
                .is_err()
        );
    }
}
