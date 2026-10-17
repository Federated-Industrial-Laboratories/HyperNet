// SPDX-License-Identifier: MIT
// Fresh route contexts renew permission without consuming an ordinary request sequence.
use super::*;
use crate::authority_read::{self as fresh, Query};

impl Client<'_> {
    pub(super) fn read_action(&mut self, command: routes::Command) -> Result<V> {
        let started = authority_challenge::boot_time_ms()?;
        let command = DomainCommand::Route(command);
        self.permitted(&command)?;
        let descriptor = self.store.descriptor().clone();
        let operation = Operation {
            grant: None,
            command: command.clone(),
            snapshot: domains::snapshot(&a(vec![
                a(vec![
                    V::Uint(self.store.prefix().scope().epoch),
                    V::Uint(self.store.prefix().height()),
                    b(self.store.prefix().policy_state()),
                ]),
                a(vec![]),
            ]))?,
        };
        let nonce = random()?;
        let signed = fresh::Request::sign(
            descriptor.scope(),
            &self.config.key,
            self.store.requester(),
            nonce,
            self.store.prefix().height(),
            Query::Domain(operation),
        )?;
        let health = self.guard.health()?;
        let now = health.observe()?;
        let duration =
            self.deadline
                .map_or(Ok(authority_challenge::MAXIMUM_DURATION_MS), |deadline| {
                    Ok::<_, anyhow::Error>(
                        transport::remaining(deadline)?
                            .min(authority_challenge::MAXIMUM_DURATION_MS),
                    )
                })?;
        let deadline = now
            .boot_ms
            .checked_add(duration)
            .context("Route read deadline overflow")?;
        let challenge =
            self.session
                .issue_read(&signed, &self.config.key, nonce, duration, health)?;
        let outcome = (|| {
            let (reply, history) = transport::exchange_read(
                &descriptor,
                &signed,
                &challenge,
                deadline,
                Path::new("/Authority/Control.sock"),
                self.store.prefix(),
                self.store.tree_head(),
                &mut || self.guard.health(),
            )
            .context("obtain fresh Route context and history")?;
            let mut candidate = None;
            let verified = fresh::verify_response(
                &descriptor,
                &signed,
                &challenge,
                fresh::Response {
                    node: &reply.node,
                    certificate: &reply.certificate,
                    result: &reply.result,
                    ancestry: &history.nodes,
                },
                |request, result, statement| {
                    let (state, records) = self.disk.context();
                    let selected = fresh::verify_domain(
                        &self.guard.bootstrap,
                        state,
                        records,
                        request,
                        result,
                        statement,
                        &[],
                    )?;
                    ensure!(
                        selected.updates.is_empty(),
                        "fresh Route context changes domain state"
                    );
                    result::minimum(&selected.versions, self.store.generations())?;
                    let versions = selected.versions.clone();
                    candidate = Some(selected);
                    Ok(versions)
                },
            )
            .context("verify fresh Route authority context")?;
            let verified = history.attach_read(&self.store, verified)?;
            if verified.result.disposition != Disposition::Permit {
                let code = verified.result.code;
                self.store
                    .observe_read(verified, &mut self.session, self.guard.health()?, 0)?;
                anyhow::bail!("Route maintenance refused with code {code}");
            }
            let expiry = verified
                .statement
                .expires_at_ms
                .saturating_sub(authority_challenge::DELTA_MS);
            let candidate = candidate.context("fresh Route permit omitted verified context")?;
            transport::remaining(deadline)?;
            let value = self.store.accept_read(
                verified,
                &mut self.session,
                self.guard.health()?,
                0,
                |_, _| {
                    self.active.check(self.guard)?;
                    self.disk.publish(candidate.state, candidate.records)?;
                    self.active.check(self.guard)?;
                    transport::remaining(deadline)?;
                    Ok(candidate.value)
                },
            )?;
            self.last_expiry = expiry;
            Ok(value)
        })();
        if outcome.is_err() {
            self.session.discard(&challenge)?;
        } else {
            self.costs.observe(
                &command,
                self.config.profile.identity.service,
                authority_challenge::boot_time_ms()?.saturating_sub(started),
            );
        }
        outcome
    }
}
