// SPDX-License-Identifier: MIT
//! Current administration and four independently consented deployments define one committee.
use super::{State, array, b, reference, transactions::Decision};
use crate::{
    authority_epoch::{Declaration, Terminal},
    authority_governance::{Governance, Requirement},
    authority_membership::current,
    authority_proof::{Intent, VersionRef},
    consensus::records::Configuration,
    runtime_manifest::Manifest,
    trust_wire,
};
use anyhow::{Context, Result, ensure};
#[allow(
    clippy::too_many_arguments,
    reason = "Keep protocol inputs, state and validation callbacks explicit."
)]
pub(super) fn evaluate(
    declaration: &Declaration,
    state: &State,
    config: &Configuration,
    prior: &[u8],
    intent: &Intent,
    at: u64,
    expires: u64,
    replay: bool,
) -> Result<Decision> {
    let mut out = Decision {
        code: 0,
        value: array(vec![
            crate::trust_wire::Value::Uint(201),
            crate::trust_wire::Value::Uint(1),
            crate::trust_wire::Value::Text("Reconfigure".into()),
            array(vec![]),
        ]),
        expires,
        records: None,
        domains: None,
        restrictions: Default::default(),
        admissions: vec![],
        created: None,
        terminal: None,
    };
    if declaration.old_scope.network != config.scope.network
        || declaration.old_scope.incarnation != config.scope.incarnation
        || declaration.old_scope.configuration != config.scope.configuration
        || declaration.old_scope.epoch != config.scope.epoch
        || declaration.snapshot.height != state.height
        || declaration.snapshot.state != trust_wire::digest(prior)
        || replay
    {
        out.code = 12;
        return Ok(out);
    }
    let governance = Governance::parse(
        config.scope.network,
        config.scope.incarnation,
        &state.records,
    )?;
    let requirement = Requirement {
        subject: intent.requester,
        actions: &[9],
        scope: (0, intent.network),
        namespace: None,
        usage: [0, 1, 0, 1],
        evaluated_at_ms: at,
        expected: &intent.expected,
    };
    let capability = match governance.capability(declaration.grant, &requirement) {
        Ok(v) => v,
        Err(_) => {
            out.code = 3;
            return Ok(out);
        }
    };
    let mut dependencies = capability.dependencies;
    out.expires = out.expires.min(capability.expires_ms);
    let index = state.deployments()?;
    let valid = (|| -> Result<()> {
        for kind in [100, 114] {
            dependencies.push(
                governance
                    .versions()
                    .into_iter()
                    .find(|v| v.kind == kind && v.id == intent.network)
                    .context("current network policy is missing")?,
            );
        }
        let selected: Vec<_> = declaration.nominations.iter().map(|n| n.voter).collect();
        ensure!(
            selected.iter().all(|key| !config.historical_voter(key)),
            "Committee replacement currently requires four fresh authority identities"
        );
        let mut peer_contract = None;
        for nomination in &declaration.nominations {
            let registration = index
                .deployments
                .get(&nomination.profile.id)
                .context("nominated deployment is not registered")?;
            ensure!(
                registration.profile == nomination.profile
                    && registration.consent == nomination.consent
                    && registration.services.get(&0) == Some(&nomination.voter)
                    && !index.withdrawals.contains_key(&registration.deployment),
                "nomination lacks exact unwithdrawn authority deployment"
            );
            let (manifest_bytes, consent) = state
                .evidence
                .deployment_offer(registration.deployment)?
                .context("nomination lacks admitted operator provenance")?;
            let manifest = Manifest::parse(&manifest_bytes)?;
            let authority = manifest
                .authority_config
                .as_ref()
                .context("Nominated deployment lacks authority transport consent")?;
            let peers: Vec<_> = authority
                .ordered_peer_endpoint_ids
                .iter()
                .map(|id| {
                    manifest
                        .endpoints
                        .iter()
                        .find(|e| e.endpoint_id == *id)
                        .map(|e| e.service_key)
                        .context("Nominated peer endpoint missing")
                })
                .collect::<Result<_>>()?;
            ensure!(
                peers == selected,
                "Nominated consent does not name the exact successor committee"
            );
            let endpoints: Vec<_> = selected
                .iter()
                .map(|key| {
                    let endpoint = manifest
                        .endpoints
                        .iter()
                        .find(|e| e.service_key == *key)
                        .context("Nominated peer endpoint missing")?;
                    Ok((
                        endpoint.service_key,
                        endpoint.address,
                        endpoint.port,
                        endpoint.transport_key,
                        endpoint.leaf_der.clone(),
                    ))
                })
                .collect::<Result<_>>()?;
            if let Some(previous) = &peer_contract {
                ensure!(
                    *previous == endpoints,
                    "Nominated operators approved different peer transport contracts"
                );
            } else {
                peer_contract = Some(endpoints);
            }
            let (payload, signatures) = trust_wire::envelope(&consent, 1)?;
            ensure!(
                current(at, manifest.validity)
                    && manifest.deployment == registration.deployment
                    && manifest.operator == registration.operator
                    && signatures[0].0 == registration.operator
                    && payload == manifest.unsigned_consent(0)?
                    && trust_wire::digest(&manifest.desired()?) == registration.profile.digest
                    && trust_wire::digest(&payload) == registration.consent.digest,
                "nominated local consent is absent, stale or changed"
            );
            let registrar = governance.current_capability(
                registration.grant.id,
                &Requirement {
                    subject: registration.registrar,
                    actions: &[13],
                    scope: (5, registration.deployment),
                    namespace: None,
                    usage: [0, 1, 0, 1],
                    evaluated_at_ms: at,
                    expected: &[],
                },
            )?;
            out.expires = out
                .expires
                .min(manifest.validity.1)
                .min(registrar.expires_ms);
            dependencies.extend(registrar.dependencies);
            dependencies.extend([
                registration.reference.clone(),
                registration.profile.clone(),
                registration.consent.clone(),
            ]);
        }
        dependencies.sort_by_key(VersionRef::index);
        dependencies.dedup();
        crate::authority_proof::validate_versions(&dependencies, 64)?;
        ensure!(
            dependencies == declaration.snapshot.references,
            "committee snapshot omits or substitutes a dependency"
        );
        Ok(())
    })();
    if valid.is_err() {
        out.code = 3;
        return Ok(out);
    }
    out.value = array(vec![
        crate::trust_wire::Value::Uint(201),
        crate::trust_wire::Value::Uint(1),
        crate::trust_wire::Value::Text("Reconfigure".into()),
        array(dependencies.iter().map(reference).collect()),
        b(&declaration.digest()),
        crate::trust_wire::Value::Uint(declaration.next_epoch),
    ]);
    out.terminal = Some(Terminal {
        declaration: declaration.clone(),
        intent: intent.digest,
    });
    Ok(out)
}
