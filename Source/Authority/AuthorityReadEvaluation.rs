// SPDX-License-Identifier: MIT
// Pure evaluators and independent consumers share the same exact current authorization checks.
use super::*;
use crate::{
    authority_membership::{self as membership, Reservations},
    authority_objects::Object,
    trust_bootstrap::Verified,
};

pub(crate) fn evaluate_domain(
    operation: &Operation,
    state: &domains::State,
    records: &[Vec<u8>],
    reserved: &Reservations,
    requester: Key,
    at: u64,
) -> Result<domains::Decision> {
    match &operation.command {
        domains::Command::Stream(
            domains::streams::Command::Permit { .. }
            | domains::streams::Command::Lookup { .. }
            | domains::streams::Command::Inspect { .. },
        ) => domains::streams::evaluate_read(operation, state, records, reserved, requester, at),
        domains::Command::Page(domains::page::Command::View { .. }) => {
            domains::page::evaluate_read(operation, state, records, reserved, requester, at)
        }
        domains::Command::Route(
            domains::routes::Command::Lookup { .. }
            | domains::routes::Command::VoucherContext { .. },
        ) => domains::routes::evaluate_read(operation, state, records, reserved, requester, at),
        _ => anyhow::bail!("operation is not an independently evaluable fresh read"),
    }
}
#[allow(clippy::too_many_arguments)]
pub fn verify_domain(
    bootstrap: &Verified,
    prior_state: &domains::State,
    prior_records: &[Vec<u8>],
    request: &Request,
    result: &OperationResult,
    statement: &Statement,
    objects: &[Object],
) -> Result<domains::result::Candidate> {
    let Query::Domain(operation) = &request.query else {
        anyhow::bail!("domain fresh query required")
    };
    ensure!(
        result.disposition == proof::Disposition::Permit
            && result.action == "AuthorityDomain"
            && objects.is_empty(),
        "fresh domain result differs"
    );
    let scope = bootstrap.descriptor().scope();
    ensure!(
        request.scope.network == scope.network
            && request.scope.incarnation == scope.incarnation
            && statement.scope == request.scope,
        "fresh domain scope differs"
    );
    let value = wire::decode(&result.value)?;
    let f = record(&value, 201, 5)?;
    ensure!(f[2].text()? == result.action, "fresh domain action differs");
    let versions = f[3]
        .list(64)?
        .iter()
        .map(domains::version)
        .collect::<Result<Vec<_>>>()?;
    proof::validate_versions(&versions, 64)?;
    let body = f[4].array(4)?;
    ensure!(
        body[0].text()? == operation.command.name() && body[3] == V::Null,
        "fresh command result differs"
    );
    let returned = body[1]
        .list(domains::page::MAXIMUM_CONTEXT_RECORDS)?
        .iter()
        .map(|v| domains::Record::parse(v.bytes()?, scope.network, scope.incarnation))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        returned
            .windows(2)
            .all(|p| p[0].reference.index() < p[1].reference.index()),
        "fresh domain records are not sorted and distinct"
    );
    let governance = body[2]
        .list(64)?
        .iter()
        .map(|v| Ok(v.bytes()?.to_vec()))
        .collect::<Result<Vec<_>>>()?;
    let gov_refs = crate::authority_governance::Governance::record_versions(
        scope.network,
        scope.incarnation,
        &governance,
    )?;
    let mut exact = gov_refs.clone();
    exact.extend(returned.iter().map(|r| r.reference.clone()));
    exact.sort_by_key(VersionRef::index);
    ensure!(exact == versions, "fresh domain record closure differs");
    let mut selected = prior_records.to_vec();
    for (reference, bytes) in gov_refs.iter().zip(&governance) {
        selected.retain(|old| {
            !crate::authority_governance::Governance::record_versions(
                scope.network,
                scope.incarnation,
                std::slice::from_ref(old),
            )
            .is_ok_and(|v| v[0].index() == reference.index())
        });
        selected.push(bytes.clone());
    }
    membership::sort_records(&mut selected)?;
    let source = domains::result::merge(bootstrap, &selected)?;
    let mut state = prior_state.clone();
    for record in returned {
        state.records.insert(record.reference.index(), record);
    }
    domains::result::derive_keys(&mut state)?;
    ensure!(
        operation.command.required_inputs(&state)?.is_empty(),
        "fresh query unexpectedly requires immutable inputs"
    );
    let decision = evaluate_domain(
        operation,
        &state,
        &source,
        &Reservations(bootstrap.reservations().to_vec()),
        request.requester,
        statement.evaluated_at_ms,
    )?;
    ensure!(
        decision.code == 0
            && decision.state.is_none()
            && decision.value == value
            && decision.versions == versions
            && statement.expires_at_ms <= decision.expires_ms,
        "fresh domain result differs from independent current authorization"
    );
    state.charge()?;
    Ok(domains::result::Candidate {
        value,
        versions,
        updates: vec![],
        state,
        records: selected,
    })
}
