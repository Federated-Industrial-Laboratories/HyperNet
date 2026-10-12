// SPDX-License-Identifier: MIT
// Inventories admit complete entries against the actual certified-result encoding budget.
use super::*;

pub(super) fn result(
    c: &page::Evaluation<'_>,
    next: &State,
    changed: &BTreeSet<(u64, Digest)>,
    command: &Command,
    cursor: Option<Digest>,
) -> Result<(V, Vec<VersionRef>)> {
    let mut dependencies = c.dependencies.clone();
    sorted(&mut dependencies)?;
    let mut selected = c.selected.clone();
    for index in changed {
        selected.insert(*index, next.record(index.0, index.1)?.clone());
    }
    ensure!(
        selected.len() <= MAXIMUM_CONTEXT_RECORDS,
        "federation selected context exceeds result capacity"
    );
    let mut versions = dependencies
        .iter()
        .filter(|r| !selected.contains_key(&r.index()))
        .cloned()
        .collect::<Vec<_>>();
    versions.extend(selected.values().map(|r| r.reference.clone()));
    sorted(&mut versions)?;
    let governance = dependencies
        .iter()
        .filter(|r| r.kind < 132)
        .map(|r| Ok(b(c.governance.record_bytes(r.kind, r.id)?)))
        .collect::<Result<Vec<_>>>()?;
    let value = a(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("AuthorityDomain".into()),
        a(versions.iter().map(reference).collect()),
        a(vec![
            V::Text(command.name().into()),
            a(selected.values().map(|r| b(&r.bytes)).collect()),
            a(governance),
            cursor.map_or(V::Null, |id| b(&id)),
        ]),
    ]);
    wire::encode(&value)?;
    Ok((value, versions))
}
#[allow(clippy::too_many_arguments)]
pub(super) fn inventory(
    c: &mut page::Evaluation<'_>,
    next: &State,
    changed: &BTreeSet<(u64, Digest)>,
    command: &Command,
    ids: Vec<Digest>,
    cursor: &mut Option<Digest>,
    mut select: impl FnMut(&mut page::Evaluation<'_>, Digest) -> Result<()>,
) -> Result<()> {
    let mut last = None;
    let mut admitted = 0;
    for id in ids {
        let prior = (c.dependencies.clone(), c.selected.clone(), c.expires);
        if select(c, id).is_err() {
            c.dependencies = prior.0;
            c.selected = prior.1;
            c.expires = prior.2;
            continue;
        }
        if result(c, next, changed, command, Some(id)).is_err() {
            c.dependencies = prior.0;
            c.selected = prior.1;
            c.expires = prior.2;
            ensure!(
                admitted > 0,
                "one federation inventory entry exceeds certified result capacity"
            );
            *cursor = last;
            return Ok(());
        }
        admitted += 1;
        last = Some(id);
    }
    *cursor = None;
    Ok(())
}
#[allow(
    clippy::too_many_arguments,
    reason = "Inventory verification retains its exact foreign proof, local policy, resulting state and continuation."
)]
pub(super) fn list(
    c: &mut page::Evaluation<'_>,
    intent: &Intent,
    operation: &Operation,
    treaty: &Treaty,
    proof: &VerifiedForeign,
    next: &State,
    changed: &BTreeSet<(u64, Digest)>,
    cursor: &mut Option<Digest>,
) -> Result<()> {
    let Command::Export {
        admission,
        include_bundle: false,
        ..
    } = &proof.command
    else {
        anyhow::bail!("fresh foreign inventory Export required")
    };
    let Command::Admission {
        page: None,
        revision: None,
        ..
    } = admission.command()?
    else {
        anyhow::bail!("foreign inventory admission required")
    };
    ensure!(
        admission.intent()?.minimum_policy_epoch == intent.minimum_policy_epoch,
        "inventory lease names another local authority epoch"
    );
    c.capability(
        grant(operation)?,
        intent.requester,
        &[0],
        (1, page::namespace_id(&treaty.destination_namespace)?),
        Some(&treaty.destination_namespace),
        0,
    )?;
    c.application(
        intent.requester,
        grant(operation)?,
        None,
        "PagesRead",
        &treaty.destination_namespace,
        None,
    )?;
    let ids = proof
        .state
        .records
        .values()
        .filter(|r| r.reference.kind == 153)
        .map(|r| r.reference.id)
        .collect::<Vec<_>>();
    let mut processed = None;
    for id in ids {
        let before = (c.dependencies.clone(), c.selected.clone(), c.expires);
        let share_record = proof.state.record(153, id)?;
        let share = Share::parse(
            &share_record.payload,
            treaty.source.network,
            treaty.source.incarnation,
        )?;
        let page = qualified_page(treaty.id, &treaty.source, share.page)?;
        let selected = (|| -> Result<()> {
            let (_, head, _, revision) = c.federation_revision(page, true)?;
            ensure!(
                revision.native == share.revision
                    && revision.share == share_record.reference
                    && share.allowed,
                "local foreign publication no longer matches shared source"
            );
            c.federation_principal(
                intent.requester,
                grant(operation)?,
                None,
                0,
                treaty,
                page,
                share.page,
                revision.bundle.len() as u64,
            )?;
            current_review(c, &head, treaty, &revision)?;
            Ok(())
        })();
        if selected.is_err() {
            c.dependencies = before.0;
            c.selected = before.1;
            c.expires = before.2;
            processed = Some(id);
            continue;
        }
        if result(
            c,
            next,
            changed,
            match &operation.command {
                super::super::super::Command::Federation(c) => c,
                _ => unreachable!(),
            },
            Some(id),
        )
        .is_err()
        {
            c.dependencies = before.0;
            c.selected = before.1;
            c.expires = before.2;
            *cursor = processed;
            ensure!(
                cursor.is_some(),
                "one federation listing exceeds certified result capacity"
            );
            return Ok(());
        }
        processed = Some(id);
    }
    *cursor = proof.cursor;
    Ok(())
}
