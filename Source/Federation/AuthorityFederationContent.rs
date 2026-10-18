// SPDX-License-Identifier: MIT
// A source Bridge reads exact native content only under fresh bilateral destination admission.
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn authorise(
    c: &mut page::Evaluation<'_>,
    operation: &Operation,
    command: &Command,
    intent: &Intent,
    next: &mut State,
    changed: &mut BTreeSet<(u64, Digest)>,
    replay: bool,
) -> Result<()> {
    let Command::ContentAuthorise {
        placement,
        host,
        offset,
        bytes,
        proof,
    } = command
    else {
        unreachable!()
    };
    let Command::Admission {
        agreement,
        page: Some(raw),
        revision: Some(requested),
        ..
    } = proof.command()?
    else {
        anyhow::bail!("source content requires exact destination revision admission")
    };
    let accepted = c.select(151, agreement.id)?;
    let accepted = c.federation_agreement(&accepted.reference)?;
    ensure!(
        accepted
            .treaty
            .source
            .matches(c.state.network, c.state.incarnation)
            && intent.requester == accepted.treaty.source_bridge,
        "content transfer is outside the exact source Bridge"
    );
    let bridge = c.select(152, intent.requester)?;
    service(c, intent, operation, &accepted, &bridge.reference)?;
    let (_, review, revision, _, _) = c.federation_source(&accepted.treaty, raw)?;
    ensure!(
        review.statement.revision == requested,
        "source content revision changed after admission"
    );
    let exact = page::content::select_placement(c, &requested, &revision, false)?;
    ensure!(
        exact == *placement,
        "content transfer substituted its source placement"
    );
    let value = page::content::live(c, placement)?;
    ensure!(
        !value.opaque
            && value.revision.kind == 141
            && value.hosts.contains(host)
            && *bytes > 0
            && *bytes <= 32768
            && offset
                .checked_add(*bytes)
                .is_some_and(|end| end <= value.bytes),
        "foreign content read exceeds explicit host, mode or immutable range"
    );
    let selected = c.host(host, Some(&accepted.treaty.source_namespace), true)?;
    ensure!(
        selected.profile.role == 1
            && selected.profile.content.is_some()
            && value.bytes <= selected.profile.maximum_asset_bytes,
        "foreign content exceeds current selected host consent"
    );
    let verified = c.federation_foreign(proof, &accepted.treaty, &Resolved::default(), replay)?;
    foreign_floor(c, next, changed, &verified, replay)
}
