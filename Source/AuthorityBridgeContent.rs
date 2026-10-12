// SPDX-License-Identifier: MIT
// Page bodies cross the Bridge as finite host receipts, separately from authority metadata.
use super::*;
pub(super) fn source(client: &client::Shared<'_>, value: &V) -> Result<Vec<u8>> {
    let f = value.array(9)?;
    let command = federation::Command::ContentAuthorise {
        proof: federation::ForeignProof::parse(f[4].bytes()?)?,
        placement: domains::version(&f[5])?,
        host: domains::version(&f[6])?,
        offset: f[7].uint()?,
        bytes: f[8].uint()?,
    };
    reply("BridgeContent", vec![b(&client.media(command, &[])?)])
}
pub(super) async fn fetch(
    client: &client::Shared<'_>,
    network: &tls::Transport,
    treaty: &federation::Treaty,
    proof: &federation::ForeignProof,
    verified: &federation::VerifiedForeign,
) -> Result<Resolved> {
    let (metadata, review) = proof.exported_publication()?;
    let id = page::content::placement_id(&metadata)?;
    let record = verified.state.record(159, id)?.clone();
    let placement = page::content::Placement::parse(&record.payload)?;
    ensure!(
        placement.revision == review.statement.revision && !placement.opaque,
        "Bridge source placement differs from native publication"
    );
    let host = placement
        .hosts
        .iter()
        .find(|host| {
            verified.state.record(147, host.id).is_ok_and(|record| {
                record.reference == **host
                    && page::Host::parse(
                        &record.payload,
                        verified.state.network,
                        verified.state.incarnation,
                    )
                    .is_ok_and(|value| !value.withdrawn && value.profile.content.is_some())
            })
        })
        .context("source body has no current consenting selected host")?
        .clone();
    let raw = metadata.author.raw_page;
    let mut bytes = Vec::with_capacity(metadata.author.source.len());
    while bytes.len() < metadata.author.source.len() {
        let offset = bytes.len() as u64;
        let count = (placement.bytes - offset).min(32768);
        let (_, admission, _) = admission(
            client,
            network,
            treaty.id,
            Some(raw),
            Some(placement.revision.clone()),
            None,
        )
        .await?;
        let response = network
            .exchange(
                treaty.source_bridge,
                &packet(
                    "BridgeContent",
                    vec![
                        b(&treaty.id),
                        b(&admission.bytes),
                        crate::authority_membership::reference(&record.reference),
                        crate::authority_membership::reference(&host),
                        V::Uint(offset),
                        V::Uint(count),
                    ],
                )?,
                client.deadline()?,
            )
            .await?;
        let value = wire::decode_state(&response)?;
        let f = value.array(4)?;
        ensure!(
            f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BridgeContent",
            "source content response differs"
        );
        let context = client.context().0;
        let agreement = federation::Agreement::parse(
            &context.record(151, treaty.id)?.payload,
            context.network,
            context.incarnation,
        )?;
        let trust = federation::ForeignTrust::parse(
            &context.record(150, agreement.foreign.id)?.payload,
            context.network,
            context.incarnation,
        )?;
        let floor =
            federation::ForeignFloor::parse(&context.record(157, agreement.foreign.id)?.payload)?
                .resolve(&trust)?;
        let receipt = page::MediaReceipt::parse(f[3].bytes()?)?;
        let report = receipt.verify(&trust.verified()?, &floor.descriptor)?;
        ensure!(
            report.result().disposition() == crate::authority_proof::Disposition::Permit
                && report.request().requester == treaty.source_bridge
                && report.result().executed.expires_at_ms > client.now()?.saturating_add(1250),
            "source content lacks current exact Bridge authorization"
        );
        let operation = domains::Operation::parse(report.request())?;
        let domains::Command::Federation(federation::Command::ContentAuthorise {
            placement: p,
            host: h,
            offset: o,
            bytes: n,
            proof: a,
        }) = operation.command
        else {
            anyhow::bail!("source receipt substituted the finite content action")
        };
        ensure!(
            p == record.reference
                && h == host
                && o == offset
                && n == count
                && a.bytes == admission.bytes,
            "source content receipt changed placement, host, extent or admission"
        );
        let response = wire::decode(report.response())?;
        bytes.extend_from_slice(response.array(11)?[9].bytes()?);
        ensure!(
            bytes.len() as u64 == offset + count,
            "source returned another body extent"
        );
    }
    let bundle = proof.rebuild_bundle(&bytes)?;
    let reference = review.bundle.context("source approved bundle absent")?;
    Resolved::exact(
        std::slice::from_ref(&reference),
        vec![crate::authority_objects::Object::verify(
            reference.clone(),
            page::objects::Bundle::encode(
                &bundle.source,
                &bundle.author.bytes,
                &bundle.review.bytes,
            )?,
        )?],
    )
}
