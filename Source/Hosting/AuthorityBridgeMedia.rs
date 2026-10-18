// SPDX-License-Identifier: MIT
// Bulk assets cross only consented bridges and are decoded again by each destination store.
use super::*;
use sha2::{Digest as _, Sha256};
pub(super) fn source(
    client: &client::Shared<'_>,
    _network: &tls::Transport,
    value: &V,
) -> Result<Vec<u8>> {
    let f = value.array(9)?;
    let proof = federation::ForeignProof::parse(f[4].bytes()?)?;
    let asset = domains::version(&f[5])?;
    let host = domains::version(&f[6])?;
    let offset = f[7].uint()?;
    let bytes = f[8].uint()?;
    let command = federation::Command::MediaAuthorise {
        asset,
        host,
        effect: page::MediaEffect::Read,
        offset,
        bytes,
        digest: None,
        proof,
    };
    let receipt = client.media(command, &[])?;
    reply("BridgeMedia", vec![b(&receipt)])
}
pub(super) async fn replicate(
    client: &client::Shared<'_>,
    network: &tls::Transport,
    id: Digest,
    raw: [u8; 16],
) -> Result<()> {
    let agreement = federation::Agreement::parse(
        &client.context().0.record(151, id)?.payload,
        client.context().0.network,
        client.context().0.incarnation,
    )?;
    let qualified = federation::qualified_page(id, &agreement.treaty.source, raw)?;
    let head = federation::ForeignPage::parse(&client.context().0.record(154, qualified)?.payload)?;
    let Some(reference) = head.pending else {
        // Re-importing an already reviewed immutable revision preserves that decision and its copies.
        return Ok(());
    };
    let revision =
        federation::ForeignRevision::parse(&client.context().0.record(155, reference.id)?.payload)?;
    for manifest in &revision.metadata.assets {
        let asset = client
            .context()
            .0
            .record(144, page::asset_id(&reference, &manifest.id)?)?
            .clone();
        let placement = page::Asset::parse(&asset.payload)?;
        // The full canonical object is bounded by the Page media profile, never by a peer-declared allocation.
        let mut bytes = Vec::with_capacity(usize::try_from(manifest.bytes)?);
        let mut offset = 0;
        while offset < manifest.bytes {
            let count = (manifest.bytes - offset).min(32768);
            let treaty = agreement.treaty.clone();
            let source_asset = page::asset_id(&revision.native, &manifest.id)?;
            // A fresh export selects the exact source placement and its generation before the source effect.
            let (proof, objects) = lease(
                client,
                network,
                id,
                Some(raw),
                Some(revision.native.clone()),
                None,
                None,
                false,
            )
            .await?;
            let verified =
                proof.verify(&client.context().0, &treaty, client.now()?, &objects, false)?;
            let source_record = verified.state.record(144, source_asset)?;
            let source_value = page::Asset::parse(&source_record.payload)?;
            ensure!(
                source_value.manifest == *manifest,
                "foreign source media descriptor changed"
            );
            let host = source_value
                .hosts
                .iter()
                .find(|h| treaty.source_hosts.contains(&h.id))
                .context("source media has no agreed placement")?;
            // Export advanced the source's destination floor. Refresh Admission against that exact new anchor.
            let (_, admission, _) = admission(
                client,
                network,
                id,
                Some(raw),
                Some(revision.native.clone()),
                None,
            )
            .await?;
            let response = network
                .exchange(
                    treaty.source_bridge,
                    &packet(
                        "BridgeMedia",
                        vec![
                            b(&id),
                            b(&admission.bytes),
                            reference_value(&source_record.reference),
                            reference_value(host),
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
                f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "BridgeMedia",
                "source media response differs"
            );
            let receipt = page::MediaReceipt::parse(f[3].bytes()?)?;
            let trust = federation::ForeignTrust::parse(
                &client
                    .context()
                    .0
                    .record(150, agreement.foreign.id)?
                    .payload,
                client.context().0.network,
                client.context().0.incarnation,
            )?;
            let floor = federation::ForeignFloor::parse(
                &client
                    .context()
                    .0
                    .record(157, agreement.foreign.id)?
                    .payload,
            )?
            .resolve(&trust)?;
            let report = receipt.verify(&trust.verified()?, &floor.descriptor)?;
            ensure!(
                report.result().disposition() == crate::authority_proof::Disposition::Permit
                    && report.request().requester == treaty.source_bridge,
                "source media lacks exact bridge permit"
            );
            let operation = domains::Operation::parse(report.request())?;
            let domains::Command::Federation(federation::Command::MediaAuthorise {
                asset: a,
                host: h,
                effect,
                offset: o,
                bytes: c,
                proof: source_admission,
                ..
            }) = &operation.command
            else {
                anyhow::bail!("source receipt changed finite media operation")
            };
            ensure!(
                source_admission.bytes == admission.bytes
                    && report.result().executed.expires_at_ms > client.now()?.saturating_add(1250),
                "source receipt does not bind this live exact admission"
            );
            ensure!(
                *a == source_record.reference
                    && *h == *host
                    && *effect == page::MediaEffect::Read
                    && *o == offset
                    && *c == count,
                "source changed exact media extent"
            );
            let response = wire::decode(report.response())?;
            let r = response.array(11)?;
            bytes.extend_from_slice(r[9].bytes()?);
            offset = offset
                .checked_add(count)
                .context("bridge media offset overflow")?;
        }
        ensure!(
            bytes.len() as u64 == manifest.bytes
                && hex::encode(Sha256::digest(&bytes)) == manifest.digest,
            "source media bytes differ from approved content"
        );
        crate::markup::media::validate_asset_bytes(manifest, &bytes).map_err(anyhow::Error::msg)?;
        for host in &placement.hosts {
            let mut copy = None;
            for (index, chunk) in bytes.chunks(32768).enumerate() {
                let (proof, _) = lease(
                    client,
                    network,
                    id,
                    Some(raw),
                    Some(revision.native.clone()),
                    None,
                    None,
                    false,
                )
                .await?;
                let receipt = client.media(
                    federation::Command::MediaAuthorise {
                        asset: asset.reference.clone(),
                        host: host.clone(),
                        effect: page::MediaEffect::Upload,
                        offset: (index * 32768) as u64,
                        bytes: chunk.len() as u64,
                        digest: Some(Sha256::digest(chunk).into()),
                        proof,
                    },
                    chunk,
                )?;
                let report = client.local_media_report(&receipt)?;
                let value = wire::decode(report.response())?;
                let f = value.array(11)?;
                if f[10] != V::Null {
                    copy = Some(page::CopyReceipt::parse(
                        f[10].bytes()?,
                        client.context().0.network,
                        client.context().0.incarnation,
                    )?);
                }
            }
            let receipt =
                copy.context("destination media store omitted validated whole-asset receipt")?;
            let (proof, _) = lease(
                client,
                network,
                id,
                Some(raw),
                Some(revision.native.clone()),
                None,
                None,
                false,
            )
            .await?;
            client.action(federation::Command::MediaReceipt { receipt, proof })?;
        }
    }
    Ok(())
}
fn reference_value(value: &VersionRef) -> V {
    crate::authority_membership::reference(value)
}
