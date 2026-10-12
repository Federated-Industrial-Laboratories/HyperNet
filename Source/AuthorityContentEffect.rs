// SPDX-License-Identifier: MIT
// A completed copy is signed only after source validation and durable storage of its exact bytes.
use super::*;
use crate::authority_proof::{Digest, VersionRef};
fn copy_receipt(
    bytes: &[u8],
    object: &disk::Object,
    placement: &VersionRef,
    host: &VersionRef,
    profile: &page::HostProfile,
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let (payload, signers) = wire::envelope(bytes, 1)?;
    let value = wire::decode(&payload)?;
    let f = value.array(8)?;
    let v = f[5].array(5)?;
    ensure!(
        f[0].text()? == "HyperNetDurableCopy"
            && f[1].uint()? == 1
            && f[2].fixed::<32>()? == profile.manifest.network
            && f[3].fixed::<32>()? == profile.manifest.incarnation
            && f[4].fixed::<32>()? == wire::digest(&profile.envelope)
            && signers.len() == 1
            && signers[0].0 == profile.service
            && v[0].fixed::<32>()? == object.placement
            && v[1].fixed::<32>()? == object.digest
            && v[2].uint()? == object.bytes
            && v[3].uint()? == object.expires_ms
            && v[4].boolean()? == object.opaque,
        "durable content receipt differs from the selected complete object"
    );
    let receipt = content::Copy {
        placement: placement.clone(),
        host: host.clone(),
        digest: object.digest,
        bytes: object.bytes,
        request: f[6].fixed()?,
        recorded_ms: f[7].uint()?,
        expires_ms: object.expires_ms,
        envelope: vec![],
    };
    let signed = wire::sign_envelope(
        &receipt.payload(profile.manifest.network, profile.manifest.incarnation)?,
        key,
    )?;
    content::Copy::parse(
        &signed,
        profile.manifest.network,
        profile.manifest.incarnation,
    )?;
    Ok(signed)
}
fn complete(
    disk: &mut disk::Disk,
    object: &disk::Object,
    request: Digest,
    key: &SigningKey,
    now: u64,
    revision: Option<&page::Revision>,
) -> Result<Vec<u8>> {
    disk.complete(object, request, key, now, |file| {
        if !object.opaque {
            ensure!(
                object.bytes <= crate::authority_objects::PAGE_SOURCE_BYTES as u64,
                "content source exceeds its bound"
            );
            let mut bytes = vec![0; object.bytes as usize];
            file.read_exact_at(&mut bytes, 0)?;
            revision
                .context("content completion lacks exact source metadata")?
                .verify_source(&bytes)?;
        }
        Ok(())
    })
}
#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    disk: &mut disk::Disk,
    request: &Request,
    selected: &content::Placement,
    revision: Option<&page::Revision>,
    profile: &page::HostProfile,
    payload: &[u8],
    key: &SigningKey,
    now: u64,
) -> Result<Vec<u8>> {
    let page::Command::Content(content::Command::Authorise {
        placement,
        host,
        effect,
        offset,
        bytes,
        digest,
    }) = request.command()
    else {
        anyhow::bail!("unexpected content effect")
    };
    let object = disk::Object {
        placement: placement.digest,
        digest: selected.digest,
        bytes: selected.bytes,
        expires_ms: selected.expires_ms,
        opaque: selected.opaque,
    };
    let mut response = Vec::new();
    let mut receipt = None;
    let hash = match effect {
        content::Effect::Upload | content::Effect::Repair => {
            ensure!(
                payload.len() as u64 == *bytes
                    && *digest == Some(sha2::Sha256::digest(payload).into()),
                "content upload differs from signed extent"
            );
            if *effect == content::Effect::Repair {
                disk.repair(&object, now)?;
            } else {
                disk.reserve(&object, now)?;
            }
            let completed = disk
                .inventory()
                .iter()
                .any(|(o, s, _)| o.placement == object.placement && *s == disk::Status::Complete);
            let received = if completed {
                disk.reconcile(&object, now)?;
                ensure!(
                    disk.read(&object, *offset, *bytes as usize, now)? == payload,
                    "completed content retry changed bytes"
                );
                object.bytes
            } else {
                disk.write(&object, *offset, payload, now)?
            };
            if received == object.bytes {
                receipt = Some(complete(
                    disk,
                    &object,
                    request.intent().digest,
                    key,
                    now,
                    revision,
                )?);
            }
            digest.context("upload digest absent")?
        }
        content::Effect::Read | content::Effect::Inspect => {
            ensure!(payload.is_empty(), "content read carries unexpected bytes");
            disk.reconcile(&object, now)?;
            response = disk.read(&object, *offset, *bytes as usize, now)?;
            receipt = Some(complete(
                disk,
                &object,
                request.intent().digest,
                key,
                now,
                revision,
            )?);
            sha2::Sha256::digest(&response).into()
        }
        content::Effect::Purge => {
            ensure!(payload.is_empty(), "content purge carries unexpected bytes");
            disk.purge(placement.digest, now)?;
            sha2::Sha256::digest([]).into()
        }
    };
    let receipt = receipt
        .map(|r| copy_receipt(&r, &object, placement, host, profile, key))
        .transpose()?;
    wire::encode(&V::Array(vec![
        V::Uint(201),
        V::Uint(1),
        V::Text("PageContentEffect".into()),
        crate::authority_membership::reference(placement),
        crate::authority_membership::reference(host),
        V::Uint(effect.code()),
        V::Uint(*offset),
        V::Uint(*bytes),
        V::Bytes(hash.to_vec()),
        V::Bytes(response),
        receipt.map_or(V::Null, V::Bytes),
    ]))
}
