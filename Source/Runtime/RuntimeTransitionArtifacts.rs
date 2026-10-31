// SPDX-License-Identifier: MIT
// Staging addresses use SHA-256; service consent binds the staged bytes with RecordDigest.
use super::*;

fn read(root: &Path, replacement: &Replacement) -> Result<Vec<u8>> {
    crate::trust_bootstrap::hex32(&replacement.digest)?;
    let bytes = files::read(
        &root.join("TransitionFiles").join(&replacement.digest),
        files::MAXIMUM,
    )?;
    ensure!(
        files::hex_digest(&bytes) == replacement.digest,
        "Staged successor changed"
    );
    Ok(bytes)
}

pub(super) fn configuration(
    root: &Path,
    replacements: &BTreeMap<String, Replacement>,
) -> Result<BTreeMap<String, [u8; 32]>> {
    replacements
        .iter()
        .filter_map(|(relative, replacement)| {
            relative
                .strip_prefix("Config/")
                .map(|name| Ok((name.into(), wire::digest(&read(root, replacement)?))))
        })
        .collect()
}

pub(super) fn recover(t: &mut Transaction) -> Result<()> {
    let Some(profile) = &t.service else {
        return Ok(());
    };
    ensure!(
        t.proposal.service
            && profile.root == t.proposal.root
            && profile.manifest == t.proposal.successor,
        "Retained service successor differs"
    );
    let root = &t.proposal.root;
    let mut corrected = profile.clone();
    for (name, digest) in configuration(root, &t.replacements)? {
        let prior = profile
            .artifacts
            .get(&name)
            .context("Staged configuration was not consented")?;
        let replacement = &t.replacements[&format!("Config/{name}")];
        ensure!(
            *prior == digest || *prior == crate::trust_bootstrap::hex32(&replacement.digest)?,
            "Retained artifact is neither its staged address nor its RecordDigest"
        );
        corrected.artifacts.insert(name, digest);
    }
    if corrected.artifacts == profile.artifacts {
        return Ok(());
    }
    let retained = t
        .replacements
        .get("Authorization/LocalConsent.cbor")
        .context("Retained local service consent absent")?;
    let (payload, signatures) = wire::envelope(&read(root, retained)?, 1)?;
    let role = profile.role()?.role;
    ensure!(
        signatures.len() == 1
            && signatures[0].0 == profile.manifest.operator
            && payload
                == crate::runtime_service_authorization::local_consent(
                    &profile.manifest,
                    role,
                    profile.manifest.generation,
                    &profile.artifacts
                )?,
        "Retained local consent differs from the exact interrupted profile"
    );
    let manifest = t
        .replacements
        .get("Config/Manifest.cbor")
        .context("Staged service manifest absent")?;
    ensure!(
        read(root, manifest)? == t.proposal.successor.encode()?,
        "Staged manifest differs from reviewed successor"
    );
    corrected.validate()?;
    let key = services::setup::operator(&corrected)?;
    ensure!(
        key.verifying_key().to_bytes() == corrected.manifest.operator,
        "Recovery operator differs"
    );
    let local = crate::runtime_service_authorization::local_consent(
        &corrected.manifest,
        role,
        corrected.manifest.generation,
        &corrected.artifacts,
    )?;
    stage(
        root,
        &mut t.replacements,
        "Authorization/LocalConsent.cbor",
        &wire::sign_envelope(&local, &key)?,
        true,
        None,
    )?;
    t.service = Some(corrected);
    // Preserve the proposal and operation identity before any active file is replaced.
    files::save(&root.join("Transition.json"), t)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeTransitionArtifactsTests.rs"]
mod tests;
