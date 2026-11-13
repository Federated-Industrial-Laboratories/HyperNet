// SPDX-License-Identifier: MIT
// Reviewed public certificate bundles stage only the existing TLS and peer bindings.
use super::*;
use crate::runtime_manifest::certificates;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EndpointCertificate {
    endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport_key: Option<String>,
    certificate_pem: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Bundle {
    format: String,
    issuer_pem: String,
    certificates: Vec<EndpointCertificate>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    previous_issuer_pem: String,
    bundle: Bundle,
}

impl Selection {
    fn leaves(&self) -> Result<BTreeMap<[u8; 32], Vec<u8>>> {
        ensure!(
            self.bundle.format == "HyperNetTransportCertificates/1"
                && (1..=16).contains(&self.bundle.certificates.len()),
            "Unsupported certificate bundle"
        );
        let mut leaves = BTreeMap::new();
        for endpoint in &self.bundle.certificates {
            let id = crate::trust_bootstrap::hex32(&endpoint.endpoint)?;
            ensure!(
                leaves
                    .insert(id, certificates::der(&endpoint.certificate_pem)?)
                    .is_none(),
                "Repeated certificate endpoint"
            );
        }
        Ok(leaves)
    }
}
pub(super) fn status(root: &Path, service: bool) -> Result<Value> {
    super::require_idle(root)?;
    let (manifest, _) = current(root, service)?;
    ensure!(
        !manifest.endpoints.is_empty(),
        "Deployment has no TLS certificates"
    );
    let (_, issuer) = installed_issuer(root, service)?;
    let issuer_interval = certificates::interval(&issuer)?;
    let mut expiry = issuer_interval.1;
    let mut start = issuer_interval.0;
    let now = files::now()?
        .checked_mul(1000)
        .context("Certificate time overflow")?;
    let mut valid = true;
    let mut endpoints = Vec::new();
    for endpoint in &manifest.endpoints {
        let interval = certificates::interval(&endpoint.leaf_der)?;
        expiry = expiry.min(interval.1);
        start = start.max(interval.0);
        valid &= certificates::current(&endpoint.leaf_der, &issuer, endpoint.address, now).is_ok();
        endpoints.push(json!({"endpoint":hex::encode(endpoint.endpoint_id),"serviceKey":hex::encode(endpoint.service_key),
            "transportKey":hex::encode(endpoint.transport_key),"validitySeconds":interval}));
    }
    Ok(
        json!({"format":"HyperNetTransportStatus/1","valid":valid,"notBeforeMs":start * 1000,
        "notAfterMs":expiry * 1000,"issuerValiditySeconds":issuer_interval,"endpoints":endpoints,
        "manifestGeneration":manifest.generation,"transportSuccessor":manifest.transport_certificates.is_some()}),
    )
}
pub(super) fn template(root: &Path, service: bool) -> Result<Value> {
    super::require_idle(root)?;
    let (manifest, _) = current(root, service)?;
    ensure!(
        !manifest.endpoints.is_empty() && (!service || manifest.roles[0].role == 5),
        "Certificate template requires an authority or route service"
    );
    let (_, issuer) = installed_issuer(root, service)?;
    let issuer_pem = certificates::pem(&issuer)?;
    let bundle = Bundle {
        format: "HyperNetTransportCertificates/1".into(),
        issuer_pem,
        certificates: manifest
            .endpoints
            .iter()
            .map(|e| {
                Ok(EndpointCertificate {
                    endpoint: hex::encode(e.endpoint_id),
                    service_key: Some(hex::encode(e.service_key)),
                    transport_key: Some(hex::encode(e.transport_key)),
                    certificate_pem: certificates::pem(&e.leaf_der)?,
                })
            })
            .collect::<Result<_>>()?,
    };
    Ok(serde_json::to_value(bundle)?)
}
fn installed_issuer(root: &Path, service: bool) -> Result<(String, Vec<u8>)> {
    let raw = String::from_utf8(files::public_read(
        &issuer_path(root, service),
        if service { 8192 } else { 65536 },
    )?)?;
    let issuer = if service {
        certificates::der(&raw)?
    } else {
        certificates::repeated_issuer_der(&raw)?
    };
    Ok((raw, issuer))
}
fn issuer_path(root: &Path, service: bool) -> PathBuf {
    root.join(if service {
        "Config/CertificateAuthority.pem"
    } else {
        "Work/Config/Tls/Authority.pem"
    })
}
pub(super) fn prepare(
    root: &Path,
    service: bool,
    previous: &Manifest,
    successor: &mut Manifest,
    path: Option<&Path>,
) -> Result<Option<Selection>> {
    let Some(path) = path else { return Ok(None) };
    ensure!(
        !service || (previous.roles.len() == 1 && previous.roles[0].role == 5),
        "Certificate succession requires an authority or route service"
    );
    let bytes = files::public_read(path, 128 * 1024)?;
    let mut bundle: Bundle = serde_json::from_slice(&bytes)?;
    bundle.issuer_pem = certificates::pem(&certificates::der(&bundle.issuer_pem)?)?;
    for endpoint in &mut bundle.certificates {
        endpoint.certificate_pem =
            certificates::pem(&certificates::der(&endpoint.certificate_pem)?)?;
    }
    let (previous_issuer_pem, _) = installed_issuer(root, service)?;
    let selection = Selection {
        previous_issuer_pem,
        bundle,
    };
    if let Some(current) = &previous.transport_certificates {
        ensure!(
            current.issuer_pem == selection.previous_issuer_pem,
            "Installed issuer differs from current transport consent"
        );
    }
    successor.adopt_certificates(
        previous,
        selection.bundle.issuer_pem.clone(),
        &selection.leaves()?,
        selection.previous_issuer_pem.clone(),
    )?;
    validate(previous, successor, &selection, true)?;
    Ok(Some(selection))
}
pub(super) fn validate(
    previous: &Manifest,
    successor: &Manifest,
    selection: &Selection,
    fresh: bool,
) -> Result<()> {
    certificates::issuer_successor(
        &if previous.authority_config.is_some() {
            certificates::repeated_issuer_der(&selection.previous_issuer_pem)?
        } else {
            certificates::der(&selection.previous_issuer_pem)?
        },
        &certificates::der(&selection.bundle.issuer_pem)?,
    )?;
    let leaves = selection.leaves()?;
    for selected in &selection.bundle.certificates {
        let endpoint = successor
            .endpoints
            .iter()
            .find(|e| hex::encode(e.endpoint_id) == selected.endpoint)
            .context("Selected certificate endpoint differs")?;
        ensure!(
            selected
                .service_key
                .as_ref()
                .is_none_or(|key| *key == hex::encode(endpoint.service_key))
                && selected
                    .transport_key
                    .as_ref()
                    .is_none_or(|key| *key == hex::encode(endpoint.transport_key)),
            "Certificate bundle public identity differs from retained endpoint"
        );
    }
    let mut expected = successor.clone();
    expected.adopt_certificates(
        previous,
        selection.bundle.issuer_pem.clone(),
        &leaves,
        selection.previous_issuer_pem.clone(),
    )?;
    ensure!(
        &expected == successor && successor.transport_changed(previous),
        "Reviewed certificate successor is unchanged or differs from its exact bundle"
    );
    if fresh {
        successor.current_transport(
            files::now()?
                .checked_mul(1000)
                .context("Certificate time overflow")?,
        )?;
    }
    Ok(())
}
pub(super) fn stage_files(
    root: &Path,
    proposal: &Proposal,
    replacements: &mut BTreeMap<String, Replacement>,
    fresh: bool,
) -> Result<()> {
    let Some(selection) = &proposal.transport else {
        return Ok(());
    };
    validate(&proposal.previous, &proposal.successor, selection, fresh)?;
    let own = proposal
        .successor
        .endpoints
        .iter()
        .find(|endpoint| {
            proposal.successor.roles[0]
                .bind_endpoint_ids
                .contains(&endpoint.endpoint_id)
        })
        .context("Own certificate endpoint absent")?;
    let leaf = certificates::pem(&own.leaf_der)?;
    let names = if proposal.service {
        [
            (
                "Config/Certificate.pem",
                "Config/Certificate.pem",
                leaf.as_bytes(),
            ),
            (
                "Config/CertificateAuthority.pem",
                "Config/CertificateAuthority.pem",
                selection.bundle.issuer_pem.as_bytes(),
            ),
        ]
    } else {
        [
            (
                "Work/Config/Tls/Certificate.pem",
                "Config/Tls/Certificate.pem",
                leaf.as_bytes(),
            ),
            (
                "Work/Config/Tls/Authority.pem",
                "Config/Tls/Authority.pem",
                selection.bundle.issuer_pem.as_bytes(),
            ),
        ]
    };
    for (relative, launch, bytes) in names {
        stage(root, replacements, relative, bytes, false, Some(launch))?;
    }
    Ok(())
}
pub(super) fn summary(selection: &Selection) -> Result<Value> {
    Ok(
        json!({"issuerKey":hex::encode(crate::runtime_manifest::leaf_key(&certificates::der(&selection.bundle.issuer_pem)?)?),
        "previousIssuerDigest":files::hex_digest(selection.previous_issuer_pem.as_bytes()),
        "issuerDigest":files::hex_digest(selection.bundle.issuer_pem.as_bytes()),
        "issuerValiditySeconds":certificates::interval(&certificates::der(&selection.bundle.issuer_pem)?)?,
        "endpoints":selection.leaves()?.iter().map(|(id, leaf)| Ok(json!({"endpoint":hex::encode(id),"certificateDigest":files::hex_digest(leaf),"validitySeconds":certificates::interval(leaf)?}))).collect::<Result<Vec<_>>>()?,
        "authority":"Same keys, addresses, ports, issuer identity, SAN and usages; no new capability or budget"}),
    )
}

/// Historical application cannot select different software or authorise serving.
pub(super) fn historical(proposal: &Proposal) -> Result<()> {
    historical_at(
        proposal,
        files::now()?
            .checked_mul(1000)
            .context("Certificate time overflow")?,
    )
}
pub(super) fn historical_at(proposal: &Proposal, now: u64) -> Result<()> {
    ensure!(
        proposal.transport.is_some() && proposal.package.is_none(),
        "Historical apply requires an exact certificate-only successor"
    );
    let interval = proposal
        .successor
        .transport_interval()?
        .context("Historical certificate successor absent")?;
    ensure!(
        now >= interval.0 && now >= interval.1 && now >= proposal.successor.validity.0,
        "Historical certificate successor must have expired and already started"
    );
    Ok(())
}
