// SPDX-License-Identifier: MIT
use super::model::save;
use super::{bootstrap, containers, files::*, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub fn current_health(root: &Path, p: &Profile, s: &State) -> Result<Value> {
    ensure!(now()? >= s.last_time, "Clock moved backwards");
    verify_consent(root, p, s)?;
    ensure!(
        containers::processes(p, s)?,
        "The appointed authority process is not running"
    );
    let health = containers::live_status(p, s, signer_generation(root)?)?;
    bootstrap::retain_status(root, p, &health)?;
    Ok(health)
}
pub(super) fn check_artifacts(root: &Path, p: &Profile) -> Result<()> {
    ensure!(
        executable(&std::env::current_exe()?.canonicalize()?)? == p.software_digest,
        "Consented software changed"
    );
    for (relative, digest) in &p.artifacts {
        ensure!(
            hex_digest(&read(&root.join(relative), MAXIMUM)?) == *digest,
            "Imported configuration changed"
        );
    }
    let info: Value = serde_json::from_slice(&podman(&strings(&["info", "--format", "json"]))?)?;
    ensure!(
        info["host"]["security"]["rootless"] == true && info["host"]["cgroupVersion"] == "v2",
        "Rootless Podman and cgroup v2 required"
    );
    ensure!(
        selinux_enabled()? == p.selinux_relabel
            && info["host"]["security"]["selinuxEnabled"] == p.selinux_relabel,
        "SELinux mode differs from the reviewed local profile"
    );
    let image: Value = serde_json::from_slice(&podman(&strings(&["image", "inspect", &p.image]))?)?;
    ensure!(
        image[0]["Id"].as_str().is_some_and(
            |id| id.trim_start_matches("sha256:") == p.image.trim_start_matches("sha256:")
        ),
        "Installed image identity changed"
    );
    Ok(())
}
fn start(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    super::transition::require_servable(root)?;
    ensure!(
        capacity(root)? >= p.resources.state_bytes,
        "Available storage is below the consented admission budget"
    );
    verify_consent(root, p, s)?;
    ensure!(
        s.withdrawal_generation == 0,
        "Withdrawn deployment cannot restart"
    );
    check_artifacts(root, p)?;
    ensure!(
        !s.resources.iter().any(|r| r.kind == "container"),
        "Stop recorded containers before starting"
    );
    containers::verify_image(root, p, s)?;
    containers::prepare(root, p)?;
    if p.purpose.future() {
        ensure!(
            s.initialised,
            "Future authority requires explicit committed epoch preparation and activation"
        );
        let status = containers::temporary(root, p, s, false)?;
        bootstrap::retain_status(root, p, &status)?;
        ensure!(
            status["canVote"] == true,
            "Prepared future authority awaits certified readiness activation"
        );
    } else {
        bootstrap::initialise(root, p, s)?;
    }
    containers::network(root, p, s)?;
    verify_consent(root, p, s)?;
    containers::authority(root, p, s)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match current_health(root, p, s) {
            Ok(health) => {
                s.status = if health["clockReady"] == true {
                    "Running"
                } else {
                    "ClockUnavailable"
                }
                .into();
                return Ok(());
            }
            Err(error) if Instant::now() >= deadline => {
                return Err(error.context("Appointed replica did not expose local status"));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}
fn stop(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    containers::stop(root, p, s)?;
    bootstrap::stopped(root, p, s)?;
    Ok(())
}
fn preview(p: &Profile, s: &State) -> Result<Value> {
    Ok(
        json!({"version":1,"deployment":p.deployment,"network":p.network,"signer":p.signer,
        "profileDigest":s.profile_digest,"generation":s.generation,"status":s.status,
        "backend":"BasicHotStuff","roles":["Authority"],"committeeSize":4,"quorumSize":3,
        "endpoints":{"peerListener":format!("{}:{}",p.bind,p.port),"peers":p.config.peers},
        "resources":p.resources,"storageEnforcement":"Engine bounded objects and journals; available-space admission is not a filesystem quota",
        "expires":p.expires,"sessionPolicy":p.session_policy,"selinuxRelabel":p.selinux_relabel,"managedBootPolicy":p.session_policy=="Managed",
        "logoutBehaviour":"Graceful foreground supervisor exit stops the owned replica; abrupt loss retains independent consent expiry and withdrawal enforcement",
        "delta":if s.accepted_consent.is_none(){"Exact authority appointment and listed resources require consent"}else{"No resource expansion"},
        "requirements":["Accepted independently pinned bootstrap and appointed voter key","Rootless Podman with delegated cgroup v2","Landlock ABI 6 and seccomp","Signed healthy clock witness","Explicit IPv4 peer origins and published listener"],
        "unsupported":["DomainHosting","ServiceRegistration","ReaderJoin","IPv6InstalledProfile"],
        "quorum":"NotProbed","manifest":p.manifest}),
    )
}
fn compact_receipts(
    receipts: &mut std::collections::BTreeMap<String, Receipt>,
    pending: Option<&str>,
) {
    if receipts.len() <= 64 {
        return;
    }
    let mut previous: Vec<_> = receipts
        .iter()
        .filter(|(id, _)| pending != Some(id.as_str()))
        .map(|(id, receipt)| {
            (
                receipt.result["generation"].as_u64().unwrap_or(0),
                id.clone(),
            )
        })
        .collect();
    previous.sort();
    for (_, id) in previous.into_iter().take(receipts.len() - 64) {
        receipts.remove(&id);
    }
}
pub fn dispatch(root: &Path, request: Request) -> Result<Value> {
    if matches!(request.operation, Operation::Diagnose) {
        return super::diagnostics::preview(super::diagnostics::collect_authority(root));
    }
    let root = super::files::root(root)?;
    let _lock = lock(&root)?;
    if root.join("Transition.json").try_exists()? {
        return match request.operation {
            Operation::Stop => super::transition::restrict(&root, false, false),
            Operation::Withdraw => super::transition::restrict(&root, false, true),
            Operation::Status | Operation::Preview => super::transition::pending_status(&root),
            _ => {
                anyhow::bail!("Resume the exact stopped successor before another runtime operation")
            }
        };
    }
    let (p, mut s) = load(&root)?;
    match request.operation {
        Operation::Preview => return preview(&p, &s),
        Operation::Status => {
            let health = if matches!(
                s.status.as_str(),
                "Running" | "ClockUnavailable" | "Degraded"
            ) {
                current_health(&root, &p, &s).ok()
            } else {
                None
            };
            return Ok(
                json!({"deployment":p.deployment,"generation":s.generation,"profileDigest":s.profile_digest,
                "status":if matches!(s.status.as_str(),"Running"|"ClockUnavailable") && health.is_none(){"Degraded"}else{&s.status},
                "running":health.is_some(),"ready":false,"backend":"BasicHotStuff","quorum":"NotProbed",
                "clockReady":health.as_ref().is_some_and(|v|v["clockReady"]==true),"authority":health,
                "minimumSignerGeneration":signer_generation(&root)?,"consentValid":verify_consent(&root,&p,&s).is_ok(),
                "expires":p.expires,"withdrawalGeneration":s.withdrawal_generation,"resourceCount":s.resources.len(),
                "failureCode":s.failure_code,"pendingOperation":s.pending.is_some(),"readerRouting":"Unavailable","managedBootPolicy":p.session_policy=="Managed"}),
            );
        }
        _ => {}
    }
    let operation_id = request
        .operation_id
        .as_deref()
        .context("Operation ID required")?;
    crate::protocol::fixed_hex::<16>(operation_id).map_err(anyhow::Error::msg)?;
    let digest = hex_digest(&serde_json::to_vec(&request)?);
    let retrying_withdrawal = if let Some(receipt) = s.receipts.get(operation_id) {
        ensure!(
            receipt.request_digest == digest,
            "Operation ID was already used for different input"
        );
        if matches!(request.operation, Operation::Withdraw) && receipt.result["ok"] != true {
            // Resume the same restrictive operation without allocating another receipt.
            true
        } else {
            return Ok(receipt.result.clone());
        }
    } else {
        false
    };
    let veto = matches!(request.operation, Operation::Withdraw)
        && request
            .expected_generation
            .is_some_and(|generation| generation > 0 && generation <= s.generation);
    ensure!(
        (veto || request.expected_generation == Some(s.generation))
            && request.profile_digest.as_deref() == Some(&s.profile_digest),
        "Stale generation or changed desired profile"
    );
    if matches!(request.operation, Operation::Start) {
        ensure!(
            !s.resources.iter().any(|r| r.kind == "container"),
            "Stop or recover recorded workloads before a new activation"
        );
        let floor = request
            .minimum_signer_generation
            .context("Start requires --minimum-signer-generation retained independently")?;
        ensure!(
            floor >= signer_generation(&root)?,
            "Signer floor is below retained generation"
        );
    } else {
        ensure!(
            request.minimum_signer_generation.is_none(),
            "Signer generation is only accepted for Start"
        );
    }
    let emergency = matches!(request.operation, Operation::Stop | Operation::Withdraw);
    if !retrying_withdrawal {
        ensure!(
            !matches!(request.operation, Operation::Stop)
                || s.status != "Stopped"
                || s.resources.iter().any(|r| r.kind == "container"),
            "Already stopped"
        );
        ensure!(
            !matches!(request.operation, Operation::Withdraw) || s.withdrawal_generation == 0,
            "Withdrawal is already terminal"
        );
    }
    ensure!(
        emergency || s.pending.is_none(),
        "Interrupted operation requires stop or withdrawal"
    );
    ensure!(emergency || now()? >= s.last_time, "Clock moved backwards");
    let audit_manifest = p.manifest.canonical()?;
    let audit_operation = match request.operation {
        Operation::Consent => "Consent",
        Operation::Start => "Start",
        Operation::Stop => "Stop",
        Operation::Withdraw => "Withdraw",
        _ => unreachable!(),
    };
    if emergency {
        crate::runtime_audit::restrictive(&root, &audit_manifest, audit_operation, "Prepared");
    } else {
        crate::runtime_audit::record(&root, &audit_manifest, audit_operation, "Prepared")?;
    }
    s.generation = s
        .generation
        .checked_add(1)
        .context("Generation exhausted")?;
    s.pending = Some(operation_id.into());
    s.last_time = s.last_time.max(now()?);
    s.failure_code = None;
    s.receipts.insert(operation_id.into(), Receipt {
        request_digest: digest.clone(),
        result: json!({"ok":false,"generation":s.generation,"status":"Recovering","failureCode":"InterruptedOperation"}),
    });
    compact_receipts(&mut s.receipts, s.pending.as_deref());
    if let Err(error) = save(&root, &s) {
        if emergency {
            let _ = containers::stop(&root, &p, &mut s);
        }
        return Err(error.context("Operation identity could not be persisted"));
    }
    if matches!(request.operation, Operation::Withdraw) {
        if s.withdrawal_generation == 0 {
            if let Err(error) = publish_public(&root.join("Authorization/Withdrawal.json"), b"1") {
                let _ = containers::stop(&root, &p, &mut s);
                return Err(error
                    .context("Withdrawal could not be persisted; owned workload stop attempted"));
            }
            s.withdrawal_generation = 1;
        }
        s.status = "Withdrawn".into();
        s.accepted_consent = None;
    } else if matches!(request.operation, Operation::Start) {
        s.status = "Starting".into();
    }
    if let Err(error) = save(&root, &s) {
        if emergency {
            let _ = containers::stop(&root, &p, &mut s);
        }
        return Err(error.context("Lifecycle intent could not be persisted"));
    }
    let outcome: Result<()> = match request.operation {
        Operation::Consent => (|| {
            ensure!(
                s.withdrawal_generation == 0 && s.resources.is_empty(),
                "Consent requires an unstarted fresh deployment"
            );
            ensure!(now()? < p.expires, "Profile expired");
            let signed =
                crate::trust_wire::sign_envelope(&consent(&p, &s)?, &key(&root, "Operator")?)?;
            super::files::save(
                &root.join("ConsentRecord.json"),
                &json!({"digest":hex::encode(crate::trust_wire::digest(&consent(&p, &s)?))}),
            )?;
            let path = root.join("Authorization/Consent.cbor");
            if path.exists() {
                ensure!(
                    public_read(&path, MAXIMUM)? == signed,
                    "Retained consent signature differs"
                );
            } else {
                publish_public(&path, &signed)?;
            }
            s.accepted_consent = Some(hex::encode(crate::trust_wire::digest(&consent(&p, &s)?)));
            s.status = "Stopped".into();
            Ok(())
        })(),
        Operation::Start => (|| {
            retain_signer_generation(
                &root,
                request
                    .minimum_signer_generation
                    .context("Signer floor required")?,
            )?;
            start(&root, &p, &mut s)
        })(),
        Operation::Stop => stop(&root, &p, &mut s).map(|_| {
            if s.withdrawal_generation == 0 {
                s.status = "Stopped".into();
            }
        }),
        Operation::Withdraw => (|| {
            stop(&root, &p, &mut s)?;
            containers::withdraw_networks(&root, &p, &mut s)
        })(),
        _ => unreachable!(),
    };
    let mut result = match outcome {
        Ok(()) => {
            json!({"ok":true,"operation":request.operation,"generation":s.generation,"profileDigest":s.profile_digest,"status":s.status,"minimumSignerGeneration":signer_generation(&root)?})
        }
        Err(error) => {
            let cleanup = if matches!(request.operation, Operation::Start) {
                // Retain bounded evidence before stopping and removing the exact workload.
                // Diagnostics must not prevent fail-closed cleanup.
                let _ = containers::authority_failure(&root, &p, &s);
                containers::stop(&root, &p, &mut s).is_ok()
            } else {
                true
            };
            if s.withdrawal_generation == 0 {
                s.status = "Failed".into();
            }
            s.failure_code = Some(
                if cleanup {
                    "OperationFailed"
                } else {
                    "ResourceRecoveryRequired"
                }
                .into(),
            );
            s.pending = None;
            s.receipts.insert(operation_id.into(),Receipt{request_digest:digest,result:json!({"ok":false,"generation":s.generation,"status":s.status,"failureCode":s.failure_code})});
            save(&root, &s)?;
            crate::runtime_audit::restrictive(&root, &audit_manifest, audit_operation, "Failed");
            return Err(
                error.context("Runtime operation failed; state retained for stop or withdrawal")
            );
        }
    };
    save(&root, &s)?;
    if emergency {
        result["auditRecorded"] = json!(crate::runtime_audit::restrictive(
            &root,
            &audit_manifest,
            audit_operation,
            "Committed"
        ));
    } else if let Err(error) =
        crate::runtime_audit::record(&root, &audit_manifest, audit_operation, "Committed")
    {
        if matches!(request.operation, Operation::Start) {
            let _ = stop(&root, &p, &mut s);
        }
        s.pending = None;
        s.status = "Failed".into();
        s.failure_code = Some("AuditUnavailable".into());
        s.receipts.insert(operation_id.into(), Receipt { request_digest: digest,
            result: json!({"ok":false,"generation":s.generation,"status":s.status,"failureCode":s.failure_code}) });
        save(&root, &s)?;
        return Err(error.context("Runtime outcome retained; audit completion failed"));
    } else {
        result["auditRecorded"] = json!(true);
    }
    s.pending = None;
    s.receipts.insert(
        operation_id.into(),
        Receipt {
            request_digest: digest,
            result: result.clone(),
        },
    );
    save(&root, &s)?;
    Ok(result)
}
pub fn session_stop(root: &Path) -> Result<()> {
    let root = super::files::root(root)?;
    let _lock = lock(&root)?;
    let (p, mut s) = load(&root)?;
    crate::runtime_audit::restrictive(&root, &p.manifest.canonical()?, "Stop", "Prepared");
    stop(&root, &p, &mut s)?;
    crate::runtime_audit::restrictive(&root, &p.manifest.canonical()?, "Stop", "Committed");
    if s.withdrawal_generation == 0 {
        s.status = "Stopped".into();
    }
    s.generation = s
        .generation
        .checked_add(1)
        .context("Generation exhausted")?;
    save(&root, &s)
}

/// Local veto persistence precedes publication; cleanup failure must not hide a restriction.
pub fn withdrawal_receipt(root: &Path) -> Result<Value> {
    use crate::trust_wire::{self as wire, Value as V};
    let root = super::files::root(root)?;
    let _lock = lock(&root)?;
    if root.join("Transition.json").try_exists()? {
        return super::transition::withdrawal_receipt(&root, false, None);
    }
    let (profile, state) = load(&root)?;
    let generation = withdrawal(&root)?;
    ensure!(
        generation > 0 && generation == state.withdrawal_generation,
        "Persist local withdrawal before requesting a publication receipt"
    );
    let manifest = profile.manifest.canonical()?;
    let cleanup = state.pending.is_none()
        && !state
            .resources
            .iter()
            .any(|r| matches!(r.kind.as_str(), "container" | "network"));
    let bytes = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("HyperNetLocalWithdrawal".into()),
        V::Bytes(manifest.network.to_vec()),
        V::Bytes(manifest.incarnation.to_vec()),
        V::Bytes(manifest.deployment.to_vec()),
        V::Bytes(manifest.operator.to_vec()),
        V::Bytes(manifest.operational_digest()?.to_vec()),
        V::Uint(generation),
        V::Bool(cleanup),
    ]))?;
    let signed = wire::sign_envelope(&bytes, &key(&root, "Operator")?)?;
    let path = root.join("Authorization/WithdrawalReceipt.cbor");
    publish_public(&path, &signed)?;
    Ok(
        json!({"withdrawalReceipt":path,"withdrawalGeneration":generation,"cleanupComplete":cleanup,"networkPublished":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_receipts_compact_without_evicting_pending_operation() {
        let mut receipts = std::collections::BTreeMap::new();
        for generation in 1..=200u64 {
            receipts.insert(
                generation.to_string(),
                Receipt {
                    request_digest: "digest".into(),
                    result: json!({"generation":generation}),
                },
            );
            compact_receipts(&mut receipts, Some("1"));
        }
        assert_eq!(receipts.len(), 64);
        assert!(receipts.contains_key("1"));
        assert!(receipts.contains_key("200"));
        assert!(!receipts.contains_key("136"));
    }
}
