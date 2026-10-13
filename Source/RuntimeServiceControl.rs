// SPDX-License-Identifier: MIT
// Local consent, durable activation and owned-resource cleanup govern the foreground service session.
use super::*;
use std::sync::atomic::Ordering;

fn permitted(p: &Profile, s: &State) -> Result<()> {
    p.check_artifacts()?;
    ensure!(
        s.consented && !s.withdrawn,
        "explicit current local service consent required"
    );
    ensure!(
        files::public_read(&p.root.join("Authorization/Withdrawal.json"), 64)? == b"0",
        "local service consent is withdrawn"
    );
    let (local, signatures) = wire::envelope(
        &files::public_read(
            &p.root.join("Authorization/LocalConsent.cbor"),
            wire::MAXIMUM,
        )?,
        1,
    )?;
    ensure!(
        signatures.len() == 1
            && signatures[0].0 == p.manifest.operator
            && local
                == crate::runtime_service_authorization::local_consent(
                    &p.manifest,
                    p.role()?.role,
                    1,
                    &p.artifacts
                )?,
        "local service consent differs from the exact profile"
    );
    Ok(())
}
pub(super) fn exchange(p: &Profile, s: &mut State, packet: &Path, receipt: &Path) -> Result<Value> {
    permitted(p, s)?;
    let role = p.role()?.role;
    let (command, limit, status) = match role {
        1 => (
            "authority-content-exchange",
            crate::authority_domains::page::MEDIA_RECEIPT_LIMIT,
            "ContentReceiptExported",
        ),
        7 => (
            "authority-bridge-exchange",
            4 * wire::MAXIMUM,
            "BridgeResponseExported",
        ),
        2 => (
            "authority-media-exchange",
            crate::authority_domains::page::MEDIA_RECEIPT_LIMIT,
            "MediaReceiptExported",
        ),
        3 => (
            "authority-mail-exchange",
            crate::authority_domains::mail::RECEIPT_LIMIT,
            "MailReceiptExported",
        ),
        4 => (
            "authority-transfer-exchange",
            crate::authority_domains::transfer::RECEIPT_LIMIT,
            "TransferReceiptExported",
        ),
        _ => anyhow::bail!(
            "packet exchange requires a Content, Media, Mail, Transfer or Bridge service"
        ),
    };
    workload::recover(p, s, false)?;
    let resource = s
        .container
        .as_ref()
        .context("start the installed service before exchanging a packet")?;
    ensure!(
        workload::verify(p, resource)?["State"]["Running"] == true,
        "service is not running"
    );
    let input = zeroize::Zeroizing::new(files::read(packet, wire::MAXIMUM)?);
    let (reply, _) = files::capture_input(
        Path::new("/usr/bin/podman"),
        &files::strings(&[
            "exec",
            "--interactive",
            "--user=1000:1000",
            resource.id.as_deref().unwrap(),
            "/HyperNet",
            command,
        ]),
        if role == 7 {
            p.manifest
                .validity
                .1
                .checked_sub(
                    files::now()?
                        .checked_mul(1000)
                        .context("bridge wall time overflow")?,
                )
                .context("bridge consent expired")?
                .div_ceil(1000)
        } else {
            30
        },
        limit,
        16384,
        Some(&input),
    )?;
    if role == 7 {
        let value = wire::decode_state(&reply)?;
        let fields = value.list(5)?;
        ensure!(
            fields.len() >= 3
                && fields[0].uint()? == 201
                && fields[1].uint()? == 1
                && matches!(fields[2].text()?, "BridgeLease" | "BridgeSync"),
            "bridge response differs"
        );
        files::create(receipt, &reply)?;
    } else if matches!(role, 1 | 2) {
        let parsed = crate::authority_domains::page::MediaReceipt::parse(&reply)?;
        files::create(receipt, parsed.canonical())?;
    } else if role == 3 {
        let parsed = crate::authority_domains::mail::Receipt::parse(&reply)?;
        files::create(receipt, parsed.canonical())?;
    } else {
        let parsed = crate::authority_domains::transfer::Receipt::parse(&reply)?;
        files::create(receipt, parsed.canonical())?;
    }
    Ok(json!({"status":status,"receipt":receipt,"currentPermission":false}))
}
fn initialise(p: &Profile, s: &mut State) -> Result<()> {
    permitted(p, s)?;
    preparation::prepare(p)?;
    if !s.initialised {
        ensure!(
            files::capacity(&p.root)? >= p.manifest.volumes[0].storage_admission_bytes,
            "insufficient space for admitted service storage"
        );
        let _ = workload::finite(p, s, &files::strings(&["runtime-service-initialise"]), None)?;
        s.initialised = true;
        save(p, s)?;
    }
    Ok(())
}
pub(super) fn status(p: &Profile, s: &mut State) -> Result<Value> {
    workload::recover(p, s, false)?;
    workload::recover(p, s, true)?;
    let mut result = preview(p, s)?;
    let running = if let Some(r) = &s.container {
        containers::container_present(r.id.as_deref().context("service ID absent")?)?
            && workload::verify(p, r)?["State"]["Running"] == true
    } else {
        false
    };
    result["running"] = json!(running);
    result["serviceReadiness"] = json!("NotProbed");
    result["cleanupComplete"] = json!(
        s.container.is_none() && s.helper.is_none() && s.egress.is_none() && s.network.is_none()
    );
    Ok(result)
}
pub(super) fn stop(p: &Profile, s: &mut State) -> Result<()> {
    workload::remove(p, s, false)?;
    workload::remove(p, s, true)?;
    egress::remove(p, s)?;
    workload::remove_network(p, s)
}
pub(super) fn withdraw(p: &Profile, s: &mut State) -> Result<Value> {
    // Publish the veto before cleanup; a failed Podman operation cannot restore permission.
    files::publish_public(&p.root.join("Authorization/Withdrawal.json"), b"1")?;
    s.withdrawn = true;
    save(p, s)?;
    let cleanup = stop(p, s);
    let mut result = preview(p, s)?;
    result["cleanupComplete"] = json!(cleanup.is_ok());
    if let Err(e) = cleanup {
        result["cleanupError"] = json!(format!("{e:#}"));
    }
    result["networkPublished"] = json!(false);
    Ok(result)
}
pub(super) fn withdrawal_receipt(p: &Profile, s: &State, output: &Path) -> Result<Value> {
    ensure!(
        s.withdrawn
            && files::public_read(&p.root.join("Authorization/Withdrawal.json"), 64)? == b"1",
        "persist local withdrawal before exporting its assertion"
    );
    use wire::Value as V;
    let cleanup =
        s.container.is_none() && s.helper.is_none() && s.egress.is_none() && s.network.is_none();
    let payload = wire::encode(&V::Array(vec![
        V::Uint(200),
        V::Uint(1),
        V::Text("HyperNetLocalWithdrawal".into()),
        V::Bytes(p.manifest.network.to_vec()),
        V::Bytes(p.manifest.incarnation.to_vec()),
        V::Bytes(p.manifest.deployment.to_vec()),
        V::Bytes(p.manifest.operator.to_vec()),
        V::Bytes(wire::digest(&p.manifest.desired()?).to_vec()),
        V::Uint(1),
        V::Bool(cleanup),
    ]))?;
    let key = setup::operator(p)?;
    ensure!(
        key.verifying_key().to_bytes() == p.manifest.operator,
        "withdrawal signer differs from local operator"
    );
    files::create(output, &wire::sign_envelope(&payload, &key)?)?;
    Ok(
        json!({"withdrawalReceipt":output,"withdrawalGeneration":1,"cleanupComplete":cleanup,"networkPublished":false}),
    )
}
pub(super) fn activation_receipt(p: &Profile, s: &mut State, output: &Path) -> Result<Value> {
    ensure!(s.initialised, "service has no retained activation state");
    workload::recover(p, s, false)?;
    let bytes = if let Some(r) = &s.container {
        let v = workload::verify(p, r)?;
        ensure!(
            v["State"]["Running"] == true,
            "stop the exited service resource before exporting its retained report"
        );
        files::capture(
            Path::new("/usr/bin/podman"),
            &files::strings(&[
                "exec",
                "--user=1000:1000",
                r.id.as_deref().unwrap(),
                "/HyperNet",
                "runtime-service-receipt",
            ]),
            30,
            crate::authority_runtime_activation::RECEIPT_LIMIT,
            16384,
        )?
        .0
    } else {
        workload::finite(p, s, &files::strings(&["runtime-service-receipt"]), None)?
    };
    let receipt = crate::authority_runtime_activation::Receipt::parse(&bytes)?;
    files::create(output, receipt.canonical())?;
    Ok(json!({"activationReceipt":output,"currentPermission":false,"serviceReadiness":"NotProbed"}))
}
pub(super) fn epoch(p: &Profile, s: &mut State, input: &Path, args: &[String]) -> Result<Value> {
    permitted(p, s)?;
    ensure!(
        s.container.is_none(),
        "stop the service before an authority epoch transition"
    );
    initialise(p, s)?;
    Ok(serde_json::from_slice(&workload::finite(
        p,
        s,
        args,
        Some(input),
    )?)?)
}
fn requester_scope(role: u64, initialised: bool, resources: bool) -> Result<()> {
    ensure!(
        role == 7,
        "requester recovery is supported only for a Bridge service"
    );
    ensure!(
        initialised,
        "Bridge has no initialised requester state to recover"
    );
    ensure!(
        !resources,
        "stop the Bridge service before requester recovery"
    );
    Ok(())
}
pub(super) fn requester(
    p: &Profile,
    s: &mut State,
    expected: Option<&Path>,
    output: &Path,
) -> Result<Value> {
    use std::{fs, os::unix::fs::PermissionsExt};
    permitted(p, s)?;
    requester_scope(
        p.role()?.role,
        s.initialised,
        s.container.is_some() || s.network.is_some(),
    )?;
    preparation::prepare(p)?;
    files::safe_path(output)?;
    ensure!(
        output.is_absolute(),
        "requester metadata output requires an absolute private path"
    );
    files::private_dir(output.parent().context("metadata output parent absent")?)?;
    ensure!(
        !output.try_exists()?,
        "requester metadata output already exists; no file replaced"
    );
    let bytes = expected.map(|path| files::read(path, 486)).transpose()?;
    if let Some(bytes) = &bytes {
        let metadata = crate::authority_proof::OwnStreamMetadata::parse(bytes)?;
        ensure!(
            metadata.scope().network == p.manifest.network
                && metadata.scope().incarnation == p.manifest.incarnation
                && metadata.requester() == p.role()?.service_key,
            "expected metadata has another Bridge identity"
        );
    }
    let input = bytes
        .as_ref()
        .map(|_| p.root.join(format!("RequesterInput{}", files::random_id())));
    let reply = (|| {
        if let (Some(path), Some(bytes)) = (&input, &bytes) {
            files::directory(path)?;
            files::publish_public(&path.join("Expected.cbor"), bytes)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        }
        workload::finite(
            p,
            s,
            &files::strings(&[if expected.is_some() {
                "runtime-service-requester-fence"
            } else {
                "runtime-service-requester-status"
            }]),
            input.as_deref(),
        )
    })();
    let cleanup = (|| -> Result<()> {
        if let Some(path) = &input {
            if path.join("Expected.cbor").try_exists()? {
                fs::remove_file(path.join("Expected.cbor"))?;
            }
            if path.try_exists()? {
                fs::remove_dir(path)?;
            }
            fs::File::open(&p.root)?.sync_all()?;
        }
        Ok(())
    })();
    let reply = reply?;
    cleanup?;
    let metadata = crate::authority_proof::OwnStreamMetadata::parse(&reply)?;
    ensure!(
        metadata.scope().network == p.manifest.network
            && metadata.scope().incarnation == p.manifest.incarnation
            && metadata.requester() == p.role()?.service_key,
        "requester recovery returned another Bridge identity"
    );
    files::create(output, metadata.canonical())?;
    let state = metadata.state();
    Ok(json!({
        "status":if expected.is_some(){"BridgeRequesterFenced"}else{"BridgeRequesterStatusExported"},
        "metadata":output,"metadataDigest":hex::encode(wire::digest(metadata.canonical())),
        "generation":state.map(|v|v.generation),"retiredThrough":state.map(|v|v.retired_through),
        "completion":state.and_then(|v|v.completion.as_ref()).map(|c|json!({
            "sequence":c.sequence,"intent":hex::encode(c.intent),
            "disposition":format!("{:?}",c.disposition),"reason":c.reason,
            "resultDigest":hex::encode(c.result_digest)})),
        "currentPermission":false,"serviceReadiness":"Stopped",
        "unknownOutcomes":"Retained; fencing does not establish whether an old effect occurred"
    }))
}
pub(super) fn start(path: &Path, request: &Path) -> Result<Value> {
    let root = files::root(path)?;
    let _manager = files::manager_lock(&root.join("Manager"))?;
    super::super::STOP.store(false, Ordering::Relaxed);
    unsafe {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::signal(
                signal,
                super::super::terminate as *const () as libc::sighandler_t,
            );
        }
    }
    let outcome = (|| -> Result<()> {
        {
            let _lock = files::lock(&root)?;
            let (p, mut s) = load(&root)?;
            permitted(&p, &s)?;
            ensure!(
                s.container.is_none(),
                "stop the previous service resource before starting"
            );
            let bytes = files::read(request, wire::MAXIMUM)?;
            let parsed = crate::authority_runtime_activation::Request::parse(&bytes)?;
            ensure!(
                parsed.operation().recipient == p.role()?.service_key,
                "activation request has another recipient"
            );
            initialise(&p, &mut s)?;
            files::publish_public(&root.join("Authorization/ActivationRequest.cbor"), &bytes)?;
            let command = match p.role()?.role {
                5 => files::strings(&["private-route-service"]),
                7 => files::strings(&["authority-bridge-service"]),
                8 => files::strings(&["ssh-service", "--config", "/Config/ServiceConfig.json"]),
                1 => files::strings(&["authority-page-service"]),
                2 => files::strings(&["authority-media-service"]),
                4 => files::strings(&["authority-transfer-service"]),
                3 => files::strings(&["authority-mail-service"]),
                _ => unreachable!(),
            };
            egress::start(&p, &mut s)?;
            let id = workload::create(&p, &mut s, false, &command, None)?;
            files::podman(&files::strings(&["start", &id]))?;
            let r = s.container.as_ref().unwrap();
            workload::verify(&p, r)?;
            println!(
                "{}",
                json!({"status":"ServiceStarting","session":"Foreground","automaticBoot":false,"serviceReadiness":"NotProbed"})
            );
        }
        while !super::super::STOP.load(Ordering::Relaxed) {
            {
                let _lock = files::lock(&root)?;
                let (p, mut s) = load(&root)?;
                if s.withdrawn
                    || files::now()?
                        .checked_mul(1000)
                        .context("wall time overflow")?
                        >= p.manifest.validity.1
                {
                    break;
                }
                if let Some(egress) = &s.egress {
                    ensure!(
                        super::egress::verify(&p, egress)?["State"]["Running"] == true,
                        "consented egress helper stopped"
                    );
                }
                let Some(r) = &s.container else { break };
                let v = workload::verify(&p, r)?;
                if v["State"]["Running"] != true {
                    let exit = v["State"]["ExitCode"]
                        .as_i64()
                        .context("service exit status absent")?;
                    stop(&p, &mut s)?;
                    ensure!(exit == 0, "service exited with status {exit}");
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Ok(())
    })();
    let cleanup = (|| {
        let _lock = files::lock(&root)?;
        let (p, mut s) = load(&root)?;
        stop(&p, &mut s)
    })();
    outcome?;
    cleanup?;
    Ok(json!({"status":"Stopped"}))
}

#[cfg(test)]
mod requester_tests {
    use super::*;
    #[test]
    fn requester_recovery_requires_initialised_stopped_bridge() {
        assert!(requester_scope(7, true, false).is_ok());
        for role in [1, 2, 3, 4, 8] {
            assert!(requester_scope(role, true, false).is_err());
        }
        assert!(requester_scope(7, false, false).is_err());
        assert!(requester_scope(7, true, true).is_err());
    }
}
