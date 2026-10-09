// SPDX-License-Identifier: MIT
use super::model::save;
use super::{containers, files::*, model::*};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

fn await_condition(mut f: impl FnMut() -> Result<()>, seconds: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match f() {
            Ok(()) => return Ok(()),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}
fn envelope(
    p: &Profile,
    key: &SigningKey,
    command: crate::types::Command,
) -> Result<crate::types::Envelope> {
    let request = crate::types::Request {
        version: 1,
        request_id: hex::encode(rand::random::<[u8; 16]>()),
        issued_at: now()?,
        command,
    };
    let payload = serde_json::to_vec(&request)?;
    let mut message = crate::types::DOMAIN.to_vec();
    message.extend_from_slice(&hex::decode(&p.network)?);
    message.extend_from_slice(key.verifying_key().as_bytes());
    message.extend_from_slice(&payload);
    Ok(crate::types::Envelope {
        network: p.network.clone(),
        public_key: hex::encode(key.verifying_key().as_bytes()),
        payload: URL_SAFE_NO_PAD.encode(&payload),
        signature: hex::encode(key.sign(&message).to_bytes()),
    })
}
pub fn authority_request(
    root: &Path,
    p: &Profile,
    identity: &str,
    command: crate::types::Command,
) -> Result<Value> {
    let envelope = envelope(p, &key(root, identity)?, command)?;
    let ca = reqwest::Certificate::from_pem(&read(&root.join("Pki/NetworkCa.pem"), 65536)?)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(
            "hypernetauthority",
            std::net::SocketAddr::new(p.bind.into(), p.port),
        )
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .build()?;
    crate::runtime()?.block_on(async {
        let mut response = client
            .post(format!("https://HyperNetAuthority:{}/V1/Command", p.port))
            .json(&envelope)
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= MAXIMUM,
                "Authority response exceeds bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        let reply: crate::types::Reply = serde_json::from_slice(&bytes)?;
        ensure!(reply.ok, "Current authority refused request");
        Ok(reply.result)
    })
}
fn registration_stage(root: &Path, state: &mut State, next: usize) -> Result<()> {
    const STAGES: [&str; 5] = ["Pending", "Invited", "Redeemed", "Consented", "Complete"];
    let current = STAGES
        .iter()
        .position(|value| *value == state.registration_stage)
        .context("Invalid registration stage")?;
    if current < next {
        state.registration_stage = STAGES[next].into();
        save(root, state)?;
    }
    Ok(())
}
fn register(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    let member = json!({"grants":3,"expires":p.expires,"revoked":false});
    if !s.host_registered {
        let mut secret_bytes = read(&root.join("Keys/Invitation.secret"), 32)?;
        ensure!(
            secret_bytes.len() == 32,
            "Invalid retained invitation secret"
        );
        let verifier = hex_digest(&secret_bytes);
        let secret = hex::encode(&secret_bytes);
        zeroize::Zeroize::zeroize(&mut secret_bytes);
        authority_request(
            root,
            p,
            "Administrator",
            crate::types::Command::Invite {
                verifier,
                device_key: p.host.clone(),
                grants: 3,
                expires: p.expires,
            },
        )?;
        registration_stage(root, s, 1)?;
        let redeemed =
            authority_request(root, p, "Host", crate::types::Command::Redeem { secret })?;
        ensure!(
            redeemed["deviceKey"] == p.host && redeemed["member"] == member,
            "Retained host membership differs; no grant was restored"
        );
        registration_stage(root, s, 2)?;
    }
    let der = run(
        Path::new("/usr/bin/openssl"),
        &strings(&[
            "x509",
            "-in",
            root.join("Pki/Host.pem").to_str().unwrap(),
            "-outform",
            "DER",
        ]),
        10,
    )?;
    let document = read(&root.join("HostConsent.json"), 16384)?;
    let consent = crate::types::Consent {
        profile: hex_digest(&document),
        grants: 2,
        expires: p.expires,
        certificate: hex_digest(&der),
        active: true,
        document: URL_SAFE_NO_PAD.encode(document),
    };
    let status = authority_request(
        root,
        p,
        "Administrator",
        crate::types::Command::Status {
            device_key: Some(p.host.clone()),
        },
    )?;
    ensure!(
        status["deviceKey"] == p.host && status["member"] == member,
        "Registered host membership differs; no grant was restored"
    );
    let expected = serde_json::to_value(&consent)?;
    if status["consent"].is_null() {
        ensure!(
            !s.host_registered
                && !matches!(s.registration_stage.as_str(), "Consented" | "Complete"),
            "Recorded consent is missing; no consent was restored"
        );
        let reply = authority_request(
            root,
            p,
            "Host",
            crate::types::Command::Consent {
                profile: consent.profile,
                grants: consent.grants,
                expires: consent.expires,
                certificate: consent.certificate,
                document: consent.document,
            },
        )?;
        ensure!(
            reply["deviceKey"] == p.host && reply["consent"] == expected,
            "Consent registration differs from the local profile"
        );
    } else {
        ensure!(
            status["consent"] == expected,
            "Retained consent changed or was withdrawn; no consent was restored"
        );
    }
    registration_stage(root, s, 3)?;
    s.host_registered = true;
    registration_stage(root, s, 4)?;
    save(root, s)
}
pub fn current_health(root: &Path, p: &Profile, s: &State) -> Result<Value> {
    ensure!(now()? >= s.last_time, "Clock moved backwards");
    verify_consent(root, p, s)?;
    ensure!(
        containers::processes(p, s)?,
        "A required process is not running"
    );
    let authority = authority_request(
        root,
        p,
        "Administrator",
        crate::types::Command::Status { device_key: None },
    )?;
    let host = containers::host_status(p, s)?;
    Ok(json!({"authority":authority,"host":host}))
}
fn create_host_consent(root: &Path, p: &Profile) -> Result<()> {
    let value = crate::host::Consent {
        version: 3,
        network: p.network.clone(),
        device_key: p.host.clone(),
        grants: 2,
        expires: p.expires,
        memory_bytes: 134217728,
        pids: 32,
        cpu_quota: 50000,
        cpu_period: 100000,
        state_bytes: 8388608,
        authority_endpoint: "https://HyperNetAuthority:8443".into(),
        authority_address: format!("{}:8443", p.ip(20)).parse()?,
        services: vec!["Pages".into()],
        namespaces: vec!["Public".into()],
        page_cache_bytes: 1048576,
        page_media_cache_bytes: 0,
    };
    let payload = serde_json::to_vec(&value)?;
    let mut message = b"HyperNet/Consent/3\0".to_vec();
    message.extend_from_slice(&payload);
    let signed = json!({"payload":URL_SAFE_NO_PAD.encode(payload),"signature":hex::encode(key(root,"Host")?.sign(&message).to_bytes())});
    let path = root.join("HostConsent.json");
    if path.exists() {
        ensure!(
            read(&path, 16384)? == serde_json::to_vec(&signed)?,
            "Retained hosting consent differs"
        );
        Ok(())
    } else {
        super::files::save(&path, &signed)
    }
}
fn check_artifacts(root: &Path, p: &Profile) -> Result<()> {
    ensure!(
        executable(&std::env::current_exe()?.canonicalize()?)? == p.software_digest
            && executable(&p.etcd)? == p.etcd_digest
            && executable(&p.etcdctl)? == p.etcdctl_digest,
        "Consented software changed"
    );
    for (relative, digest) in &p.artifacts {
        let path = Path::new(relative);
        ensure!(
            !path.is_absolute()
                && path
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "Invalid artifact handle"
        );
        ensure!(
            hex_digest(&read(&root.join(path), MAXIMUM)?) == *digest,
            "Generated configuration changed"
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
    ensure!(
        capacity(root)? >= 536870912,
        "At least 512 MiB of available runtime filesystem capacity is required"
    );
    verify_consent(root, p, s)?;
    ensure!(
        s.withdrawal_generation == 0,
        "Withdrawn runtime requires new setup and consent"
    );
    check_artifacts(root, p)?;
    ensure!(
        !s.resources.iter().any(|r| r.kind == "container"),
        "Stop recorded containers before starting"
    );
    containers::network(root, p, s, false)?;
    containers::network(root, p, s, true)?;
    containers::prepare(root, p)?;
    super::bootstrap::prepare_authority(root, s)?;
    containers::voters(root, p, s)?;
    super::bootstrap::run(root, p, s)?;
    containers::authority(root, p, s)?;
    await_condition(
        || {
            authority_request(
                root,
                p,
                "Administrator",
                crate::types::Command::Status { device_key: None },
            )
            .map(|_| ())
        },
        15,
    )?;
    register(root, p, s)?;
    containers::host(root, p, s)?;
    await_condition(|| current_health(root, p, s).map(|_| ()), 15)?;
    s.status = "Ready".into();
    Ok(())
}
fn preview(p: &Profile, s: &State) -> Result<Value> {
    Ok(
        json!({"version":1,"deployment":p.deployment,"network":p.network,"profileDigest":s.profile_digest,"generation":s.generation,"status":s.status,"backend":"TrustedCrashFault","byzantineQualified":false,"policy":{"participation":"InvitationOnly","pages":"HostReadable","readerRouting":"Unavailable","recovery":"ExistingTrustedAuthorityOnly"},"roles":["Authority","PageStore"],"endpoints":{"authority":format!("{}:{}",p.bind,p.port),"voterManagement":(0..3).map(|i|format!("127.0.0.1:{}",p.voter_port_base+i)).collect::<Vec<_>>()},"resources":{"voters":3,"containers":6,"voterBackendBytesEach":67108864,"voterMemoryBytesEach":536870912,"authorityMemoryBytes":536870912,"hostMemoryBytes":134217728,"gateMemoryBytes":134217728,"pageCacheBytes":1048576,"durableStorage":"Dedicated runtime directories; underlying filesystem capacity required","cpuPeriod":100000,"voterCpuQuotaEach":100000,"authorityCpuQuota":100000,"hostCpuQuota":50000,"gateCpuQuota":50000},"expires":p.expires,"sessionPolicy":p.session_policy,"selinuxRelabel":p.selinux_relabel,"bootEnabled":false,"logoutBehaviour":"Graceful supervisor exit stops owned containers; abrupt loss retains consent timeout","delta":if s.accepted_consent.is_none(){"All listed roles and resources require consent"}else{"No resource expansion"},"requirements":["Rootless Podman with delegated cgroup v2","Landlock ABI 6 and seccomp","Three trusted crash-fault voters; no Byzantine assurance","Sufficient dedicated filesystem space","Explicit live relay unavailable; no reader join"],"unsupported":["ByzantineAuthority","SealedPages","RelayJoin","Renew","Update","Restore","UnattendedBoot"]}),
    )
}
fn mutation_capacity(
    operation: &Operation,
    count: usize,
    stopped: bool,
    withdrawn: bool,
) -> Result<()> {
    match operation {
        Operation::Stop => ensure!(
            !stopped && count < 121,
            "No new stop is needed or the stop receipt reserve is exhausted"
        ),
        Operation::Withdraw => ensure!(
            !withdrawn && count < 122,
            "Withdrawal is already terminal or its receipt reserve is exhausted"
        ),
        _ => ensure!(
            count < 120,
            "Receipt capacity reached; stop or withdraw this deployment"
        ),
    }
    Ok(())
}
pub fn dispatch(root: &Path, request: Request) -> Result<Value> {
    let root = super::files::root(root)?;
    let _lock = lock(&root)?;
    let (p, mut s) = load(&root)?;
    match request.operation {
        Operation::Preview => return preview(&p, &s),
        Operation::Diagnose => {
            return Ok(
                json!({"deployment":p.deployment,"generation":s.generation,"recordedState":s.status,"resourceCount":s.resources.len(),"withdrawalGeneration":s.withdrawal_generation,"pendingOperation":s.pending.is_some(),"bootstrapStage":s.bootstrap_stage,"registrationStage":s.registration_stage,"failureCode":s.failure_code,"networkProbed":false,"exported":false}),
            );
        }
        Operation::Status => {
            let ready = matches!(s.status.as_str(), "Ready" | "Degraded")
                && current_health(&root, &p, &s).is_ok();
            return Ok(
                json!({"deployment":p.deployment,"generation":s.generation,"profileDigest":s.profile_digest,"status":if s.status=="Ready"&&!ready{"Degraded"}else{&s.status},"ready":ready,"backend":"TrustedCrashFault","byzantineQualified":false,"quorum":if ready{"ObservedAvailable"}else{"UnavailableOrNotChecked"},"clock":"LocalRollbackChecked; ByzantineClockBoundsUnqualified","consentValid":verify_consent(&root,&p,&s).is_ok(),"expires":p.expires,"withdrawalGeneration":s.withdrawal_generation,"resourceCount":s.resources.len(),"failureCode":s.failure_code,"pendingOperation":s.pending.is_some(),"readerRouting":"Unavailable","bootEnabled":false}),
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
    if let Some(receipt) = s.receipts.get(operation_id) {
        ensure!(
            receipt.request_digest == digest,
            "Operation ID was already used for different input"
        );
        return Ok(receipt.result.clone());
    }
    let veto = matches!(request.operation, Operation::Withdraw)
        && request
            .expected_generation
            .is_some_and(|generation| generation > 0 && generation <= s.generation);
    ensure!(
        (veto || request.expected_generation == Some(s.generation))
            && request.profile_digest.as_deref() == Some(&s.profile_digest),
        "Stale generation or changed desired profile"
    );
    let emergency = matches!(request.operation, Operation::Stop | Operation::Withdraw);
    mutation_capacity(
        &request.operation,
        s.receipts.len(),
        s.status == "Stopped" && !s.resources.iter().any(|r| r.kind == "container"),
        s.withdrawal_generation > 0,
    )?;
    ensure!(
        emergency || s.pending.is_none(),
        "Interrupted operation requires stop or withdrawal"
    );
    ensure!(emergency || now()? >= s.last_time, "Clock moved backwards");
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
    if let Err(error) = save(&root, &s) {
        if emergency {
            let _ = containers::stop(&root, &p, &mut s);
        }
        return Err(error.context("Operation identity could not be persisted"));
    }
    if matches!(request.operation, Operation::Withdraw) {
        s.withdrawal_generation = s
            .withdrawal_generation
            .checked_add(1)
            .context("Withdrawal counter exhausted")?;
        if let Err(error) =
            super::files::save(&root.join("Withdrawal.json"), &s.withdrawal_generation)
        {
            let _ = containers::stop(&root, &p, &mut s);
            return Err(
                error.context("Withdrawal could not be persisted; owned workload stop attempted")
            );
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
                &json!({"digest":hex_digest(&signed)}),
            )?;
            let path = root.join("Consent.cbor");
            if path.exists() {
                ensure!(
                    read(&path, MAXIMUM)? == signed,
                    "Retained consent signature differs"
                );
            } else {
                create(&path, &signed)?;
            }
            create_host_consent(&root, &p)?;
            s.accepted_consent = Some(hex_digest(&signed));
            s.status = "Stopped".into();
            Ok(())
        })(),
        Operation::Start => start(&root, &p, &mut s),
        Operation::Stop => containers::stop(&root, &p, &mut s).map(|_| {
            if s.withdrawal_generation == 0 {
                s.status = "Stopped".into();
            }
        }),
        Operation::Withdraw => containers::stop(&root, &p, &mut s),
        _ => unreachable!(),
    };
    let result = match outcome {
        Ok(()) => {
            json!({"ok":true,"operation":request.operation,"generation":s.generation,"profileDigest":s.profile_digest,"status":s.status})
        }
        Err(error) => {
            let cleanup = if matches!(request.operation, Operation::Start) {
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
            return Err(
                error.context("Runtime operation failed; state retained for stop or withdrawal")
            );
        }
    };
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
    containers::stop(&root, &p, &mut s)?;
    if s.withdrawal_generation == 0 {
        s.status = "Stopped".into();
    }
    s.generation = s
        .generation
        .checked_add(1)
        .context("Generation exhausted")?;
    save(&root, &s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_receipts_preserve_terminal_stop_and_withdrawal() {
        assert!(mutation_capacity(&Operation::Start, 120, false, false).is_err());
        assert!(mutation_capacity(&Operation::Stop, 120, false, false).is_ok());
        assert!(mutation_capacity(&Operation::Stop, 121, false, false).is_err());
        assert!(mutation_capacity(&Operation::Withdraw, 121, false, false).is_ok());
        assert!(mutation_capacity(&Operation::Withdraw, 122, false, false).is_err());
        assert!(mutation_capacity(&Operation::Stop, 1, true, false).is_err());
        assert!(mutation_capacity(&Operation::Withdraw, 1, false, true).is_err());
    }
}
