// SPDX-License-Identifier: MIT
use super::model::save;
use super::{files::*, model::*};
use anyhow::{Result, ensure};
use clap::Args;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Args)]
pub struct Setup {
    #[arg(long)]
    pub directory: PathBuf,
    #[arg(long)]
    pub image: String,
    #[arg(long)]
    pub etcd: PathBuf,
    #[arg(long)]
    pub etcdctl: PathBuf,
    #[arg(long)]
    pub bind: std::net::Ipv4Addr,
    #[arg(long)]
    pub port: u16,
    #[arg(long)]
    pub voter_port_base: u16,
    #[arg(long)]
    pub subnet: std::net::Ipv4Addr,
    #[arg(long, default_value_t = 3600)]
    pub lifetime_seconds: u64,
    #[arg(long,value_parser=["Session"])]
    pub session_policy: String,
}
fn issuance(root: &Path, args: &[String]) -> Result<()> {
    run(Path::new("/usr/bin/openssl"), args, 15)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
fn ca(pki: &Path, name: &str) -> Result<()> {
    issuance(
        pki,
        &strings(&[
            "req",
            "-config",
            "/dev/null",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-days",
            "8",
            "-keyout",
            pki.join(format!("{name}Key.pem")).to_str().unwrap(),
            "-out",
            pki.join(format!("{name}.pem")).to_str().unwrap(),
            "-subj",
            &format!("/CN={name}"),
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]),
    )
}
fn certificate(
    pki: &Path,
    name: &str,
    issuer: &str,
    cn: &str,
    san: &str,
    usage: &str,
) -> Result<()> {
    issuance(
        pki,
        &strings(&[
            "req",
            "-config",
            "/dev/null",
            "-new",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            pki.join(format!("{name}Key.pem")).to_str().unwrap(),
            "-out",
            pki.join(format!("{name}.csr")).to_str().unwrap(),
            "-subj",
            &format!("/CN={cn}"),
        ]),
    )?;
    let extension = pki.join(format!("{name}Extensions.txt"));
    let san = if san.is_empty() {
        String::new()
    } else {
        format!("subjectAltName={san}\n")
    };
    create(&extension,format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\n{san}").as_bytes())?;
    issuance(
        pki,
        &strings(&[
            "x509",
            "-req",
            "-in",
            pki.join(format!("{name}.csr")).to_str().unwrap(),
            "-CA",
            pki.join(format!("{issuer}.pem")).to_str().unwrap(),
            "-CAkey",
            pki.join(format!("{issuer}Key.pem")).to_str().unwrap(),
            "-set_serial",
            &format!("0x{}", &random_id()[..30]),
            "-days",
            "8",
            "-extfile",
            extension.to_str().unwrap(),
            "-out",
            pki.join(format!("{name}.pem")).to_str().unwrap(),
        ]),
    )
}
fn identity(root: &Path, name: &str) -> Result<String> {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    create(
        &root.join("Keys").join(format!("{name}.key")),
        &key.to_bytes(),
    )?;
    Ok(hex::encode(key.verifying_key().as_bytes()))
}
fn copy(root: &Path, name: &str, destination: &Path, new_name: &str) -> Result<()> {
    create(
        &destination.join(new_name),
        &read(&root.join("Pki").join(name), 65536)?,
    )
}
fn remember(
    root: &Path,
    relative: &str,
    artifacts: &mut std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remember(
                root,
                &format!("{relative}/{}", entry.file_name().to_str().unwrap()),
                artifacts,
            )?;
        } else {
            let name = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .unwrap()
                .to_string();
            artifacts.insert(name, hex_digest(&read(&entry.path(), MAXIMUM)?));
        }
    }
    Ok(())
}
pub fn setup(args: Setup) -> Result<serde_json::Value> {
    for path in [&args.directory, &args.etcd, &args.etcdctl] {
        safe_path(path)?;
    }
    ensure!(
        args.directory.as_os_str().len() <= 88,
        "Runtime path is too long for its management socket"
    );
    ensure!(unsafe { libc::geteuid() } != 0, "Use a non-root operator");
    ensure!(
        (30..=604800).contains(&args.lifetime_seconds),
        "Lifetime must be thirty seconds through seven days"
    );
    ensure!(
        args.directory.is_absolute() && !args.directory.exists(),
        "Select a new absolute runtime directory"
    );
    let parent = args
        .directory
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing parent"))?;
    private_dir(parent)?;
    ancestors(parent)?;
    ensure!(
        parent.canonicalize()? == parent,
        "Parent cannot contain symbolic links"
    );
    let current = std::env::current_exe()?.canonicalize()?;
    let mut profile = Profile {
        version: 1,
        deployment: random_id(),
        network: random_id(),
        incarnation: random_id(),
        software_digest: executable(&current)?,
        image: args.image,
        etcd: args.etcd.clone(),
        etcd_digest: executable(&args.etcd)?,
        etcdctl: args.etcdctl.clone(),
        etcdctl_digest: executable(&args.etcdctl)?,
        bind: args.bind,
        port: args.port,
        voter_port_base: args.voter_port_base,
        subnet: args.subnet,
        expires: now()?
            .checked_add(args.lifetime_seconds)
            .ok_or_else(|| anyhow::anyhow!("Time overflow"))?,
        created: now()?,
        operator: random_id(),
        administrator: random_id(),
        host: random_id(),
        session_policy: args.session_policy,
        selinux_relabel: selinux_enabled()?,
        root: args.directory.clone(),
        artifacts: Default::default(),
    };
    profile.validate(&args.directory)?;
    ensure!(
        profile.subnet.octets()[2] < 254,
        "Subnet needs an adjacent private /24"
    );
    directory(&args.directory)?;
    let root = &args.directory;
    reserve(root)?;
    for name in ["Keys", "Pki", "Work", "AuthorityState", "Diagnostics"] {
        directory(&root.join(name))?;
    }
    profile.operator = identity(root, "Operator")?;
    profile.administrator = identity(root, "Administrator")?;
    profile.host = identity(root, "Host")?;
    create(
        &root.join("Keys/Invitation.secret"),
        &rand::random::<[u8; 32]>(),
    )?;
    let pki = root.join("Pki");
    for name in ["NetworkCa", "HostCa", "VoterCa", "PeerCa"] {
        ca(&pki, name)?;
    }
    certificate(&pki, "Root", "VoterCa", "root", "", "clientAuth")?;
    certificate(
        &pki,
        "BrokerStore",
        "VoterCa",
        "HyperNetBroker",
        "",
        "clientAuth",
    )?;
    certificate(
        &pki,
        "Authority",
        "NetworkCa",
        "HyperNetAuthority",
        &format!("DNS:HyperNetAuthority,IP:{}", profile.bind),
        "serverAuth",
    )?;
    certificate(&pki, "Host", "HostCa", "HyperNetHost", "", "clientAuth")?;
    for i in 1..=3 {
        let name = format!("Voter{i}");
        certificate(
            &pki,
            &name,
            "VoterCa",
            &name,
            &format!("DNS:HyperNetVoter,IP:127.0.0.1,IP:{}", profile.ip(10 + i)),
            "serverAuth",
        )?;
        certificate(
            &pki,
            &format!("{name}Peer"),
            "PeerCa",
            "HyperNetVoter",
            &format!("IP:{}", profile.ip(10 + i)),
            "serverAuth,clientAuth",
        )?;
        let dir = root.join("Work").join(&name);
        directory(&dir)?;
        directory(&dir.join("Config"))?;
        directory(&dir.join("State"))?;
        for file in [
            format!("{name}.pem"),
            format!("{name}Key.pem"),
            format!("{name}Peer.pem"),
            format!("{name}PeerKey.pem"),
            "VoterCa.pem".into(),
            "PeerCa.pem".into(),
        ] {
            copy(root, &file, &dir.join("Config"), &file)?;
        }
    }
    let authority = root.join("Work/Authority");
    directory(&authority)?;
    for (from, to) in [
        ("Authority.pem", "AuthorityCertificate.pem"),
        ("AuthorityKey.pem", "AuthorityKey.pem"),
        ("HostCa.pem", "HostingCa.pem"),
        ("VoterCa.pem", "VoterCa.pem"),
        ("BrokerStore.pem", "BrokerCertificate.pem"),
        ("BrokerStoreKey.pem", "BrokerKey.pem"),
    ] {
        copy(root, from, &authority, to)?;
    }
    let config = json!({"network":profile.network,"listen":"0.0.0.0:8443","stateDirectory":"/State","certificate":"/Config/AuthorityCertificate.pem","privateKey":"/Config/AuthorityKey.pem","clientCa":"/Config/HostingCa.pem","etcdEndpoints":(1..=3).map(|i|format!("https://{}:2379",profile.ip(10+i))).collect::<Vec<_>>(),"etcdCa":"/Config/VoterCa.pem","etcdCertificate":"/Config/BrokerCertificate.pem","etcdKey":"/Config/BrokerKey.pem","etcdServerName":"HyperNetVoter"});
    super::files::save(&authority.join("Authority.json"), &config)?;
    let mut initial = config;
    initial["stateDirectory"] = json!(root.join("AuthorityState"));
    initial["etcdEndpoints"] = json!(
        (0..3)
            .map(|i| format!("https://127.0.0.1:{}", profile.voter_port_base + i))
            .collect::<Vec<_>>()
    );
    for (field, file) in [
        ("certificate", "Authority.pem"),
        ("privateKey", "AuthorityKey.pem"),
        ("clientCa", "HostCa.pem"),
        ("etcdCa", "VoterCa.pem"),
        ("etcdCertificate", "BrokerStore.pem"),
        ("etcdKey", "BrokerStoreKey.pem"),
    ] {
        initial[field] = json!(pki.join(file));
    }
    super::files::save(&root.join("Bootstrap.json"), &initial)?;
    let host = root.join("Work/Host");
    directory(&host)?;
    for (from, to) in [
        ("NetworkCa.pem", "Ca.pem"),
        ("Host.pem", "Client.pem"),
        ("HostKey.pem", "ClientKey.pem"),
    ] {
        copy(root, from, &host, to)?;
    }
    let host_key = key(root, "Host")?;
    super::files::save(
        &host.join("Identity.json"),
        &json!({"secretKey":hex::encode(host_key.to_bytes()),"publicKey":profile.host}),
    )?;
    let octets = profile.subnet.octets();
    let gate = format!("{}.{}.{}.3:8443", octets[0], octets[1], octets[2] + 1);
    super::files::save(
        &host.join("Host.json"),
        &json!({"network":profile.network,"endpoint":"https://HyperNetAuthority:8443","stateDirectory":"/State","identity":"/Config/Identity.json","caCertificate":"/Config/Ca.pem","clientCertificate":"/Config/Client.pem","clientKey":"/Config/ClientKey.pem","consentFile":"/Config/Consent.json","relayAddress":gate}),
    )?;
    let gate_dir = root.join("Work/Gate");
    directory(&gate_dir)?;
    super::files::save(
        &gate_dir.join("Gate.json"),
        &json!({"listen":gate,"destination":format!("{}:8443",profile.ip(20)),"allowedSource":format!("{}.{}.{}.2",octets[0],octets[1],octets[2]+1),"expires":profile.expires,"bytesPerSecond":1048576,"maximumConnections":16,"maximumConnectionBytes":16777216}),
    )?;
    let upstream = fs::read("/usr/share/containers/seccomp.json")?;
    ensure!(upstream.len() <= MAXIMUM, "Seccomp profile exceeds bound");
    let mut seccomp: serde_json::Value = serde_json::from_slice(&upstream)?;
    ensure!(
        seccomp["defaultAction"] == "SCMP_ACT_ERRNO",
        "Deny-by-default seccomp required"
    );
    let calls = seccomp["syscalls"]
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("Invalid seccomp profile"))?;
    for call in calls.iter_mut() {
        call["names"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("Invalid seccomp names"))?
            .retain(|n| n != "socket" && n != "socketcall");
    }
    calls.retain(|c| !c["names"].as_array().unwrap().is_empty());
    for family in [1, 2, 10] {
        for protocol in [0, 6] {
            if family == 1 && protocol != 0 {
                continue;
            }
            calls.push(json!({"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":family,"op":"SCMP_CMP_EQ"},{"index":1,"value":15,"valueTwo":1,"op":"SCMP_CMP_MASKED_EQ"},{"index":2,"value":protocol,"op":"SCMP_CMP_EQ"}]}));
        }
    }
    super::files::save(&root.join("Seccomp.json"), &seccomp)?;
    remember(root, "Pki", &mut profile.artifacts)?;
    remember(root, "Keys", &mut profile.artifacts)?;
    remember(root, "Work", &mut profile.artifacts)?;
    for name in ["Bootstrap.json", "Seccomp.json"] {
        profile
            .artifacts
            .insert(name.into(), hex_digest(&read(&root.join(name), MAXIMUM)?));
    }
    super::files::save(&root.join("Profile.json"), &profile)?;
    create(&root.join("DesiredProfile.cbor"), &desired(&profile)?)?;
    super::files::save(&root.join("Withdrawal.json"), &0u64)?;
    super::files::save(&root.join("Generation.json"), &1u64)?;
    let state = State::new(&profile)?;
    save(root, &state)?;
    Ok(
        json!({"status":"AwaitingConsent","generation":state.generation,"profileDigest":state.profile_digest,"deployment":profile.deployment,"expires":profile.expires,"backend":"TrustedCrashFault","networkServing":false,"byzantineQualified":false}),
    )
}
