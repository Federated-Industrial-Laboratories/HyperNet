// SPDX-License-Identifier: MIT
//! Prepare identities, certificates and replica inputs without starting a workload.
#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeProvisionTests.rs"]
mod tests;
#[path = "RuntimeProvisionTls.rs"]
mod tls;
use crate::{authority_files, runtime_management::files, trust_bootstrap};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Subcommand)]
pub enum Command {
    /// Create an offline Ed25519 certificate issuer; no role or network authority is granted.
    Issuer {
        #[command(flatten)]
        location: Location,
        #[arg(long, default_value_t = 365, value_parser = clap::value_parser!(u32).range(1..=3650))]
        days: u32,
    },
    /// Create a local role identity and a separately keyed transport request.
    Identity {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        address: Ipv4Addr,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1025..))]
        port: u16,
    },
    /// Issue an exact independently authenticated request under an explicitly pinned issuer.
    Issue {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        issuer_digest: String,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_digest: String,
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=365))]
        days: u32,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare the local monitor configuration; initialise and run it with authority-clock.
    Clock {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        export_directory: PathBuf,
        #[arg(long, default_value = "/usr/bin/chronyc")]
        chronyc: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Build authority setup inputs from accepted bootstrap and independently pinned public peers.
    Replica {
        #[command(flatten)]
        location: Location,
        #[arg(long)]
        identity_directory: PathBuf,
        #[arg(long)]
        bootstrap: PathBuf,
        #[arg(long)]
        bootstrap_digest: String,
        #[arg(long, num_args = 4, required = true)]
        peer: Vec<PathBuf>,
        #[arg(long, num_args = 4, required = true)]
        peer_digest: Vec<String>,
        #[arg(long)]
        clock_observation: PathBuf,
        #[arg(long)]
        monitor_key: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    version: u64,
    identity: String,
    transport: String,
    address: Ipv4Addr,
    port: u16,
    request_pem: String,
    signature: String,
}
impl Request {
    fn signed_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"purpose":"HyperNetTransportRequest1",
            "version":self.version,"identity":self.identity,"transport":self.transport,
            "address":self.address,"port":self.port,"requestPem":self.request_pem}),
        )?)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.port > 1024
                && !self.address.is_unspecified()
                && !self.address.is_multicast()
                && !self.address.is_broadcast(),
            "Invalid transport request endpoint"
        );
        let identity = trust_bootstrap::hex32(&self.identity)?;
        let transport = trust_bootstrap::hex32(&self.transport)?;
        ensure!(
            identity != transport && self.request_pem.len() <= 8192,
            "Invalid transport identity separation"
        );
        let signature = Signature::from_slice(&hex::decode(&self.signature)?)?;
        VerifyingKey::from_bytes(&identity)?.verify_strict(&self.signed_bytes()?, &signature)?;
        tls::verify_request(self.request_pem.as_bytes(), &transport)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Peer {
    request: Request,
    certificate_pem: String,
    authority_pem: String,
}
impl Peer {
    fn validate(&self, scratch: &Path) -> Result<Vec<u8>> {
        self.request.validate()?;
        let der = tls::certificate(self.certificate_pem.as_bytes())?;
        ensure!(
            crate::runtime_manifest::leaf_key(&der)?
                == trust_bootstrap::hex32(&self.request.transport)?,
            "Issued certificate differs from the requested transport key"
        );
        tls::verify_leaf(
            scratch,
            self.certificate_pem.as_bytes(),
            self.authority_pem.as_bytes(),
            &self.request.address.to_string(),
        )?;
        Ok(der)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    public_key: String,
    secret_key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}
fn identity(root: &Path) -> Result<SigningKey> {
    let bytes = Zeroizing::new(files::read(&root.join("Identity.json"), 4096)?);
    let value: Identity = serde_json::from_slice(&bytes)?;
    let seed = Zeroizing::new(trust_bootstrap::hex32(&value.secret_key)?);
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        hex::encode(key.verifying_key().to_bytes()) == value.public_key,
        "Local identity key pair differs"
    );
    Ok(key)
}
struct PreparedDirectory {
    root: PathBuf,
    destination: PathBuf,
}
impl PreparedDirectory {
    fn new(path: &Path) -> Result<Self> {
        files::safe_path(path)?;
        ensure!(
            path.is_absolute() && !path.try_exists()?,
            "A new absolute preparation directory is required"
        );
        let parent = files::root(path.parent().context("Preparation parent required")?)?;
        let root = parent.join(format!("Preparation{}", files::random_id()));
        files::directory(&root)?;
        Ok(Self {
            root,
            destination: path.to_owned(),
        })
    }
    fn commit(self) -> Result<PathBuf> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        fs::File::open(&self.root)?.sync_all()?;
        let source = CString::new(self.root.as_os_str().as_bytes())?;
        let target = CString::new(self.destination.as_os_str().as_bytes())?;
        ensure!(
            unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    source.as_ptr(),
                    libc::AT_FDCWD,
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "Cannot publish preparation directory: {}",
            std::io::Error::last_os_error()
        );
        fs::File::open(
            self.destination
                .parent()
                .context("Preparation parent required")?,
        )?
        .sync_all()?;
        Ok(self.destination.clone())
    }
}
impl Drop for PreparedDirectory {
    fn drop(&mut self) {
        // Only the unpublished private directory created by this operation is removed.
        if self.root.exists() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
fn publish(path: &Path, value: &impl Serialize) -> Result<String> {
    files::safe_path(path)?;
    files::root(path.parent().context("Private output parent required")?)?;
    let bytes = serde_json::to_vec(value)?;
    files::create(path, &bytes)?;
    Ok(files::hex_digest(&bytes))
}
fn issuer(directory: &Path, days: u32) -> Result<serde_json::Value> {
    let preparation = PreparedDirectory::new(directory)?;
    let root = preparation.root.clone();
    tls::key(&root)?;
    let pem = tls::command(
        &files::strings(&[
            "req",
            "-new",
            "-x509",
            "-batch",
            "-config",
            "/dev/null",
            "-key",
            &tls::text(&root.join("Transport.key"))?,
            "-subj",
            "/CN=HyperNet Transport Issuer",
            "-days",
            &days.to_string(),
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]),
        None,
    )?;
    tls::certificate(&pem)?;
    files::create(&root.join("Authority.pem"), &pem)?;
    let root = preparation.commit()?;
    Ok(
        json!({"status":"IssuerPrepared","certificate":root.join("Authority.pem"),
        "issuerDigest":files::hex_digest(&pem),"networkUsed":false}),
    )
}
fn prepare_identity(directory: &Path, address: Ipv4Addr, port: u16) -> Result<serde_json::Value> {
    ensure!(
        !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast(),
        "Explicit unicast address required"
    );
    let preparation = PreparedDirectory::new(directory)?;
    let root = preparation.root.clone();
    let signer = SigningKey::generate(&mut rand::rngs::OsRng);
    let value = Identity {
        public_key: hex::encode(signer.verifying_key().to_bytes()),
        secret_key: hex::encode(signer.to_bytes()),
    };
    let secret = Zeroizing::new(serde_json::to_vec(&value)?);
    files::create(&root.join("Identity.json"), &secret)?;
    let service_seed = Zeroizing::new(signer.to_bytes());
    files::create(&root.join("Service.key"), service_seed.as_ref())?;
    let transport = tls::key(&root)?;
    let request_pem = tls::command(
        &files::strings(&[
            "req",
            "-new",
            "-batch",
            "-config",
            "/dev/null",
            "-key",
            &tls::text(&root.join("Transport.key"))?,
            "-subj",
            "/CN=HyperNet Transport",
        ]),
        None,
    )?;
    let mut request = Request {
        version: 1,
        identity: value.public_key.clone(),
        transport: hex::encode(transport),
        address,
        port,
        request_pem: String::from_utf8(request_pem)?,
        signature: String::new(),
    };
    request.signature = hex::encode(signer.sign(&request.signed_bytes()?).to_bytes());
    request.validate()?;
    let pin = publish(&root.join("TransportRequest.json"), &request)?;
    let root = preparation.commit()?;
    Ok(
        json!({"status":"IdentityPrepared","identity":request.identity,"transport":request.transport,
        "request":root.join("TransportRequest.json"),"requestDigest":pin,"networkUsed":false}),
    )
}
fn issue(
    root: &Path,
    issuer_pin: &str,
    request_path: &Path,
    request_pin: &str,
    days: u32,
    output: &Path,
) -> Result<serde_json::Value> {
    let root = files::root(root)?;
    let _lock = files::lock(&root)?;
    let authority = tls::read_pinned(&root.join("Authority.pem"), issuer_pin)?;
    let request: Request = serde_json::from_slice(&tls::read_pinned(request_path, request_pin)?)?;
    request.validate()?;
    let extensions = format!(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:{}\n",
        request.address
    );
    let extension_path = root.join(format!("Extensions{}.cnf", files::random_id()));
    files::create(&extension_path, extensions.as_bytes())?;
    let serial = format!("0x{}", hex::encode(rand::random::<[u8; 16]>()));
    let result = tls::command(
        &files::strings(&[
            "x509",
            "-req",
            "-CA",
            &tls::text(&root.join("Authority.pem"))?,
            "-CAkey",
            &tls::text(&root.join("Transport.key"))?,
            "-set_serial",
            &serial,
            "-days",
            &days.to_string(),
            "-extfile",
            &tls::text(&extension_path)?,
        ]),
        Some(request.request_pem.as_bytes()),
    );
    fs::remove_file(extension_path)?;
    let peer = Peer {
        request,
        certificate_pem: String::from_utf8(result?)?,
        authority_pem: String::from_utf8(authority)?,
    };
    peer.validate(&root)?;
    let digest = publish(output, &peer)?;
    Ok(
        json!({"status":"CertificateIssued","peer":output,"peerDigest":digest,
        "identity":peer.request.identity,"transport":peer.request.transport,"networkUsed":false}),
    )
}
#[allow(clippy::too_many_arguments)]
fn replica(
    directory: &Path,
    identity_directory: &Path,
    bootstrap: &Path,
    pin: &str,
    peers: &[PathBuf],
    pins: &[String],
    observation: &Path,
    monitor: &str,
) -> Result<serde_json::Value> {
    ensure!(
        peers.len() == 4 && pins.len() == 4,
        "Four independently authenticated peer records required"
    );
    let local = files::root(identity_directory)?;
    let key = identity(&local)?;
    let local_key = key.verifying_key().to_bytes();
    let bootstrap = authority_files::read_single(bootstrap, files::MAXIMUM, false)?;
    ensure!(
        files::hex_digest(&bootstrap) == pin,
        "Bootstrap differs from independently authenticated digest"
    );
    let verified = trust_bootstrap::inspect(&bootstrap, true)?;
    let monitor_key = trust_bootstrap::hex32(monitor)?;
    ensure!(
        verified
            .summary
            .clock_monitors
            .iter()
            .any(|key| key == monitor),
        "Clock monitor is not reserved by accepted bootstrap"
    );
    crate::trust_wire::valid_key(&monitor_key)?;
    let boot = crate::consensus_clock::kernel_boot()?;
    crate::authority_clock_handoff::Source::Signed {
        path: observation.to_owned(),
        public_key: monitor.to_owned(),
        kernel_boot: boot.clone(),
    }
    .health()?
    .observe()?;
    let preparation = PreparedDirectory::new(directory)?;
    let root = preparation.root.clone();
    let mut values = Vec::new();
    for (path, digest) in peers.iter().zip(pins) {
        let value: Peer = serde_json::from_slice(&tls::read_pinned(path, digest)?)?;
        let der = value.validate(&root)?;
        ensure!(
            verified
                .summary
                .authority_transports
                .get(&value.request.identity)
                == Some(&value.request.transport),
            "Peer transport does not match accepted authority appointment"
        );
        values.push((value, der));
    }
    values.sort_by(|a, b| a.0.request.identity.cmp(&b.0.request.identity));
    ensure!(
        values
            .windows(2)
            .all(|v| v[0].0.request.identity != v[1].0.request.identity),
        "Repeated peer identity"
    );
    let selected = values
        .iter()
        .find(|v| v.0.request.identity == hex::encode(local_key))
        .context("Local identity is not appointed")?;
    let original: Request = files::json(&local.join("TransportRequest.json"))?;
    ensure!(
        serde_json::to_vec(&original)? == serde_json::to_vec(&selected.0.request)?,
        "Issued request differs from the locally retained request"
    );
    let private = Zeroizing::new(files::read(&local.join("Transport.key"), 8192)?);
    let public = tls::command(&files::strings(&["pkey", "-pubout"]), Some(&private))?;
    ensure!(
        tls::public_key(&public)? == trust_bootstrap::hex32(&selected.0.request.transport)?,
        "Local transport key differs"
    );
    files::create(&root.join("Transport.key"), &private)?;
    files::create(
        &root.join("Identity.json"),
        &Zeroizing::new(files::read(&local.join("Identity.json"), 4096)?),
    )?;
    files::create(&root.join("Bootstrap.cbor"), &bootstrap)?;
    files::create(
        &root.join("Certificate.pem"),
        selected.0.certificate_pem.as_bytes(),
    )?;
    let mut authorities = Vec::new();
    let mut endpoints = Vec::new();
    let mut leaves = Vec::new();
    for (index, (peer, der)) in values.iter().enumerate() {
        authorities.extend_from_slice(peer.authority_pem.as_bytes());
        authorities.push(b'\n');
        let leaf = root.join(format!("Peer{}.pem", index + 1));
        files::create(&leaf, peer.certificate_pem.as_bytes())?;
        leaves.push(directory.join(format!("Peer{}.pem", index + 1)));
        endpoints.push(
            json!({"key":trust_bootstrap::hex32(&peer.request.identity)?,
            "origin":format!("https://{}:{}/",peer.request.address,peer.request.port),
            "certificateSha256":trust_bootstrap::hex32(&files::hex_digest(der))?}),
        );
    }
    files::create(&root.join("CertificateAuthority.pem"), &authorities)?;
    let config = json!({"listen":format!("{}:{}",selected.0.request.address,selected.0.request.port),
        "peers":endpoints,"tls":{"certificate":directory.join("Certificate.pem"),"privateKey":directory.join("Transport.key"),"certificateAuthority":directory.join("CertificateAuthority.pem")},
        "clock":{"kind":"Signed","path":observation,"publicKey":monitor,"kernelBoot":boot},"controlSocket":"/State/Control/Control.sock"});
    publish(&root.join("ReplicaConfig.json"), &config)?;
    let root = preparation.commit()?;
    Ok(
        json!({"status":"ReplicaInputsPrepared","directory":root,"voter":hex::encode(local_key),
        "replicaConfig":root.join("ReplicaConfig.json"),"peerCertificates":leaves,
        "bootstrapDigest":pin,"networkUsed":false,"workloadStarted":false}),
    )
}
pub fn run(command: Command) -> Result<()> {
    let result = match command {
        Command::Issuer { location, days } => issuer(&location.directory, days)?,
        Command::Identity {
            location,
            address,
            port,
        } => prepare_identity(&location.directory, address, port)?,
        Command::Issue {
            location,
            issuer_digest,
            request,
            request_digest,
            days,
            output,
        } => issue(
            &location.directory,
            &issuer_digest,
            &request,
            &request_digest,
            days,
            &output,
        )?,
        Command::Replica {
            location,
            identity_directory,
            bootstrap,
            bootstrap_digest,
            peer,
            peer_digest,
            clock_observation,
            monitor_key,
        } => replica(
            &location.directory,
            &identity_directory,
            &bootstrap,
            &bootstrap_digest,
            &peer,
            &peer_digest,
            &clock_observation,
            &monitor_key,
        )?,
        Command::Clock {
            location,
            export_directory,
            chronyc,
            socket,
        } => {
            files::safe_path(&export_directory)?;
            files::safe_path(&socket)?;
            ensure!(
                export_directory.is_absolute()
                    && !export_directory.try_exists()?
                    && socket.is_absolute(),
                "New absolute clock export and explicit local socket required"
            );
            files::executable(&chronyc)?;
            let preparation = PreparedDirectory::new(&location.directory)?;
            let root = preparation.root.clone();
            publish(
                &root.join("ClockConfig.json"),
                &json!({"chronyc":chronyc,"socket":socket,"exportDirectory":export_directory}),
            )?;
            let root = preparation.commit()?;
            json!({"status":"ClockConfigurationPrepared","directory":root,"networkUsed":false,"monitorStarted":false})
        }
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
