// SPDX-License-Identifier: MIT
// A dedicated PID namespace supervises one accepted SSH grant under fresh authority leases.
use crate::{
    confinement, mail_authority as signed, protocol, ssh_authority,
    ssh_types::{self, Grant, Lease, SshConsent},
    store, types,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    network: String,
    identity: PathBuf,
    consent_file: PathBuf,
    grant_file: PathBuf,
    authority_ca: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
    state_directory: PathBuf,
    listen: SocketAddr,
    relay_address: SocketAddr,
}
pub struct Config {
    pub state_directory: PathBuf,
    pub listen: SocketAddr,
    pub relay_address: SocketAddr,
    consent: SshConsent,
    consent_digest: String,
    grant: Grant,
    key: SigningKey,
    authority_ca: reqwest::Certificate,
    transport_identity: reqwest::Identity,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            unsafe { libc::getpid() } == 1 && unsafe { libc::geteuid() } == 1000,
            "SSH supervisor must be PID 1 under its dedicated service UID"
        );
        let raw: Configuration = serde_json::from_slice(&store::read_bounded(path, 16384)?)?;
        ensure!(
            raw.state_directory == Path::new("/State")
                && raw.listen.port() > 1024
                && raw.relay_address.port() > 0,
            "Invalid SSH runtime paths or ports"
        );
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Identity {
            secret_key: String,
            public_key: String,
        }
        let bytes = zeroize::Zeroizing::new(store::read_private(&raw.identity, 4096)?);
        let mut identity: Identity = serde_json::from_slice(&bytes)?;
        let secret = protocol::fixed_hex::<32>(&identity.secret_key).map_err(anyhow::Error::msg);
        identity.secret_key.zeroize();
        let mut secret = secret?;
        let key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        ensure!(
            hex::encode(key.verifying_key().as_bytes()) == identity.public_key,
            "Service identity mismatch"
        );
        let object: types::Envelope =
            serde_json::from_slice(&store::read_bounded(&raw.consent_file, 16384)?)?;
        let consent = ssh_authority::consent(&object, &raw.network).map_err(anyhow::Error::msg)?;
        ensure!(
            consent.service_key == identity.public_key && consent.expires > store::now()?,
            "Service consent identity or expiry mismatch"
        );
        let consent_digest =
            signed::object_digest(ssh_types::CONSENT, &object).map_err(anyhow::Error::msg)?;
        let grant: Grant = serde_json::from_slice(&store::read_bounded(&raw.grant_file, 8192)?)?;
        ssh_authority::public_key(&grant.ssh_public_key).map_err(anyhow::Error::msg)?;
        ensure!(
            grant.service_key == consent.service_key
                && grant.service_generation == consent.generation
                && grant.account == consent.account
                && grant.purpose == consent.purpose
                && grant.accepted
                && !grant.revoked
                && grant.expires > store::now()?
                && grant.expires <= consent.expires,
            "Grant does not match active service consent"
        );
        ensure!(
            store::read_bounded(Path::new("/Config/SshdConfig"), 16384)?
                == settings(raw.listen).as_bytes(),
            "SSH restrictions differ from the required profile"
        );
        ensure!(
            store::read_bounded(Path::new("/Config/AuthorizedKeys"), 4096)?
                == format!("restrict {}\n", grant.ssh_public_key).as_bytes(),
            "SSH authorised key differs from grant"
        );
        let command = store::read_bounded(Path::new("/Service/Command"), 32 * 1024 * 1024)?;
        ensure!(
            signed::hash(&command) == consent.command_digest,
            "Packaged command differs from consent"
        );
        let host = Command::new("/OpenSSH/bin/ssh-keygen")
            .args(["-y", "-f", "/Config/SshHostKey"])
            .env_clear()
            .env("PATH", "/OpenSSH/bin")
            .env("OPENSSL_CONF", "/dev/null")
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            host.status.success() && String::from_utf8(host.stdout)?.trim() == consent.ssh_host_key,
            "OpenSSH host key differs from consent"
        );
        let cert = store::read_bounded(&raw.certificate, 65536)?;
        let chain = CertificateDer::pem_slice_iter(&cert).collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !chain.is_empty() && signed::hash(chain[0].as_ref()) == consent.certificate_digest,
            "Service transport certificate differs from consent"
        );
        let private = zeroize::Zeroizing::new(store::read_private(&raw.private_key, 65536)?);
        let loaded = crate::transport::tls_provider()
            .key_provider
            .load_private_key(PrivateKeyDer::from_pem_slice(&private)?)
            .map_err(|_| anyhow::anyhow!("Invalid service TLS key"))?;
        let public = loaded
            .public_key()
            .context("TLS key public identity unavailable")?;
        for key in [
            identity.public_key.clone(),
            ssh_authority::public_key(&consent.ssh_host_key).map_err(anyhow::Error::msg)?,
            ssh_authority::public_key(&grant.ssh_public_key).map_err(anyhow::Error::msg)?,
        ] {
            let mut forbidden = hex::decode("302a300506032b6570032100")?;
            forbidden.extend(hex::decode(key)?);
            ensure!(
                public.as_ref() != forbidden,
                "TLS, service and native SSH keys must differ"
            );
        }
        let mut pem = zeroize::Zeroizing::new(cert);
        pem.extend_from_slice(b"\n");
        pem.extend_from_slice(&private);
        let transport_identity = reqwest::Identity::from_pem(&pem)?;
        let authority_ca =
            reqwest::Certificate::from_pem(&store::read_bounded(&raw.authority_ca, 65536)?)?;
        Ok(Self {
            state_directory: raw.state_directory,
            listen: raw.listen,
            relay_address: raw.relay_address,
            consent,
            consent_digest,
            grant,
            key,
            authority_ca,
            transport_identity,
        })
    }
    fn client(&self) -> Result<reqwest::Client> {
        let url = reqwest::Url::parse(&self.consent.authority_endpoint)?;
        Ok(reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .add_root_certificate(self.authority_ca.clone())
            .identity(self.transport_identity.clone())
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .connect_timeout(Duration::from_secs(1))
            .resolve(
                url.host_str().context("Missing authority TLS name")?,
                self.relay_address,
            )
            .build()?)
    }
    async fn lease(&self, client: &reqwest::Client) -> Result<Lease> {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let request = types::Request {
            version: 1,
            request_id: hex::encode(nonce),
            issued_at: store::now()?,
            command: types::Command::SshAuthorise {
                service_key: self.consent.service_key.clone(),
                grant_id: self.grant.grant_id.clone(),
            },
        };
        let object = signed::sign(types::DOMAIN, &self.consent.network, &request, &self.key)
            .map_err(anyhow::Error::msg)?;
        let url = reqwest::Url::parse(&self.consent.authority_endpoint)?.join("V1/Command")?;
        let mut response = client.post(url).json(&object).send().await?;
        ensure!(response.status().is_success(), "SSH authority unavailable");
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 65536,
                "SSH authority response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let reply: types::Reply = serde_json::from_slice(&bytes)?;
        ensure!(reply.ok, "SSH permission unavailable");
        let object: types::Envelope = serde_json::from_value(reply.result["lease"].clone())?;
        ensure!(
            object.public_key == self.consent.authority_signer,
            "Incorrect SSH authority signer"
        );
        let lease: Lease = signed::verify(ssh_types::LEASE, &object, &self.consent.network)
            .map_err(anyhow::Error::msg)?;
        let now = store::now()?;
        ensure!(
            lease.version == 1
                && lease.network == self.consent.network
                && lease.service_key == self.consent.service_key
                && lease.service_generation == self.consent.generation
                && lease.consent_digest == self.consent_digest
                && lease.issued_at <= now
                && lease.expires > now
                && lease.expires <= lease.issued_at.saturating_add(5)
                && lease.expires <= self.grant.expires
                && serde_json::to_value(&lease.grant)? == serde_json::to_value(&self.grant)?,
            "Incorrect or expired SSH lease"
        );
        Ok(lease)
    }
    fn resources(&self, p: &confinement::Profile) -> Result<()> {
        let cpu = p
            .cpu_max
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            p.memory_max <= self.consent.memory_bytes
                && p.pids_max <= self.consent.pids
                && cpu.len() == 2
                && u128::from(cpu[0]) * u128::from(self.consent.cpu_period)
                    <= u128::from(self.consent.cpu_quota) * u128::from(cpu[1]),
            "SSH resource limits exceed consent"
        );
        let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::statvfs(c"/Work".as_ptr(), &mut filesystem) } == 0,
            "SSH workspace limits unavailable"
        );
        ensure!(
            u128::from(filesystem.f_blocks) * u128::from(filesystem.f_frsize) + 8192
                <= u128::from(self.consent.state_bytes),
            "SSH workspace exceeds consent"
        );
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } == 0
                && limit.rlim_cur <= self.consent.state_bytes
                && limit.rlim_max <= self.consent.state_bytes,
            "SSH file size limit exceeds consent"
        );
        Ok(())
    }
}
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Floor {
    network: String,
    consent_digest: String,
    grant_id: String,
    epoch: u64,
    revision: i64,
    time: u64,
}
fn record(
    config: &Config,
    disk: &mut FloorFile,
    floor: &mut Floor,
    lease: &Lease,
) -> Result<tokio::time::Instant> {
    let now = store::now()?;
    ensure!(
        now >= floor.time
            && lease.authority_epoch >= floor.epoch
            && lease.authority_revision >= floor.revision,
        "SSH authority or clock rollback"
    );
    floor.epoch = lease.authority_epoch;
    floor.revision = lease.authority_revision;
    floor.time = now;
    disk.commit(floor)?;
    ensure!(
        lease.expires > now && lease.expires <= config.grant.expires,
        "SSH lease expired during persistence"
    );
    // The monotonic deadline never depends on a later wall-clock adjustment.
    let remaining = (std::time::UNIX_EPOCH + Duration::from_secs(lease.expires))
        .duration_since(std::time::SystemTime::now())
        .context("SSH lease expired")?;
    Ok(tokio::time::Instant::now() + remaining)
}
fn settings(listen: SocketAddr) -> String {
    include_str!("../Packaging/SshdConfig")
        .replace("@Port@", &listen.port().to_string())
        .replace("@Address@", &listen.ip().to_string())
}
struct FloorFile {
    file: std::fs::File,
    generation: u64,
}
impl FloorFile {
    fn open(path: &Path) -> Result<(Self, Option<Floor>)> {
        use std::os::unix::fs::FileExt;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.len() == 8192
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.nlink() == 1
                && meta.permissions().mode() & 0o077 == 0,
            "Invalid private SSH floor file"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "SSH state is already active"
        );
        let mut bytes = [0u8; 8192];
        file.read_exact_at(&mut bytes, 0)?;
        let mut best = None;
        for index in 0..2 {
            let bank = &bytes[index * 4096..(index + 1) * 4096];
            let generation = u64::from_le_bytes(bank[16..24].try_into().unwrap());
            let length = u64::from_le_bytes(bank[24..32].try_into().unwrap()) as usize;
            if &bank[..16] == b"HyperNetSshF1\0\0\0"
                && generation > 0
                && length <= 4032
                && hex::encode(&bank[32..64]) == signed::hash(&bank[64..64 + length])
            {
                let floor = serde_json::from_slice::<Floor>(&bank[64..64 + length])?;
                if best.as_ref().is_none_or(|(old, _)| generation > *old) {
                    best = Some((generation, floor));
                }
            }
        }
        ensure!(
            best.is_some() || bytes.iter().all(|b| *b == 0),
            "SSH floor has no valid committed bank"
        );
        let (generation, floor) = match best {
            Some((generation, floor)) => (generation, Some(floor)),
            None => (0, None),
        };
        Ok((Self { file, generation }, floor))
    }
    fn commit(&mut self, floor: &Floor) -> Result<()> {
        use std::os::unix::fs::FileExt;
        let bytes = serde_json::to_vec(floor)?;
        ensure!(bytes.len() <= 4032, "SSH floor exceeds fixed storage");
        let generation = self
            .generation
            .checked_add(1)
            .context("SSH floor generation exhausted")?;
        let mut bank = [0u8; 4096];
        bank[..16].copy_from_slice(b"HyperNetSshF1\0\0\0");
        bank[16..24].copy_from_slice(&generation.to_le_bytes());
        bank[24..32].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        bank[32..64].copy_from_slice(&hex::decode(signed::hash(&bytes))?);
        bank[64..64 + bytes.len()].copy_from_slice(&bytes);
        self.file.write_all_at(&bank, (generation % 2) * 4096)?;
        self.file.sync_all()?;
        self.generation = generation;
        Ok(())
    }
}
pub async fn run(config: Config, profile: confinement::Profile) -> Result<()> {
    config.resources(&profile)?;
    let (mut disk, saved) = FloorFile::open(&config.state_directory.join("SshState.bin"))?;
    let mut floor = saved.unwrap_or(Floor {
        network: config.consent.network.clone(),
        consent_digest: config.consent_digest.clone(),
        grant_id: config.grant.grant_id.clone(),
        ..Default::default()
    });
    ensure!(
        floor.network == config.consent.network
            && floor.consent_digest == config.consent_digest
            && floor.grant_id == config.grant.grant_id,
        "SSH state belongs to another consent or grant"
    );
    let client = config.client()?;
    let lease = config.lease(&client).await?;
    let mut deadline = record(&config, &mut disk, &mut floor, &lease)?;
    let mut child = Command::new("/HyperNet")
        .args(["ssh-child", "--port", &config.listen.port().to_string()])
        .env_clear()
        .env("PATH", "/OpenSSH/bin:/bin")
        .env("OPENSSL_CONF", "/dev/null")
        .stdin(Stdio::null())
        .spawn()?;
    println!("SshService ready");
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let outcome:Result<()>=async {
        loop {
            tokio::select! { biased;
                _=tokio::time::sleep_until(deadline)=>break,
                _=terminate.recv()=>break,
                _=tokio::signal::ctrl_c()=>break,
                _=tick.tick()=>{
                    if child.try_wait()?.is_some(){break;}
                    let fresh=tokio::time::timeout_at(deadline,config.lease(&client)).await;
                    match fresh {Ok(Ok(lease))=>deadline=record(&config,&mut disk,&mut floor,&lease)?,_=>break}
                }
            }
        }
        Ok(())
    }.await;
    let _ = child.kill();
    let _ = child.wait();
    // PID 1 exit is the final stop for every child, including detached workload processes.
    outcome
}
pub fn child(port: u16) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000,
        "Dedicated SSH service UID required"
    );
    confinement::enter_ssh_child(port)?;
    Err(Command::new("/OpenSSH/sbin/sshd")
        .args(["-D", "-e", "-f", "/Config/SshdConfig"])
        .env_clear()
        .env("PATH", "/OpenSSH/bin:/bin")
        .env("OPENSSL_CONF", "/dev/null")
        .exec()
        .into())
}
pub fn command() -> Result<()> {
    confinement::enter_ssh_command()?;
    Err(Command::new("/Service/Command")
        .env_clear()
        .env("PATH", "/Service")
        .env("LANG", "C")
        .current_dir("/Work")
        .exec()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Directory, PathBuf) {
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let directory =
            Directory(std::env::temp_dir().join(format!("HyperNetSshFloor{}", hex::encode(nonce))));
        std::fs::create_dir(&directory.0).unwrap();
        let path = directory.0.join("Floor.bin");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.set_len(8192).unwrap();
        (directory, path)
    }
    #[test]
    fn restart_recovers_committed_floor_and_survives_torn_latest_bank() {
        let (_directory, path) = fixture();
        let (mut disk, saved) = FloorFile::open(&path).unwrap();
        assert!(saved.is_none());
        let mut floor = Floor {
            network: "Network".into(),
            epoch: 1,
            revision: 7,
            time: 100,
            ..Default::default()
        };
        disk.commit(&floor).unwrap();
        floor.revision = 8;
        disk.commit(&floor).unwrap();
        assert!(FloorFile::open(&path).is_err());
        drop(disk);
        let (disk, saved) = FloorFile::open(&path).unwrap();
        assert_eq!(saved.unwrap().revision, 8);
        disk.file.write_all_at(b"Broken", 64).unwrap();
        disk.file.sync_all().unwrap();
        drop(disk);
        let (disk, saved) = FloorFile::open(&path).unwrap();
        assert_eq!(saved.unwrap().revision, 7);
        assert_eq!(disk.generation, 1);
    }
    #[test]
    fn corrupt_floor_and_nonprivate_state_fail_closed() {
        let (_directory, path) = fixture();
        let (disk, _) = FloorFile::open(&path).unwrap();
        disk.file.write_all_at(b"Broken", 0).unwrap();
        drop(disk);
        assert!(FloorFile::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(FloorFile::open(&path).is_err());
    }
}
