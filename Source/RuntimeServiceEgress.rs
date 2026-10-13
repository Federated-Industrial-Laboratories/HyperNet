// SPDX-License-Identifier: MIT
// A credential-free helper connects only the exact numeric destinations in local consent.
use super::*;
use crate::authority_domains::routes::RegisteredProfile;
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    destinations: BTreeMap<String, SocketAddr>,
    maximum_connections: usize,
    maximum_bytes: u64,
    duration_ms: u64,
    idle_ms: u64,
    expires_ms: u64,
}
pub(crate) fn configuration(manifest: &Manifest, profile: &RegisteredProfile) -> Result<Vec<u8>> {
    let role = manifest
        .roles
        .iter()
        .find(|r| r.role == 5)
        .context("route role absent")?;
    let mut destinations = BTreeMap::new();
    for id in &role.outbound_endpoint_ids {
        let endpoint = manifest
            .endpoints
            .iter()
            .find(|e| e.endpoint_id == *id)
            .context("consented egress endpoint absent")?;
        destinations.insert(
            hex::encode(id),
            SocketAddr::new(endpoint.address, endpoint.port),
        );
    }
    serde_json::to_vec(&Configuration {
        destinations,
        maximum_connections: usize::try_from(profile.maximum_connections)?,
        maximum_bytes: profile.limits.bytes,
        duration_ms: profile.limits.duration_ms,
        idle_ms: profile.limits.idle_ms,
        expires_ms: profile.validity.1.min(manifest.validity.1),
    })
    .map_err(Into::into)
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    ensure!((1..=1024).contains(&size), "invalid egress frame");
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn copy(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    budget: Arc<AtomicU64>,
    idle: Duration,
) -> Result<()> {
    let mut bytes = [0; 8192];
    loop {
        let n = timeout(idle, from.read(&mut bytes)).await??;
        if n == 0 {
            to.shutdown().await?;
            return Ok(());
        }
        ensure!(
            budget
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| left
                    .checked_sub(n as u64))
                .is_ok(),
            "egress byte budget exhausted"
        );
        timeout(idle, to.write_all(&bytes[..n])).await??;
    }
}
async fn connection(mut client: UnixStream, config: Arc<Configuration>) -> Result<()> {
    ensure!(
        client.peer_cred()?.uid() == unsafe { libc::geteuid() },
        "egress peer owner differs"
    );
    let bytes = timeout(Duration::from_millis(config.idle_ms), frame(&mut client)).await??;
    let v = wire::decode(&bytes)?;
    let f = v.array(4)?;
    ensure!(
        f[0].uint()? == 200 && f[1].uint()? == 1 && f[2].text()? == "RouteDial",
        "unknown egress request"
    );
    let id = f[3].fixed::<32>()?;
    let address = *config
        .destinations
        .get(&hex::encode(id))
        .context("destination lacks exact local consent")?;
    let remote = timeout(
        Duration::from_millis(config.idle_ms),
        TcpStream::connect(address),
    )
    .await??;
    let reply = wire::encode(&wire::Value::Array(vec![
        wire::Value::Uint(201),
        wire::Value::Uint(1),
        wire::Value::Text("RouteDial".into()),
        wire::Value::Bytes(id.to_vec()),
    ]))?;
    client.write_u32(u32::try_from(reply.len())?).await?;
    client.write_all(&reply).await?;
    let (cr, cw) = client.into_split();
    let (rr, rw) = remote.into_split();
    let budget = Arc::new(AtomicU64::new(config.maximum_bytes));
    let idle = Duration::from_millis(config.idle_ms);
    timeout(Duration::from_millis(config.duration_ms), async {
        tokio::select! {r=copy(cr,rw,budget.clone(),idle)=>r,r=copy(rr,cw,budget,idle)=>r}
    })
    .await??;
    Ok(())
}
pub fn run() -> Result<()> {
    crate::confinement::disable_dumps()?;
    let bytes = crate::authority_files::read(Path::new("/Config/Egress.json"), wire::MAXIMUM, true)
        .context("cannot read isolated egress configuration")?;
    let config: Configuration =
        serde_json::from_slice(&bytes).context("invalid isolated egress configuration")?;
    ensure!(
        config.destinations.len() <= 16
            && (1..=4096).contains(&config.maximum_connections)
            && (16384..=1024 * 1024 * 1024).contains(&config.maximum_bytes)
            && (1000..=3600000).contains(&config.duration_ms)
            && (100..=config.duration_ms).contains(&config.idle_ms),
        "egress resource bounds differ"
    );
    let mut ports = vec![];
    for (id, address) in &config.destinations {
        crate::protocol::fixed_hex::<32>(id).map_err(anyhow::Error::msg)?;
        ensure!(
            address.port() > 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
            "egress requires numeric unicast destination"
        );
        ports.push(address.port());
    }
    ports.sort();
    ports.dedup();
    let directory = crate::authority_files::private_directory(Path::new("/State"))
        .context("cannot open isolated egress socket directory")?;
    drop(directory);
    crate::confinement::enter_authority(
        Path::new("/State"),
        &[
            PathBuf::from("/Config/Egress.json"),
            PathBuf::from("/Authorization"),
        ],
        &[],
        &ports,
    )
    .context("egress confinement could not be installed")?;
    crate::confinement::canaries(Path::new("/State"))
        .context("egress confinement boundary check failed")?;
    crate::runtime()?.block_on(serve(config))
}
async fn serve(config: Configuration) -> Result<()> {
    let path = Path::new("/State/Egress.sock");
    if let Ok(m) = fs::symlink_metadata(path) {
        ensure!(
            m.file_type().is_socket(),
            "egress socket path has another type"
        );
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let config = Arc::new(config);
    let slots = Arc::new(Semaphore::new(config.maximum_connections));
    let mut connections = JoinSet::new();
    let mut previous = 0;
    loop {
        let now = files::now()?
            .checked_mul(1000)
            .context("egress clock overflow")?;
        ensure!(
            now >= previous && now < config.expires_ms,
            "egress consent expired or clock moved backwards"
        );
        previous = now;
        ensure!(
            fs::read("/Authorization/Withdrawal.json")? == b"0",
            "egress local consent withdrawn"
        );
        while connections.try_join_next().is_some() {}
        let Ok(accepted) = timeout(Duration::from_millis(100), listener.accept()).await else {
            continue;
        };
        let (stream, _) = accepted?;
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let config = config.clone();
        connections.spawn(async move {
            let _slot = slot;
            let _ = connection(stream, config).await;
        });
    }
}
fn receipt(p: &Profile) -> PathBuf {
    p.root.join("Egress.id")
}
fn identity(p: &Profile, r: &Resource, v: &Value) -> Result<()> {
    ensure!(
        v["Name"]
            .as_str()
            .is_some_and(|n| n.trim_start_matches('/') == r.name)
            && v["Config"]["Labels"]["io.hypernet.deployment"]
                == hex::encode(p.manifest.deployment)
            && v["Config"]["Labels"]["io.hypernet.configuration"] == p.digest()?
            && v["Image"]
                .as_str()
                .is_some_and(|i| i.trim_start_matches("sha256:")
                    == hex::encode(p.role().unwrap().image_digest))
            && v["HostConfig"]["NetworkMode"]
                .as_str()
                .is_some_and(|n| n.starts_with("slirp4netns")),
        "egress resource ownership or network differs"
    );
    Ok(())
}
pub(super) fn verify(p: &Profile, r: &Resource) -> Result<Value> {
    let id = r.id.as_ref().context("unresolved egress resource")?;
    let v = containers::inspect("container", id)?;
    identity(p, r, &v)?;
    ensure!(
        v["Id"] == *id
            && r.fingerprint.as_deref() == Some(containers::fingerprint("container", &v)?.as_str()),
        "egress configuration changed"
    );
    Ok(v)
}
fn recover(p: &Profile, s: &mut State) -> Result<()> {
    let Some(r) = s.egress.as_ref() else {
        return Ok(());
    };
    if r.id.is_some() {
        return Ok(());
    }
    let path = receipt(p);
    if !path.try_exists()? {
        let names = String::from_utf8(files::podman(&files::strings(&[
            "ps",
            "--all",
            "--format",
            "{{.Names}}",
        ]))?)?;
        ensure!(
            !names.lines().any(|n| n == r.name),
            "unresolved egress container lacks its receipt"
        );
        s.egress = None;
        return save(p, s);
    }
    let id = String::from_utf8(files::receipt(&path)?)?
        .trim()
        .to_string();
    crate::protocol::fixed_hex::<32>(&id).map_err(anyhow::Error::msg)?;
    if !containers::container_present(&id)? {
        s.egress = None;
        save(p, s)?;
        fs::remove_file(path)?;
        fs::File::open(&p.root)?.sync_all()?;
        return Ok(());
    }
    let v = containers::inspect("container", &id)?;
    identity(p, r, &v)?;
    let r = s.egress.as_mut().unwrap();
    r.id = Some(id);
    r.fingerprint = Some(containers::fingerprint("container", &v)?);
    save(p, s)
}
pub(super) fn remove(p: &Profile, s: &mut State) -> Result<()> {
    recover(p, s)?;
    if let Some(r) = &s.egress {
        let id = r.id.as_ref().context("egress resource unresolved")?;
        if containers::container_present(id)? {
            verify(p, r)?;
            files::podman(&files::strings(&["rm", "--force", id]))?;
        }
        s.egress = None;
        save(p, s)?;
    }
    let path = receipt(p);
    if path.try_exists()? {
        let _ = files::receipt(&path)?;
        fs::remove_file(path)?;
        fs::File::open(&p.root)?.sync_all()?;
    }
    Ok(())
}
pub(super) fn start(p: &Profile, s: &mut State) -> Result<()> {
    if p.role()?.role != 5 {
        return Ok(());
    }
    remove(p, s)?;
    let role = p.role()?;
    let name = format!("{}Egress", p.name());
    let path = receipt(p);
    let names = String::from_utf8(files::podman(&files::strings(&[
        "ps",
        "--all",
        "--format",
        "{{.Names}}",
    ]))?)?;
    ensure!(
        !names.lines().any(|n| n == name) && !path.try_exists()?,
        "egress name or receipt already owned"
    );
    let remaining = p
        .manifest
        .validity
        .1
        .checked_sub(
            files::now()?
                .checked_mul(1000)
                .context("egress time overflow")?,
        )
        .context("egress consent expired")?
        .div_ceil(1000);
    let profile = crate::authority_domains::routes::RegisteredProfile::parse(
        &files::read(&p.root.join("Config/RouteProfile.cbor"), wire::MAXIMUM)?,
        p.manifest.network,
        p.manifest.incarnation,
    )?;
    let descriptors = profile.maximum_connections * 2 + 64;
    let mut args = files::strings(&[
        "create",
        "--name",
        &name,
        "--cidfile",
        path.to_str().unwrap(),
        "--pull=never",
        "--entrypoint=/HyperNet",
        "--read-only",
        "--read-only-tmpfs=false",
        "--userns=nomap",
        "--user=1000:1000",
        "--env=HOME=/",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        &format!(
            "--security-opt=seccomp={}",
            p.root.join("Config/Seccomp.json").display()
        ),
        "--ipc=private",
        "--pid=private",
        "--network=slirp4netns:allow_host_loopback=false",
        "--ulimit=core=0:0",
        &format!("--ulimit=nofile={descriptors}:{descriptors}"),
        "--ulimit=nproc=4096:4096",
        "--ulimit=fsize=1048576:1048576",
        &format!("--memory={}", role.memory_bytes / 4),
        &format!("--memory-swap={}", role.memory_bytes / 4),
        &format!("--pids-limit={}", role.pids / 4),
        &format!("--cpu-period={}", role.cpu_period),
        &format!("--cpu-quota={}", role.cpu_quota / 4),
        &format!("--timeout={remaining}"),
        "--stop-timeout=15",
        "--log-driver=k8s-file",
        "--log-opt=max-size=1mb",
        "--label",
        &format!(
            "io.hypernet.deployment={}",
            hex::encode(p.manifest.deployment)
        ),
        "--label",
        &format!("io.hypernet.configuration={}", p.digest()?),
    ]);
    workload::mount(
        p,
        &mut args,
        &p.root.join("Launch/EgressConfig"),
        "/Config",
        false,
        false,
    );
    workload::mount(
        p,
        &mut args,
        &p.root.join("Launch/State/Egress"),
        "/State",
        true,
        true,
    );
    workload::mount(
        p,
        &mut args,
        &p.root.join("Authorization"),
        "/Authorization",
        false,
        true,
    );
    args.extend([p.image()?, "private-route-egress".into()]);
    s.egress = Some(Resource {
        kind: "container".into(),
        name,
        id: None,
        fingerprint: None,
        network_ids: BTreeMap::new(),
    });
    save(p, s)?;
    files::podman(&args)?;
    recover(p, s)?;
    let r = s.egress.as_ref().context("egress resource absent")?;
    verify(p, r)?;
    let id = r.id.as_ref().unwrap();
    containers::image::verify(id, &hex::encode(p.manifest.software_digest))?;
    files::podman(&files::strings(&["start", id]))?;
    verify(p, r)?;
    // The service retries only its owned socket while the helper initialises.
    Ok(())
}
