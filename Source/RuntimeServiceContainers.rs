// SPDX-License-Identifier: MIT
// Fixed service containers retain exact resource identities before execution or cleanup.
use super::*;
use std::fs;

pub(super) fn verify(p: &Profile, r: &Resource) -> Result<Value> {
    let id =
        r.id.as_deref()
            .context("service resource identity is unresolved")?;
    let v = containers::inspect(&r.kind, id)?;
    let (actual, name, labels) = if r.kind == "network" {
        (&v["id"], &v["name"], &v["labels"])
    } else {
        (&v["Id"], &v["Name"], &v["Config"]["Labels"])
    };
    ensure!(
        actual == id
            && name
                .as_str()
                .is_some_and(|n| n.trim_start_matches('/') == r.name)
            && labels["io.hypernet.deployment"] == hex::encode(p.manifest.deployment)
            && labels["io.hypernet.configuration"] == p.digest()?,
        "resource ownership differs; no action performed"
    );
    ensure!(
        r.fingerprint.as_deref() == Some(containers::fingerprint(&r.kind, &v)?.as_str()),
        "resource configuration changed; no action performed"
    );
    if r.kind == "container" {
        let networks = v["NetworkSettings"]["Networks"]
            .as_object()
            .context("container network inspection absent")?;
        if r.network_ids.is_empty() {
            ensure!(
                v["HostConfig"]["NetworkMode"] == "none"
                    && (networks.is_empty()
                        || (networks.len() == 1 && networks.contains_key("none"))),
                "unnetworked service has an unexpected attachment"
            );
        } else {
            ensure!(
                networks.len() == r.network_ids.len(),
                "service has unconsented network attachments"
            );
            for (name, id) in &r.network_ids {
                let n = containers::inspect("network", id)?;
                ensure!(
                    n["id"] == *id
                        && n["name"] == *name
                        && n["internal"] == (p.role()?.role != 7)
                        && n["dns_enabled"] == false
                        && n["labels"]["io.hypernet.configuration"] == p.digest()?,
                    "service network differs from consent"
                );
                ensure!(
                    networks
                        .get(name)
                        .is_some_and(|n| n["NetworkID"] == *name || n["NetworkID"] == *id),
                    "attached service network identity changed"
                );
            }
        }
    }
    Ok(v)
}
fn labels(p: &Profile) -> Result<Vec<String>> {
    Ok(files::strings(&[
        "--label",
        &format!(
            "io.hypernet.deployment={}",
            hex::encode(p.manifest.deployment)
        ),
        "--label",
        &format!("io.hypernet.configuration={}", p.digest()?),
    ]))
}
fn resource(kind: &str, name: String) -> Resource {
    Resource {
        kind: kind.into(),
        name,
        id: None,
        fingerprint: None,
        network_ids: BTreeMap::new(),
    }
}
fn receipt(p: &Profile, helper: bool) -> PathBuf {
    p.root
        .join(if helper { "Helper.id" } else { "Container.id" })
}
fn slot(s: &mut State, helper: bool) -> &mut Option<Resource> {
    if helper {
        &mut s.helper
    } else {
        &mut s.container
    }
}
fn owned(p: &Profile, r: &Resource, v: &Value) -> Result<()> {
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
                    == hex::encode(p.role().unwrap().image_digest)),
        "container creation receipt has another owner or image"
    );
    Ok(())
}
pub(super) fn recover(p: &Profile, s: &mut State, helper: bool) -> Result<()> {
    let Some(r) = slot(s, helper).as_ref() else {
        return Ok(());
    };
    if r.id.is_some() {
        return Ok(());
    }
    let path = receipt(p, helper);
    if !path.try_exists()? {
        let names = String::from_utf8(files::podman(&files::strings(&[
            "ps",
            "--all",
            "--format",
            "{{.Names}}",
        ]))?)?;
        ensure!(
            !names.lines().any(|n| n == r.name),
            "unresolved container without its creation receipt; no unrelated resource touched"
        );
        *slot(s, helper) = None;
        return save(p, s);
    }
    let id = String::from_utf8(files::receipt(&path)?)?
        .trim()
        .to_string();
    crate::protocol::fixed_hex::<32>(&id).map_err(anyhow::Error::msg)?;
    if !containers::container_present(&id)? {
        *slot(s, helper) = None;
        save(p, s)?;
        fs::remove_file(path)?;
        fs::File::open(&p.root)?.sync_all()?;
        return Ok(());
    }
    let v = containers::inspect("container", &id)?;
    owned(p, r, &v)?;
    let r = slot(s, helper).as_mut().unwrap();
    r.id = Some(id);
    r.fingerprint = Some(containers::fingerprint("container", &v)?);
    save(p, s)
}
pub(super) fn remove(p: &Profile, s: &mut State, helper: bool) -> Result<()> {
    recover(p, s, helper)?;
    if let Some(r) = slot(s, helper).as_ref() {
        let id = r.id.as_deref().context("container identity absent")?;
        if containers::container_present(id)? {
            verify(p, r)?;
            files::podman(&files::strings(&["rm", "--force", id]))?;
        }
        // Preserve the identity until Podman has removed precisely that container.
        *slot(s, helper) = None;
        save(p, s)?;
    }
    let path = receipt(p, helper);
    if path.try_exists()? {
        let _ = files::receipt(&path)?;
        fs::remove_file(path)?;
        fs::File::open(&p.root)?.sync_all()?;
    }
    Ok(())
}
pub(super) fn network(p: &Profile, s: &mut State) -> Result<()> {
    if let Some(r) = &s.network {
        if r.id.is_some() {
            verify(p, r)?;
            return Ok(());
        }
    } else {
        let name = format!("{}Network", p.name());
        let list: Vec<Value> = serde_json::from_slice(&files::podman(&files::strings(&[
            "network", "ls", "--format", "json",
        ]))?)?;
        ensure!(
            !list.iter().any(|n| n["name"] == name),
            "service network name is already owned; no resource adopted"
        );
        s.network = Some(resource("network", name));
        save(p, s)?;
    }
    let name = &s.network.as_ref().unwrap().name;
    let list: Vec<Value> = serde_json::from_slice(&files::podman(&files::strings(&[
        "network", "ls", "--format", "json",
    ]))?)?;
    if !list.iter().any(|n| n["name"] == *name) {
        let mut args = files::strings(&["network", "create", "--disable-dns"]);
        if p.role()?.role != 7 {
            args.push("--internal".into());
        }
        args.extend(labels(p)?);
        args.push(name.clone());
        files::podman(&args)?;
    }
    let v = containers::inspect("network", name)?;
    ensure!(
        v["name"] == *name
            && v["internal"] == (p.role()?.role != 7)
            && v["dns_enabled"] == false
            && v["labels"]["io.hypernet.configuration"] == p.digest()?
            && v["labels"]["io.hypernet.deployment"] == hex::encode(p.manifest.deployment),
        "interrupted service network differs from recorded intent"
    );
    let id = v["id"].as_str().context("network ID absent")?.to_string();
    crate::protocol::fixed_hex::<32>(&id).map_err(anyhow::Error::msg)?;
    let r = s.network.as_mut().unwrap();
    r.id = Some(id);
    r.fingerprint = Some(containers::fingerprint("network", &v)?);
    save(p, s)
}
pub(super) fn remove_network(p: &Profile, s: &mut State) -> Result<()> {
    ensure!(
        s.container.is_none() && s.helper.is_none(),
        "service containers remain"
    );
    if s.network.is_none() {
        return Ok(());
    }
    let list: Vec<Value> = serde_json::from_slice(&files::podman(&files::strings(&[
        "network", "ls", "--format", "json",
    ]))?)?;
    let r = s.network.as_ref().unwrap();
    let present = list.iter().any(|n| {
        r.id.as_ref()
            .map_or(n["name"] == r.name, |id| n["id"] == *id)
    });
    if !present {
        // A prior removal may have completed before state publication. Never recreate it during cleanup.
        s.network = None;
        return save(p, s);
    }
    // Resolve only a present network whose creation intent was durably retained.
    network(p, s)?;
    let r = s.network.as_ref().unwrap();
    verify(p, r)?;
    files::podman(&files::strings(&[
        "network",
        "rm",
        r.id.as_deref().unwrap(),
    ]))?;
    s.network = None;
    save(p, s)
}
fn mount(
    p: &Profile,
    args: &mut Vec<String>,
    source: &Path,
    target: &str,
    write: bool,
    shared: bool,
) {
    let mut mode = if write {
        "rw,nosuid,nodev,noexec"
    } else {
        "ro,nosuid,nodev,noexec"
    }
    .to_string();
    if p.selinux {
        mode.push_str(if shared { ",z" } else { ",Z" });
    }
    args.extend(files::strings(&[
        "--volume",
        &format!("{}:{target}:{mode}", source.display()),
    ]));
}
pub(super) fn create(
    p: &Profile,
    s: &mut State,
    helper: bool,
    command: &[String],
    input: Option<&Path>,
) -> Result<String> {
    ensure!(
        slot(s, helper).is_none(),
        "owned service container already exists"
    );
    p.check_artifacts()?;
    let role = p.role()?;
    let name = format!("{}{}", p.name(), if helper { "Helper" } else { "Workload" });
    let names = String::from_utf8(files::podman(&files::strings(&[
        "ps",
        "--all",
        "--format",
        "{{.Names}}",
    ]))?)?;
    ensure!(
        !names.lines().any(|n| n == name),
        "container name collision; unrelated resource preserved"
    );
    let path = receipt(p, helper);
    ensure!(
        !path.try_exists()?,
        "container receipt exists without its resource"
    );
    let now = files::now()?
        .checked_mul(1000)
        .context("wall time overflow")?;
    let reporting = helper && command == files::strings(&["runtime-service-receipt"]);
    let remaining = if reporting {
        60
    } else {
        p.manifest
            .validity
            .1
            .checked_sub(now)
            .context("service consent expired")?
            / 1000
    };
    ensure!(remaining > 0, "service consent expired");
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
        "--env=HOME=/Work",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        &format!(
            "--security-opt=seccomp={}",
            p.root.join("Config/Seccomp.json").display()
        ),
        "--ipc=private",
        "--pid=private",
        "--ulimit=core=0:0",
        "--ulimit=nofile=256:256",
        "--ulimit=nproc=4096:4096",
        &format!("--ulimit=fsize={0}:{0}", role.state_admission_bytes),
        &format!("--memory={}", role.memory_bytes),
        &format!("--memory-swap={}", role.memory_bytes),
        &format!("--pids-limit={}", role.pids),
        &format!("--cpu-period={}", role.cpu_period),
        &format!("--cpu-quota={}", role.cpu_quota),
        &format!(
            "--timeout={}",
            if helper { remaining.min(60) } else { remaining }
        ),
        "--stop-timeout=15",
        "--log-driver=k8s-file",
        "--log-opt=max-size=1mb",
        "--mount",
        &format!(
            "type=tmpfs,destination=/Work,rw,noexec,nosuid,nodev,tmpfs-size={},tmpfs-mode=0700,U=true",
            role.state_admission_bytes
        ),
    ]);
    args.extend(labels(p)?);
    let mut r = resource("container", name);
    if !helper && matches!(role.role, 7 | 8) {
        network(p, s)?;
        let n = s.network.as_ref().unwrap();
        verify(p, n)?;
        r.network_ids.insert(n.name.clone(), n.id.clone().unwrap());
        let endpoint = p
            .manifest
            .endpoints
            .iter()
            .find(|e| role.bind_endpoint_ids.contains(&e.endpoint_id))
            .context("service bind endpoint absent")?;
        args.extend(files::strings(&[
            "--network",
            &n.name,
            "--publish",
            &format!(
                "{}:{}:{}/tcp",
                endpoint.address, endpoint.port, endpoint.port
            ),
        ]));
    } else {
        args.push("--network=none".into());
    }
    mount(
        p,
        &mut args,
        &p.root.join("Launch/Config"),
        "/Config",
        false,
        false,
    );
    mount(
        p,
        &mut args,
        &p.root.join("Launch/State"),
        "/State",
        !reporting,
        false,
    );
    mount(
        p,
        &mut args,
        &p.root.join("Authorization"),
        "/Authorization",
        false,
        true,
    );
    mount(
        p,
        &mut args,
        s.authority_control.as_ref().unwrap_or(&p.authority_control),
        "/Authority",
        false,
        true,
    );
    mount(p, &mut args, &p.clock_directory, "/Clock", false, true);
    let requester_recovery = helper
        && (command == files::strings(&["runtime-service-requester-status"])
            || command == files::strings(&["runtime-service-requester-fence"]));
    if !requester_recovery {
        for (key, selected) in &p.media_controls {
            mount(
                p,
                &mut args,
                &selected.directory.join("Launch/State/Control"),
                &format!("/Media/{key}/Control"),
                false,
                true,
            );
        }
    }
    if let Some(input) = input {
        mount(p, &mut args, input, "/EpochInput", false, true);
    }
    args.push(p.image()?);
    args.extend(command.iter().cloned());
    *slot(s, helper) = Some(r);
    save(p, s)?;
    files::podman(&args)?;
    recover(p, s, helper)?;
    let r = slot(s, helper)
        .as_ref()
        .context("created resource absent")?;
    verify(p, r)?;
    let id = r.id.clone().context("created container ID absent")?;
    containers::image::verify(&id, &hex::encode(p.manifest.software_digest))?;
    Ok(id)
}
pub(super) fn finite(
    p: &Profile,
    s: &mut State,
    command: &[String],
    input: Option<&Path>,
) -> Result<Vec<u8>> {
    ensure!(
        s.container.is_none(),
        "stop the service before changing its retained state"
    );
    remove(p, s, true)?;
    let result = (|| {
        let id = create(p, s, true, command, input)?;
        files::capture(
            Path::new("/usr/bin/podman"),
            &files::strings(&["start", "--attach", &id]),
            65,
            4 * wire::MAXIMUM,
            16384,
        )
        .map(|v| v.0)
    })();
    let cleanup = remove(p, s, true);
    let bytes = result?;
    cleanup?;
    Ok(bytes)
}
