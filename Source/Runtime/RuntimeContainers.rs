// SPDX-License-Identifier: MIT
use super::model::save;
use super::{files::*, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
#[path = "RuntimeImage.rs"]
pub(super) mod image;
#[path = "RuntimePreparation.rs"]
pub(super) mod preparation;
pub use preparation::prepare;

fn topology(p: &Profile, role: &str) -> Result<BTreeMap<String, String>> {
    Ok(match role {
        "Authority" => [(p.network_name(), p.ip(20))].into(),
        "Initialise" | "Inspect" | "ImageCheck" => BTreeMap::new(),
        _ => anyhow::bail!("Unknown container role"),
    })
}

fn check_addresses(
    networks: &Value,
    expected: &BTreeMap<String, String>,
    running: bool,
) -> Result<()> {
    let actual = networks
        .as_object()
        .context("Missing effective network attachments")?;
    ensure!(
        actual.len() == expected.len(),
        "Network attachments differ from consent"
    );
    for (name, address) in expected {
        let value = actual
            .get(name)
            .context("Required network attachment is missing")?;
        ensure!(
            value["DriverOpts"].is_null()
                && value["IPAMConfig"].is_null()
                && value["Links"].is_null(),
            "Unexpected network options"
        );
        ensure!(
            value["IPv6Gateway"] == ""
                && value["GlobalIPv6Address"] == ""
                && value["GlobalIPv6PrefixLen"] == 0,
            "Unexpected IPv6 route"
        );
        if running {
            ensure!(
                value["IPAddress"] == *address
                    && value["IPPrefixLen"] == 24
                    && value["Gateway"]
                        == format!(
                            "{}.1",
                            address.rsplit_once('.').context("Invalid IPv4 address")?.0
                        ),
                "Active network addressing differs from consent"
            );
        } else {
            ensure!(
                value["IPAddress"] == "" && value["IPPrefixLen"] == 0 && value["Gateway"] == "",
                "Inactive container retains unexpected addressing"
            );
        }
    }
    Ok(())
}
fn check_unnetworked(value: &Value) -> Result<()> {
    ensure!(
        value["HostConfig"]["NetworkMode"] == "none",
        "Unnetworked container mode differs from consent"
    );
    let networks = value["NetworkSettings"]["Networks"]
        .as_object()
        .context("Missing effective network attachments")?;
    // Podman 4.9 and 5.7 report this synthetic entry for --network=none.
    // It names no actual network and must contain no addressing or options.
    let synthetic = json!({"none":{
        "EndpointID":"", "Gateway":"", "IPAddress":"", "IPPrefixLen":0,
        "IPv6Gateway":"", "GlobalIPv6Address":"", "GlobalIPv6PrefixLen":0,
        "MacAddress":"", "NetworkID":"none", "DriverOpts":null,
        "IPAMConfig":null, "Links":null
    }});
    ensure!(
        networks.is_empty() || Some(networks) == synthetic.as_object(),
        "Unnetworked container has effective network attachments"
    );
    Ok(())
}
fn verify_topology(p: &Profile, r: &Resource, value: &Value) -> Result<()> {
    let role = r
        .name
        .strip_prefix(&p.prefix())
        .context("Invalid container role")?;
    let expected = topology(p, role)?;
    ensure!(
        r.network_ids.len() == expected.len(),
        "Recorded network identities differ"
    );
    if expected.is_empty() {
        check_unnetworked(value)?;
    } else {
        check_addresses(
            &value["NetworkSettings"]["Networks"],
            &expected,
            value["State"]["Running"] == true,
        )?;
    }
    for name in expected.keys() {
        let id = r
            .network_ids
            .get(name)
            .context("Missing recorded network identity")?;
        crate::protocol::fixed_hex::<32>(id).map_err(anyhow::Error::msg)?;
        let network = inspect("network", id)?;
        ensure!(
            network["id"] == *id
                && network["name"] == *name
                && network["internal"] == false
                && network["labels"]["io.hypernet.deployment"] == p.deployment
                && network["labels"]["io.hypernet.configuration"] == p.configuration_digest()?,
            "Effective network identity differs from consent"
        );
        let attachment = &value["NetworkSettings"]["Networks"][name];
        ensure!(
            attachment["NetworkID"] == *name || attachment["NetworkID"] == *id,
            "Attached network identity differs"
        );
    }
    Ok(())
}

pub(super) fn inspect(kind: &str, id: &str) -> Result<Value> {
    let bytes = podman(&strings(&[kind, "inspect", id]))?;
    let value: Value = serde_json::from_slice(&bytes)?;
    value
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .context("Missing resource inspection")
}
#[path = "RuntimeContainerFingerprint.rs"]
mod fingerprint;
pub(super) fn fingerprint(kind: &str, v: &Value) -> Result<String> {
    fingerprint::of(kind, v)
}

pub fn verify(p: &Profile, r: &Resource) -> Result<Value> {
    let id =
        r.id.as_deref()
            .context("Unresolved resource creation requires recovery")?;
    let value = inspect(&r.kind, id)?;
    let (actual_id, name, labels) = if r.kind == "network" {
        (&value["id"], &value["name"], &value["labels"])
    } else {
        (&value["Id"], &value["Name"], &value["Config"]["Labels"])
    };
    ensure!(
        actual_id == id
            && name
                .as_str()
                .is_some_and(|x| x.trim_start_matches('/') == r.name)
            && labels["io.hypernet.deployment"] == p.deployment
            && labels["io.hypernet.configuration"] == p.configuration_digest()?,
        "Resource identity differs; no action performed"
    );
    ensure!(
        r.fingerprint.as_deref() == Some(fingerprint(&r.kind, &value)?.as_str()),
        "Resource configuration differs; no action performed"
    );
    if r.kind == "container" {
        verify_topology(p, r, &value)?;
    }
    Ok(value)
}
fn recover_container(root: &Path, p: &Profile, r: &mut Resource) -> Result<()> {
    if r.id.is_some() {
        return Ok(());
    }
    let role = r
        .name
        .strip_prefix(&p.prefix())
        .context("Invalid role identity")?;
    let id = String::from_utf8(receipt(&root.join(format!("Container{role}.id")))?)?
        .trim()
        .to_string();
    crate::protocol::fixed_hex::<32>(&id).map_err(anyhow::Error::msg)?;
    let value = inspect("container", &id)?;
    ensure!(
        value["Id"] == id
            && value["Name"]
                .as_str()
                .is_some_and(|n| n.trim_start_matches('/') == r.name)
            && value["Config"]["Labels"]["io.hypernet.deployment"] == p.deployment
            && value["Config"]["Labels"]["io.hypernet.configuration"]
                == p.configuration_digest()?
            && value["Image"]
                .as_str()
                .is_some_and(|image| image.trim_start_matches("sha256:")
                    == p.image.trim_start_matches("sha256:")),
        "Persisted container receipt differs from configuration"
    );
    verify_topology(p, r, &value)?;
    r.id = Some(id);
    r.fingerprint = Some(fingerprint("container", &value)?);
    Ok(())
}
pub(super) fn container_present(id: &str) -> Result<bool> {
    let result = String::from_utf8(podman(&strings(&[
        "ps",
        "--all",
        "--no-trunc",
        "--filter",
        &format!("id={id}"),
        "--format",
        "{{.ID}}",
    ]))?)?;
    ensure!(
        result.trim().is_empty() || result.trim() == id,
        "Container identity query returned an unexpected result"
    );
    Ok(!result.trim().is_empty())
}
fn labels(p: &Profile) -> Result<Vec<String>> {
    Ok(strings(&[
        "--label",
        &format!("io.hypernet.deployment={}", p.deployment),
        "--label",
        &format!("io.hypernet.configuration={}", p.configuration_digest()?),
    ]))
}
pub fn network(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    let name = p.network_name();
    if let Some(r) = s
        .resources
        .iter()
        .find(|r| r.kind == "network" && r.name == name)
    {
        verify(p, r)?;
        return Ok(());
    }
    let existing: Vec<Value> =
        serde_json::from_slice(&podman(&strings(&["network", "ls", "--format", "json"]))?)?;
    ensure!(
        !existing.iter().any(|network| network["name"] == name),
        "Network name collision; unrelated resource preserved"
    );
    let subnet = format!("{}/24", p.subnet);
    s.resources.push(Resource {
        kind: "network".into(),
        name: name.clone(),
        id: None,
        fingerprint: None,
        network_ids: BTreeMap::new(),
    });
    save(root, s)?;
    let mut args = strings(&[
        "network",
        "create",
        "--disable-dns",
        "--subnet",
        &subnet,
        "--gateway",
        &p.ip(1),
    ]);
    args.extend(labels(p)?);
    args.push(name.clone());
    podman(&args)?;
    let value = inspect("network", &name)?;
    let id = value["id"]
        .as_str()
        .context("Missing network identity")?
        .to_string();
    crate::protocol::fixed_hex::<32>(&id).map_err(anyhow::Error::msg)?;
    let r = s.resources.last_mut().unwrap();
    r.id = Some(id);
    r.fingerprint = Some(fingerprint("network", &value)?);
    save(root, s)?;
    Ok(())
}
fn common(p: &Profile, role: &str, memory: u64, pids: u64, quota: u64) -> Result<Vec<String>> {
    let lifetime = if role == "Inspect" {
        45
    } else {
        p.expires.checked_sub(now()?).context("Consent expired")?
    };
    ensure!(lifetime > 0, "Consent expired");
    let mut args = strings(&[
        "create",
        "--name",
        &format!("{}{role}", p.prefix()),
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
            p.root.join("Seccomp.json").display()
        ),
        "--ipc=private",
        "--pid=private",
        "--ulimit=core=0:0",
        "--ulimit=nofile=256:256",
        "--ulimit=nproc=4096:4096",
        &format!("--memory={memory}"),
        &format!("--memory-swap={memory}"),
        &format!("--pids-limit={pids}"),
        &format!("--cpu-period={}", p.resources.cpu_period),
        &format!("--cpu-quota={quota}"),
        &format!("--timeout={lifetime}"),
        "--stop-timeout=15",
        "--log-driver=k8s-file",
        "--log-opt=max-size=1mb",
    ]);
    args.extend(labels(p)?);
    Ok(args)
}
fn volume_options(write: bool, executable: bool, selinux: bool) -> String {
    let mut options = vec![if write { "rw" } else { "ro" }, "nosuid", "nodev"];
    if !executable {
        options.push("noexec");
    }
    if selinux {
        options.push("Z");
    }
    options.join(",")
}
fn mount(p: &Profile, args: &mut Vec<String>, source: &Path, target: &str, write: bool) {
    args.extend(strings(&[
        "--volume",
        &format!(
            "{}:{target}:{}",
            source.display(),
            volume_options(write, false, p.selinux_relabel)
        ),
    ]));
}

fn create_container(
    root: &Path,
    p: &Profile,
    s: &mut State,
    role: &str,
    mut args: Vec<String>,
    start: bool,
) -> Result<()> {
    let name = format!("{}{role}", p.prefix());
    ensure!(
        !s.resources
            .iter()
            .any(|r| r.kind == "container" && r.name == name),
        "Container already recorded; stop before starting"
    );
    let existing = String::from_utf8(podman(&strings(&[
        "ps",
        "--all",
        "--format",
        "{{.Names}}",
    ]))?)?;
    ensure!(
        !existing.lines().any(|current| current == name),
        "Container name collision; unrelated resource preserved"
    );
    let cid = root.join(format!("Container{role}.id"));
    ensure!(
        !cid.exists(),
        "Container receipt exists without a resolved resource"
    );
    args.splice(1..1, strings(&["--cidfile", cid.to_str().unwrap()]));
    let mut network_ids = BTreeMap::new();
    for network_name in topology(p, role)?.keys() {
        let resource = s
            .resources
            .iter()
            .find(|r| r.kind == "network" && &r.name == network_name)
            .context("Required network is not recorded")?;
        verify(p, resource)?;
        network_ids.insert(
            network_name.clone(),
            resource
                .id
                .clone()
                .context("Network identity is unresolved")?,
        );
    }
    s.resources.push(Resource {
        kind: "container".into(),
        name: name.clone(),
        id: None,
        fingerprint: None,
        network_ids,
    });
    save(root, s)?;
    let output = podman(&args)?;
    let id = String::from_utf8(output)?.trim().to_string();
    crate::protocol::fixed_hex::<32>(&id).map_err(anyhow::Error::msg)?;
    let stored = String::from_utf8(receipt(&cid)?)?;
    ensure!(stored.trim() == id, "Container receipt mismatch");
    let value = inspect("container", &id)?;
    let r = s.resources.last_mut().unwrap();
    r.id = Some(id.clone());
    r.fingerprint = Some(fingerprint("container", &value)?);
    save(root, s)?;
    verify(p, s.resources.last().unwrap())?;
    if start {
        podman(&strings(&["start", &id]))?;
    }
    Ok(())
}
pub fn verify_image(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    let mut args = common(
        p,
        "ImageCheck",
        p.resources.memory_bytes,
        p.resources.pids,
        p.resources.cpu_quota,
    )?;
    args.extend(strings(&["--network=none", &p.image, "--version"]));
    // The image is not executed and no credentials, state or authorization are mounted.
    create_container(root, p, s, "ImageCheck", args, false)?;
    let index = s
        .resources
        .iter()
        .position(|r| r.name == format!("{}ImageCheck", p.prefix()))
        .context("Image verification resource absent")?;
    let resource = &s.resources[index];
    verify(p, resource)?;
    let result = image::verify(
        resource
            .id
            .as_deref()
            .context("Image container identity absent")?,
        &p.software_digest,
    );
    remove_container(root, p, resource)?;
    s.resources.remove(index);
    save(root, s)?;
    result
}
fn workload_args(root: &Path, p: &Profile, role: &str) -> Result<Vec<String>> {
    let mut args = common(
        p,
        role,
        p.resources.memory_bytes,
        p.resources.pids,
        p.resources.cpu_quota,
    )?;
    if role == "Authority" {
        args.extend(strings(&[
            "--network",
            &format!("{}:ip={}", p.network_name(), p.ip(20)),
            "--publish",
            &format!("{}:{}:{}", p.bind, p.port, p.port),
        ]));
    } else {
        args.push("--network=none".into());
    }
    mount(p, &mut args, &root.join("Launch/Config"), "/Config", false);
    mount(
        p,
        &mut args,
        &root.join("Launch/State/Authority"),
        "/State",
        true,
    );
    let mut control_options = String::from("rw,nosuid,nodev,noexec");
    if p.selinux_relabel {
        control_options.push_str(",z");
    }
    args.extend(strings(&[
        "--volume",
        &format!(
            "{}:/State/Control:{control_options}",
            root.join("Launch/State/Control").display()
        ),
    ]));
    mount(
        p,
        &mut args,
        &root.join("Authorization"),
        "/Authorization",
        false,
    );
    // Directory binding observes signed observation replacement without granting writes.
    args.extend(strings(&[
        "--volume",
        &format!(
            "{}:/Clock:ro,nosuid,nodev,noexec",
            p.clock_directory.display()
        ),
    ]));
    Ok(args)
}
pub fn authority(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    let mut args = workload_args(root, p, "Authority")?;
    args.extend(strings(&[
        &p.image,
        "runtime-guard",
        "--kind",
        "authority",
        "--expires",
        &p.expires.to_string(),
        "--",
        &format!("--minimum-generation={}", signer_generation(root)?),
    ]));
    create_container(root, p, s, "Authority", args, true)
}
pub fn temporary(root: &Path, p: &Profile, s: &mut State, initialise: bool) -> Result<Value> {
    let role = if initialise { "Initialise" } else { "Inspect" };
    let mut args = workload_args(root, p, role)?;
    args.extend(strings(&[
        &p.image,
        "authority-replica",
        if initialise { "initialise" } else { "status" },
        "--directory",
        "/State/Replica",
    ]));
    if initialise {
        args.extend(strings(&[
            "--bootstrap",
            "/Config/Bootstrap.cbor",
            "--bootstrap-digest",
            &p.bootstrap_digest,
            "--key",
            "/Config/Identity.json",
            "--config",
            "/Config/ReplicaConfig.json",
            "--authorization",
            "/Authorization",
        ]));
    } else {
        args.extend(strings(&[
            "--minimum-generation",
            &signer_generation(root)?.to_string(),
        ]));
    }
    run_temporary(root, p, s, role, args, MAXIMUM)
}
pub(super) fn consent_successor(
    root: &Path,
    p: &Profile,
    s: &mut State,
    previous: &str,
) -> Result<Value> {
    let role = "Inspect";
    let mut args = workload_args(root, p, role)?;
    if root.join("OperationalOffers").try_exists()? {
        mount(
            p,
            &mut args,
            &root.join("OperationalOffers"),
            "/History",
            false,
        );
    }
    args.extend(strings(&[
        &p.image,
        "authority-replica",
        "apply-consent",
        "--directory",
        "/State/Replica",
        "--minimum-generation",
        &signer_generation(root)?.to_string(),
        "--expected-profile-digest",
        previous,
        "--authorization",
        "/Authorization",
    ]));
    if root.join("OperationalOffers").try_exists()? {
        args.extend(strings(&["--history-directory", "/History"]));
    }
    run_temporary(root, p, s, role, args, MAXIMUM)
}
pub(super) fn epoch_temporary(
    root: &Path,
    p: &Profile,
    s: &mut State,
    input: &Path,
    output: Option<&Path>,
    command: &[String],
) -> Result<Value> {
    let role = "Inspect";
    let mut args = workload_args(root, p, role)?;
    mount(p, &mut args, input, "/EpochInput", false);
    if let Some(output) = output {
        mount(p, &mut args, output, "/EpochOutput", true);
    }
    args.extend(strings(&[&p.image, "authority-replica", "epoch"]));
    args.extend(command.iter().cloned());
    run_temporary(
        root,
        p,
        s,
        role,
        args,
        2 * crate::authority_capacity::MAX_STATE_BYTES
            + crate::authority_epoch::archive::MAX_ARCHIVE_BYTES
            + 1048576,
    )
}
fn run_temporary(
    root: &Path,
    p: &Profile,
    s: &mut State,
    role: &str,
    args: Vec<String>,
    maximum: usize,
) -> Result<Value> {
    create_container(root, p, s, role, args, true)?;
    let index = s
        .resources
        .iter()
        .position(|r| r.name == format!("{}{role}", p.prefix()))
        .context("Temporary container is not recorded")?;
    let result = (|| -> Result<Value> {
        let resource = &s.resources[index];
        let id = resource
            .id
            .as_deref()
            .context("Temporary identity missing")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        loop {
            let value = verify(p, resource)?;
            if value["State"]["Running"] == false {
                ensure!(
                    value["State"]["ExitCode"] == 0,
                    "Inert signer command refused; retained data was not replaced"
                );
                let (bytes, _) = capture(
                    Path::new("/usr/bin/podman"),
                    &strings(&["logs", id]),
                    45,
                    maximum,
                    32768,
                )?;
                return Ok(serde_json::from_slice(&bytes)?);
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "Inert signer command timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })();
    if result.is_err() {
        let _ = failure_diagnostic(root, p, &s.resources[index], role);
    }
    remove_container(root, p, &s.resources[index])?;
    s.resources.remove(index);
    save(root, s)?;
    result
}
fn failure_diagnostic(root: &Path, p: &Profile, resource: &Resource, role: &str) -> Result<()> {
    ensure!(
        matches!(role, "Authority" | "Initialise" | "Inspect")
            && resource.kind == "container"
            && resource.name == format!("{}{role}", p.prefix()),
        "Unexpected diagnostic resource"
    );
    let observed = verify(p, resource)?;
    let id = resource
        .id
        .as_deref()
        .context("Diagnostic identity missing")?;
    let state = &observed["State"];
    let mut record = json!({
        "stage":role,"resourceId":id,
        "state":{
            "running":state["Running"].as_bool(),
            "exitCode":state["ExitCode"].as_i64(),
            "oomKilled":state["OOMKilled"].as_bool(),
            "pid":state["Pid"].as_u64()
        }
    });
    match capture(
        Path::new("/usr/bin/podman"),
        &strings(&["logs", "--tail=64", id]),
        15,
        32768,
        32768,
    ) {
        Ok((out, err)) => {
            record["stdout"] = json!(String::from_utf8_lossy(&out));
            record["stderr"] = json!(String::from_utf8_lossy(&err));
        }
        Err(_) => record["capture"] = json!("UnavailableOrExceededBound"),
    }
    super::files::save(
        &root.join("Diagnostics").join(format!("{role}Failure.json")),
        &record,
    )
}
pub fn authority_failure(root: &Path, p: &Profile, s: &State) -> Result<()> {
    if let Some(resource) = s.resources.iter().find(|resource| {
        resource.kind == "container" && resource.name == format!("{}Authority", p.prefix())
    }) {
        failure_diagnostic(root, p, resource, "Authority")?;
    }
    Ok(())
}
fn remove_container(root: &Path, p: &Profile, r: &Resource) -> Result<()> {
    let id = r.id.as_deref().context("Unresolved container identity")?;
    if container_present(id)? {
        verify(p, r)?;
        podman(&strings(&["stop", "--time=15", id]))?;
        podman(&strings(&["rm", id]))?;
    }
    let role = r
        .name
        .strip_prefix(&p.prefix())
        .context("Invalid role name")?;
    let cid = root.join(format!("Container{role}.id"));
    if cid.exists() {
        let recorded = String::from_utf8(receipt(&cid)?)?;
        ensure!(recorded.trim() == id, "Container receipt changed");
        fs::remove_file(cid)?;
        fs::File::open(root)?.sync_all()?;
    }
    Ok(())
}
pub fn stop(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    let mut failed = false;
    for index in (0..s.resources.len()).rev() {
        if s.resources[index].kind != "container" {
            continue;
        }
        if recover_container(root, p, &mut s.resources[index]).is_err() {
            failed = true;
            continue;
        }
        if save(root, s).is_err() {
            failed = true;
        }
        let remove = remove_container(root, p, &s.resources[index]);
        if remove.is_err() {
            failed = true;
            continue;
        }
        s.resources.remove(index);
        if save(root, s).is_err() {
            failed = true;
        }
    }
    ensure!(
        !failed,
        "Exact resource recovery required; unrelated resources were preserved"
    );
    Ok(())
}
pub fn withdraw_networks(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    ensure!(
        !s.resources.iter().any(|r| r.kind == "container"),
        "Stop owned containers before releasing networking"
    );
    for index in (0..s.resources.len()).rev() {
        let resource = &s.resources[index];
        ensure!(resource.kind == "network", "Unexpected recorded resource");
        let id = resource
            .id
            .as_deref()
            .context("Unresolved network identity; withdrawal remains effective")?;
        let current: Vec<Value> =
            serde_json::from_slice(&podman(&strings(&["network", "ls", "--format", "json"]))?)?;
        let mut present = false;
        for network in &current {
            let actual = network["id"]
                .as_str()
                .context("Network listing omitted its full identity")?;
            crate::protocol::fixed_hex::<32>(actual).map_err(anyhow::Error::msg)?;
            present |= actual == id;
        }
        if present {
            verify(p, resource)?;
            podman(&strings(&["network", "rm", id]))?;
        }
        s.resources.remove(index);
        save(root, s)?;
    }
    Ok(())
}
pub fn processes(p: &Profile, s: &State) -> Result<bool> {
    for r in &s.resources {
        let value = verify(p, r)?;
        if r.kind == "container" && value["State"]["Running"] != true {
            return Ok(false);
        }
    }
    Ok(s.resources.iter().filter(|r| r.kind == "container").count() == 1)
}
pub fn live_status(p: &Profile, s: &State, minimum_generation: u64) -> Result<Value> {
    let r = s
        .resources
        .iter()
        .find(|r| r.kind == "container" && r.name == format!("{}Authority", p.prefix()))
        .context("Authority is not started")?;
    let inspected = verify(p, r)?;
    ensure!(
        inspected["State"]["Running"] == true,
        "Authority is not running"
    );
    let bytes = podman(&strings(&[
        "exec",
        r.id.as_deref().unwrap(),
        "/HyperNet",
        "authority-replica",
        "live-status",
        "--directory",
        "/State/Replica",
        "--minimum-generation",
        &minimum_generation.to_string(),
    ]))?;
    Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unnetworked_requires_none_mode_and_no_effective_attachment() {
        let empty = json!({"HostConfig":{"NetworkMode":"none"},"NetworkSettings":{"Networks":{}}});
        assert!(check_unnetworked(&empty).is_ok());
        let mut synthetic = empty.clone();
        synthetic["NetworkSettings"]["Networks"] = json!({"none":{
            "EndpointID":"", "Gateway":"", "IPAddress":"", "IPPrefixLen":0,
            "IPv6Gateway":"", "GlobalIPv6Address":"", "GlobalIPv6PrefixLen":0,
            "MacAddress":"", "NetworkID":"none", "DriverOpts":null,
            "IPAMConfig":null, "Links":null
        }});
        assert!(check_unnetworked(&synthetic).is_ok());
        for (field, hidden) in [
            ("IPAddress", json!("10.89.132.20")),
            ("Gateway", json!("10.89.132.1")),
            ("GlobalIPv6Address", json!("fd00::1")),
            ("NetworkID", json!("Authority")),
            ("DriverOpts", json!({"route":"unexpected"})),
        ] {
            let mut changed = synthetic.clone();
            changed["NetworkSettings"]["Networks"]["none"][field] = hidden;
            assert!(check_unnetworked(&changed).is_err(), "{field}");
        }
        let mut changed = synthetic.clone();
        changed["NetworkSettings"]["Networks"]["Authority"] = json!({});
        assert!(check_unnetworked(&changed).is_err());
        for mut changed in [empty, synthetic] {
            changed["HostConfig"]["NetworkMode"] = json!("host");
            assert!(check_unnetworked(&changed).is_err());
        }
    }
    #[test]
    fn effective_networks_reject_new_routes_and_changed_addresses() {
        let expected = BTreeMap::from([("Authority".into(), "10.89.132.11".into())]);
        let mut networks = json!({"Authority":{"DriverOpts":null,"IPAMConfig":null,"Links":null,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"Gateway":"","IPAddress":"","IPPrefixLen":0}});
        assert!(check_addresses(&networks, &expected, false).is_ok());
        networks["Authority"]["IPAddress"] = json!("10.89.132.11");
        networks["Authority"]["IPPrefixLen"] = json!(24);
        networks["Authority"]["Gateway"] = json!("10.89.132.1");
        assert!(check_addresses(&networks, &expected, true).is_ok());
        let mut changed = networks.clone();
        changed["Extra"] = changed["Authority"].clone();
        assert!(check_addresses(&changed, &expected, true).is_err());
        changed = networks.clone();
        changed["Authority"]["IPAddress"] = json!("10.89.132.12");
        assert!(check_addresses(&changed, &expected, true).is_err());
        changed = networks.clone();
        changed["Authority"]["Gateway"] = json!("10.89.132.254");
        assert!(check_addresses(&changed, &expected, true).is_err());
        networks["Authority"]["GlobalIPv6Address"] = json!("fd00::1");
        assert!(check_addresses(&networks, &expected, true).is_err());
    }
    #[test]
    fn mount_options_bind_exact_selinux_and_execution_modes() {
        assert_eq!(
            volume_options(false, false, false),
            "ro,nosuid,nodev,noexec"
        );
        assert_eq!(
            volume_options(false, false, true),
            "ro,nosuid,nodev,noexec,Z"
        );
        assert_eq!(
            volume_options(true, false, true),
            "rw,nosuid,nodev,noexec,Z"
        );
        assert_eq!(volume_options(false, true, false), "ro,nosuid,nodev");
        assert_eq!(volume_options(false, true, true), "ro,nosuid,nodev,Z");
    }
    #[test]
    fn inspection_normalizes_only_exact_podman_defaults() {
        let created = json!({"Id":"id","Image":"image","Config":{"Hostname":"host","Env":[],"Annotations":null},"HostConfig":{"Ulimits":[{"Name":"RLIMIT_NPROC","Soft":4096,"Hard":4096}]},"Mounts":[]});
        let mut started = created.clone();
        started["Config"]["Env"] = json!(["HOSTNAME=host", "HOME=/"]);
        started["Config"]["Annotations"] =
            json!({"io.container.manager":"libpod","org.opencontainers.image.stopSignal":"15"});
        assert_eq!(
            fingerprint("container", &created).unwrap(),
            fingerprint("container", &started).unwrap()
        );
        let mut altered = started.clone();
        altered["Config"]["Env"] = json!(["HOSTNAME=host", "HOME=/Other"]);
        assert_ne!(
            fingerprint("container", &created).unwrap(),
            fingerprint("container", &altered).unwrap()
        );
        let mut altered = started.clone();
        altered["HostConfig"]["Ulimits"][0]["Hard"] = json!(8192);
        assert_ne!(
            fingerprint("container", &created).unwrap(),
            fingerprint("container", &altered).unwrap()
        );
        started["Config"]["Annotations"]["Other"] = json!("unexpected");
        assert_ne!(
            fingerprint("container", &created).unwrap(),
            fingerprint("container", &started).unwrap()
        );
    }
    #[test]
    fn inspection_preserves_explicit_home_across_image_user_defaults() {
        for home in ["/", "/Work"] {
            let created = json!({"Id":"id","Image":"image","Config":{"Hostname":"host","Env":[format!("HOME={home}")],"Annotations":null},"HostConfig":{},"Mounts":[]});
            let mut started = created.clone();
            started["Config"]["Env"] = json!(["HOSTNAME=host", format!("HOME={home}")]);
            assert_eq!(
                fingerprint("container", &created).unwrap(),
                fingerprint("container", &started).unwrap()
            );
            started["Config"]["Env"] = json!(["HOSTNAME=host", "HOME=/Other"]);
            assert_ne!(
                fingerprint("container", &created).unwrap(),
                fingerprint("container", &started).unwrap()
            );
        }
    }
    #[test]
    fn inspection_preserves_stop_and_mount_constraints_across_start() {
        let created = json!({"Id":"id","Image":"image","Config":{"Hostname":"host","Env":[],"Annotations":null},"HostConfig":{"Annotations":null,"StopTimeout":15},"Mounts":[{"Type":"bind","Source":"/ProbeRead","Destination":"/Config","RW":false,"Options":["ro","nosuid","nodev","noexec"]}]});
        let mut started = created.clone();
        started["Config"]["Env"] = json!(["HOSTNAME=host", "HOME=/"]);
        for section in ["Config", "HostConfig"] {
            started[section]["Annotations"] = json!({
                "io.container.manager":"libpod",
                "org.opencontainers.image.stopSignal":"15",
                "org.systemd.property.KillSignal":"15",
                "org.systemd.property.TimeoutStopUSec":"uint64 15000000"
            });
        }
        let expected = fingerprint("container", &created).unwrap();
        assert_eq!(expected, fingerprint("container", &started).unwrap());
        for section in ["Config", "HostConfig"] {
            for (name, changed) in [
                ("org.systemd.property.KillSignal", "9"),
                ("org.systemd.property.TimeoutStopUSec", "uint64 30000000"),
                ("Other", "unexpected"),
            ] {
                let mut altered = started.clone();
                altered[section]["Annotations"][name] = json!(changed);
                assert_ne!(expected, fingerprint("container", &altered).unwrap());
            }
        }
        let mut altered = started.clone();
        altered["HostConfig"]["StopTimeout"] = json!(30);
        assert_ne!(expected, fingerprint("container", &altered).unwrap());
        altered = started;
        altered["Mounts"][0]["RW"] = json!(true);
        assert_ne!(expected, fingerprint("container", &altered).unwrap());
    }
}
