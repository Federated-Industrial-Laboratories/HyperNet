// SPDX-License-Identifier: MIT
use super::model::save;
use super::{files::*, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};
#[path = "RuntimePreparation.rs"]
mod preparation;
pub use preparation::prepare;

fn topology(p: &Profile, role: &str) -> Result<BTreeMap<String, String>> {
    let a = p.subnet.octets();
    let host_ip = |last| format!("{}.{}.{}.{last}", a[0], a[1], a[2] + 1);
    Ok(match role {
        "Voter1" => [(p.network_name(), p.ip(11))].into(),
        "Voter2" => [(p.network_name(), p.ip(12))].into(),
        "Voter3" => [(p.network_name(), p.ip(13))].into(),
        "Authority" => [(p.network_name(), p.ip(20))].into(),
        "Gate" => [
            (p.network_name(), p.ip(21)),
            (p.host_network_name(), host_ip(3)),
        ]
        .into(),
        "Host" => [(p.host_network_name(), host_ip(2))].into(),
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
                    && matches!(value["Gateway"].as_str(), Some("" | "<nil>")),
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
    check_addresses(
        &value["NetworkSettings"]["Networks"],
        &expected,
        value["State"]["Running"] == true,
    )?;
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
                && network["internal"] == true
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

fn inspect(kind: &str, id: &str) -> Result<Value> {
    let bytes = podman(&strings(&[kind, "inspect", id]))?;
    let value: Value = serde_json::from_slice(&bytes)?;
    value
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .context("Missing resource inspection")
}
fn fingerprint(kind: &str, v: &Value) -> Result<String> {
    let selected = if kind == "network" {
        json!({"id":v["id"],"name":v["name"],"subnets":v["subnets"],"internal":v["internal"],"labels":v["labels"],"driver":v["driver"],"networkInterface":v["network_interface"],"dnsEnabled":v["dns_enabled"],"ipv6Enabled":v["ipv6_enabled"],"options":v["options"],"ipamOptions":v["ipam_options"]})
    } else {
        let mut config = v["Config"].clone();
        let host = v["HostConfig"].clone();
        // Podman supplies these informational defaults when a created container starts.
        if config["Annotations"].is_null() {
            config["Annotations"] = json!({});
        }
        let annotations = config["Annotations"]
            .as_object_mut()
            .context("Invalid annotations")?;
        annotations
            .entry("io.container.manager")
            .or_insert(json!("libpod"));
        annotations
            .entry("org.opencontainers.image.stopSignal")
            .or_insert(json!("15"));
        let hostname = config["Hostname"]
            .as_str()
            .context("Missing hostname")?
            .to_string();
        let environment = config["Env"]
            .as_array_mut()
            .context("Invalid environment")?;
        for (name, value) in [("HOME", "/"), ("HOSTNAME", hostname.as_str())] {
            if !environment.iter().any(|item| {
                item.as_str()
                    .is_some_and(|s| s.starts_with(&format!("{name}=")))
            }) {
                environment.push(json!(format!("{name}={value}")));
            }
        }
        environment.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        json!({"Id":v["Id"],"Image":v["Image"],"Config":config,"HostConfig":host,"Mounts":v["Mounts"],"MountLabel":v["MountLabel"],"ProcessLabel":v["ProcessLabel"]})
    };
    Ok(hex_digest(&serde_json::to_vec(&selected)?))
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
fn container_present(id: &str) -> Result<bool> {
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
pub fn network(root: &Path, p: &Profile, s: &mut State, host: bool) -> Result<()> {
    let name = if host {
        p.host_network_name()
    } else {
        p.network_name()
    };
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
    let octets = p.subnet.octets();
    let subnet = if host {
        format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2] + 1)
    } else {
        format!("{}/24", p.subnet)
    };
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
        "--internal",
        "--disable-dns",
        "--subnet",
        &subnet,
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
fn common(p: &Profile, role: &str, memory: u64, pids: u32, quota: u32) -> Result<Vec<String>> {
    let lifetime = p.expires.checked_sub(now()?).context("Consent expired")?;
    ensure!(lifetime > 0, "Consent expired");
    let mut args = strings(&[
        "create",
        "--name",
        &format!("{}{role}", p.prefix()),
        "--pull=never",
        "--read-only",
        "--read-only-tmpfs=false",
        "--userns=nomap",
        "--user=0:0",
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
        "--cpu-period=100000",
        &format!("--cpu-quota={quota}"),
        &format!("--timeout={lifetime}"),
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

fn create_start(
    root: &Path,
    p: &Profile,
    s: &mut State,
    role: &str,
    mut args: Vec<String>,
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
    podman(&strings(&["start", &id]))?;
    Ok(())
}
pub fn voters(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    for i in 1..=3 {
        let role = format!("Voter{i}");
        let mut args = common(p, &role, 536870912, 128, 100000)?;
        args.extend(strings(&[
            "--network",
            &format!("{}:ip={}", p.network_name(), p.ip(10 + i)),
            "--publish",
            &format!("127.0.0.1:{}:2379", p.voter_port_base + u16::from(i) - 1),
        ]));
        args.extend(strings(&[
            "--volume",
            &format!(
                "{}:/Etcd:{}",
                p.etcd.display(),
                volume_options(false, true, p.selinux_relabel)
            ),
        ]));
        mount(
            p,
            &mut args,
            &root.join(format!("Launch/{role}/Config")),
            "/Config",
            false,
        );
        mount(
            p,
            &mut args,
            &root.join(format!("Launch/{role}/State")),
            "/State",
            true,
        );
        args.extend(strings(&[
            &p.image,
            "runtime-guard",
            "--kind",
            "voter",
            "--expires",
            &p.expires.to_string(),
            "--",
            &format!("--name={role}"),
            "--data-dir=/State",
            "--listen-client-urls=https://0.0.0.0:2379",
            &format!("--advertise-client-urls=https://{}:2379", p.ip(10 + i)),
            "--listen-peer-urls=https://0.0.0.0:2380",
            &format!(
                "--initial-advertise-peer-urls=https://{}:2380",
                p.ip(10 + i)
            ),
            &format!(
                "--initial-cluster={}",
                (1..=3)
                    .map(|n| format!("Voter{n}=https://{}:2380", p.ip(10 + n)))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            &format!("--initial-cluster-token={}", p.deployment),
            &format!("--cert-file=/Config/{role}.pem"),
            &format!("--key-file=/Config/{role}Key.pem"),
            "--client-cert-auth",
            "--trusted-ca-file=/Config/VoterCa.pem",
            &format!("--peer-cert-file=/Config/{role}Peer.pem"),
            &format!("--peer-key-file=/Config/{role}PeerKey.pem"),
            "--peer-client-cert-auth",
            "--peer-trusted-ca-file=/Config/PeerCa.pem",
            "--peer-cert-allowed-cn=HyperNetVoter",
            "--tls-min-version=TLS1.3",
            "--tls-max-version=TLS1.3",
            "--quota-backend-bytes=67108864",
            "--max-wals=2",
            "--max-snapshots=2",
            "--snapshot-count=100",
            "--auto-compaction-retention=1m",
            "--enable-grpc-gateway=false",
        ]));
        create_start(root, p, s, &role, args)?;
    }
    Ok(())
}
pub fn authority(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    podman(&strings(&[
        "unshare",
        "/usr/bin/chown",
        "-R",
        "1:1",
        root.join("AuthorityState").to_str().unwrap(),
    ]))?;
    let mut args = common(p, "Authority", 536870912, 64, 100000)?;
    args.extend(strings(&[
        "--network",
        &format!("{}:ip={}", p.network_name(), p.ip(20)),
        "--publish",
        &format!("{}:{}:8443", p.bind, p.port),
        "--ulimit=fsize=65536:65536",
    ]));
    mount(
        p,
        &mut args,
        &root.join("Launch/Authority"),
        "/Config",
        false,
    );
    mount(p, &mut args, &root.join("AuthorityState"), "/State", true);
    args.extend(strings(&[
        &p.image,
        "runtime-guard",
        "--kind",
        "authority",
        "--expires",
        &p.expires.to_string(),
    ]));
    create_start(root, p, s, "Authority", args)
}
pub fn host(root: &Path, p: &Profile, s: &mut State) -> Result<()> {
    let a = p.subnet.octets();
    let gate = format!("{}.{}.{}.3", a[0], a[1], a[2] + 1);
    let host = format!("{}.{}.{}.2", a[0], a[1], a[2] + 1);
    let mut args = common(p, "Gate", 134217728, 32, 50000)?;
    args.extend(strings(&[
        "--network",
        &format!("{}:ip={gate}", p.host_network_name()),
        "--network",
        &format!("{}:ip={}", p.network_name(), p.ip(21)),
        "--tmpfs=/State:rw,noexec,nosuid,nodev,size=8388608,mode=0700",
    ]));
    mount(p, &mut args, &root.join("Launch/Gate"), "/Config", false);
    args.extend(strings(&[
        "--entrypoint=/HyperNetGate",
        &p.image,
        "/Config/Gate.json",
    ]));
    create_start(root, p, s, "Gate", args)?;
    let mut args = common(p, "Host", 134217728, 32, 50000)?;
    args.extend(strings(&[
        "--network",
        &format!("{}:ip={host}", p.host_network_name()),
        "--tmpfs=/State:rw,noexec,nosuid,nodev,size=8388608,mode=0700",
    ]));
    mount(p, &mut args, &root.join("Launch/Host"), "/Config", false);
    args.extend(strings(&[
        &p.image,
        "host",
        "--config",
        "/Config/Host.json",
    ]));
    create_start(root, p, s, "Host", args)
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
        let r = &s.resources[index];
        let id = r.id.as_deref().unwrap();
        let remove = (|| -> Result<()> {
            if container_present(id)? {
                verify(p, r)?;
                podman(&strings(&["stop", "--time=2", id]))?;
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
            }
            Ok(())
        })();
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
pub fn processes(p: &Profile, s: &State) -> Result<bool> {
    for r in &s.resources {
        let value = verify(p, r)?;
        if r.kind == "container" && value["State"]["Running"] != true {
            return Ok(false);
        }
    }
    Ok(s.resources.iter().filter(|r| r.kind == "container").count() == 6)
}
pub fn host_status(p: &Profile, s: &State) -> Result<Value> {
    let r = s
        .resources
        .iter()
        .find(|r| r.kind == "container" && r.name == format!("{}Host", p.prefix()))
        .context("Host is not started")?;
    verify(p, r)?;
    let bytes = podman(&strings(&["logs", "--tail=1", r.id.as_deref().unwrap()]))?;
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["active"] == true
            && v["leaseExpires"]
                .as_u64()
                .is_some_and(|t| t > now().unwrap_or(u64::MAX)),
        "Host lease is not current"
    );
    Ok(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_networks_reject_new_routes_and_changed_addresses() {
        let expected = BTreeMap::from([("Authority".into(), "10.89.132.11".into())]);
        let mut networks = json!({"Authority":{"DriverOpts":null,"IPAMConfig":null,"Links":null,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"Gateway":"","IPAddress":"","IPPrefixLen":0}});
        assert!(check_addresses(&networks, &expected, false).is_ok());
        networks["Authority"]["IPAddress"] = json!("10.89.132.11");
        networks["Authority"]["IPPrefixLen"] = json!(24);
        networks["Authority"]["Gateway"] = json!("<nil>");
        assert!(check_addresses(&networks, &expected, true).is_ok());
        let mut changed = networks.clone();
        changed["Extra"] = changed["Authority"].clone();
        assert!(check_addresses(&changed, &expected, true).is_err());
        changed = networks.clone();
        changed["Authority"]["IPAddress"] = json!("10.89.132.12");
        assert!(check_addresses(&changed, &expected, true).is_err());
        changed = networks.clone();
        changed["Authority"]["Gateway"] = json!("10.89.132.1");
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
}
