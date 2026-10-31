// SPDX-License-Identifier: MIT
// Compare exact resource configuration across documented container startup defaults.
use super::super::files::hex_digest;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

fn normalise_work_ownership(config: &Value, host: &mut Value) -> Result<()> {
    let Some(options) = host["Tmpfs"]["/Work"].as_str() else {
        return Ok(());
    };
    let mut parts: Vec<&str> = options.split(',').collect();
    if let Some(index) = parts.iter().position(|p| *p == "U") {
        ensure!(
            config["User"] == "1000:1000"
                && parts.iter().filter(|p| **p == "U").count() == 1
                && !parts
                    .iter()
                    .any(|p| p.starts_with("uid=") || p.starts_with("gid=")),
            "Unexpected tmpfs ownership configuration"
        );
        // Podman resolves U to this explicit container user's IDs at first start.
        parts.splice(index..=index, ["uid=1000", "gid=1000"]);
        host["Tmpfs"]["/Work"] = json!(parts.join(","));
    }
    Ok(())
}
pub(super) fn of(kind: &str, v: &Value) -> Result<String> {
    let selected = if kind == "network" {
        json!({"id":v["id"],"name":v["name"],"subnets":v["subnets"],"internal":v["internal"],"labels":v["labels"],"driver":v["driver"],"networkInterface":v["network_interface"],"dnsEnabled":v["dns_enabled"],"ipv6Enabled":v["ipv6_enabled"],"options":v["options"],"ipamOptions":v["ipam_options"]})
    } else {
        let mut config = v["Config"].clone();
        let mut host = v["HostConfig"].clone();
        normalise_work_ownership(&config, &mut host)?;
        // Podman adds these defaults at first start, including HostConfig on 5.7.
        // The signal and timeout match the fixed 15-second stop configuration.
        // Preserve every supplied value so altered annotations remain detectable.
        for section in [&mut config, &mut host] {
            if section["Annotations"].is_null() {
                section["Annotations"] = json!({});
            }
            let annotations = section["Annotations"]
                .as_object_mut()
                .context("Invalid annotations")?;
            for (name, value) in [
                ("io.container.manager", "libpod"),
                ("org.opencontainers.image.stopSignal", "15"),
                ("org.systemd.property.KillSignal", "15"),
                ("org.systemd.property.TimeoutStopUSec", "uint64 15000000"),
            ] {
                annotations.entry(name).or_insert(json!(value));
            }
        }
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

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeContainerFingerprintUnitTests.rs"]
mod tests;
