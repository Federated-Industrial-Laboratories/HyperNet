// SPDX-License-Identifier: MIT
// Unit tests for RuntimeContainers.
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
