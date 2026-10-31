// SPDX-License-Identifier: MIT
// Unit tests for RuntimeContainerFingerprint.
use super::*;
#[test]
fn work_tmpfs_startup_resolves_only_exact_consented_ownership() {
    let options = "rw,noexec,nosuid,nodev,size=134217728,mode=0700,U,rprivate,tmpcopyup";
    let created = json!({"Id":"id","Image":"image",
        "Config":{"User":"1000:1000","Hostname":"host","Env":["HOME=/Work"]},
        "HostConfig":{"Tmpfs":{"/Work":options}},"Mounts":[]});
    let mut started = created.clone();
    started["HostConfig"]["Tmpfs"]["/Work"] = json!(options.replace(",U,", ",uid=1000,gid=1000,"));
    let expected = of("container", &created).unwrap();
    assert_eq!(expected, of("container", &started).unwrap());
    for (before, after) in [
        ("uid=1000", "uid=0"),
        ("gid=1000", "gid=0"),
        ("0700", "0777"),
        ("134217728", "268435456"),
        ("noexec", "exec"),
        ("nosuid", "suid"),
        ("nodev", "dev"),
    ] {
        let mut altered = started.clone();
        altered["HostConfig"]["Tmpfs"]["/Work"] = json!(
            started["HostConfig"]["Tmpfs"]["/Work"]
                .as_str()
                .unwrap()
                .replace(before, after)
        );
        assert_ne!(expected, of("container", &altered).unwrap());
    }
    for user in ["0:0", "1000:0", "Other"] {
        let mut altered = created.clone();
        altered["Config"]["User"] = json!(user);
        assert!(of("container", &altered).is_err());
    }
}
