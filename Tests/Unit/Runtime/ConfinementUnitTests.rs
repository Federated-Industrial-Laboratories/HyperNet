// SPDX-License-Identifier: MIT
// Unit tests for Confinement.
use super::*;
#[test]
fn authority_read_roots_do_not_expand_other_roles_or_arbitrary_paths() {
    for root in ["/Clock", "/Authorization", "/Authority"] {
        assert_eq!(
            read_root(Path::new(root), true, InputMounts::None).unwrap(),
            Path::new(root)
        );
        assert!(read_root(Path::new(root), false, InputMounts::None).is_err());
    }
    for authority in [false, true] {
        assert_eq!(
            read_root(
                Path::new("/Config/Tls/Certificate.pem"),
                authority,
                InputMounts::None
            )
            .unwrap(),
            Path::new("/Config")
        );
        for rejected in [
            "/",
            "/etc",
            "/State",
            "/proc",
            "/Clock/Observation.json",
            "/Authorization/Consent.cbor",
            "/Clock/../etc",
            "/ConfigOther",
            "Config/Tls",
        ] {
            assert!(
                read_root(Path::new(rejected), authority, InputMounts::None).is_err(),
                "{rejected}"
            );
        }
    }
}
#[test]
fn bridge_media_access_requires_an_exact_control_directory_and_role() {
    let host = "ab".repeat(32);
    let selected = PathBuf::from(format!("/Media/{host}/Control"));
    assert_eq!(
        read_root(&selected, true, InputMounts::Bridge).unwrap(),
        selected
    );
    assert!(read_root(&selected, true, InputMounts::None).is_err());
    assert!(read_root(&selected, false, InputMounts::None).is_err());
    assert!(read_root(&selected, false, InputMounts::Bridge).is_err());
    for path in [
        "/Media".into(),
        format!("/Media/{host}"),
        format!("/Media/{host}/State"),
        format!("/Media/{host}/Control/Control.sock"),
        format!("/Media/{host}/Control/../Control"),
        format!("/Media/{host}/../Control"),
        format!("/Media//{host}/Control"),
        format!("/Media/{}/Control", host.to_uppercase()),
        "/Media/ab/Control".into(),
        format!("Media/{host}/Control"),
    ] {
        assert!(
            read_root(Path::new(&path), true, InputMounts::Bridge).is_err(),
            "{path}"
        );
    }
}
#[test]
fn route_socket_mounts_are_exact_and_do_not_expand_other_roles() {
    for root in ["/Egress", "/Application"] {
        let path = Path::new(root);
        assert_eq!(read_root(path, true, InputMounts::Route).unwrap(), path);
        assert!(read_root(path, false, InputMounts::Route).is_err());
        for mounts in [InputMounts::None, InputMounts::Bridge] {
            assert!(read_root(path, true, mounts).is_err());
        }
    }
    for rejected in [
        "/",
        "/State",
        "/Egress/Egress.sock",
        "/Application/Control.sock",
        "/Egress/../Application",
        "/ApplicationOther",
        "Application",
    ] {
        assert!(read_root(Path::new(rejected), true, InputMounts::Route).is_err());
    }
    let media = PathBuf::from(format!("/Media/{}/Control", "ab".repeat(32)));
    assert!(read_root(&media, true, InputMounts::Route).is_err());
}
#[test]
fn nomap_excludes_the_login_identity_in_the_parent_namespace() {
    assert!(require_subordinate_mapping("0 1 65536\n").is_ok());
    assert!(require_subordinate_mapping("0 1000 1\n1 100000 65536\n").is_err());
    assert!(require_subordinate_mapping("0 1 1000\n1000 0 1\n1001 1001 64536\n").is_err());
    assert!(require_subordinate_mapping("0 0 65536\n").is_err());
    assert!(require_subordinate_mapping("").is_err());
}

#[test]
fn canonical_grants_reject_parent_and_symlink_escape() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "HyperNetConfinement{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let inside = directory.join("Inside");
    let outside = directory.join("Outside");
    fs::create_dir(&inside).unwrap();
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, inside.join("Escape")).unwrap();
    assert!(confined_path(&inside, &inside).is_ok());
    assert!(confined_path(&inside.join("../Outside"), &inside).is_err());
    assert!(confined_path(&inside.join("Escape"), &inside).is_err());
    fs::remove_dir_all(directory).unwrap();
}
