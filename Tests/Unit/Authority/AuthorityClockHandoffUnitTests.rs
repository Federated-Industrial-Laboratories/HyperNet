// SPDX-License-Identifier: MIT
// Unit tests for AuthorityClockHandoff.
use super::*;
#[test]
fn signed_clock_expiry_only_recovers_otherwise_valid_observations() {
    let key = SigningKey::from_bytes(&[62; 32]);
    let boot = "12345678-1234-1234-1234-123456789abc";
    let old = Witness {
        version: 1,
        kernel_boot: boot.into(),
        sample_wall_ms: 10000,
        sample_boot_ms: 2000,
        valid_until_boot_ms: 3000,
        maximum_error_ms: 20,
        source: "162.159.200.1".parse().unwrap(),
    };
    let now = clock::Moment {
        wall_ms: 11000,
        boot_ms: 3000,
    };
    let check = |w: &Witness, signer: &SigningKey| {
        verify(
            &wire::sign_envelope(&payload(w)?, signer)?,
            key.verifying_key().to_bytes(),
            boot,
            now,
        )
    };
    assert!(
        check(&old, &key)
            .unwrap_err()
            .is::<clock::ObservationExpired>()
    );
    let fresh = Witness {
        sample_wall_ms: 11000,
        sample_boot_ms: 3000,
        valid_until_boot_ms: 4000,
        ..old.clone()
    };
    check(&fresh, &key).unwrap();
    for invalid in [
        Witness {
            maximum_error_ms: 251,
            ..old.clone()
        },
        Witness {
            source: "127.0.0.1".parse().unwrap(),
            ..old.clone()
        },
        Witness {
            kernel_boot: "22345678-1234-1234-1234-123456789abc".into(),
            ..old.clone()
        },
        Witness {
            valid_until_boot_ms: 2999,
            ..old.clone()
        },
        Witness {
            sample_wall_ms: 12000,
            ..old.clone()
        },
        Witness {
            sample_wall_ms: 11001,
            sample_boot_ms: 3001,
            valid_until_boot_ms: 4001,
            ..old.clone()
        },
    ] {
        assert!(
            !check(&invalid, &key)
                .unwrap_err()
                .is::<clock::ObservationExpired>()
        );
    }
    assert!(
        !check(&old, &SigningKey::from_bytes(&[63; 32]))
            .unwrap_err()
            .is::<clock::ObservationExpired>()
    );
}
#[test]
fn atomically_replaced_observations_keep_their_original_validity() {
    let directory = crate::consensus::journal::tests::Directory::new();
    let key = SigningKey::from_bytes(&[61; 32]);
    let public = key.verifying_key().to_bytes();
    let boot = "12345678-1234-1234-1234-123456789abc";
    let old = Witness {
        version: 1,
        kernel_boot: boot.into(),
        sample_wall_ms: 10000,
        sample_boot_ms: 2000,
        valid_until_boot_ms: 3000,
        maximum_error_ms: 20,
        source: "162.159.200.1".parse().unwrap(),
    };
    let current = Witness {
        sample_wall_ms: 10100,
        sample_boot_ms: 2100,
        valid_until_boot_ms: 3100,
        ..old.clone()
    };
    let before_expiry = clock::Moment {
        wall_ms: 10100,
        boot_ms: 2100,
    };
    let at_old_expiry = clock::Moment {
        wall_ms: 11000,
        boot_ms: 3000,
    };
    let signed_path = directory.0.join("ClockHealth.cbor");
    let old_signed = wire::sign_envelope(&payload(&old).unwrap(), &key).unwrap();
    let current_signed = wire::sign_envelope(&payload(&current).unwrap(), &key).unwrap();
    replace_observation(&directory.0, "ClockHealth.cbor", &old_signed, 0o644).unwrap();
    let opened = open_signed_observation(&signed_path).unwrap();
    replace_observation(&directory.0, "ClockHealth.cbor", &current_signed, 0o644).unwrap();
    assert_eq!(opened.metadata().unwrap().nlink(), 0);
    let retained = read_opened_observation(opened, false).unwrap();
    assert_eq!(retained, old_signed);
    assert!(verify(&retained, public, boot, before_expiry).is_ok());
    assert!(verify(&retained, public, boot, at_old_expiry).is_err());
    assert!(
        verify(
            &retained,
            SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
            boot,
            before_expiry
        )
        .is_err()
    );
    assert!(
        verify(
            &retained,
            public,
            "22345678-1234-1234-1234-123456789abc",
            before_expiry
        )
        .is_err()
    );
    let fresh =
        read_opened_observation(open_signed_observation(&signed_path).unwrap(), false).unwrap();
    assert_eq!(fresh, current_signed);
    assert!(verify(&fresh, public, boot, at_old_expiry).is_ok());

    let private_path = directory.0.join("ClockHealth.json");
    replace_observation(
        &directory.0,
        "ClockHealth.json",
        &serde_json::to_vec(&old).unwrap(),
        0o600,
    )
    .unwrap();
    let opened = open_observation(&private_path).unwrap();
    replace_observation(
        &directory.0,
        "ClockHealth.json",
        &serde_json::to_vec(&current).unwrap(),
        0o600,
    )
    .unwrap();
    assert_eq!(opened.metadata().unwrap().nlink(), 0);
    let retained: Witness =
        serde_json::from_slice(&read_opened_observation(opened, true).unwrap()).unwrap();
    assert!(retained.health(boot, before_expiry).is_ok());
    assert!(retained.health(boot, at_old_expiry).is_err());
    let fresh: Witness =
        serde_json::from_slice(&read_private_observation(&private_path).unwrap()).unwrap();
    assert!(fresh.health(boot, at_old_expiry).is_ok());
}
#[test]
fn observation_readers_reject_links_symlinks_oversize_and_private_permission_changes() {
    let directory = crate::consensus::journal::tests::Directory::new();
    let path = directory.0.join("ClockHealth.json");
    replace_observation(&directory.0, "ClockHealth.json", b"observation", 0o600).unwrap();
    let linked = directory.0.join("Linked.json");
    std::fs::hard_link(&path, &linked).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
    assert!(read_opened_observation(open_signed_observation(&path).unwrap(), false).is_err());
    assert!(read_private_observation(&path).is_err());
    std::fs::remove_file(&linked).unwrap();
    std::os::unix::fs::symlink(&path, &linked).unwrap();
    assert!(open_signed_observation(&linked).is_err());
    assert!(read_private_observation(&linked).is_err());
    assert!(open_signed_observation(Path::new("ClockHealth.json")).is_err());
    assert!(
        read_opened_observation(open_signed_observation(&directory.0).unwrap(), false).is_err()
    );
    assert!(read_private_observation(&directory.0).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_private_observation(&path).is_err());
    assert_eq!(
        read_opened_observation(open_signed_observation(&path).unwrap(), false).unwrap(),
        b"observation"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, vec![0; 4096]).unwrap();
    assert_eq!(read_private_observation(&path).unwrap().len(), 4096);
    std::fs::write(&path, vec![0; 4097]).unwrap();
    assert!(read_opened_observation(open_signed_observation(&path).unwrap(), false).is_err());
    assert!(read_private_observation(&path).is_err());
}
#[test]
fn transient_replacement_preserves_open_readers_and_cleans_failed_publication() {
    let directory = crate::consensus::journal::tests::Directory::new();
    let path = directory.0.join("ClockHealth.json");
    replace_observation(&directory.0, "ClockHealth.json", b"old", 0o600).unwrap();
    let mut old = OpenOptions::new().read(true).open(&path).unwrap();
    replace_observation(&directory.0, "ClockHealth.json", b"new", 0o600).unwrap();
    let mut retained = Vec::new();
    old.read_to_end(&mut retained).unwrap();
    assert_eq!(retained, b"old");
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

    let protected = directory.0.join("Protected.bin");
    std::fs::write(&protected, b"protected").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&protected, &path).unwrap();
    replace_observation(&directory.0, "ClockHealth.json", b"current", 0o600).unwrap();
    assert_eq!(std::fs::read(&protected).unwrap(), b"protected");
    assert!(std::fs::symlink_metadata(&path).unwrap().is_file());

    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(replace_observation(&directory.0, "ClockHealth.json", b"failed", 0o600).is_err());
    assert!(path.is_dir());
    assert!(std::fs::read_dir(&directory.0).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("ClockPending")
    }));
}
#[test]
fn monitor_pin_boot_expiry_and_progression_are_all_required() {
    let key = SigningKey::from_bytes(&[61; 32]);
    let boot = "12345678-1234-1234-1234-123456789abc";
    let w = Witness {
        version: 1,
        kernel_boot: boot.into(),
        sample_wall_ms: 10000,
        sample_boot_ms: 2000,
        valid_until_boot_ms: 3000,
        maximum_error_ms: 20,
        source: "162.159.200.1".parse().unwrap(),
    };
    let encoded = wire::sign_envelope(&payload(&w).unwrap(), &key).unwrap();
    let public = key.verifying_key().to_bytes();
    let now = clock::Moment {
        wall_ms: 10100,
        boot_ms: 2100,
    };
    assert!(verify(&encoded, public, boot, now).is_ok());
    assert!(
        verify(
            &encoded,
            SigningKey::from_bytes(&[62; 32]).verifying_key().to_bytes(),
            boot,
            now
        )
        .is_err()
    );
    assert!(
        verify(
            &encoded,
            public,
            "22345678-1234-1234-1234-123456789abc",
            now
        )
        .is_err()
    );
    assert!(
        verify(
            &encoded,
            public,
            boot,
            clock::Moment {
                wall_ms: 11000,
                boot_ms: 3000
            }
        )
        .is_err()
    );
    assert!(
        verify(
            &encoded,
            public,
            boot,
            clock::Moment {
                wall_ms: 10500,
                boot_ms: 2100
            }
        )
        .is_err()
    );
    assert!(
        verify(
            &encoded,
            public,
            boot,
            clock::Moment {
                wall_ms: 9999,
                boot_ms: 1999
            }
        )
        .is_err()
    );
    let mut changed = encoded.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify(&changed, public, boot, now).is_err());
}
