// SPDX-License-Identifier: MIT
use super::*;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("HyperNetDiagnostics{}", files::random_id()));
        crate::authority_files::create_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn state(marker: &str) -> model::State {
    model::State {
        version: 1,
        generation: 42,
        withdrawal_generation: 0,
        status: marker.into(),
        accepted_consent: Some(marker.into()),
        profile_digest: marker.into(),
        resources: vec![model::Resource {
            kind: marker.into(),
            name: marker.into(),
            id: Some(marker.into()),
            fingerprint: Some(marker.into()),
            network_ids: BTreeMap::from([(marker.into(), marker.into())]),
        }],
        initialised: true,
        last_time: 12345678,
        failure_code: Some(marker.into()),
        receipts: BTreeMap::from([(
            marker.into(),
            model::Receipt {
                request_digest: marker.into(),
                result: json!({"body":marker}),
            },
        )]),
        pending: Some(marker.into()),
    }
}
#[test]
fn authority_snapshot_never_copies_untrusted_strings_or_identities() {
    let marker = "PrivateCanary\u{1b}[31mhttps://secret.invalid/query";
    let bytes = encode(&authority(&state(marker))).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("PrivateCanary"));
    assert!(!text.contains("secret.invalid"));
    assert!(!text.contains("12345678"));
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["recorded"]["state"], "Unknown");
    assert_eq!(value["recorded"]["failureCode"], "Unknown");
    assert_eq!(value["recorded"]["generation"], 42);
    assert_eq!(value["recorded"]["resourceCount"], 1);
    assert_eq!(value["recorded"]["pendingOperation"], true);
    assert_eq!(value["currentAuthority"], false);
    assert_eq!(value["readinessProbed"], false);
    assert_eq!(value["networkUsed"], false);
}
#[test]
fn service_snapshot_reports_recorded_consent_without_inventing_readiness() {
    for (role, expected) in [
        (1, "Page"),
        (2, "Media"),
        (3, "Mail"),
        (4, "Transfer"),
        (5, "PrivateRoute"),
        (7, "Bridge"),
        (8, "Ssh"),
    ] {
        let value = serde_json::to_value(service(role, true, false, true, 4)).unwrap();
        assert_eq!(value["recorded"]["role"], expected);
        assert_eq!(value["recorded"]["state"], "Consented");
        assert_eq!(value["recorded"]["generation"], 1);
        assert_eq!(value["recorded"]["resourceCount"], 4);
        assert!(value["recorded"]["pendingOperation"].is_null());
        assert_eq!(value["readinessProbed"], false);
        let withdrawn = serde_json::to_value(service(role, true, true, true, 1)).unwrap();
        assert_eq!(withdrawn["recorded"]["state"], "Withdrawn");
        assert_eq!(withdrawn["recorded"]["withdrawalGeneration"], 1);
    }
}
#[test]
fn nonblocking_diagnosis_uses_the_existing_lifecycle_lock_and_fixed_errors() {
    let directory = Directory::new();
    let lock = files::lock(&directory.0).unwrap();
    assert!(files::try_lock(&directory.0).is_err());
    let busy = encode(&collect_authority(&directory.0)).unwrap();
    assert_eq!(busy, encode(&unavailable(true)).unwrap());
    drop(lock);
    let retry = files::try_lock(&directory.0).unwrap();
    assert!(files::try_lock(&directory.0).is_err());
    drop(retry);
    crate::authority_files::write_new(
        &directory.0.join("Profile.json"),
        br#"{"deployment":"PrivateCanary","error":"\u001b[31m"}"#,
    )
    .unwrap();
    assert_eq!(encode(&collect_authority(&directory.0)).unwrap(), busy);
    let service = super::super::services::run(super::super::services::Command::Diagnose(Options {
        directory: directory.0.clone(),
        output: None,
        preview_digest: None,
    }))
    .unwrap();
    assert_eq!(service["snapshot"]["availability"], "UnavailableOrInvalid");
    assert!(
        !serde_json::to_string(&service)
            .unwrap()
            .contains("PrivateCanary")
    );
    let entries: Vec<_> = fs::read_dir(&directory.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 2);
}
#[test]
fn export_binds_selected_bytes_and_refuses_changes_overwrites_and_symlinks() {
    let directory = Directory::new();
    let snapshot = service(1, true, false, true, 1);
    let bytes = encode(&snapshot).unwrap();
    let expected = files::hex_digest(&bytes);
    let output = directory.0.join("Diagnostic.json");
    let changed = encode(&service(1, true, true, true, 1)).unwrap();
    assert_eq!(
        export(&changed, &expected, &output)
            .unwrap_err()
            .to_string(),
        "DiagnosticSnapshotChanged"
    );
    assert!(!output.exists());
    assert_eq!(
        export(&bytes, "SecretCanary", &output)
            .unwrap_err()
            .to_string(),
        "DiagnosticPreviewDigestInvalid"
    );
    export(&bytes, &expected, &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        export(&changed, &files::hex_digest(&changed), &output)
            .unwrap_err()
            .to_string(),
        "DiagnosticOutputUnavailable"
    );
    assert_eq!(fs::read(&output).unwrap(), bytes);
    symlink(&output, directory.0.join("Link.json")).unwrap();
    assert!(export(&bytes, &expected, &directory.0.join("Link.json")).is_err());
    symlink(&directory.0, directory.0.join("LinkDirectory")).unwrap();
    assert!(
        export(
            &bytes,
            &expected,
            &directory.0.join("LinkDirectory/New.json")
        )
        .is_err()
    );
    assert!(!directory.0.join("New.json").exists());
    let public = directory.0.join("Public");
    fs::create_dir(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(export(&bytes, &expected, &public.join("New.json")).is_err());
    assert!(!public.join("New.json").exists());
}
