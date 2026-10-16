// SPDX-License-Identifier: MIT
use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("HyperNetAudit{}", files::random_id()));
        files::directory(&root).unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn interrupted_append_keeps_identity_and_missing_retained_tail_refuses() {
    let directory = Directory::new();
    let manifest = crate::runtime_manifest::tests::fixture();
    initialise(&directory.0, &manifest).unwrap();
    let root = audit_root(&directory.0).unwrap();
    let old_head = files::read(&root.join("Head.json"), ENTRY_LIMIT).unwrap();
    record(&directory.0, &manifest, "Consent", "Prepared").unwrap();
    let (_, _, expected) = load(&root).unwrap();
    let before: Signed<Head> = serde_json::from_slice(&old_head).unwrap();
    files::save(&root.join("Head.json"), &before).unwrap();
    let (_, _, recovered) = load(&root).unwrap();
    assert_eq!(recovered.digest().unwrap(), expected.digest().unwrap());
    assert_eq!(recovered.payload.sequence, 2);
    fs::remove_file(event_path(&root, 2)).unwrap();
    assert!(load(&root).is_err());
    assert!(initialise(&directory.0, &manifest).is_err());
}

#[test]
fn independent_witness_rejects_validly_signed_fork_and_unwitnessed_pruning() {
    let directory = Directory::new();
    let manifest = crate::runtime_manifest::tests::fixture();
    initialise(&directory.0, &manifest).unwrap();
    let root = audit_root(&directory.0).unwrap();
    let (policy, signer, head) = load(&root).unwrap();
    let witness_path = directory.0.join("Witness");
    let result = witness::initialise(&witness_path, &policy.scope.emitter).unwrap();
    let witness_key = result["witnessKey"].as_str().unwrap();
    let batch_path = directory.0.join("Batch.json");
    export(&directory.0, 0, &batch_path).unwrap();
    let receipt = directory.0.join("Receipt.json");
    witness::accept(&witness_path, &batch_path, &receipt).unwrap();
    witness::accept(&witness_path, &batch_path, &directory.0.join("Retry.json")).unwrap();
    let report = witness::prune(&directory.0, &receipt, witness_key).unwrap();
    assert_eq!(report["throughSequence"], 0);
    assert!(event_path(&root, 1).exists());
    assert!(witness::prune(&directory.0, &receipt, &policy.scope.emitter).is_err());

    let mut batch: Batch = read(&batch_path, EXPORT_LIMIT).unwrap();
    let event = &mut batch.events[0];
    event.payload.outcome = "Failed".into();
    *event = Signed::new(event.payload.clone(), &signer).unwrap();
    batch.head = Signed::new(event_head(event, &batch.base.payload).unwrap(), &signer).unwrap();
    files::save(&batch_path, &batch).unwrap();
    assert!(witness::accept(&witness_path, &batch_path, &directory.0.join("Fork.json")).is_err());
    let (_, _, current) = load(&root).unwrap();
    assert_eq!(head.digest().unwrap(), current.digest().unwrap());
}

#[test]
fn event_schema_excludes_unstructured_messages_and_forged_metadata() {
    let directory = Directory::new();
    let manifest = crate::runtime_manifest::tests::fixture();
    initialise(&directory.0, &manifest).unwrap();
    assert!(record(&directory.0, &manifest, "Secret body or query", "Committed").is_err());
    let root = audit_root(&directory.0).unwrap();
    let output = directory.0.join("Batch.json");
    export(&directory.0, 0, &output).unwrap();
    let mut batch: Batch = read(&output, EXPORT_LIMIT).unwrap();
    batch.events[0].payload.software_digest = hex::encode([1; 32]);
    assert!(event_head(&batch.events[0], &batch.base.payload).is_err());
    let (_, _, head) = load(&root).unwrap();
    assert_eq!(head.payload.sequence, 1);
}

#[test]
fn expired_witnessed_prefix_prunes_without_breaking_the_next_append() {
    let directory = Directory::new();
    let manifest = crate::runtime_manifest::tests::fixture();
    initialise(&directory.0, &manifest).unwrap();
    let root = audit_root(&directory.0).unwrap();
    let (mut policy, _, _) = load(&root).unwrap();
    policy.retention_seconds = 1;
    files::save(&root.join("Policy.json"), &policy).unwrap();
    let witness_path = directory.0.join("Witness");
    let result = witness::initialise(&witness_path, &policy.scope.emitter).unwrap();
    let witness_key = result["witnessKey"].as_str().unwrap();
    let batch = directory.0.join("Batch.json");
    let receipt = directory.0.join("Receipt.json");
    export(&directory.0, 0, &batch).unwrap();
    witness::accept(&witness_path, &batch, &receipt).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let pruned = witness::prune(&directory.0, &receipt, witness_key).unwrap();
    assert_eq!(pruned["throughSequence"], 1);
    assert!(!event_path(&root, 1).exists());
    record(&directory.0, &manifest, "Stop", "Committed").unwrap();
    let next = directory.0.join("Next.json");
    export(&directory.0, 1, &next).unwrap();
    witness::accept(&witness_path, &next, &directory.0.join("NextReceipt.json")).unwrap();
    assert!(export(&directory.0, 0, &directory.0.join("Missing.json")).is_err());
}

#[test]
fn lowering_budget_cannot_leave_the_configuration_outcome_unwritable() {
    let directory = Directory::new();
    let manifest = crate::runtime_manifest::tests::fixture();
    files::directory(&directory.0.join("Authorization")).unwrap();
    files::create(
        &directory.0.join("Authorization/Manifest.cbor"),
        &manifest.encode().unwrap(),
    )
    .unwrap();
    initialise(&directory.0, &manifest).unwrap();
    let root = audit_root(&directory.0).unwrap();
    while retained_bytes(&root).unwrap() < 65536 {
        record(&directory.0, &manifest, "Stop", "Committed").unwrap();
    }
    let original = files::read(&root.join("Policy.json"), ENTRY_LIMIT).unwrap();
    assert!(
        run(Command::Configure {
            directory: directory.0.clone(),
            maximum_bytes: 65536,
            retention_seconds: 1,
        })
        .is_err()
    );
    assert_eq!(
        files::read(&root.join("Policy.json"), ENTRY_LIMIT).unwrap(),
        original
    );
    record(&directory.0, &manifest, "Stop", "Committed").unwrap();
}
