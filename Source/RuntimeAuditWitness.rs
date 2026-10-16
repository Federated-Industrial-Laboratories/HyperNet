// SPDX-License-Identifier: MIT
//! An independently retained head detects forks and missing exported event tails.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WitnessPolicy {
    purpose: String,
    emitter: String,
    witness: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    purpose: String,
    witness: String,
    head: Signed<Head>,
    witnessed_at: u64,
}
pub(super) fn initialise(directory: &Path, emitter: &str) -> Result<serde_json::Value> {
    crate::trust_wire::valid_key(&hex32(emitter)?)?;
    files::safe_path(directory)?;
    files::root(
        directory
            .parent()
            .context("Private witness parent required")?,
    )?;
    ensure!(
        !directory.try_exists()?,
        "Witness directory already exists; retain its head"
    );
    files::directory(directory)?;
    let key = create_key(directory)?;
    let witness = hex::encode(key.verifying_key().to_bytes());
    let policy = WitnessPolicy {
        purpose: "HyperNetAuditWitness1".into(),
        emitter: emitter.into(),
        witness: witness.clone(),
    };
    files::create(
        &directory.join("Policy.json"),
        &serde_json::to_vec(&policy)?,
    )?;
    Ok(json!({"status":"AuditWitnessInitialised","witnessKey":witness,"emitterKey":emitter}))
}
pub(super) fn accept(directory: &Path, path: &Path, output: &Path) -> Result<serde_json::Value> {
    let root = files::root(directory)?;
    let _lock = files::lock(&root)?;
    let policy: WitnessPolicy = read(&root.join("Policy.json"), ENTRY_LIMIT)?;
    let key = key(&root)?;
    ensure!(
        policy.purpose == "HyperNetAuditWitness1"
            && policy.witness == hex::encode(key.verifying_key().to_bytes()),
        "Witness identity differs"
    );
    let batch: Batch = read(path, EXPORT_LIMIT)?;
    validate_head(&batch.base)?;
    validate_head(&batch.head)?;
    ensure!(
        batch.base.payload.scope.emitter == policy.emitter
            && batch.head.payload.scope == batch.base.payload.scope,
        "Batch differs from the independently accepted emitter"
    );
    let now = files::now()?;
    ensure!(
        batch.head.payload.recorded_at <= now,
        "Audit batch is dated in the future"
    );
    let retained = root.join("Receipt.json");
    let previous: Option<Signed<Receipt>> = if retained.try_exists()? {
        Some(read(&retained, 2 * ENTRY_LIMIT)?)
    } else {
        None
    };
    if let Some(old) = &previous {
        old.verify(&policy.witness)?;
        ensure!(
            old.payload.purpose == policy.purpose
                && old.payload.witness == policy.witness
                && old.payload.head.payload.scope.emitter == policy.emitter
                && now >= old.payload.witnessed_at,
            "Witness state or clock differs"
        );
        if old.payload.head.payload == batch.head.payload {
            files::root(output.parent().context("Private receipt parent required")?)?;
            files::create(output, &serde_json::to_vec(old)?)?;
            return Ok(
                json!({"status":"AuditHeadAlreadyWitnessed","sequence":batch.head.payload.sequence,
                "headDigest":batch.head.digest()?,"receipt":output}),
            );
        }
        ensure!(
            old.payload.head.payload == batch.base.payload,
            "Audit fork, rollback or missing exported prefix"
        );
    } else {
        ensure!(
            batch.base.payload.sequence == 0,
            "First witnessed batch must include the signed genesis head"
        );
    }
    let mut cursor = batch.base.payload.clone();
    for event in &batch.events {
        cursor = event_head(event, &cursor)?;
    }
    ensure!(
        cursor == batch.head.payload,
        "Audit batch omits or changes its declared tail"
    );
    let receipt = Signed::new(
        Receipt {
            purpose: policy.purpose,
            witness: policy.witness.clone(),
            head: batch.head,
            witnessed_at: now,
        },
        &key,
    )?;
    // Retain the head before acknowledging it. An interrupted output can be retried exactly.
    files::save(&retained, &receipt)?;
    files::root(output.parent().context("Private receipt parent required")?)?;
    files::create(output, &serde_json::to_vec(&receipt)?)?;
    Ok(
        json!({"status":"AuditHeadWitnessed","sequence":cursor.sequence,
        "headDigest":receipt.payload.head.digest()?,"witnessKey":policy.witness,"receipt":output}),
    )
}
pub(super) fn prune(
    directory: &Path,
    receipt_path: &Path,
    witness_key: &str,
) -> Result<serde_json::Value> {
    crate::trust_wire::valid_key(&hex32(witness_key)?)?;
    let root = audit_root(directory)?;
    let _lock = files::lock(&root)?;
    let (policy, key, head) = load(&root)?;
    let receipt: Signed<Receipt> = read(receipt_path, 2 * ENTRY_LIMIT)?;
    receipt.verify(witness_key)?;
    validate_head(&receipt.payload.head)?;
    ensure!(
        receipt.payload.purpose == "HyperNetAuditWitness1"
            && receipt.payload.witness == witness_key
            && witness_key != policy.scope.emitter
            && receipt.payload.head.payload.scope == policy.scope,
        "Audit receipt purpose, independent key or scope differs"
    );
    let now = files::now()?;
    ensure!(
        now >= head.payload.recorded_at
            && now >= receipt.payload.witnessed_at
            && receipt.payload.witnessed_at >= receipt.payload.head.payload.recorded_at,
        "Audit retention clock differs"
    );
    let accepted = head_at(&root, receipt.payload.head.payload.sequence, &key, &head)?;
    ensure!(
        accepted.payload == receipt.payload.head.payload,
        "Witness head is not on this retained history"
    );
    let anchor: Signed<Head> = read(&root.join("Anchor.json"), ENTRY_LIMIT)?;
    let mut cursor = anchor.payload.clone();
    let mut expired = anchor.payload.clone();
    while cursor.sequence < accepted.payload.sequence {
        let event: Signed<Event> = read(&event_path(&root, cursor.sequence + 1), ENTRY_LIMIT)?;
        cursor = event_head(&event, &cursor)?;
        if cursor
            .recorded_at
            .checked_add(policy.retention_seconds)
            .is_some_and(|t| t <= now)
        {
            expired = cursor.clone();
        }
    }
    ensure!(
        cursor == accepted.payload,
        "Witnessed history continuity differs"
    );
    let anchor = Signed::new(expired.clone(), &key)?;
    files::save(&root.join("WitnessReceipt.json"), &receipt)?;
    files::save(&root.join("Anchor.json"), &anchor)?;
    // A crash after the new anchor leaves extra expired files, never a missing live prefix.
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(number) = name
            .strip_prefix("Event")
            .and_then(|n| n.strip_suffix(".json"))
        {
            let sequence: u64 = number.parse()?;
            ensure!(
                name == format!("Event{sequence:020}.json"),
                "Unexpected audit event path"
            );
            if sequence <= expired.sequence {
                let _: Signed<Event> = read(&entry.path(), ENTRY_LIMIT)?;
                fs::remove_file(entry.path())?;
            }
        }
    }
    fs::File::open(&root)?.sync_all()?;
    Ok(
        json!({"status":"ExpiredAuditEventsPruned","throughSequence":expired.sequence,
        "witnessedSequence":accepted.payload.sequence,"retentionSeconds":policy.retention_seconds}),
    )
}
