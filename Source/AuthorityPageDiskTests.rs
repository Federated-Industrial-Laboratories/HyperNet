// SPDX-License-Identifier: MIT
// Interrupted cache publication preserves pinned exact bundles and never opens corruption as empty state.
use super::*;
use crate::{
    authority_deployment_tests as deployment,
    authority_domains::page::{self, objects},
    authority_proof::VersionRef,
};
fn bundle(page_id: [u8; 16]) -> Object {
    let body = b"HyperNetPage/2\n# Bookshop\n: Approved opening hours.\n";
    let source = Reference::for_bytes(Class::PageSource, body).unwrap();
    let grant = VersionRef {
        kind: 102,
        id: [23; 32],
        generation: 1,
        digest: [82; 32],
    };
    let parameters =
        objects::Author::parameters(page_id, "Books", body, &grant, None, 600000).unwrap();
    let bytes = deployment::signed(
        &deployment::key(5),
        "PageAuthorStatement",
        page::page_id(&page_id).unwrap(),
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let author = objects::Author::parse(&bytes, [20; 32], [21; 32]).unwrap();
    let revision = domains::Record::next(
        &domains::State::empty([20; 32], [21; 32]),
        141,
        page::revision_id(author.intent.resource, 1).unwrap(),
        page::Revision::from_source(author.clone(), body)
            .unwrap()
            .value(),
    )
    .unwrap();
    let parameters = objects::Reviewer::parameters(
        &revision.reference,
        &source,
        author.intent.requester,
        author.intent.digest,
        &grant,
        None,
        true,
        0,
        None,
        10000,
    )
    .unwrap();
    let reviewed = deployment::signed(
        &deployment::key(5),
        "PageReviewStatement",
        author.intent.resource,
        1,
        wire::decode(&parameters).unwrap(),
        vec![],
    );
    let bytes = objects::Bundle::encode(body, &author.bytes, &reviewed).unwrap();
    Object::verify(
        Reference::for_bytes(Class::PageBundle, &bytes).unwrap(),
        bytes,
    )
    .unwrap()
}
fn resolve(object: Object) -> Resolved {
    Resolved::exact(&[object.reference().clone()], vec![object]).unwrap()
}
#[test]
fn page_cache_recovers_torn_successor_and_preserves_pending_bundle_within_physical_budget() {
    let manifest = deployment::manifest();
    let first = bundle([71; 16]);
    let second = bundle([72; 16]);
    let service = manifest.services()[&1];
    let domain = domains::State::empty(manifest.network, manifest.incarnation);
    let state = State {
        label: "AuthorityPageStorage".into(),
        network: manifest.network,
        incarnation: manifest.incarnation,
        service,
        time: 2000,
        domain: domain.clone(),
        governance: vec![],
        payload: vec![],
        records: BTreeMap::from([(
            first.reference().identity(),
            Entry {
                object: first.clone(),
                expires: 100000,
                used: 2000,
            },
        )]),
    };
    let physical = 2
        * (wire::encode_bounded(&state.value(), 1024 * 1024)
            .unwrap()
            .len() as u64
            + HEADER);
    let mut profile = HostProfile {
        manifest: manifest.clone(),
        role: 1,
        service,
        volume: [101; 32],
        namespaces: vec!["Books".into()],
        state_bytes: physical,
        maximum_asset_bytes: crate::authority_objects::PAGE_BUNDLE_BYTES.min(physical as usize)
            as u64,
        retention_ms: 98000,
        content: None,
        envelope: vec![],
    };
    profile.envelope =
        wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
    let profile =
        HostProfile::parse(&profile.envelope, manifest.network, manifest.incarnation).unwrap();
    let path = std::env::temp_dir().join(format!(
        "HyperNetPageDisk{}.bin",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    Disk::initialise(&path, &profile).unwrap();
    let mut disk = Disk::open(&path, &profile, 2000).unwrap();
    disk.publish(
        domain.clone(),
        vec![],
        &resolve(first.clone()),
        &profile,
        2000,
        &[],
    )
    .unwrap();
    assert_eq!(disk.file.metadata().unwrap().len(), physical);
    let inactive = (1 - disk.active) as u64 * disk.bank;
    disk.file
        .write_all_at(b"InterruptedSuccessor", inactive + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    let mut disk = Disk::open(&path, &profile, 2000).unwrap();
    assert_eq!(
        disk.objects(&[first.reference().clone()])
            .unwrap()
            .get(first.reference())
            .unwrap(),
        first.bytes()
    );
    assert!(
        disk.publish(
            domain.clone(),
            vec![],
            &resolve(second.clone()),
            &profile,
            2000,
            &[first.reference().clone()]
        )
        .is_err()
    );
    assert!(disk.live(first.reference(), 2000));
    disk.publish(
        domain,
        vec![],
        &resolve(second.clone()),
        &profile,
        2000,
        &[],
    )
    .unwrap();
    assert!(disk.objects(&[first.reference().clone()]).is_err());
    drop(disk);
    let disk = Disk::open(&path, &profile, 2000).unwrap();
    assert!(disk.live(second.reference(), 2000));
    disk.file.write_all_at(&[0; 16], 0).unwrap();
    disk.file.write_all_at(&[0; 16], disk.bank).unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    assert!(Disk::open(&path, &profile, 2000).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn bridge_pending_extent_recovers_torn_bank_without_exceeding_physical_consent() {
    let manifest = deployment::manifest();
    let service = manifest.services()[&7];
    let payload = vec![91; 32768];
    let state = State {
        label: "AuthorityBridgeStorage".into(),
        network: manifest.network,
        incarnation: manifest.incarnation,
        service,
        time: 2000,
        domain: domains::State::empty(manifest.network, manifest.incarnation),
        governance: vec![],
        records: BTreeMap::new(),
        payload: payload.clone(),
    };
    let physical = 2
        * (wire::encode_bounded(&state.value(), 1024 * 1024)
            .unwrap()
            .len() as u64
            + HEADER);
    let mut profile = domains::federation::BridgeProfile {
        manifest: manifest.clone(),
        service,
        volume: [107; 32],
        agreements: vec![([73; 32], [74; 32])],
        state_bytes: physical,
        envelope: vec![],
    };
    profile.envelope =
        wire::sign_envelope(&profile.payload().unwrap(), &deployment::key(90)).unwrap();
    let profile = domains::federation::BridgeProfile::parse(
        &profile.envelope,
        manifest.network,
        manifest.incarnation,
    )
    .unwrap();
    let path = std::env::temp_dir().join(format!(
        "HyperNetBridgeDisk{}.bin",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    Disk::initialise_bridge(&path, &profile).unwrap();
    let mut disk = Disk::open_bridge(&path, &profile, 2000).unwrap();
    disk.stage_bridge_payload(&payload, 2000).unwrap();
    assert_eq!(disk.file.metadata().unwrap().len(), physical);
    let inactive = (1 - disk.active) as u64 * disk.bank;
    disk.file
        .write_all_at(b"InterruptedExtent", inactive + HEADER)
        .unwrap();
    disk.file.sync_all().unwrap();
    drop(disk);
    let mut disk = Disk::open_bridge(&path, &profile, 2000).unwrap();
    assert_eq!(disk.bridge_payload().unwrap(), payload);
    assert!(disk.stage_bridge_payload(&vec![0; 32769], 2000).is_err());
    assert_eq!(disk.bridge_payload().unwrap(), payload);
    let mut larger = disk.state.clone();
    larger.payload.push(1);
    assert!(disk.commit(larger).is_err());
    assert_eq!(disk.file.metadata().unwrap().len(), physical);
    drop(disk);
    let page = HostProfile {
        manifest,
        role: 1,
        service,
        volume: [107; 32],
        namespaces: vec!["Books".into()],
        state_bytes: physical,
        maximum_asset_bytes: 1024,
        retention_ms: 10000,
        content: None,
        envelope: vec![],
    };
    assert!(Disk::open(&path, &page, 2000).is_err());
    let disk = Disk::open_bridge(&path, &profile, 2000).unwrap();
    assert_eq!(disk.bridge_payload().unwrap(), payload);
    drop(disk);
    std::fs::remove_file(path).unwrap();
}
