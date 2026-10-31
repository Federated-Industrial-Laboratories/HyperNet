// SPDX-License-Identifier: MIT
// Cross-executable qualification uses real policy execution and the independently verified Suite floor.
use super::super::journal::tests::Directory;
use super::*;
use crate::{
    authority_application::{PolicyApplication, tests::Fixture},
    authority_files, authority_floor, trust_bootstrap,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value as Json, json};
use sha2::{Digest as _, Sha256};
use std::path::Path;

fn diagnostic(value: V) -> Json {
    match value {
        V::Uint(v) => json!(v),
        V::Bytes(v) => json!({"hex":hex::encode(v)}),
        V::Text(v) => json!(v),
        V::Array(v) => Json::Array(v.into_iter().map(diagnostic).collect()),
        V::Bool(v) => json!(v),
        V::Null => Json::Null,
    }
}
async fn suite(binary: &Path, arguments: Vec<String>) -> Result<Json> {
    let binary = binary.to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        crate::runtime_management::files::run(&binary, &arguments, 15)
    })
    .await??;
    Ok(serde_json::from_slice(&output)?)
}
fn text(path: &Path) -> String {
    path.to_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires the independent Suite executable and a normally produced live NTS clock witness"]
async fn suite_inspects_policy_through_independent_quorum_and_retained_floor() {
    let clock = PathBuf::from(
        std::env::var("HYPERNET_TEST_CLOCK_WITNESS")
            .expect("HYPERNET_TEST_CLOCK_WITNESS is a native prerequisite"),
    );
    let client = PathBuf::from(
        std::env::var("HYPERNET_TEST_SUITE").expect("HYPERNET_TEST_SUITE is a native prerequisite"),
    );
    assert!(client.is_absolute() && client.is_file());
    tokio::time::timeout(Duration::from_secs(60), async {
        let now = crate::authority_clock_monitor::health(&clock).unwrap().observe().unwrap().wall_ms;
        let fixture = Fixture::at(now);
        let verified = trust_bootstrap::check(&fixture.bootstrap, true, now).unwrap();
        let configuration = Configuration::trusted(verified.descriptor().canonical()).unwrap();
        assert_eq!(configuration.bytes, fixture.configuration().bytes);
        let expected = fixture.expected.iter().find(|v| v.kind == 100).unwrap().clone();
        let initial = wire::decode(&fixture.initial).unwrap();
        let policy = initial.array(6).unwrap()[4].list(34).unwrap().iter().find_map(|record| {
            let bytes = record.bytes().ok()?;
            (wire::digest(bytes) == expected.digest).then(|| bytes.to_vec())
        }).expect("Verified bootstrap policy is present");
        assert_eq!(expected.generation, 1);
        let root = Directory::new();
        let bootstrap = root.0.join("Bootstrap.cbor");
        authority_files::write_new(&bootstrap, &fixture.bootstrap).unwrap();
        let identity = root.0.join("SuiteIdentity.json");
        authority_files::write_new(&identity, &serde_json::to_vec(&json!({"secretKey":hex::encode(fixture.requester.to_bytes()),"publicKey":hex::encode(fixture.requester.verifying_key().to_bytes())})).unwrap()).unwrap();
        let floor = root.0.join("OperatorFloor");
        let common = vec!["--bootstrap".into(), text(&bootstrap), "--bootstrap-digest".into(), hex::encode(Sha256::digest(&fixture.bootstrap)), "--directory".into(), text(&floor), "--clock-witness".into(), text(&clock)];
        let mut initialise = vec!["authority-inspection".into(), "initialise".into()]; initialise.extend(common.clone());
        initialise.extend(["--requester".into(), hex::encode(fixture.requester.verifying_key().to_bytes())]);
        let result = suite(&client, initialise).await.unwrap();
        assert_eq!(result["status"], "Initialised"); assert_eq!(result["committedHeight"], 0);
        let store = authority_floor::Store::open(&floor, verified.descriptor().clone()).unwrap();
        assert_eq!(store.prefix().height(), 0); drop(store);
        let mut keys = [1,2,3,4].map(|seed| SigningKey::from_bytes(&[seed;32]));
        keys.sort_by_key(|key| key.verifying_key().to_bytes());
        assert_eq!(configuration.voters, keys.clone().map(|key| key.verifying_key().to_bytes()));
        let (peers, credentials, addresses) = tests::certificates(&root.0, &keys);
        let directories: Vec<_> = (0..4).map(|_| Directory::new()).collect();
        let mut stops = Vec::new(); let mut configs = Vec::new();
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..4 {
            let mut runtime = tests::config(clock.clone(), &directories[i].0, &keys);
            runtime.peers = peers.clone(); runtime.tls = credentials[i].clone(); runtime.listen = addresses[i];
            let engine = Engine::create(&directories[i].0, configuration.clone(), keys[i].clone(), fixture.initial.clone()).unwrap();
            let (stop, receiver) = watch::channel(false);
            tasks.spawn(serve(runtime.clone(), engine, Arc::new(PolicyApplication::new(configuration.clone())), receiver));
            stops.push(stop); configs.push(runtime);
        }
        for runtime in &configs {
            tokio::time::timeout(Duration::from_secs(3), async {
                while tokio::net::UnixStream::connect(&runtime.control_socket).await.is_err() { tokio::time::sleep(Duration::from_millis(20)).await; }
            }).await.unwrap();
        }
        // Genesis grants use the same conservative interval as normal policy evaluation.
        let maturity = now.checked_add(1250).unwrap();
        while crate::authority_clock_monitor::health(&clock).unwrap().observe().unwrap().wall_ms < maturity {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let mut prior_height = 0;
        for peer in [0, 2] {
            let mut arguments = vec!["authority-inspection".into(), "inspect".into()]; arguments.extend(common.clone());
            arguments.extend(["--key".into(), text(&identity), "--socket".into(), text(&configs[peer].control_socket), "--grant".into(), hex::encode(fixture.grant), "--kind".into(), "100".into(), "--lookup".into(), hex::encode(configuration.scope.network)]);
            let result = suite(&client, arguments).await.unwrap();
            assert_eq!(result["kind"], 100); assert_eq!(result["generation"], 1);
            assert_eq!(result["lookup"], hex::encode(configuration.scope.network));
            assert_eq!(result["recordDigest"], hex::encode(expected.digest));
            assert_eq!(result["record"], diagnostic(wire::decode(&policy).unwrap()));
            let height = result["committedHeight"].as_u64().unwrap(); assert!(height > prior_height);
            let store = authority_floor::Store::open(&floor, verified.descriptor().clone()).unwrap();
            assert_eq!(store.prefix().height(), height);
            assert!(store.generations().contains(&expected));
            prior_height = height; drop(store);
            eprintln!("Independent Suite inspection verified policy generation 1 at committed height {height}");
        }
        for stop in stops { stop.send(true).unwrap(); }
        while let Some(result) = tasks.join_next().await { result.unwrap().unwrap(); }
    }).await.expect("Policy/Suite interoperability qualification exceeded its bound");
}
