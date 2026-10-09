// SPDX-License-Identifier: MIT
use super::{
    files::*,
    model::{Profile, State, save},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

const STAGES: [&str; 8] = [
    "Pending",
    "RootReady",
    "BrokerRoleReady",
    "BrokerPermissionsReady",
    "BrokerUserReady",
    "AuthenticationReady",
    "NamespaceCommitted",
    "Complete",
];
fn stage(root: &Path, state: &mut State, next: usize) -> Result<()> {
    let current = STAGES
        .iter()
        .position(|value| *value == state.bootstrap_stage)
        .context("Invalid bootstrap stage")?;
    if current < next {
        state.bootstrap_stage = STAGES[next].into();
        save(root, state)?;
    }
    Ok(())
}
fn ctl_output(profile: &Profile, arguments: &[&str]) -> Result<Vec<u8>> {
    ensure!(
        executable(&profile.etcdctl)? == profile.etcdctl_digest,
        "Voter management executable changed"
    );
    let mut args = strings(&[
        &format!(
            "--endpoints={}",
            (0..3)
                .map(|i| format!("https://127.0.0.1:{}", profile.voter_port_base + i))
                .collect::<Vec<_>>()
                .join(",")
        ),
        &format!(
            "--cacert={}",
            profile.root.join("Pki/VoterCa.pem").display()
        ),
        &format!("--cert={}", profile.root.join("Pki/Root.pem").display()),
        &format!("--key={}", profile.root.join("Pki/RootKey.pem").display()),
        "--command-timeout=3s",
        "--dial-timeout=2s",
        "--max-recv-bytes=262144",
        "--write-out=json",
    ]);
    args.extend(strings(arguments));
    super::files::run(&profile.etcdctl, &args, 6)
}
fn ctl(profile: &Profile, arguments: &[&str]) -> Result<Value> {
    serde_json::from_slice(&ctl_output(profile, arguments)?).with_context(|| {
        format!(
            "Invalid voter management {} JSON reply",
            arguments.first().copied().unwrap_or("unknown")
        )
    })
}
fn names(value: &Value, field: &str) -> Result<BTreeSet<String>> {
    if value[field].is_null() {
        return Ok(BTreeSet::new());
    }
    let list = value[field]
        .as_array()
        .context("Invalid authentication list")?;
    ensure!(list.len() <= 2, "Unexpected authentication identities");
    let mut result = BTreeSet::new();
    for item in list {
        let name = item.as_str().context("Invalid authentication identity")?;
        ensure!(
            matches!(name, "root" | "HyperNetBroker") && result.insert(name.to_string()),
            "Unexpected or duplicate authentication identity"
        );
    }
    Ok(result)
}
fn expected_permissions(profile: &Profile) -> BTreeSet<(String, String)> {
    let authority = format!("/HyperNet/{}/Authority", profile.network);
    let pages = format!("/HyperNet/{}/Pages/", profile.network);
    let end = format!("/HyperNet/{}/Pages0", profile.network);
    BTreeSet::from([
        (STANDARD.encode(authority), String::new()),
        (STANDARD.encode(pages), STANDARD.encode(end)),
    ])
}
fn permissions(
    value: &Value,
    expected: &BTreeSet<(String, String)>,
) -> Result<BTreeSet<(String, String)>> {
    let mut result = BTreeSet::new();
    if value["perm"].is_null() {
        return Ok(result);
    }
    let list = value["perm"]
        .as_array()
        .context("Invalid broker permissions")?;
    ensure!(list.len() <= 2, "Unexpected broker permissions");
    for permission in list {
        let key = permission["key"]
            .as_str()
            .context("Missing permission key")?
            .to_string();
        ensure!(
            permission["range_end"].is_null() || permission["range_end"].is_string(),
            "Invalid permission range encoding"
        );
        let end = permission["range_end"].as_str().unwrap_or("").to_string();
        let pair = (key, end);
        ensure!(
            permission["permType"] == 2 && expected.contains(&pair) && result.insert(pair),
            "Broker permissions differ from the exact intended scope"
        );
    }
    Ok(result)
}
fn user(profile: &Profile, identity: &str, role: &str, locked: bool) -> Result<()> {
    let users = names(&ctl(profile, &["user", "list"])?, "users")?;
    if !users.contains(identity) {
        ensure!(
            !locked,
            "An authenticated user is missing; no grant was restored"
        );
        ctl(profile, &["user", "add", identity, "--no-password"])?;
    }
    let roles = names(&ctl(profile, &["user", "get", identity])?, "roles")?;
    ensure!(
        roles.is_empty() || roles == BTreeSet::from([role.to_string()]),
        "User has unexpected roles"
    );
    if roles.is_empty() {
        ensure!(
            !locked,
            "An authenticated role grant is missing; no grant was restored"
        );
        ctl(profile, &["user", "grant-role", identity, role])?;
    }
    ensure!(
        names(&ctl(profile, &["user", "get", identity])?, "roles")?
            == BTreeSet::from([role.to_string()]),
        "User role reconciliation failed"
    );
    Ok(())
}
pub fn prepare_authority(root: &Path, state: &State) -> Result<()> {
    if !state.bootstrap_done {
        ensure!(
            !state
                .resources
                .iter()
                .any(|resource| resource.kind == "container"),
            "Authority bootstrap preparation requires stopped workloads"
        );
        let directory = root.join("AuthorityState");
        ensure!(
            std::fs::symlink_metadata(&directory)?.is_dir(),
            "Invalid authority state directory"
        );
        podman(&strings(&[
            "unshare",
            "/usr/bin/chown",
            "-R",
            "--no-dereference",
            "0:0",
            directory.to_str().context("Invalid authority path")?,
        ]))?;
    }
    Ok(())
}
pub fn run(root: &Path, profile: &Profile, state: &mut State) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match ctl(profile, &["endpoint", "health"]) {
            Ok(_) => break,
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    let auth = ctl(profile, &["auth", "status"])?;
    ensure!(
        auth["enabled"].is_null() || auth["enabled"].is_boolean(),
        "Invalid authentication status"
    );
    let enabled = auth["enabled"].as_bool().unwrap_or(false);
    let previous = STAGES
        .iter()
        .position(|value| *value == state.bootstrap_stage)
        .context("Invalid bootstrap stage")?;
    ensure!(
        enabled || (!state.bootstrap_done && previous < 5),
        "Previously enabled authentication is now disabled"
    );
    user(profile, "root", "root", enabled)?;
    stage(root, state, 1)?;
    let roles = names(&ctl(profile, &["role", "list"])?, "roles")?;
    if !roles.contains("HyperNetBroker") {
        ensure!(
            !enabled,
            "Authenticated broker role is missing; no role was restored"
        );
        ctl(profile, &["role", "add", "HyperNetBroker"])?;
    }
    stage(root, state, 2)?;
    let expected = expected_permissions(profile);
    let actual = permissions(
        &ctl(profile, &["role", "get", "HyperNetBroker"])?,
        &expected,
    )?;
    ensure!(
        !enabled || actual == expected,
        "Authenticated broker permissions changed; no grant was restored"
    );
    for (key, end) in expected.difference(&actual) {
        let key = String::from_utf8(STANDARD.decode(key)?)?;
        let mut args = vec![
            "role",
            "grant-permission",
            "HyperNetBroker",
            "readwrite",
            key.as_str(),
        ];
        if !end.is_empty() {
            args.push("--prefix");
        }
        ctl(profile, &args)?;
    }
    ensure!(
        permissions(
            &ctl(profile, &["role", "get", "HyperNetBroker"])?,
            &expected
        )? == expected,
        "Broker permission reconciliation failed"
    );
    stage(root, state, 3)?;
    user(profile, "HyperNetBroker", "HyperNetBroker", enabled)?;
    ensure!(
        names(&ctl(profile, &["user", "list"])?, "users")?
            == BTreeSet::from(["root".into(), "HyperNetBroker".into()]),
        "Authentication user set differs"
    );
    // The root grant is built in and need not have a stored role object.
    ensure!(
        names(&ctl(profile, &["role", "list"])?, "roles")?.contains("HyperNetBroker"),
        "Authentication role set differs"
    );
    stage(root, state, 4)?;
    if !enabled {
        // etcdctl emits a fixed text acknowledgement here, even in JSON mode.
        // The authenticated status request below verifies the committed state.
        ctl_output(profile, &["auth", "enable"])?;
    }
    ensure!(
        ctl(profile, &["auth", "status"])?["enabled"] == true,
        "Authentication did not become active"
    );
    stage(root, state, 5)?;
    if !state.bootstrap_done {
        let config = crate::authority_config(&root.join("Bootstrap.json"))?;
        crate::runtime()?.block_on(async {
            tokio::time::timeout(Duration::from_secs(20), async {
                let mut store = crate::store::Store::connect(&config).await?;
                store
                    .initialise_runtime(&profile.administrator, profile.created)
                    .await
            })
            .await
            .context("Authority initialization timed out")?
        })?;
        stage(root, state, 6)?;
        state.bootstrap_done = true;
        stage(root, state, 7)?;
        save(root, state)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_reconciliation_rejects_broader_or_changed_rights() {
        let expected = BTreeSet::from([("a2V5".into(), String::new())]);
        assert!(
            permissions(
                &serde_json::json!({"perm":[{"permType":2,"key":"a2V5"}]}),
                &expected
            )
            .is_ok()
        );
        for value in [
            serde_json::json!({"perm":[{"permType":1,"key":"a2V5"}]}),
            serde_json::json!({"perm":[{"permType":2,"key":"b3RoZXI="}]}),
            serde_json::json!({"perm":[{"permType":2,"key":"a2V5","range_end":"eg=="}]}),
        ] {
            assert!(permissions(&value, &expected).is_err());
        }
        assert!(names(&serde_json::json!({"users":["root","Unexpected"]}), "users").is_err());
    }
}
