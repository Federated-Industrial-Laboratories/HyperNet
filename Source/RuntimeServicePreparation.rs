// SPDX-License-Identifier: MIT
// Publish one exact private service tree; preparation never replaces retained journals.
use super::*;
use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Prepared {
    profile: String,
    identity: Option<(u64, u64)>,
}

fn directory(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        files::directory(path)?;
    }
    files::private_dir(path)
}
fn members(path: &Path, expected: &[&str]) -> Result<()> {
    let found = fs::read_dir(path)?
        .map(|e| {
            e?.file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid preparation name"))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        found
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()),
        "unpublished service preparation contains unexpected data"
    );
    Ok(())
}
pub(super) fn prepare(p: &Profile) -> Result<()> {
    p.check_artifacts()?;
    let route = p.role()?.role == 5;
    let directories: &[&str] = if route {
        &["Config", "EgressConfig", "State"]
    } else {
        &["Config", "State"]
    };
    let journal = p.root.join("Preparation.json");
    let pending = p.root.join("LaunchPending");
    let launch = p.root.join("Launch");
    let mut prepared: Prepared = if journal.try_exists()? {
        files::json(&journal)?
    } else {
        ensure!(
            !pending.try_exists()? && !launch.try_exists()?,
            "unrecorded service directory; no data replaced"
        );
        let v = Prepared {
            profile: p.digest()?,
            identity: None,
        };
        files::save(&journal, &v)?;
        v
    };
    ensure!(
        prepared.profile == p.digest()?,
        "service preparation profile changed"
    );
    if prepared.identity.is_none() {
        ensure!(
            !launch.try_exists()?,
            "incomplete preparation cannot own a published tree"
        );
        if pending.try_exists()? {
            ensure!(
                fs::symlink_metadata(&pending)?.is_dir(),
                "preparation is not a directory"
            );
            files::podman(&files::strings(&[
                "unshare",
                "/usr/bin/chown",
                "-R",
                "-h",
                "0:0",
                pending.to_str().unwrap(),
            ]))?;
        }
        directory(&pending)?;
        for name in directories {
            directory(&pending.join(name))?;
        }
        for name in if route {
            vec!["Requester", "Recipient", "Control", "Egress"]
        } else {
            vec!["Requester", "Recipient", "Control"]
        } {
            let d = pending.join("State").join(name);
            directory(&d)?;
            ensure!(
                fs::read_dir(&d)?.next().is_none(),
                "unpublished service journals require explicit recovery; no data replaced"
            );
            fs::File::open(d)?.sync_all()?;
        }
        for (name, expected) in &p.artifacts {
            let bytes = zeroize::Zeroizing::new(files::read(
                &p.root.join("Config").join(name),
                wire::MAXIMUM,
            )?);
            ensure!(
                wire::digest(&bytes) == *expected,
                "consented service configuration changed"
            );
            let mut targets = vec![pending.join("Config").join(name)];
            if route && name == "Egress.json" {
                targets.push(pending.join("EgressConfig/Egress.json"));
            }
            for path in targets {
                if path.try_exists()? {
                    ensure!(
                        files::read(&path, wire::MAXIMUM)? == *bytes,
                        "partial configuration differs"
                    );
                } else {
                    files::create(&path, &bytes)?;
                }
            }
        }
        members(&pending, directories)?;
        if route {
            members(&pending.join("EgressConfig"), &["Egress.json"])?;
        }
        members(
            &pending.join("State"),
            if route {
                &["Control", "Egress", "Recipient", "Requester"]
            } else {
                &["Control", "Recipient", "Requester"]
            },
        )?;
        members(
            &pending.join("Config"),
            &p.artifacts.keys().map(String::as_str).collect::<Vec<_>>(),
        )?;
        fs::File::open(&pending)?.sync_all()?;
        for name in directories {
            fs::File::open(pending.join(name))?.sync_all()?;
        }
        files::podman(&files::strings(&[
            "unshare",
            "/usr/bin/chown",
            "-R",
            "-h",
            "1001:1001",
            pending.to_str().unwrap(),
        ]))?;
        files::podman(&files::strings(&[
            "unshare",
            "/usr/bin/sync",
            "--file-system",
            pending.to_str().unwrap(),
        ]))?;
        let m = fs::symlink_metadata(&pending)?;
        prepared.identity = Some((m.dev(), m.ino()));
        files::save(&journal, &prepared)?;
    }
    let location = if launch.try_exists()? {
        &launch
    } else {
        &pending
    };
    let m = fs::symlink_metadata(location)?;
    ensure!(
        m.is_dir() && Some((m.dev(), m.ino())) == prepared.identity,
        "prepared service directory identity differs"
    );
    if location == &pending {
        let from = std::ffi::CString::new(pending.as_os_str().as_bytes())?;
        let to = std::ffi::CString::new(launch.as_os_str().as_bytes())?;
        ensure!(
            unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    from.as_ptr(),
                    libc::AT_FDCWD,
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } == 0,
            "cannot publish exact service preparation: {}",
            std::io::Error::last_os_error()
        );
        fs::File::open(&p.root)?.sync_all()?;
    }
    Ok(())
}
