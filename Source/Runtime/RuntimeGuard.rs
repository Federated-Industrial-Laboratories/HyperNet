// SPDX-License-Identifier: MIT
//! Enforce the absolute operator deadline independently of the local manager.
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use std::{
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Clone, ValueEnum)]
pub enum Kind {
    Authority,
}
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn terminate(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn boottime() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0,
        "Boot clock unavailable"
    );
    ensure!(value.tv_sec >= 0, "Invalid boot clock");
    Ok(value.tv_sec as u64)
}
fn expired(previous: u64, wall: u64, expires: u64, boot: u64, deadline: u64) -> bool {
    wall < previous || wall >= expires || boot >= deadline
}
pub fn run(kind: Kind, expires: u64, arguments: Vec<String>) -> Result<()> {
    crate::confinement::preflight()?;
    let now = crate::store::now()?;
    ensure!(
        expires > now && expires - now <= 604800,
        "Runtime consent deadline is expired or invalid"
    );
    let deadline = boottime()?
        .checked_add(expires - now)
        .context("Deadline overflow")?;
    let authorization = std::path::Path::new("/Authorization");
    let manifest = crate::runtime_authorization::Manifest::read(authorization)?;
    crate::runtime_authorization::verify(
        authorization,
        &manifest.config_digest()?,
        &manifest.signer,
        &manifest.bootstrap_digest,
    )?;
    ensure!(
        expires == manifest.expires,
        "Guard deadline differs from consent"
    );
    let floor = match kind {
        Kind::Authority => {
            ensure!(
                arguments.len() == 1,
                "Authority guard requires one signer floor"
            );
            let value = arguments[0]
                .strip_prefix("--minimum-generation=")
                .context("Invalid signer floor argument")?;
            let floor: u64 = value.parse()?;
            ensure!(
                floor > 0 && value == floor.to_string(),
                "Invalid signer floor"
            );
            floor
        }
    };
    let args = vec![
        "authority-replica".to_string(),
        "run".into(),
        "--directory".into(),
        "/State/Replica".into(),
        "--minimum-generation".into(),
        floor.to_string(),
        "--authorization".into(),
        "/Authorization".into(),
    ];
    STOP.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGTERM, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, terminate as *const () as libc::sighandler_t);
    }
    let mut child = Command::new("/HyperNet")
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/")
        .stdin(Stdio::null())
        .spawn()?;
    let mut previous = now;
    let result = (|| -> Result<()> {
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "Guarded service exited unsuccessfully");
                return Ok(());
            }
            let wall = crate::store::now()?;
            let consent_current = (|| -> Result<bool> {
                let bytes = crate::runtime_authorization::public_read(
                    &authorization.join("Withdrawal.json"),
                    64,
                )?;
                Ok(serde_json::from_slice::<u64>(&bytes)? == 0)
            })()
            .unwrap_or(false);
            if STOP.load(Ordering::Relaxed)
                || !consent_current
                || expired(previous, wall, expires, boottime()?, deadline)
            {
                return Ok(());
            }
            previous = wall;
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    if child.try_wait()?.is_some() {
        return result;
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let grace = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if std::time::Instant::now() >= grace {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    result
}
#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeGuardUnitTests.rs"]
mod tests;
