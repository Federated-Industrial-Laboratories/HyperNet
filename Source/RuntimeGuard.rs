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
    Voter,
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
    let (program, args) = match kind {
        Kind::Authority => {
            ensure!(
                arguments.is_empty(),
                "Authority guard accepts no extra arguments"
            );
            (
                "/HyperNet",
                vec![
                    "authority".into(),
                    "--config".into(),
                    "/Config/Authority.json".into(),
                ],
            )
        }
        Kind::Voter => {
            ensure!(
                !arguments.is_empty()
                    && arguments.len() <= 32
                    && arguments.iter().all(|a| a.len() <= 2048
                        && a.starts_with("--")
                        && !a.contains(['\n', '\r', '\0'])),
                "Invalid voter arguments"
            );
            ("/Etcd", arguments)
        }
    };
    STOP.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGTERM, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, terminate as *const () as libc::sighandler_t);
    }
    let mut child = Command::new(program)
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
            if STOP.load(Ordering::Relaxed)
                || expired(previous, wall, expires, boottime()?, deadline)
            {
                return Ok(());
            }
            previous = wall;
            std::thread::sleep(Duration::from_millis(100));
        }
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn suspend_and_clock_changes_do_not_extend_deadlines() {
        assert!(expired(100, 101, 200, 200, 200));
        assert!(expired(100, 200, 200, 10, 200));
        assert!(expired(100, 99, 200, 10, 200));
        assert!(!expired(100, 101, 200, 10, 200));
    }
}
