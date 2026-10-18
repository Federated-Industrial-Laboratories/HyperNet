// SPDX-License-Identifier: MIT
// A dedicated PID namespace supervises one accepted SSH grant under fresh quorum leases.
use crate::{
    authority_clock_handoff::Source,
    authority_domains::ssh,
    authority_files, confinement,
    runtime_manifest::{Manifest, Role},
    store, trust_bootstrap, trust_wire as wire,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
#[path = "AuthoritySshClient.rs"]
mod client;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    bootstrap_file: PathBuf,
    manifest_file: PathBuf,
    profile_file: PathBuf,
    identity_file: PathBuf,
    state_directory: PathBuf,
    control_socket: PathBuf,
    clock_witness_file: PathBuf,
    grant_id: String,
    native_user_key: String,
    listen: SocketAddr,
}
pub struct Config {
    pub listen: SocketAddr,
    control: PathBuf,
    clock: Source,
    role: Role,
    pub state_directory: PathBuf,
    bootstrap: trust_bootstrap::Verified,
    key: SigningKey,
    service: ssh::Profile,
    grant: [u8; 32],
    native: [u8; 32],
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            unsafe { libc::getpid() } == 1 && unsafe { libc::geteuid() } == 1000,
            "SSH supervisor must be PID 1 under its dedicated service UID"
        );
        let raw: Configuration =
            serde_json::from_slice(&authority_files::read(path, 16384, true)?)?;
        for (actual, required) in [
            (&raw.bootstrap_file, "/Config/Bootstrap.cbor"),
            (&raw.manifest_file, "/Config/Manifest.cbor"),
            (&raw.profile_file, "/Config/SshProfile.cbor"),
            (&raw.identity_file, "/Config/Service.key"),
            (&raw.state_directory, "/State/Requester"),
            (&raw.control_socket, "/Authority/Control.sock"),
            (&raw.clock_witness_file, "/Clock/ClockHealth.cbor"),
        ] {
            ensure!(
                actual == Path::new(required),
                "SSH runtime path differs from the confined profile"
            );
        }
        let manifest = Manifest::parse(&authority_files::read(
            &raw.manifest_file,
            crate::runtime_manifest::MAXIMUM,
            true,
        )?)?;
        let clock = Source::Signed {
            path: raw.clock_witness_file,
            public_key: hex::encode(manifest.clock.monitor_key),
            kernel_boot: manifest.clock.kernel_boot.clone(),
        };
        let now = clock.health()?.observe()?;
        let bootstrap = trust_bootstrap::inspect(
            &authority_files::read(&raw.bootstrap_file, wire::MAXIMUM, true)?,
            true,
        )?;
        ensure!(
            bootstrap.file_digest() == manifest.bootstrap_digest
                && bootstrap.descriptor().scope().network == manifest.network
                && bootstrap.descriptor().scope().incarnation == manifest.incarnation
                && crate::authority_membership::current(now.wall_ms, manifest.validity),
            "SSH manifest differs from accepted bootstrap or current consent"
        );
        let profile = ssh::Profile::parse(
            &authority_files::read(&raw.profile_file, 4096, true)?,
            manifest.network,
            manifest.incarnation,
        )?;
        let role = manifest
            .roles
            .iter()
            .find(|r| r.role == 8)
            .context("SSH role absent from manifest")?
            .clone();
        let endpoint = manifest
            .endpoints
            .iter()
            .find(|e| e.endpoint_id == profile.endpoint)
            .context("SSH profile endpoint absent")?;
        ensure!(
            profile.deployment == manifest.deployment
                && profile.operator == manifest.operator
                && profile.service == role.service_key
                && manifest.permits_definition(&profile.manifest).is_ok()
                && crate::authority_membership::current(
                    now.wall_ms,
                    crate::authority_operational_consent::validity(
                        &manifest,
                        &profile.manifest,
                        profile.validity
                    )?
                )
                && role.bind_endpoint_ids == [profile.endpoint]
                && endpoint.service_key == profile.service
                && endpoint.port == raw.listen.port()
                && raw.listen.port() > 1024
                && raw.listen.ip().is_unspecified()
                && raw.listen.is_ipv4() == endpoint.address.is_ipv4(),
            "SSH profile differs from exact local manifest and exposure"
        );
        let key_bytes =
            zeroize::Zeroizing::new(authority_files::read(&raw.identity_file, 32, true)?);
        let seed: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            key_bytes
                .as_slice()
                .try_into()
                .context("SSH service key must contain exactly 32 bytes")?,
        );
        let key = SigningKey::from_bytes(&seed);
        ensure!(
            key.verifying_key().to_bytes() == profile.service,
            "SSH identity differs from registered role"
        );
        let grant = trust_bootstrap::hex32(&raw.grant_id)?;
        let native = trust_bootstrap::hex32(&raw.native_user_key)?;
        wire::valid_key(&native)?;
        ensure!(
            grant != [0; 32]
                && native != profile.native
                && native != profile.service
                && native != profile.operator,
            "SSH session identifier or native user class differs"
        );
        ensure!(
            authority_files::read(Path::new("/Config/SshdConfig"), 16384, true)?
                == settings(raw.listen).as_bytes(),
            "SSH restrictions differ from the required profile"
        );
        ensure!(
            authority_files::read(Path::new("/Config/AuthorizedKeys"), 4096, true)?
                == format!("restrict {}\n", ssh::native_public(native)).as_bytes(),
            "SSH authorised key differs from local acceptance"
        );
        let command = store::read_bounded(Path::new("/Service/Command"), 32 * 1024 * 1024)?;
        ensure!(
            <[u8; 32]>::from(Sha256::digest(&command)) == profile.command_digest,
            "packaged SSH command differs from operator consent"
        );
        let host = Command::new("/OpenSSH/bin/ssh-keygen")
            .args(["-y", "-f", "/Config/SshHostKey"])
            .env_clear()
            .env("PATH", "/OpenSSH/bin")
            .env("OPENSSL_CONF", "/dev/null")
            .stdin(Stdio::null())
            .output()?;
        ensure!(
            host.status.success()
                && String::from_utf8(host.stdout)?.trim() == ssh::native_public(profile.native),
            "SSH host key differs from operator consent"
        );
        Ok(Self {
            listen: raw.listen,
            control: raw.control_socket,
            clock,
            role,
            state_directory: raw.state_directory,
            bootstrap,
            key,
            service: profile,
            grant,
            native,
        })
    }
    fn resources(&self, p: &confinement::Profile) -> Result<()> {
        let cpu = p
            .cpu_max
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(
            p.memory_max <= self.role.memory_bytes
                && p.pids_max <= self.role.pids
                && cpu.len() == 2
                && u128::from(cpu[0]) * u128::from(self.role.cpu_period)
                    <= u128::from(self.role.cpu_quota) * u128::from(cpu[1]),
            "SSH resource limits exceed consent"
        );
        let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::statvfs(c"/Work".as_ptr(), &mut filesystem) } == 0,
            "SSH workspace limits unavailable"
        );
        ensure!(
            u128::from(filesystem.f_blocks) * u128::from(filesystem.f_frsize)
                <= u128::from(self.role.state_admission_bytes),
            "SSH workspace exceeds consent"
        );
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } == 0
                && limit.rlim_cur <= self.role.state_admission_bytes
                && limit.rlim_max <= self.role.state_admission_bytes,
            "SSH file size limit exceeds consent"
        );
        Ok(())
    }
}
fn settings(listen: SocketAddr) -> String {
    include_str!("../../Packaging/SshdConfig")
        .replace("@Port@", &listen.port().to_string())
        .replace("@Address@", &listen.ip().to_string())
}

// Namespace init ignores default fatal signals; an explicit async-signal-safe handler exits
// every supervisor thread when the suspend-aware timer expires, without event-loop polling.
extern "C" fn expired(_: libc::c_int) {
    unsafe { libc::_exit(124) }
}
struct Deadline(libc::timer_t);
impl Deadline {
    fn new() -> Result<Self> {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = expired as *const () as usize;
        ensure!(
            unsafe { libc::sigemptyset(&mut action.sa_mask) } == 0,
            "SSH deadline signal mask unavailable"
        );
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::sigaction(libc::SIGALRM, &action, &mut old) } == 0,
            "SSH deadline handler unavailable"
        );
        if old.sa_sigaction != libc::SIG_DFL {
            unsafe {
                libc::sigaction(libc::SIGALRM, &old, std::ptr::null_mut());
            }
            anyhow::bail!("SSH deadline signal is already in use");
        }
        let mut unblocked: libc::sigset_t = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::sigemptyset(&mut unblocked) } == 0
                && unsafe { libc::sigaddset(&mut unblocked, libc::SIGALRM) } == 0
                && unsafe {
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblocked, std::ptr::null_mut())
                } == 0,
            "SSH deadline signal cannot be unblocked"
        );
        let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
        event.sigev_notify = libc::SIGEV_SIGNAL;
        event.sigev_signo = libc::SIGALRM;
        let mut timer = std::mem::MaybeUninit::uninit();
        ensure!(
            unsafe { libc::timer_create(libc::CLOCK_BOOTTIME, &mut event, timer.as_mut_ptr()) }
                == 0,
            "SSH kernel deadline unavailable"
        );
        Ok(Self(unsafe { timer.assume_init() }))
    }
    fn arm(&self, boot_ms: u64) -> Result<()> {
        ensure!(
            crate::authority_challenge::boot_time_ms()? < boot_ms,
            "SSH deadline expired"
        );
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: (boot_ms / 1000).try_into()?,
                tv_nsec: ((boot_ms % 1000) * 1_000_000).try_into()?,
            },
        };
        ensure!(
            unsafe {
                libc::timer_settime(self.0, libc::TIMER_ABSTIME, &spec, std::ptr::null_mut())
            } == 0,
            "SSH kernel deadline could not be armed"
        );
        Ok(())
    }
}
impl Drop for Deadline {
    fn drop(&mut self) {
        unsafe {
            libc::timer_delete(self.0);
        }
    }
}
pub async fn run(
    config: Config,
    profile: confinement::Profile,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<()> {
    config.resources(&profile)?;
    guard()?;
    let deadline = Deadline::new()?;
    let mut client = client::Client::open(
        config.bootstrap,
        config.key,
        &config.state_directory,
        config.service,
        config.grant,
        config.native,
    )?;
    let clock = &config.clock;
    let mut health = || clock.health();
    let mut end = 0;
    let mut child = client.lease(&config.control, None, &mut health, &mut guard, |boot| {
        deadline.arm(boot)?;
        end = boot;
        Command::new("/HyperNet")
            .args(["ssh-child", "--port", &config.listen.port().to_string()])
            .env_clear()
            .env("PATH", "/OpenSSH/bin:/bin")
            .env("OPENSSL_CONF", "/dev/null")
            .stdin(Stdio::null())
            .spawn()
            .map_err(Into::into)
    })?;
    println!("SshService ready");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let outcome:Result<()>=async { loop {
        tokio::select! { biased;
            _=terminate.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            _=tick.tick()=>{
                guard()?;health()?.observe()?;if child.try_wait()?.is_some(){break;}
                let now=crate::authority_challenge::boot_time_ms()?;
                if end.saturating_sub(now)<=3000 {
                    client.lease(&config.control,Some(end),&mut health,&mut guard,|boot|{deadline.arm(boot)?;end=boot;Ok(())})?;
                }
            }
        }
    } Ok(()) }.await;
    let _ = child.kill();
    let _ = child.wait();
    outcome
}
pub fn child(port: u16) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000,
        "dedicated SSH service UID required"
    );
    confinement::enter_ssh_child(port)?;
    Err(Command::new("/OpenSSH/sbin/sshd")
        .args(["-D", "-e", "-f", "/Config/SshdConfig"])
        .env_clear()
        .env("PATH", "/OpenSSH/bin:/bin")
        .env("OPENSSL_CONF", "/dev/null")
        .exec()
        .into())
}
pub fn command() -> Result<()> {
    confinement::enter_ssh_command()?;
    Err(Command::new("/Service/Command")
        .env_clear()
        .env("PATH", "/Service")
        .env("LANG", "C")
        .current_dir("/Work")
        .exec()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadline_subprocess() {
        if std::env::var_os("HYPERNET_SSH_DEADLINE_TEST").is_none() {
            return;
        }
        let timer = Deadline::new().unwrap();
        timer
            .arm(crate::authority_challenge::boot_time_ms().unwrap() + 150)
            .unwrap();
        // Simulate a blocked supervisor; no userspace polling enforces this deadline.
        std::thread::sleep(Duration::from_secs(2));
        panic!("kernel SSH deadline did not terminate the supervisor");
    }
    #[test]
    fn kernel_deadline_stops_a_blocked_supervisor() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["ssh_service::tests::deadline_subprocess", "--exact"])
            .env("HYPERNET_SSH_DEADLINE_TEST", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(124));
        let timer = Deadline::new().unwrap();
        assert!(
            timer
                .arm(crate::authority_challenge::boot_time_ms().unwrap())
                .is_err()
        );
    }
}
