// SPDX-License-Identifier: MIT
//! Fail-closed Linux OCI and Landlock boundary, installed before worker threads.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::{
    ffi::CString,
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub landlock_abi: u32,
    pub uid_mapping: String,
    pub seccomp: u32,
    pub no_new_privileges: bool,
    pub memory_max: u64,
    pub pids_max: u64,
    pub cpu_max: String,
    pub filesystem_confined: bool,
    pub tcp_ports_confined: bool,
}

#[repr(C)]
struct Ruleset {
    filesystem: u64,
    network: u64,
    scoped: u64,
}
#[repr(C, packed)]
struct PathRule {
    access: u64,
    parent: i32,
}
#[repr(C)]
struct PortRule {
    access: u64,
    port: u64,
}

const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const MAKE_SOCK: u64 = 1 << 9;
const ALL_FILESYSTEM: u64 = (1 << 16) - 1;
const STATE_ACCESS: u64 = READ_FILE
    | READ_DIR
    | (1 << 1)
    | (1 << 4)
    | (1 << 5)
    | (1 << 7)
    | (1 << 8)
    | (1 << 13)
    | (1 << 14);

pub fn disable_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "core dump limits could not be disabled"
    );
    // RLIMIT_CORE alone does not constrain a piped host crash collector.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "process dumping could not be disabled"
    );
    ensure!(
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "process dump protection was not retained"
    );
    Ok(())
}

fn syscall_result(value: libc::c_long) -> Result<libc::c_long> {
    if value < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(value)
    }
}

fn status_field<'a>(status: &'a str, name: &str) -> Result<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name).map(str::trim))
        .with_context(|| format!("missing process restriction {name}"))
}

fn numeric_limit(name: &str) -> Result<u64> {
    let value: u64 = fs::read_to_string(Path::new("/sys/fs/cgroup").join(name))?
        .trim()
        .parse()
        .with_context(|| format!("{name} must have a finite limit"))?;
    ensure!(value > 0, "resource limit must be positive");
    Ok(value)
}

fn require_subordinate_mapping(mapping: &str) -> Result<()> {
    let rows: Vec<_> = mapping
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    ensure!(
        rows.len() == 1,
        "a subordinate-only user namespace is required"
    );
    let fields = rows[0]
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    // In rootless Podman's parent namespace, ID zero maps to the login ID;
    // subordinate IDs start at one. /proc reports this immediate-parent map.
    ensure!(
        fields.len() == 3 && fields[0] == 0 && fields[1] == 1 && fields[2] > 0,
        "the rootless nomap namespace must exclude the parent login ID"
    );
    Ok(())
}

pub(crate) fn preflight() -> Result<Profile> {
    ensure!(
        Path::new("/run/.containerenv").is_file(),
        "an isolated OCI container is required"
    );
    ensure!(
        fs::read("/Canary")? == b"HyperNet filesystem canary\n",
        "the isolation canary is missing"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    ensure!(
        status_field(&status, "Threads:")? == "1",
        "confinement must precede thread creation"
    );
    ensure!(
        status_field(&status, "NoNewPrivs:")? == "1",
        "no-new-privileges is required"
    );
    ensure!(
        status_field(&status, "Seccomp:")? == "2",
        "a syscall filter is required"
    );
    for field in ["CapEff:", "CapPrm:", "CapInh:", "CapBnd:", "CapAmb:"] {
        ensure!(
            u64::from_str_radix(status_field(&status, field)?, 16)? == 0,
            "all capability sets must be empty"
        );
    }
    let uid_mapping = fs::read_to_string("/proc/self/uid_map")?;
    require_subordinate_mapping(&uid_mapping)?;
    require_subordinate_mapping(&fs::read_to_string("/proc/self/gid_map")?)?;
    let root_is_readonly = fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() > 5
                && fields[4] == "/"
                && fields[5].split(',').any(|option| option == "ro")
        });
    ensure!(root_is_readonly, "a read-only root filesystem is required");
    let inherited: Vec<i32> = fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    for fd in inherited.into_iter().filter(|fd| *fd > 2) {
        // The directory enumerator is closed before checking the collected list.
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1,
            "an unexpected file descriptor was inherited"
        );
    }
    let memory_max = numeric_limit("memory.max")?;
    let pids_max = numeric_limit("pids.max")?;
    let cpu_max = fs::read_to_string("/sys/fs/cgroup/cpu.max")?
        .trim()
        .to_string();
    let cpu: Vec<u64> = cpu_max
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .context("a finite CPU quota is required")?;
    ensure!(
        cpu.len() == 2 && cpu[0] > 0 && cpu[1] > 0,
        "invalid CPU quota"
    );
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<Ruleset>(),
            0usize,
            1u32,
        )
    };
    let abi = syscall_result(abi).context("Landlock is required")? as u32;
    ensure!(abi >= 6, "Landlock ABI 6 or newer is required");
    Ok(Profile {
        landlock_abi: abi,
        uid_mapping: uid_mapping.trim().to_owned(),
        seccomp: 2,
        no_new_privileges: true,
        memory_max,
        pids_max,
        cpu_max,
        filesystem_confined: false,
        tcp_ports_confined: false,
    })
}

fn path_rule(ruleset: &OwnedFd, path: &Path, access: u64) -> Result<()> {
    let canonical = fs::canonicalize(path)?;
    ensure!(
        canonical != Path::new("/"),
        "the entire root cannot be granted"
    );
    let pathname = CString::new(canonical.as_os_str().as_bytes())?;
    let fd = syscall_result(
        unsafe { libc::open(pathname.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) } as libc::c_long,
    )?;
    let directory = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let rule = PathRule {
        access,
        parent: directory.as_raw_fd(),
    };
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            1u32,
            &rule,
            0u32,
        )
    })?;
    Ok(())
}

fn confined_path(path: &Path, root: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(root)?;
    let canonical = fs::canonicalize(path)?;
    ensure!(
        canonical.starts_with(root),
        "filesystem grant escapes its permitted root"
    );
    Ok(canonical)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputMounts {
    None,
    Bridge,
    Route,
}

fn read_root(path: &Path, authority: bool, mounts: InputMounts) -> Result<&Path> {
    if authority {
        for root in ["/Clock", "/Authorization", "/Authority"] {
            if path == Path::new(root) {
                return Ok(Path::new(root));
            }
        }
        if mounts == InputMounts::Route {
            for root in ["/Egress", "/Application"] {
                if path == Path::new(root) {
                    return Ok(Path::new(root));
                }
            }
        }
        if mounts == InputMounts::Bridge
            && let Some(host) = path
                .to_str()
                .and_then(|s| s.strip_prefix("/Media/"))
                .and_then(|s| s.strip_suffix("/Control"))
            && host.len() == 64
            && host
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Ok(path);
        }
    }
    ensure!(
        path.starts_with("/Config"),
        "read grant is outside the role's fixed input roots"
    );
    Ok(Path::new("/Config"))
}

fn port_rule(ruleset: &OwnedFd, port: u16, access: u64) -> Result<()> {
    ensure!(
        port > 0,
        "ephemeral bind and unrestricted ports are not granted"
    );
    let rule = PortRule {
        access,
        port: u64::from(port),
    };
    syscall_result(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            2u32,
            &rule,
            0u32,
        )
    })?;
    Ok(())
}

pub fn enter(
    state: &Path,
    read_paths: &[PathBuf],
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> Result<Profile> {
    enter_state(
        state,
        read_paths,
        bind_ports,
        connect_ports,
        false,
        false,
        InputMounts::None,
    )
}

/// Authority also reads its fixed clock and consent mounts, never general proc access.
#[allow(dead_code)] // The confined TCP relay shares this module without authority mounts.
pub fn enter_authority(
    state: &Path,
    read_paths: &[PathBuf],
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> Result<Profile> {
    enter_state(
        state,
        read_paths,
        bind_ports,
        connect_ports,
        false,
        true,
        InputMounts::None,
    )
}

/// Bridges add only the exact consented local media control directories.
#[allow(dead_code)] // The confined TCP relay shares this module without bridge mounts.
pub fn enter_bridge(
    state: &Path,
    read_paths: &[PathBuf],
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> Result<Profile> {
    enter_state(
        state,
        read_paths,
        bind_ports,
        connect_ports,
        false,
        true,
        InputMounts::Bridge,
    )
}

/// Routes add only the fixed egress and selected application socket directories.
#[allow(dead_code)] // The standalone confinement checker has no route mounts.
pub fn enter_route(state: &Path, read_paths: &[PathBuf], bind_ports: &[u16]) -> Result<Profile> {
    enter_state(
        state,
        read_paths,
        bind_ports,
        &[],
        false,
        true,
        InputMounts::Route,
    )
}

#[allow(dead_code)]
pub fn enter_mail(
    state: &Path,
    bind_ports: &[u16],
    connect_ports: &[u16],
    maximum: u64,
) -> Result<Profile> {
    let limit = libc::rlimit {
        rlim_cur: maximum,
        rlim_max: maximum,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) } == 0,
        "mail file size limit could not be enforced"
    );
    enter_state(
        state,
        &[],
        bind_ports,
        connect_ports,
        true,
        false,
        InputMounts::None,
    )
}

fn enter_state(
    state: &Path,
    read_paths: &[PathBuf],
    bind_ports: &[u16],
    connect_ports: &[u16],
    single_file: bool,
    authority_clock: bool,
    mounts: InputMounts,
) -> Result<Profile> {
    let mut profile = preflight()?;
    let state = confined_path(state, Path::new("/State"))?;
    ensure!(
        if single_file {
            state.is_file()
        } else {
            state.is_dir()
        },
        "state grant has the wrong file type"
    );
    let attr = Ruleset {
        filesystem: ALL_FILESYSTEM,
        network: 3,
        scoped: 3,
    };
    let fd = syscall_result(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<Ruleset>(),
            0u32,
        )
    })?;
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    path_rule(
        &ruleset,
        &state,
        if single_file {
            READ_FILE | (1 << 1)
        } else if authority_clock {
            STATE_ACCESS | MAKE_SOCK
        } else {
            STATE_ACCESS
        },
    )?;
    if authority_clock && state == Path::new("/State/Replica") {
        let control = confined_path(Path::new("/State/Control"), Path::new("/State"))?;
        ensure!(
            control.is_dir(),
            "installed authority control directory is absent"
        );
        path_rule(&ruleset, &control, STATE_ACCESS | MAKE_SOCK)?;
    }
    for path in read_paths {
        let root = read_root(path, authority_clock, mounts)?;
        let path = confined_path(path, root)?;
        if root != Path::new("/Config") {
            ensure!(
                path == root && path.is_dir(),
                "authority input must be its fixed mount directory without redirection"
            );
        }
        let access = if path.is_dir() {
            READ_FILE | READ_DIR
        } else {
            READ_FILE
        };
        path_rule(&ruleset, &path, access)?;
    }
    if authority_clock {
        for path in [
            "/proc/self/timens_offsets",
            "/proc/sys/kernel/random/boot_id",
        ] {
            path_rule(&ruleset, Path::new(path), READ_FILE)?;
        }
    }
    for port in bind_ports {
        port_rule(&ruleset, *port, 1)?;
    }
    for port in connect_ports {
        port_rule(&ruleset, *port, 2)?;
    }
    syscall_result(unsafe {
        libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32)
    })?;
    profile.filesystem_confined = true;
    profile.tcp_ports_confined = true;
    Ok(profile)
}

/// Canaries are evaluated inside the same restricted process as the service.
pub fn canaries(state: &Path) -> Result<()> {
    ensure!(
        fs::read("/Canary").is_err_and(|error| error.raw_os_error() == Some(libc::EACCES)),
        "filesystem read boundary failed"
    );
    ensure!(
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open("/HyperNetCanary")
            .is_err(),
        "root write boundary failed"
    );
    ensure!(
        std::net::TcpListener::bind("127.0.0.1:1").is_err(),
        "TCP bind boundary failed"
    );
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket >= 0 {
        unsafe {
            libc::close(socket);
        }
        bail!("UDP socket boundary failed");
    }
    let path = state.join("ConfinementCanary");
    fs::write(&path, b"HyperNet")?;
    ensure!(
        fs::read(&path)? == b"HyperNet",
        "state read/write boundary failed"
    );
    fs::remove_file(path)?;
    Ok(())
}

/// Mail grants one fixed file; directory creation and truncation remain denied.
#[allow(dead_code)]
pub fn mail_canaries(state: &Path) -> Result<()> {
    ensure!(
        fs::read("/Canary").is_err(),
        "mail filesystem read boundary failed"
    );
    ensure!(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("/State/Unpermitted")
            .is_err(),
        "mail directory creation boundary failed"
    );
    ensure!(
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(state)
            .is_err(),
        "mail truncation boundary failed"
    );
    ensure!(
        std::net::TcpListener::bind("127.0.0.1:1").is_err(),
        "mail TCP bind boundary failed"
    );
    Ok(())
}

// SSH wrappers progressively reduce inherited access before executing the service.
#[allow(dead_code)]
fn ssh_rules(
    state: Option<&Path>,
    stage: u8,
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> Result<Profile> {
    let mut profile = preflight()?;
    let attr = Ruleset {
        filesystem: ALL_FILESYSTEM,
        network: 3,
        scoped: 3,
    };
    let fd = syscall_result(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<Ruleset>(),
            0u32,
        )
    })?;
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let execute = 1;
    if let Some(state) = state {
        let state = confined_path(state, Path::new("/State"))?;
        ensure!(
            stage == 0 && state == Path::new("/State") && state.is_dir(),
            "SSH authority stores require the dedicated fixed state mount"
        );
        path_rule(&ruleset, &state, STATE_ACCESS)?;
        for root in ["/Clock", "/Authorization", "/Authority", "/Config"] {
            let path = confined_path(Path::new(root), Path::new(root))?;
            ensure!(
                path == Path::new(root) && path.is_dir(),
                "SSH authority input must be a fixed mount without redirection"
            );
            path_rule(&ruleset, &path, READ_FILE | READ_DIR)?;
        }
    }
    for directory in ["/lib", "/lib64", "/usr/lib"] {
        let path = Path::new(directory);
        if path.exists() {
            path_rule(&ruleset, path, READ_FILE | READ_DIR | execute)?;
        }
    }
    path_rule(&ruleset, Path::new("/Service/Command"), READ_FILE | execute)?;
    path_rule(&ruleset, Path::new("/Work"), STATE_ACCESS)?;
    path_rule(&ruleset, Path::new("/dev/null"), READ_FILE | (1 << 1))?;
    path_rule(&ruleset, Path::new("/dev/urandom"), READ_FILE)?;
    if stage < 2 {
        for directory in ["/OpenSSH", "/proc", "/sys/fs/cgroup"] {
            path_rule(
                &ruleset,
                Path::new(directory),
                READ_FILE | READ_DIR | if directory == "/OpenSSH" { execute } else { 0 },
            )?;
        }
        for path in ["/HyperNet", "/bin/sh"] {
            path_rule(&ruleset, Path::new(path), READ_FILE | execute)?;
        }
        for path in [
            "/Canary",
            "/run/.containerenv",
            "/etc/passwd",
            "/etc/group",
            "/etc/nsswitch.conf",
            "/Config/SshHostKey",
        ] {
            path_rule(&ruleset, Path::new(path), READ_FILE)?;
        }
        for path in ["/Config/SshdConfig", "/Config/AuthorizedKeys"] {
            path_rule(&ruleset, Path::new(path), READ_FILE)?;
        }
    }
    for port in bind_ports {
        port_rule(&ruleset, *port, 1)?;
    }
    for port in connect_ports {
        port_rule(&ruleset, *port, 2)?;
    }
    syscall_result(unsafe {
        libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32)
    })?;
    profile.filesystem_confined = true;
    profile.tcp_ports_confined = true;
    Ok(profile)
}
#[allow(dead_code)]
pub fn enter_ssh_parent(
    state: &Path,
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> Result<Profile> {
    ssh_rules(Some(state), 0, bind_ports, connect_ports)
}
#[allow(dead_code)]
pub fn enter_ssh_child(bind_port: u16) -> Result<Profile> {
    ssh_rules(None, 1, &[bind_port], &[])
}
#[allow(dead_code)]
pub fn enter_ssh_command() -> Result<Profile> {
    ssh_rules(None, 2, &[], &[])
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/ConfinementUnitTests.rs"]
mod tests;
