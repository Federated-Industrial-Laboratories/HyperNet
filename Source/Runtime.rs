// SPDX-License-Identifier: MIT
#[path = "RuntimeBootstrap.rs"]
mod bootstrap;
#[path = "RuntimeContainers.rs"]
mod containers;
#[path = "RuntimeControl.rs"]
mod control;
#[path = "RuntimeFiles.rs"]
mod files;
#[path = "RuntimeModel.rs"]
mod model;
#[path = "RuntimeSetup.rs"]
mod setup;

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use model::{Operation, Request};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
#[derive(Args)]
pub struct Location {
    #[arg(long)]
    directory: PathBuf,
}
#[derive(Args)]
pub struct Mutation {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    operation_id: String,
    #[arg(long)]
    expected_generation: u64,
    #[arg(long)]
    profile_digest: String,
}
#[derive(Subcommand)]
pub enum Command {
    Setup(setup::Setup),
    Preview(Location),
    Status(Location),
    Diagnose(Location),
    Consent(Mutation),
    Start(Mutation),
    Stop(Mutation),
    Withdraw(Mutation),
    Serve(Location),
}
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn terminate(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn peer(stream: &UnixStream) -> Result<()> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } == 0
            && size as usize == std::mem::size_of::<libc::ucred>()
            && credentials.uid == unsafe { libc::geteuid() },
        "Local peer is not the runtime owner"
    );
    Ok(())
}
fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length > 0 && length <= 16384,
        "Management request exceeds bound"
    );
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 16384, "Management response exceeds bound");
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}
fn client(root: &Path, request: &Request) -> Result<serde_json::Value> {
    let mut stream = UnixStream::connect(root.join("Management.sock"))
        .context("Start requires the foreground runtime serve session")?;
    peer(&stream)?;
    stream.set_read_timeout(Some(Duration::from_secs(180)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_frame(&mut stream, &serde_json::to_vec(request)?)?;
    let response: serde_json::Value = serde_json::from_slice(&read_frame(&mut stream)?)?;
    ensure!(
        response["ok"] == true,
        "Runtime manager refused operation: {}",
        response["error"].as_str().unwrap_or("OperationFailed")
    );
    Ok(response["result"].clone())
}
fn serve(path: &Path) -> Result<()> {
    let root = files::root(path)?;
    if !root.join("Manager").exists() {
        files::directory(&root.join("Manager"))?;
    }
    let _manager = files::manager_lock(&root.join("Manager"))?;
    let socket = root.join("Management.sock");
    if let Ok(m) = fs::symlink_metadata(&socket) {
        ensure!(
            m.file_type().is_socket()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "Unexpected management socket"
        );
        ensure!(
            UnixStream::connect(&socket).is_err(),
            "Manager already running"
        );
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let identity = fs::symlink_metadata(&socket)?;
    listener.set_nonblocking(true)?;
    STOP.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGTERM, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, terminate as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, terminate as *const () as libc::sighandler_t);
    }
    println!(
        "{}",
        serde_json::json!({"status":"ManagementReady","networkListener":false,"session":"Foreground","automaticBoot":false})
    );
    let outcome = (|| -> Result<()> {
        loop {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let (p, _) = model::load(&root)?;
            if files::now()? >= p.expires {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                    let result = (|| -> Result<serde_json::Value> {
                        peer(&stream)?;
                        let request: Request = serde_json::from_slice(&read_frame(&mut stream)?)?;
                        control::dispatch(&root, request)
                    })();
                    let response = match result {
                        Ok(value) => serde_json::json!({"ok":true,"result":value}),
                        Err(error) => serde_json::json!({"ok":false,"error":format!("{error:#}")}),
                    };
                    let _ = write_frame(&mut stream, &serde_json::to_vec(&response)?);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    })();
    let stopped = control::session_stop(&root);
    if let Ok(m) = fs::symlink_metadata(&socket)
        && m.dev() == identity.dev()
        && m.ino() == identity.ino()
    {
        fs::remove_file(socket)?;
    }
    outcome?;
    stopped
}
fn operate(
    directory: PathBuf,
    operation: Operation,
    mutation: Option<Mutation>,
) -> Result<serde_json::Value> {
    let request = if let Some(m) = mutation {
        Request {
            operation,
            operation_id: Some(m.operation_id),
            expected_generation: Some(m.expected_generation),
            profile_digest: Some(m.profile_digest),
        }
    } else {
        Request {
            operation,
            operation_id: None,
            expected_generation: None,
            profile_digest: None,
        }
    };
    let root = files::root(&directory)?;
    if matches!(request.operation, Operation::Start) {
        client(&root, &request)
    } else {
        control::dispatch(&root, request)
    }
}
pub fn run(command: Command) -> Result<()> {
    let result = match command {
        Command::Setup(args) => setup::setup(args)?,
        Command::Serve(args) => return serve(&args.directory),
        Command::Preview(args) => operate(args.directory, Operation::Preview, None)?,
        Command::Status(args) => operate(args.directory, Operation::Status, None)?,
        Command::Diagnose(args) => operate(args.directory, Operation::Diagnose, None)?,
        Command::Consent(args) => operate(args.directory.clone(), Operation::Consent, Some(args))?,
        Command::Start(args) => operate(args.directory.clone(), Operation::Start, Some(args))?,
        Command::Stop(args) => operate(args.directory.clone(), Operation::Stop, Some(args))?,
        Command::Withdraw(args) => {
            operate(args.directory.clone(), Operation::Withdraw, Some(args))?
        }
    };
    println!("{}", serde_json::to_string(&result)?);
    ensure!(
        result.get("ok") != Some(&serde_json::Value::Bool(false)),
        "Recorded runtime operation failed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_frames_are_bounded_and_unknown_operations_refused() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&16385u32.to_be_bytes()).unwrap();
        assert!(read_frame(&mut b).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"operation":"Shell","operationId":null,"expectedGeneration":null,"profileDigest":null}"#).is_err());
    }
    #[test]
    fn peer_credentials_match_the_actual_socket_owner() {
        let (a, _) = UnixStream::pair().unwrap();
        peer(&a).unwrap();
    }
}
