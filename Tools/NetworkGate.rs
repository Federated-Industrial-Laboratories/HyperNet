// SPDX-License-Identifier: MIT
//! Fixed-destination, bounded TCP relay for an isolated internal network.
#[path = "../Source/Confinement.rs"]
mod confinement;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    time::{Instant, sleep_until, timeout},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Configuration {
    listen: SocketAddr,
    destination: SocketAddr,
    allowed_source: std::net::IpAddr,
    bytes_per_second: u64,
    maximum_connections: usize,
    maximum_connection_bytes: u64,
}

async fn copy(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    schedule: Arc<Mutex<Instant>>,
    rate: u64,
    maximum: u64,
) -> Result<()> {
    let mut buffer = [0u8; 8192];
    let mut count = 0u64;
    loop {
        let length = timeout(Duration::from_secs(10), reader.read(&mut buffer)).await??;
        if length == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        count = count
            .checked_add(length as u64)
            .context("connection byte limit")?;
        ensure!(count <= maximum, "connection byte limit");
        let ready = {
            let mut next = schedule.lock().await;
            let ready = (*next).max(Instant::now());
            *next = ready + Duration::from_secs_f64(length as f64 / rate as f64);
            ready
        };
        sleep_until(ready).await;
        timeout(Duration::from_secs(5), writer.write_all(&buffer[..length])).await??;
    }
}

async fn run(config: Configuration) -> Result<()> {
    let listener = TcpListener::bind(config.listen).await?;
    let slots = Arc::new(Semaphore::new(config.maximum_connections));
    let schedule = Arc::new(Mutex::new(Instant::now()));
    loop {
        let (incoming, source) = listener.accept().await?;
        if source.ip() != config.allowed_source {
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let destination = config.destination;
        let rate = config.bytes_per_second;
        let maximum = config.maximum_connection_bytes;
        let schedule = schedule.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let result: Result<()> = async {
                let outgoing =
                    timeout(Duration::from_secs(3), TcpStream::connect(destination)).await??;
                let (in_read, in_write) = incoming.into_split();
                let (out_read, out_write) = outgoing.into_split();
                // Either direction ending also terminates the peer direction.
                tokio::select! {
                    result = copy(in_read, out_write, schedule.clone(), rate, maximum) => result,
                    result = copy(out_read, in_write, schedule, rate, maximum) => result,
                }
            }
            .await;
            if result.is_err() {
                eprintln!("ConnectionClosed");
            }
        });
    }
}

fn main() -> Result<()> {
    confinement::disable_dumps()?;
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .context("usage: HyperNetGate /Config/Gate.json")?,
    );
    ensure!(
        args.next().is_none() && path.starts_with("/Config"),
        "invalid configuration path"
    );
    let bytes = std::fs::read(&path)?;
    ensure!(bytes.len() <= 8192, "configuration is too large");
    let config: Configuration = serde_json::from_slice(&bytes)?;
    ensure!(
        (1024..=64 * 1024 * 1024).contains(&config.bytes_per_second),
        "invalid rate limit"
    );
    ensure!(
        (1..=64).contains(&config.maximum_connections),
        "invalid connection limit"
    );
    ensure!(
        (16384..=64 * 1024 * 1024).contains(&config.maximum_connection_bytes),
        "invalid byte limit"
    );
    ensure!(
        !config.destination.ip().is_unspecified() && config.destination.port() > 0,
        "invalid destination"
    );
    let profile = confinement::enter(
        Path::new("/State"),
        &[path],
        &[config.listen.port()],
        &[config.destination.port()],
    )?;
    confinement::canaries(Path::new("/State"))?;
    println!("{}", serde_json::to_string(&profile)?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(config))
}
