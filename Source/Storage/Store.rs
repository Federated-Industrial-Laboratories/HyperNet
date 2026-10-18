// SPDX-License-Identifier: MIT
// Local runtime utilities bound configured files and reject clocks before the epoch.
use anyhow::{Context, Result, bail};
use std::{
    fs::File,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Clock is before the Unix epoch")?
        .as_secs())
}

pub fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        bail!("File exceeds its permitted size");
    }
    Ok(bytes)
}
