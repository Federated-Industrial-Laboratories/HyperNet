// SPDX-License-Identifier: MIT
//! Read the current runtime network inventory without allocating resources or exposing host labels.
use super::files;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};

const MAXIMUM: usize = 1024;

fn ranges(inventory: &[Value]) -> Result<Value> {
    ensure!(
        inventory.len() <= MAXIMUM,
        "Network inventory exceeds its bound"
    );
    let mut count = 0;
    let mut ipv4 = BTreeSet::new();
    for network in inventory {
        let subnets = network["subnets"]
            .as_array()
            .context("Network subnet inventory is absent")?;
        count += subnets.len();
        ensure!(count <= MAXIMUM, "Subnet inventory exceeds its bound");
        for subnet in subnets {
            let cidr = subnet["subnet"]
                .as_str()
                .context("Network subnet is not a CIDR")?;
            let (address, prefix) = cidr
                .split_once('/')
                .context("Network subnet prefix is absent")?;
            let prefix: u32 = prefix.parse().context("Invalid network subnet prefix")?;
            match address
                .parse::<IpAddr>()
                .context("Invalid network subnet address")?
            {
                IpAddr::V4(address) => {
                    ensure!(prefix <= 32, "Invalid IPv4 subnet prefix");
                    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                    ensure!(
                        u32::from(address) & !mask == 0,
                        "IPv4 subnet has host bits set"
                    );
                    ipv4.insert(format!("{address}/{prefix}"));
                }
                IpAddr::V6(address) => {
                    ensure!(prefix <= 128, "Invalid IPv6 subnet prefix");
                    let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
                    ensure!(
                        u128::from(address) & !mask == 0,
                        "IPv6 subnet has host bits set"
                    );
                }
            }
        }
    }
    Ok(json!({"version":1,"complete":true,"ipv4Subnets":ipv4}))
}

pub(super) fn run() -> Result<Value> {
    let inventory: Vec<Value> = serde_json::from_slice(&files::podman(&files::strings(&[
        "network", "ls", "--format", "json",
    ]))?)?;
    ranges(&inventory)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeNetworkPreviewUnitTests.rs"]
mod tests;
