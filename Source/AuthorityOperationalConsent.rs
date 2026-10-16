// SPDX-License-Identifier: MIT
//! Operational consent can renew a stable service definition without rewriting its approvals.
use crate::runtime_manifest::Manifest;
use anyhow::{Result, ensure};

pub fn validity(
    current: &Manifest,
    definition: &Manifest,
    interval: (u64, u64),
) -> Result<(u64, u64)> {
    current.permits_definition(definition)?;
    ensure!(
        interval.0 >= definition.validity.0
            && interval.1 <= definition.validity.1
            && interval.0 < interval.1,
        "Service interval exceeds its original operator consent"
    );
    let span = if interval == definition.validity {
        current.validity
    } else {
        (
            interval.0.max(current.validity.0),
            interval.1.min(current.validity.1),
        )
    };
    ensure!(
        span.0 < span.1,
        "Independent service lifetime does not overlap current consent"
    );
    Ok(span)
}
