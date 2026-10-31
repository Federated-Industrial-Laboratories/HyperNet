// SPDX-License-Identifier: MIT
// Installed epoch handoff copies only the exact indexed immutable object directory.
use super::super::files as runtime_files;
use crate::{
    authority_capacity, authority_files,
    authority_object_files::{Directory, INDEX},
    authority_objects::EpochIndex,
    trust_wire,
};
use anyhow::{Result, ensure};
use std::path::Path;

pub(super) fn open(path: &Path, terminal_state: &[u8]) -> Result<Directory> {
    let bytes =
        authority_files::read(&path.join(INDEX), authority_capacity::MAX_STATE_BYTES, true)?;
    let index = EpochIndex::parse(&bytes)?;
    ensure!(
        index.terminal_state() == trust_wire::digest(terminal_state),
        "epoch object index differs from the exact terminal state"
    );
    // The stopped signer independently derives the complete required closure before Ready.
    Directory::open(path, &index)
}

pub(super) fn copy(source: &Directory, destination: &Path) -> Result<()> {
    runtime_files::safe_path(destination)?;
    ensure!(
        destination.is_absolute(),
        "epoch objects require an absolute private path"
    );
    if destination.try_exists()? {
        let retained = Directory::open(destination, source.index())?;
        for reference in source.index().references() {
            ensure!(
                retained.read(reference)? == source.read(reference)?,
                "existing epoch object differs; no file replaced"
            );
        }
        Ok(())
    } else {
        Directory::create(destination, source.index(), |reference| {
            source.read(reference)
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Runtime/RuntimeEpochObjectsUnitTests.rs"]
mod tests;
