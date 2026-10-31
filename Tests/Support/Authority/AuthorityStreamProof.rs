// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
impl StreamResponse {
    #[cfg(test)]
    pub fn metadata(&self) -> &OwnStreamMetadata {
        match self {
            Self::Status(metadata) | Self::Fence { metadata, .. } => metadata,
        }
    }
}
