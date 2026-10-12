// SPDX-License-Identifier: MIT
//! Coupled retained-state bounds; network frame limits are independent.
pub const MAX_RECORDS: usize = 2048;
pub const MAX_STREAMS: usize = 256;
pub const MAX_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_GOVERNANCE_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_STREAM_BYTES: usize = 1024 * 1024;
pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DEPLOYMENT_EVIDENCE: usize = 80 * 1024;
pub const MAX_OTHER_EVIDENCE: usize = 16 * 1024;
pub const WITHDRAWAL_RECORD_RESERVE: usize = 8 * 1024;
pub const WITHDRAWAL_RESULT_RESERVE: usize = 16 * 1024;
// Four retained state copies and two apply copies expand at most fourfold in JSON.
// 16 MiB base + (8 MiB - 256 KiB) * 6 * 4 = 202 MiB; retain 22 MiB margin.
pub const MAX_JOURNAL_BYTES: usize = 224 * 1024 * 1024;
pub const MAX_JOURNAL_ALLOCATION: u64 = 225 * 1024 * 1024;
