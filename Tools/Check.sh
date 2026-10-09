#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Check formatting, strict Rust diagnostics, tests and launcher syntax.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
jobs=${HYPERNET_JOBS:-4}
cargo fmt --manifest-path "$root/Cargo.toml" -- --check
cargo clippy --manifest-path "$root/Cargo.toml" --locked --all-targets --jobs "$jobs" -- -D warnings
cargo test --manifest-path "$root/Cargo.toml" --locked --jobs "$jobs"
for script in "$root"/Tools/*.sh; do
    bash -n "$script"
done
python3 -B "$root/Tests/Lifecycle.py"
