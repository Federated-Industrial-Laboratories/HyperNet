#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Check formatting, strict Rust diagnostics, tests and launcher syntax.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
jobs=${HYPERNET_JOBS:-4}
# Retain interrupted fixtures on persistent private storage across host restarts.
export TMPDIR=${HYPERNET_TEST_DIRECTORY:-${XDG_STATE_HOME:-$HOME/.local/state}/HyperNet/Tests}
mkdir -p -m 0700 "$TMPDIR"
python3 - "$TMPDIR" <<'PYTHON'
import os
from pathlib import Path
import stat
import sys
path = Path(sys.argv[1])
metadata = path.lstat()
if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
    raise SystemExit('Test directory must be private and owned by the current user')
PYTHON
cargo fmt --manifest-path "$root/Cargo.toml" -- --check
cargo clippy --manifest-path "$root/Cargo.toml" --release --locked --all-targets --jobs "$jobs" -- -D warnings
cargo test --manifest-path "$root/Cargo.toml" --release --locked --jobs "$jobs"
for script in "$root"/Tools/*.sh; do
    bash -n "$script"
done
python3 -B "$root/Tests/Bundle.py"
