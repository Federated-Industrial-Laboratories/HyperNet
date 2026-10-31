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
if not path.is_absolute() or path.resolve() != path:
    raise SystemExit('Test directory must be canonical and absolute')
for ancestor in path.parents:
    metadata = ancestor.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
        raise SystemExit('Test directory ancestors must not be writable by other accounts: ' + str(ancestor))
# The longest socket fixture adds a 17-byte directory and Control.sock.
if len(os.fsencode(path / ('S' + '0' * 16) / 'Control.sock')) >= 108:
    raise SystemExit('Test directory is too long for Unix sockets; set HYPERNET_TEST_DIRECTORY to a shorter private path')
PYTHON
cargo fmt --manifest-path "$root/Cargo.toml" -- --check
# Include files retain module scope and are not discovered by cargo fmt.
shopt -s globstar
rustfmt --edition 2024 --check "$root"/Tests/**/*.rs
cargo clippy --manifest-path "$root/Cargo.toml" --release --locked --all-targets --jobs "$jobs" -- -D warnings
cargo test --manifest-path "$root/Cargo.toml" --release --locked --jobs "$jobs"
for script in "$root"/Tools/*.sh; do
    bash -n "$script"
done
python3 -B "$root/Tests/Bundle.py"
