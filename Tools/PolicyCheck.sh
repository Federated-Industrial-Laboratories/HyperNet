#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Prove policy contracts using GNATprove; an optional argument selects output.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-${XDG_STATE_HOME:-$HOME/.local/state}/HyperNet/PolicyProof}
mkdir -p "$output"
exec "${GNATPROVE:-gnatprove}" -P "$root/Policy/Policy.gpr" \
    -XPolicyOutput="$(realpath "$output")" --level=4 --checks-as-errors=on -j2
