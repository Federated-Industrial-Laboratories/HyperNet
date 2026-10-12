#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Operate the installed consenting service lifecycle.
set -euo pipefail
exec HyperNet runtime services "$@"
