#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Installed SSH lifecycle uses the same exact manifest, local consent and quorum activation as other services.
set -euo pipefail
exec HyperNet runtime services "$@"
