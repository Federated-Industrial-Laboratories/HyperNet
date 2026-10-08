#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Order profile operations using a persistent lock outside removable profile data.

acquire_lifecycle_lock() {
    local profile=$1
    local lock_directory="${profile}Lifecycle"
    local lock_file="$lock_directory/Lock"
    if ! mkdir -m 0700 -- "$lock_directory" 2>/dev/null; then
        [[ -d "$lock_directory" && ! -L "$lock_directory" && -O "$lock_directory" \
            && $(stat -c %a "$lock_directory") == 700 ]] || fail 'Lifecycle lock directory is not private'
    fi
    if [[ -e "$lock_file" || -L "$lock_file" ]]; then
        [[ -f "$lock_file" && ! -L "$lock_file" && -O "$lock_file" \
            && $(stat -c %h "$lock_file") == 1 \
            && $(stat -c %a "$lock_file") == 600 ]] || fail 'Lifecycle lock file is not private'
    fi
    # All cooperating commands retain the same inode, including after failed
    # initialisation. Removing a locked file would permit a second independent lock.
    exec 9>"$lock_file"
    flock --exclusive 9
}

podman() {
    # Detached container supervisors must not extend the lifecycle lock lifetime.
    command podman "$@" 9>&-
}

consent_lifetime() {
    local expires=$1 now
    now=$(date +%s)
    [[ "$expires" =~ ^[0-9]+$ ]] && (( expires > now && expires-now <= 604800 )) || return 1
    printf '%s\n' "$((expires-now))"
}
