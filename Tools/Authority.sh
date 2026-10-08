#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Manage an isolated authority broker with an existing durable rollback floor.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -ge 2 ]] || fail 'Usage: Authority.sh Initialise Profile ConfigDirectory StateDirectory ImageId EgressNetwork Publication | Start|Status|Stop|Restart Profile'
action=$1
directory=$(realpath -m "$2")
[[ "$directory" != / && "$directory" != "$HOME" ]] || fail 'Select a dedicated profile directory'
[[ $(id -u) != 0 && $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || fail 'Rootless Podman is required'
source "$(dirname "$0")/Lifecycle.sh"
acquire_lifecycle_lock "$directory"
control="$directory/Control.json"

initialise() {
    [[ $# == 5 ]] || fail 'Initialise needs ConfigDirectory StateDirectory ImageId EgressNetwork Publication'
    [[ ! -e "$directory" ]] || fail 'Profile directory already exists'
    source=$(realpath "$1")
    state=$(realpath "$2")
    [[ "$directory" != "$state"/* ]] || fail 'Profile and persistent state directories must be separate'
    image=$3
    network=$4
    publication=$5
    [[ "$state" != / && "$state" != "$HOME" && -d "$state" ]] || fail 'Select a dedicated state directory'
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Use the immutable local image ID'
    podman image exists "$image" || fail 'Image is not installed'
    podman network exists "$network" || fail 'Egress network does not exist'
    for name in Authority.json AuthorityCertificate.pem AuthorityKey.pem HostingCa.pem VoterCa.pem BrokerCertificate.pem BrokerKey.pem; do
        [[ -f "$source/$name" && ! -L "$source/$name" ]] || fail 'Configuration contains a missing or symbolic file'
    done
    signing=$(jq -r '.federationSigningKey // empty' "$source/Authority.json")
    if [[ -n "$signing" ]]; then
        [[ -f "$source/FederationSigningKey.json" && ! -L "$source/FederationSigningKey.json" ]] || fail 'Federation requires its separate signing identity file'
    fi
    [[ -f "$state/AuthorityFloor.json" && ! -L "$state/AuthorityFloor.json" && $(stat -c %h "$state/AuthorityFloor.json") == 1 ]] || fail 'A private initialised rollback floor is required'
    for file in "$state"/* "$state"/.[!.]* "$state"/..?*; do
        [[ -e "$file" || -L "$file" ]] || continue
        [[ "$file" == "$state/AuthorityFloor.json" || "$file" == "$state/Authority.lock" ]] || fail 'State directory contains unrelated files'
        [[ -f "$file" && ! -L "$file" && $(stat -c %h "$file") == 1 ]] || fail 'State must contain only private regular files'
    done
    listen=$(jq -er '.listen | strings' "$source/Authority.json")
    port=${listen##*:}
    [[ "$port" =~ ^[0-9]+$ && "$port" -gt 1 && "$port" -le 65535 ]] || fail 'Invalid broker listen port'
    [[ "$publication" == *":$port" && "$publication" != -* ]] || fail 'Publication must explicitly map the configured broker port'
    mkdir -m 0700 "$directory"
    trap 'podman unshare rm -rf -- "$directory"' EXIT
    mkdir -m 0700 "$directory/Config"
    for name in AuthorityCertificate.pem AuthorityKey.pem HostingCa.pem VoterCa.pem BrokerCertificate.pem BrokerKey.pem; do
        install -m 0400 "$source/$name" "$directory/Config/$name"
    done
    if [[ -n "$signing" ]]; then
        install -m 0400 "$source/FederationSigningKey.json" "$directory/Config/FederationSigningKey.json"
    fi
    jq '.stateDirectory="/State" | .certificate="/Config/AuthorityCertificate.pem" | .privateKey="/Config/AuthorityKey.pem" | .clientCa="/Config/HostingCa.pem" | .etcdCa="/Config/VoterCa.pem" | .etcdCertificate="/Config/BrokerCertificate.pem" | .etcdKey="/Config/BrokerKey.pem" | if .federationSigningKey != null then .federationSigningKey="/Config/FederationSigningKey.json" else . end' \
        "$source/Authority.json" > "$directory/Config/Authority.json"
    chmod 0400 "$directory/Config/Authority.json"
    bash "$(dirname "$0")/Seccomp.sh" "$directory/Seccomp.json"
    identity=$(printf '%s' "$directory" | sha256sum | cut -c1-16)
    jq -n --arg name "HyperNetAuthority$identity" --arg image "$image" --arg network "$network" \
        --arg state "$state" --arg publication "$publication" \
        '{name:$name,image:$image,network:$network,state:$state,publication:$publication,memoryBytes:536870912,pids:64,cpuQuota:100000,cpuPeriod:100000}' > "$control"
    chmod 0700 "$state"
    chmod 0600 "$state"/*
    podman unshare chown -R 1:1 "$directory/Config" "$state"
    trap - EXIT
    printf 'Initialised %s\n' "$directory"
}

load() {
    [[ -f "$control" && ! -L "$control" ]] || fail 'Profile is not initialised'
    name=$(jq -er '.name' "$control")
    image=$(jq -er '.image' "$control")
    network=$(jq -er '.network' "$control")
    state=$(jq -er '.state' "$control")
    publication=$(jq -er '.publication' "$control")
}

stop() {
    if podman container exists "$name"; then
        podman stop --time=3 "$name" >/dev/null
        podman rm "$name" >/dev/null
    fi
}

start() {
    ! podman container exists "$name" || fail 'Broker already exists; use Restart'
    podman run -d --name "$name" --pull=never --read-only --read-only-tmpfs=false \
        --userns=nomap --user=0:0 --cap-drop=all --security-opt=no-new-privileges \
        --security-opt="seccomp=$directory/Seccomp.json" --ipc=private --pid=private \
        --ulimit=core=0:0 --ulimit=nofile=256:256 --ulimit=fsize=65536:65536 \
        --memory=536870912 --memory-swap=536870912 --pids-limit=64 \
        --cpu-period=100000 --cpu-quota=100000 --log-driver=k8s-file --log-opt=max-size=1mb \
        --network="$network" --publish="$publication" \
        --volume="$directory/Config:/Config:ro,nosuid,nodev,noexec" \
        --volume="$state:/State:rw,nosuid,nodev,noexec" \
        "$image" authority --config /Config/Authority.json >/dev/null
    printf 'Started %s\n' "$name"
}

case "$action" in
    Initialise) initialise "${@:3}" ;;
    Start) [[ $# == 2 ]] || fail 'Unexpected arguments'; load; start ;;
    Stop) [[ $# == 2 ]] || fail 'Unexpected arguments'; load; stop ;;
    Restart) [[ $# == 2 ]] || fail 'Unexpected arguments'; load; stop; start ;;
    Status)
        [[ $# == 2 ]] || fail 'Unexpected arguments'; load
        if podman container exists "$name"; then
            podman inspect --format '{{json .State}}' "$name"
            podman logs --tail=2 "$name"
        else printf '{"running":false}\n'; fi
        ;;
    *) fail 'Unknown action' ;;
esac
