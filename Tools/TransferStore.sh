#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Manage a selected transfer store and its fixed authority relay.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -ge 2 ]] || fail 'Usage: TransferStore.sh Initialise Directory ConfigDirectory StateDirectory ImageId EgressNetwork Publication | Renew Directory ConfigDirectory | Start|Status|Stop|Restart|Withdraw Directory'
action=$1
directory=$(realpath -m "$2")
[[ "$directory" != / && "$directory" != "$HOME" ]] || fail 'Select a dedicated profile directory'
[[ $(id -u) != 0 ]] || fail 'Rootless Podman is required'
[[ $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || fail 'Rootless Podman is required'
source "$(dirname "$0")/Lifecycle.sh"
acquire_lifecycle_lock "$directory"
control="$directory/Control.json"

initialise() {
    [[ $# == 5 ]] || fail 'Initialise needs ConfigDirectory StateDirectory ImageId EgressNetwork Publication'
    [[ ! -e "$directory" ]] || fail 'Profile directory already exists'
    source=$(realpath "$1")
    state=$(realpath -m "$2")
    image=$3
    egress=$4
    publication=$5
    [[ "$state" != / && "$state" != "$HOME" && ! -e "$state" && "$state" != "$directory" && "$state" != "$directory/"* ]] || fail 'Select a new dedicated state directory outside the profile'
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Use the immutable local image ID'
    podman image exists "$image" || fail 'Image is not installed'
    podman network exists "$egress" || fail 'Egress network does not exist'
    for name in TransferStore.json Consent.json Identity.json Ca.pem AuthorityCa.pem Client.pem ClientKey.pem; do
        [[ -f "$source/$name" && ! -L "$source/$name" ]] || fail 'Configuration contains a missing or symbolic file'
    done
    created_network=''
    mkdir -m 0700 "$directory"
    trap 'if [[ -n "$created_network" ]]; then podman network rm "$created_network" >/dev/null 2>&1 || true; fi; podman unshare rm -rf -- "$directory"; if [[ -n "${created_state:-}" ]]; then podman unshare rm -rf -- "$state"; fi' EXIT
    mkdir -m 0700 "$directory/Config" "$directory/Gate"
    for name in TransferStore.json Consent.json Identity.json Ca.pem AuthorityCa.pem Client.pem ClientKey.pem; do
        install -m 0600 "$source/$name" "$directory/Config/$name"
    done
    # The runtime verifies this exact signed document before requesting a lease.
    payload=$(jq -er '.payload' "$source/Consent.json" | tr '_-' '/+')
    case $((${#payload} % 4)) in 2) payload+='==';; 3) payload+='=';; 1) fail 'Invalid consent encoding';; esac
    consent=$(printf '%s' "$payload" | base64 --decode)
    jq -e --argjson now "$(date +%s)" '
        .version == 1 and .services == ["Transfer"] and
        ([.generation,.expires,.memoryBytes,.pids,.cpuPeriod,.cpuQuota,.stateBytes] | all(type == "number" and . == floor)) and
        .generation >= 1 and .expires > $now and .expires <= $now+604800 and
        .memoryBytes >= 536870912 and .memoryBytes <= 8589934592 and .pids >= 32 and .pids <= 512 and
        .cpuPeriod == 100000 and .cpuQuota >= 1000 and .cpuQuota <= 800000 and
        .stateBytes >= 8388608 and .stateBytes <= 67108864 and .stateBytes % 4096 == 0
        ' <<< "$consent" >/dev/null || fail 'Invalid transfer resource or service consent'
    listen=$(jq -er '.listen | strings' "$source/TransferStore.json")
    listen_port=${listen##*:}
    public_address=$(jq -er '.address' <<< "$consent")
    public_port=${public_address##*:}
    [[ "$listen_port" =~ ^[0-9]+$ && "$listen_port" -gt 1 && "$listen_port" -le 65535 ]] || fail 'Invalid transfer listen port'
    [[ "$publication" != -* && "$publication" == *":$public_port:$listen_port" ]] || fail 'Publication must map the consented external port to the configured listener'
    mkdir -m 0700 "$state"
    created_state=true
    # Reserve all blocks before starting; runtime cannot grow or truncate this file.
    fallocate --length "$(jq -er '.stateBytes' <<< "$consent")" "$state/TransferState.bin"
    chmod 0600 "$state/TransferState.bin"
    identity=$(printf '%s' "$directory" | sha256sum | cut -c1-16)
    name="HyperNetTransfer$identity"
    network="${name}Internal"
    podman network create --internal --disable-dns --label "io.hypernet.profile=$identity" "$network" >/dev/null
    created_network=$network
    subnet=$(podman network inspect "$network" --format '{{(index .Subnets 0).Subnet}}')
    [[ "$subnet" == *.0/24 ]] || fail 'A private IPv4 /24 network is required'
    prefix=${subnet%.*}
    host_address="$prefix.2"
    gate_address="$prefix.3"
    destination=$(jq -er '.authorityAddress' <<< "$consent")
    gate_port=${destination##*:}
    [[ "$gate_port" =~ ^[0-9]+$ && "$gate_port" -gt 0 && "$gate_port" -le 65535 ]] || fail 'Invalid authority port'
    jq --arg relay "$gate_address:$gate_port" '.relayAddress=$relay | .stateFile="/State/TransferState.bin" | .identity="/Config/Identity.json" | .authorityCa="/Config/AuthorityCa.pem" | .caCertificate="/Config/Ca.pem" | .certificate="/Config/Client.pem" | .privateKey="/Config/ClientKey.pem" | .consentFile="/Config/Consent.json"' \
        "$source/TransferStore.json" > "$directory/Config/TransferStore.json"
    jq -n --arg listen "$gate_address:$gate_port" --arg destination "$destination" --arg source "$host_address" --argjson expires "$(jq -er '.expires' <<< "$consent")" \
        '{listen:$listen,destination:$destination,allowedSource:$source,expires:$expires,bytesPerSecond:1048576,maximumConnections:16,maximumConnectionBytes:16777216}' > "$directory/Gate/Gate.json"
    bash "$(dirname "$0")/Seccomp.sh" "$directory/Seccomp.json"
    jq -n --arg name "$name" --arg image "$image" --arg network "$network" --arg egress "$egress" \
        --arg hostAddress "$host_address" --arg gateAddress "$gate_address" --arg state "$state" --arg publication "$publication" --argjson consent "$consent" \
        '{name:$name,image:$image,network:$network,egress:$egress,hostAddress:$hostAddress,gateAddress:$gateAddress,state:$state,publication:$publication,consent:$consent}' > "$control"
    chmod 0400 "$directory/Config/"* "$directory/Gate/"*
    # Container UID zero maps to the first subordinate UID, never the login UID.
    podman unshare chown -R 1:1 "$directory/Config" "$directory/Gate" "$state"
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
    egress=$(jq -er '.egress' "$control")
    common=(--pull=never --read-only --read-only-tmpfs=false --userns=nomap --user=0:0
        --cap-drop=all --security-opt=no-new-privileges --security-opt="seccomp=$directory/Seccomp.json"
        --ipc=private --pid=private --ulimit=nofile=256:256 --ulimit=core=0:0 --log-driver=k8s-file --log-opt=max-size=1mb)
}

stop() {
    for container in "$name" "${name}Gate"; do
        if podman container exists "$container"; then
            podman stop --time=1 "$container" >/dev/null
            podman rm "$container" >/dev/null
        fi
    done
}

start() {
    [[ ! -e "$directory/RenewalPending" ]] || fail 'Incomplete renewal requires operator recovery before restart'
    [[ ! -e "$directory/Withdrawn" ]] || fail 'Consent was withdrawn; initialise a new profile with fresh consent'
    jq -e --argjson now "$(date +%s)" '.consent.expires | type == "number" and . == floor and . > $now and . <= $now+604800' "$control" >/dev/null || fail 'Consent is expired or invalid'
    ! podman container exists "$name" || fail 'Transfer store already exists; use Restart'
    ! podman container exists "${name}Gate" || fail 'Relay already exists; use Restart'
    gate_address=$(jq -er '.gateAddress' "$control")
    host_address=$(jq -er '.hostAddress' "$control")
    memory=$(jq -er '.consent.memoryBytes' "$control")
    pids=$(jq -er '.consent.pids' "$control")
    quota=$(jq -er '.consent.cpuQuota' "$control")
    storage=$(jq -er '.consent.stateBytes' "$control")
    lifetime=$(consent_lifetime "$(jq -er '.consent.expires' "$control")") || fail 'Consent expired during startup'
    if ! podman run -d --name "${name}Gate" "${common[@]}" --timeout="$lifetime" --memory=134217728 --memory-swap=134217728 \
        --pids-limit=32 --cpu-period=100000 --cpu-quota=50000 \
        --tmpfs=/State:rw,noexec,nosuid,nodev,size=8388608,mode=0700 \
        --network="$network:ip=$gate_address" --network="$egress" \
        --volume="$directory/Gate:/Config:ro,nosuid,nodev,noexec" \
        --entrypoint=/HyperNetGate "$image" /Config/Gate.json >/dev/null; then
        stop; fail 'Relay start failed'
    fi
    lifetime=$(consent_lifetime "$(jq -er '.consent.expires' "$control")") || { stop; fail 'Consent expired during startup'; }
    if ! podman run -d --name "$name" "${common[@]}" --timeout="$lifetime" --memory="$memory" --memory-swap="$memory" \
        --pids-limit="$pids" --cpu-period=100000 --cpu-quota="$quota" \
        --ulimit="fsize=$storage:$storage" --publish="$publication" \
        --volume="$state/TransferState.bin:/State/TransferState.bin:rw,nosuid,nodev,noexec" \
        --network="$network:ip=$host_address" --volume="$directory/Config:/Config:ro,nosuid,nodev,noexec" \
        "$image" transfer-store --config /Config/TransferStore.json >/dev/null; then
        stop
        fail 'Transfer store start failed'
    fi
    printf 'Started %s\n' "$name"
}

renew() {
    [[ $# == 1 ]] || fail 'Renew needs ConfigDirectory'
    source=$(realpath "$1")
    [[ ! -e "$directory/RenewalPending" && ! -e "$directory/Renewal" ]] || fail 'Incomplete renewal requires operator recovery'
    for file in TransferStore.json Consent.json Identity.json Ca.pem AuthorityCa.pem Client.pem ClientKey.pem; do
        [[ -f "$source/$file" && ! -L "$source/$file" ]] || fail 'Configuration contains a missing or symbolic file'
    done
    payload=$(jq -er '.payload' "$source/Consent.json" | tr '_-' '/+')
    case $((${#payload} % 4)) in 2) payload+='==';; 3) payload+='=';; 1) fail 'Invalid consent encoding';; esac
    consent=$(printf '%s' "$payload" | base64 --decode)
    jq -e --argjson previous "$(jq '.consent' "$control")" --argjson now "$(date +%s)" '
        .version == 1 and .services == ["Transfer"] and .network == $previous.network and
        .hostKey == $previous.hostKey and .authoritySigner == $previous.authoritySigner and
        .generation == $previous.generation+1 and .stateBytes == $previous.stateBytes and
        .endpoint == $previous.endpoint and .address == $previous.address and
        .authorityEndpoint == $previous.authorityEndpoint and .authorityAddress == $previous.authorityAddress and
        .expires > $now and .expires <= $now+604800 and
        ([.generation,.expires,.memoryBytes,.pids,.cpuPeriod,.cpuQuota,.stateBytes] | all(type == "number" and . == floor)) and
        .memoryBytes >= 536870912 and .memoryBytes <= 8589934592 and .pids >= 32 and .pids <= 512 and
        .cpuPeriod == 100000 and .cpuQuota >= 1000 and .cpuQuota <= 800000
        ' <<< "$consent" >/dev/null || fail 'Renewal must preserve identity, endpoints and state size with the exact next generation'
    listen=$(jq -er '.listen' "$source/TransferStore.json")
    [[ "$publication" == *":${listen##*:}" ]] || fail 'Renewal must preserve the internal listener port'
    [[ $(jq -er '.publicKey' "$source/Identity.json") == "$(jq -er '.hostKey' <<< "$consent")" ]] || fail 'Renewal signing identity differs'
    stop
    staging="$directory/Renewal"
    mkdir -m 0700 "$staging" "$staging/Config" "$staging/Gate"
    for file in Consent.json Identity.json Ca.pem AuthorityCa.pem Client.pem ClientKey.pem; do
        install -m 0400 "$source/$file" "$staging/Config/$file"
    done
    gate_address=$(jq -er '.gateAddress' "$control")
    host_address=$(jq -er '.hostAddress' "$control")
    destination=$(jq -er '.authorityAddress' <<< "$consent")
    gate_port=${destination##*:}
    jq --arg relay "$gate_address:$gate_port" '.relayAddress=$relay | .stateFile="/State/TransferState.bin" | .identity="/Config/Identity.json" | .authorityCa="/Config/AuthorityCa.pem" | .caCertificate="/Config/Ca.pem" | .certificate="/Config/Client.pem" | .privateKey="/Config/ClientKey.pem" | .consentFile="/Config/Consent.json"' \
        "$source/TransferStore.json" > "$staging/Config/TransferStore.json"
    jq -n --arg listen "$gate_address:$gate_port" --arg destination "$destination" --arg source "$host_address" --argjson expires "$(jq -er '.expires' <<< "$consent")" \
        '{listen:$listen,destination:$destination,allowedSource:$source,expires:$expires,bytesPerSecond:1048576,maximumConnections:16,maximumConnectionBytes:16777216}' > "$staging/Gate/Gate.json"
    jq --argjson consent "$consent" '.consent=$consent' "$control" > "$staging/Control.json"
    chmod 0400 "$staging/Config/"* "$staging/Gate/"*
    podman unshare chown -R 1:1 "$staging/Config" "$staging/Gate"
    printf 'Renewal pending\n' > "$directory/RenewalPending"
    sync -f "$directory"
    mv "$directory/Config" "$directory/PreviousConfig"
    mv "$directory/Gate" "$directory/PreviousGate"
    # Reparenting a directory changes its parent entry and needs its owner rights.
    podman unshare mv "$staging/Config" "$directory/Config"
    podman unshare mv "$staging/Gate" "$directory/Gate"
    mv "$staging/Control.json" "$control"
    sync -f "$directory"
    podman unshare rm -rf -- "$directory/PreviousConfig" "$directory/PreviousGate"
    rmdir "$staging"
    rm -f -- "$directory/Withdrawn" "$directory/RenewalPending"
    sync -f "$directory"
    printf 'Renewed local transfer consent; start the retained store after authority registration\n'
}

case "$action" in
    Initialise) initialise "${@:3}" ;;
    Renew) [[ $# == 3 ]] || fail 'Renew needs ConfigDirectory'; load; renew "$3" ;;
    Start) [[ $# == 2 ]] || fail 'Unexpected arguments'; load; start ;;
    Stop) [[ $# == 2 ]] || fail 'Unexpected arguments'; load; stop ;;
    Restart) [[ $# == 2 ]] || fail 'Unexpected arguments'; load; stop; start ;;
    Withdraw)
        [[ $# == 2 ]] || fail 'Unexpected arguments'; load
        persisted=true
        printf 'Withdrawn\n' > "$directory/Withdrawn" || persisted=false
        for container in "$name" "${name}Gate"; do
            if podman container exists "$container"; then
                podman kill --signal=KILL "$container" >/dev/null 2>&1 || true
            fi
        done
        stop
        if [[ "$persisted" == true ]]; then
            sync -f "$directory/Withdrawn" || persisted=false
            sync -f "$directory" || persisted=false
        fi
        [[ "$persisted" == true ]] || fail 'Host stopped, but withdrawal could not be persisted; do not restart this profile'
        printf 'Local transfer consent withdrawn\n'
        ;;
    Status)
        [[ $# == 2 ]] || fail 'Unexpected arguments'; load
        if podman container exists "$name"; then
            podman inspect --format '{{json .State}}' "$name"
            podman logs --tail=1 "$name"
        else printf '{"running":false}\n'; fi
        ;;
    *) fail 'Unknown action' ;;
esac
