#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Manage a consenting rootless host and its fixed-destination network relay.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -ge 2 ]] || fail 'Usage: Host.sh Initialise Directory ConfigDirectory ImageId [EgressNetwork] | Start|Status|Stop|Restart|Withdraw Directory'
action=$1
directory=$(realpath -m "$2")
[[ "$directory" != / && "$directory" != "$HOME" ]] || fail 'Select a dedicated profile directory'
[[ $(id -u) != 0 ]] || fail 'Rootless Podman is required'
[[ $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || fail 'Rootless Podman is required'
source "$(dirname "$0")/Lifecycle.sh"
acquire_lifecycle_lock "$directory"
control="$directory/Control.json"

initialise() {
    [[ $# -ge 2 && $# -le 3 ]] || fail 'Initialise needs ConfigDirectory ImageId [EgressNetwork]'
    [[ ! -e "$directory" ]] || fail 'Profile directory already exists'
    source=$(realpath "$1")
    image=$2
    egress=${3:-podman}
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Use the immutable local image ID'
    podman image exists "$image" || fail 'Image is not installed'
    podman network exists "$egress" || fail 'Egress network does not exist'
    for name in Host.json Consent.json Identity.json Ca.pem Client.pem ClientKey.pem; do
        [[ -f "$source/$name" && ! -L "$source/$name" ]] || fail 'Configuration contains a missing or symbolic file'
    done
    created_network=''
    mkdir -m 0700 "$directory"
    trap 'if [[ -n "$created_network" ]]; then podman network rm "$created_network" >/dev/null 2>&1 || true; fi; podman unshare rm -rf -- "$directory"' EXIT
    mkdir -m 0700 "$directory/Config" "$directory/Gate"
    for name in Host.json Consent.json Identity.json Ca.pem Client.pem ClientKey.pem; do
        install -m 0600 "$source/$name" "$directory/Config/$name"
    done
    # The runtime verifies this exact signed document before requesting a lease.
    payload=$(jq -er '.payload' "$source/Consent.json" | tr '_-' '/+')
    case $((${#payload} % 4)) in 2) payload+='==';; 3) payload+='=';; 1) fail 'Invalid consent encoding';; esac
    consent=$(printf '%s' "$payload" | base64 --decode)
    jq -e --argjson now "$(date +%s)" '
        (["authorityAddress","authorityEndpoint","cpuPeriod","cpuQuota","deviceKey","expires","grants","memoryBytes","network","pids","stateBytes","version"]) as $base |
        .version == 3 and keys == (($base + ["services","namespaces","pageCacheBytes","pageMediaCacheBytes"]) | sort) and
        (.pageCacheBytes | type == "number" and . == floor) and .pageMediaCacheBytes == 0 and
        ((.services == [] and .namespaces == [] and .pageCacheBytes == 0) or
         (.services == ["Pages"] and (.namespaces | type == "array" and length >= 1 and length <= 16 and
              all(type == "string" and test("\\A[A-Za-z][A-Za-z0-9]{0,31}\\z")) and (unique | length) == length) and
          .pageCacheBytes >= 65536 and .pageCacheBytes <= .stateBytes-262144)) and
        .grants == 2 and ([.expires,.memoryBytes,.pids,.cpuPeriod,.cpuQuota,.stateBytes] | all(type == "number" and . == floor)) and
        .expires > $now and .expires <= $now+604800 and .memoryBytes >= 67108864 and .memoryBytes <= 8589934592 and
        .pids >= 16 and .pids <= 512 and .cpuPeriod == 100000 and .cpuQuota >= 1000 and .cpuQuota <= 800000 and
        .stateBytes >= 1048576 and .stateBytes <= 268435456
        ' <<< "$consent" >/dev/null || fail 'Invalid resource or service consent'
    identity=$(printf '%s' "$directory" | sha256sum | cut -c1-16)
    name="HyperNet$identity"
    network="${name}Internal"
    podman network create --internal --label "io.hypernet.profile=$identity" "$network" >/dev/null
    created_network=$network
    subnet=$(podman network inspect "$network" --format '{{(index .Subnets 0).Subnet}}')
    [[ "$subnet" == *.0/24 ]] || fail 'A private IPv4 /24 network is required'
    prefix=${subnet%.*}
    host_address="$prefix.2"
    gate_address="$prefix.3"
    destination=$(jq -er '.authorityAddress' <<< "$consent")
    gate_port=${destination##*:}
    [[ "$gate_port" =~ ^[0-9]+$ && "$gate_port" -gt 0 && "$gate_port" -le 65535 ]] || fail 'Invalid authority port'
    jq --arg relay "$gate_address:$gate_port" '.relayAddress=$relay | .stateDirectory="/State" | .identity="/Config/Identity.json" | .caCertificate="/Config/Ca.pem" | .clientCertificate="/Config/Client.pem" | .clientKey="/Config/ClientKey.pem" | .consentFile="/Config/Consent.json"' \
        "$source/Host.json" > "$directory/Config/Host.json"
    jq -n --arg listen "$gate_address:$gate_port" --arg destination "$destination" --arg source "$host_address" --argjson expires "$(jq -er '.expires' <<< "$consent")" \
        '{listen:$listen,destination:$destination,allowedSource:$source,expires:$expires,bytesPerSecond:1048576,maximumConnections:16,maximumConnectionBytes:16777216}' > "$directory/Gate/Gate.json"
    bash "$(dirname "$0")/Seccomp.sh" "$directory/Seccomp.json"
    jq -n --arg name "$name" --arg image "$image" --arg network "$network" --arg egress "$egress" \
        --arg hostAddress "$host_address" --arg gateAddress "$gate_address" --argjson consent "$consent" \
        '{name:$name,image:$image,network:$network,egress:$egress,hostAddress:$hostAddress,gateAddress:$gateAddress,consent:$consent}' > "$control"
    chmod 0400 "$directory/Config/"* "$directory/Gate/"*
    # Container UID zero maps to the first subordinate UID, never the login UID.
    podman unshare chown -R 1:1 "$directory/Config" "$directory/Gate"
    trap - EXIT
    printf 'Initialised %s\n' "$directory"
}

load() {
    [[ -f "$control" && ! -L "$control" ]] || fail 'Profile is not initialised'
    name=$(jq -er '.name' "$control")
    image=$(jq -er '.image' "$control")
    network=$(jq -er '.network' "$control")
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
    [[ ! -e "$directory/Withdrawn" ]] || fail 'Consent was withdrawn; initialise a new profile with fresh consent'
    jq -e --argjson now "$(date +%s)" '.consent.expires | type == "number" and . == floor and . > $now and . <= $now+604800' "$control" >/dev/null || fail 'Consent is expired or invalid'
    ! podman container exists "$name" || fail 'Host already exists; use Restart'
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
        --volume="$directory/Gate:/Config:ro,nosuid,nodev,noexec,Z" \
        --entrypoint=/HyperNetGate "$image" /Config/Gate.json >/dev/null; then
        stop; fail 'Relay start failed'
    fi
    lifetime=$(consent_lifetime "$(jq -er '.consent.expires' "$control")") || { stop; fail 'Consent expired during startup'; }
    if ! podman run -d --name "$name" "${common[@]}" --timeout="$lifetime" --memory="$memory" --memory-swap="$memory" \
        --pids-limit="$pids" --cpu-period=100000 --cpu-quota="$quota" \
        --tmpfs="/State:rw,noexec,nosuid,nodev,size=$storage,mode=0700" \
        --network="$network:ip=$host_address" --volume="$directory/Config:/Config:ro,nosuid,nodev,noexec,Z" \
        "$image" host --config /Config/Host.json >/dev/null; then
        stop
        fail 'Host start failed'
    fi
    printf 'Started %s\n' "$name"
}

case "$action" in
    Initialise) initialise "${@:3}" ;;
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
        printf 'Local consent withdrawn\n'
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
