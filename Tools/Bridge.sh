#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Manage one consented federation bridge and its two fixed-destination relays.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -ge 2 ]] || fail 'Usage: Bridge.sh Initialise Directory ConfigDirectory ImageId [SourceEgress [DestinationEgress]] | Start|Status|Stop|Restart|Withdraw Directory'
action=$1
directory=$(realpath -m "$2")
[[ "$directory" != / && "$directory" != "$HOME" ]] || fail 'Select a dedicated bridge profile directory'
[[ $(id -u) != 0 ]] || fail 'Rootless Podman is required'
[[ $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || fail 'Rootless Podman is required'
source "$(dirname "$0")/Lifecycle.sh"
acquire_lifecycle_lock "$directory"
control="$directory/Control.json"

initialise() {
    [[ $# -ge 2 && $# -le 4 ]] || fail 'Initialise needs ConfigDirectory ImageId [SourceEgress [DestinationEgress]]'
    [[ ! -e "$directory" ]] || fail 'Bridge profile already exists'
    source=$(realpath "$1")
    image=$2
    source_egress=${3:-podman}
    destination_egress=${4:-$source_egress}
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Use an immutable local image ID'
    podman image exists "$image" || fail 'Image is not installed'
    podman network exists "$source_egress" || fail 'Source egress network does not exist'
    podman network exists "$destination_egress" || fail 'Destination egress network does not exist'
    files=(Bridge.json Consent.json Treaty.json SourceIdentity.json SourceCa.pem SourceClient.pem SourceClientKey.pem
        DestinationIdentity.json DestinationCa.pem DestinationClient.pem DestinationClientKey.pem)
    for file in "${files[@]}"; do
        [[ -f "$source/$file" && ! -L "$source/$file" ]] || fail 'A required configuration file is missing or symbolic'
    done
    [[ $(stat -c %s "$source/Consent.json") -le 16384 ]] || fail 'Bridge consent is too large'
    payload=$(jq -er 'select(keys == ["destinationSignature","payload","sourceSignature"]) | .payload' "$source/Consent.json" | tr '_-' '/+')
    case $((${#payload} % 4)) in 2) payload+='==';; 3) payload+='=';; 1) fail 'Invalid bridge consent encoding';; esac
    consent=$(printf '%s' "$payload" | base64 --decode)
    jq -e --argjson now "$(date +%s)" '
        def hexbytes($size): type == "string" and length == $size*2 and test("\\A[0-9a-f]+\\z");
        def namespace: type == "string" and test("\\A[A-Za-z][A-Za-z0-9]{0,31}\\z");
        def endpoint:
            keys == ["authorityAddress","authorityEndpoint","authorityKey","caCertificateDigest","deviceKey","network"] and
            ([.network,.deviceKey,.authorityKey,.caCertificateDigest] | all(hexbytes(32))) and
            (.authorityAddress | type == "string") and (.authorityEndpoint | type == "string");
        keys == ["agreementId","cpuPeriod","cpuQuota","destination","destinationNamespace","expires","memoryBytes","pids","service","source","sourceNamespace","stateBytes","treatyDigest","version"] and
        .version == 1 and .service == "FederationPages" and (.agreementId | hexbytes(16)) and (.treatyDigest | hexbytes(32)) and
        (.sourceNamespace | namespace) and (.destinationNamespace | namespace) and (.source | endpoint) and (.destination | endpoint) and
        .source.network != .destination.network and
        ([.source.deviceKey,.destination.deviceKey,.source.authorityKey,.destination.authorityKey] | unique | length == 4) and
        ([.expires,.memoryBytes,.pids,.cpuQuota,.cpuPeriod,.stateBytes] | all(type == "number" and . == floor)) and
        .expires > $now and .expires <= $now+604800 and .memoryBytes >= 67108864 and .memoryBytes <= 8589934592 and
        .pids >= 16 and .pids <= 512 and .cpuPeriod == 100000 and .cpuQuota >= 1000 and .cpuQuota <= 800000 and
        .stateBytes >= 1048576 and .stateBytes <= 268435456
        ' <<< "$consent" >/dev/null || fail 'Invalid bridge resource or endpoint consent'
    created_network=''
    mkdir -m 0700 "$directory"
    trap 'if [[ -n "$created_network" ]]; then podman network rm "$created_network" >/dev/null 2>&1 || true; fi; podman unshare rm -rf -- "$directory"' EXIT
    mkdir -m 0700 "$directory/Config" "$directory/SourceGate" "$directory/DestinationGate"
    for file in "${files[@]}"; do install -m 0600 "$source/$file" "$directory/Config/$file"; done
    identity=$(printf '%s' "$directory" | sha256sum | cut -c1-16)
    name="HyperNetBridge$identity"
    network="${name}Internal"
    podman network create --internal --label "io.hypernet.bridge=$identity" "$network" >/dev/null
    created_network=$network
    subnet=$(podman network inspect "$network" --format '{{(index .Subnets 0).Subnet}}')
    [[ "$subnet" == *.0/24 ]] || fail 'A private IPv4 /24 network is required'
    prefix=${subnet%.*}
    bridge_address="$prefix.2"
    source_gate_address="$prefix.3"
    destination_gate_address="$prefix.4"
    for role in Source Destination; do
        field=${role,}
        destination=$(jq -er --arg role "$field" '.[$role].authorityAddress' <<< "$consent")
        port=${destination##*:}
        [[ "$port" =~ ^[0-9]+$ && "$port" -gt 0 && "$port" -le 65535 ]] || fail 'Invalid authority port'
        if [[ "$role" == Source ]]; then gate_address=$source_gate_address; source_relay="$gate_address:$port"
        else gate_address=$destination_gate_address; destination_relay="$gate_address:$port"; fi
        jq -n --arg listen "$gate_address:$port" --arg destination "$destination" --arg source "$bridge_address" --argjson expires "$(jq -er '.expires' <<< "$consent")" \
            '{listen:$listen,destination:$destination,allowedSource:$source,expires:$expires,bytesPerSecond:1048576,maximumConnections:16,maximumConnectionBytes:16777216}' \
            > "$directory/${role}Gate/Gate.json"
    done
    jq --arg sourceRelay "$source_relay" --arg destinationRelay "$destination_relay" '
        .consentFile="/Config/Consent.json" | .treatyFile="/Config/Treaty.json" | .stateDirectory="/State" |
        .source.relayAddress=$sourceRelay | .source.identity="/Config/SourceIdentity.json" |
        .source.caCertificate="/Config/SourceCa.pem" | .source.clientCertificate="/Config/SourceClient.pem" |
        .source.clientKey="/Config/SourceClientKey.pem" |
        .destination.relayAddress=$destinationRelay | .destination.identity="/Config/DestinationIdentity.json" |
        .destination.caCertificate="/Config/DestinationCa.pem" | .destination.clientCertificate="/Config/DestinationClient.pem" |
        .destination.clientKey="/Config/DestinationClientKey.pem"
        ' "$source/Bridge.json" > "$directory/Config/Bridge.json"
    bash "$(dirname "$0")/Seccomp.sh" "$directory/Seccomp.json"
    jq -n --arg name "$name" --arg image "$image" --arg network "$network" --arg sourceEgress "$source_egress" \
        --arg destinationEgress "$destination_egress" --arg bridgeAddress "$bridge_address" \
        --arg sourceGateAddress "$source_gate_address" --arg destinationGateAddress "$destination_gate_address" --argjson consent "$consent" \
        '{name:$name,image:$image,network:$network,sourceEgress:$sourceEgress,destinationEgress:$destinationEgress,
          bridgeAddress:$bridgeAddress,sourceGateAddress:$sourceGateAddress,destinationGateAddress:$destinationGateAddress,consent:$consent}' > "$control"
    chmod 0400 "$directory/Config/"* "$directory/SourceGate/"* "$directory/DestinationGate/"*
    podman unshare chown -R 1:1 "$directory/Config" "$directory/SourceGate" "$directory/DestinationGate"
    trap - EXIT
    printf 'Initialised %s\n' "$directory"
}

load() {
    [[ -f "$control" && ! -L "$control" ]] || fail 'Bridge profile is not initialised'
    name=$(jq -er '.name' "$control")
    image=$(jq -er '.image' "$control")
    network=$(jq -er '.network' "$control")
    common=(--pull=never --read-only --read-only-tmpfs=false --userns=nomap --user=0:0
        --cap-drop=all --security-opt=no-new-privileges --security-opt="seccomp=$directory/Seccomp.json"
        --ipc=private --pid=private --ulimit=nofile=256:256 --ulimit=core=0:0 --log-driver=k8s-file --log-opt=max-size=1mb)
}

stop() {
    for container in "$name" "${name}SourceGate" "${name}DestinationGate"; do
        if podman container exists "$container"; then
            podman stop --time=1 "$container" >/dev/null
            podman rm "$container" >/dev/null
        fi
    done
}

start() {
    [[ ! -e "$directory/Withdrawn" ]] || fail 'Bridge consent was withdrawn; initialise a new profile'
    jq -e --argjson now "$(date +%s)" '.consent.expires | type == "number" and . == floor and . > $now and . <= $now+604800' "$control" >/dev/null || fail 'Bridge consent is expired or invalid'
    for container in "$name" "${name}SourceGate" "${name}DestinationGate"; do
        ! podman container exists "$container" || fail 'Bridge container exists; use Restart'
    done
    for role in Source Destination; do
        field=${role,}
        gate_address=$(jq -er --arg field "${field}GateAddress" '.[$field]' "$control")
        egress=$(jq -er --arg field "${field}Egress" '.[$field]' "$control")
        lifetime=$(consent_lifetime "$(jq -er '.consent.expires' "$control")") || { stop; fail 'Bridge consent expired during startup'; }
        if ! podman run -d --name "${name}${role}Gate" "${common[@]}" --timeout="$lifetime" --memory=134217728 --memory-swap=134217728 \
            --pids-limit=32 --cpu-period=100000 --cpu-quota=50000 \
            --tmpfs=/State:rw,noexec,nosuid,nodev,size=8388608,mode=0700 \
            --network="$network:ip=$gate_address" --network="$egress" \
            --volume="$directory/${role}Gate:/Config:ro,nosuid,nodev,noexec" \
            --entrypoint=/HyperNetGate "$image" /Config/Gate.json >/dev/null; then
            stop; fail 'Bridge relay start failed'
        fi
    done
    bridge_address=$(jq -er '.bridgeAddress' "$control")
    memory=$(jq -er '.consent.memoryBytes' "$control")
    pids=$(jq -er '.consent.pids' "$control")
    quota=$(jq -er '.consent.cpuQuota' "$control")
    storage=$(jq -er '.consent.stateBytes' "$control")
    lifetime=$(consent_lifetime "$(jq -er '.consent.expires' "$control")") || { stop; fail 'Bridge consent expired during startup'; }
    if ! podman run -d --name "$name" "${common[@]}" --timeout="$lifetime" --memory="$memory" --memory-swap="$memory" \
        --pids-limit="$pids" --cpu-period=100000 --cpu-quota="$quota" \
        --tmpfs="/State:rw,noexec,nosuid,nodev,size=$storage,mode=0700" --network="$network:ip=$bridge_address" \
        --volume="$directory/Config:/Config:ro,nosuid,nodev,noexec" "$image" bridge --config /Config/Bridge.json >/dev/null; then
        stop; fail 'Bridge start failed'
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
        for container in "$name" "${name}SourceGate" "${name}DestinationGate"; do
            if podman container exists "$container"; then podman kill --signal=KILL "$container" >/dev/null 2>&1 || true; fi
        done
        stop
        if [[ "$persisted" == true ]]; then
            sync -f "$directory/Withdrawn" || persisted=false
            sync -f "$directory" || persisted=false
        fi
        [[ "$persisted" == true ]] || fail 'Bridge stopped, but withdrawal could not be persisted; do not restart this profile'
        printf 'Local bridge consent withdrawn\n'
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
