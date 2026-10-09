#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Run one explicitly accepted SSH grant in a dedicated rootless PID namespace.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -ge 2 ]] || fail 'Usage: SshService.sh Initialise Directory ConfigDirectory StateDirectory ImageId EgressNetwork Publication | Start|Status|Stop|Restart|Withdraw Directory'
action=$1
directory=$(realpath -m "$2")
[[ "$directory" != / && "$directory" != "$HOME" ]] || fail 'Select a dedicated profile directory'
[[ $(id -u) != 0 && $(podman info --format '{{.Host.Security.Rootless}}') == true ]] || fail 'Rootless Podman is required'
source "$(dirname "$0")/Lifecycle.sh"
acquire_lifecycle_lock "$directory"
control="$directory/Control.json"
initialise() {
    [[ $# == 5 && ! -e "$directory" ]] || fail 'Initialise needs a new profile, ConfigDirectory StateDirectory ImageId EgressNetwork Publication'
    source=$(realpath "$1");state=$(realpath -m "$2");image=$3;egress=$4;publication=$5
    [[ ! -e "$state" && "$state" != / && "$state" != "$HOME" && "$state" != "$directory" && "$state" != "$directory/"* ]] || fail 'Select a new dedicated state directory outside the profile'
    [[ "$image" =~ ^sha256:[a-f0-9]{64}$ ]] || fail 'Use an immutable image ID'
    podman image exists "$image" && podman network exists "$egress" || fail 'Image or egress network is unavailable'
    for file in SshService.json Consent.json Grant.json Identity.json AuthorityCa.pem Client.pem ClientKey.pem SshHostKey; do
        [[ -f "$source/$file" && ! -L "$source/$file" ]] || fail 'Missing or symbolic configuration file'
    done
    payload=$(jq -er '.payload' "$source/Consent.json" | tr '_-' '/+')
    case $((${#payload} % 4)) in 2) payload+='==';; 3) payload+='=';; 1) fail 'Invalid consent encoding';; esac
    consent=$(printf '%s' "$payload" | base64 --decode)
    grant=$(cat "$source/Grant.json")
    jq -e --arg image "${image#sha256:}" --argjson now "$(date +%s)" '
      .version == 1 and .imageDigest == $image and .account == "HyperNetService" and
      ([.generation,.expires,.memoryBytes,.pids,.cpuPeriod,.cpuQuota,.stateBytes,.maximumSessionSeconds] | all(type == "number" and . == floor)) and
      .generation >= 1 and .expires > $now and .expires <= $now+604800 and
      .memoryBytes >= 134217728 and .memoryBytes <= 8589934592 and .pids >= 32 and .pids <= 512 and
      .cpuPeriod == 100000 and .cpuQuota >= 1000 and .cpuQuota <= 800000 and
      .stateBytes >= 8388608 and .stateBytes <= 67108864 and .stateBytes % 4096 == 0 and
      .maximumSessionSeconds >= 1 and .maximumSessionSeconds <= 300' <<< "$consent" >/dev/null || fail 'Invalid service consent/resources'
    jq -e --argjson c "$consent" --argjson now "$(date +%s)" '.accepted == true and .revoked == false and .serviceKey == $c.serviceKey and .serviceGeneration == $c.generation and .account == $c.account and .purpose == $c.purpose and .expires > $now and .expires <= $c.expires and .expires <= $now+$c.maximumSessionSeconds' <<< "$grant" >/dev/null || fail 'Grant does not match current service consent'
    listen=$(jq -er '.listen|strings' "$source/SshService.json");listen_port=${listen##*:};listen_address=${listen%:*};listen_address=${listen_address#\[};listen_address=${listen_address%\]}
    [[ "$listen_port" =~ ^[0-9]+$ && "$listen_port" -gt 1024 && "$listen_port" -le 65535 && "$listen_address" =~ ^[0-9A-Fa-f:.]+$ ]] || fail 'Invalid SSH listener'
    address=$(jq -er '.address' <<< "$consent");public_port=${address##*:}
    [[ "$publication" != -* && "$publication" == *":$public_port:$listen_port" ]] || fail 'Publication must match the consented port'
    mkdir -m 0700 "$directory" "$state";created_network=''
    trap 'if [[ -n "$created_network" ]]; then podman network rm "$created_network" >/dev/null 2>&1 || true; fi; podman unshare rm -rf -- "$directory" "$state"' EXIT
    mkdir -m 0700 "$directory/Config" "$directory/Gate"
    for file in SshService.json Consent.json Grant.json Identity.json AuthorityCa.pem Client.pem ClientKey.pem SshHostKey; do install -m 0600 "$source/$file" "$directory/Config/$file"; done
    sed -e "s/@Port@/$listen_port/g" -e "s/@Address@/$listen_address/g" "$(dirname "$0")/../Packaging/SshdConfig" > "$directory/Config/SshdConfig"
    printf 'restrict %s\n' "$(jq -er '.sshPublicKey' <<< "$grant")" > "$directory/Config/AuthorizedKeys"
    fallocate --length 8192 "$state/SshState.bin";chmod 0600 "$state/SshState.bin"
    identity=$(printf '%s' "$directory" | sha256sum | cut -c1-16);name="HyperNetSsh$identity";network="${name}Internal"
    podman network create --internal --disable-dns --label "io.hypernet.profile=$identity" "$network" >/dev/null;created_network=$network
    subnet=$(podman network inspect "$network" --format '{{(index .Subnets 0).Subnet}}');[[ "$subnet" == *.0/24 ]] || fail 'Private IPv4 /24 required'
    prefix=${subnet%.*};host_address="$prefix.2";gate_address="$prefix.3"
    destination=$(jq -er '.authorityAddress' <<< "$consent");gate_port=${destination##*:};[[ "$gate_port" =~ ^[0-9]+$ ]] || fail 'Invalid authority port'
    expires=$(jq -er '.expires' <<< "$grant")
    jq --arg relay "$gate_address:$gate_port" '.relayAddress=$relay|.stateDirectory="/State"|.identity="/Config/Identity.json"|.authorityCa="/Config/AuthorityCa.pem"|.certificate="/Config/Client.pem"|.privateKey="/Config/ClientKey.pem"|.consentFile="/Config/Consent.json"|.grantFile="/Config/Grant.json"' "$source/SshService.json" > "$directory/Config/SshService.json"
    jq -n --arg listen "$gate_address:$gate_port" --arg destination "$destination" --arg source "$host_address" --argjson expires "$expires" '{listen:$listen,destination:$destination,allowedSource:$source,expires:$expires,bytesPerSecond:1048576,maximumConnections:16,maximumConnectionBytes:16777216}' > "$directory/Gate/Gate.json"
    bash "$(dirname "$0")/Seccomp.sh" "$directory/Seccomp.json"
    jq -n --arg name "$name" --arg image "$image" --arg network "$network" --arg egress "$egress" --arg hostAddress "$host_address" --arg gateAddress "$gate_address" --arg state "$state" --arg publication "$publication" --argjson consent "$consent" --argjson grant "$grant" '{name:$name,image:$image,network:$network,egress:$egress,hostAddress:$hostAddress,gateAddress:$gateAddress,state:$state,publication:$publication,consent:$consent,grant:$grant}' > "$control"
    chmod 0400 "$directory/Config/"* "$directory/Gate/"*
    podman unshare chown -R 1001:1001 "$directory/Config" "$state"
    podman unshare chown -R 1:1 "$directory/Gate"
    trap - EXIT
    printf 'Initialised %s\n' "$directory"
}
load() {
    [[ -f "$control" && ! -L "$control" ]] || fail 'Profile is not initialised'
    name=$(jq -er '.name' "$control");image=$(jq -er '.image' "$control");network=$(jq -er '.network' "$control");state=$(jq -er '.state' "$control");publication=$(jq -er '.publication' "$control");egress=$(jq -er '.egress' "$control")
    common=(--pull=never --read-only --read-only-tmpfs=false --userns=nomap --cap-drop=all --security-opt=no-new-privileges --security-opt="seccomp=$directory/Seccomp.json" --ipc=private --pid=private --ulimit=nofile=256:256 --ulimit=core=0:0 --log-driver=k8s-file --log-opt=max-size=1mb)
}
stop() {
    for container in "$name" "${name}Gate"; do
        if podman container exists "$container"; then podman stop --time=1 "$container" >/dev/null;podman rm "$container" >/dev/null;fi
    done
}
start() {
    [[ ! -e "$directory/Withdrawn" ]] || fail 'Local consent withdrawn; create a fresh profile'
    jq -e --argjson now "$(date +%s)" '.consent.expires > $now and .grant.expires > $now and .grant.expires <= $now+.consent.maximumSessionSeconds and .grant.accepted and (.grant.revoked|not)' "$control" >/dev/null || fail 'Grant or consent expired'
    ! podman container exists "$name" && ! podman container exists "${name}Gate" || fail 'Profile already exists; use Restart'
    gate_address=$(jq -er '.gateAddress' "$control");host_address=$(jq -er '.hostAddress' "$control")
    expires=$(jq -er '.grant.expires' "$control");lifetime=$(consent_lifetime "$expires") || fail 'Grant expired during startup'
    memory=$(jq -er '.consent.memoryBytes' "$control");pids=$(jq -er '.consent.pids' "$control");quota=$(jq -er '.consent.cpuQuota' "$control");storage=$(jq -er '.consent.stateBytes' "$control")
    if ! podman run -d --name "${name}Gate" "${common[@]}" --user=0:0 --timeout="$lifetime" --memory=134217728 --memory-swap=134217728 --pids-limit=32 --cpu-period=100000 --cpu-quota=50000 --tmpfs=/State:rw,noexec,nosuid,nodev,size=8388608,mode=0700 --network="$network:ip=$gate_address" --network="$egress" --volume="$directory/Gate:/Config:ro,nosuid,nodev,noexec" --entrypoint=/HyperNetGate "$image" /Config/Gate.json >/dev/null;then stop;fail 'Relay start failed';fi
    lifetime=$(consent_lifetime "$expires") || { stop;fail 'Grant expired during startup'; }
    if ! podman run -d --name "$name" "${common[@]}" --user=1000:1000 --timeout="$lifetime" --memory="$memory" --memory-swap="$memory" --pids-limit="$pids" --cpu-period=100000 --cpu-quota="$quota" --ulimit="fsize=$storage:$storage" --publish="$publication" --tmpfs="/Work:rw,noexec,nosuid,nodev,size=$((storage-8192)),mode=0700,U" --volume="$state/SshState.bin:/State/SshState.bin:rw,nosuid,nodev,noexec" --network="$network:ip=$host_address" --volume="$directory/Config:/Config:ro,nosuid,nodev,noexec" "$image" ssh-service --config /Config/SshService.json >/dev/null;then stop;fail 'SSH service start failed';fi
    printf 'Started %s\n' "$name"
}
case "$action" in
 Initialise) initialise "${@:3}";;
 Start) [[ $# == 2 ]] || fail 'Unexpected arguments';load;start;;
 Stop) [[ $# == 2 ]] || fail 'Unexpected arguments';load;stop;;
 Restart) [[ $# == 2 ]] || fail 'Unexpected arguments';load;stop;start;;
 Withdraw)
    [[ $# == 2 ]] || fail 'Unexpected arguments';load;persisted=true
    printf 'Withdrawn\n' > "$directory/Withdrawn" || persisted=false
    for container in "$name" "${name}Gate";do if podman container exists "$container";then podman kill --signal=KILL "$container" >/dev/null 2>&1 || true;fi;done
    stop
    if [[ "$persisted" == true ]];then sync -f "$directory/Withdrawn" || persisted=false;sync -f "$directory" || persisted=false;fi
    [[ "$persisted" == true ]] || fail 'Service stopped but withdrawal could not be persisted; do not restart'
    printf 'Local SSH consent withdrawn\n';;
 Status) [[ $# == 2 ]] || fail 'Unexpected arguments';load;if podman container exists "$name";then podman inspect --format '{{json .State}}' "$name";podman logs --tail=1 "$name";else printf '{"running":false}\n';fi;;
 *) fail 'Unknown action';;
esac
