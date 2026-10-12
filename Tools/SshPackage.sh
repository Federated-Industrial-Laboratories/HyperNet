#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Package maintained OpenSSH and one explicitly selected command above a HyperNet image.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 6 ]] || fail 'Usage: SshPackage.sh BaseImageId OpenSSHBuild CommandBinary CommandLicence OutputDirectory Version'
base=$1
ssh_source=$(realpath "$2")
command_binary=$(realpath "$3")
command_licence=$(realpath "$4")
output=$(realpath -m "$5")
version=$6
[[ "$base" =~ ^sha256:[a-f0-9]{64}$ && "$version" == 10.6p1 ]] || fail 'Use an immutable base image and the qualified OpenSSH version'
podman image exists "$base" || fail 'Base image is not installed'
[[ ! -e "$output" && -f "$command_binary" && -x "$command_binary" && -f "$command_licence" ]] || fail 'Select an executable command, its licence and a new output directory'
[[ $("$ssh_source/ssh" -V 2>&1) == OpenSSH_10.6p1,* ]] || fail 'OpenSSH version differs from the qualified profile'
mkdir -p "$output/RootFs/OpenSSH/"{bin,sbin,Libexec} "$output/RootFs/"{Service,Documentation,Work,Empty,etc,bin,State}
chmod 0755 "$output/RootFs/State"
for file in ssh-keygen; do install -m 0555 "$ssh_source/$file" "$output/RootFs/OpenSSH/bin/$file"; done
install -m 0555 "$ssh_source/sshd" "$output/RootFs/OpenSSH/sbin/sshd"
for file in sshd-auth sshd-session; do install -m 0555 "$ssh_source/$file" "$output/RootFs/OpenSSH/Libexec/$file"; done
install -m 0555 "$command_binary" "$output/RootFs/Service/Command"
install -m 0555 /bin/sh "$output/RootFs/bin/sh"
shell_path=$(realpath /bin/sh)
shell_owner=$(dpkg-query -S "$shell_path" | awk -F ': ' 'NF == 2 && $1 !~ /^diversion/ {print $1; exit}')
[[ -n "$shell_owner" ]] || fail 'The command shell has no package ownership record'
shell_version=$(dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}' "$shell_owner")
printf 'Program\tBinaryPackage\tBinaryVersion\tSourcePackage\tSourceVersion\tSha256\n/bin/sh\t%s\t%s\n' "$shell_version" "$(sha256sum /bin/sh | cut -d' ' -f1)" > "$output/RootFs/Documentation/SshSystemPrograms.tsv"
install -m 0444 "/usr/share/doc/${shell_owner%%:*}/copyright" "$output/RootFs/Documentation/ShellLicence.txt"
install -m 0444 "$ssh_source/LICENCE" "$output/RootFs/Documentation/OpenSSHLicence.txt"
install -m 0444 "$command_licence" "$output/RootFs/Documentation/ServiceLicence.txt"
printf 'Library\tBinaryPackage\tBinaryVersion\tSourcePackage\tSourceVersion\tSha256\n' > "$output/RootFs/Documentation/SshSystemLibraries.tsv"
: > "$output/RootFs/Documentation/SshSystemLibraryNotices.txt"
declare -A included=()
for binary in "$ssh_source/ssh-keygen" "$ssh_source/sshd" "$ssh_source/sshd-auth" "$ssh_source/sshd-session" "$command_binary" /bin/sh; do
    while IFS= read -r library; do
        [[ "$library" = /* && -f "$library" ]] || continue
        install -D -m 0555 "$library" "$output/RootFs/$library"
        canonical=$(realpath "$library")
        owner=$(dpkg-query -S "$canonical" | awk -F ': ' 'NF == 2 && $1 !~ /^diversion/ {print $1; exit}')
        [[ -n "$owner" ]] || fail 'A copied library has no package ownership record'
        package=$(dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}' "$owner")
        printf '%s\t%s\t%s\n' "$library" "$package" "$(sha256sum "$library" | cut -d' ' -f1)" >> "$output/RootFs/Documentation/SshSystemLibraries.tsv"
        if [[ ! -v included["$owner"] ]]; then
            included["$owner"]=1
            printf '\nPackage: %s\n\n' "$package" >> "$output/RootFs/Documentation/SshSystemLibraryNotices.txt"
            cat "/usr/share/doc/${owner%%:*}/copyright" >> "$output/RootFs/Documentation/SshSystemLibraryNotices.txt"
        fi
    done < <(ldd "$binary" 2>/dev/null | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}')
done
# The service account has no usable password authentication; PAM is not compiled in.
printf 'root:x:0:0:Container:/:/Unavailable\nHyperNetService:x:1000:1000:Service:/Work:/bin/sh\n' > "$output/RootFs/etc/passwd"
printf 'root:x:0:\nHyperNetService:x:1000:\n' > "$output/RootFs/etc/group"
printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' > "$output/RootFs/etc/nsswitch.conf"
chmod 0444 "$output/RootFs/etc/"*
chmod 0755 "$output/RootFs/OpenSSH/"{bin,sbin,Libexec}
# Runtime state is mounted separately; the image contains no keys or grant credentials.
chmod 0755 "$output/RootFs" "$output/RootFs/"{OpenSSH,Service,Documentation,Work,Empty,etc,bin}
jq -n --arg version "$version" --arg command "$(sha256sum "$command_binary" | cut -d' ' -f1)" '{openSshVersion:$version,commandDigest:$command}' > "$output/RootFs/Documentation/SshProfile.json"
printf 'FROM %s\nCOPY RootFs/ /\nUSER 1000:1000\nENTRYPOINT ["/HyperNet"]\n' "$base" > "$output/Containerfile"
podman build --network=none --pull=never --file "$output/Containerfile" --iidfile "$output/ImageId.txt" "$output"
cat "$output/ImageId.txt"
