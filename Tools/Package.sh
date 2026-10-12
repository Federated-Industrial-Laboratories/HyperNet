#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Build a minimal OCI image from trusted binaries; write its immutable image ID.
set -euo pipefail
umask 077
if [[ $# != 2 ]]; then
    printf 'Usage: Package.sh BinaryDirectory OutputDirectory\n' >&2
    exit 2
fi
binary_directory=$(realpath "$1")
output_directory=$(realpath -m "$2")
[[ ! -e "$output_directory" ]] || { printf 'Output directory already exists\n' >&2; exit 1; }
mkdir -p "$output_directory/RootFs/State" "$output_directory/RootFs/Config" "$output_directory/RootFs/etc" "$output_directory/RootFs/Documentation"
command -v dpkg-query >/dev/null || { printf 'This packager requires Debian-format library ownership records\n' >&2; exit 1; }
printf 'Library\tBinaryPackage\tBinaryVersion\tSourcePackage\tSourceVersion\tSha256\n' > "$output_directory/RootFs/Documentation/SystemLibraries.tsv"
: > "$output_directory/RootFs/Documentation/SystemLibraryNotices.txt"
declare -A included_packages=()
for binary in HyperNet HyperNetGate; do
    [[ -f "$binary_directory/$binary" && ! -L "$binary_directory/$binary" ]]
    install -m 0555 "$binary_directory/$binary" "$output_directory/RootFs/$binary"
    while IFS= read -r library; do
        [[ "$library" = /* && -f "$library" ]] || continue
        install -D -m 0555 "$library" "$output_directory/RootFs/$library"
        canonical=$(realpath "$library")
        owner=$(dpkg-query -S "$canonical" | awk -F ': ' 'NF == 2 && $1 !~ /^diversion/ {print $1; exit}')
        [[ -n "$owner" ]] || { printf 'A copied library has no package ownership record\n' >&2; exit 1; }
        version=$(dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}' "$owner")
        digest=$(sha256sum "$library" | cut -d' ' -f1)
        printf '%s\t%s\t%s\n' "$library" "$version" "$digest" >> "$output_directory/RootFs/Documentation/SystemLibraries.tsv"
        if [[ ! -v included_packages["$owner"] ]]; then
            included_packages["$owner"]=1
            printf '\nPackage: %s\n\n' "$version" >> "$output_directory/RootFs/Documentation/SystemLibraryNotices.txt"
            cat "/usr/share/doc/${owner%%:*}/copyright" >> "$output_directory/RootFs/Documentation/SystemLibraryNotices.txt"
        fi
    done < <(ldd "$binary_directory/$binary" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}')
done
for licence in LGPL-2.1 LGPL-3 GPL-2 GPL-3; do
    printf '\nLicence text: %s\n\n' "$licence" >> "$output_directory/RootFs/Documentation/SystemLibraryNotices.txt"
    cat "/usr/share/common-licenses/$licence" >> "$output_directory/RootFs/Documentation/SystemLibraryNotices.txt"
done
repository=$(cd "$(dirname "$0")/.." && pwd)
cp "$repository/Licence.txt" "$repository/Packaging/LibraryLicences.md" "$output_directory/RootFs/Documentation/"
if [[ -f "$repository/Documentation/ThirdPartyNotices.txt" ]]; then
    cp "$repository/Documentation/ThirdPartyNotices.txt" "$output_directory/RootFs/Documentation/"
else
    printf 'Rust dependency notices are required before sharing this local image\n' >&2
fi
printf 'root:x:0:0:Container:/:/Unavailable\n' > "$output_directory/RootFs/etc/passwd"
printf 'HyperNet filesystem canary\n' > "$output_directory/RootFs/Canary"
chmod 0555 "$output_directory/RootFs" "$output_directory/RootFs/etc"
chmod 0444 "$output_directory/RootFs/etc/passwd" "$output_directory/RootFs/Canary"
cp "$(dirname "$0")/../Packaging/Containerfile" "$output_directory/Containerfile"
bash "$(dirname "$0")/Seccomp.sh" "$output_directory/Seccomp.json"
podman build --network=none --pull=never --file "$output_directory/Containerfile" \
    --iidfile "$output_directory/ImageId.txt" "$output_directory"
cat "$output_directory/ImageId.txt"
