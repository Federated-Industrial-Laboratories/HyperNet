#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Extend Podman's maintained allowlist with the network protocol restrictions.
set -euo pipefail
umask 077
[[ $# == 1 ]] || { printf 'Usage: Seccomp.sh OutputFile\n' >&2; exit 2; }
set -o noclobber
jq 'if .defaultAction != "SCMP_ACT_ERRNO" then error("A deny-by-default upstream profile is required") else . end
    | .syscalls |= map(.names -= ["socket","socketcall"] | select(.names | length > 0))
    | .syscalls += [([1,2,10][] as $family | [0,6][] as $protocol
      | select($family != 1 or $protocol == 0)
      | {names:["socket"],action:"SCMP_ACT_ALLOW",args:[
          {index:0,value:$family,op:"SCMP_CMP_EQ"},
          {index:1,value:15,valueTwo:1,op:"SCMP_CMP_MASKED_EQ"},
          {index:2,value:$protocol,op:"SCMP_CMP_EQ"}]})]' \
    /usr/share/containers/seccomp.json > "$1"
