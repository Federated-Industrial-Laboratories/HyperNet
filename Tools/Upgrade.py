#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Switch a stopped profile to a verified compatible image without editing state."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
import Bundle

PREFIXES = {'Authority': 'HyperNetAuthority', 'Host': 'HyperNet', 'Bridge': 'HyperNetBridge',
            'MailStore': 'HyperNetMail', 'TransferStore': 'HyperNetTransfer'}


def compatible(metadata, current_schema):
    Bundle.require(type(current_schema) is int and 1 <= current_schema <= 7, 'Unknown current authority schema')
    Bundle.require(metadata['authoritySchemaMinimum'] == 1 and metadata['authoritySchemaMaximum'] == 7,
                   'Unqualified image state compatibility profile')
    Bundle.require(metadata['authoritySchemaMinimum'] <= current_schema <= metadata['authoritySchemaMaximum'],
                   'The selected image cannot read the declared authority schema')


def stopped(name, kind):
    names = [name]
    if kind == 'Bridge':
        names += [name + 'SourceGate', name + 'DestinationGate']
    elif kind != 'Authority':
        names.append(name + 'Gate')
    for name in names:
        checked = subprocess.run(['podman', 'container', 'exists', name], capture_output=True, timeout=15)
        Bundle.require(checked.returncode == 1, 'Stop and remove every profile container before switching its image')


def switch(args):
    Bundle.require(os.geteuid() != 0 and args.kind in PREFIXES, 'Use a rootless, non-SSH profile')
    profile = Bundle.private_parent(args.profile)
    info = profile.lstat()
    Bundle.require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                   and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                   'The profile directory must be private')
    selected = argparse.Namespace(prefix=args.installation, public_key=args.public_key, ssh_keygen=args.ssh_keygen)
    manifest, _, _ = Bundle.installed_manifest(selected)
    Bundle.require(manifest['architecture'] == Bundle.architecture(), 'Image architecture mismatch')
    compatible(manifest['metadata'], args.state_schema)
    Bundle.image_matches(manifest)
    locks = Path(str(profile) + 'Lifecycle')
    locks.mkdir(mode=0o700, exist_ok=True)
    info = locks.lstat()
    Bundle.require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                   and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                   'Lifecycle directory must be private')
    lock = os.open(locks / 'Lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock)
        Bundle.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                       and stat.S_IMODE(info.st_mode) == 0o600, 'Lifecycle lock must be private')
        fcntl.flock(lock, fcntl.LOCK_EX)
        with Bundle.open_regular(profile / 'Control.json', 65536) as source:
            original = source.read()
            info = os.fstat(source.fileno())
        Bundle.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'Profile control must be private')
        control = Bundle.decode(original)
        expected_name = PREFIXES[args.kind] + hashlib.sha256(str(profile).encode()).hexdigest()[:16]
        Bundle.require(control.get('name') == expected_name and 'grant' not in control, 'Profile kind or identity mismatch')
        Bundle.require(control.get('image') == args.expected_image, 'Current image changed; inspect the profile before retrying')
        stopped(expected_name, args.kind)
        image = manifest['metadata']['imageId']
        control['image'] = image
        descriptor, name = tempfile.mkstemp(prefix='Upgrade', dir=profile)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(Bundle.encode(control))
                output.flush()
                os.fsync(output.fileno())
            os.replace(name, profile / 'Control.json')
            parent = os.open(profile, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return {'kind': args.kind, 'previousImage': args.expected_image, 'imageId': image,
                'runtimeVersion': manifest['version'], 'declaredAuthoritySchema': args.state_schema,
                'started': False, 'stateChanged': False, 'consentChanged': False}
    finally:
        os.close(lock)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=PREFIXES)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--installation', required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--ssh-keygen', default='/usr/bin/ssh-keygen')
    parser.add_argument('--expected-image', required=True)
    parser.add_argument('--state-schema', type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', args.expected_image):
        parser.error('Use the full expected current image ID')
    print(json.dumps(switch(args), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('HyperNet image switch: ' + str(error).encode('ascii', 'backslashreplace').decode(), file=sys.stderr)
        sys.exit(1)
