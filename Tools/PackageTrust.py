#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite offline update policy and an independently pinned local rollback floor."""
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

MAX_POLICY = 16384
MAX_INTEGER = (1 << 63) - 1
CONTRACTS = {'HyperNet': 'HyperNet080Authority1', 'HyperNetSuite': 'HyperNet080Client1'}
TARGET_FIELDS = {'format', 'product', 'architecture', 'version', 'versionFloor',
                 'stateContract', 'rootGeneration', 'rootPin', 'sequence',
                 'notBefore', 'expires', 'archiveSha256', 'archiveBytes', 'manifestSha256'}
TRUST_FIELDS = {'format', 'product', 'architecture', 'rootGeneration', 'rootPin',
                'publicKey', 'versionFloor', 'stateContract', 'sequence', 'targetDigest', 'lastTime'}


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_INTEGER


def version(api, value):
    api.require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})', value), 'Invalid update version')
    return tuple(map(int, value.split('.')))


def pin(key):
    return hashlib.sha256((key + '\n').encode('ascii')).hexdigest()


def digest(api, value):
    return hashlib.sha256(api.encode(value)).hexdigest()


def clock(api, floor):
    now = int(time.time())
    api.require(integer(now, 1) and now >= floor, 'Package clock moved behind the retained time floor')
    return now


def canonical(api, data):
    api.require(len(data) <= MAX_POLICY, 'Update metadata exceeds its bound')
    value = api.decode(data)
    api.require(api.encode(value) == data, 'Update metadata must use canonical JSON')
    return value


def owner_file(api, path):
    with api.open_regular(path, MAX_POLICY) as source:
        info = os.fstat(source.fileno())
        api.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'Trust files must be private owner files')
        return source.read(MAX_POLICY + 1)


def directory(api, path):
    path = api.private_parent(path)
    info = path.lstat()
    api.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'Trust directory must be a private owner directory')
    return path


def save(api, root, value):
    data = api.encode(value)
    api.require(len(data) <= MAX_POLICY, 'Trust state exceeds its bound')
    fd, name = tempfile.mkstemp(prefix='Pending', dir=root)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, root / 'Trust.json')
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def validate_trust(api, value):
    api.require(isinstance(value, dict) and set(value) == TRUST_FIELDS, 'Invalid package trust state')
    api.require(type(value['format']) is int and value['format'] == 1
                and value['product'] == api.PRODUCT and value['architecture'] == api.architecture(), 'Wrong package trust scope')
    api.require(value['stateContract'] == CONTRACTS[api.PRODUCT], 'Unsupported package state contract')
    api.require(integer(value['rootGeneration'], 1) and integer(value['sequence'])
                and integer(value['lastTime'], 1), 'Invalid package trust counters')
    version(api, value['versionFloor'])
    api.require(isinstance(value['publicKey'], str) and len(value['publicKey']) <= 256
                and isinstance(value['rootPin'], str) and api.HEX.fullmatch(value['rootPin'])
                and pin(value['publicKey']) == value['rootPin'], 'Invalid retained publisher pin')
    target = value['targetDigest']
    api.require(target is None if value['sequence'] == 0 else isinstance(target, str) and api.HEX.fullmatch(target), 'Invalid retained target digest')
    return value


@contextlib.contextmanager
def locked(api, path):
    root = directory(api, path)
    fd = os.open(root / 'Lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        api.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0, 'Invalid package trust lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = validate_trust(api, canonical(api, owner_file(api, root / 'Trust.json')))
        yield root, value
    finally:
        os.close(fd)


def validate_target(api, value):
    api.require(isinstance(value, dict) and set(value) == TARGET_FIELDS, 'Invalid signed update policy')
    api.require(type(value['format']) is int and value['format'] == 1
                and value['product'] == api.PRODUCT and value['architecture'] == api.architecture(), 'Wrong update product or architecture')
    api.require(value['stateContract'] == CONTRACTS[api.PRODUCT], 'Update state contract is incompatible')
    api.require(integer(value['rootGeneration'], 1) and integer(value['sequence'], 1)
                and integer(value['notBefore'], 1) and integer(value['expires'], 1)
                and value['notBefore'] < value['expires']
                and integer(value['archiveBytes'], 1) and value['archiveBytes'] <= api.MAX_ARCHIVE, 'Invalid signed update bounds')
    api.require(all(isinstance(value[name], str) and api.HEX.fullmatch(value[name])
                    for name in ('rootPin', 'archiveSha256', 'manifestSha256')), 'Invalid signed update digest')
    api.require(version(api, value['version']) >= version(api, value['versionFloor']), 'Update version is below its signed floor')
    return value


def verify_policy(api, path, signature, key, temporary, ssh_keygen):
    signers = temporary / 'UpdateSigners'
    signers.write_text(f'{api.PRINCIPAL} namespaces="{api.PRODUCT}Update1" {key}\n', encoding='ascii')
    signers.chmod(0o600)
    with path.open('rb') as source:
        api.run([ssh_keygen, '-Y', 'verify', '-f', str(signers), '-I', api.PRINCIPAL,
                 '-n', api.PRODUCT + 'Update1', '-s', str(signature)], input_file=source)


def authorise(api, args):
    output = api.private_parent(args.output)
    api.require(not output.exists() and not output.is_symlink()
                and not Path(str(output) + '.sig').exists(), 'Update output already exists')
    with tempfile.TemporaryDirectory(prefix='PackageAuthorise', dir=output.parent) as name:
        temporary = Path(name)
        archive, _ = api.prepared(args, temporary)
        manifest, original = api.parse_archive(archive)
        value = {'format': 1, 'product': api.PRODUCT, 'architecture': manifest['architecture'],
                 'version': manifest['version'], 'versionFloor': args.version_floor,
                 'stateContract': args.state_contract, 'rootGeneration': args.root_generation,
                 'rootPin': pin(api.public_key(args.public_key)), 'sequence': args.sequence,
                 'notBefore': args.not_before, 'expires': args.expires,
                 'archiveSha256': api.digest_file(archive, api.MAX_ARCHIVE),
                 'archiveBytes': archive.stat().st_size, 'manifestSha256': hashlib.sha256(original).hexdigest()}
        validate_target(api, value)
        policy = temporary / 'Target.json'
        policy.write_bytes(api.encode(value))
        policy.chmod(0o600)
        api.run([args.ssh_keygen, '-Y', 'sign', '-n', api.PRODUCT + 'Update1', '-f',
                 str(Path(args.signing_key).absolute()), str(policy)])
        signature = Path(str(policy) + '.sig')
        signature.chmod(0o600)
        verify_policy(api, policy, signature, api.public_key(args.public_key), temporary, args.ssh_keygen)
        api.rename_new(signature, Path(str(output) + '.sig'))
        try:
            api.rename_new(policy, output)
        except BaseException:
            Path(str(output) + '.sig').unlink()
            raise
    return {'status': 'UpdateAuthorised', 'targetDigest': digest(api, value), 'policy': str(output)}


def authenticated_target(api, args, key, archive, manifest, original, temporary):
    policy, signature = temporary / 'Target.json', temporary / 'Target.json.sig'
    api.copy_private(args.policy, policy, MAX_POLICY)
    api.copy_private(args.policy_signature, signature, 32768)
    verify_policy(api, policy, signature, key, temporary, args.ssh_keygen)
    with policy.open('rb') as source:
        value = validate_target(api, canonical(api, source.read(MAX_POLICY + 1)))
    api.require(value['rootPin'] == pin(key), 'Target differs from the supplied historical publisher key')
    api.require(value['version'] == manifest['version'] and value['architecture'] == manifest['architecture']
                and value['manifestSha256'] == hashlib.sha256(original).hexdigest()
                and value['archiveBytes'] == archive.stat().st_size
                and value['archiveSha256'] == api.digest_file(archive, api.MAX_ARCHIVE), 'Update policy does not bind this exact package')
    api.require(any(entry['path'] == 'Tools/PackageTrust.py' for entry in manifest['files']), 'Package lacks the current update verifier')
    return value


class TargetInspection:
    """Historical integrity only: cannot authorise installation or activation."""
    def __init__(self, api, args):
        self.api, self.args = api, args
        self.key = api.public_key(args.public_key)

    def check(self, archive, manifest, original, temporary):
        self.target = authenticated_target(self.api, self.args, self.key, archive, manifest, original, temporary)
        self.target_digest = digest(self.api, self.target)


class Admission:
    """Hold the trust lock until the checked installation is durably published."""
    def __init__(self, api, args):
        self.api, self.args = api, args
        api.require(all(getattr(args, name, None) for name in ('trust_directory', 'policy', 'policy_signature')), 'Install requires retained trust and signed update policy')
        self.guard = locked(api, args.trust_directory)

    def __enter__(self):
        self.root, self.trust = self.guard.__enter__()
        try:
            self.api.require(self.trust['rootPin'] == pin(self.api.public_key(self.args.public_key)), 'Publisher differs from retained update root')
            clock(self.api, self.trust['lastTime'])
            return self
        except BaseException:
            self.guard.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *error):
        return self.guard.__exit__(*error)

    def check(self, archive, manifest, original, temporary):
        api = self.api
        self.target = authenticated_target(api, self.args, self.trust['publicKey'], archive, manifest, original, temporary)
        value = self.target
        api.require(value['rootGeneration'] == self.trust['rootGeneration']
                    and value['rootPin'] == self.trust['rootPin'], 'Update names another trust root generation')
        api.require(version(api, value['version']) >= version(api, self.trust['versionFloor']), 'Update version is below the retained version floor')
        api.require(value['sequence'] >= self.trust['sequence'], 'Update sequence is below the retained floor')
        self.target_digest = digest(api, value)
        api.require(value['sequence'] != self.trust['sequence'] or self.target_digest == self.trust['targetDigest'], 'Update sequence conflicts with the retained exact target')
        self.fresh()

    def fresh(self):
        now = clock(self.api, self.trust['lastTime'])
        self.api.require(self.target['notBefore'] <= now < self.target['expires'], 'Signed update policy is not currently valid')
        return now

    def commit(self):
        now = self.fresh()
        value = dict(self.trust, sequence=self.target['sequence'], targetDigest=self.target_digest,
                     versionFloor=self.target['version'], lastTime=now)
        save(self.api, self.root, value)
        self.trust = value


def trust_command(api, args):
    if args.command == 'KeyPin':
        return {'rootPin': pin(api.public_key(args.public_key))}
    if args.command == 'Authorise':
        return authorise(api, args)
    if args.command == 'TrustInit':
        key = api.public_key(args.public_key)
        api.require(pin(key) == args.root_pin, 'Public key differs from the independently authenticated pin')
        value = {'format': 1, 'product': api.PRODUCT, 'architecture': api.architecture(),
                 'rootGeneration': args.root_generation, 'rootPin': args.root_pin, 'publicKey': key,
                 'versionFloor': args.version_floor, 'stateContract': args.state_contract,
                 'sequence': 0, 'targetDigest': None, 'lastTime': clock(api, 0)}
        validate_trust(api, value)
        root = api.private_parent(args.trust_directory)
        api.require(not root.exists() and not root.is_symlink(), 'Trust directory already exists')
        with tempfile.TemporaryDirectory(prefix='PackageTrust', dir=root.parent) as name:
            staged = Path(name) / 'Trust'
            staged.mkdir(mode=0o700)
            fd = os.open(staged / 'Lock', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fsync(fd)
            os.close(fd)
            save(api, staged, value)
            api.rename_new(staged, root)
        return {'status': 'TrustInitialised', 'trustDigest': digest(api, value), 'trust': value}
    with locked(api, args.trust_directory) as (root, value):
        if args.command == 'TrustInspect':
            return {'status': 'TrustInspected', 'trustDigest': digest(api, value), 'trust': value}
        api.require(args.command == 'TrustRotate', 'Unknown trust command')
        api.require(args.expected_trust_digest == digest(api, value), 'Trust changed since inspection')
        key = api.public_key(args.public_key)
        api.require(pin(key) == args.root_pin and args.root_pin != value['rootPin'], 'Independently authenticate a different new root pin')
        api.require(integer(args.root_generation, 1) and args.root_generation == value['rootGeneration'] + 1, 'Root rotation must advance exactly one generation')
        value = dict(value, publicKey=key, rootPin=args.root_pin, rootGeneration=args.root_generation,
                     lastTime=clock(api, value['lastTime']))
        save(api, root, value)
        return {'status': 'TrustRotated', 'trustDigest': digest(api, value), 'trust': value}


def arguments(commands):
    option = commands.add_parser('KeyPin', help='Display a key pin for independent authentication')
    option.add_argument('--public-key', required=True)
    for command in ('TrustInit', 'TrustInspect', 'TrustRotate'):
        option = commands.add_parser(command)
        option.add_argument('--trust-directory', required=True)
        if command != 'TrustInspect':
            option.add_argument('--public-key', required=True)
            option.add_argument('--root-pin', required=True)
            option.add_argument('--root-generation', type=int, required=True)
        if command == 'TrustInit':
            option.add_argument('--version-floor', required=True)
            option.add_argument('--state-contract', required=True)
        if command == 'TrustRotate':
            option.add_argument('--expected-trust-digest', required=True)
    option = commands.add_parser('Authorise', help='Sign an exact finite offline update target')
    for name in ('archive', 'signature', 'public-key', 'signing-key', 'output', 'version-floor', 'state-contract'):
        option.add_argument('--' + name, required=True)
    for name in ('root-generation', 'sequence', 'not-before', 'expires'):
        option.add_argument('--' + name, required=True, type=int)


COMMANDS = {'KeyPin', 'TrustInit', 'TrustInspect', 'TrustRotate', 'Authorise'}
