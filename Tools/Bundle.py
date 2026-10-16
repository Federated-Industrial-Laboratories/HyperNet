#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create, verify and install signed offline packages without changing profiles."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
sys.dont_write_bytecode = True
import PackageTrust

PRODUCT = 'HyperNet'
VERSION = '0.7.5'
NAMESPACE = 'HyperNetBundle1'
PRINCIPAL = 'HyperNetPublisher'
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_MANIFEST = 256 * 1024
MAX_FILES = 512
BLOCK = 1024 * 1024
HEX = re.compile(r'[a-f0-9]{64}\Z')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid number')))


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def run(arguments, *, input_file=None, timeout=120):
    result = subprocess.run(arguments, stdin=input_file or subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                            env={'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C',
                                 **{name: os.environ[name] for name in ('HOME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS') if name in os.environ}})
    require(result.returncode == 0, 'External operation failed: ' + Path(arguments[0]).name)
    require(len(result.stdout) <= MAX_MANIFEST, 'External response exceeds its bound')
    return result.stdout


def open_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'A regular, nonlinked file is required')
        require(0 <= info.st_size <= maximum, 'File exceeds its bound')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def copy_private(source, destination, maximum):
    total = 0
    with open_regular(source, maximum) as incoming, open(destination, 'xb') as outgoing:
        os.chmod(destination, 0o600)
        while chunk := incoming.read(BLOCK):
            total += len(chunk)
            require(total <= maximum, 'File grew beyond its bound')
            outgoing.write(chunk)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    os.chmod(destination, 0o400)


def digest_file(path, maximum=MAX_FILE):
    digest = hashlib.sha256()
    with open_regular(path, maximum) as source:
        while chunk := source.read(BLOCK):
            digest.update(chunk)
    return digest.hexdigest()


def architecture():
    value = platform.machine()
    require(value in ('x86_64', 'aarch64'), 'No package profile for this architecture')
    return value


def image_architecture(value):
    return {'x86_64': 'amd64', 'aarch64': 'arm64'}[value]


def allowed_path(name):
    if name in ('Licence.txt', 'ReadMe.md', 'ImageId.txt', 'Images/HyperNetOci.tar', 'Bin/HyperNet', 'Tests/RuntimeWorkflow.py'):
        return True
    return bool(re.fullmatch(r'(Tools/[A-Z][A-Za-z0-9]*\.(py|sh)|Documentation/[A-Z][A-Za-z0-9]*\.(md|txt|tsv|json)|Packaging/(LibraryLicences\.md|Containerfile|SshdConfig))', name))


def file_mode(name):
    return 0o700 if name.startswith(('Bin/', 'Tools/', 'Tests/')) else 0o600


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {'format', 'product', 'version', 'architecture', 'metadata', 'files'}, 'Invalid package manifest')
    require(type(value['format']) is int and value['format'] == 1 and value['product'] == PRODUCT, 'Wrong package product or format')
    require(isinstance(value['version'], str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value['version']), 'Invalid package version')
    require(value['architecture'] in ('x86_64', 'aarch64'), 'Unsupported package architecture')
    metadata = value['metadata']
    require(isinstance(metadata, dict) and set(metadata) == {'imageId', 'imageArchive', 'binaries', 'authoritySchema', 'hostRuntime', 'prerequisites'}, 'Invalid package metadata')
    require(isinstance(metadata['imageId'], str) and re.fullmatch(r'sha256:[a-f0-9]{64}', metadata['imageId']), 'Invalid immutable image identity')
    require(metadata['imageArchive'] == 'Images/HyperNetOci.tar', 'Unexpected image path')
    require(isinstance(metadata['binaries'], dict) and set(metadata['binaries']) == {'HyperNet', 'HyperNetGate'} and all(isinstance(v, str) and HEX.fullmatch(v) for v in metadata['binaries'].values()), 'Invalid binary inventory')
    require(type(metadata['authoritySchema']) is int and metadata['authoritySchema'] == 1, 'Invalid authority schema')
    require(isinstance(metadata['prerequisites'], list) and len(metadata['prerequisites']) <= 32 and all(isinstance(v, str) and len(v) <= 256 for v in metadata['prerequisites']), 'Invalid prerequisites')
    host = metadata['hostRuntime']
    require(isinstance(host, dict) and set(host) == {'elfInterpreter', 'neededLibraries', 'glibcMinimum'}, 'Invalid native runtime metadata')
    require(host['elfInterpreter'] == {'x86_64': '/lib64/ld-linux-x86-64.so.2', 'aarch64': '/lib/ld-linux-aarch64.so.1'}[value['architecture']], 'Invalid native ELF interpreter')
    require(isinstance(host['neededLibraries'], list) and 1 <= len(host['neededLibraries']) <= 32
            and all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_.+-]+\.so(\.[0-9]+)*', v) for v in host['neededLibraries'])
            and host['neededLibraries'] == sorted(set(host['neededLibraries'])), 'Invalid native libraries')
    require(isinstance(host['glibcMinimum'], str) and re.fullmatch(r'2\.[0-9]+', host['glibcMinimum']), 'Invalid native glibc requirement')
    files = value['files']
    require(isinstance(files, list) and 1 <= len(files) <= MAX_FILES, 'Invalid file count')
    paths = []
    total = 0
    for item in files:
        require(isinstance(item, dict) and set(item) == {'path', 'size', 'mode', 'sha256'}, 'Invalid file inventory')
        name = item['path']
        require(isinstance(name, str) and allowed_path(name) and str(PurePosixPath(name)) == name, 'Unexpected package path')
        require(type(item['size']) is int and 0 <= item['size'] <= MAX_FILE, 'Invalid file size')
        require(type(item['mode']) is int and item['mode'] == file_mode(name), 'Invalid file mode')
        require(isinstance(item['sha256'], str) and HEX.fullmatch(item['sha256']), 'Invalid file digest')
        paths.append(name)
        total += item['size']
    require(paths == sorted(set(paths)) and total <= MAX_ARCHIVE, 'Duplicate, unordered or oversized inventory')
    require({'Bin/HyperNet', 'Images/HyperNetOci.tar', 'ImageId.txt', 'Licence.txt', 'ReadMe.md', 'Tools/Bundle.py', 'Tools/Qualify.py', 'Tools/Seccomp.sh', 'Documentation/ThirdPartyNotices.txt', 'Documentation/SystemLibraries.tsv', 'Documentation/SystemLibraryNotices.txt'}.issubset(paths), 'Required package files are missing')
    native = next(item for item in files if item['path'] == 'Bin/HyperNet')
    require(native['sha256'] == metadata['binaries']['HyperNet'], 'Native and confined runtime identities differ')
    return value


def public_key(path):
    with open_regular(path, 16384) as source:
        lines = source.read().decode('ascii').splitlines()
    require(len(lines) == 1, 'Select one independently pinned public key')
    fields = lines[0].split()
    require(len(fields) >= 2 and fields[0] == 'ssh-ed25519', 'An Ed25519 package public key is required')
    raw = base64.b64decode(fields[1], validate=True)
    require(len(raw) == 51 and raw[:19] == b'\0\0\0\x0bssh-ed25519\0\0\0\x20', 'Invalid Ed25519 public key')
    require(base64.b64encode(raw).decode() == fields[1], 'Noncanonical public key')
    return fields[0] + ' ' + fields[1]


def verify_signature(archive, signature, key_path, temporary, ssh_keygen, key_value=None):
    key = key_value if key_value is not None else public_key(key_path)
    signers = temporary / 'AllowedSigners'
    signers.write_text(f'{PRINCIPAL} namespaces="{NAMESPACE}" {key}\n')
    signers.chmod(0o600)
    with archive.open('rb') as source:
        run([ssh_keygen, '-Y', 'verify', '-f', str(signers), '-I', PRINCIPAL,
             '-n', NAMESPACE, '-s', str(signature)], input_file=source)


def archive_members(archive):
    """Read bounded USTAR regular members without PAX, links or extractall."""
    seen = set()
    total = 0
    with archive.open('rb') as source:
        while True:
            header = source.read(512)
            require(len(header) == 512, 'Truncated archive header')
            if header == bytes(512):
                require(source.read(512) == bytes(512), 'Missing archive terminator')
                while chunk := source.read(BLOCK):
                    require(not any(chunk), 'Unexpected trailing archive data')
                break
            require(header[156:157] in (b'0', b'\0') and header[257:263] == b'ustar\0', 'Only USTAR regular files are accepted')
            item = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            require(item.isreg() and not item.linkname and not item.pax_headers and not item.sparse, 'Archive links and special files are forbidden')
            require(item.name not in seen and len(seen) < MAX_FILES + 1, 'Duplicate or excessive archive members')
            require(item.name == 'Manifest.json' or (item.name.startswith('Payload/') and allowed_path(item.name[8:])), 'Unexpected archive member')
            require(str(PurePosixPath(item.name)) == item.name and not item.name.startswith('/'), 'Unsafe archive path')
            require(0 <= item.size <= MAX_FILE, 'Archive member exceeds its bound')
            require(item.mode in (0o600, 0o700), 'Unsafe archive mode')
            seen.add(item.name)
            total += item.size
            require(total <= MAX_ARCHIVE, 'Archive content exceeds its bound')
            yield item, source
            padding = (-item.size) % 512
            require(source.read(padding) == bytes(padding), 'Invalid archive padding')


def parse_archive(archive, output=None):
    manifest = None
    original = None
    expected = {}
    seen = set()
    for item, source in archive_members(archive):
        if manifest is None:
            require(item.name == 'Manifest.json' and item.size <= MAX_MANIFEST and item.mode == 0o600, 'Manifest must be the first member')
            original = source.read(item.size)
            require(len(original) == item.size, 'Truncated manifest')
            manifest = validate_manifest(decode(original))
            expected = {entry['path']: entry for entry in manifest['files']}
            continue
        require(item.name.startswith('Payload/'), 'Unexpected manifest or payload')
        name = item.name[8:]
        require(name in expected, 'Unlisted archive file')
        entry = expected[name]
        require(item.size == entry['size'] and item.mode == entry['mode'], 'Archive metadata differs from manifest')
        seen.add(name)
        outgoing = None
        try:
            if output is not None:
                destination = output / name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                outgoing = destination.open('xb')
                os.chmod(destination, entry['mode'])
            remaining = item.size
            digest = hashlib.sha256()
            while remaining:
                chunk = source.read(min(BLOCK, remaining))
                require(chunk, 'Truncated archive file')
                remaining -= len(chunk)
                digest.update(chunk)
                if outgoing is not None:
                    outgoing.write(chunk)
            require(digest.hexdigest() == entry['sha256'], 'Archive digest mismatch')
            if outgoing is not None:
                outgoing.flush()
                os.fsync(outgoing.fileno())
        finally:
            if outgoing is not None:
                outgoing.close()
    require(manifest is not None and seen == set(expected), 'Incomplete package archive')
    return manifest, original


def inspect_image(image):
    value = decode(run(['podman', 'image', 'inspect', image]))
    require(isinstance(value, list) and len(value) == 1, 'Invalid image inspection')
    return value[0]


def image_matches(manifest):
    value = inspect_image(manifest['metadata']['imageId'])
    identity = value['Id']
    require(isinstance(identity, str) and re.fullmatch(r'(sha256:)?[a-f0-9]{64}', identity), 'Invalid inspected image identity')
    identity = identity if identity.startswith('sha256:') else 'sha256:' + identity
    require(identity == manifest['metadata']['imageId'] and value['Os'] == 'linux'
            and value['Architecture'] == image_architecture(manifest['architecture']), 'Loaded image identity or architecture mismatch')


def image_binaries(image, temporary):
    container = None
    identity = temporary / 'ContainerId'
    try:
        created = run(['podman', 'create', '--name', 'HyperNetBundle' + uuid.uuid4().hex,
                       '--cidfile', str(identity),
                       '--pull=never', '--network=none', '--entrypoint=/HyperNet', image, '--version'])
        candidate = created.decode('ascii').strip()
        require(re.fullmatch(r'[a-f0-9]{64}', candidate), 'Invalid temporary-container identity')
        container = candidate
        digests = {}
        for name in ('HyperNet', 'HyperNetGate'):
            target = temporary / name
            run(['podman', 'cp', container + ':/' + name, str(target)])
            digests[name] = digest_file(target)
        return digests
    finally:
        if container is None and identity.exists():
            with open_regular(identity, 128) as source:
                candidate = source.read().decode('ascii').strip()
            require(re.fullmatch(r'[a-f0-9]{64}', candidate), 'Invalid owned-container identity')
            container = candidate
        if container is not None:
            run(['podman', 'rm', container])


def runtime_matches(manifest):
    require(manifest['architecture'] == architecture(), 'Package architecture does not match this machine')
    require(platform.system() == 'Linux', 'Only native Linux packages are qualified')
    try:
        libc_version = os.confstr('CS_GNU_LIBC_VERSION').split()
    except (OSError, ValueError, AttributeError):
        raise ValueError('GNU libc is required') from None
    require(len(libc_version) == 2 and libc_version[0] == 'glibc', 'GNU libc is required')
    require(tuple(map(int, libc_version[1].split('.'))) >= tuple(map(int, manifest['metadata']['hostRuntime']['glibcMinimum'].split('.'))), 'Host glibc is older than the package requirement')
    require(Path(manifest['metadata']['hostRuntime']['elfInterpreter']).is_file(), 'Required ELF interpreter is unavailable')


def binary_metadata(binary):
    with open_regular(binary, MAX_FILE) as source:
        header = source.read(20)
    require(header[:6] == b'\x7fELF\x02\x01', 'A little-endian ELF64 binary is required')
    require(int.from_bytes(header[18:20], 'little') == {'x86_64': 62, 'aarch64': 183}[architecture()], 'ELF architecture does not match the package')
    program = run(['readelf', '--program-headers', '--wide', str(binary)]).decode('ascii')
    dynamic = run(['readelf', '--dynamic', '--wide', str(binary)]).decode('ascii')
    versions = run(['readelf', '--version-info', '--wide', str(binary)]).decode('ascii')
    interpreters = re.findall(r'Requesting program interpreter: ([^]\n]+)', program)
    require(len(interpreters) == 1, 'One ELF interpreter is required')
    needed = sorted(set(re.findall(r'\(NEEDED\).*Shared library: \[([^]\n]+)\]', dynamic)))
    glibc = re.findall(r'GLIBC_(2\.[0-9]+)\b', versions)
    require(glibc and needed, 'Dynamic GNU/Linux dependency information is missing')
    require(not re.search(r'\((?:RPATH|RUNPATH)\)', dynamic), 'Embedded library search paths are forbidden')
    return {'elfInterpreter': interpreters[0], 'neededLibraries': needed,
            'glibcMinimum': max(glibc, key=lambda v: tuple(map(int, v.split('.'))))}


def private_parent(path):
    path = Path(os.path.abspath(path))
    require(path.name not in ('', '.', '..') and path != Path.home(), 'Select a dedicated installation prefix')
    current = Path('/')
    for part in path.parent.parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'Installation parents must be real directories')
        require(not info.st_mode & 0o022 or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX), 'Installation parent is writable by others')
    return path


def rename_new(source, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.renameat2
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        raise OSError(ctypes.get_errno(), 'Cannot publish an existing or unsupported destination')
    fd = os.open(Path(destination).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepared(args, temporary, key=None):
    archive = temporary / 'Archive.tar'
    signature = temporary / 'Archive.tar.sig'
    copy_private(args.archive, archive, MAX_ARCHIVE)
    copy_private(args.signature, signature, 32768)
    verify_signature(archive, signature, args.public_key, temporary, args.ssh_keygen, key)
    return archive, signature


def install(args):
    with PackageTrust.Admission(sys.modules[__name__], args) as admission:
        return install_current(args, admission)


def install_current(args, admission):
    prefix = private_parent(args.prefix)
    require(not prefix.exists() and not prefix.is_symlink(), 'Installation prefix already exists')
    require(os.geteuid() != 0, 'Install for the dedicated rootless operator, not root')
    with tempfile.TemporaryDirectory(prefix='HyperNetInstall', dir=prefix.parent) as temporary_name:
        temporary = Path(temporary_name)
        archive, signature = prepared(args, temporary, admission.trust['publicKey'])
        staged = temporary / 'Install'
        staged.mkdir(mode=0o700)
        manifest, original = parse_archive(archive, staged)
        runtime_matches(manifest)
        admission.check(archive, manifest, original, temporary)
        require((staged / 'ImageId.txt').read_text().strip() == manifest['metadata']['imageId'], 'Packaged image ID differs from the manifest')
        run(['podman', 'load', '--input', str(staged / manifest['metadata']['imageArchive'])])
        image_matches(manifest)
        (staged / 'Manifest.json').write_bytes(original)
        (staged / 'Manifest.json').chmod(0o600)
        (staged / 'Package').mkdir(mode=0o700)
        shutil.copyfile(archive, staged / 'Package/Archive.tar')
        shutil.copyfile(signature, staged / 'Package/Archive.tar.sig')
        for path in (staged / 'Package').iterdir():
            path.chmod(0o600)
        for path in sorted(staged.rglob('*'), reverse=True):
            if path.is_file():
                with path.open('rb') as source:
                    os.fsync(source.fileno())
            elif path.is_dir():
                fd = os.open(path, os.O_DIRECTORY)
                os.fsync(fd)
                os.close(fd)
        fd = os.open(staged, os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        admission.commit()
        admission.fresh()
        rename_new(staged, prefix)
    return {'product': PRODUCT, 'version': manifest['version'], 'prefix': str(prefix), 'imageId': manifest['metadata']['imageId']}


def installed_manifest(args, admission=None):
    prefix = private_parent(args.prefix)
    info = prefix.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Installation prefix is not private')
    package_info = (prefix / 'Package').lstat()
    require(stat.S_ISDIR(package_info.st_mode) and not stat.S_ISLNK(package_info.st_mode) and package_info.st_uid == os.geteuid() and stat.S_IMODE(package_info.st_mode) == 0o700, 'Installed package evidence must be private')
    with tempfile.TemporaryDirectory(prefix='HyperNetVerify') as temporary_name:
        temporary = Path(temporary_name)
        args.archive = prefix / 'Package/Archive.tar'
        args.signature = prefix / 'Package/Archive.tar.sig'
        archive, signature = prepared(args, temporary)
        manifest, original = parse_archive(archive)
        with open_regular(prefix / 'Manifest.json', MAX_MANIFEST) as source:
            require(source.read() == original, 'Installed manifest was modified')
        expected = {entry['path']: entry for entry in manifest['files']}
        expected['Manifest.json'] = {'mode': 0o600, 'size': len(original), 'sha256': hashlib.sha256(original).hexdigest()}
        for name, copied in [('Package/Archive.tar', archive), ('Package/Archive.tar.sig', signature)]:
            expected[name] = {'mode': 0o600, 'size': copied.stat().st_size, 'sha256': digest_file(copied, MAX_ARCHIVE)}
        directories = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != '.'}
        found = set()
        pending = [prefix]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                name = str(path.relative_to(prefix))
                info = path.lstat()
                require(info.st_uid == os.geteuid() and not stat.S_ISLNK(info.st_mode), 'Foreign-owned or symbolic installation entry')
                if stat.S_ISDIR(info.st_mode):
                    require(name in directories and stat.S_IMODE(info.st_mode) == 0o700, 'Unexpected installation directory')
                    pending.append(path)
                else:
                    require(name in expected and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'Unexpected installation file')
                    entry = expected[name]
                    require(info.st_size == entry['size'] and stat.S_IMODE(info.st_mode) == entry['mode'] and digest_file(path, MAX_ARCHIVE) == entry['sha256'], 'Installed file was modified')
                    found.add(name)
        require(found == set(expected), 'Installed file is missing')
        if admission is not None:
            admission.check(archive, manifest, original, temporary)
        return manifest, expected, directories


def admit_installed(args):
    """Authenticate a stopped cutover without changing the retained update floor."""
    with PackageTrust.Admission(sys.modules[__name__], args) as admission:
        manifest = installed_manifest(args, admission)[0]
        require(admission.target['sequence'] == admission.trust['sequence']
                and admission.target_digest == admission.trust['targetDigest'],
                'Cutover requires the exact retained installed target')
        admission.fresh()
        return {'manifest': manifest,
                'trustDigest': PackageTrust.digest(sys.modules[__name__], admission.trust),
                'targetDigest': admission.target_digest,
                **{name: admission.target[name] for name in
                   ('notBefore', 'expires', 'rootGeneration', 'sequence')}}


def inspect_installed_target(args):
    inspection = PackageTrust.TargetInspection(sys.modules[__name__], args)
    manifest = installed_manifest(args, inspection)[0]
    return {'manifest': manifest, 'activationAllowed': False,
            'targetDigest': inspection.target_digest,
            **{name: inspection.target[name] for name in
               ('notBefore', 'expires', 'rootGeneration', 'rootPin', 'sequence')}}


def remove(args):
    prefix = private_parent(args.prefix)
    _, files, directories = installed_manifest(args)
    for name in sorted(files):
        (prefix / name).unlink()
    for name in sorted(directories, key=lambda value: (value.count('/'), value), reverse=True):
        (prefix / name).rmdir()
    prefix.rmdir()
    return {'removed': str(prefix), 'profilesPreserved': True, 'imagesPreserved': True}


def create(args):
    repository = Path(__file__).resolve().parents[1]
    package = Path(args.package).resolve(strict=True)
    output = private_parent(args.output)
    require(not output.exists() and not Path(str(output) + '.sig').exists(), 'Output already exists')
    image_id = (package / 'ImageId.txt').read_text().strip()
    runtime_version = run([str(package / 'RootFs/HyperNet'), '--version']).decode('ascii').strip()
    require(runtime_version == 'HyperNet 0.7.5', 'Runtime does not match the current package contract')
    runtime_version = runtime_version.split()[1]
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image_id), 'Invalid package image identity')
    machine = architecture()
    with tempfile.TemporaryDirectory(prefix='HyperNetBundle', dir=output.parent) as temporary_name:
        temporary = Path(temporary_name)
        image = temporary / 'HyperNetOci.tar'
        run(['podman', 'save', '--format', 'oci-archive', '--output', str(image), image_id])
        image.chmod(0o600)
        files = {'Bin/HyperNet': package / 'RootFs/HyperNet', 'Images/HyperNetOci.tar': image, 'ImageId.txt': package / 'ImageId.txt', 'Licence.txt': repository / 'Licence.txt', 'ReadMe.md': repository / 'ReadMe.md'}
        for folder in ('Tools', 'Documentation', 'Packaging', 'Tests'):
            for path in sorted((repository / folder).iterdir()):
                name = str(path.relative_to(repository))
                if allowed_path(name) and path.is_file():
                    files[name] = path
        for path in sorted((package / 'RootFs/Documentation').iterdir()):
            if path.name in ('SystemLibraries.tsv', 'SystemLibraryNotices.txt'):
                files['Documentation/' + path.name] = path
        manifest = {'format': 1, 'product': PRODUCT, 'version': runtime_version, 'architecture': machine,
                    'metadata': {'imageId': image_id, 'imageArchive': 'Images/HyperNetOci.tar',
                    'authoritySchema': 1, 'hostRuntime': binary_metadata(package / 'RootFs/HyperNet'),
                    'binaries': {name: digest_file(package / 'RootFs' / name) for name in ('HyperNet', 'HyperNetGate')},
                    'prerequisites': ['Linux; package architecture must match the native processor', 'Python 3.11+, OpenSSH ssh-keygen Ed25519 SSHSIG, Bash, GNU coreutils, jq and flock', 'Rootless Podman with a maintained OCI runtime, nomap and subordinate UID/GID mappings', 'Delegated cgroup v2 CPU, memory and PID controllers; seccomp; Landlock ABI 6+', 'Confined GNU/Linux libraries and their loader are carried inside the OCI image', 'Native Bin/HyperNet requires the declared host GNU libc ABI, ELF loader and maintained shared libraries', 'An independently verified accepted bootstrap, appointed voter identity, pinned TLS inputs and signed healthy clock export are required for authority runtime setup', 'The build packager uses Debian-format library inventory; runtime hosts do not require dpkg']},
                    'files': [{'path': name, 'size': path.stat().st_size, 'mode': file_mode(name), 'sha256': digest_file(path)} for name, path in sorted(files.items())]}
        validate_manifest(manifest)
        image_matches(manifest)
        require(image_binaries(image_id, temporary) == manifest['metadata']['binaries'], 'Image binaries differ from the supplied build files')
        manifest_path = temporary / 'Manifest.json'
        manifest_path.write_bytes(encode(manifest))
        manifest_path.chmod(0o600)
        archive = temporary / 'Archive.tar'
        with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as target:
            for name, path, mode in [('Manifest.json', manifest_path, 0o600), *[('Payload/' + entry['path'], files[entry['path']], entry['mode']) for entry in manifest['files']]]:
                info = tarfile.TarInfo(name)
                info.mode, info.size, info.mtime = mode, path.stat().st_size, 0
                with open_regular(path, MAX_FILE) as source:
                    target.addfile(info, source)
        require(archive.stat().st_size <= MAX_ARCHIVE, 'Archive exceeds its bound')
        parse_archive(archive)
        run([args.ssh_keygen, '-Y', 'sign', '-n', NAMESPACE, '-f', str(Path(args.signing_key).absolute()), str(archive)])
        signature = Path(str(archive) + '.sig')
        os.chmod(archive, 0o600)
        os.chmod(signature, 0o600)
        rename_new(signature, Path(str(output) + '.sig'))
        try:
            rename_new(archive, output)
        except BaseException:
            Path(str(output) + '.sig').unlink()
            raise
    return {'archive': str(output), 'signature': str(output) + '.sig', 'product': PRODUCT, 'version': runtime_version, 'imageId': image_id}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh-keygen', default='/usr/bin/ssh-keygen', help='Independently trusted OpenSSH verifier')
    commands = parser.add_subparsers(dest='command', required=True)
    PackageTrust.arguments(commands)
    package = commands.add_parser('Create')
    package.add_argument('--package', required=True)
    package.add_argument('--output', required=True)
    package.add_argument('--signing-key', required=True)
    for command in ('Verify', 'Install'):
        option = commands.add_parser(command)
        option.add_argument('--archive', required=True)
        option.add_argument('--signature', required=True)
        option.add_argument('--public-key', required=True)
        if command == 'Install':
            option.add_argument('--prefix', required=True)
            option.add_argument('--trust-directory', required=True)
            option.add_argument('--policy', required=True)
            option.add_argument('--policy-signature', required=True)
    for command in ('VerifyInstalled', 'AdmitInstalled', 'InspectInstalledTarget', 'Remove'):
        option = commands.add_parser(command)
        option.add_argument('--prefix', required=True)
        option.add_argument('--public-key', required=True)
        if command == 'AdmitInstalled':
            option.add_argument('--trust-directory', required=True)
        if command in ('AdmitInstalled', 'InspectInstalledTarget'):
            option.add_argument('--policy', required=True)
            option.add_argument('--policy-signature', required=True)
    args = parser.parse_args()
    if args.command in PackageTrust.COMMANDS:
        result = PackageTrust.trust_command(sys.modules[__name__], args)
    elif args.command == 'Create':
        result = create(args)
    elif args.command == 'Install':
        result = install(args)
    elif args.command == 'Remove':
        result = remove(args)
    elif args.command == 'VerifyInstalled':
        result = installed_manifest(args)[0]
    elif args.command == 'AdmitInstalled':
        result = admit_installed(args)
    elif args.command == 'InspectInstalledTarget':
        result = inspect_installed_target(args)
    else:
        with tempfile.TemporaryDirectory(prefix='HyperNetVerify') as temporary_name:
            temporary = Path(temporary_name)
            archive, _ = prepared(args, temporary)
            result = parse_archive(archive)[0]
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        print('HyperNet package: ' + str(error).encode('ascii', 'backslashreplace').decode(), file=sys.stderr)
        sys.exit(1)
