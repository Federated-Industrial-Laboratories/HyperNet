#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check signed package trust, archive containment and installed-file ownership."""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'Tools'))
import Bundle
import Upgrade


class Packages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='HyperNetPackageKeys')
        cls.key = Path(cls.keys.name) / 'Signer'
        cls.other = Path(cls.keys.name) / 'Other'
        for path in (cls.key, cls.other):
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='HyperNetPackageTests')
        self.directory = Path(self.temporary.name)
        self.counter = 0
        self.image = 'sha256:' + '1' * 64
        self.payload = {name: b'Package fixture\n' for name in (
            'Bin/HyperNet', 'Licence.txt', 'ReadMe.md', 'Tools/Bundle.py', 'Tools/Qualify.py', 'Tools/Upgrade.py',
            'Tools/Authority.sh', 'Tools/Lifecycle.sh', 'Tools/Seccomp.sh',
            'Documentation/ThirdPartyNotices.txt', 'Documentation/SystemLibraries.tsv',
            'Documentation/SystemLibraryNotices.txt', 'Images/HyperNetOci.tar')}
        self.payload['ImageId.txt'] = (self.image + '\n').encode()
        self.manifest = {'format': 1, 'product': 'HyperNet', 'version': '0.7.5',
                         'architecture': Bundle.architecture(), 'metadata': {
                             'imageId': self.image, 'imageArchive': 'Images/HyperNetOci.tar',
                             'authoritySchema': 9,
                             'hostRuntime': {'elfInterpreter': {'x86_64': '/lib64/ld-linux-x86-64.so.2', 'aarch64': '/lib/ld-linux-aarch64.so.1'}[Bundle.architecture()], 'neededLibraries': ['libc.so.6'], 'glibcMinimum': '2.34'},
                             'binaries': {'HyperNet': hashlib.sha256(self.payload['Bin/HyperNet']).hexdigest(), 'HyperNetGate': '3' * 64},
                             'prerequisites': ['Synthetic package contract fixture']},
                         'files': [{'path': name, 'mode': Bundle.file_mode(name),
                                    'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                                   for name, data in sorted(self.payload.items())]}

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, manifest=None, mutate=None, namespace=Bundle.NAMESPACE):
        self.counter += 1
        target = self.directory / ('Archive' + str(self.counter) + '.tar')
        manifest = manifest or self.manifest
        members = [('Manifest.json', Bundle.encode(manifest), 0o600, tarfile.REGTYPE)]
        members += [('Payload/' + item['path'], self.payload[item['path']], item['mode'], tarfile.REGTYPE)
                    for item in self.manifest['files']]
        if mutate:
            members = mutate(members)
        with tarfile.open(target, 'w', format=tarfile.USTAR_FORMAT) as archive:
            for name, data, mode, kind in members:
                item = tarfile.TarInfo(name)
                item.mode, item.type = mode, kind
                item.size = len(data) if kind == tarfile.REGTYPE else 0
                if kind == tarfile.SYMTYPE:
                    item.linkname = '/tmp/Outside'
                archive.addfile(item, io.BytesIO(data) if item.size else None)
        subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', namespace, '-f', str(self.key), str(target)], check=True, capture_output=True)
        return argparse.Namespace(archive=target, signature=Path(str(target) + '.sig'),
                                  public_key=Path(str(self.key) + '.pub'), ssh_keygen='/usr/bin/ssh-keygen',
                                  prefix=self.directory / 'Installed')

    def verify(self, args):
        with tempfile.TemporaryDirectory(prefix='Verify', dir=self.directory) as path:
            copied, _ = Bundle.prepared(args, Path(path))
            return Bundle.parse_archive(copied)[0]

    def installed(self, args):
        actual_run = Bundle.run
        def invoke(arguments, **kwargs):
            if arguments[:2] == ['podman', 'load']:
                return b''
            return actual_run(arguments, **kwargs)
        with patch.object(Bundle, 'run', side_effect=invoke), patch.object(Bundle, 'image_matches'):
            return Bundle.install(args)

    def test_signature_namespace_pinned_key_and_private_copy_precede_parsing(self):
        args = self.archive()
        self.assertEqual(self.verify(args)['metadata']['imageId'], self.image)
        wrong = copy.copy(args)
        wrong.public_key = Path(str(self.other) + '.pub')
        with self.assertRaises(ValueError):
            self.verify(wrong)
        with self.assertRaises(ValueError):
            self.verify(self.archive(namespace='HyperNetSuiteBundle1'))
        with args.archive.open('r+b') as changed:
            changed.write(b'Changed')
        with patch.object(Bundle, 'parse_archive', side_effect=AssertionError('Unverified parsing')):
            with self.assertRaises(ValueError):
                self.installed(args)
        self.assertFalse(args.prefix.exists())

    def test_signed_unsafe_duplicate_special_and_missing_members_are_rejected(self):
        mutations = [
            lambda members: members + [('Payload/../Outside', b'data', 0o600, tarfile.REGTYPE)],
            lambda members: members + [members[-1]],
            lambda members: members[:-1],
            lambda members: members + [('Payload/Documentation/Link.txt', b'', 0o600, tarfile.SYMTYPE)],
            lambda members: members + [('Payload/Tools/Device.sh', b'', 0o700, tarfile.CHRTYPE)],
            lambda members: members[:-1] + [(members[-1][0], b'Changed', members[-1][2], members[-1][3])],
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                with self.assertRaises((ValueError, tarfile.TarError)):
                    self.verify(self.archive(mutate=mutate))
        self.assertFalse((self.directory / 'Outside').exists())

    def test_manifest_product_bounds_and_supported_state_schema_are_strict(self):
        for field, value in [('product', 'HyperNetSuite'), ('format', 2), ('architecture', 'Unknown')]:
            manifest = copy.deepcopy(self.manifest)
            manifest[field] = value
            with self.assertRaises(ValueError):
                self.verify(self.archive(manifest))
        for maximum in (6, 99):
            manifest = copy.deepcopy(self.manifest)
            manifest['metadata']['authoritySchema'] = maximum
            with self.assertRaises(ValueError):
                self.verify(self.archive(manifest))
        manifest = copy.deepcopy(self.manifest)
        manifest['files'][0]['size'] = Bundle.MAX_FILE + 1
        with self.assertRaises(ValueError):
            self.verify(self.archive(manifest))

    def test_native_runtime_metadata_and_image_identity_are_bound(self):
        mutations = [lambda m: m['metadata']['binaries'].update(HyperNet='0' * 64),
                     lambda m: m['metadata']['hostRuntime'].update(elfInterpreter='/Untrusted/Loader'),
                     lambda m: m['metadata']['hostRuntime'].update(neededLibraries=['../Library.so']),
                     lambda m: m['files'].remove(next(v for v in m['files'] if v['path'] == 'Bin/HyperNet'))]
        for mutate in mutations:
            manifest = copy.deepcopy(self.manifest)
            mutate(manifest)
            with self.assertRaises(ValueError):
                Bundle.validate_manifest(manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest['metadata']['hostRuntime']['glibcMinimum'] = '2.999'
        with self.assertRaises(ValueError):
            Bundle.runtime_matches(manifest)

    def test_install_is_no_clobber_and_remove_refuses_modified_or_extra_files(self):
        args = self.archive()
        self.installed(args)
        self.assertEqual(Bundle.installed_manifest(args)[0]['version'], '0.7.5')
        self.assertEqual((args.prefix / 'Bin/HyperNet').stat().st_mode & 0o777, 0o700)
        with self.assertRaises(ValueError):
            self.installed(args)
        managed = args.prefix / 'ReadMe.md'
        original = managed.read_bytes()
        managed.write_bytes(b'Modified\n')
        with self.assertRaises(ValueError):
            Bundle.remove(args)
        self.assertTrue((args.prefix / 'Licence.txt').exists())
        managed.write_bytes(original)
        extra = args.prefix / 'PrivateState.txt'
        extra.write_text('Preserve unrelated data')
        with self.assertRaises(ValueError):
            Bundle.remove(args)
        self.assertEqual(extra.read_text(), 'Preserve unrelated data')
        extra.unlink()
        state = self.directory / 'ProfileState'
        state.mkdir()
        (state / 'Canary').write_text('Retained')
        result = Bundle.remove(args)
        self.assertTrue(result['imagesPreserved'])
        self.assertFalse(args.prefix.exists())
        self.assertEqual((state / 'Canary').read_text(), 'Retained')

    def test_installed_symlinks_hardlinks_and_evidence_directory_are_refused(self):
        args = self.archive()
        self.installed(args)
        managed = args.prefix / 'ReadMe.md'
        saved = managed.read_bytes()
        managed.unlink()
        managed.symlink_to(self.directory / 'Outside')
        with self.assertRaises(ValueError):
            Bundle.installed_manifest(args)
        managed.unlink()
        managed.write_bytes(saved)
        managed.chmod(0o600)
        os.link(managed, self.directory / 'Hardlink')
        with self.assertRaises(ValueError):
            Bundle.installed_manifest(args)
        (self.directory / 'Hardlink').unlink()
        evidence = args.prefix / 'Package'
        evidence.rename(self.directory / 'Evidence')
        evidence.symlink_to(self.directory / 'Evidence', target_is_directory=True)
        with self.assertRaises(ValueError):
            Bundle.installed_manifest(args)

    def test_upgrade_keeps_schema_and_stopped_container_boundaries(self):
        metadata = self.manifest['metadata']
        Upgrade.compatible(metadata, 9)
        for schema in (0, 7, 8, 99):
            with self.assertRaises(ValueError):
                Upgrade.compatible(metadata, schema)
        for maximum in (6, 99):
            changed = dict(metadata, authoritySchema=maximum)
            with self.assertRaises(ValueError):
                Upgrade.compatible(changed, 9)
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaises(ValueError):
                Upgrade.stopped('HyperNetFixture', 'Authority')
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 125)):
            with self.assertRaises(ValueError):
                Upgrade.stopped('HyperNetFixture', 'Host')
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)) as calls:
            Upgrade.stopped('HyperNetFixture', 'Bridge')
            self.assertEqual(calls.call_count, 9)

    def test_inspected_image_accepts_only_exact_bare_or_prefixed_sha256(self):
        value = {'Os': 'linux', 'Architecture': Bundle.image_architecture(Bundle.architecture())}
        for identity in (self.image, self.image[7:]):
            with patch.object(Bundle, 'inspect_image', return_value=dict(value, Id=identity)):
                Bundle.image_matches(self.manifest)
        for identity in ('1' * 12, 'sha256:' + '2' * 64, 'sha512:' + '1' * 64, '1' * 64 + '\n'):
            with patch.object(Bundle, 'inspect_image', return_value=dict(value, Id=identity)):
                with self.assertRaises(ValueError):
                    Bundle.image_matches(self.manifest)

    def test_upgrade_changes_only_expected_image_and_preserves_profile_state(self):
        profile = self.directory / 'Profile'
        profile.mkdir(mode=0o700)
        old_image = 'sha256:' + '4' * 64
        control = {'name': 'HyperNetAuthority' + hashlib.sha256(str(profile).encode()).hexdigest()[:16],
                   'image': old_image, 'authority': {'consent': 'Retained'}}
        path = profile / 'Control.json'
        path.write_bytes(Bundle.encode(control))
        path.chmod(0o600)
        state = profile / 'State'
        state.mkdir(mode=0o700)
        (state / 'Canary').write_bytes(b'Unchanged persistent state')
        args = argparse.Namespace(kind='Authority', profile=profile, installation=self.directory / 'Installed',
                                  public_key=Path(str(self.key) + '.pub'), ssh_keygen='/usr/bin/ssh-keygen',
                                  state_schema=9, expected_image=old_image)
        with patch.object(Bundle, 'installed_manifest', return_value=(self.manifest, {}, set())), \
                patch.object(Bundle, 'image_matches'), patch.object(Upgrade, 'stopped') as stopped:
            result = Upgrade.switch(args)
            stopped.assert_called_once_with(control['name'], 'Authority')
            self.assertFalse(result['started'])
            self.assertEqual(Bundle.decode(path.read_bytes()), dict(control, image=self.image))
            self.assertEqual((state / 'Canary').read_bytes(), b'Unchanged persistent state')
            saved = path.read_bytes()
            with self.assertRaises(ValueError):
                Upgrade.switch(args)
            self.assertEqual(path.read_bytes(), saved)
            args.kind = 'SshService'
            with self.assertRaises(ValueError):
                Upgrade.switch(args)


if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
