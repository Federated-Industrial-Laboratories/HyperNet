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
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'Tools'))
import Bundle
import PackageTrust


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
            'Bin/HyperNet', 'Licence.txt', 'ReadMe.md', 'Tools/Bundle.py', 'Tools/PackageTrust.py', 'Tools/Qualify.py',
            'Tools/Seccomp.sh',
            'Documentation/ThirdPartyNotices.txt', 'Documentation/SystemLibraries.tsv',
            'Documentation/SystemLibraryNotices.txt', 'Images/HyperNetOci.tar')}
        self.payload['ImageId.txt'] = (self.image + '\n').encode()
        self.manifest = {'format': 1, 'product': 'HyperNet', 'version': '0.8.0',
                         'architecture': Bundle.architecture(), 'metadata': {
                             'imageId': self.image, 'imageArchive': 'Images/HyperNetOci.tar',
                             'authoritySchema': 1,
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
        self.current(args)
        actual_run = Bundle.run
        def invoke(arguments, **kwargs):
            if arguments[:2] == ['podman', 'load']:
                return b''
            return actual_run(arguments, **kwargs)
        with patch.object(Bundle, 'run', side_effect=invoke), patch.object(Bundle, 'image_matches'):
            return Bundle.install(args)

    def current(self, args):
        if getattr(args, 'policy', None):
            return
        args.trust_directory = self.directory / 'Trust'
        if not args.trust_directory.exists():
            PackageTrust.trust_command(Bundle, argparse.Namespace(command='TrustInit',
                trust_directory=args.trust_directory, public_key=args.public_key,
                root_pin=PackageTrust.pin(Bundle.public_key(args.public_key)), root_generation=1,
                version_floor='0.8.0', state_contract='HyperNet080Authority2'))
        args.policy = self.directory / ('Target' + str(self.counter) + '.json')
        args.policy_signature = Path(str(args.policy) + '.sig')
        PackageTrust.authorise(Bundle, argparse.Namespace(archive=args.archive, signature=args.signature,
            public_key=args.public_key, signing_key=self.key, output=args.policy,
            root_generation=1, sequence=1, version_floor='0.8.0', state_contract='HyperNet080Authority2',
            not_before=int(time.time()) - 1, expires=int(time.time()) + 3600, ssh_keygen='/usr/bin/ssh-keygen'))

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
        self.assertEqual(Bundle.installed_manifest(args)[0]['version'], '0.8.0')
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

    def test_cutover_requires_fresh_exact_installed_target_without_floor_change(self):
        args = self.archive()
        self.installed(args)
        before = (args.trust_directory / 'Trust.json').read_bytes()
        report = Bundle.admit_installed(args)
        self.assertEqual(report['manifest'], self.manifest)
        self.assertEqual(report['trustDigest'], hashlib.sha256(before).hexdigest())
        self.assertEqual(report['sequence'], 1)
        self.assertEqual((args.trust_directory / 'Trust.json').read_bytes(), before)
        with patch.object(PackageTrust.time, 'time', return_value=report['expires']):
            with self.assertRaisesRegex(ValueError, 'not currently valid'):
                Bundle.admit_installed(args)
            historical = Bundle.inspect_installed_target(args)
            self.assertFalse(historical['activationAllowed'])
            self.assertEqual(historical['targetDigest'], report['targetDigest'])
        with PackageTrust.locked(Bundle, args.trust_directory) as (root, trust):
            PackageTrust.save(Bundle, root, dict(trust, sequence=2, targetDigest='f' * 64))
        with self.assertRaisesRegex(ValueError, 'below the retained floor'):
            Bundle.admit_installed(args)
        floor = (args.trust_directory / 'Trust.json').read_bytes()
        self.assertFalse(Bundle.inspect_installed_target(args)['activationAllowed'])
        self.assertEqual((args.trust_directory / 'Trust.json').read_bytes(), floor)
        (args.prefix / 'ReadMe.md').write_bytes(b'Altered')
        with self.assertRaisesRegex(ValueError, 'modified'):
            Bundle.inspect_installed_target(args)

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

    def test_inspected_image_accepts_only_exact_bare_or_prefixed_sha256(self):
        value = {'Os': 'linux', 'Architecture': Bundle.image_architecture(Bundle.architecture())}
        for identity in (self.image, self.image[7:]):
            with patch.object(Bundle, 'inspect_image', return_value=dict(value, Id=identity)):
                Bundle.image_matches(self.manifest)
        for identity in ('1' * 12, 'sha256:' + '2' * 64, 'sha512:' + '1' * 64, '1' * 64 + '\n'):
            with patch.object(Bundle, 'inspect_image', return_value=dict(value, Id=identity)):
                with self.assertRaises(ValueError):
                    Bundle.image_matches(self.manifest)

    def test_interrupted_publication_retains_floor_and_exact_retry_succeeds(self):
        args = self.archive()
        self.current(args)
        with patch.object(Bundle, 'rename_new', side_effect=OSError('Interrupted publication')):
            with self.assertRaises(OSError):
                self.installed(args)
        self.assertFalse(args.prefix.exists())
        self.assertEqual(json.loads((args.trust_directory / 'Trust.json').read_bytes())['sequence'], 1)
        self.installed(args)
        self.assertEqual(Bundle.installed_manifest(args)[0]['product'], 'HyperNet')
        Bundle.remove(args)



class OfflineUpdates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='PackageUpdateTests')
        self.root = Path(self.temporary.name)
        self.key, self.other = self.root / 'Signer', self.root / 'NextSigner'
        for key in (self.key, self.other):
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        self.trust = self.root / 'Trust'
        self.contract = PackageTrust.CONTRACTS[Bundle.PRODUCT]
        self.init = argparse.Namespace(command='TrustInit', trust_directory=self.trust,
            public_key=str(self.key) + '.pub', root_pin=PackageTrust.pin(Bundle.public_key(str(self.key) + '.pub')),
            root_generation=1, version_floor='0.8.0', state_contract=self.contract)
        PackageTrust.trust_command(Bundle, self.init)
        self.archive = self.root / 'Archive.tar'
        self.archive.write_bytes(b'Exact synthetic archive identity')
        self.manifest = {'version': '0.8.0', 'architecture': Bundle.architecture(),
                         'files': [{'path': 'Tools/PackageTrust.py'}]}
        self.original = Bundle.encode(self.manifest)
        self.now = int(time.time())
        self.target = {'format': 1, 'product': Bundle.PRODUCT, 'architecture': Bundle.architecture(),
            'version': '0.8.0', 'versionFloor': '0.8.0', 'stateContract': self.contract,
            'rootGeneration': 1, 'rootPin': self.init.root_pin, 'sequence': 1,
            'notBefore': self.now - 1, 'expires': self.now + 60,
            'archiveSha256': Bundle.digest_file(self.archive), 'archiveBytes': self.archive.stat().st_size,
            'manifestSha256': hashlib.sha256(self.original).hexdigest()}
        self.serial = 0

    def tearDown(self):
        self.temporary.cleanup()

    def policy(self, changes=None, key=None):
        self.serial += 1
        policy = self.root / ('Target' + str(self.serial) + '.json')
        policy.write_bytes(Bundle.encode(dict(self.target, **(changes or {}))))
        subprocess.run(['/usr/bin/ssh-keygen', '-Y', 'sign', '-n', Bundle.PRODUCT + 'Update1',
                        '-f', str(key or self.key), str(policy)], check=True, capture_output=True)
        return argparse.Namespace(trust_directory=self.trust, policy=policy,
            policy_signature=str(policy) + '.sig', public_key=str(key or self.key) + '.pub',
            ssh_keygen='/usr/bin/ssh-keygen')

    def accept(self, args, commit=True):
        with PackageTrust.Admission(Bundle, args) as admission:
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                admission.check(self.archive, self.manifest, self.original, Path(scratch))
                if commit:
                    admission.commit()
                return admission.target_digest

    def state(self):
        return json.loads((self.trust / 'Trust.json').read_bytes())

    def test_update_floor_exact_retry_equivocation_and_rollback(self):
        first = self.policy()
        self.accept(first)
        self.assertEqual(self.accept(first), self.state()['targetDigest'])
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.accept(self.policy({'expires': self.now + 61}))
        self.accept(self.policy({'sequence': 2}))
        with self.assertRaisesRegex(ValueError, 'below the retained floor'):
            self.accept(first)
        self.assertEqual(self.state()['sequence'], 2)

    def test_update_expiry_scope_contract_and_numeric_bounds_fail_closed(self):
        for changes in ({'expires': self.now}, {'notBefore': self.now + 30},
                        {'rootGeneration': 2}, {'rootPin': '0' * 64},
                        {'stateContract': 'Other'}, {'stateContract': 'HyperNet080Authority1'},
                        {'product': 'Other'},
                        {'architecture': 'Other'}, {'sequence': True},
                        {'sequence': 1 << 63}, {'archiveBytes': True},
                        {'versionFloor': '0.8.1'}, {'archiveSha256': '0' * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.accept(self.policy(changes))
        self.assertEqual(self.state()['sequence'], 0)
        self.assertIsNone(self.state()['targetDigest'])
        previous = dict(self.state(), stateContract='HyperNet080Authority1')
        with self.assertRaisesRegex(ValueError, 'Unsupported package state contract'):
            PackageTrust.validate_trust(Bundle, previous)

    def test_update_rechecks_expiry_at_floor_and_publication_boundaries(self):
        args = self.policy()
        with PackageTrust.Admission(Bundle, args) as admission:
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                admission.check(self.archive, self.manifest, self.original, Path(scratch))
            with patch.object(PackageTrust.time, 'time', return_value=self.now + 60):
                with self.assertRaisesRegex(ValueError, 'not currently valid'):
                    admission.commit()
            self.assertEqual(self.state()['sequence'], 0)
            admission.commit()
            with patch.object(PackageTrust.time, 'time', return_value=self.now + 60):
                with self.assertRaisesRegex(ValueError, 'not currently valid'):
                    admission.fresh()
        self.assertEqual(self.state()['sequence'], 1)

    def test_update_root_rotation_preserves_floor_and_requires_new_sequence(self):
        self.accept(self.policy())
        before = self.state()
        args = argparse.Namespace(command='TrustRotate', trust_directory=self.trust,
            expected_trust_digest=PackageTrust.digest(Bundle, before), public_key=str(self.other) + '.pub',
            root_pin=PackageTrust.pin(Bundle.public_key(str(self.other) + '.pub')), root_generation=2)
        with patch.object(args, 'root_pin', '0' * 64), self.assertRaises(ValueError):
            PackageTrust.trust_command(Bundle, args)
        PackageTrust.trust_command(Bundle, args)
        self.assertEqual(self.state()['sequence'], before['sequence'])
        self.assertEqual(self.state()['targetDigest'], before['targetDigest'])
        self.assertEqual(self.state()['versionFloor'], before['versionFloor'])
        with self.assertRaisesRegex(ValueError, 'changed since inspection'):
            PackageTrust.trust_command(Bundle, args)
        with self.assertRaisesRegex(ValueError, 'differs from retained'):
            self.accept(self.policy())
        changes = {'rootGeneration': 2, 'rootPin': args.root_pin}
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.accept(self.policy(changes, self.other))
        self.accept(self.policy(dict(changes, sequence=2), self.other))

    def test_update_lock_clock_floor_and_missing_policy_refuse(self):
        args = self.policy()
        with PackageTrust.locked(Bundle, self.trust), self.assertRaises(BlockingIOError):
            self.accept(args)
        with patch.object(PackageTrust.time, 'time', return_value=self.state()['lastTime'] - 1):
            with self.assertRaisesRegex(ValueError, 'clock moved'):
                self.accept(args)
        with self.assertRaisesRegex(ValueError, 'requires retained trust'):
            PackageTrust.Admission(Bundle, argparse.Namespace())


if __name__ == '__main__':
    os.umask(0o077)
    unittest.main()
