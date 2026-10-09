#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise installed consented media authoring, review, replicas and withdrawal.

Uses isolated TLS voters and two confined PageMedia stores. All fixtures are
removed on exit. Requires rootless Podman, OpenSSL and Python cryptography.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import time
import urllib.request
import zlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PagesWorkflow import PagesWorkflow
from BrowserWorkflow import Terminal


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def png(width, height):
    def chunk(kind, value):
        return struct.pack('!I', len(value)) + kind + value + struct.pack('!I', zlib.crc32(kind+value))
    pixels = b''.join(bytes([0])+b''.join(bytes([x*255//width, y*255//height, 180])
                                      for x in range(width)) for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))


class MediaWorkflow(PagesWorkflow):
    def __init__(self, args):
        super().__init__(args, slot=15, media=True)
        self.media_tool = self.host_tool.with_name('PageMediaStore.sh')
        self.stores = {}

    def media(self, name, *args, good=True):
        result = self.cli(name, 'media', *args, good=good, timeout=60)
        return json.loads(result.stdout) if good else result

    def host(self, name, port, namespace='News', address='127.0.0.1'):
        key = self.client(name, transport=True)
        self.admit(name, key, 3)
        self.certificate(name, 'NetworkCa', name, f'DNS:media.example,IP:{address}', 'serverAuth,clientAuth')
        profile = json.loads((self.root/name/'Profile.json').read_text())
        profile.update(clientCertificate=str(self.pki/(name+'.pem')), clientKey=str(self.pki/(name+'Key.pem')))
        self.write(self.root/name/'Profile.json', profile)
        source = self.root/(name+'Config')
        source.mkdir(mode=0o700)
        state = self.root/(name+'State')
        der = subprocess.check_output(['openssl', 'x509', '-in', str(self.pki/(name+'.pem')), '-outform', 'DER'])
        spec = {'version': 1, 'network': self.network, 'hostKey': key, 'generation': 1, 'services': ['PageMedia'],
                'endpoint': f'https://media.example:{port}', 'address': f'{address}:{port}',
                'caDigest': hashlib.sha256((self.pki/'NetworkCa.pem').read_bytes()).hexdigest(),
                'certificateDigest': hashlib.sha256(der).hexdigest(),
                'authorityEndpoint': 'https://authority.example:8443',
                'authorityAddress': self.broker_address+':8443', 'authoritySigner': self.media_signer,
                'memoryBytes': 536870912, 'pids': 64, 'cpuQuota': 100000, 'cpuPeriod': 100000,
                'stateBytes': 16777216, 'expires': int(time.time())+1800,
                'namespaces': [namespace], 'retentionSeconds': 1200}
        self.write(source/'Specification.json', spec)
        self.media(name, 'host-consent', '--input', source/'Specification.json', '--output', source/'Consent.json')
        self.media(name, 'host-register', '--input', source/'Consent.json')
        for origin, target in [(self.root/name/'Identity.json', 'Identity.json'),
                               (self.pki/'NetworkCa.pem', 'AuthorityCa.pem'), (self.pki/'NetworkCa.pem', 'Ca.pem'),
                               (self.pki/(name+'.pem'), 'Client.pem'), (self.pki/(name+'Key.pem'), 'ClientKey.pem')]:
            shutil.copy2(origin, source/target)
        self.write(source/'PageMediaStore.json', {'network': self.network, 'identity': '/Config/Identity.json',
                   'consentFile': '/Config/Consent.json', 'authorityCa': '/Config/AuthorityCa.pem',
                   'certificate': '/Config/Client.pem', 'privateKey': '/Config/ClientKey.pem',
                   'caCertificate': '/Config/Ca.pem', 'stateFile': '/State/PageMediaState.bin',
                   'listen': '0.0.0.0:8443', 'relayAddress': '10.1.1.3:8443'})
        for path in source.iterdir():
            path.chmod(0o600)
        runtime = self.root/(name+'Runtime')
        self.stores[name] = {'key': key, 'profile': runtime, 'port': port, 'address': address}
        self.run('bash', self.media_tool, 'Initialise', runtime, source, state, self.args.image,
                 self.prefix, f'{address}:{port}:8443', timeout=60)
        self.control(name, 'Start')
        return key

    def control(self, name, action):
        result = self.run('bash', self.media_tool, action, self.stores[name]['profile'], timeout=60)
        if action in ['Start', 'Restart']:
            store = self.stores[name]
            context = ssl.create_default_context(cafile=str(self.pki/'NetworkCa.pem'))
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            deadline = time.monotonic()+15
            while True:
                try:
                    with socket.create_connection((store['address'], store['port']), timeout=1) as stream:
                        with context.wrap_socket(stream, server_hostname='media.example'):
                            break
                except OSError:
                    if time.monotonic() >= deadline:
                        control = json.loads((store['profile']/'Control.json').read_text())
                        log = self.run('podman', 'logs', '--tail=10', control['name'], good=False)
                        raise RuntimeError('Media store TLS readiness failed: '+log.stdout[-1000:]+log.stderr[-1000:])
                    time.sleep(.1)
        return result

    def operation(self, name, host, page, source, asset, action, offset=0, payload=None, digest=None):
        raw = json.loads((self.root/name/'Identity.json').read_text())
        body = {'version': 1, 'agreementId': None, 'admission': None, 'network': self.network,
                'operationId': secrets.token_hex(16), 'issuedAt': int(time.time()),
                'hostKey': self.stores[host]['key'], 'pageId': page, 'revision': 1, 'assetId': asset['id'],
                'sourceDigest': hashlib.sha256(source.encode()).hexdigest(), 'action': action,
                'offset': offset, 'chunkBytes': len(payload) if payload else min(32768, asset['bytes']-offset) if action == 'Fetch' else 0,
                'chunkDigest': digest or hashlib.sha256(payload).hexdigest() if payload else None}
        value = json.dumps(body, separators=(',', ':')).encode()
        message = b'HyperNet/PageMediaOperation/1\0'+bytes.fromhex(self.network)+bytes.fromhex(raw['publicKey'])+value
        signed = {'network': self.network, 'publicKey': raw['publicKey'], 'payload': encoded(value),
                  'signature': Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw['secretKey'])).sign(message).hex()}
        request = urllib.request.Request(f'https://127.0.0.1:{self.stores[host]["port"]}/V1/PageMedia',
                  json.dumps({'operation': signed, 'payload': encoded(payload) if payload else None}).encode(),
                  headers={'Content-Type': 'application/json'})
        context = ssl.create_default_context(cafile=str(self.pki/'NetworkCa.pem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        try:
            with urllib.request.urlopen(request, context=context, timeout=15) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            return json.load(error)

    def import_asset(self, id, path):
        output = self.root/(id+'.bin')
        manifest = self.root/(id+'Manifest.json')
        args = ['import', '--input', path, '--output', output, '--manifest', manifest,
                '--id', id, '--copies', '2']
        for host in sorted([self.one, self.two]):
            args += ['--host', host]
        result = self.media('Author', *args)
        return result['asset'], output

    def source(self, assets):
        lines = ['HyperNetPage/2', '# Media board', ': Images load only after explicit reveal.']
        for asset in assets:
            lines += ['@Asset '+json.dumps(asset, separators=(',', ':'))]
            lines += ['@Image '+json.dumps({'id': asset['id']+'View', 'asset': asset['id'],
                       'alt': 'Static '+asset['id'], 'rows': 8, 'motion': {'preset': 'ImagePan', 'durationMs': 2000}})]
            lines += ['@Button '+json.dumps({'label': 'Reveal '+asset['id'],
                       'action': {'kind': 'Reveal', 'target': asset['id']+'View'}})]
        lines += ['@Text {"id":"Notice","value":"Local motion","motion":{"preset":"ColourPulse","durationMs":2000}}']
        return '\n'.join(lines)+'\n'

    def saved_submit(self, page, source):
        draft = self.root/(page+'Draft.txt')
        saved = self.root/(page+'Submission.json')
        draft.write_text(source)
        self.cli('Author', 'pages', 'submit', '--file', draft, '--namespace', 'News', '--page-id', page,
                 '--output', saved)
        return saved

    def review_disclosure(self, page, vector, vector_file):
        for name, permissions in [('TextReviewer', ['ReviewInspect']),
                                  ('MediaReviewer', ['MediaInspect', 'ReviewInspect'])]:
            self.client(name)
            profile = json.loads((self.root/name/'Profile.json').read_text())
            profile['application'] = True
            self.write(self.root/name/'Profile.json', profile)
            consent = self.signed(name, {'type': 'ApplicationConsent', 'ownerKey': self.admin,
                      'expires': int(time.time())+600, 'namespaces': ['News'], 'pageIds': [page],
                      'permissions': permissions, 'reviewPolicyDigest': None, 'reviewMode': None})
            result = self.api('Administrator', {'type': 'ApplicationGrantCreate', 'consent': consent})
            assert result['ok'], result['code']
            receipt = self.root/(name+'Receipt.json')
            job = self.root/(name+'Job.json')
            self.cli(name, 'adapters', 'review-export', '--page-id', page, '--recipient', 'LocalClassifier',
                     '--purpose', 'Review the selected media', '--policy-digest', 'ab'*32,
                     '--expires', str(int(time.time())+240), '--consent-disclosure',
                     '--output', job, '--receipt', receipt)
            self.check(name+' text export contains no media payload',
                       'payload' not in json.loads(job.read_text()) and 'HyperNetVector/1' in job.read_text())
            output = self.root/(name+'Media.json')
            media_receipt = self.root/(name+'MediaReceipt.json')
            arguments = ['adapters', 'media-export', '--receipt', receipt, '--asset', vector['id'],
                         '--output', output, '--media-receipt', media_receipt]
            if name == 'TextReviewer':
                denied = self.cli(name, *arguments, '--consent-media-disclosure', good=False)
                self.check('ReviewInspect alone cannot disclose asset bytes',
                           denied.returncode != 0 and not output.exists() and not media_receipt.exists())
            else:
                denied = self.cli(name, *arguments, good=False)
                self.check('media disclosure requires separate explicit consent',
                           denied.returncode != 0 and not output.exists() and not media_receipt.exists())
                self.cli(name, *arguments, '--consent-media-disclosure')
                exported = json.loads(output.read_text())
                meta = exported['disclosure']
                raw = base64.urlsafe_b64decode(exported['payload']+'='*(-len(exported['payload']) % 4))
                self.check('media disclosure binds the exact job and independently verified selected asset',
                           meta['reviewJobDigest'] == json.loads(job.read_text())['jobDigest']
                           and meta['asset'] == vector and meta['recipient'] == 'LocalClassifier'
                           and raw == vector_file.read_bytes() and media_receipt.exists())

    def exercise(self):
        for name in ['Author', 'Reader']:
            self.admit(name, self.client(name), 1)
        self.one = self.host('MediaHostOne', 30543)
        self.two = self.host('MediaHostTwo', 30544)
        self.media('Administrator', 'policy-set', '--minimum-copies', '2')
        image = self.root/'Input.png'; image.write_bytes(png(160, 90))
        svg = self.root/'Input.svg'
        svg.write_text('<svg xmlns="http://www.w3.org/2000/svg" width="64" height="48"><script>alert(1)</script>'
                       '<rect width="64" height="48" fill="#006699" onclick="bad()"/>'
                       '<path d="M 8 8 L 56 40 L 8 40 Z" fill="#ffcc00"/></svg>')
        raster, raster_file = self.import_asset('Photo', image)
        vector, vector_file = self.import_asset('Icon', svg)
        self.check('isolated PNG import produces bounded canonical RGB', raster['bytes'] == 160*90*3 and raster['profile'] == 'HyperNetRaster/1')
        self.check('SVG import retains safe typed geometry without XML or active strings',
                   vector['profile'] == 'HyperNetVector/1' and b'<svg' not in vector_file.read_bytes()
                   and b'alert' not in vector_file.read_bytes() and b'onclick' not in vector_file.read_bytes())
        self.media('Author', 'export-svg', '--input', vector_file, '--output', self.root/'Safe.svg')
        self.check('canonical vector exports a passive interoperable SVG',
                   '<path' in (self.root/'Safe.svg').read_text() and 'script' not in (self.root/'Safe.svg').read_text())
        page = secrets.token_hex(16); source = self.source([raster, vector]); saved = self.saved_submit(page, source)
        review = self.inspect(page)
        self.check('incomplete media cannot be approved', self.review(review, good=False).returncode != 0)
        self.check('reader cannot fetch quarantined media', not self.operation('Reader', 'MediaHostOne', page, source, raster, 'Fetch')['ok'])
        part = raster_file.read_bytes()[:32768]
        first = self.operation('Author', 'MediaHostOne', page, source, raster, 'Put', payload=part)
        self.check('first immutable upload chunk is durable', first['ok'])
        self.control('MediaHostOne', 'Restart')
        self.check('duplicate exact chunk is resumable after store restart', self.operation('Author', 'MediaHostOne', page, source, raster, 'Put', payload=part)['ok'])
        wrong = bytes([part[0] ^ 1])+part[1:]
        self.check('same-offset different bytes are refused', not self.operation('Author', 'MediaHostOne', page, source, raster, 'Put', payload=wrong)['ok'])
        self.media('Author', 'upload', '--submission', saved, '--asset', 'Photo', '--input', raster_file, '--host', self.one)
        self.check('one complete copy does not satisfy required copies', self.review(review, good=False).returncode != 0)
        for asset, path in [(raster, raster_file), (vector, vector_file)]:
            self.media('Author', 'upload', '--submission', saved, '--asset', asset['id'], '--input', path)
        self.check('sealed copies still require explicit moderator inspection', self.review(review, good=False).returncode != 0)
        self.review_disclosure(page, vector, vector_file)
        for asset in [raster, vector]:
            result = self.media('Administrator', 'inspect', '--review', review, '--asset', asset['id'], '--output', self.root/(asset['id']+'Reviewed.bin'))
            self.check('moderator independently verifies and acknowledges '+asset['id'], result['verified'] and result['reviewAttested'])
        self.review(review)
        plain = self.read(page).stdout
        self.check('plain read includes alt text and manifests without graphics', 'Static Photo' in plain and raster['digest'] in plain and '\x1b' not in plain)
        self.media('Reader', 'read', '--page-id', page, '--asset', 'Photo', '--host', self.two, '--output', self.root/'Read.bin')
        self.check('fresh published reference reads exact bytes from selected replica', (self.root/'Read.bin').read_bytes() == raster_file.read_bytes())
        self.media('Author', 'replicate', '--page-id', page, '--asset', 'Photo', '--source-host', self.one, '--destination-host', self.two)
        self.check('explicit author replication resumes the immutable approved object', True)
        self.client('TextApplication')
        consent = self.signed('TextApplication', {'type': 'ApplicationConsent', 'ownerKey': self.admin,
                    'expires': int(time.time())+600, 'namespaces': ['News'], 'pageIds': [page],
                    'permissions': ['PagesRead'], 'reviewPolicyDigest': None, 'reviewMode': None})
        assert self.api('Administrator', {'type': 'ApplicationGrantCreate', 'consent': consent})['ok']
        self.check('PagesRead alone cannot fetch media', not self.operation('TextApplication', 'MediaHostOne', page, source, raster, 'Fetch')['ok'])
        reader = Terminal(self, 'browse',
                           f'hypernet://{self.network}/{json.loads((self.root/"Author"/"Identity.json").read_text())["publicKey"]}/News/{page}')
        try:
            reader.read(b'Media board')
            frame = reader.key(b'\t\r', b'Verified media revealed')
            self.check('real TUI explicitly reveals verified media with graphics-off fallback', 'Static Photo' in frame and 'Verified media revealed' in frame)
        finally:
            reader.close()
        self.media('MediaHostTwo', 'host-withdraw', '--host-key', self.two, '--expected-generation', '1')
        self.check('withdrawn host denies fresh selected-store access',
                   self.media('Reader', 'read', '--page-id', page, '--asset', 'Photo', '--host', self.two,
                              '--output', self.root/'Revoked.bin', good=False).returncode != 0)
        self.cli('Author', 'pages', 'withdraw', '--page-id', page, '--expected-version', '2')
        self.check('withdrawn page denies fresh media despite retained digest knowledge',
                   not self.operation('Reader', 'MediaHostOne', page, source, raster, 'Fetch')['ok'])

    def cleanup(self):
        for store in self.stores.values():
            path = store['profile']/'Control.json'
            if path.exists():
                control = json.loads(path.read_text())
                for name in [control['name'], control['name']+'Gate']:
                    self.run('podman', 'rm', '-f', name, good=False, timeout=30)
                self.run('podman', 'network', 'rm', control['network'], good=False)
        super().cleanup()

    def execute(self):
        try:
            super().execute()
        finally:
            path = Path(self.args.output)
            if path.exists():
                report = json.loads(path.read_text()); report['imageId'] = self.args.image
                report['sourceSha256']['Tests/MediaWorkflow.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                path.write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ['suite', 'node', 'image', 'etcd-directory', 'seccomp', 'output']:
        parser.add_argument('--'+field, required=True)
    args = parser.parse_args(); args.recovery_only = args.lifecycle_only = False
    MediaWorkflow(args).execute()


if __name__ == '__main__':
    main()
