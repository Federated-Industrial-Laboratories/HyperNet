#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify consented static media across two installed authorities and a bridge.

Uses existing private host-interface binding, isolated voters and confined stores.
Removes every synthetic store, bridge, network and profile on exit.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import shutil
import time
from FederationWorkflow import FederationWorkflow
from MediaWorkflow import MediaWorkflow, png
from PagesWorkflow import PagesWorkflow


class Domain(MediaWorkflow):
    def __init__(self, args, slot):
        PagesWorkflow.__init__(self, args, slot=slot, federation=True, media=True)
        self.media_tool = self.host_tool.with_name('PageMediaStore.sh')
        self.stores = {}


class MediaFederationWorkflow(FederationWorkflow):
    def __init__(self, args):
        self.args = args
        self.source = Domain(args, 16)
        self.destination = Domain(args, 17)
        self.results = []
        self.profile = None
        self.bridge_tool = self.source.host_tool.with_name('Bridge.sh')
        self.external = None

    def setup(self):
        s, d = self.source, self.destination
        address = ipaddress.ip_address(self.args.media_address)
        if address.version != 4 or not address.is_private or address.is_loopback or address.is_unspecified:
            raise ValueError('Select an existing private host-interface IPv4 address')
        s.provision(); d.provision()
        self.author = s.client('Author'); s.admit('Author', self.author, 1)
        self.reader = d.client('Reader'); d.admit('Reader', self.reader, 1)
        for domain in [s, d]:
            domain.bridge = domain.client('Bridge', transport=True)
            domain.admit('Bridge', domain.bridge, 9)
        self.source_host = s.host('SourceMedia', 30553, address=str(address))
        self.destination_host = d.host('DestinationMedia', 30554, namespace='PartnerNews', address=str(address))
        self.agreement = secrets.token_hex(16)
        self.treaty = dict(version=2, agreementId=self.agreement,
            sourceNetwork=s.network, destinationNetwork=d.network,
            sourceAuthorityKey=s.signer, destinationAuthorityKey=d.signer,
            sourceBridgeKey=s.bridge, destinationBridgeKey=d.bridge,
            sourceNamespace='News', destinationNamespace='PartnerNews',
            service='Pages', profile='HyperNetPage/2', expires=int(time.time())+1800,
            mediaProfiles=['HyperNetRaster/1'], mediaSourceHosts=[self.source_host],
            mediaDestinationHosts=[self.destination_host], mediaMaxBytes=262144, mediaRequiredCopies=1)
        self.configuration = s.root/'BridgeConfiguration'; self.configuration.mkdir(mode=0o700)
        self.treaty_path = self.configuration/'Treaty.json'; s.write(self.treaty_path, self.treaty)
        self.digest = json.loads(s.run(s.suite, 'federation', 'treaty', self.treaty_path).stdout)['digest']
        for domain in [s, d]:
            domain.call('Administrator', 'federation', 'accept', '--treaty', self.treaty_path)
        def endpoint(domain):
            return dict(network=domain.network, deviceKey=domain.bridge, authorityKey=domain.signer,
                authorityEndpoint='https://authority.example:8443', authorityAddress=domain.broker_address+':8443',
                caCertificateDigest=hashlib.sha256((domain.pki/'NetworkCa.pem').read_bytes()).hexdigest())
        media = []
        for index, (domain, name) in enumerate([(s, 'SourceMedia'), (d, 'DestinationMedia')]):
            spec = json.loads((domain.root/(name+'Config')/'Specification.json').read_text())
            media.append({field: spec[field] for field in ['network', 'hostKey', 'endpoint', 'address',
                          'caDigest', 'certificateDigest', 'authoritySigner']})
            shutil.copy2(domain.pki/'NetworkCa.pem', self.configuration/f'MediaCa{index}.pem')
        self.spec = dict(version=2, service='FederationPages', agreementId=self.agreement,
            treatyDigest=self.digest, sourceNamespace='News', destinationNamespace='PartnerNews',
            source=endpoint(s), destination=endpoint(d), expires=int(time.time())+1200,
            memoryBytes=268435456, pids=64, cpuQuota=100000, cpuPeriod=100000, stateBytes=16777216,
            media=media, **{field: self.treaty[field] for field in ['mediaProfiles', 'mediaSourceHosts',
                'mediaDestinationHosts', 'mediaMaxBytes', 'mediaRequiredCopies']})
        self.sign_configuration()
        self.register(s); self.register(d)
        self.page = secrets.token_hex(16)
        source_png = s.root/'Raster.png'; source_png.write_bytes(png(128, 96))
        self.raster = s.root/'Raster.bin'
        self.asset = s.media('Author', 'import', '--input', source_png, '--output', self.raster,
            '--manifest', s.root/'Asset.json', '--id', 'Picture', '--host', self.source_host, '--copies', '1')['asset']
        source = s.source([self.asset]); saved = s.saved_submit(self.page, source)
        s.media('Author', 'upload', '--submission', saved, '--asset', 'Picture', '--input', self.raster)
        inspected = s.inspect(self.page)
        s.media('Administrator', 'inspect', '--review', inspected, '--asset', 'Picture', '--output', s.root/'Reviewed.bin')
        s.review(inspected)
        self.start()

    def exercise(self):
        s, d = self.source, self.destination
        self.check('media approval and treaty do not replace source author sharing consent', not self.queue())
        disabled = dict(self.treaty, agreementId=secrets.token_hex(16), mediaProfiles=[], mediaSourceHosts=[],
                        mediaDestinationHosts=[], mediaMaxBytes=0, mediaRequiredCopies=0)
        disabled_path = s.root/'TextTreaty.json'; s.write(disabled_path, disabled)
        s.call('Administrator', 'federation', 'accept', '--treaty', disabled_path)
        self.check('text-only treaty cannot acquire media disclosure through page sharing',
            s.cli('Author', 'federation', 'share', '--agreement', disabled['agreementId'], '--page-id', self.page, good=False).returncode != 0)
        self.share(); self.wait_pending()
        review = d.root/'ForeignReview.json'
        d.cli('Administrator', 'federation', 'inspect', '--agreement', self.agreement, '--page-id', self.page, '--output', review)
        self.check('destination approval requires its own media inspection',
            d.cli('Administrator', 'federation', 'review', '--input', review, '--decision', 'approve', good=False).returncode != 0)
        output = d.root/'ForeignReviewed.bin'
        result = None
        for _ in range(40):
            result = d.media('Administrator', 'inspect', '--federated', '--review', review, '--asset', 'Picture', '--output', output, good=False)
            if result.returncode == 0:
                break
            time.sleep(.25)
        self.check('confined bridge transfers verified static bytes to the consented destination',
                   result.returncode == 0 and output.read_bytes() == self.raster.read_bytes())
        d.cli('Administrator', 'federation', 'review', '--input', review, '--decision', 'approve')
        fetched = d.root/'ForeignRead.bin'
        d.media('Reader', 'read', '--agreement', self.agreement, '--page-id', self.page,
                '--asset', 'Picture', '--output', fetched)
        self.check('destination reader verifies source geometry using separate destination placement', fetched.read_bytes() == self.raster.read_bytes())
        self.share(withdraw=True)
        time.sleep(6)
        self.check('source author withdrawal denies fresh destination media access',
            d.media('Reader', 'read', '--agreement', self.agreement, '--page-id', self.page,
                    '--asset', 'Picture', '--output', d.root/'Withdrawn.bin', good=False).returncode != 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ['suite', 'node', 'image', 'etcd-directory', 'seccomp', 'output', 'media-address']:
        parser.add_argument('--'+field, required=True)
    MediaFederationWorkflow(parser.parse_args()).execute()


if __name__ == '__main__':
    main()
