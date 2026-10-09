#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise installed form publication, explicit consent and encrypted typed intake.

Uses the private three-voter Pages fixture and two confined mail stores. Requires
rootless Podman, OpenSSL and Python cryptography. All fixtures are removed on exit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from PagesWorkflow import PagesWorkflow
from BrowserWorkflow import Terminal


class FormsWorkflow(PagesWorkflow):
    def __init__(self, args):
        super().__init__(args, slot=14, mail=True)
        self.mail_tool = self.host_tool.with_name('MailStore.sh')
        self.stores = {}
        self.vaults = {}

    def mail_call(self, name, *args, good=True):
        command = [self.suite, '--config', self.root/name/'Profile.json', 'mail']
        if name in self.vaults:
            command += ['--vault', self.vaults[name]['directory'], '--key', self.vaults[name]['key']]
        result = self.run(*command, *args, good=good, timeout=45)
        return json.loads(result.stdout) if good else result

    def forms(self, name, *args, good=True, reader=None):
        args = list(args)
        if reader:
            args = ['--reader-config', self.root/reader/'Profile.json'] + args
        vault = self.vaults[name]
        result = self.run(self.suite, '--config', self.root/name/'Profile.json', 'forms',
                          '--vault', vault['directory'], '--key', vault['key'], *args,
                          good=good, timeout=50)
        if good:
            assert not any(ch in result.stdout for ch in ['\x1b', '\x07', '\u202e', '\u2066'])
            return json.loads(result.stdout)
        return result

    def vault(self, name):
        self.vaults[name] = {'directory': self.root/(name+'Vault'), 'key': self.root/(name+'AgeIdentity.txt')}
        return self.mail_call(name, 'init', '--authority-key', self.mail_signer)

    def mailbox(self, name, label, hosts):
        args = ['address-create', '--mailbox', label, '--expires', str(int(time.time())+1800),
                '--retention', '1200', '--copies', str(len(hosts))]
        for host in hosts:
            args += ['--host', host]
        return self.mail_call(name, *args)

    def host(self, name, port):
        key = self.client(name, transport=True)
        self.admit(name, key, 3)
        self.certificate(name, 'NetworkCa', name, 'DNS:mail.example,IP:127.0.0.1', 'serverAuth,clientAuth')
        profile = json.loads((self.root/name/'Profile.json').read_text())
        profile.update(clientCertificate=str(self.pki/(name+'.pem')), clientKey=str(self.pki/(name+'Key.pem')))
        self.write(self.root/name/'Profile.json', profile)
        source = self.root/(name+'Config')
        source.mkdir(mode=0o700)
        state = self.root/(name+'State')
        der = subprocess.check_output(['openssl', 'x509', '-in', str(self.pki/(name+'.pem')), '-outform', 'DER'])
        spec = {'version': 1, 'network': self.network, 'hostKey': key, 'generation': 1, 'services': ['Mail'],
                'endpoint': f'https://mail.example:{port}', 'address': f'127.0.0.1:{port}',
                'caDigest': hashlib.sha256((self.pki/'NetworkCa.pem').read_bytes()).hexdigest(),
                'certificateDigest': hashlib.sha256(der).hexdigest(),
                'authorityEndpoint': 'https://authority.example:8443',
                'authorityAddress': self.broker_address+':8443', 'authoritySigner': self.mail_signer,
                'memoryBytes': 536870912, 'pids': 64, 'cpuQuota': 100000, 'cpuPeriod': 100000,
                'stateBytes': 16777216, 'expires': int(time.time())+1800}
        self.write(source/'Specification.json', spec)
        self.mail_call(name, 'host-consent', '--spec', source/'Specification.json', '--output', source/'Consent.json')
        self.mail_call(name, 'host-register', '--consent', source/'Consent.json')
        for origin, target in [(self.root/name/'Identity.json', 'Identity.json'),
                               (self.pki/'NetworkCa.pem', 'AuthorityCa.pem'), (self.pki/'NetworkCa.pem', 'Ca.pem'),
                               (self.pki/(name+'.pem'), 'Client.pem'), (self.pki/(name+'Key.pem'), 'ClientKey.pem')]:
            shutil.copy2(origin, source/target)
        self.write(source/'MailStore.json', {'network': self.network, 'identity': '/Config/Identity.json',
                   'consentFile': '/Config/Consent.json', 'authorityCa': '/Config/AuthorityCa.pem',
                   'certificate': '/Config/Client.pem', 'privateKey': '/Config/ClientKey.pem',
                   'caCertificate': '/Config/Ca.pem', 'stateFile': '/State/MailState.bin',
                   'listen': '0.0.0.0:8443', 'relayAddress': '10.1.1.3:8443'})
        for path in source.iterdir():
            path.chmod(0o600)
        runtime = self.root/(name+'Runtime')
        self.stores[name] = {'key': key, 'profile': runtime}
        self.run('bash', self.mail_tool, 'Initialise', runtime, source, state, self.args.image,
                 self.prefix, f'127.0.0.1:{port}:8443', timeout=60)
        self.control(name, 'Start')
        return key

    def control(self, name, action):
        return self.run('bash', self.mail_tool, action, self.stores[name]['profile'], timeout=60)

    def verify_contact(self, name, address):
        self.mail_call(name, 'contact-verify', '--address', address['addressId'],
                       '--owner-fingerprint', address['manifest']['publicKey'])

    def draft(self, suffix=''):
        form = {'id': 'Feedback', 'label': 'Feedback', 'profile': 'HyperNetFormMail/1',
                'recipient': self.recipient['addressId'], 'owner': self.recipient['manifest']['publicKey']}
        fields = [{'id': 'Message', 'label': 'Message', 'kind': 'Multiline', 'maxBytes': 1024, 'required': True},
                  {'id': 'Count', 'label': 'Count', 'kind': 'Integer', 'minimum': -5, 'maximum': 5, 'required': True},
                  {'id': 'Agreed', 'label': 'Agreed', 'kind': 'Boolean', 'required': True},
                  {'id': 'Choice', 'label': 'Choice', 'kind': 'Choice', 'options': ['One', 'Two'], 'required': True}]
        return ('HyperNetPage/2\n# Feedback\n: Explicit feedback '+suffix+'.\n@Form '+json.dumps(form)+'\n' +
                ''.join('@Field '+json.dumps(field)+'\n' for field in fields) +
                '@Submit {"label":"Review feedback"}\n@End\n')

    def prepare(self, good=True, values=None):
        return self.forms('Alice', 'prepare', '--mailbox', 'Personal', '--page-id', self.page,
                          '--form-id', 'Feedback', '--values', values or self.values_file,
                          good=good, reader='PageReader')

    def accept(self):
        return self.forms('Bob', 'accept', '--mailbox', 'Private', '--page-id', self.page,
                          '--form-id', 'Feedback', reader='PageReader')

    def confirm(self, review, good=True, confirm=True):
        args = ['submit', '--mailbox', 'Personal', '--review-id', review['reviewId']]
        if confirm:
            args.append('--confirm')
        return self.forms('Alice', *args, good=good, reader='PageReader')

    def reader_application(self):
        key = self.client('PageReader')
        profile = json.loads((self.root/'PageReader'/'Profile.json').read_text())
        profile['application'] = True
        self.write(self.root/'PageReader'/'Profile.json', profile)
        consent = self.signed('PageReader', {'type': 'ApplicationConsent', 'ownerKey': self.admin,
                 'expires': int(time.time())+1200, 'namespaces': ['News'], 'pageIds': [self.page],
                 'permissions': ['PagesRead'], 'reviewPolicyDigest': None, 'reviewMode': None})
        reply = self.api('Administrator', {'type': 'ApplicationGrantCreate', 'consent': consent})
        assert reply['ok'], reply['code']
        return key

    def exercise(self):
        for name in ['Author', 'Reader', 'Alice', 'Bob']:
            self.admit(name, self.client(name), 1)
        self.one = self.host('MailHostOne', 30443)
        self.two = self.host('MailHostTwo', 30444)
        self.vault('Alice')
        self.vault('Bob')
        self.sender = self.mailbox('Alice', 'Personal', [self.one])
        self.recipient = self.mailbox('Bob', 'Private', [self.one, self.two])
        self.page = secrets.token_hex(16)
        self.values = {'Message': 'Form message '+secrets.token_hex(16)+'\nSecond line.', 'Count': -2,
                       'Agreed': False, 'Choice': 'Two'}
        self.values_file = self.root/'Values.json'
        self.write(self.values_file, self.values)
        self.submit(self.page, self.draft())
        self.review(self.inspect(self.page))
        self.reader_application()
        self.check('PagesRead application cannot use mail authority operations',
                   not self.api('PageReader', {'type': 'MailHosts'})['ok'])
        unpinned = self.prepare(good=False)
        self.check('sender must independently pin recipient contact before preparing',
                   unpinned.returncode != 0 and 'verify recipient owner fingerprint' in unpinned.stderr)
        self.verify_contact('Alice', self.recipient)
        self.verify_contact('Bob', self.sender)
        self.mail_call('Bob', 'refill', '--mailbox', 'Private', '--count', '8')
        accepted = self.accept()
        self.check('receiver independently accepts exact publication through separate Pages application',
                   accepted['record']['descriptor']['publicationVersion'] == 2)
        invalid = self.root/'InvalidValues.json'
        self.write(invalid, {**self.values, 'Count': 6})
        invalid_values = self.prepare(good=False, values=invalid)
        self.check('typed values are rejected before a review is retained',
                   invalid_values.returncode != 0 and 'InvalidFormInteger' in invalid_values.stderr)
        reviewed = self.prepare()
        saved = self.forms('Alice', 'review', '--review-id', reviewed['reviewId'])
        self.check('encrypted persisted review binds actual route publication policy and typed values',
                   saved == reviewed and reviewed['values'] == self.values and
                   reviewed['senderAddress'] == self.sender['addressId'] and
                   reviewed['recipientAddress'] == self.recipient['addressId'] and reviewed['requiredCopies'] == 2)
        self.check('retained review requires separate explicit confirmation',
                   self.confirm(reviewed, good=False, confirm=False).returncode != 0)
        inbox = self.mail_call('Bob', 'inbox', '--mailbox', 'Private')
        self.check('prepare and review create no inbox delivery',
                   len(inbox['hosts']) == 2 and all(host.get('entries') == [] for host in inbox['hosts']))
        self.submit(self.page, self.draft('updated'), version=2)
        self.review(self.inspect(self.page))
        self.check('changed approved publication refuses old review without reconsent',
                   self.confirm(reviewed, good=False).returncode != 0)
        self.forms('Alice', 'discard', '--review-id', reviewed['reviewId'])
        policy_review = self.prepare()
        self.mail_call('Bob', 'placement', '--mailbox', 'Private', '--host', self.one, '--copies', '1')
        self.check('changed recipient storage policy refuses old review without reconsent',
                   self.confirm(policy_review, good=False).returncode != 0)
        self.forms('Alice', 'discard', '--review-id', policy_review['reviewId'])
        self.mail_call('Bob', 'placement', '--mailbox', 'Private', '--host', self.one, '--host', self.two, '--copies', '2')
        self.mail_call('Bob', 'refill', '--mailbox', 'Private', '--count', '8')
        reviewed = self.prepare()
        self.control('MailHostTwo', 'Stop')
        partial = self.confirm(reviewed)
        assert partial['state'] == 'Partial', 'Expected partial delivery: '+json.dumps(partial)
        self.check('confirmed exact submission persists and honestly reports partial selected-store delivery',
                   partial['messageId'] == reviewed['submissionId'] and partial['state'] == 'Partial' and not partial['durable'])
        self.check('a second confirmation cannot create a fresh message for the consumed review',
                   self.confirm(reviewed, good=False).returncode != 0)
        self.control('MailHostTwo', 'Start')
        self.control('MailHostOne', 'Restart')
        delivered = self.forms('Alice', 'retry', '--mailbox', 'Personal', '--message-id', reviewed['submissionId'])
        self.check('new client process and store restart retry the original immutable submission',
                   delivered['durable'] and delivered['messageId'] == reviewed['submissionId'])
        unaccepted = self.forms('Bob', 'receive', '--mailbox', 'Private', '--host', self.one,
                                '--message-id', reviewed['submissionId'])
        self.check('signed newer publication remains unrecognised until independently accepted',
                   unaccepted['status'] == 'Unrecognised' and unaccepted['reason'] == 'PublicationNotAccepted')
        self.accept()
        received = self.forms('Bob', 'receive', '--mailbox', 'Private', '--local', '--message-id', reviewed['submissionId'])
        self.check('accepted authenticated form exposes exact typed values without business execution',
                   received['status'] == 'Accepted' and not received['duplicate'] and received['values'] == self.values and
                   received['submissionId'] == reviewed['submissionId'] and received['businessProcessing'] == 'NotPerformed')
        duplicate = self.forms('Bob', 'receive', '--mailbox', 'Private', '--host', self.two,
                               '--message-id', reviewed['submissionId'])
        self.check('durable submission ledger marks duplicate intake across process and replica reads', duplicate['duplicate'])
        consumer = Path(self.suite).parents[1]/'Tools/FormsConsumer.py'
        consumed = json.loads(self.run('python3', '-B', consumer, '--suite', self.suite, '--config',
                              self.root/'Bob'/'Profile.json', '--vault', self.vaults['Bob']['directory'],
                              '--key', self.vaults['Bob']['key'], '--mailbox', 'Private', '--message-id',
                              reviewed['submissionId'], '--local').stdout)
        self.check('installed headless consumer exposes authenticated typed data without actions',
                   consumed['status'] == 'Accepted' and consumed['duplicate'] and consumed['values'] == self.values)

        self.check('form values remain encrypted in sender and receiver vault files',
                   all(self.values['Message'].split('\n')[0].encode() not in (v['directory']/'Vault.age').read_bytes()
                       for v in self.vaults.values()))
        self.exercise_tui()
        self.call('Author', 'pages', 'withdraw', '--page-id', self.page, '--expected-version', '4')
        self.check('withdrawal prevents new form consent', self.prepare(good=False).returncode != 0)
        retried = self.forms('Alice', 'retry', '--mailbox', 'Personal', '--message-id', reviewed['submissionId'])
        self.check('withdrawal does not replace or recall previously consented immutable mail',
                   retried['messageId'] == reviewed['submissionId'] and retried['durable'])
        self.run('podman', 'stop', '--time=1', self.broker)
        interrupted = self.forms('Alice', 'retry', '--mailbox', 'Personal', '--message-id', reviewed['submissionId'])
        self.check('authority outage preserves known durable receipts and reports retry failure separately',
                   interrupted['state'] == 'Stored' and interrupted['durable'] and not interrupted['retryConfirmed']
                   and interrupted['requiredCopies'] == 2 and set(interrupted['storedHosts']) == {self.one, self.two}
                   and interrupted['messageId'] == reviewed['submissionId'] and interrupted['error'])

    def exercise_tui(self):
        author = json.loads((self.root/'Author'/'Identity.json').read_text())['publicKey']
        address = f'hypernet://{self.network}/{author}/News/{self.page}'
        vault = self.vaults['Alice']
        terminal = Terminal(self, 'browse', address, '--vault', vault['directory'],
                            '--key', vault['key'], '--mailbox', 'Personal',
                            '--mail-config', self.root/'Alice'/'Profile.json')
        values = {'Message': 'Browser q 世界\nSecond line', 'Count': -2, 'Agreed': False, 'Choice': 'Two'}
        try:
            terminal.read(b'Page opened')
            terminal.key(b'\t\r', b'Edit form field')
            terminal.key(b'\x1b[200~'+values['Message'].encode()+b'\x1b[201~', b'Edit form field')
            frame = terminal.resize(48, 24)
            assert 'Edit form field' in frame and terminal.process.poll() is None
            terminal.resize(120, 30)
            terminal.key(b'\r', b'Field saved locally')
            terminal.key(b'\t\r', b'Edit form field')
            terminal.key(b'6\r', b'InvalidFormInteger')
            terminal.key(b'\x15-2\r', b'Field saved locally')
            terminal.key(b'\t\r', b'Edit form field')
            terminal.key(b'false\r', b'Field saved locally')
            terminal.key(b'\t\r', b'Edit form field')
            terminal.key(b'Two\r', b'Field saved locally')
            self.check('browser edits bounded typed values and inert Unicode multiline paste across resize', True)
            terminal.key(b'\t\r', b'Trusted form review')
            listed = self.forms('Alice', 'reviews')['reviews']
            assert len(listed) == 1
            review = self.forms('Alice', 'review', '--review-id', listed[0]['reviewId'])
            self.check('browser review records exact typed values and actual selected sender before delivery',
                       review['values'] == values and review['senderAddress'] == self.sender['addressId'])
            terminal.key(b'\x1b', b'Form review cancelled')
            self.check('browser cancellation discards the review without queuing another submission',
                       self.forms('Alice', 'reviews')['reviews'] == [])
            terminal.key(b'r', b'Page refreshed')
            terminal.key(b'\r', b'Trusted form review')
            reviewed = self.forms('Alice', 'reviews')['reviews']
            assert len(reviewed) == 1
            current = self.forms('Alice', 'review', '--review-id', reviewed[0]['reviewId'])
            assert current['values'] == values
            terminal.key(b'SEND\r', b'Read to the end before confirming')
            terminal.key(b'\x1b[F', b'Type SEND then Enter')
            terminal.key(b'\x1b[200~SEND\x1b[201~\r', b'Trusted form review')
            self.check('browser requires complete review and directly typed confirmation; paste cannot send',
                       len(self.forms('Alice', 'reviews')['reviews']) == 1)
            terminal.key(b'SEND\r', b'Form submission')
            accepted = self.forms('Bob', 'receive', '--mailbox', 'Private', '--host', self.one,
                                  '--message-id', current['submissionId'])
            self.check('confirmed browser form arrives as independently accepted encrypted typed mail',
                       accepted['status'] == 'Accepted' and accepted['values'] == values and not accepted['duplicate'])
        finally:
            terminal.close(key=b'\x03')
        self.check('browser forms restore one terminal session and leave no unconfirmed review',
                   self.forms('Alice', 'reviews')['reviews'] == [])
        self.exercise_layout_budget(author)

    def exercise_layout_budget(self, author):
        page = secrets.token_hex(16)
        source = 'HyperNetPage/2\n# Budget\n' + '@Panel {"label":"Panel","padding":4}\n' * 6
        for index in range(4):
            form = {'id': f'F{index}', 'label': 'Form', 'profile': 'HyperNetFormMail/1',
                    'recipient': self.recipient['addressId'], 'owner': self.recipient['manifest']['publicKey']}
            source += '@Form ' + json.dumps(form) + '\n'
            for field in range(4):
                source += '@Field ' + json.dumps({'id': f'T{field}', 'label': 'Text', 'kind': 'Text', 'maxBytes': 2048}) + '\n'
            source += '@Submit {"label":"Review"}\n@End\n'
        source += '@End\n' * 6
        self.submit(page, source)
        self.review(self.inspect(page))
        terminal = Terminal(self, 'browse', f'hypernet://{self.network}/{author}/News/{page}')
        try:
            terminal.read(b'Page opened')
            terminal.resize(80, 30)
            for index in range(3):
                for field in range(4):
                    terminal.key(b'\t\r', b'Edit form field')
                    refused = index == 2 and field == 3
                    frame = terminal.key(b'\x1b[200~' + b'x' * 2000 + b'\x1b[201~\r',
                                         b'Field not saved' if refused else b'Field saved locally')
                    if refused:
                        assert 'Edit form field' in frame and 'Layout unavailable' not in frame
                        terminal.key(b'\x15Short\r', b'Field saved locally')
                        assert 'Short' in terminal.key(b'\r', b'Edit form field')
                if index < 2:
                    terminal.key(b'\t')  # Skip this form's Submit control.
        finally:
            terminal.close(key=b'\x03')
        self.check('oversized field save retains the editor and accepts a shorter value without losing the page', True)

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
                report = json.loads(path.read_text())
                report['imageId'] = self.args.image
                report['sourceSha256']['Tests/FormsWorkflow.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                path.write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ['suite', 'node', 'image', 'etcd-directory', 'seccomp', 'output']:
        parser.add_argument('--'+field, required=True)
    args = parser.parse_args()
    args.recovery_only = args.lifecycle_only = False
    FormsWorkflow(args).execute()


if __name__ == '__main__':
    main()
