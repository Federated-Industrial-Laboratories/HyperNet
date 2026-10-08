#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise two isolated installed authorities and a confined one-way Pages bridge.

Inputs match TrustWorkflow. Uses only synthetic identities and content. Both
three-voter domains and all bridge containers are removed on exit.
"""
import argparse
import hashlib
import fcntl
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import struct
import subprocess
import termios
import time
from PagesWorkflow import PagesWorkflow


class FederationWorkflow:
    def __init__(self, args):
        self.args = args
        self.source = PagesWorkflow(args, slot=0, federation=True)
        self.destination = PagesWorkflow(args, slot=1, federation=True)
        self.results = []
        self.profile = None
        self.bridge_tool = self.source.host_tool.with_name('Bridge.sh')
        self.external = None

    def check(self, label, condition):
        if not condition:
            raise AssertionError(label)
        self.results.append(label)
        print('PASS', label, flush=True)

    def setup(self):
        s, d = self.source, self.destination
        s.provision(); d.provision()
        self.author = s.client('Author'); s.admit('Author', self.author, 1)
        self.reader = d.client('Reader'); d.admit('Reader', self.reader, 1)
        for domain in [s, d]:
            domain.bridge = domain.client('Bridge', transport=True)
            domain.admit('Bridge', domain.bridge, 9)
        self.agreement = secrets.token_hex(16)
        self.treaty = dict(version=1, agreementId=self.agreement,
            sourceNetwork=s.network, destinationNetwork=d.network,
            sourceAuthorityKey=s.signer, destinationAuthorityKey=d.signer,
            sourceBridgeKey=s.bridge, destinationBridgeKey=d.bridge,
            sourceNamespace='News', destinationNamespace='PartnerNews',
            service='Pages', profile='HyperNetPage/1', expires=int(time.time())+1800)
        self.configuration = s.root/'BridgeConfiguration'
        self.configuration.mkdir(mode=0o700)
        self.treaty_path = self.configuration/'Treaty.json'
        s.write(self.treaty_path, self.treaty)
        terms = json.loads(s.run(s.suite,'federation','treaty',self.treaty_path).stdout)
        self.digest = terms['digest']
        s.call('Administrator','federation','accept','--treaty',self.treaty_path)
        self.check('bridge grant cannot read native membership content before consent',
            not s.api('Bridge',dict(type='PageList',namespace='News',after=None))['ok'])
        self.build_consent()
        self.check('unaccepted destination cannot register bridge consent',
            self.register(d, good=False).returncode != 0)
        d.call('Administrator','federation','accept','--treaty',self.treaty_path)
        self.register(s); self.register(d)
        self.check('both independent administrators accept identical immutable terms',
            s.call('Administrator','federation','agreements')['result']['entries'][0]['digest'] == self.digest
            and d.call('Administrator','federation','agreements')['result']['entries'][0]['digest'] == self.digest)
        self.page = secrets.token_hex(16)
        local_author=d.client('Author'); d.admit('Author',local_author,1)
        self.local_page=secrets.token_hex(16)
        d.submit(self.local_page,f'HyperNetPage/1\n# LocalGate\n=> hypernet://{s.network}/{self.author}/News/{self.page} Partner page\n')
        d.review(d.inspect(self.local_page))
        s.submit(self.page,f'HyperNetPage/1\n# Partner\n: Original shared content.\n=> hypernet://{d.network}/{local_author}/News/{self.local_page} Local page\n')
        s.review(s.inspect(self.page))
        self.start()

    def build_consent(self):
        s, d = self.source, self.destination
        def endpoint(domain):
            return dict(network=domain.network, deviceKey=domain.bridge, authorityKey=domain.signer,
                authorityEndpoint='https://authority.example:8443',
                authorityAddress=domain.broker_address+':8443',
                caCertificateDigest=hashlib.sha256((domain.pki/'NetworkCa.pem').read_bytes()).hexdigest())
        self.spec = dict(version=1, service='FederationPages', agreementId=self.agreement,
            treatyDigest=self.digest, sourceNamespace='News', destinationNamespace='PartnerNews',
            source=endpoint(s), destination=endpoint(d), expires=int(time.time())+1200,
            memoryBytes=268435456,pids=64,cpuQuota=100000,cpuPeriod=100000,stateBytes=16777216)
        self.sign_configuration()

    def sign_configuration(self):
        s, d = self.source, self.destination
        spec = self.configuration/'Specification.json'
        consent = self.configuration/'Consent.json'
        s.write(spec, self.spec)
        if consent.exists(): consent.unlink()
        result = s.run(s.suite,'federation','sign-consent','--spec',spec,'--treaty',self.treaty_path,
            '--source-identity',s.root/'Bridge'/'Identity.json','--destination-identity',d.root/'Bridge'/'Identity.json',
            '--output',consent)
        self.consent_digest = json.loads(result.stdout)['profile']
        config = dict(consentFile='/Config/Consent.json',treatyFile='/Config/Treaty.json',stateDirectory='/State')
        for role, domain in [('Source',s),('Destination',d)]:
            for origin, suffix in [(domain.root/'Bridge'/'Identity.json','Identity.json'),
                (domain.pki/'NetworkCa.pem','Ca.pem'),(domain.pki/'Host.pem','Client.pem'),(domain.pki/'HostKey.pem','ClientKey.pem')]:
                shutil.copy2(origin,self.configuration/(role+suffix))
            config[role.lower()] = dict(network=domain.network,endpoint=self.spec[role.lower()]['authorityEndpoint'],
                identity='/Config/'+role+'Identity.json',caCertificate='/Config/'+role+'Ca.pem',
                clientCertificate='/Config/'+role+'Client.pem',clientKey='/Config/'+role+'ClientKey.pem',
                relayAddress='10.1.1.3:8443')
        s.write(self.configuration/'Bridge.json',config)

    def register(self, domain, good=True):
        der=subprocess.check_output(['openssl','x509','-in',str(domain.pki/'Host.pem'),'-outform','DER'])
        return domain.cli('Bridge','federation','register','--consent',self.configuration/'Consent.json',
            '--certificate',hashlib.sha256(der).hexdigest(),good=good)

    def start(self, source_egress=None, destination_egress=None):
        s, d = self.source, self.destination
        self.profile=s.root/('BridgeProfile'+secrets.token_hex(4))
        s.run('bash',self.bridge_tool,'Initialise',self.profile,self.configuration,self.args.image,
            source_egress or s.prefix,destination_egress or d.prefix,timeout=60)
        s.run('bash',self.bridge_tool,'Start',self.profile,timeout=60)
        self.control=json.loads((self.profile/'Control.json').read_text())
        self.wait_active()

    def wait_active(self):
        s=self.source
        for _ in range(100):
            output=s.run('podman','logs','--tail=1',self.control['name'],good=False).stdout
            try: value=json.loads(output)
            except json.JSONDecodeError: value={}
            if value.get('active'):
                return
            time.sleep(.2)
        raise AssertionError('bridge did not become active: '+output[-1500:])

    def queue(self):
        return self.destination.call('Administrator','federation','queue','--agreement',self.agreement)['result']['entries']

    def wait_pending(self):
        for _ in range(80):
            entries=self.queue()
            if any(entry['pageId']==self.page for entry in entries): return
            time.sleep(.15)
        raise AssertionError('shared page did not reach destination quarantine')

    def review(self):
        d=self.destination
        path=d.root/('ForeignReview'+secrets.token_hex(4)+'.json')
        d.cli('Administrator','federation','inspect','--agreement',self.agreement,'--page-id',self.page,'--output',path)
        return d.cli('Administrator','federation','review','--input',path,'--decision','approve')

    def read(self, good=True):
        return self.destination.cli('Reader','federation','read','--agreement',self.agreement,'--page-id',self.page,good=good)

    def wait_read(self, text):
        for _ in range(80):
            result=self.read(good=False)
            if result.returncode==0 and text in result.stdout: return result
            time.sleep(.15)
        raise AssertionError('foreign publication did not become readable: '+result.stderr[-1000:])

    def share(self, withdraw=False):
        args=['federation','share','--agreement',self.agreement,'--page-id',self.page]
        if withdraw: args+=['--withdraw']
        return self.source.cli('Author',*args)

    def stop_bridge(self, remove=False):
        if self.profile and (self.profile/'Control.json').exists():
            self.source.run('bash',self.bridge_tool,'Stop',self.profile,good=False,timeout=30)
            if remove:
                control=json.loads((self.profile/'Control.json').read_text())
                self.source.run('podman','network','rm',control['network'],good=False)
                self.profile=None

    def navigate(self):
        d=self.destination
        master,slave=pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',32,140,0,0))
        original=termios.tcgetattr(slave)
        process=subprocess.Popen([d.suite,'--config',str(d.root/'Reader'/'Profile.json'),
            'pages','read','--page-id',self.local_page,'--tui'],stdin=slave,stdout=slave,stderr=slave,
            env=dict(os.environ,TERM='xterm-256color'),start_new_session=True)
        def expect(title):
            output=b''; end=time.monotonic()+12
            marker=b'HyperNet Pages | '+title
            while marker not in output and time.monotonic()<end:
                if select.select([master],[],[],.1)[0]:
                    try: output+=os.read(master,65536)
                    except OSError: break
            assert marker in output, 'cross-network terminal navigation did not reach '+title.decode()
        try:
            expect(b'LocalGate')
            os.write(master,b'\r'); expect(b'Partner')
            os.write(master,b'r'); expect(b'Partner')
            os.write(master,b'\r'); expect(b'LocalGate')
            os.write(master,b'b'); expect(b'Partner')
            os.write(master,b'b'); expect(b'LocalGate')
            os.write(master,b'q'); process.wait(timeout=5)
            self.check('installed TUI follows native foreign and return links with verified refresh and shared Back history',
                process.returncode==0 and termios.tcgetattr(slave)==original)
        finally:
            if process.poll() is None: process.kill(); process.wait()
            os.close(master); os.close(slave)

    def exercise(self):
        s,d=self.source,self.destination
        self.check('native approval and treaty alone do not permit export',not self.queue())
        self.share(); self.wait_pending()
        self.check('author opt-in reaches destination quarantine',self.read(good=False).returncode!=0)
        self.check('bridge cannot bypass native Pages service isolation',
            not s.api('Bridge',dict(type='PageRead',pageId=self.page),hosting=True)['ok'])
        self.check('ordinary member cannot mint destination bridge permits',
            not d.api('Reader',dict(type='FederationPermit',agreementId=self.agreement,profile=self.consent_digest))['ok'])
        self.check('bridge signatures require their separate TLS client certificate',
            not d.api('Bridge',dict(type='FederationPermit',agreementId=self.agreement,profile=self.consent_digest))['ok'])
        self.review()
        result=self.wait_read('Original shared content.')
        self.check('independent destination reader verifies origin and local approval',
            s.network in result.stdout and 'PartnerNews' in result.stdout)
        self.navigate()
        inspection=json.loads(s.run('podman','inspect',self.control['name']).stdout)[0]
        self.check('bridge has one internal network no published port and bounded memory',
            list(inspection['NetworkSettings']['Networks'])==[self.control['network']]
            and not inspection['HostConfig']['PortBindings'] and inspection['HostConfig']['Memory']==268435456)
        s.run('bash',self.bridge_tool,'Stop',self.profile,timeout=30)
        time.sleep(6)
        self.check('bridge partition expires previously approved foreign reads',self.read(good=False).returncode!=0)
        s.run('bash',self.bridge_tool,'Start',self.profile,timeout=60)
        self.wait_active(); self.wait_read('Original shared content.')
        self.check('bridge restart renews evidence without another content approval',not self.queue())
        self.share(withdraw=True); time.sleep(6)
        self.check('source author withdrawal stops destination reads within lease bound',self.read(good=False).returncode!=0)
        self.share(); self.wait_read('Original shared content.')
        s.submit(self.page,'HyperNetPage/1\n# Partner\n: Changed shared content.\n',version=2)
        s.review(s.inspect(self.page)); time.sleep(6)
        self.check('new native publication does not inherit old author sharing',self.read(good=False).returncode!=0)
        self.share(); self.wait_pending()
        self.check('new shared publication requires new destination review',self.read(good=False).returncode!=0)
        self.review(); self.wait_read('Changed shared content.')
        self.check('exact changed publication becomes readable after both fresh decisions',True)
        s.run('podman','pause',s.broker)
        try:
            time.sleep(6)
            self.check('source authority outage cannot renew destination permission',self.read(good=False).returncode!=0)
        finally:
            s.run('podman','unpause',s.broker)
        self.wait_read('Changed shared content.')
        if self.external:
            self.external(self)
        d.call('Bridge','federation','withdraw-consent')
        self.check('local bridge-consent withdrawal immediately denies foreign reads',self.read(good=False).returncode!=0)
        self.register(d); self.wait_read('Changed shared content.')
        d.call('Administrator','federation','withdraw','--agreement',self.agreement,'--expected-version','1')
        self.check('local treaty withdrawal immediately denies foreign reads',self.read(good=False).returncode!=0)
        self.check('withdrawn immutable treaty cannot be silently reaccepted',
            d.cli('Administrator','federation','accept','--treaty',self.treaty_path,good=False).returncode!=0)

    def exercise_expiry(self):
        s,d=self.source,self.destination
        self.share(); self.wait_pending(); self.review()
        self.wait_read('Original shared content.')
        self.stop_bridge(remove=True)
        self.spec['expires']=int(time.time())+20
        self.sign_configuration(); self.register(s); self.register(d)
        self.start(); self.wait_read('Original shared content.')
        self.check('short-lived bridge consent preserves verified publication until expiry',True)
        s.admit('Member',s.member,3)
        expiry=int(time.time())+20
        der=subprocess.check_output(['openssl','x509','-in',str(s.pki/'Host.pem'),'-outform','DER'])
        s.start_consented_host(str(expiry),hashlib.sha256(der).hexdigest())
        paused=[self.control['name'],self.control['name']+'DestinationGate',s.host_name,s.host_name+'Gate']
        for name in paused:
            s.run('podman','kill','--signal=STOP',name)
        self.check('owned fixtures deliberately suspend worker and relay expiry handling',True)
        deadline=max(expiry,self.spec['expires'])+3
        while time.time()<deadline:
            time.sleep(max(0,min(.25,deadline-time.time())))
        gate=self.control['name']+'SourceGate'
        states={name:json.loads(s.run('podman','inspect',name).stdout)[0]['State']
                for name in paused+[gate]}
        self.check('external runtime limits terminate stopped bridge host and relay processes',
            all(not states[name]['Running'] and states[name]['ExitCode']!=0 for name in paused))
        self.check('relay absolute expiry works independently of its stopped bridge',
            not states[gate]['Running'] and 'ConsentExpired' in s.run('podman','logs',gate,good=False).stderr)
        self.check('expired consent cannot restart the installed bridge',
            s.run('bash',self.bridge_tool,'Restart',self.profile,good=False).returncode!=0)
        self.check('expired consent cannot restart the installed native host',
            s.run('bash',s.host_tool,'Restart',s.host_profile,good=False).returncode!=0)

    def execute(self):
        error=None
        try:
            self.setup()
            if getattr(self.args,'expiry_only',False): self.exercise_expiry()
            else: self.exercise()
        except Exception as caught:
            error=str(caught)
            raise
        finally:
            self.stop_bridge(remove=True)
            self.destination.cleanup(); self.source.cleanup()
            repository=Path(__file__).resolve().parents[1]
            Path(self.args.output).write_text(json.dumps(dict(passed=self.results,error=error,imageId=self.args.image,
                nodeSha256=hashlib.sha256(Path(self.source.node).read_bytes()).hexdigest(),
                suiteSha256=hashlib.sha256(Path(self.source.suite).read_bytes()).hexdigest(),
                sourceSha256={str(p.relative_to(repository)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for group in ['Source/*.rs','Tools/*.rs','Tools/*.sh','Tests/*Workflow.py'] for p in repository.glob(group)}),indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ['suite','node','image','etcd-directory','seccomp','output']:
        parser.add_argument('--'+field,required=True)
    parser.add_argument('--expiry-only',action='store_true',help='Check installed worker and relay expiry, including stopped processes')
    FederationWorkflow(parser.parse_args()).execute()

if __name__=='__main__':
    main()
