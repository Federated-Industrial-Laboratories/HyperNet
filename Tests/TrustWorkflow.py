#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise installed clients against three TLS voters and a confined authority.

Inputs: --suite, --node, --image, --etcd-directory, --seccomp, --output.
Requires rootless Podman, OpenSSL and Python cryptography. Fixtures are private
and removed on exit. Output contains results and public source digests only.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time


class Workflow:
    def __init__(self, args, slot=0, federation=False):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix='HyperNetQualification'))
        self.network = secrets.token_hex(32)
        self.prefix = 'HyperNetQualification' + secrets.token_hex(4)
        self.results = []
        self.containers = []
        self.network_created = False
        self.host_profile = None
        self.host_tool = Path(__file__).resolve().parents[1] / 'Tools' / 'Host.sh'
        self.authority_tool = self.host_tool.with_name('Authority.sh')
        self.authority_profile = None
        self.pki = self.root / 'Pki'
        self.pki.mkdir(mode=0o700)
        self.suite = str(Path(args.suite).resolve())
        self.node = str(Path(args.node).resolve())
        self.etcd = Path(args.etcd_directory).resolve()
        self.subnet = f'10.89.{72+slot}'
        self.store_port = 23790 + slot * 10
        self.broker_port = 28443 + slot
        self.federation = federation
        self.endpoint = f'https://localhost:{self.broker_port}'
        self.broker = self.prefix + 'Broker'

    def run(self, *command, good=True, timeout=30, input=None):
        result = subprocess.run([str(c) for c in command], input=input, text=True,
                                capture_output=True, timeout=timeout)
        if good and result.returncode:
            # Commands never put private keys or invitation secrets in arguments.
            raise RuntimeError(f'{command[0]} failed ({result.returncode}): {result.stderr[-2000:]}')
        return result

    def write(self, path, value):
        path.write_text(json.dumps(value) + '\n')
        path.chmod(0o600)

    def check(self, label, condition):
        if not condition:
            raise AssertionError(label)
        self.results.append(label)
        print('PASS', label, flush=True)

    def openssl(self, *args):
        return self.run('openssl', *args)

    def ca(self, name):
        self.openssl('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '2',
                     '-keyout', self.pki / (name + 'Key.pem'), '-out', self.pki / (name + '.pem'),
                     '-subj', '/CN=' + name, '-addext', 'basicConstraints=critical,CA:TRUE')

    def certificate(self, name, ca, cn, san, usage):
        self.openssl('req', '-new', '-newkey', 'ed25519', '-nodes', '-keyout', self.pki / (name + 'Key.pem'),
                     '-out', self.pki / (name + '.csr'), '-subj', '/CN=' + cn)
        extension = self.pki / (name + 'Extensions.txt')
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=' + usage + '\n' + ('subjectAltName=' + san + '\n' if san else ''))
        self.openssl('x509', '-req', '-in', self.pki / (name + '.csr'), '-CA', self.pki / (ca + '.pem'),
                     '-CAkey', self.pki / (ca + 'Key.pem'), '-set_serial', str(secrets.randbits(120)),
                     '-days', '2', '-extfile', extension, '-out', self.pki / (name + '.pem'))

    def client(self, name, transport=False):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        key = json.loads(self.run(self.suite, 'keygen', '--output', directory / 'Identity.json').stdout)['publicKey']
        config = {'network':self.network, 'endpoint':self.endpoint,
                  'caCertificate':str(self.pki / 'NetworkCa.pem'), 'identity':str(directory / 'Identity.json')}
        if transport:
            config.update(clientCertificate=str(self.pki / 'Host.pem'), clientKey=str(self.pki / 'HostKey.pem'))
        self.write(directory / 'Profile.json', config)
        return key

    def call(self, name, *args, good=True):
        response = self.run(self.suite, '--config', self.root / name / 'Profile.json', *args, good=good, timeout=15)
        if good:
            return json.loads(response.stdout)
        return response

    def authctl(self, *args, good=True, endpoints=None):
        return self.run(self.etcd / 'etcdctl', '--endpoints=' + (endpoints or ','.join(f'https://127.0.0.1:{self.store_port+i}' for i in range(1,4))),
                        '--cacert=' + str(self.pki / 'StoreCa.pem'), '--cert=' + str(self.pki / 'Root.pem'),
                        '--key=' + str(self.pki / 'RootKey.pem'), '--command-timeout=5s', *args, good=good, timeout=12)

    def provision(self):
        self.run('podman', 'network', 'create', '--subnet', self.subnet+'.0/24', self.prefix)
        self.network_created = True
        for name in ['StoreCa', 'PeerCa', 'NetworkCa', 'HostCa']:
            self.ca(name)
        self.certificate('Root', 'StoreCa', 'root', '', 'clientAuth')
        self.certificate('BrokerStore', 'StoreCa', 'HyperNetBroker', '', 'clientAuth')
        self.certificate('Broker', 'NetworkCa', 'HyperNetAuthority', 'DNS:localhost,DNS:authority.example,IP:127.0.0.1', 'serverAuth')
        self.certificate('Host', 'HostCa', 'HyperNetHost', '', 'clientAuth')
        cluster = ','.join(f'Voter{i}=https://{self.subnet}.{10+i}:2380' for i in range(1,4))
        for i in range(1,4):
            name = f'Voter{i}'
            address = f'{self.subnet}.{10+i}'
            self.certificate(name, 'StoreCa', name, 'DNS:HyperNetVoter,IP:127.0.0.1,IP:' + address, 'serverAuth')
            self.certificate(name + 'Peer', 'PeerCa', 'HyperNetVoter', 'IP:' + address, 'serverAuth,clientAuth')
            directory = self.root / name
            directory.mkdir(mode=0o700)
            config = directory / 'Config'; config.mkdir(mode=0o700)
            state = directory / 'State'; state.mkdir(mode=0o700)
            for file in [name+'.pem',name+'Key.pem',name+'Peer.pem',name+'PeerKey.pem','StoreCa.pem','PeerCa.pem']:
                shutil.copy2(self.pki / file, config / file)
            self.run('podman', 'unshare', 'chown', '-R', '1:1', directory)
            container = self.prefix + name
            self.containers.append(container)
            self.run('podman','run','-d','--name',container,'--network',self.prefix,'--ip',address,
                     '--userns=nomap','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges',
                     '--read-only','--memory=512m','--memory-swap=512m','--pids-limit=128','--cpus=1',
                     '--log-driver=none','--publish',f'127.0.0.1:{self.store_port+i}:2379',
                     '-v',f'{self.etcd}/etcd:/Etcd:ro','-v',f'{config}:/Config:ro', '-v',f'{state}:/State:rw',
                     '--entrypoint=/Etcd',self.args.image,'--name='+name,'--data-dir=/State',
                     '--listen-client-urls=https://0.0.0.0:2379','--advertise-client-urls=https://'+address+':2379',
                     '--listen-peer-urls=https://0.0.0.0:2380','--initial-advertise-peer-urls=https://'+address+':2380',
                     '--initial-cluster='+cluster,'--initial-cluster-token='+self.prefix,
                     '--cert-file=/Config/'+name+'.pem','--key-file=/Config/'+name+'Key.pem',
                     '--client-cert-auth','--trusted-ca-file=/Config/StoreCa.pem',
                     '--peer-cert-file=/Config/'+name+'Peer.pem','--peer-key-file=/Config/'+name+'PeerKey.pem',
                     '--peer-client-cert-auth','--peer-trusted-ca-file=/Config/PeerCa.pem','--peer-cert-allowed-cn=HyperNetVoter',
                     '--tls-min-version=TLS1.3','--tls-max-version=TLS1.3','--quota-backend-bytes=16777216',
                     '--max-wals=2','--max-snapshots=2','--snapshot-count=100','--auto-compaction-retention=1h',
                     '--enable-grpc-gateway=false', timeout=60)
        for _ in range(20):
            if self.authctl('endpoint','health',good=False).returncode == 0:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError('TLS authority voters did not become healthy')
        self.authctl('user','add','root','--no-password')
        self.authctl('user','grant-role','root','root')
        self.authctl('role','add','HyperNetBroker')
        self.authctl('role','grant-permission','HyperNetBroker','readwrite','/HyperNet/'+self.network+'/Authority')
        self.authctl('role','grant-permission','HyperNetBroker','readwrite','/HyperNet/'+self.network+'/Pages/','--prefix')
        if self.federation:
            self.authctl('role','grant-permission','HyperNetBroker','readwrite','/HyperNet/'+self.network+'/Federation/','--prefix')
        self.authctl('user','add','HyperNetBroker','--no-password')
        self.authctl('user','grant-role','HyperNetBroker','HyperNetBroker')
        self.authctl('auth','enable')
        self.check('three authenticated TLS voters with RBAC', self.authctl('endpoint','health').returncode == 0)
        self.admin = self.client('Administrator')
        self.member = self.client('Member', transport=True)
        self.stranger = self.client('Stranger')
        directory = self.root / 'BrokerRuntime'; directory.mkdir(mode=0o700)
        configdir = directory / 'Config'; configdir.mkdir(mode=0o700)
        statedir = directory / 'State'; statedir.mkdir(mode=0o700)
        for file in ['NetworkCa.pem','Broker.pem','BrokerKey.pem','HostCa.pem','StoreCa.pem','BrokerStore.pem','BrokerStoreKey.pem']:
            shutil.copy2(self.pki/file,configdir/file)
        config = {'network':self.network,'listen':'0.0.0.0:8443','stateDirectory':str(statedir),
                  'certificate':str(configdir/'Broker.pem'),'privateKey':str(configdir/'BrokerKey.pem'),
                  'clientCa':str(configdir/'HostCa.pem'),'etcdEndpoints':[f'https://127.0.0.1:{self.store_port+i}' for i in range(1,4)],
                  'etcdCa':str(configdir/'StoreCa.pem'),'etcdCertificate':str(configdir/'BrokerStore.pem'),
                  'etcdKey':str(configdir/'BrokerStoreKey.pem'),'etcdServerName':'HyperNetVoter'}
        if self.federation:
            signer = configdir/'FederationSigningKey.json'
            self.signer = json.loads(self.run(self.suite,'keygen','--output',signer).stdout)['publicKey']
            config['federationSigningKey'] = str(signer)
        self.write(directory/'Bootstrap.json',config)
        self.run(self.node,'initialise','--config',directory/'Bootstrap.json','--admin-key',self.admin)
        config['stateDirectory']='/State'
        config['etcdEndpoints']=[f'https://{self.subnet}.{10+i}:2379' for i in range(1,4)]
        if self.federation:
            config['federationSigningKey']='/Config/FederationSigningKey.json'
        for field in ['certificate','privateKey','clientCa','etcdCa','etcdCertificate','etcdKey']:
            config[field]='/Config/'+Path(config[field]).name
        self.write(configdir/'Authority.json',config)
        for origin,destination in [('Broker.pem','AuthorityCertificate.pem'),('BrokerKey.pem','AuthorityKey.pem'),
                                   ('HostCa.pem','HostingCa.pem'),('StoreCa.pem','VoterCa.pem'),
                                   ('BrokerStore.pem','BrokerCertificate.pem'),('BrokerStoreKey.pem','BrokerKey.pem')]:
            shutil.copy2(self.pki/origin,configdir/destination)
        self.authority_profile=self.root/'AuthorityProfile'
        self.run('bash',self.authority_tool,'Initialise',self.authority_profile,configdir,statedir,
                 self.args.image,self.prefix,f'127.0.0.1:{self.broker_port}:8443',timeout=60)
        self.broker=json.loads((self.authority_profile/'Control.json').read_text())['name']
        self.containers.append(self.broker)
        self.run('bash',self.authority_tool,'Start',self.authority_profile,timeout=60)
        broker_inspect=json.loads(self.run('podman','inspect',self.broker).stdout)[0]
        self.broker_address=broker_inspect['NetworkSettings']['Networks'][self.prefix]['IPAddress']
        for _ in range(30):
            if self.call('Administrator','status',good=False).returncode == 0:
                break
            time.sleep(0.2)
        else:
            log=self.run('podman','logs',self.broker,good=False)
            raise RuntimeError('Confined broker did not become ready: '+log.stdout[-2000:]+log.stderr[-2000:])
        self.check('confined authority and independent installed client',True)
        self.check('authority operator status reports running process','running' in self.run('bash',self.authority_tool,'Status',self.authority_profile).stdout)

    def signed(self, name, command, network=None, timestamp=None, request_id=None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        identity=json.loads((self.root/name/'Identity.json').read_text())
        network=network or self.network
        payload=json.dumps({'version':1,'requestId':request_id or secrets.token_hex(16),
                            'issuedAt':timestamp if timestamp is not None else int(time.time()),'command':command},separators=(',',':')).encode()
        message=b'HyperNet/Request/1\0'+bytes.fromhex(network)+bytes.fromhex(identity['publicKey'])+payload
        key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(identity['secretKey']))
        return {'network':network,'publicKey':identity['publicKey'],'payload':base64.urlsafe_b64encode(payload).decode().rstrip('='),'signature':key.sign(message).hex()}

    def request(self, envelope, hosting=False):
        context=ssl.create_default_context(cafile=str(self.pki/'NetworkCa.pem'))
        context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_3
        if hosting:
            context.load_cert_chain(str(self.pki/'Host.pem'),str(self.pki/'HostKey.pem'))
        connection=http.client.HTTPSConnection('localhost',self.broker_port,context=context,timeout=10)
        try:
            connection.request('POST','/V1/Command',json.dumps(envelope),{'Content-Type':'application/json'})
            response=connection.getresponse()
            return json.loads(response.read(262145))
        finally:
            connection.close()

    def start_consented_host(self, expiry, fingerprint):
        source=self.root/'HostConfiguration'; source.mkdir(mode=0o700)
        specification={'grants':2,'expires':int(expiry),'memoryBytes':268435456,'pids':64,
                       'cpuQuota':100000,'cpuPeriod':100000,'stateBytes':16777216,
                       'authorityEndpoint':'https://authority.example:8443','authorityAddress':self.broker_address+':8443'}
        self.write(source/'Specification.json',specification)
        consent=self.call('Member','host-consent','--spec',source/'Specification.json','--output',source/'Consent.json')
        self.profile=consent['profile']
        self.call('Member','consent','--profile',self.profile,'--grants','2','--expires',expiry,'--certificate',fingerprint)
        for origin,destination in [(self.root/'Member'/'Identity.json','Identity.json'),
                                   (self.pki/'NetworkCa.pem','Ca.pem'),(self.pki/'Host.pem','Client.pem'),
                                   (self.pki/'HostKey.pem','ClientKey.pem')]:
            shutil.copy2(origin,source/destination)
        self.write(source/'Host.json',{'network':self.network,'endpoint':specification['authorityEndpoint'],
                    'caCertificate':'/Config/Ca.pem','identity':'/Config/Identity.json',
                    'clientCertificate':'/Config/Client.pem','clientKey':'/Config/ClientKey.pem',
                    'consentFile':'/Config/Consent.json','stateDirectory':'/State','relayAddress':'10.1.1.3:8443'})
        malformed=self.root/'MalformedConfiguration'
        shutil.copytree(source,malformed)
        signed=json.loads((malformed/'Consent.json').read_text())
        content=json.loads(base64.urlsafe_b64decode(signed['payload']+'='*(-len(signed['payload'])%4)))
        canary=self.root/'UnexpectedExecution'
        content['expires']='$(touch '+str(canary)+')'
        signed['payload']=base64.urlsafe_b64encode(json.dumps(content).encode()).decode().rstrip('=')
        self.write(malformed/'Consent.json',signed)
        invalid_profile=self.root/'InvalidHostProfile'
        refused=self.run('bash',self.host_tool,'Initialise',invalid_profile,malformed,self.args.image,self.prefix,good=False,timeout=30)
        self.check('malformed local consent cannot execute shell or leave a profile',refused.returncode!=0 and not canary.exists() and not invalid_profile.exists())
        self.host_profile=self.root/'HostProfile'
        self.run('bash',self.host_tool,'Initialise',self.host_profile,source,self.args.image,self.prefix,timeout=60)
        self.run('bash',self.host_tool,'Start',self.host_profile,timeout=60)
        host_control=json.loads((self.host_profile/'Control.json').read_text())
        self.host_name=host_control['name']
        for _ in range(25):
            status=self.run('podman','logs','--tail=1',self.host_name,good=False).stdout
            if '"active":true' in status:break
            time.sleep(0.2)
        self.check('consented host runs through fixed endpoint relay','"active":true' in status)

    def exercise_lifecycle(self):
        from Lifecycle import overlap
        expiry=str(int(time.time())+3600)
        invitation=self.root/'Invitation.json'
        self.call('Administrator','invite','--device-key',self.member,'--grants','3','--expires',expiry,'--output',invitation)
        self.call('Member','redeem','--invitation',invitation)
        der=subprocess.check_output(['openssl','x509','-in',str(self.pki/'Host.pem'),'-outform','DER'])
        self.start_consented_host(expiry,hashlib.sha256(der).hexdigest())
        overlap(self.host_tool,self.host_profile,self.host_name+'Gate',self.root/'LifecycleBarrier',start='Restart',real=True)
        self.check('concurrent restart cannot reverse completed local withdrawal',
                   (self.host_profile/'Withdrawn').exists() and all(
                       self.run('podman','container','exists',name,good=False).returncode!=0
                       for name in [self.host_name,self.host_name+'Gate']))
        self.check('withdrawn host rejects a later start',
                   self.run('bash',self.host_tool,'Start',self.host_profile,good=False).returncode!=0)
        self.run('bash',self.authority_tool,'Restart',self.authority_profile,timeout=45)
        for _ in range(20):
            if self.call('Member','status',good=False).returncode==0:break
            time.sleep(0.2)
        self.check('serialized authority restart preserves admitted membership',self.call('Member','status')['ok'])
        self.run('bash',self.authority_tool,'Stop',self.authority_profile,timeout=30)
        self.check('authority stop removes its container',self.run('podman','container','exists',self.broker,good=False).returncode!=0)

    def exercise(self):
        self.check('uninvited device denied',self.call('Stranger','status',good=False).returncode!=0)
        legacy=ssl.create_default_context(cafile=str(self.pki/'NetworkCa.pem'))
        legacy.minimum_version=legacy.maximum_version=ssl.TLSVersion.TLSv1_2
        connection=http.client.HTTPSConnection('localhost',28443,context=legacy,timeout=3)
        try:
            connection.connect()
            legacy_denied=False
        except ssl.SSLError:
            legacy_denied=True
        finally:
            connection.close()
        self.check('TLS 1.2 downgrade denied',legacy_denied)
        profile=self.root/'Stranger'/'Profile.json'
        original=json.loads(profile.read_text())
        wrong=dict(original); wrong['caCertificate']=str(self.pki/'PeerCa.pem'); self.write(profile,wrong)
        self.check('untrusted authority certificate denied',self.call('Stranger','status',good=False).returncode!=0)
        self.write(profile,original)
        self.check('wrong network denied',not self.request(self.signed('Administrator',{'type':'Status'},network='ff'*32))['ok'])
        self.check('stale signed request denied',not self.request(self.signed('Administrator',{'type':'Status'},timestamp=1))['ok'])
        envelope=self.signed('Administrator',{'type':'Status'}); envelope['signature']='00'*64
        self.check('invalid signature denied',not self.request(envelope)['ok'])
        expiry=str(int(time.time())+3600)
        invitation=self.root/'Invitation.json'
        self.call('Administrator','invite','--device-key',self.member,'--grants','3','--expires',expiry,'--output',invitation)
        self.call('Administrator','invite','--device-key',self.member,'--grants','3','--expires',expiry,'--output',invitation)
        secret=json.loads(invitation.read_text())['secret']
        self.check('invitation bound to intended device',not self.request(self.signed('Stranger',{'type':'Redeem','secret':secret}))['ok'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            races=list(pool.map(lambda _:self.call('Member','redeem','--invitation',invitation,good=False),range(2)))
        self.check('concurrent same-device redemption converges',all(result.returncode==0 for result in races))
        self.check('one membership created',self.call('Administrator','status')['result']['memberCount']==2)
        self.snapshot=self.root/'PreviousAuthority.db'
        self.authctl('snapshot','save',self.snapshot,endpoints='https://127.0.0.1:23791')
        self.snapshot.chmod(0o600)
        self.check('member cannot issue administrative invitation',not self.request(self.signed('Member',{'type':'Invite','verifier':'03'*32,'deviceKey':self.stranger,'grants':7,'expires':int(expiry)}))['ok'])
        self.profile='04'*32
        # DER output uses binary mode separately; never pass private material through output.
        der=subprocess.check_output(['openssl','x509','-in',str(self.pki/'Host.pem'),'-outform','DER'])
        fingerprint=hashlib.sha256(der).hexdigest()
        self.call('Member','consent','--profile',self.profile,'--grants','2','--expires',expiry,'--certificate',fingerprint)
        self.check('mTLS and consent permit heartbeat',self.call('Member','heartbeat','--profile',self.profile)['result']['effectiveGrants']==2)
        self.check('signature alone cannot host',not self.request(self.signed('Member',{'type':'Heartbeat','profile':self.profile}))['ok'])
        self.call('Member','withdraw')
        self.check('withdrawal denies heartbeat',self.call('Member','heartbeat','--profile',self.profile,good=False).returncode!=0)
        self.start_consented_host(expiry,fingerprint)
        self.run('bash',self.host_tool,'Withdraw',self.host_profile,timeout=30)
        self.check('local withdrawal immediately removes host',self.run('podman','container','exists',self.host_name,good=False).returncode!=0)
        self.check('withdrawn local consent cannot restart',self.run('bash',self.host_tool,'Start',self.host_profile,good=False).returncode!=0)
        self.run('bash',self.authority_tool,'Restart',self.authority_profile,timeout=45)
        for _ in range(20):
            if self.call('Member','status',good=False).returncode==0:break
            time.sleep(0.2)
        self.check('authority restart preserves membership and consent',self.call('Member','heartbeat','--profile',self.profile)['ok'])
        statuses=json.loads(self.authctl('endpoint','status','--write-out=json').stdout)
        leader=next(item['Status']['header']['member_id'] for item in statuses if item['Status']['leader']==item['Status']['header']['member_id'])
        number=next(i+1 for i,item in enumerate(statuses) if item['Status']['header']['member_id']==leader)
        stopped=self.prefix+f'Voter{number}'
        self.run('podman','stop','--time','3',stopped,timeout=15)
        time.sleep(1)
        self.check('majority survives voter leader loss',self.call('Member','status')['ok'])
        second=next(i for i in range(1,4) if i!=number)
        self.run('podman','stop','--time','3',self.prefix+f'Voter{second}',timeout=15)
        self.check('quorum loss denies fresh reads',self.call('Member','status',good=False).returncode!=0)
        self.check('quorum loss denies membership changes',self.call('Administrator','revoke','--device-key',self.member,good=False).returncode!=0)
        self.run('podman','start',stopped,self.prefix+f'Voter{second}',timeout=30)
        for _ in range(20):
            if self.call('Member','status',good=False).returncode==0:break
            time.sleep(0.2)
        self.check('quorum recovery restores unchanged membership',self.call('Member','status')['ok'])
        self.call('Administrator','revoke','--device-key',self.member)
        self.check('revocation stops access',self.call('Member','status',good=False).returncode!=0)
        self.check('revocation stops hosting',self.call('Member','heartbeat','--profile',self.profile,good=False).returncode!=0)
        self.check('invitation replay cannot restore revoked key',self.call('Member','redeem','--invitation',invitation,good=False).returncode!=0)
        self.run('bash',self.authority_tool,'Restart',self.authority_profile,timeout=45)
        time.sleep(1)
        self.check('revocation survives restart',self.call('Member','status',good=False).returncode!=0)
        self.check('last administrator cannot be revoked',self.call('Administrator','revoke','--device-key',self.admin,good=False).returncode!=0)
        self.restore_previous_snapshot()

    def exercise_recovery(self):
        expiry=str(int(time.time())+3600)
        invitation=self.root/'Invitation.json'
        self.call('Administrator','invite','--device-key',self.member,'--grants','3','--expires',expiry,'--output',invitation)
        self.call('Member','redeem','--invitation',invitation)
        self.snapshot=self.root/'PreviousAuthority.db'
        self.authctl('snapshot','save',self.snapshot,endpoints='https://127.0.0.1:23791')
        self.snapshot.chmod(0o600)
        self.call('Administrator','revoke','--device-key',self.member)
        self.check('revocation committed after retained snapshot',self.call('Member','status',good=False).returncode!=0)
        self.restore_previous_snapshot()

    def restore_previous_snapshot(self):
        self.run('podman','stop','--time','3',self.broker,timeout=15)
        for i in range(1,4):
            self.run('podman','stop','--time','3',self.prefix+f'Voter{i}',timeout=15)
        cluster=','.join(f'Voter{i}=https://{self.subnet}.{10+i}:2380' for i in range(1,4))
        for i in range(1,4):
            state=self.root/f'Voter{i}'/'State'
            self.run('podman','unshare','rm','-rf',state)
            self.run('podman','unshare',self.etcd/'etcdutl','snapshot','restore',self.snapshot,'--data-dir='+str(state),
                     '--name='+f'Voter{i}','--initial-cluster='+cluster,
                     '--initial-advertise-peer-urls='+f'https://{self.subnet}.{10+i}:2380',
                     '--initial-cluster-token='+self.prefix+'Restored')
            self.run('podman','unshare','chmod','0700',state)
            self.run('podman','unshare','chown','-R','1:1',state)
        self.run('podman','start',*[self.prefix+f'Voter{i}' for i in range(1,4)],timeout=30)
        for _ in range(20):
            if self.authctl('endpoint','health',good=False).returncode==0:break
            time.sleep(0.2)
        self.run('podman','start',self.broker,timeout=30)
        time.sleep(1)
        self.check('stale full-cluster restore cannot resurrect membership',self.call('Member','status',good=False).returncode!=0)
        inspect=json.loads(self.run('podman','inspect',self.broker).stdout)[0]
        self.check('broker refuses changed authority cluster identity',inspect['State']['Status']=='exited' and inspect['State']['ExitCode']!=0)

    def cleanup(self):
        if self.host_profile and (self.host_profile/'Control.json').exists():
            control=json.loads((self.host_profile/'Control.json').read_text())
            for name in [control['name'],control['name']+'Gate']:
                self.run('podman','rm','-f',name,good=False,timeout=30)
            self.run('podman','network','rm',control['network'],good=False)
        for container in reversed(self.containers):
            self.run('podman','rm','-f',container,good=False,timeout=30)
        if self.network_created:
            self.run('podman','network','rm',self.prefix,good=False)
        self.run('podman','unshare','chown','-R','0:0',self.root,good=False)
        shutil.rmtree(self.root)

    def execute(self):
        error=None
        try:
            self.provision()
            if self.args.recovery_only:
                self.exercise_recovery()
            elif self.args.lifecycle_only:
                self.exercise_lifecycle()
            else:
                self.exercise()
        except Exception as caught:
            error=str(caught)
            raise
        finally:
            self.cleanup()
            Path(self.args.output).write_text(json.dumps({'passed':self.results,'error':error,
                'nodeSha256':hashlib.sha256(Path(self.node).read_bytes()).hexdigest(),
                'suiteSha256':hashlib.sha256(Path(self.suite).read_bytes()).hexdigest(),
                'sourceSha256':{name:hashlib.sha256((self.host_tool.parents[1]/name).read_bytes()).hexdigest()
                    for name in ['Tools/Host.sh','Tools/Authority.sh','Tools/Lifecycle.sh',
                                 'Tests/Lifecycle.py','Tests/TrustWorkflow.py']}},indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ['suite','node','image','etcd-directory','seccomp','output']:
        parser.add_argument('--'+field,required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--recovery-only',action='store_true',help='Run only snapshot rollback protection after provisioning')
    mode.add_argument('--lifecycle-only',action='store_true',help='Run only concurrent host withdrawal and authority lifecycle after provisioning')
    Workflow(parser.parse_args()).execute()

if __name__=='__main__':
    main()
