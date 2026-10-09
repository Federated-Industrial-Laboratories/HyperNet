#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise installed Pages submission, review, scoped replication and withdrawal.

Uses the private three-voter TLS fixture from TrustWorkflow. Requires rootless
Podman, OpenSSL and Python cryptography. All fixtures are removed on exit.
"""
import argparse
import concurrent.futures
import hashlib
import fcntl
import os
import pty
import select
import struct
import termios
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from TrustWorkflow import Workflow


class PagesWorkflow(Workflow):
    def cli(self, name, *args, good=True, timeout=30):
        return self.run(self.suite, '--config', self.root/name/'Profile.json',
                        *args, good=good, timeout=timeout)

    def api(self, name, command, hosting=False):
        return self.request(self.signed(name, command), hosting=hosting)

    def admit(self, name, key, grants):
        path = self.root/(name+'Invitation.json')
        self.call('Administrator','invite','--device-key',key,'--grants',str(grants),
                  '--expires',str(int(time.time())+3600),'--output',path)
        self.call(name,'redeem','--invitation',path)

    def submit(self, page, text, version=0, namespace='News'):
        path = self.root/('Draft'+secrets.token_hex(4)+'.txt')
        path.write_text(text)
        result = self.cli('Author','pages','submit','--file',path,'--namespace',namespace,
                          '--page-id',page,'--expected-version',str(version),
                          '--output',path.with_suffix('.json'))
        return json.loads(result.stdout)['result']

    def inspect(self, page):
        path = self.root/('Review'+secrets.token_hex(4)+'.json')
        self.cli('Administrator','pages','inspect','--page-id',page,'--output',path)
        return path

    def review(self, path, decision='approve', good=True):
        return self.cli('Administrator','pages','review','--input',path,
                        '--decision',decision,good=good)

    def read(self, page, replica=False, good=True):
        args=['pages','read','--page-id',page]
        if replica: args += ['--replica',self.member]
        return self.cli('Reader',*args,good=good,timeout=40)

    def start_pages_host(self):
        self.source=self.root/'HostConfiguration'; self.source.mkdir(mode=0o700)
        expiry=int(time.time())+1800
        specification={'grants':2,'expires':expiry,'memoryBytes':268435456,'pids':64,
            'cpuQuota':100000,'cpuPeriod':100000,'stateBytes':16777216,
            'authorityEndpoint':'https://authority.example:8443','authorityAddress':self.broker_address+':8443',
            'services':['Pages'],'namespaces':['News'],'pageCacheBytes':65536,'pageMediaCacheBytes':0}
        self.write(self.source/'Specification.json',specification)
        consent=self.call('Member','host-consent','--spec',self.source/'Specification.json',
                          '--output',self.source/'Consent.json')
        self.profile=consent['profile']
        der=subprocess.check_output(['openssl','x509','-in',str(self.pki/'Host.pem'),'-outform','DER'])
        fingerprint=hashlib.sha256(der).hexdigest()
        self.call('Member','consent','--profile',self.profile,'--grants','2',
            '--expires',str(expiry),'--certificate',fingerprint,good=False)
        # A profile hash without its signed document is not valid hosting consent.
        self.check('profile hash alone cannot register hosting consent',not self.api('Member',
            {'type':'PageSync','profile':self.profile,'knownInventory':None,'fetch':None},hosting=True)['ok'])
        self.call('Member','consent','--profile',self.profile,'--grants','2','--expires',str(expiry),
                  '--certificate',fingerprint,'--document',self.source/'Consent.json')
        for origin,destination in [(self.root/'Member'/'Identity.json','Identity.json'),
            (self.pki/'NetworkCa.pem','Ca.pem'),(self.pki/'Host.pem','Client.pem'),(self.pki/'HostKey.pem','ClientKey.pem')]:
            shutil.copy2(origin,self.source/destination)
        self.write(self.source/'Host.json',{'network':self.network,'endpoint':specification['authorityEndpoint'],
            'caCertificate':'/Config/Ca.pem','identity':'/Config/Identity.json',
            'clientCertificate':'/Config/Client.pem','clientKey':'/Config/ClientKey.pem',
            'consentFile':'/Config/Consent.json','stateDirectory':'/State','relayAddress':'10.1.1.3:8443'})
        self.host_profile=self.root/'HostProfile'
        self.run('bash',self.host_tool,'Initialise',self.host_profile,self.source,self.args.image,self.prefix,timeout=60)
        self.run('bash',self.host_tool,'Start',self.host_profile,timeout=60)
        self.host_name=json.loads((self.host_profile/'Control.json').read_text())['name']
        self.wait_cache(1)

    def wait_cache(self, expected):
        for _ in range(60):
            output=self.run('podman','logs','--tail=1',self.host_name,good=False).stdout.strip()
            try: state=json.loads(output)
            except json.JSONDecodeError: state={}
            pages=state.get('pages',{})
            if pages.get('ready') and pages.get('objects')==expected:
                self.check('scoped host cache converges to '+str(expected)+' objects',pages['bytes']<=65536)
                return
            time.sleep(.25)
        raise AssertionError('Pages host cache did not converge: '+output[-1000:])

    def change_cache(self, delete=False):
        pid=self.run('podman','inspect','--format','{{.State.Pid}}',self.host_name).stdout.strip()
        script = """import ctypes,pathlib,sys
c=ctypes.CDLL(None)
c.setfsgid(1);c.setfsuid(1)
assert c.setfsgid(-1)==1 and c.setfsuid(-1)==1
paths=list(pathlib.Path('/proc/'+sys.argv[1]+'/root/State/Pages').glob('Page*.json'))
assert len(paths)==1
if sys.argv[2]=='delete': paths[0].unlink()
else: paths[0].write_bytes(b'Untrusted cache replacement\\n')
"""
        self.run('podman','unshare','python3','-c',script,pid,'delete' if delete else 'corrupt')
        self.check('operator fault injection '+('deletes' if delete else 'alters')+' the owned confined cache',True)

    def navigate(self, page):
        master,slave=pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,120,0,0))
        original=termios.tcgetattr(slave)
        process=subprocess.Popen([self.suite,'--config',str(self.root/'Reader'/'Profile.json'),
            'pages','read','--page-id',page,'--tui'],stdin=slave,stdout=slave,stderr=slave,
            env=dict(os.environ,TERM='xterm-256color'),start_new_session=True)
        def expect(marker, status):
            marker=b'HyperNet Browser | '+marker
            output=b''; end=time.monotonic()+12
            while (marker not in output or status not in output) and time.monotonic()<end:
                if select.select([master],[],[],.1)[0]:
                    try: output+=os.read(master,65536)
                    except OSError: break
            assert marker in output and status in output, 'authenticated terminal navigation did not reach expected page'
        try:
            expect(b'Outside',b'Page opened')
            os.write(master,b'\t\r'); expect(b'Welcome',b'Page opened')
            os.write(master,b'r'); expect(b'Welcome',b'Page refreshed')
            os.write(master,b'b'); expect(b'Outside',b'Retained view restored')
            os.write(master,b'q'); process.wait(timeout=5)
            self.check('authenticated TUI follows verifies refreshes and returns through internal links',
                       process.returncode==0 and termios.tcgetattr(slave)==original)
        finally:
            if process.poll() is None: process.kill(); process.wait()
            os.close(master); os.close(slave)

    def exercise(self):
        author=self.client('Author'); reader=self.client('Reader')
        self.admit('Author',author,1); self.admit('Reader',reader,1); self.admit('Member',self.member,3)
        page=secrets.token_hex(16)
        def component_page(message):
            return ('HyperNetPage/2\n# Welcome\n'
                '@Panel {"label":"News","colour":"Cyan"}\n'
                '@Row {"minChildColumns":24}\n'
                '@Column {"weight":2}\n'
                '@Text '+json.dumps({'value':message,'bold':True})+'\n'
                '@Progress {"label":"Published","value":1,"maximum":1}\n'
                '@End\n'
                '@ScrollBox {"id":"Details","label":"Details","rows":2}\n'
                ': First detail.\n: Second detail.\n: Complete offscreen detail.\n'
                '@End\n@End\n'
                '@Button {"label":"Read details","action":{"kind":"Focus","target":"Details"}}\n'
                '@End\n')
        original=component_page('Approved original.')
        first=self.submit(page,original)
        self.check('submission enters quarantine at version one',first['version']==1)
        self.check('quarantined page cannot be discovered',not self.call('Reader','pages','list')['result']['entries'])
        self.check('quarantined page cannot be read',self.read(page,good=False).returncode!=0)
        self.check('ordinary member cannot inspect another author draft',not self.api('Reader',{'type':'PageInspect','pageId':page})['ok'])
        bad={'type':'PageSubmit','pageId':secrets.token_hex(16),'expectedVersion':0,'namespace':'News',
             'audience':'Members','profile':'HyperNetPage/2','body':'HyperNetPage/2\n# Bad\n: \u001b]52;bad\u0007\n'}
        bad['digest']=hashlib.sha256(bad['body'].encode()).hexdigest()
        self.check('authority rejects terminal controls in signed markup',not self.api('Author',bad)['ok'])
        for label, profile, body in [
            ('retired page profile', 'HyperNetPage/1', 'HyperNetPage/1\n# Retired\n: Text.\n'),
            ('header and profile mismatch', 'HyperNetPage/2', 'HyperNetPage/1\n# Retired\n: Text.\n'),
            ('unimplemented form component', 'HyperNetPage/2', 'HyperNetPage/2\n# Form\n@Form {}\n')]:
            bad.update(pageId=secrets.token_hex(16), profile=profile, body=body,
                       digest=hashlib.sha256(body.encode()).hexdigest())
            self.check('authority rejects '+label, not self.api('Author',bad)['ok'])
        record=self.inspect(page)
        value=json.loads(record.read_text())
        pending=value['inspection']['pending']
        command={'type':'PageReview','pageId':page,'expectedVersion':1,'revision':1,
            'digest':pending['digest'],'profile':pending['profile'],'author':author,'namespace':'News',
            'audience':'Members','submissionDigest':pending['submissionDigest'],'decision':'Approve'}
        self.check('ordinary member cannot approve',not self.api('Reader',command)['ok'])
        changed=dict(command,digest='00'*32)
        self.check('approval cannot substitute a different source hash',not self.api('Administrator',changed)['ok'])
        self.review(record)
        rendered=self.read(page).stdout
        self.check('independent reader verifies approved component page',
            all(text in rendered for text in ['Approved original.','Published','Complete offscreen detail.','Read details']))
        self.check('old review record cannot approve twice',self.review(record,good=False).returncode!=0)
        replacement=component_page('Approved replacement.')
        self.submit(page,replacement,2)
        self.check('pending replacement leaves current publication readable','Approved original.' in self.read(page).stdout)
        stale=self.inspect(page)
        self.submit(page,replacement.replace('replacement','latest'),3)
        self.check('stale review cannot approve changed pending bytes',self.review(stale,good=False).returncode!=0)
        current=self.inspect(page)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            decisions=list(pool.map(lambda _:self.review(current,good=False),range(2)))
        self.check('concurrent review has exactly one committed decision',sum(r.returncode==0 for r in decisions)==1)
        self.check('new publication replaces previous bytes','Approved latest.' in self.read(page).stdout)
        other=secrets.token_hex(16)
        self.submit(other,f'HyperNetPage/2\n# Outside\n: Another namespace.\n=> hypernet://{self.network}/{author}/News/{page} Welcome page\n',namespace='Other')
        self.review(self.inspect(other))
        self.navigate(other)
        self.start_pages_host()
        self.check('hosting signature without transport certificate cannot sync',not self.api('Member',{'type':'PageSync','profile':self.profile,'knownInventory':None,'fetch':None})['ok'])
        self.check('hosting identity cannot bypass namespace via ordinary read',not self.api('Member',{'type':'PageRead','pageId':other})['ok'])
        sync=self.api('Member',{'type':'PageSync','profile':self.profile,'knownInventory':None,'fetch':None},hosting=True)
        self.check('replica inventory contains only consented namespace',[entry['pageId'] for entry in sync['result']['entries']]==[page])
        outside=self.api('Member',{'type':'PageSync','profile':self.profile,'knownInventory':None,'fetch':other},hosting=True)
        self.check('replica fetch cannot escape namespace',outside['ok'] and outside['result']['bundle'] is None)
        self.change_cache(delete=True)
        self.check('disappeared replica file is refetched without restart','Approved latest.' in self.read(page,replica=True).stdout)
        self.change_cache()
        result=self.read(page,replica=True)
        self.check('tampered cache is discarded and installed reader receives verified replica bytes','Approved latest.' in result.stdout and 'Content supplied by replica' in result.stdout)
        self.check('replica cannot serve an unconsented namespace',self.read(other,replica=True,good=False).returncode!=0)
        # Completed delivery tickets remain bounded records until their 15-second expiry.
        time.sleep(16)
        self.run('bash',self.host_tool,'Stop',self.host_profile,timeout=30)
        self.check('offline requested replica does not fall back to origin',self.read(page,replica=True,good=False).returncode!=0)
        self.run('bash',self.host_tool,'Start',self.host_profile,timeout=60)
        self.wait_cache(1)
        self.check('fresh volatile host cache recovers replica reads','Approved latest.' in self.read(page,replica=True).stdout)
        rejected=secrets.token_hex(16)
        self.submit(rejected,'HyperNetPage/2\n# Rejected\n: Never published.\n')
        self.review(self.inspect(rejected),'reject')
        self.check('rejected submission remains unreadable',self.read(rejected,good=False).returncode!=0)
        self.call('Author','pages','withdraw','--page-id',page,'--expected-version','5')
        self.check('withdrawn publication is unreadable',self.read(page,good=False).returncode!=0)
        self.wait_cache(0)
        self.check('withdrawal prevents new replica reads',self.read(page,replica=True,good=False).returncode!=0)
        self.call('Administrator','grant','--device-key',self.member,'--grants','1','--expires',str(int(time.time())+3600))
        self.check('removing host grant cannot turn retained consent into a reader',not self.api('Member',{'type':'PageRead','pageId':other})['ok'])
        self.check('consented service identity cannot be promoted to administrator',self.call('Administrator','grant','--device-key',self.member,'--grants','7','--expires',str(int(time.time())+3600),good=False).returncode!=0)
        self.call('Administrator','revoke','--device-key',author)
        self.check('author revocation removes its remaining publications',self.read(other,good=False).returncode!=0)
        self.run('podman','stop','--time','3',self.prefix+'Voter1',self.prefix+'Voter2',timeout=20)
        self.check('quorum loss denies Pages discovery',self.cli('Reader','pages','list',good=False).returncode!=0)

    def execute(self):
        try: super().execute()
        finally:
            path=Path(self.args.output)
            if path.exists():
                result=json.loads(path.read_text())
                result['sourceSha256']['Tests/PagesWorkflow.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                path.write_text(json.dumps(result,indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for field in ['suite','node','image','etcd-directory','seccomp','output']:
        parser.add_argument('--'+field,required=True)
    args=parser.parse_args(); args.recovery_only=False; args.lifecycle_only=False
    PagesWorkflow(args).execute()

if __name__=='__main__': main()
