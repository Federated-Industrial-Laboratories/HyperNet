#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Qualify one installed appointed-voter lifecycle with supplied isolated inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('node', 'image', 'bootstrap', 'bootstrap-digest', 'voter-key',
                 'replica-config', 'bind', 'port', 'subnet', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--peer-certificate', nargs=4, required=True)
    parser.add_argument('--memory-bytes', type=int, default=536870912)
    parser.add_argument('--pids', type=int, default=64)
    parser.add_argument('--cpu-quota', type=int, default=100000)
    parser.add_argument('--state-bytes', type=int, default=1073741824)
    parser.add_argument('--lifetime-seconds', type=int, default=600)
    parser.add_argument('--work-directory', required=True, help='Existing private persistent directory for qualification state')
    args = parser.parse_args()
    work = Path(args.work_directory).resolve(strict=True)
    info = work.stat()
    if not info.st_uid == os.geteuid() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Select an existing private persistent work directory owned by this user')
    os.umask(0o077)
    node = str(Path(args.node).resolve())
    parent = Path(tempfile.mkdtemp(prefix='HyperNetRuntime', dir=work))
    root = parent / 'Instance'
    report = {'binarySha256': hashlib.sha256(Path(node).read_bytes()).hexdigest(),
              'image': args.image, 'passed': False, 'checks': [], 'error': None,
              'quorumQualification': False, 'cleanupErrors': []}
    supervisor = None

    def invoke(command, extra=(), good=True):
        result = subprocess.run([node, 'runtime', command, '--directory', str(root),
                                 *map(str, extra)], capture_output=True, text=True,
                                timeout=180)
        if not good:
            return result
        if result.returncode:
            raise RuntimeError(command + ': ' + result.stderr[-2048:])
        return json.loads(result.stdout)

    def mutation(command, *, good=True, generation=None):
        state = invoke('status')
        values = ['--operation-id', os.urandom(16).hex(), '--expected-generation',
                  state['generation'] if generation is None else generation,
                  '--profile-digest', state['profileDigest']]
        if command == 'start':
            values += ['--minimum-signer-generation', state['minimumSignerGeneration']]
        return invoke(command, values, good)

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        report['checks'].append(name)
        print('PASS', name, flush=True)

    def serve():
        process = subprocess.Popen([node, 'runtime', 'serve', '--directory', str(root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        readable, _, _ = select.select([process.stdout], [], [], 10)
        if not readable:
            process.terminate()
            process.communicate(timeout=45)
            raise RuntimeError('Manager readiness record did not arrive')
        line = process.stdout.readline()
        if not line or json.loads(line).get('status') != 'ManagementReady':
            if process.poll() is None:
                process.terminate()
            raise RuntimeError('Manager refused: ' + process.communicate(timeout=45)[1][-1024:])
        return process

    def podman(*values):
        return subprocess.run(['/usr/bin/podman', *map(str, values)], capture_output=True,
                              text=True, timeout=45, check=True)

    try:
        setup = invoke('setup', ['--image', args.image, '--bootstrap', Path(args.bootstrap).resolve(),
                       '--bootstrap-digest', args.bootstrap_digest, '--voter-key', Path(args.voter_key).resolve(),
                       '--replica-config', Path(args.replica_config).resolve(), '--peer-certificate', *[Path(p).resolve() for p in args.peer_certificate], '--bind', args.bind,
                       '--port', args.port, '--subnet', args.subnet, '--memory-bytes', args.memory_bytes,
                       '--pids', args.pids, '--cpu-quota', args.cpu_quota,
                       '--state-bytes', args.state_bytes, '--lifetime-seconds', args.lifetime_seconds])
        check('setup is inert and imports one appointed signer',
              setup['status'] == 'AwaitingConsent' and not setup['networkServing']
              and invoke('status')['resourceCount'] == 0)
        preview = invoke('preview')
        check('preview names only the current authority role',
              preview['roles'] == ['Authority'] and preview['backend'] == 'BasicHotStuff')
        supervisor = serve()
        check('management socket is private', stat.S_IMODE((root / 'Management.sock').stat().st_mode) == 0o600)
        refused = mutation('start', good=False)
        check('activation without consent refuses before resource creation',
              refused.returncode != 0 and invoke('status')['resourceCount'] == 0)
        mutation('consent')
        mutation('start')
        live = invoke('status')
        check('live status reports the exact healthy signer without claiming quorum',
              live['running'] and live['clockReady'] and not live['ready']
              and live['quorum'] == 'NotProbed'
              and live['authority']['signer'] == setup['signer'])
        first = live['minimumSignerGeneration']
        mutation('stop')
        stopped = invoke('status')
        check('stop preserves the signer and retains its independent generation',
              not stopped['running'] and stopped['status'] == 'Stopped'
              and stopped['minimumSignerGeneration'] >= first)
        mutation('start')
        restarted = invoke('status')
        check('restart opens the retained signer at the retained floor',
              restarted['running'] and restarted['minimumSignerGeneration'] >= stopped['minimumSignerGeneration'])
        supervisor.send_signal(signal.SIGKILL)
        supervisor.communicate(timeout=10)
        supervisor = None
        check('abrupt manager loss does not pretend the voter stopped', invoke('status')['running'])
        mutation('withdraw', generation=1)
        withdrawn = invoke('status')
        check('offline restrictive withdrawal wins with an older observed generation',
              withdrawn['status'] == 'Withdrawn' and withdrawn['withdrawalGeneration'] == 1
              and not withdrawn['running'] and not withdrawn['consentValid'])
        report['lastSignerGeneration'] = withdrawn['minimumSignerGeneration']
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        if supervisor is not None and supervisor.poll() is None:
            supervisor.terminate()
            try:
                supervisor.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.communicate(timeout=10)
        if (root / 'State.json').exists():
            try:
                current = invoke('status')
                if current['withdrawalGeneration'] == 0:
                    mutation('withdraw')
                state = json.loads((root / 'State.json').read_text())
                profile = json.loads((root / 'Profile.json').read_text())
                manifest = profile['manifest']
                for resource in state['resources']:
                    if resource['kind'] != 'network' or resource['id'] is None:
                        raise RuntimeError('Unresolved resources retained for exact recovery')
                    value = json.loads(podman('network', 'inspect', resource['id']).stdout)[0]
                    if value['id'] != resource['id'] or value['name'] != resource['name'] or value['labels'].get('io.hypernet.deployment') != manifest['deployment']:
                        raise RuntimeError('Network identity changed; no removal attempted')
                    podman('network', 'rm', resource['id'])
                # Only the exact prepared private tree from this driver can be removed.
                launch = root / 'Launch'
                if launch.exists():
                    preparation = json.loads((root / 'Preparation.json').read_text())
                    metadata = launch.lstat()
                    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_dev != preparation['device'] or metadata.st_ino != preparation['inode']:
                        raise RuntimeError('Prepared identity changed; state retained')
                    podman('unshare', '/usr/bin/rm', '-rf', '--', launch)
                import shutil
                shutil.rmtree(parent)
            except Exception as error:
                report['cleanupErrors'].append(str(error))
                report['retainedDirectory'] = str(root)
        elif parent.exists():
            import shutil
            shutil.rmtree(parent)
        if report['cleanupErrors']:
            report['passed'] = False
        Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']), 'error': report['error']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
