#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the installed native runtime using its documented setup and commands."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import select
import socket
import stat
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--etcd-directory', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--port', type=int, default=32543)
    parser.add_argument('--voter-port-base', type=int, default=32551)
    parser.add_argument('--subnet', default='10.89.132.0')
    parser.add_argument('--selection', choices=['All', 'Lifecycle', 'Recovery'], default='All')
    args = parser.parse_args()
    os.umask(0o077)
    node = str(Path(args.node).resolve())
    report = {'binarySha256': hashlib.sha256(Path(node).read_bytes()).hexdigest(), 'image': args.image,
              'passed': False, 'checks': [], 'error': None, 'selection': args.selection}
    supervisor = None
    parent = Path(tempfile.mkdtemp(prefix='HyperNetRuntime'))
    root = parent / 'Instance'
    roots = []
    fixture_ids = []

    def command(action, *extra, good=True):
        result = subprocess.run([node, 'runtime', action, '--directory', str(root), *map(str, extra)],
                                capture_output=True, text=True, timeout=180)
        if good and result.returncode:
            raise RuntimeError(action + ': ' + result.stderr[-3000:])
        return json.loads(result.stdout) if good else result

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        report['checks'].append(name)
        print('PASS', name, flush=True)

    def mutation(action, operation=None, generation=None, digest=None, good=True):
        state = command('status')
        return command(action, '--operation-id', operation or os.urandom(16).hex(),
                       '--expected-generation', generation if generation is not None else state['generation'],
                       '--profile-digest', digest or state['profileDigest'], good=good)

    def serve():
        process = subprocess.Popen([node, 'runtime', 'serve', '--directory', str(root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        readable, _, _ = select.select([process.stdout], [], [], 10)
        if not readable:
            process.terminate()
            process.communicate(timeout=30)
            raise RuntimeError('Supervisor readiness record did not arrive')
        line = process.stdout.readline()
        if not line or json.loads(line).get('status') != 'ManagementReady':
            if process.poll() is None:
                process.terminate()
            raise RuntimeError('Supervisor failed: ' + process.communicate(timeout=30)[1])
        return process

    def setup(lifetime, port, subnet_offset=0):
        subnet = args.subnet.split('.')
        subnet[2] = str(int(subnet[2]) + subnet_offset)
        return command('setup', '--image', args.image,
                          '--etcd', Path(args.etcd_directory).resolve() / 'etcd',
                          '--etcdctl', Path(args.etcd_directory).resolve() / 'etcdctl',
                          '--bind', '127.0.0.1', '--port', port,
                          '--voter-port-base', args.voter_port_base, '--subnet', '.'.join(subnet),
                          '--lifetime-seconds', lifetime, '--session-policy', 'Session')

    def recovery():
        nonlocal root, supervisor
        root = parent / 'Recovery'
        roots.append(root)
        setup(600, args.port + 2, 4)
        mutation('consent')
        # Reproduce an interrupted inert staging directory, using no fabricated credentials.
        profile_digest = hashlib.sha256((root / 'Profile.json').read_bytes()).hexdigest()
        (root / 'Preparation.json').write_text(json.dumps({'configuration': profile_digest, 'device': None, 'inode': None}))
        (root / 'LaunchPending').mkdir(mode=0o700)
        supervisor = serve()

        def interrupt_at(predicate, label):
            nonlocal supervisor
            before = command('status')
            operation = os.urandom(16).hex()
            starter = subprocess.Popen([node, 'runtime', 'start', '--directory', str(root),
                                        '--operation-id', operation,
                                        '--expected-generation', str(before['generation']),
                                        '--profile-digest', before['profileDigest']],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 160
            while True:
                state = json.loads((root / 'State.json').read_text())
                if predicate(state):
                    supervisor.kill()
                    supervisor.communicate(timeout=10)
                    supervisor = None
                    starter.communicate(timeout=20)
                    check(label, starter.returncode != 0)
                    return operation, before
                if starter.poll() is not None:
                    raise RuntimeError('Activation ended before interruption: ' + starter.communicate()[1][-3000:])
                if time.monotonic() >= deadline:
                    raise RuntimeError('Activation did not reach interruption boundary')
                time.sleep(0.002)

        operation, before = interrupt_at(lambda state: state['bootstrapStage'] == 'RootReady',
                                         'manager interruption retains committed root authentication state')
        check('partial Launch staging finishes before voter activation', (root / 'Launch').is_dir() and not (root / 'LaunchPending').exists())
        interrupted_generation = command('status')['generation']
        supervisor = serve()
        retry = command('start', '--operation-id', operation, '--expected-generation', before['generation'],
                        '--profile-digest', before['profileDigest'], good=False)
        check('interrupted request retry returns its durable failure without repeating effects', retry.returncode != 0 and json.loads(retry.stdout)['failureCode'] == 'InterruptedOperation' and command('status')['generation'] == interrupted_generation)
        check('interrupted operation ID cannot be reused for changed input', mutation('stop', operation=operation, good=False).returncode != 0)
        mutation('stop')
        interrupt_at(lambda state: state['bootstrapDone'] and state['registrationStage'] == 'Pending',
                     'retained authentication resumes through committed namespace initialization')
        # The committed namespace/floor exists; model a lost final local completion write.
        state = json.loads((root / 'State.json').read_text())
        state['bootstrapDone'] = False
        state['bootstrapStage'] = 'NamespaceCommitted'
        (root / 'State.json').write_text(json.dumps(state))
        mutation('stop')
        supervisor = serve()
        interrupt_at(lambda state: state['registrationStage'] == 'Redeemed',
                     'committed namespace and floor resume before enrolment completes')
        mutation('stop')
        supervisor = serve()
        mutation('start')
        check('interrupted invitation redemption resumes the same host identity', command('status')['ready'] is True)
        mutation('stop')
        state = json.loads((root / 'State.json').read_text())
        state['hostRegistered'] = False
        state['registrationStage'] = 'Redeemed'
        (root / 'State.json').write_text(json.dumps(state))
        paths = [str(root / 'Launch' / ('Voter' + str(number)) / 'State') for number in range(1, 4)]
        before_inodes = subprocess.run(['/usr/bin/podman', 'unshare', '/usr/bin/stat', '-c', '%d:%i', *paths], capture_output=True, text=True, timeout=10, check=True).stdout
        # Preserve the completed tree inode while reproducing loss of its final rename.
        (root / 'Launch').rename(root / 'LaunchPending')
        mutation('start')
        after_inodes = subprocess.run(['/usr/bin/podman', 'unshare', '/usr/bin/stat', '-c', '%d:%i', *paths], capture_output=True, text=True, timeout=10, check=True).stdout
        check('completed preparation publication resumes without deleting voter state', before_inodes == after_inodes and command('status')['ready'] is True)
        check('committed consent resumes after loss of its completion flag', json.loads((root / 'State.json').read_text())['hostRegistered'] is True)
        state = json.loads((root / 'State.json').read_text())
        host = next(resource['id'] for resource in state['resources'] if resource['kind'] == 'container' and resource['name'].endswith('Host'))
        extra_name = parent.name + 'UnexpectedRoute'
        subprocess.run(['/usr/bin/podman', 'network', 'create', '--internal', '--disable-dns', extra_name], capture_output=True, timeout=30, check=True)
        extra = json.loads(subprocess.run(['/usr/bin/podman', 'network', 'inspect', extra_name], capture_output=True, text=True, timeout=10, check=True).stdout)[0]['id']
        fixture_ids.append(extra)
        subprocess.run(['/usr/bin/podman', 'network', 'connect', extra, host], capture_output=True, timeout=15, check=True)
        check('an unconsented effective network attachment prevents readiness', command('status')['ready'] is False)
        observed = json.loads(subprocess.run(['/usr/bin/podman', 'inspect', host], capture_output=True, text=True, timeout=10, check=True).stdout)[0]
        check('topology refusal preserves the exact changed resource for repair', observed['Id'] == host and extra_name in observed['NetworkSettings']['Networks'])
        subprocess.run(['/usr/bin/podman', 'network', 'disconnect', extra, host], capture_output=True, timeout=15, check=True)
        mutation('stop')
        subprocess.run(['/usr/bin/podman', 'network', 'rm', extra], capture_output=True, timeout=10, check=True)
        fixture_ids.remove(extra)
        check('restoring the consented topology permits exact owned cleanup', command('status')['status'] == 'Stopped')
        mutation('withdraw')
        supervisor.terminate()
        supervisor.communicate(timeout=40)
        supervisor = None

    try:
        if args.selection in ['All', 'Lifecycle']:
            roots.append(root)
            initial = setup(600, args.port)
            check('setup is inert and awaits consent', initial['status'] == 'AwaitingConsent' and command('status')['resourceCount'] == 0)
            check('preview exposes trusted backend and unavailable reader routes', command('preview')['byzantineQualified'] is False)
            check('start requires foreground manager', mutation('start', good=False).returncode != 0)
            supervisor = serve()
            socket_stat = (root / 'Management.sock').stat()
            check('private socket is owner-only', stat.S_ISSOCK(socket_stat.st_mode) and stat.S_IMODE(socket_stat.st_mode) == 0o600 and socket_stat.st_uid == os.geteuid())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(str(root / 'Management.sock'))
                payload = json.dumps({'operation': 'Shell', 'operationId': None, 'expectedGeneration': None, 'profileDigest': None}).encode()
                connection.sendall(len(payload).to_bytes(4, 'big') + payload)
                size = int.from_bytes(connection.recv(4), 'big')
                response = b''
                while len(response) < size:
                    response += connection.recv(size - len(response))
            check('private dispatcher refuses unsupported operations', json.loads(response)['ok'] is False)
            duplicate_manager = subprocess.run([node, 'runtime', 'serve', '--directory', str(root)], capture_output=True, timeout=5)
            check('second manager fails without waiting for the active session', duplicate_manager.returncode != 0)
            missing = command('status')
            missing_id = os.urandom(16).hex()
            check('start without consent is refused', mutation('start', missing_id, missing['generation'], missing['profileDigest'], good=False).returncode != 0)
            failed_generation = command('status')['generation']
            check('failed request retry remains a failure without another generation', mutation('start', missing_id, missing['generation'], missing['profileDigest'], good=False).returncode != 0 and command('status')['generation'] == failed_generation)
            state = command('status')
            operation = os.urandom(16).hex()
            accepted = mutation('consent', operation, state['generation'], state['profileDigest'])
            repeated = mutation('consent', operation, state['generation'], state['profileDigest'])
            check('exact consent retry is idempotent', accepted == repeated)
            check('changed operation ID payload is refused', mutation('stop', operation, state['generation'], state['profileDigest'], good=False).returncode != 0)
            check('stale generation cannot start', mutation('start', generation=1, good=False).returncode != 0)
            profile = json.loads((root / 'Profile.json').read_text())
            collision_name = 'HyperNetRuntime' + profile['deployment'][:16] + 'Authority'
            subprocess.run(['/usr/bin/podman', 'network', 'create', '--internal', '--disable-dns', collision_name], capture_output=True, timeout=30, check=True)
            collision = json.loads(subprocess.run(['/usr/bin/podman', 'network', 'inspect', collision_name], capture_output=True, text=True, timeout=10, check=True).stdout)[0]['id']
            fixture_ids.append(collision)
            collision_result = mutation('start', good=False)
            preserved = json.loads(subprocess.run(['/usr/bin/podman', 'network', 'inspect', collision], capture_output=True, text=True, timeout=10, check=True).stdout)[0]
            check('name collision is refused and unrelated resource preserved', collision_result.returncode != 0 and preserved['id'] == collision and command('status')['resourceCount'] == 0)
            subprocess.run(['/usr/bin/podman', 'network', 'rm', collision], capture_output=True, timeout=10, check=True)
            fixture_ids.remove(collision)
            mutation('start')
            check('real confined authority and host become ready', command('status')['ready'] is True)
            check('diagnostics make no network probe', command('diagnose')['networkProbed'] is False)
            active = json.loads((root / 'State.json').read_text())
            voters = [resource['id'] for resource in active['resources'] if resource['kind'] == 'container' and 'Voter' in resource['name']]
            for identity in voters[:2]:
                subprocess.run(['/usr/bin/podman', 'stop', '--time=1', identity], capture_output=True, timeout=15, check=True)
            check('missing quorum cannot report readiness', command('status')['ready'] is False)
            mutation('stop')
            check('stop preserves bootstrap and hosting registration', command('status')['status'] == 'Stopped')
            stopped_generation = command('status')['generation']
            check('fresh redundant stop does not consume a receipt', mutation('stop', good=False).returncode != 0 and command('status')['generation'] == stopped_generation)
            mutation('start')
            check('retained-state restart becomes ready', command('status')['ready'] is True)
            supervisor.send_signal(signal.SIGHUP)
            supervisor.communicate(timeout=30)
            check('foreground session exit stops owned workloads', supervisor.returncode == 0 and command('status')['status'] == 'Stopped')
            supervisor = serve()
            mutation('start')
            supervisor.kill()
            supervisor.communicate(timeout=10)
            supervisor = None
            check('abrupt supervisor loss preserves diagnosable exact resources', command('status')['ready'] is True)
            mutation('stop')
            supervisor = serve()
            before_withdrawal = (root / 'State.json').read_bytes()
            before_start = command('status')
            starter = subprocess.Popen([node, 'runtime', 'start', '--directory', str(root),
                                        '--operation-id', os.urandom(16).hex(),
                                        '--expected-generation', str(before_start['generation']),
                                        '--profile-digest', before_start['profileDigest']],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 15
            while json.loads((root / 'State.json').read_text())['status'] != 'Starting':
                if starter.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Concurrent start did not reach its durable activation intent')
                time.sleep(0.01)
            withdrawn = command('withdraw', '--operation-id', os.urandom(16).hex(),
                                '--expected-generation', before_start['generation'],
                                '--profile-digest', before_start['profileDigest'])
            starter.communicate(timeout=180)
            check('local withdrawal veto wins a concurrent activation', withdrawn['status'] == 'Withdrawn' and command('status')['ready'] is False)
            check('offline local withdrawal stops resources and persists tombstone', command('status')['status'] == 'Withdrawn' and command('status')['withdrawalGeneration'] > 0)
            withdrawn_generation = command('status')['generation']
            check('fresh redundant withdrawal does not consume a receipt', mutation('withdraw', good=False).returncode != 0 and command('status')['generation'] == withdrawn_generation)
            floor = json.loads((root / 'Generation.json').read_text())
            (root / 'State.json').write_bytes(before_withdrawal)
            check('separate generation floor defeats a stale lifecycle journal', command('status')['generation'] >= floor)
            check('separate withdrawal floor defeats a stale lifecycle journal', command('status')['status'] == 'Withdrawn' and command('status')['ready'] is False)
            check('withdrawn runtime cannot restart', mutation('start', good=False).returncode != 0)
            supervisor.terminate()
            supervisor.communicate(timeout=40)
            supervisor = None
            root = parent / 'Expiry'
            roots.append(root)
            setup(120, args.port + 1, 2)
            mutation('consent')
            supervisor = serve()
            mutation('start')
            check('short consent deployment becomes ready', command('status')['ready'] is True)
            expiry = command('status')['expires']
            active = json.loads((root / 'State.json').read_text())
            identities = [resource['id'] for resource in active['resources'] if resource['kind'] == 'container']
            supervisor.kill()
            supervisor.communicate(timeout=10)
            supervisor = None
            print('WAIT consent expiry after abrupt supervisor loss', flush=True)
            while time.time() <= expiry + 2:
                time.sleep(min(0.5, max(0.01, expiry + 2 - time.time())))
            inspections = json.loads(subprocess.run(['/usr/bin/podman', 'container', 'inspect', *identities], capture_output=True, text=True, timeout=15, check=True).stdout)
            check('absolute consent expiry stops every workload after manager death', all(not item['State']['Running'] for item in inspections) and command('status')['ready'] is False)
        if args.selection in ['All', 'Recovery']:
            recovery()
        report['passed'] = True
    except (OSError, ValueError, AssertionError, RuntimeError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    finally:
        cleanup_errors = []
        if supervisor and supervisor.poll() is None:
            try:
                supervisor.terminate()
                supervisor.communicate(timeout=40)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append('Supervisor: ' + str(error))
        for root in roots:
            if not (root / 'State.json').exists():
                continue
            if not report['passed']:
                try:
                    recorded = json.loads((root / 'State.json').read_text())
                    for resource in recorded['resources']:
                        if resource['kind'] != 'container' or not resource.get('id'):
                            continue
                        result = subprocess.run(['/usr/bin/podman', 'inspect', resource['id']], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            observed = json.loads(result.stdout)[0]
                            fields = ['Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'MountLabel', 'ProcessLabel', 'State']
                            report.setdefault('failedResourceInspections', []).append({field: observed.get(field) for field in fields})
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    report.setdefault('diagnosticErrors', []).append(str(error))
            try:
                mutation('withdraw')
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                pass
            try:
                state = json.loads((root / 'State.json').read_text())
                for resource in reversed(state['resources']):
                    if not resource.get('id'):
                        cleanup_errors.append('Unresolved resource identity retained at ' + str(root))
                        continue
                    # Only immutable IDs recorded by production are eligible for fixture cleanup.
                    command_line = ['/usr/bin/podman', 'network', 'rm', resource['id']] if resource['kind'] == 'network' else ['/usr/bin/podman', 'rm', '--force', resource['id']]
                    result = subprocess.run(command_line, capture_output=True, text=True, timeout=30)
                    if result.returncode:
                        cleanup_errors.append('Exact resource ' + resource['id'] + ': ' + result.stderr[-1000:])
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        for identity in fixture_ids:
            try:
                result = subprocess.run(['/usr/bin/podman', 'network', 'rm', identity], capture_output=True, text=True, timeout=30)
                if result.returncode:
                    cleanup_errors.append(result.stderr[-1000:])
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        if not cleanup_errors:
            try:
                result = subprocess.run(['/usr/bin/podman', 'unshare', '/usr/bin/rm', '-rf', str(parent)], capture_output=True, text=True, timeout=30)
                if result.returncode:
                    cleanup_errors.append(result.stderr[-1000:])
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            report['passed'] = False
            report['cleanupErrors'] = cleanup_errors
        Path(args.output).write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
