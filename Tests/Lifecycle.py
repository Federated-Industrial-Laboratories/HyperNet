#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise concurrent launcher commands at a deterministic container-start barrier."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


PODMAN = r'''#!/usr/bin/env python3
import fcntl, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
directory = pathlib.Path(os.environ['HYPERNET_TEST_DIRECTORY'])
try:
    fcntl.fcntl(9, fcntl.F_GETFD)
except OSError:
    pass
else:
    raise RuntimeError('A lifecycle lock descriptor reached Podman')
if args and args[0] == 'run':
    name = args[args.index('--name') + 1]
    if name == os.environ.get('HYPERNET_TEST_PAUSE_CONTAINER'):
        (directory / 'Entered').touch()
        deadline = time.monotonic() + 30
        while not (directory / 'Release').exists():
            if time.monotonic() >= deadline:
                raise RuntimeError('Container creation barrier timed out')
            time.sleep(0.01)
real = os.environ.get('HYPERNET_TEST_REAL_PODMAN')
if real:
    os.execv(real, [real, *args])
containers = directory / 'Containers'
if args[:1] == ['info']:
    print('true')
elif args[:2] == ['container', 'exists']:
    sys.exit(0 if (containers / args[2]).exists() else 1)
elif args[:1] == ['run']:
    (containers / name).touch()
    print(name)
elif args[:1] in (['kill'], ['stop']):
    pass
elif args[:1] == ['rm']:
    (containers / args[-1]).unlink(missing_ok=True)
else:
    raise RuntimeError('Unexpected Podman operation in lifecycle regression')
'''

FLOCK = r'''#!/usr/bin/env python3
import os, pathlib, sys
directory = pathlib.Path(os.environ['HYPERNET_TEST_DIRECTORY'])
(directory / ('Waiting' + os.environ['HYPERNET_TEST_ROLE'])).touch()
real = os.environ['HYPERNET_TEST_REAL_FLOCK']
os.execv(real, [real, *sys.argv[1:]])
'''


class Barrier:
    def __init__(self, directory, pause_name, real=False):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        commands = self.directory / 'Commands'
        commands.mkdir(mode=0o700)
        (self.directory / 'Containers').mkdir(mode=0o700)
        for name, contents in [('podman', PODMAN), ('flock', FLOCK)]:
            path = commands / name
            path.write_text(contents)
            path.chmod(0o700)
        self.environment = dict(os.environ,
            PATH=str(commands) + os.pathsep + os.environ['PATH'],
            HYPERNET_TEST_DIRECTORY=str(self.directory),
            HYPERNET_TEST_PAUSE_CONTAINER=pause_name,
            HYPERNET_TEST_REAL_FLOCK=shutil.which('flock'))
        if real:
            self.environment['HYPERNET_TEST_REAL_PODMAN'] = shutil.which('podman')
        self.processes = []

    def launch(self, tool, action, profile, *arguments):
        environment = dict(self.environment, HYPERNET_TEST_ROLE=action)
        process = subprocess.Popen(['bash', str(tool), action, str(profile), *map(str, arguments)],
            env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        return process

    def wait(self, name, process):
        deadline = time.monotonic() + 30
        while not (self.directory / name).exists():
            if process.poll() is not None:
                output, error = process.communicate()
                raise AssertionError(f'Launcher exited before {name}: {output} {error}')
            if time.monotonic() >= deadline:
                raise AssertionError(f'Launcher did not reach {name}')
            time.sleep(0.01)

    def finish(self):
        (self.directory / 'Release').touch()
        for process in self.processes:
            if process.poll() is None:
                try:
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)


def overlap(tool, profile, pause_name, directory, start='Start', finish='Withdraw', real=False):
    """Pause container creation, queue termination, then complete both commands."""
    barrier = Barrier(directory, pause_name, real=real)
    try:
        starter = barrier.launch(tool, start, profile)
        barrier.wait('Entered', starter)
        terminator = barrier.launch(tool, finish, profile)
        barrier.wait('Waiting' + finish, terminator)
        if terminator.poll() is not None:
            raise AssertionError('Termination returned while creation was still paused')
        if finish == 'Withdraw' and (Path(profile) / 'Withdrawn').exists():
            raise AssertionError('Withdrawal changed the profile outside the lifecycle lock')
        (barrier.directory / 'Release').touch()
        for process in [starter, terminator]:
            output, error = process.communicate(timeout=45)
            if process.returncode:
                raise AssertionError(f'Concurrent lifecycle command failed: {output} {error}')
        return barrier.directory / 'Containers'
    finally:
        barrier.finish()


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='HyperNetLifecycle')
        self.root = Path(self.temporary.name)
        self.tools = Path(__file__).resolve().parents[1] / 'Tools'

    def tearDown(self):
        self.temporary.cleanup()

    def profile(self, name):
        profile = self.root / name
        profile.mkdir(mode=0o700)
        value = {'name':name,'image':'sha256:'+'0'*64,'network':'Network','egress':'Egress',
                 'state':str(self.root/'State'),'publication':'127.0.0.1:8443:8443',
                 'hostAddress':'192.0.2.2','gateAddress':'192.0.2.3',
                 'consent':{'expires':int(time.time())+3600,'memoryBytes':67108864,
                    'pids':16,'cpuQuota':1000,'stateBytes':1048576}}
        (profile / 'Control.json').write_text(json.dumps(value))
        return profile

    def host_race(self, action):
        profile = self.profile('Host')
        containers = overlap(self.tools/'Host.sh', profile, 'HostGate', self.root/'Barrier', start=action)
        self.assertTrue((profile/'Withdrawn').exists())
        self.assertEqual(list(containers.iterdir()), [])
        retry = Barrier(self.root/'Retry', '')
        try:
            process = retry.launch(self.tools/'Host.sh', 'Start', profile)
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(list((retry.directory/'Containers').iterdir()), [])
        finally:
            retry.finish()

    def test_start_cannot_resurrect_withdrawn_host(self):
        self.host_race('Start')

    def test_restart_cannot_resurrect_withdrawn_host(self):
        self.host_race('Restart')

    def test_authority_stop_orders_after_concurrent_start(self):
        profile = self.profile('Authority')
        containers = overlap(self.tools/'Authority.sh', profile, 'Authority', self.root/'Barrier', finish='Stop')
        self.assertEqual(list(containers.iterdir()), [])

    def test_initialisation_uses_a_persistent_lock_before_profile_exists(self):
        import fcntl
        for tool in ['Host.sh', 'Authority.sh']:
            profile = self.root / tool.removesuffix('.sh')
            lock_directory = Path(str(profile)+'Lifecycle')
            lock_directory.mkdir(mode=0o700)
            lock = lock_directory/'Lock'
            with lock.open('w') as handle:
                lock.chmod(0o600)
                inode = lock.stat().st_ino
                fcntl.flock(handle, fcntl.LOCK_EX)
                barrier = Barrier(self.root/(tool+'Barrier'), '')
                try:
                    process = barrier.launch(self.tools/tool, 'Initialise', profile)
                    barrier.wait('WaitingInitialise', process)
                    self.assertIsNone(process.poll())
                    self.assertFalse(profile.exists())
                    fcntl.flock(handle, fcntl.LOCK_UN)
                    process.communicate(timeout=5)
                    self.assertNotEqual(process.returncode, 0)
                    self.assertFalse(profile.exists())
                    self.assertEqual(lock.stat().st_ino, inode)
                finally:
                    barrier.finish()


if __name__ == '__main__':
    unittest.main()
