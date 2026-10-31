#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Measure the native kernel and rootless container boundary with owned fixtures."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import uuid


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='Verified immutable local OCI image ID')
    parser.add_argument('--output', required=True, help='New private JSON report')
    parser.add_argument('--work-directory', required=True, help='Existing private persistent directory for qualification state')
    args = parser.parse_args()
    work = Path(args.work_directory).resolve(strict=True)
    info = work.stat()
    if not info.st_uid == os.geteuid() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Select an existing private persistent work directory owned by this user')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', args.image) or os.geteuid() == 0:
        parser.error('Use an immutable local image and a non-root operator')
    report = {'product': 'HyperNet', 'version': '0.10.0', 'imageId': args.image,
              'system': platform.system(), 'architecture': platform.machine(),
              'kernel': platform.release(), 'passed': False, 'profile': None, 'error': None}
    container = None
    try:
        network_helper = next((Path(directory) / 'slirp4netns' for directory in ('/usr/bin', '/bin')
                               if os.access(Path(directory) / 'slirp4netns', os.X_OK)), None)
        if network_helper is None:
            raise ValueError('Install slirp4netns in /usr/bin or /bin for rootless service networking')
        checked = subprocess.run([str(network_helper), '--version'], capture_output=True, timeout=5, check=True)
        if len(checked.stdout) + len(checked.stderr) > 16384:
            raise ValueError('Networking helper version exceeds its bound')
        report['slirp4netns'] = {'path': str(network_helper), 'version': checked.stdout.decode('utf-8', 'replace').strip()}
        with tempfile.TemporaryDirectory(prefix='HyperNetQualification', dir=work) as name:
            temporary = Path(name)
            info = subprocess.run(['podman', 'info', '--format', 'json'], capture_output=True, timeout=30, check=True)
            if len(info.stdout) > 256 * 1024:
                raise ValueError('Podman information exceeds its bound')
            value = json.loads(info.stdout)
            if not value['host']['security']['rootless'] or value['host']['cgroupVersion'] != 'v2':
                raise ValueError('Rootless Podman and cgroup v2 are required')
            report['podmanVersion'] = value['version']['Version']
            report['runtime'] = value['host']['ociRuntime']['name']
            report['cgroupControllers'] = value['host']['cgroupControllers']
            report['selinuxEnabled'] = value['host']['security'].get('selinuxEnabled', False)
            report['seccompEnabled'] = value['host']['security'].get('seccompEnabled', False)
            subprocess.run(['bash', str(Path(__file__).with_name('Seccomp.sh')), str(temporary / 'Seccomp.json')], check=True, capture_output=True, timeout=15)
            identity = temporary / 'ContainerId'
            arguments = ['podman', 'create', '--name', 'HyperNetQualification' + uuid.uuid4().hex,
                         '--cidfile', str(identity),
                         '--pull=never', '--read-only', '--read-only-tmpfs=false', '--userns=nomap',
                         '--user=0:0', '--cap-drop=all', '--security-opt=no-new-privileges',
                         '--security-opt=seccomp=' + str(temporary / 'Seccomp.json'),
                         '--ipc=private', '--pid=private', '--network=none', '--ulimit=core=0:0',
                         '--ulimit=nofile=128:128', '--memory=268435456', '--memory-swap=268435456',
                         '--pids-limit=32', '--cpu-period=100000', '--cpu-quota=100000',
                         '--log-driver=k8s-file', '--log-opt=max-size=1mb',
                         '--tmpfs=/State:rw,noexec,nosuid,nodev,size=8388608,mode=0700',
                         args.image, 'check-confinement', '--state', '/State']
            try:
                created = subprocess.run(arguments, capture_output=True, timeout=30, check=True)
            finally:
                if identity.exists():
                    candidate = identity.read_text().strip()
                    if re.fullmatch(r'[a-f0-9]{64}', candidate):
                        container = candidate
            candidate = created.stdout.decode('ascii').strip()
            if not re.fullmatch(r'[a-f0-9]{64}', candidate):
                raise ValueError('Invalid created-container identity')
            container = candidate
            checked = subprocess.run(['podman', 'start', '--attach', container], capture_output=True, timeout=45)
            if len(checked.stdout) + len(checked.stderr) > 256 * 1024:
                raise ValueError('Confinement response exceeds its bound')
            if checked.returncode:
                raise ValueError('Confinement failed: ' + checked.stderr.decode('utf-8', 'replace')[:4096])
            profile = json.loads(checked.stdout)
            if not (profile['landlockAbi'] >= 6 and profile['filesystemConfined'] and profile['tcpPortsConfined']
                    and profile['noNewPrivileges'] and profile['seccomp'] == 2
                    and profile['memoryMax'] == 268435456 and profile['pidsMax'] == 32
                    and profile['cpuMax'] == '100000 100000'):
                raise ValueError('Actual restrictions differ from the qualification profile')
            report['profile'] = profile
            report['passed'] = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    finally:
        if container:
            try:
                subprocess.run(['podman', 'rm', '--force', container], capture_output=True, timeout=30, check=True)
                report['ownedContainerRemoved'] = True
            except (OSError, subprocess.SubprocessError):
                report['passed'] = False
                report['error'] = 'Owned qualification container cleanup failed'
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
