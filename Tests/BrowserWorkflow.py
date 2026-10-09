#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise an installed browser against a fresh authenticated Pages authority.

Uses the maintained three-voter TLS fixture. Content, identities and PTYs are
synthetic; the fixture removes its own resources. No desktop session is changed.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import termios
import time
import unicodedata

from PagesWorkflow import PagesWorkflow


CSI = re.compile(r'\x1b\[([0-9;?]*)([A-Za-z~])')


def visible(data, columns=120, rows=30):
    """Read the fixture's fixed cursor/erase/style output without executing it."""
    text = data.decode('utf-8')
    cells = [[' '] * columns for _ in range(rows)]
    x = y = at = 0
    while at < len(text):
        if text[at] == '\x1b':
            match = CSI.match(text, at)
            assert match, 'unexpected browser terminal control'
            values, command = match.groups()
            if command in ('H', 'f'):
                point = [int(value or 1) for value in values.split(';')]
                y, x = point[0] - 1, point[1] - 1 if len(point) > 1 else 0
                assert 0 <= y < rows and 0 <= x < columns, 'cursor outside terminal'
            elif command == 'J' and values == '2':
                cells = [[' '] * columns for _ in range(rows)]
            elif command == 'K':
                start, end = (0, columns) if values == '2' else (0, x + 1) if values == '1' else (x, columns)
                cells[y][start:end] = [' '] * (end - start)
            at = match.end()
            continue
        char = text[at]
        if char == '\r':
            x = 0
        elif char == '\n':
            y += 1
        elif not unicodedata.combining(char):
            width = 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
            assert 0 <= y < rows and 0 <= x and x + width <= columns, 'paint outside terminal'
            cells[y][x] = char
            x += width
        at += 1
    return '\n'.join(''.join(row).rstrip() for row in cells)


class Terminal:
    def __init__(self, workflow, *arguments):
        self.master, self.slave = pty.openpty()
        self.columns, self.rows = 120, 30
        self.size()
        self.original = termios.tcgetattr(self.slave)
        self.transcript = b''
        self.last = b''
        self.closed = False
        self.process = subprocess.Popen([workflow.suite, '--config',
            str(workflow.root/'Reader'/'Profile.json'), *map(str, arguments)],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env=dict(os.environ, TERM='xterm-256color'), start_new_session=True)

    def size(self):
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ,
                    struct.pack('HHHH', self.rows, self.columns, 0, 0))

    def read(self, marker=None, timeout=15):
        data = b''
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if select.select([self.master], [], [], .08)[0]:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
                self.transcript += chunk
                assert len(self.transcript) <= 2 * 1024 * 1024, 'unbounded browser output'
            elif data and (marker is None or marker.decode('ascii') in visible(data, self.columns, self.rows)):
                break
        frame = visible(data, self.columns, self.rows)
        assert marker is None or marker.decode('ascii') in frame, 'missing browser state: ' + repr(marker) + '\n' + frame
        self.last = data
        return frame

    def key(self, value, marker=None):
        os.write(self.master, value)
        return self.read(marker)

    def address(self, value, marker=b'Page opened'):
        self.key(b'o', b'Address:')
        # Clear any prefilled current location, then paste as one bounded value.
        return self.key(b'\x15\x1b[200~' + value.encode('ascii') + b'\x1b[201~\r', marker)

    def resize(self, columns, rows):
        self.columns, self.rows = columns, rows
        self.size()
        self.process.send_signal(signal.SIGWINCH)
        return self.read(b'HyperNet Browser')

    def close(self, key=b'q', timeout=3):
        if self.closed:
            return
        try:
            if self.process.poll() is None:
                os.write(self.master, key)
                self.process.wait(timeout=timeout)
            self.read(timeout=.2)
            assert self.process.returncode == 0, 'browser exit failed'
            assert termios.tcgetattr(self.slave) == self.original, 'terminal attributes not restored'
            assert self.transcript.count(b'\x1b[?1049h') == 1, 'browser re-entered alternate screen'
            assert self.transcript.count(b'\x1b[?1049l') == 1, 'browser did not restore one terminal session'
            assert b'\x1b[?25h' in self.transcript, 'browser did not restore cursor'
        finally:
            self.closed = True
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            os.close(self.master)
            os.close(self.slave)


class BrowserWorkflow(PagesWorkflow):
    def uri(self, page, author=None, network=None, namespace='News'):
        return f'hypernet://{network or self.network}/{author or self.author}/{namespace}/{page}'

    def home(self, changed=False):
        return ('HyperNetPage/2\n# BrowserHome\n'
            ': Unicode 世界 cafe\u0301\n'
            '@ScrollBox {"id":"Guide","label":"Guide","rows":3}\n'
            + ''.join(f': GUIDE{index:02d}\n' for index in range(1, 10))
            + '@End\n'
            + f'=> {self.uri(self.target)} GoTarget\n'
            + (': Revised publication.\n' if changed else ': Original publication.\n'))

    def publish(self, page, source, version=0, namespace='News', writer='Author', approved=True):
        path = self.root / f'Draft{page}Version{version}.txt'
        path.write_text(source)
        self.cli(writer, 'pages', 'submit', '--file', path, '--namespace', namespace,
                 '--page-id', page, '--expected-version', str(version),
                 '--output', path.with_suffix('.json'))
        if approved:
            self.review(self.inspect(page))

    def exercise(self):
        self.author = self.client('Author')
        reader = self.client('Reader')
        self.admit('Author', self.author, 1)
        self.admit('Reader', reader, 1)
        for writer in ('AuthorTwo', 'AuthorThree'):
            key = self.client(writer)
            self.admit(writer, key, 1)
            if writer == 'AuthorThree':
                self.budget_author = key
        self.first, self.target = f'{1:032x}', f'{2:032x}'
        self.publish(self.first, self.home())
        self.publish(self.target, 'HyperNetPage/2\n# BrowserTarget\n: TARGETFIRST\n'
                     + ''.join(f': TARGET{index:02d}\n' for index in range(1, 28)))
        for index in range(3, 34):
            writer = 'Author' if index <= 16 else 'AuthorTwo' if index <= 32 else 'AuthorThree'
            self.publish(f'{index:032x}', f'HyperNetPage/2\n# Entry{index}\n: Published entry.\n', writer=writer)
        outside, pending = f'{34:032x}', f'{35:032x}'
        self.publish(outside, 'HyperNetPage/2\n# OutsideCatalogue\n: Other namespace.\n', namespace='Other', writer='AuthorThree')
        self.publish(pending, 'HyperNetPage/2\n# PendingCatalogue\n: Unapproved.\n',
                     writer='AuthorThree', approved=False)
        self.check('catalogue fixture spans the 32-entry boundary with distinct approved pages', True)

        first = self.cli('Reader', 'browse', '--namespace', 'News').stdout
        second = self.cli('Reader', 'browse', '--namespace', 'News', '--after', f'{32:032x}').stdout
        self.check('plain catalogue paginates authenticated identifiers without fetching titles',
            self.first in first and f'{32:032x}' in first and f'{33:032x}' not in first
            and f'{33:032x}' in second and self.first not in second
            and all(label not in first + second for label in ['BrowserHome', 'BrowserTarget', 'PendingCatalogue', 'OutsideCatalogue'])
            and outside not in first + second and pending not in first + second
            and '\x1b' not in first + second)
        plain = self.cli('Reader', 'browse', self.uri(self.first), '--ascii').stdout
        self.check('plain URI entry verifies full page content and ASCII fallback',
            'BrowserHome' in plain and 'GUIDE01' in plain and 'GUIDE09' in plain
            and '\\u{4e16}' in plain and '\x1b' not in plain)
        invalid = self.cli('Reader', 'browse', self.uri(self.first), '--after', self.first, good=False)
        self.check('CLI rejects ambiguous address and catalogue cursor combination', invalid.returncode != 0)

        terminal = Terminal(self, 'browse', '--namespace', 'News')
        try:
            frame = terminal.read(b'Catalogue loaded')
            assert 'Trusted catalogue' in frame and 'BrowserHome' not in frame
            terminal.key(b'n', b'Catalogue loaded')
            assert f'{33:032x}' in terminal.last.decode()
            terminal.key(b'p', b'Retained view restored')
            terminal.key(b'\r', b'Page opened')
            assert 'BrowserHome' in terminal.last.decode()
            self.check('keyboard catalogue paging and selected page open work in one terminal', True)
            terminal.key(b'\t', b'Guide')
            frame = terminal.key(b'\x1b[F', b'GUIDE09')
            assert 'GUIDE01' not in frame
            terminal.key(b'\t\r', b'Page opened')
            assert 'BrowserTarget' in terminal.last.decode()
            frame = terminal.key(b'b', b'Retained view restored')
            assert 'BrowserHome' in frame and 'GUIDE09' in frame and 'GUIDE01' not in frame
            self.check('Back restores the prior page scrollbox and selected control', True)
            frame = terminal.resize(40, 24)
            assert 'BrowserHome' in frame and 'GUIDE09' in frame
            terminal.resize(120, 30)
            self.check('narrow and wide resize preserve retained browser page state', True)
            frame = terminal.key(b'r', b'Page refreshed')
            assert 'GUIDE09' in frame and 'GUIDE01' not in frame
            self.check('unchanged publication refresh preserves view state', True)
            self.publish(self.first, self.home(changed=True), version=2)
            frame = terminal.key(b'r', b'Page refreshed')
            assert 'GUIDE01' in frame and 'Revised publication.' in frame
            self.check('changed publication refresh resets document view state', True)

            budget = f'{36:032x}'
            self.publish(budget, 'HyperNetPage/2\n# BrowserBudget\n: BUDGETCONTENT\n'
                         + '@Spacer {"rows":8}\n' * 250, writer='AuthorThree')
            plain = self.cli('Reader', 'browse', self.uri(budget, author=self.budget_author)).stdout
            assert 'BUDGETCONTENT' in plain and '\x1b' not in plain
            terminal.resize(300, 30)
            frame = terminal.address(self.uri(budget, author=self.budget_author), b'Could not open:')
            assert 'BrowserHome' in frame and 'Revised publication.' in frame
            self.check('layout budget refusal preserves the previous verified page and plain output', True)
            terminal.resize(40, 24)
            frame = terminal.address(self.uri(budget, author=self.budget_author))
            assert 'BrowserBudget' in frame and 'BUDGETCONTENT' in frame
            frame = terminal.resize(300, 30)
            assert 'Layout unavailable' in frame and terminal.process.poll() is None
            terminal.key(b'?', b'Trusted browser help')
            terminal.key(b'?', b'Layout unavailable')
            frame = terminal.resize(40, 24)
            assert 'BUDGETCONTENT' in frame
            terminal.resize(300, 30)
            terminal.address(self.uri(self.first))
            frame = terminal.key(b'b', b'Layout unavailable')
            assert 'Layout unavailable' in frame
            frame = terminal.key(b'b', b'Retained view restored')
            assert 'BrowserHome' in frame
            terminal.resize(120, 30)
            self.check('resize budget refusal keeps help address and Back available and shrinking recovers layout', True)

            terminal.address(self.uri(self.target, author='ff' * 32), b'Could not open:')
            assert 'BrowserHome' in terminal.last.decode()
            terminal.address(self.uri('ee' * 16), b'Could not open:')
            assert 'BrowserHome' in terminal.last.decode()
            terminal.address(self.uri(self.target, network='aa' * 32), b'Could not open:')
            assert 'BrowserHome' in terminal.last.decode()
            self.check('wrong author missing page and unconfigured network retain the verified page', True)
            terminal.address('https://example.invalid/', b'External reference (display only):')
            assert 'BrowserHome' in terminal.last.decode()
            self.check('external references remain inert without ending the browser', True)

            terminal.key(b'o', b'Address:')
            terminal.key(b'\x15\x1b[200~invalid\nq\x1b[201~', b'Address:')
            assert terminal.process.poll() is None
            terminal.key(b'\x1b[200~' + b'x' * 2048 + b'\x1b[201~', b'Address:')
            assert terminal.process.poll() is None
            terminal.key(b'\x1b', b'BrowserHome')
            self.check('invalid and oversized pasted addresses cannot activate shortcuts or leave input mode', True)
            terminal.address(self.uri(self.target))
            assert 'BrowserTarget' in terminal.last.decode()
            terminal.key(b'?', b'Trusted browser help')
            terminal.key(b'?', b'BrowserTarget')
            terminal.key(b'c', b'Catalogue loaded')
            assert 'Trusted catalogue' in terminal.last.decode()
            terminal.key(b'b', b'Retained view restored')
            assert 'BrowserTarget' in terminal.last.decode()
            self.check('address help catalogue and Back remain available after navigation errors', True)
            assert not select.select([terminal.master], [], [], .4)[0], 'idle browser repaints'
            self.check('idle browser performs no repaint or automatic refresh', True)

            self.call('Author', 'pages', 'withdraw', '--page-id', self.target, '--expected-version', '2')
            frame = terminal.key(b'r', b'Could not refresh:')
            assert 'BrowserTarget' in frame
            self.check('withdrawn-page refresh reports failure while retaining explicitly stale display', True)
        finally:
            terminal.close()
        self.check('normal browser exit restores one terminal session and cursor', True)

        legacy = Terminal(self, 'pages', 'read', '--page-id', self.first, '--tui')
        try:
            legacy.read(b'Page opened')
            legacy.address(self.uri('ee' * 16), b'Could not open:')
            assert 'BrowserHome' in legacy.last.decode()
            legacy.key(b'o', b'Address:')
            legacy.close(key=b'\x03')
        finally:
            legacy.close()
        self.check('existing Pages TUI entry shares recoverable navigation and Ctrl-C exits address editing', True)

        blocked = Terminal(self, 'browse', self.uri(self.first), '--namespace', 'News')
        try:
            blocked.read(b'Page opened')
            self.run('podman', 'stop', '--time', '1', self.prefix+'Voter1', self.prefix+'Voter2', timeout=15)
            blocked.key(b'r', b'Loading')
            started = time.monotonic()
            blocked.close(timeout=3)
            blocked = None
            self.check('quit remains responsive and restores terminal while a quorum request is pending',
                       time.monotonic() - started < 3)
        finally:
            if blocked is not None:
                blocked.close()

    def execute(self):
        try:
            super().execute()
        finally:
            path = Path(self.args.output)
            if path.exists():
                report = json.loads(path.read_text())
                report['imageId'] = self.args.image
                report['sourceSha256']['Tests/BrowserWorkflow.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                path.write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ['suite', 'node', 'image', 'etcd-directory', 'seccomp', 'output']:
        parser.add_argument('--' + field, required=True)
    args = parser.parse_args()
    args.recovery_only = args.lifecycle_only = False
    BrowserWorkflow(args).execute()


if __name__ == '__main__':
    main()
