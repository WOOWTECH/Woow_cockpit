"""Test doubles for the HA import's container steps: a psql emulator that sends SQL to "PostgreSQL" the way psql does
(so a statement PostgreSQL refuses inside a transaction block fails here too: review C-19), and a throwaway-objects
double whose `exec` answers psql through it. Team E2.

pg-stdin-fix 2026-11-24: the emulator also runs psql's own backslash commands (`\\echo` prints its words; a backslash
command never reaches the server) and a transaction block the input opens itself (`BEGIN;` ... `COMMIT;`: an input
that ends inside the block is rolled back, as PostgreSQL does when psql disconnects), and the throwaway-objects double
keeps the files Cluster.write_file writes and answers its read-back (ha_odoo.READBACK)."""
import hashlib
import json
import re

from woowbackup import ha_odoo
from woowbackup.podman import CommandError, Result

NO_TRANSACTION = ('ALTER SYSTEM', 'VACUUM', 'CREATE DATABASE', 'DROP DATABASE', 'REINDEX DATABASE',
                  'CREATE TABLESPACE', 'ALTER DATABASE SET TABLESPACE')
BEGIN = ('BEGIN', 'BEGIN TRANSACTION', 'BEGIN WORK', 'START TRANSACTION')
COMMIT = ('COMMIT', 'COMMIT TRANSACTION', 'COMMIT WORK', 'END', 'END TRANSACTION')
ROLLBACK = ('ROLLBACK', 'ROLLBACK TRANSACTION', 'ROLLBACK WORK', 'ABORT')
WRITE_RE = re.compile(r'umask 077 && cat > (/tmp/woowbk-[a-z0-9.-]{1,40})\Z')


def split_script(text):
    """psql's view of an input, in input order: ('sql', statement) for every statement it sends to the server (split
    on `;` outside quotes, double quotes and dollar quotes; what is left at the end of the input is sent too, as psql
    does at EOF) and ('meta', line) for every backslash command (from an unquoted backslash to the end of its line: psql
    runs it itself as soon as it reads it, and it never reaches the server)."""
    items, current, i, quote, dollar = [], [], 0, None, None
    while i < len(text):
        char = text[i]
        if dollar:
            if text.startswith(dollar, i):
                current.append(dollar)
                i += len(dollar)
                dollar = None
                continue
        elif quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == '$':
            match = re.match(r'\$[A-Za-z_]*\$', text[i:])
            if match:
                dollar = match.group(0)
                current.append(dollar)
                i += len(dollar)
                continue
        elif char == '\\':
            end = text.find('\n', i)
            end = len(text) if end < 0 else end
            items.append(('meta', text[i:end].strip()))
            i = end
            continue
        elif char == ';':
            statement = ''.join(current).strip()
            if statement:
                items.append(('sql', statement))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    statement = ''.join(current).strip()
    if statement:
        items.append(('sql', statement))
    return items


def split_sql(text):
    """Statements of an SQL text that psql sends to the server (split_script without the backslash commands)."""
    return [item for kind, item in split_script(text) if kind == 'sql']


def echoed(data):
    """What psql prints for the `\\echo` commands of an input (bytes) that runs without an error."""
    lines = [' '.join(item.split()[1:]) for kind, item in split_script((data or b'').decode('utf-8'))
             if kind == 'meta' and item.split()[0] == '\\echo']
    return ''.join(line + '\n' for line in lines).encode('utf-8')


def readback_path(command):
    """The file a Cluster.write_file read-back command (ha_odoo.READBACK) reads, else None."""
    match = re.match(r'wc -c < (/tmp/woowbk-[a-z0-9.-]{1,40}) ', command)
    return match.group(1) if match and command == ha_odoo.READBACK.format(path=match.group(1)) else None


def readback_answer(data):
    """What ha_odoo.READBACK prints for a file holding `data` (an image with sha256sum), or the shell's failure when
    the file does not exist (`data` None)."""
    if data is None:
        return Result(1, b'', b"sh: can't open file")
    return Result(0, f'{len(data)}\nsha256\n{hashlib.sha256(data).hexdigest()}  -\n'.encode('ascii'), b'')


class ContainerFiles:
    """The files Cluster.write_file writes into throwaway containers, for doubles that answer `podman exec`
    themselves: `read_back(key, argv)` answers a read-back command (else None); `wrote(key, argv, data, result)`
    keeps what a write received when it succeeded and returns `result`. `files`: (key, path) -> bytes."""

    def __init__(self):
        self.files = {}

    def read_back(self, key, argv):
        path = readback_path(argv[2]) if list(argv[:2]) == ['sh', '-c'] else None
        return None if path is None else readback_answer(self.files.get((key, path)))

    def wrote(self, key, argv, data, result):
        match = WRITE_RE.fullmatch(argv[2]) if list(argv[:2]) == ['sh', '-c'] else None
        if match and result.returncode == 0:
            self.files[(key, match.group(1))] = bytes(data or b'')
        return result


def container_reply(files, role, argv, data):
    """For Mock-based doubles of TempObjects.exec: what a throwaway container answers to Cluster.write_file's write
    (kept in `files`, a ContainerFiles) and read-back, and to a psql script on stdin (its `\\echo` lines, as psql
    prints them when the script runs without an error); None for any other command."""
    answer = files.read_back(role, argv)
    if answer is not None:
        return answer
    if list(argv[:2]) == ['sh', '-c'] and WRITE_RE.fullmatch(argv[2]):
        return files.wrote(role, argv, data, Result(0, b'', b''))
    if list(argv[:1]) == ['psql'] and list(argv[-2:]) == ['-f', '-']:
        return Result(0, echoed(data), b'')
    return None


class Psql:
    """psql's transaction shapes: `-1` wraps the whole input in one transaction, `-c` with several statements is one
    implicit transaction, `-f -` without `-1` sends each statement on its own unless the input opens a transaction
    block itself (BEGIN ... COMMIT; an input that ends inside it is rolled back). `answer(sql, database)` gives the
    JSON value of a `-A -t` query. `executed`: (database, statement, in_transaction) of what was committed."""

    def __init__(self, answer=None):
        self.answer = answer or (lambda _sql, _db: None)
        self.executed = []
        self.auto_conf = {}   # ALTER SYSTEM results: name -> value text

    def __call__(self, argv, input=None):
        argv = list(argv)
        database = argv[argv.index('-d') + 1] if '-d' in argv else 'postgres'
        single = '-1' in argv or '--single-transaction' in argv
        if '-c' in argv:
            items = [('sql', s) for s in split_sql(argv[argv.index('-c') + 1])]
            implicit = single or len(items) > 1
        else:
            items = split_script((input or b'').decode('utf-8'))
            implicit = single
        output, printed, block = None, [], None
        for kind, statement in items:
            if kind == 'meta':
                if statement.split()[0] == '\\echo':
                    printed.append(' '.join(statement.split()[1:]))
                continue
            upper = ' '.join(statement.upper().split())
            if upper in BEGIN and not implicit:
                block = [] if block is None else block   # a 2nd BEGIN: PostgreSQL only warns
                continue
            if upper in COMMIT + ROLLBACK and not implicit:
                if block is not None and upper in COMMIT:
                    self.executed.extend(block)
                block = None
                continue
            in_tx = implicit or block is not None
            if in_tx and upper.startswith(NO_TRANSACTION):
                raise CommandError(f'psql 執行失敗（{upper.split()[0]} cannot run inside a transaction block）。',
                                   returncode=3, stderr=b'ERROR: cannot run inside a transaction block')
            (self.executed if block is None else block).append((database, statement, in_tx))
            match = re.match(r'ALTER SYSTEM SET ([a-z_][a-z0-9_.]*) TO (.+)\Z', statement, re.S | re.I)
            if match:
                self.auto_conf[match.group(1).lower()] = match.group(2)
            if '-c' in argv:
                output = self.answer(statement, database)
        if '-c' in argv:
            return Result(0, b'' if output is None else json.dumps(output).encode('utf-8'), b'')
        # an input that ends inside its own transaction block: nothing of the block is kept (psql still exits 0)
        return Result(0, ''.join(line + '\n' for line in printed).encode('utf-8'), b'')


class FakeTmp:
    """TempObjects for Cluster-level code: `exec(role, argv)` answers psql through `psql`, Cluster.write_file's
    write and read-back through `files` (a ContainerFiles; key: the role) and other commands through
    `handlers[program](role, argv, input, stdout)` (a handler for `sh` also sees the writes); every call is in
    `calls`."""

    def __init__(self, psql=None, handlers=None):
        self.psql = psql or Psql()
        self.handlers = dict(handlers or {})
        self.calls = []
        self.containers = []
        self.files = ContainerFiles()

    def name(self, role):
        return f'woowbk-j20261118T120000Z-0123abcd-{role}'

    def exec(self, role, argv, *, user=None, env=None, input=None, stdout=None, timeout=600, max_output=None,
             check=True, workdir=None):
        data = input.read() if hasattr(input, 'read') else input
        self.calls.append((role, list(argv), data))
        if argv[0] == 'psql':
            return self.psql(argv, data)
        answer = self.files.read_back(role, argv)
        if answer is not None:
            return answer
        handler = self.handlers.get(argv[0])
        result = Result(0, b'', b'') if handler is None else handler(role, list(argv), data, stdout)
        return self.files.wrote(role, argv, data, result)

    def running(self, role):
        return True
