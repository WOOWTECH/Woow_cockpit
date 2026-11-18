"""Test doubles for the HA import's container steps: a psql emulator that sends SQL to "PostgreSQL" the way psql does
(so a statement PostgreSQL refuses inside a transaction block fails here too: review C-19), and a throwaway-objects
double whose `exec` answers psql through it. Team E2."""
import json
import re

from woowbackup.podman import CommandError, Result

NO_TRANSACTION = ('ALTER SYSTEM', 'VACUUM', 'CREATE DATABASE', 'DROP DATABASE', 'REINDEX DATABASE',
                  'CREATE TABLESPACE', 'ALTER DATABASE SET TABLESPACE')


def split_sql(text):
    """Statements of an SQL text (split on `;` outside quotes, double quotes and dollar quotes)."""
    statements, current, i, quote, dollar = [], [], 0, None, None
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
        elif char == ';':
            statement = ''.join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    statement = ''.join(current).strip()
    if statement:
        statements.append(statement)
    return statements


class Psql:
    """psql's transaction shapes: `-1` wraps the whole input in one transaction, `-c` with several statements is one
    implicit transaction, `-f -` without `-1` sends each statement on its own. `answer(sql, database)` gives the JSON
    value of a `-A -t` query. `executed`: (database, statement, in_transaction)."""

    def __init__(self, answer=None):
        self.answer = answer or (lambda _sql, _db: None)
        self.executed = []
        self.auto_conf = {}   # ALTER SYSTEM results: name -> value text

    def __call__(self, argv, input=None):
        argv = list(argv)
        database = argv[argv.index('-d') + 1] if '-d' in argv else 'postgres'
        single = '-1' in argv or '--single-transaction' in argv
        if '-c' in argv:
            statements = split_sql(argv[argv.index('-c') + 1])
            in_tx = single or len(statements) > 1
        else:
            statements = split_sql((input or b'').decode('utf-8'))
            in_tx = single
        output = None
        for statement in statements:
            upper = ' '.join(statement.upper().split())
            if in_tx and upper.startswith(NO_TRANSACTION):
                raise CommandError(f'psql 執行失敗（{upper.split()[0]} cannot run inside a transaction block）。',
                                   returncode=3, stderr=b'ERROR: cannot run inside a transaction block')
            self.executed.append((database, statement, in_tx))
            match = re.match(r'ALTER SYSTEM SET ([a-z_][a-z0-9_.]*) TO (.+)\Z', statement, re.S | re.I)
            if match:
                self.auto_conf[match.group(1).lower()] = match.group(2)
            if '-c' in argv:
                output = self.answer(statement, database)
        return Result(0, b'' if output is None else json.dumps(output).encode('utf-8'), b'')


class FakeTmp:
    """TempObjects for Cluster-level code: `exec(role, argv)` answers psql through `psql` and other commands through
    `handlers[program](role, argv, input, stdout)`; every call is in `calls`."""

    def __init__(self, psql=None, handlers=None):
        self.psql = psql or Psql()
        self.handlers = dict(handlers or {})
        self.calls = []
        self.containers = []

    def name(self, role):
        return f'woowbk-j20261118T120000Z-0123abcd-{role}'

    def exec(self, role, argv, *, user=None, env=None, input=None, stdout=None, timeout=600, max_output=None,
             check=True, workdir=None):
        data = input.read() if hasattr(input, 'read') else input
        self.calls.append((role, list(argv), data))
        if argv[0] == 'psql':
            return self.psql(argv, data)
        handler = self.handlers.get(argv[0])
        if handler is None:
            return Result(0, b'', b'')
        return handler(role, list(argv), data, stdout)

    def running(self, role):
        return True
