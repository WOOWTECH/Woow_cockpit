#!/usr/bin/env python3
"""REAL lab test of the pg-stdin fix (lane pg-stdin-fix, 2026-11-24): the engine's own ha_odoo.Cluster, through the
engine's own tempctr.TempObjects and podman.default_runner, against a real PostgreSQL 17.11 in the LAB store
(labpodman: its own storage root, production containers are invisible to it), every container `--network none`, no
secret anywhere (trust authentication inside the throwaway container). A transport hook shortens what ONE `podman exec`
sends on stdin, the way the final verification saw it happen under host load (21:53, Odoo ARM run).

Cases: write_file (control, every attempt cut, the first attempt cut, a middle chunk lost, the cksum branch for real);
script (control, tail lost at a statement boundary, inside the last statement, only the end mark lost) with the table
state checked; the OLD `psql -1` shape with the same cut (the defect itself, not engine code); statement (control, end
mark lost, cut inside the value); custom-format dump streams and COPY data cut short (the classification of the other
stdin execs); and the clean-up (no container or volume of this job left).

Prints ONE JSON report on stdout: status, cases {name: {status, ...booleans and counts}}. Never SQL text, table data,
file content or digests. Record it with:
  python3 tests/backup/record_attempt.py --name pg-stdin-real-20261124 -- tests/backup/pg_stdin_real.py
"""
import hashlib
import json
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backup-engine'))
from woowbackup import ha_odoo, podman, tempctr   # noqa: E402
from woowbackup.errors import BackupError        # noqa: E402

LABPODMAN = '/home/woowtechopenclaw/.woowbk-lab/bin/labpodman'
IMAGE = 'docker.io/library/postgres:17.11-alpine3.23'
JOB = 'j' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(4)
TOC_PATH = '/tmp/woowbk-pgfix.toc'
TOC = ''.join(f'{n}; 1259 {16000 + n} TABLE public t{n} odoo\n' for n in range(1, 8001)).encode()   # ~300 KiB
UPDATES = "UPDATE t SET a = 'y' WHERE id = 1;\nUPDATE t SET a = 'z' WHERE id = 2;\n"


class LabRunner:
    """podman.default_runner (the engine's executor) on the lab store's podman. `cut(args, data)` (the test hook) may
    shorten what one command sends on stdin; `seen` counts the commands it was asked about, per kind."""
    uid = None

    def __init__(self):
        self.cut = None
        self.seen = {}

    def podman(self, *args, input=None, stdout=None, timeout=300, check=True, max_output=None, abort=None):
        args = list(args)
        if self.cut is not None and input is not None:
            data = input.read() if hasattr(input, 'read') else bytes(input)
            kind = kind_of(args)
            if kind is not None:
                self.seen[kind] = self.seen.get(kind, 0) + 1
                data = self.cut(kind, self.seen[kind], data)
            input = data
        result = podman.default_runner([LABPODMAN, *args], input=input, stdout=stdout, timeout=timeout,
                                       max_output=max_output, abort=abort)
        if check and result.returncode != 0:
            raise podman.CommandError(f'podman {args[0]} 執行失敗（結束碼 {result.returncode}）。',
                                      returncode=result.returncode, stderr=result.stderr, command=f'podman {args[0]}')
        return result


def kind_of(args):
    if args[:1] != ['exec']:
        return None
    command = args[next(i for i, a in enumerate(args) if a.startswith('woowbk-j')) + 1:]
    if command[:2] == ['sh', '-c'] and command[2].startswith('umask 077 && cat > '):
        return 'write'
    if command[:1] == ['psql'] and command[-2:] == ['-f', '-']:
        return 'psql'
    if command[:1] == ['psql'] and '-c' in command:
        return 'psql-c'
    if command[:1] == ['pg_restore']:
        return 'pg_restore'
    return None


def main():
    runner, cases, report = LabRunner(), {}, {'job': JOB, 'image': IMAGE, 'network': 'none'}
    started = time.monotonic()
    notes = []

    def case(name, fn):
        runner.cut, runner.seen = None, {}
        try:
            result = fn()
            ok = bool(result.pop('ok'))
            cases[name] = {'status': 'pass' if ok else 'fail', **result}
        except Exception as error:   # a case that raised what it did not expect: fixed fields only
            cases[name] = {'status': 'fail', 'exception': type(error).__name__,
                           'error_code': getattr(error, 'code', None)}
        finally:
            runner.cut = None

    with tempctr.TempObjects(runner, JOB, log=notes.append, memory='384m', cpus=None) as tmp:
        # a named volume at the image's VOLUME path: no anonymous volume is created (TempObjects removes this one)
        tmp.volume('pg')
        tmp.run('pg', IMAGE, [], detach=True, env={'POSTGRES_HOST_AUTH_METHOD': 'trust'},
                volumes=[(tmp.name('pg'), '/var/lib/postgresql/data', None)])
        db = ha_odoo.Cluster(tmp, 'pg', log=notes.append)
        db.wait_ready(tcp=True)
        image_id = runner.podman('container', 'inspect', '--format', '{{.Image}}', tmp.name('pg'),
                                 timeout=60, max_output=4096).stdout.decode().strip()
        report['image_id'] = image_id[:71]
        network = runner.podman('container', 'inspect', '--format', '{{.HostConfig.NetworkMode}}', tmp.name('pg'),
                                timeout=60, max_output=4096).stdout.decode().strip()
        report['network_mode'] = network
        mounts = runner.podman('container', 'inspect', '--format', '{{range .Mounts}}{{.Name}} {{end}}',
                               tmp.name('pg'), timeout=60, max_output=4096).stdout.decode().split()
        report['only_the_named_volume_mounted'] = mounts == [tmp.name('pg')]
        version = tmp.exec('pg', ['psql', '--version'], user='postgres', timeout=60, max_output=4096).stdout
        report['psql'] = version.decode().strip()[:60]

        def state():
            doc = db.query_json("SELECT json_build_object('n', count(*), 'changed', count(*) FILTER (WHERE a <> 'x'), "
                                "'y1', bool_or(id = 1 AND a = 'y'), 'z2', bool_or(id = 2 AND a = 'z')) FROM t")
            return doc

        def reset():
            db.script("UPDATE t SET a = 'x';\n")

        def file_state():
            out = tmp.exec('pg', ['sh', '-c', f'wc -c < {TOC_PATH} && sha256sum < {TOC_PATH}'], user='postgres',
                           timeout=60, max_output=4096).stdout.decode().split()
            return int(out[0]), out[1] == hashlib.sha256(TOC).hexdigest()

        # ---------------------------------------------------------------- write_file
        def write_control():
            db.write_file(TOC_PATH, TOC)
            size, same = file_state()
            mode = tmp.exec('pg', ['stat', '-c', '%a %U', TOC_PATH], user='postgres', timeout=60,
                            max_output=4096).stdout.decode().split()
            return {'ok': same and size == len(TOC) and mode == ['600', 'postgres'], 'bytes': size,
                    'content_equal': same, 'mode': mode[0], 'writes': 1}

        def write_cut_always():
            runner.cut = lambda kind, n, data: data[:len(data) // 2] if kind == 'write' else data
            try:
                db.write_file(TOC_PATH, TOC)
                return {'ok': False, 'raised': False}
            except BackupError as error:
                size, same = file_state()
                return {'ok': error.message == ha_odoo.INCOMPLETE_FILE and runner.seen.get('write') == 3 and not same,
                        'raised': True, 'message_is_incomplete_file': error.message == ha_odoo.INCOMPLETE_FILE,
                        'writes': runner.seen.get('write'), 'file_in_container_short': size < len(TOC)}

        def write_cut_once():
            runner.cut = lambda kind, n, data: data[:len(data) // 3] if kind == 'write' and n == 1 else data
            db.write_file(TOC_PATH, TOC)
            size, same = file_state()
            return {'ok': same and runner.seen.get('write') == 2, 'writes': runner.seen.get('write'),
                    'content_equal': same}

        def write_middle_lost():
            runner.cut = lambda kind, n, data: data[:65536] + data[65536 + 4096:] if kind == 'write' else data
            try:
                db.write_file(TOC_PATH, TOC)
                return {'ok': False, 'raised': False}
            except BackupError as error:
                return {'ok': error.message == ha_odoo.INCOMPLETE_FILE and runner.seen.get('write') == 3,
                        'raised': True, 'writes': runner.seen.get('write')}

        def write_cksum_branch():
            """The cksum branch of READBACK for real (busybox cksum), by forcing it for this case."""
            saved = ha_odoo.READBACK
            ha_odoo.READBACK = 'wc -c < {path} && echo cksum && cksum < {path}'
            try:
                db.write_file(TOC_PATH, TOC)
                whole = True
                runner.cut = lambda kind, n, data: data[:-1] if kind == 'write' else data
                try:
                    db.write_file(TOC_PATH, TOC)
                    short_refused = False
                except BackupError as error:
                    short_refused = error.message == ha_odoo.INCOMPLETE_FILE
            finally:
                ha_odoo.READBACK = saved
            runner.cut = None
            db.write_file(TOC_PATH, TOC)
            out = tmp.exec('pg', ['sh', '-c', f'cksum < {TOC_PATH}'], user='postgres', timeout=60,
                           max_output=4096).stdout.decode().split()
            same = (int(out[1]), out[0]) == ha_odoo.source_digest(TOC, None, 'cksum')
            return {'ok': whole and short_refused and same, 'whole_accepted': whole,
                    'one_byte_short_refused': short_refused, 'python_cksum_equals_busybox': same}

        case('write_file control (300 KiB list)', write_control)
        case('write_file: every attempt cut to half', write_cut_always)
        case('write_file: the first attempt cut, the second whole', write_cut_once)
        case('write_file: a 4 KiB chunk lost in the middle', write_middle_lost)
        case('write_file: the cksum branch (busybox)', write_cksum_branch)

        # ---------------------------------------------------------------- script
        db.script("CREATE TABLE t (id int PRIMARY KEY, a text NOT NULL);\n"
                  "INSERT INTO t SELECT g, 'x' FROM generate_series(1, 1000) g;\n")

        def script_control():
            reset()
            db.script(UPDATES)
            doc = state()
            return {'ok': doc == {'n': 1000, 'changed': 2, 'y1': True, 'z2': True}, 'rows': doc['n'],
                    'changed_rows': doc['changed']}

        def script_cut(marker):
            def run():
                reset()
                runner.cut = lambda kind, n, data: data[:data.index(marker)] if kind == 'psql' else data
                try:
                    db.script(UPDATES)
                    raised = None
                except BackupError as error:
                    raised = error.message
                runner.cut = None
                doc = state()
                return {'raised': raised is not None, 'message_is_incomplete_sql': raised == ha_odoo.INCOMPLETE_SQL,
                        'changed_rows': doc['changed'], 'rows': doc['n'], 'ok': raised == ha_odoo.INCOMPLETE_SQL}
            return run

        def script_boundary():
            result = script_cut(b"UPDATE t SET a = 'z'")()
            result['ok'] = result['ok'] and result['changed_rows'] == 0
            return result

        def script_inside():
            result = script_cut(b' WHERE id = 2')()
            result['ok'] = result['ok'] and result['changed_rows'] == 0
            return result

        def script_mark():
            result = script_cut(b'\\echo')()
            result['ok'] = result['ok'] and result['changed_rows'] == 2   # committed, and still noticed
            return result

        def old_shape():
            """The OLD Cluster.script argv (psql -1) with the same cut inside the last statement: what it committed."""
            reset()
            text = UPDATES.encode()
            cut = text[:text.index(b' WHERE id = 2')]
            result = tmp.exec('pg', ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', 'postgres', '-d',
                                     'postgres', '-f', '-'], user='postgres', input=cut, timeout=120,
                              max_output=64 * 1024, check=False)
            doc = state()
            reset()
            return {'ok': result.returncode == 0 and doc['changed'] == 1000, 'psql_exit': result.returncode,
                    'changed_rows': doc['changed'], 'note': 'expected: the defect - exit 0 and every row updated'}

        case('script control', script_control)
        case('script: tail lost at a statement boundary', script_boundary)
        case('script: tail lost inside the last statement (valid prefix)', script_inside)
        case('script: only the end mark lost', script_mark)
        case('OLD psql -1 shape, same cut (the defect)', old_shape)

        # ---------------------------------------------------------------- statement
        def setting():
            db.statement('SELECT pg_reload_conf();')
            time.sleep(1)
            return db.query_json("SELECT to_json(current_setting('work_mem'))")

        def statement_control():
            db.statement("ALTER SYSTEM SET work_mem TO '8MB';")
            return {'ok': setting() == '8MB', 'work_mem_is_8MB': setting() == '8MB'}

        def statement_mark_lost():
            runner.cut = lambda kind, n, data: data[:data.index(b'\\echo')] if kind == 'psql' else data
            try:
                db.statement("ALTER SYSTEM SET work_mem TO '16MB';")
                raised = None
            except BackupError as error:
                raised = error.message
            runner.cut = None
            return {'ok': raised == ha_odoo.INCOMPLETE_SQL, 'message_is_incomplete_sql': raised == ha_odoo.INCOMPLETE_SQL,
                    'applied': setting() == '16MB'}

        def statement_cut_value():
            db.statement("ALTER SYSTEM SET work_mem TO '8MB';")
            runner.cut = lambda kind, n, data: data[:data.index(b"6MB'")] if kind == 'psql' else data
            try:
                db.statement("ALTER SYSTEM SET work_mem TO '16MB';")
                raised = None
            except BackupError as error:
                raised = type(error).__name__
            runner.cut = None
            return {'ok': raised is not None and setting() == '8MB', 'raised': raised, 'unchanged': setting() == '8MB'}

        case('statement control (ALTER SYSTEM, outside a transaction)', statement_control)
        case('statement: end mark lost', statement_mark_lost)
        case('statement: cut inside the value', statement_cut_value)

        # ---------------------------------------------------------------- other stdin execs (classification)
        db.script("CREATE TABLE s (id int PRIMARY KEY, a text NOT NULL);\n"
                  "INSERT INTO s SELECT g, repeat(md5(g::text), 8) FROM generate_series(1, 20000) g;\n")
        dump = tmp.exec('pg', ['pg_dump', '-U', 'postgres', '-d', 'postgres', '-Fc', '-t', 's'], user='postgres',
                        timeout=300, max_output=64 * 1024 * 1024).stdout

        def restore(data, *extra):
            tmp.exec('pg', ['psql', '-X', '-q', '-U', 'postgres', '-d', 'postgres', '-c', 'DROP DATABASE IF EXISTS d'],
                     user='postgres', timeout=120, max_output=64 * 1024)
            tmp.exec('pg', ['createdb', '-U', 'postgres', 'd'], user='postgres', timeout=120, max_output=64 * 1024)
            result = tmp.exec('pg', ['pg_restore', '-U', 'postgres', '--no-owner', '--no-acl', '--exit-on-error',
                                     '--single-transaction', *extra, '-d', 'd'], user='postgres', input=data,
                              timeout=300, max_output=1024 * 1024, check=False)
            tables = db.query_json("SELECT to_json(count(*)) FROM pg_class WHERE relname = 's' AND relkind = 'r'", 'd')
            return result.returncode, tables

        def dump_streams():
            whole = restore(dump)
            half = restore(dump[:len(dump) // 2])
            byte = restore(dump[:-1])
            full_read = tmp.exec('pg', ['pg_restore', '-f', '/dev/null'], user='postgres', input=dump[:-1], timeout=300,
                                 max_output=64 * 1024, check=False).returncode
            listing = tmp.exec('pg', ['pg_restore', '-l'], user='postgres', input=dump[:int(len(dump) * 0.9)],
                               timeout=300, max_output=4 * 1024 * 1024, check=False).returncode
            return {'ok': whole == (0, 1) and half[0] != 0 and half[1] == 0 and byte[0] != 0 and byte[1] == 0
                    and full_read != 0, 'dump_bytes': len(dump), 'whole': list(whole), 'half': list(half),
                    'one_byte_short': list(byte), 'full_read_one_byte_short_exit': full_read,
                    'list_90_percent_exit': listing}

        def copy_text():
            tmp.exec('pg', ['psql', '-X', '-q', '-U', 'postgres', '-d', 'postgres', '-c',
                            'CREATE TABLE c (id int PRIMARY KEY, a text NOT NULL)'], user='postgres', timeout=120,
                     max_output=64 * 1024)
            rows = b''.join(f'{n}\tvalue-{n}\n'.encode() for n in range(1, 101))
            cut = rows[:-3]   # inside the last field of the last row
            result = tmp.exec('pg', ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-1', '-U', 'postgres', '-d',
                                     'postgres', '-c', 'COPY c (id, a) FROM STDIN'], user='postgres', input=cut,
                              timeout=120, max_output=64 * 1024, check=False)
            doc = db.query_json("SELECT json_build_object('n', count(*), 'last_whole', "
                                "bool_or(id = 100 AND a = 'value-100')) FROM c")
            return {'ok': True, 'copy_exit': result.returncode, 'rows_loaded': doc['n'],
                    'last_value_whole': doc['last_whole'],
                    'note': 'classification only: a tail lost inside the last field still loads every row'}

        case('custom-format dump streams cut short (pg_restore)', dump_streams)
        case('COPY text data cut inside the last field (classification)', copy_text)
    # TempObjects removed its container and volume on leaving the block
    left = runner.podman('ps', '-a', '--filter', f'label={tempctr.LABEL}={JOB}', '--format', '{{.Names}}',
                         timeout=60, max_output=64 * 1024, check=False).stdout.decode().split()
    volumes = runner.podman('volume', 'ls', '--filter', f'label={tempctr.LABEL}={JOB}', '--format', '{{.Name}}',
                            timeout=60, max_output=64 * 1024, check=False).stdout.decode().split()
    cases['clean-up (no container or volume of this job left)'] = {
        'status': 'pass' if not left and not volumes else 'fail', 'containers_left': len(left),
        'volumes_left': len(volumes)}
    report['cases'] = cases
    report['retry_notes'] = sum(1 for n in notes if '重新寫入' in n)
    report['seconds'] = round(time.monotonic() - started, 1)
    report['status'] = ('pass' if all(c['status'] == 'pass' for c in cases.values()) and report.get('network_mode') == 'none'
                        and report.get('only_the_named_volume_mounted') else 'fail')
    report['commercial_acceptance'] = 'not-complete'
    print(json.dumps(report, ensure_ascii=False, indent=1))
    return 0 if report['status'] == 'pass' else 1


if __name__ == '__main__':
    sys.exit(main())
