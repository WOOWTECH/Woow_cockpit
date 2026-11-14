"""Engine core strengthening (2026-11-13): stops and start groups, unavailability, the safety backup's hand-over,
built-in data digests at exact capture points, and PostgreSQL instance mode -- against a fake owner that also models
psql's JSON answers, pg_dumpall and an instance with several databases and roles (CONTRACT sections 4, 5, 7, 9, 10).
Owner: E2 engine core."""
import copy
import hashlib
import io
import json
import tarfile
import time
import unittest

from woowbackup import catalog, digests, podman
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError

from .test_adapter import (PODMAN, PYTHON, SYSTEMCTL, AdapterCase, FakeOwner, extract_entries, psql)
from .test_catalog import demo_entry, lookup as user_lookup

DIR_HELPER = podman.DIR_HELPER
FILES_SPEC = {'id': 'files', 'type': 'files-digest', 'volume': 'woowbk-demo-files', 'label': '上傳檔案'}
DB_SPEC = {'id': 'db', 'type': 'postgres-digest', 'postgres': 'main'}
GLOBALS = (b'--\n-- PostgreSQL database cluster dump\n--\n\n\\restrict k1X2\n\nSET default_transaction_read_only = off;\n\n'
           b"SET client_encoding = 'UTF8';\nSET standard_conforming_strings = on;\n\n--\n-- Roles\n--\n\n"
           b'CREATE ROLE notes;\n'
           b"ALTER ROLE notes WITH SUPERUSER INHERIT CREATEROLE CREATEDB LOGIN REPLICATION BYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:aa';\n"
           b'CREATE ROLE oc_admin;\n'
           b"ALTER ROLE oc_admin WITH NOSUPERUSER INHERIT NOCREATEROLE CREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$4096:bb';\n"
           b"ALTER ROLE oc_admin SET search_path TO 'public', 'pg_catalog';\n"
           b'GRANT readonly TO oc_admin WITH INHERIT TRUE GRANTED BY notes;\n\n\\unrestrict k1X2\n')


def volume_listing(data):
    """What the owner-side `digestvol` prints for a volume holding these tar members (top directory not listed,
    setuid/setgid of files masked), sorted by path bytes."""
    rows, contents = [], {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        for member in tar.getmembers():
            name = member.name.rstrip('/')
            if name in ('', '.'):
                continue
            content, target = b'', None
            if member.isreg():
                content = contents[name] = tar.extractfile(member).read()
                kind = 'f'
            elif member.islnk():
                content, kind = contents.get(member.linkname.rstrip('/'), b''), 'f'
            elif member.isdir():
                kind = 'd'
            elif member.issym():
                kind, target = 'l', member.linkname.encode()
            else:
                kind = 'p'
            mode = member.mode & 0o7777
            if kind != 'd':
                mode &= ~0o6000
            sha = hashlib.sha256(content).hexdigest() if kind == 'f' else '-'
            rows.append((name.encode(), f'{kind} {mode:04o} {member.uid} {member.gid} {len(content) if kind == "f" else 0} '
                                        f'{sha} {target.hex() if target else "-"} {name.encode().hex()}\n'.encode()))
    return b''.join(line for _name, line in sorted(rows))


def dump_of(name, payload):
    return b'PGDMP:' + name.encode() + b':' + payload


class StrengthOwner(FakeOwner):
    """FakeOwner plus psql JSON answers (`-f -` with PGOPTIONS), the volume digest helper, pg_dumpall and a whole
    PostgreSQL instance (databases with owners and extensions, roles) that a fresh start of the database unit with
    its volume removed re-initializes the way the image's entrypoint does."""

    def __init__(self, deployed=True, *, instance=False):
        super().__init__(deployed)
        self.instance = None
        self.available = ['pg_trgm', 'plpgsql']
        self.superuser = True
        self.globals = GLOBALS
        self.applied_globals = []
        self.lose_rows = False      # pg_restore silently loses data (a digest must catch it)
        self.volume_lost = None     # a volume import that loses a member: its name
        self.dropped = []
        self.untemplated = []       # ALTER DATABASE ... IS_TEMPLATE false
        self.snapshots = 0          # digest queries read inside one REPEATABLE READ transaction
        self.bootstrap = 'notes'    # the role initdb created (oid 10)
        self.initdb = 1700000000    # initdb time of the running cluster (system identifier >> 32)
        self.session_state = [True, 'off']  # the restore's role after the roles script
        self.template1_objects = 0
        self.keep_pgdata = False    # `volume rm` of the database volume does nothing (the unit uses another one)
        self.image_init = None      # what the image's init scripts add to a new cluster: {database: info}
        self.writes_between = 0     # digest reads after which the data changes (a writer the catalog does not stop)
        self.reads = 0
        self.files_change = None    # a volume that changes right after its first files-digest read
        self.listing_overflow = False  # the owner side prints more than the listing budget
        if instance:
            self.instance = {
                'postgres': {'owner': 'notes', 'data': dump_of('postgres', b'maint'), 'extensions': []},
                'notes': {'owner': 'notes', 'data': dump_of('notes', b'notes-data'), 'extensions': []},
                'nextcloud': {'owner': 'oc_admin', 'data': dump_of('nextcloud', b'nc-data'),
                              'extensions': [['pg_trgm', '1.6']]},
                'tmpl_custom': {'owner': 'notes', 'data': dump_of('tmpl_custom', b'tmpl'), 'extensions': [],
                                'template': True},
            }
            self.extra_rows = [{'name': 'template0', 'template': True, 'connect': False},
                               {'name': 'template1', 'template': True, 'connect': True}]

    # ------------------------------------------------------------- model
    def tables(self, database):
        data = self.db['data'] if self.instance is None else self.instance[database]['data']
        digest = hashlib.sha256(data).hexdigest()
        # Sums of signed 64-bit halves: negative values are normal (lab 2026-11-13)
        return [['public', 'items', 'r', str(len(data)), str(-int(digest[:15], 16)), str(int(digest[15:30], 16))],
                ['public', 'items_id_seq', 'S', '1', '5', '6'], ['cron', 'job_run', 'r', '3', '1', '1']]

    def role_rows(self):
        return [[['oc_admin', False, True, False, True, True, False, False, -1, None, 'b' * 32]],
                [['readonly', 'oc_admin', False]]]

    def reinit(self):
        """The image's entrypoint on an empty data volume: postgres, POSTGRES_DB, the bootstrap superuser only (plus
        what its init scripts add, e.g. postgis: extensions in POSTGRES_DB and a template database)."""
        self.instance = {'postgres': {'owner': 'notes', 'data': dump_of('postgres', b''), 'extensions': []},
                         'notes': {'owner': 'notes', 'data': dump_of('notes', b''), 'extensions': []}}
        for name, info in (self.image_init or {}).items():
            self.instance[name] = copy.deepcopy(info)
        self.initdb = int(time.time())

    def systemctl(self, args):
        if (self.instance is not None and args[0] == 'start' and 'woowbk-demo-db.service' in args[2:]
                and 'woowbk-demo-pgdata' not in self.volumes and not self.keep_pgdata):
            self.volumes['woowbk-demo-pgdata'] = b'PGDATA'
            self.reinit()
        return super().systemctl(args)

    def json(self, value, stdout):
        return self.out(0, (json.dumps(value) + '\n').encode(), stdout)

    def psql_file(self, database, sql, stdout):
        if sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'):
            assert sql.endswith(';\nCOMMIT;\n'), sql[-40:]
            sql = sql[len('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'):-len(';\nCOMMIT;\n')]
            self.snapshots += 1
        if sql.startswith('SET ') or sql.startswith('ALTER ROLE') or 'ROLE' in sql.split(';', 1)[0]:
            self.applied_globals.append(sql)
            return podman.Result(0, b'', b'')
        if sql == qp.SESSION_STATE_SQL:
            return self.json(self.session_state, stdout)
        if sql == qp.BOOTSTRAP_SQL:
            return self.json([self.bootstrap, 'notes'], stdout)
        if sql == qp.CLUSTER_ID_SQL:
            return self.json([str((self.initdb << 32) | 1234)], stdout)
        if sql == "SELECT json_build_array(current_setting('server_version_num'))":
            return self.json([self.db['num']], stdout)
        if sql.startswith('SELECT json_build_array((SELECT (SELECT count(*)'):
            assert database == 'template1', database
            return self.json([self.template1_objects], stdout)
        if sql == qp.INSTANCE_CATALOG_SQL:
            rows = [[name, info.get('template', False), info.get('connect', True)]
                    for name, info in sorted((self.instance or {}).items())]
            rows += [[row['name'], row['template'], row['connect']] for row in self.extra_rows
                     if row['name'] not in ('template0', 'template1')]
            return self.json(rows, stdout)
        if sql.startswith('SELECT json_build_array((SELECT rolsuper'):
            return self.json([self.superuser], stdout)
        if sql.startswith('SELECT coalesce(json_agg(json_build_array(r.nspname'):
            self.reads += 1
            if self.writes_between and self.reads == self.writes_between + 1:
                # a client the catalog does not stop commits after the first `writes_between` reads
                if self.instance is None:
                    self.db['data'] += b'+'
                else:
                    self.instance[database]['data'] += b'+'
            rows = self.tables(database)
            if ' AND c.oid IN (' in sql:
                keep = sql.split(' AND c.oid IN (', 1)[1].split(')', 1)[0].split(',')
                rows = [row for index, row in enumerate(rows, 1) if str(index) in keep]
            return self.json(rows, stdout)
        if sql == digests.LIST_SQL:
            return self.json([[index, row[0], row[1]] for index, row in enumerate(self.tables(database), 1)], stdout)
        if sql == digests.ROLES_SQL:
            return self.json(self.role_rows(), stdout)
        if sql.startswith("SELECT coalesce(json_agg(datname ORDER BY datname)"):
            return self.json(sorted(name for name, info in (self.instance or {'notes': {}, 'postgres': {}}).items()
                                    if not info.get('template') and info.get('connect', True)), stdout)
        if sql == qp.DATABASES_JSON_SQL:
            rows = [{'name': name, 'owner': info['owner'], 'encoding': 'UTF8', 'template': info.get('template', False),
                     'connect': info.get('connect', True),
                     'row': {'datlocprovider': 'c', 'datcollate': 'en_US.utf8', 'datctype': 'en_US.utf8',
                             'daticulocale': None}} for name, info in sorted(self.instance.items())]
            return self.json(rows + [{**row, 'owner': 'notes', 'encoding': 'UTF8', 'row': {}} for row in self.extra_rows],
                             stdout)
        if sql == qp.EXTENSIONS_SQL:
            return self.json(self.instance[database]['extensions'], stdout)
        if sql == qp.AVAILABLE_EXTENSIONS_SQL:
            return self.json(self.available, stdout)
        if sql == qp.ROLE_FLAGS_SQL:
            return self.json([['notes', True, True], ['oc_admin', False, True], ['readonly', False, False]], stdout)
        raise AssertionError(sql[:120])

    # ------------------------------------------------------------- commands
    def podman(self, args, data, stdout):
        if args[0] == 'unshare' and args[1:5] == [PYTHON, '-I', '-c', DIR_HELPER]:
            op, target = args[5], args[6]
            assert op == 'digestvol', op
            name = target.split('/volumes/', 1)[1].split('/', 1)[0]
            if self.listing_overflow:
                raise podman.OutputLimitExceeded(1, to_file=True)
            result = self.out(0, volume_listing(self.volumes[name]), stdout)
            if self.files_change == name:
                # a process the catalog does not stop writes a file right after the first read
                self.files_change = None
                with tarfile.open(fileobj=io.BytesIO(self.volumes[name]), mode='r:') as tar, io.BytesIO() as out:
                    with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as copy_:
                        for member in tar.getmembers():
                            copy_.addfile(member, tar.extractfile(member) if member.isreg() else None)
                        late = tarfile.TarInfo('files/late.txt')
                        late.size = 4
                        copy_.addfile(late, io.BytesIO(b'late'))
                    self.volumes[name] = out.getvalue()
            return result
        if args[0] == 'volume' and args[1] == 'import' and self.volume_lost:
            result = super().podman(args, data, stdout)
            with tarfile.open(fileobj=io.BytesIO(self.volumes[args[2]]), mode='r:') as tar, io.BytesIO() as out:
                with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as copy_:
                    for member in tar.getmembers():
                        if member.name.rstrip('/') != self.volume_lost:
                            copy_.addfile(member, tar.extractfile(member) if member.isreg() else None)
                self.volumes[args[2]] = out.getvalue()
            return result
        if args[:2] == ['volume', 'rm'] and self.keep_pgdata and 'woowbk-demo-pgdata' in args:
            return podman.Result(0, b'', b'')
        if args[0] != 'exec':
            return super().podman(args, data, stdout)
        rest = args[1:]
        if rest[0] == '-i':
            rest = rest[1:]
        if rest[0] == '-e':
            assert rest[1] == f'PGOPTIONS={digests.PG_OPTIONS}', rest[1]
            assert rest[2:4] == ['-e', 'PGCLIENTENCODING=UTF8'], rest[2:4]
            rest = rest[4:]
        container, tool = rest[0], rest[1:]
        if self.units.get(self.containers.get(container)) != 'active':
            return podman.Result(125, b'', b'Error: container is not running')
        if tool[0] == 'psql' and '-f' in tool:
            return self.psql_file(tool[tool.index('-d') + 1], data.decode(), stdout)
        if tool[0] == 'psql' and tool[-2:] == ['-c', 'SELECT 1']:
            ok = tool[tool.index('-d') + 1] in (self.instance or {'notes': 1, 'postgres': 1})
            return podman.Result(0 if ok else 2, b'1\n' if ok else b'', b'' if ok else b'FATAL: database does not exist')
        if tool[0] == 'psql' and tool[-1].startswith('ALTER DATABASE "') and tool[-1].endswith('" IS_TEMPLATE false'):
            name = tool[-1][len('ALTER DATABASE "'):-len('" IS_TEMPLATE false')]
            self.untemplated.append(name)
            self.instance[name]['template'] = False
            return podman.Result(0, b'', b'')
        if tool[0] == 'psql' and tool[-1].startswith('DROP DATABASE "'):
            name = tool[-1][len('DROP DATABASE "'):-1]
            if self.instance[name].get('template'):
                return podman.Result(1, b'', b'ERROR:  cannot drop a template database')
            self.dropped.append(name)
            del self.instance[name]
            return podman.Result(0, b'', b'')
        if tool[0] == 'pg_dumpall':
            assert tool[1:] == ['-w', '-U', 'notes', '-l', 'postgres', '--globals-only', '--no-tablespaces'], tool
            return self.out(0, self.globals, stdout)
        if tool[0] == 'pg_dump' and self.instance is not None:
            return self.out(0, self.instance[tool[tool.index('-d') + 1]]['data'], stdout)
        if tool[0] == 'pg_restore' and tool[1:3] != ['-f', '/dev/null'] and self.instance is not None:
            name = data.split(b':', 2)[1].decode()
            if '--create' in tool:
                assert name not in self.instance, f'database {name} exists'
                self.instance[name] = {'owner': 'restored', 'data': bytes(data), 'extensions': []}
            else:
                self.instance[tool[tool.index('-d') + 1]]['data'] = bytes(data)
            return podman.Result(0, b'', b'')
        if tool[0] == 'pg_restore' and tool[1:3] != ['-f', '/dev/null'] and self.lose_rows:
            result = super().podman(['exec', container, *tool], data, stdout)
            self.db['data'] = self.db['data'][:-1]
            return result
        return super().podman(['exec', container, *tool], data, stdout)


class StrengthCase(AdapterCase):
    instance = False

    def setUp(self):
        super().setUp()
        self.app = self.make_app()
        self.owner = StrengthOwner(instance=self.instance)
        self.adapter = self.make_adapter()

    def make_app(self, mutate=None):
        entry = demo_entry(self.paths)
        entry['verify'] += [copy.deepcopy(DB_SPEC), copy.deepcopy(FILES_SPEC)]
        if self.instance:
            del entry['postgres'][0]['database']
            entry['postgres'][0]['scope'] = 'instance'
        if mutate:
            mutate(entry)
        return catalog.validate_entry(entry, paths=self.paths, user_lookup=user_lookup)

    def index_of(self, argvs, predicate):
        return next(i for i, argv in enumerate(argvs) if predicate(argv))


def is_stop(argv):
    return argv[:3] == [SYSTEMCTL, '--user', 'stop']


def is_start(argv, unit=None):
    return argv[:3] == [SYSTEMCTL, '--user', 'start'] and (unit is None or unit in argv[4:])


def is_digest_sql(argv):
    return argv[:5] == [PODMAN, 'exec', '-i', '-e', f'PGOPTIONS={digests.PG_OPTIONS}']


def is_volume_digest(argv):
    return 'digestvol' in argv


class StartGroupTests(StrengthCase):
    def four_units(self, after):
        def mutate(entry):
            entry['units'] = ['woowbk-demo-db.service', 'cache.service', 'woowbk-demo-app.service', 'worker.service']
            entry['writer_units'] = ['woowbk-demo-app.service', 'worker.service']
        self.app = self.make_app(mutate)
        self.owner.after = after
        for unit in ('cache.service', 'worker.service'):
            self.owner.units[unit] = 'active'
        return self.make_adapter()

    def test_groups_follow_after_and_fall_back_to_the_catalog_order(self):
        deps = {'woowbk-demo-app.service': ['woowbk-demo-db.service', 'cache.service'],
                'worker.service': ['woowbk-demo-db.service', 'cache.service', 'network-online.target']}
        adapter = self.four_units(deps)
        units = list(self.app.units)
        # cache names no unit of the app: it waits for every unit before it (the catalog order is the fallback);
        # app and worker only wait for what they are ordered after, so they start together.
        self.assertEqual(adapter.start_groups(units), [['woowbk-demo-db.service'], ['cache.service'],
                                                       ['woowbk-demo-app.service', 'worker.service']])
        self.assertEqual(adapter.start_groups(['worker.service', 'woowbk-demo-app.service']),
                         [['woowbk-demo-app.service', 'worker.service']], 'the database runs already: one group')
        self.assertEqual(adapter.start_groups(['woowbk-demo-app.service']), [['woowbk-demo-app.service']])
        self.assertEqual(self.owner.argvs()[0], [SYSTEMCTL, '--user', 'show', '--property=Id,After,Requires,BindsTo', '--',
                                                 *units])

    def test_a_required_unit_is_waited_for_even_without_after(self):
        # Quadlet adds no After= for Requires= (review L7): worker is ordered after the database only, but requires the
        # app (BindsTo= counts the same). It used to start side by side with the app; it waits for it now.
        after = {'cache.service': ['woowbk-demo-db.service'], 'woowbk-demo-app.service': ['woowbk-demo-db.service'],
                 'worker.service': ['woowbk-demo-db.service']}
        adapter = self.four_units(after)
        self.owner.requires = {}
        units = list(self.app.units)
        self.assertEqual(adapter.start_groups(units), [['woowbk-demo-db.service'],
                                                       ['cache.service', 'woowbk-demo-app.service', 'worker.service']])
        for key in ('requires', 'binds'):
            with self.subTest(key):
                self.owner.requires, self.owner.binds = {}, {}
                setattr(self.owner, key, {'worker.service': ['woowbk-demo-app.service']})
                self.assertEqual(adapter.start_groups(units), [['woowbk-demo-db.service'],
                                                               ['cache.service', 'woowbk-demo-app.service'],
                                                               ['worker.service']])

    def test_contradicting_or_unreadable_dependencies_start_one_at_a_time(self):
        adapter = self.four_units({'woowbk-demo-db.service': ['worker.service']})
        self.assertEqual(adapter.start_groups(list(self.app.units)), [[unit] for unit in self.app.units])
        self.owner.fail = [('--property=Id,After,Requires,BindsTo', 1)]
        self.assertEqual(adapter.start_groups(list(self.app.units)), [[unit] for unit in self.app.units])

    def test_backup_stops_writers_in_one_call_and_restarts_them_as_one_group(self):
        adapter = self.four_units({'woowbk-demo-app.service': ['woowbk-demo-db.service'],
                                   'worker.service': ['woowbk-demo-db.service']})
        adapter.backup(self.staging / 'x', include_images=False)
        argvs = self.owner.argvs()
        self.assertEqual([a for a in argvs if is_stop(a)],
                         [[SYSTEMCTL, '--user', 'stop', '--', 'worker.service', 'woowbk-demo-app.service']])
        self.assertEqual([a for a in argvs if is_start(a)],
                         [[SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service', 'worker.service']])
        self.assertEqual(self.hook_calls, [['woowbk-demo-app.service', 'worker.service'], []])

    def test_a_unit_that_fails_in_its_group_is_retried_alone_and_reported(self):
        adapter = self.four_units({'woowbk-demo-app.service': ['woowbk-demo-db.service'],
                                   'worker.service': ['woowbk-demo-db.service']})
        self.owner.fail_units = {'worker.service'}
        with self.assertRaises(BackupError) as caught:
            adapter.backup(self.staging / 'x', include_images=False)
        self.assertIn('worker.service', caught.exception.message)
        starts = [a for a in self.owner.argvs() if is_start(a)]
        self.assertEqual(starts, [[SYSTEMCTL, '--user', 'start', '--', 'woowbk-demo-app.service', 'worker.service'],
                                  [SYSTEMCTL, '--user', 'start', '--', 'worker.service']])
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active', 'the other unit of the group runs')
        self.assertEqual(self.hook_calls[-1], ['worker.service'], 'the record keeps the unit that did not start')

    def test_a_signal_during_one_group_still_starts_the_others(self):
        adapter = self.four_units({})  # no dependencies: one unit per group, in catalog order
        self.owner.signal_on = ('start -- woowbk-demo-app.service', KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            adapter.backup(self.staging / 'x', include_images=False)
        self.assertEqual(self.owner.units['worker.service'], 'active')
        self.assertEqual(self.hook_calls[-1], ['woowbk-demo-app.service'])


class DigestBackupTests(StrengthCase):
    def test_digests_are_taken_while_the_writers_are_stopped(self):
        manifest, entries = self.run_backup()
        argvs = self.owner.argvs()
        stop = self.index_of(argvs, is_stop)
        start = self.index_of(argvs, is_start)
        dump = self.index_of(argvs, lambda a: 'pg_dump' in a)
        export = self.index_of(argvs, lambda a: 'export' in a and 'woowbk-demo-files' in a)
        sql = [i for i, a in enumerate(argvs) if is_digest_sql(a)]
        files = [i for i, a in enumerate(argvs) if is_volume_digest(a)]
        self.assertTrue(sql and files)
        self.assertTrue(all(stop < i < start for i in sql + files), 'exact capture points: writers stopped')
        # Read before and after what they vouch for: equal reads prove the dump / the export holds that data (H2, F3)
        self.assertTrue(min(sql) < dump < max(sql), 'the SQL digest is read before and after the dump')
        self.assertTrue(min(files) < export < max(files), 'the files digest is read before and after the export')
        by_id = {item['id']: item for item in manifest['verify_digests']}
        self.assertEqual(by_id['db']['target'], 'postgres:main')
        self.assertEqual((by_id['db']['databases'], by_id['db']['roles']), (['notes'], False))
        self.assertEqual(by_id['db']['summary'], {'databases': 1, 'tables': 2, 'sequences': 1,
                                                  'rows': len(self.owner.db['data']) + 3, 'roles': 0})
        self.assertEqual(by_id['files']['target'], 'volume:woowbk-demo-files')
        self.assertEqual(by_id['files']['summary']['files'], 3)
        contents = {e.path: e for e in entries}
        for item in manifest['verify_digests']:
            entry = contents[item['entry']]
            self.assertEqual(entry.sha256, item['digest'])
            self.assertTrue(item['entry'].startswith('apps/woowbk-demo/verify/'))
        self.assertEqual(argvs[self.index_of(argvs, is_volume_digest)][-2:],
                         ['/home/appowner/.local/share/containers/storage/volumes/woowbk-demo-files/_data', 'nosetid'])

    def test_apps_without_digest_checks_keep_the_manifest_shape(self):
        self.app = catalog.validate_entry(demo_entry(self.paths), paths=self.paths, user_lookup=user_lookup)
        manifest, entries = self.make_adapter().backup(self.staging / 'plain', include_images=False)
        self.assertNotIn('verify_digests', manifest)
        self.assertFalse([e for e in entries if '/verify/' in e.path])

    def test_exclude_tables_reads_only_the_kept_relations(self):
        def mutate(entry):
            entry['verify'][1]['exclude_tables'] = ['cron.*']
        self.app = self.make_app(mutate)
        manifest, _ = self.make_adapter().backup(self.staging / 'x', include_images=False)
        queries = [c['input'].decode() for c in self.owner.calls if is_digest_sql(c['argv'])]
        self.assertEqual(queries[0], digests.LIST_SQL)
        self.assertIn(' AND c.oid IN (1,2)) r', queries[1])
        self.assertTrue(queries[1].startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'), 'one snapshot')
        db = next(item for item in manifest['verify_digests'] if item['id'] == 'db')
        self.assertEqual((db['exclude'], db['summary']['tables']), (['cron.*'], 1))

    def test_a_digest_that_cannot_be_read_fails_the_backup_and_restarts_the_writers(self):
        self.owner.fail = [('PGOPTIONS', 2)]
        with self.assertRaises(BackupError):
            self.run_backup()
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active')

    def test_keep_stopped_hands_the_writers_over(self):
        manifest, _ = self.adapter.backup(self.staging / 'k', include_images=False, keep_stopped=True)
        self.assertEqual(self.adapter.kept_stopped, ['woowbk-demo-app.service'])
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'inactive')
        self.assertFalse([a for a in self.owner.argvs() if is_start(a)])
        self.assertEqual(self.hook_calls, [['woowbk-demo-app.service']], 'still listed for the recovery')
        self.assertEqual(manifest['verify_snapshot'], {}, 'an unconfirmed http-json snapshot is not stored')
        self.assertEqual({item['id'] for item in manifest['verify_digests']}, {'db', 'files'})
        self.assertIn('回復時以資料摘要核對', self.everything_logged())
        self.assertIsNotNone(self.adapter.timing.get('first_stop'))


class DigestRestoreTests(StrengthCase):
    def setUp(self):
        super().setUp()
        self.manifest, self.entries = self.run_backup()
        self.extract = self.root / 'job' / 'extract'
        self.extract.mkdir(parents=True, mode=0o700)
        extract_entries(self.entries, self.extract)

    def restore(self, owner=None, manifest=None):
        owner = owner or StrengthOwner()
        owner.db['data'] = b'PGDMPchanged'
        owner.volumes['woowbk-demo-files'] = self.owner.volumes['woowbk-demo-files']
        adapter = self.make_adapter(owner)
        adapter.restore(manifest or self.manifest, self.extract, mode='inplace')
        return owner, adapter

    def test_digests_match_before_the_app_starts(self):
        owner, adapter = self.restore()
        argvs = owner.argvs()
        imported = self.index_of(argvs, lambda a: a[:3] == [PODMAN, 'volume', 'import'])
        files = self.index_of(argvs, is_volume_digest)
        db_start = self.index_of(argvs, lambda a: is_start(a, 'woowbk-demo-db.service'))
        restored = self.index_of(argvs, lambda a: 'pg_restore' in a and '--single-transaction' in a)
        sql = [i for i, a in enumerate(argvs) if is_digest_sql(a)]
        app_start = self.index_of(argvs, lambda a: is_start(a, 'woowbk-demo-app.service'))
        self.assertLess(imported, files)
        self.assertLess(files, db_start, 'files are compared before anything starts')
        self.assertTrue(all(restored < i < app_start for i in sql), 'SQL digests after pg_restore, before the app')
        results = {item['id']: item for item in adapter.digest_results}
        self.assertEqual({key: item['match'] for key, item in results.items()}, {'db': True, 'files': True})
        self.assertEqual(results['files']['before'], results['files']['after'])
        self.assertIn('資料摘要 db 與備份時一致', self.everything_logged())
        self.assertEqual(owner.units['woowbk-demo-app.service'], 'active')

    def test_a_lost_row_stops_the_restore_before_the_app_starts(self):
        owner = StrengthOwner()
        owner.lose_rows = True
        with self.assertRaises(BackupError) as caught:
            self.restore(owner)
        self.assertIn('還原後的資料與備份時不一致', caught.exception.message)
        self.assertIn('資料表 notes:public.items：資料列', caught.exception.message)
        self.assertFalse([a for a in owner.argvs() if is_start(a, 'woowbk-demo-app.service')])
        db = next(item for item in self.last_adapter.digest_results if item['id'] == 'db')
        self.assertIs(db['match'], False)
        self.assertEqual(db['differences']['changed'], 1)
        self.assertEqual(db['differences']['samples'][0]['detail'], f'資料列 {len(DUMP_AFTER)} → {len(DUMP_AFTER) - 1}')

    def make_adapter(self, owner=None):
        adapter = super().make_adapter(owner)
        self.last_adapter = adapter
        return adapter

    def test_data_still_changing_after_the_restore_is_not_compared_and_does_not_fail_it(self):
        # lab 2026-11-14 (review H2): a writer the catalog does not stop kept inserting into the restored database
        # between pg_restore and the digest read; the rollback met it too and left the app masked. A difference is
        # read again; a second read that differs from the first means the data is moving: not compared, not failed.
        owner = StrengthOwner()
        owner.lose_rows = True        # the first read differs from the backup ...
        owner.writes_between = 1      # ... and the data changes again before the second read
        _owner, adapter = self.restore(owner)
        db = next(item for item in adapter.digest_results if item['id'] == 'db')
        self.assertIsNone(db['match'])
        self.assertIn('仍在變動', db['note'])
        self.assertIn(db['note'], adapter.warnings)
        self.assertEqual(owner.units['woowbk-demo-app.service'], 'active', 'the app starts')

    def test_a_stable_difference_is_read_twice_and_still_fails(self):
        owner = StrengthOwner()
        owner.lose_rows = True
        with self.assertRaises(BackupError):
            self.restore(owner)
        sql = [a for a in owner.argvs() if is_digest_sql(a)]
        self.assertTrue(len(sql) >= 4, 'first read and the confirming second read')
        self.assertFalse([a for a in owner.argvs() if is_start(a, 'woowbk-demo-app.service')])

    def test_a_lost_file_is_named_and_nothing_starts(self):
        owner = StrengthOwner()
        owner.volume_lost = 'files/b.txt'
        with self.assertRaises(BackupError):
            self.restore(owner)
        files = next(item for item in self.last_adapter.digest_results if item['id'] == 'files')
        self.assertEqual(files['differences']['missing'], 1)
        self.assertEqual(files['differences']['samples'][0]['item'], 'files/b.txt')
        self.assertFalse([a for a in owner.argvs() if is_start(a)], 'not even the database starts')

    def test_checks_without_a_digest_or_with_another_definition_are_not_compared(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['verify_digests'] = [item for item in manifest['verify_digests'] if item['id'] == 'files']
        manifest['verify_digests'][0]['exclude'] = ['*.tmp']
        _owner, adapter = self.restore(manifest=manifest)
        notes = {item['id']: (item['match'], item['note']) for item in adapter.digest_results}
        self.assertEqual(notes['db'], (None, '備份沒有這個項目的資料摘要（例如較舊的備份），未比對。'))
        self.assertEqual(notes['files'], (None, '此設備的核對設定與備份時不同，未比對。'))

    def test_a_listing_that_does_not_match_its_record_is_corrupt(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['verify_digests'][0]['digest'] = '0' * 64
        with self.assertRaises(BackupError) as caught:
            self.restore(manifest=manifest)
        self.assertEqual(caught.exception.code, 'corrupt-archive')

    def test_take_over_keeps_the_first_stop_and_reports_the_unavailability(self):
        owner = StrengthOwner()
        owner.db['data'] = b'PGDMPchanged'
        adapter = self.make_adapter(owner)
        adapter.take_over(['woowbk-demo-app.service'], 900.0)
        adapter.restore(self.manifest, self.extract, mode='inplace')
        adapter.health()
        self.assertEqual(adapter.timing['first_stop'], 900.0)
        report = adapter.timing_report()
        self.assertEqual(report, {'writer_pause_seconds': round(self.clock.t - 900.0, 1),
                                  'unavailable_seconds': round(self.clock.t - 900.0, 1)})
        hooks = self.hook_calls
        self.assertEqual(hooks, [['woowbk-demo-db.service', 'woowbk-demo-app.service'], []],
                         'listed from just before the stop until the units are masked')


DUMP_AFTER = b'PGDMP' + bytes(range(256)) * 4


class ColdDigestTests(StrengthCase):
    def make_app(self, mutate=None):
        def cold(entry):
            entry['postgres'] = []
            entry['writer_units'] = list(entry['units'])
            entry['volumes'].append({'name': 'woowbk-demo-pgdata'})
            entry['verify'] = [{'id': 'db', 'type': 'postgres-digest', 'container': 'woowbk-demo-db',
                                'unit': 'woowbk-demo-db.service', 'user': 'notes'}]
        return super().make_app(cold)

    def test_the_database_is_read_before_it_stops_and_alone_after_a_restore(self):
        self.owner.volumes['woowbk-demo-pgdata'] = self.owner.volumes['woowbk-demo-files']
        manifest, entries = self.run_backup()
        argvs = self.owner.argvs()
        stops = [i for i, a in enumerate(argvs) if is_stop(a)]
        self.assertEqual([argvs[i][4:] for i in stops], [['woowbk-demo-app.service'], ['woowbk-demo-db.service']])
        sql = [i for i, a in enumerate(argvs) if is_digest_sql(a)]
        self.assertTrue(sql and all(stops[0] < i < stops[1] for i in sql), 'read between the two stops')
        db = manifest['verify_digests'][0]
        self.assertEqual((db['target'], db['databases'], db['roles']), ('container:woowbk-demo-db', ['notes', 'postgres'], True))
        self.assertEqual(db['summary']['roles'], 1)
        extract = self.root / 'job' / 'extract'
        extract.mkdir(parents=True)
        extract_entries(entries, extract)
        owner = StrengthOwner()
        owner.volumes['woowbk-demo-pgdata'] = self.owner.volumes['woowbk-demo-files']
        adapter = self.make_adapter(owner)
        adapter.restore(manifest, extract, mode='inplace')
        argvs = owner.argvs()
        unmask = argvs.index([SYSTEMCTL, '--user', 'unmask', '--', 'woowbk-demo-db.service'])
        db_start = self.index_of(argvs, lambda a: is_start(a, 'woowbk-demo-db.service'))
        sql = [i for i, a in enumerate(argvs) if is_digest_sql(a)]
        app_start = self.index_of(argvs, lambda a: is_start(a, 'woowbk-demo-app.service'))
        self.assertTrue(unmask < db_start < min(sql) and max(sql) < app_start)
        self.assertEqual(adapter.digest_results[0]['match'], True)


class InstanceModeTests(StrengthCase):
    instance = True

    def make_app(self, mutate=None):
        def instance(entry):
            entry['verify'] = [{'id': 'db', 'type': 'postgres-digest', 'postgres': 'main'}]
            if mutate:
                mutate(entry)
        return super().make_app(instance)

    def test_backup_keeps_every_database_and_the_roles(self):
        manifest, entries = self.run_backup()
        item = manifest['postgres'][0]
        self.assertEqual((item['scope'], item['database'], item['major']), ('instance', 'postgres', 16))
        self.assertEqual([db['name'] for db in item['databases']], ['nextcloud', 'notes', 'postgres', 'tmpl_custom'])
        nextcloud = item['databases'][0]
        self.assertEqual(nextcloud, {'name': 'nextcloud', 'owner': 'oc_admin', 'encoding': 'UTF8', 'collate': 'en_US.utf8',
                                     'ctype': 'en_US.utf8', 'locale_provider': 'libc', 'icu_locale': None,
                                     'template': False, 'extensions': [{'name': 'pg_trgm', 'version': '1.6'}],
                                     'entry': 'apps/woowbk-demo/postgres/main.db0.dump'})
        self.assertIs(item['databases'][3]['template'], True, 'a template database is kept too (review F1)')
        self.assertEqual(item['bootstrap_user'], 'notes')
        self.assertEqual(item['entry'], 'apps/woowbk-demo/postgres/main.globals.sql')
        self.assertEqual(item['roles'], [{'name': 'notes', 'superuser': True, 'login': True},
                                         {'name': 'oc_admin', 'superuser': False, 'login': True},
                                         {'name': 'readonly', 'superuser': False, 'login': False}])
        contents = {e.path: e.source.read_bytes() for e in entries}
        self.assertEqual(contents['apps/woowbk-demo/postgres/main.globals.sql'], GLOBALS)
        self.assertEqual(contents['apps/woowbk-demo/postgres/main.db0.dump'], dump_of('nextcloud', b'nc-data'))
        log = self.everything_logged()
        self.assertNotIn('不會包含在備份中', log, 'nothing of the instance is left out')
        reads = [a for a in self.owner.argvs() if 'pg_restore' in a and '/dev/null' in a]
        self.assertEqual(len(reads), 4, 'every dump is read back in full')
        db = manifest['verify_digests'][0]
        self.assertEqual((db['databases'], db['roles'], db['summary']['roles']),
                         (['nextcloud', 'notes', 'postgres'], True, 1))
        self.assertNotIn('SCRAM', json.dumps(manifest), 'no password hash in the manifest')

    def test_backup_refusals(self):
        cases = {'not a superuser': lambda o: setattr(o, 'superuser', False),
                 'unsafe database name': lambda o: o.instance.update({'a=b': o.instance['notes']}),
                 'hostile globals': lambda o: setattr(o, 'globals', o.globals + b'SELECT 1; \\! id\n'),
                 # pg_dump cannot read it and an in-place restore would lose it for good (review F1)
                 'a database that accepts no connections': lambda o: o.instance.update(
                     {'archive_2024': {'owner': 'notes', 'data': b'', 'extensions': [], 'connect': False}}),
                 # a restore runs in a cluster that has only the bootstrap superuser (review F5)
                 'not the bootstrap superuser': lambda o: setattr(o, 'bootstrap', 'postgres')}
        for label, change in cases.items():
            with self.subTest(label):
                owner = StrengthOwner(instance=True)
                change(owner)
                with self.assertRaises(BackupError) as caught:
                    self.make_adapter(owner).backup(self.staging / label.replace(' ', '-'), include_images=False)
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertEqual(owner.units['woowbk-demo-app.service'], 'active')

    def restore_case(self, owner):
        manifest, entries = self.run_backup()
        extract = self.root / 'job' / 'extract'
        extract.mkdir(parents=True, exist_ok=True)
        extract_entries(entries, extract)
        return manifest, extract, self.make_adapter(owner)

    def test_restore_rebuilds_the_instance_and_reconciles_the_bootstrap_superuser(self):
        owner = StrengthOwner(instance=True)
        owner.instance['nextcloud']['data'] = dump_of('nextcloud', b'changed')
        manifest, extract, adapter = self.restore_case(owner)
        adapter.restore(manifest, extract, mode='inplace')
        argvs = owner.argvs()
        script = owner.applied_globals[0]
        self.assertNotIn('CREATE ROLE notes;', script, 'the image created its superuser: never recreated')
        self.assertIn("ALTER ROLE notes WITH SUPERUSER", script, 'its attributes and password are reconciled')
        self.assertIn('CREATE ROLE oc_admin;', script)
        self.assertNotIn('restrict', script)
        self.assertEqual(owner.dropped, ['notes', 'postgres'], 'the databases the new cluster already had are recreated')
        creates = [a for a in argvs if 'pg_restore' in a and '--create' in a]
        self.assertEqual(len(creates), 4, 'every database of the backup, the connection database and a template too')
        self.assertEqual(creates[0][-6:], ['--no-tablespaces', '-w', '-U', 'notes', '-d', 'template1'])
        self.assertNotIn('--no-owner', ' '.join(' '.join(a) for a in argvs if 'pg_restore' in a))
        self.assertFalse([a for a in argvs if 'pg_restore' in a and '--single-transaction' in a])
        self.assertEqual(owner.instance['nextcloud']['data'], dump_of('nextcloud', b'nc-data'))
        self.assertEqual(owner.instance['postgres']['data'], dump_of('postgres', b'maint'))
        self.assertEqual(adapter.digest_results[0]['match'], True)
        script_at = self.index_of(argvs, lambda a: a[:4] == [PODMAN, 'exec', '-i', 'woowbk-demo-db'] and 'psql' in a)
        self.assertLess(self.index_of(argvs, lambda a: is_start(a, 'woowbk-demo-db.service')), script_at,
                        'the roles go into the fresh cluster the image initialized')
        self.assertLess(script_at, self.index_of(argvs, lambda a: '--create' in a), 'roles before the databases')

    def test_a_missing_extension_stops_before_any_data(self):
        owner = StrengthOwner(instance=True)
        manifest, extract, adapter = self.restore_case(owner)
        owner.available = ['plpgsql']
        with self.assertRaises(BackupError) as caught:
            adapter.restore(manifest, extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('pg_trgm', caught.exception.message)
        self.assertEqual(owner.applied_globals, [])
        self.assertFalse([a for a in owner.argvs() if 'pg_restore' in a and '--create' in a])

    def test_a_cluster_that_was_not_rebuilt_is_never_written_over(self):
        owner = StrengthOwner(instance=True)
        manifest, extract, adapter = self.restore_case(owner)
        owner.keep_pgdata = True  # `volume rm` did not remove the volume the database unit uses
        with self.assertRaises(BackupError) as caught:
            adapter.restore(manifest, extract, mode='inplace')
        self.assertIn('資料庫資料卷沒有重建', caught.exception.message)
        self.assertEqual(owner.dropped, [])
        self.assertEqual(owner.applied_globals, [])

    def test_init_scripts_that_fill_the_new_cluster_do_not_stop_the_restore(self):
        # postgis/timescaledb images: their init scripts load extensions into POSTGRES_DB and create a template
        # database; the cluster is new (its initdb time is after the volume was removed), so they are replaced (F4).
        owner = StrengthOwner(instance=True)
        manifest, extract, adapter = self.restore_case(owner)
        owner.image_init = {'notes': {'owner': 'notes', 'data': dump_of('notes', b'postgis'), 'extensions': [['postgis', '3']]},
                            'tmpl_custom': {'owner': 'notes', 'data': dump_of('tmpl_custom', b''), 'extensions': [],
                                            'template': True}}
        adapter.restore(manifest, extract, mode='inplace')
        self.assertEqual(owner.untemplated, ['tmpl_custom'], 'a template database is unmarked before it is dropped')
        self.assertEqual(owner.dropped, ['notes', 'postgres', 'tmpl_custom'])
        self.assertEqual(owner.instance['notes']['data'], dump_of('notes', b'notes-data'))
        self.assertEqual(adapter.digest_results[0]['match'], True)

    def test_a_roles_script_that_takes_away_the_restore_role_stops_the_restore(self):
        owner = StrengthOwner(instance=True)
        manifest, extract, adapter = self.restore_case(owner)
        owner.session_state = [True, 'on']  # e.g. ALTER ROLE ... SET default_transaction_read_only (review L2, F8)
        with self.assertRaises(BackupError) as caught:
            adapter.restore(manifest, extract, mode='inplace')
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertFalse([a for a in owner.argvs() if 'pg_restore' in a and '--create' in a])

    def test_closed_databases_are_refused_before_anything_changes(self):
        owner = StrengthOwner(instance=True)
        manifest, extract, adapter = self.restore_case(owner)
        owner.instance['archive_2024'] = {'owner': 'notes', 'data': b'', 'extensions': [], 'connect': False}
        checks = {c['id'].split('/', 1)[1]: c for c in adapter.preflight(manifest, mode='inplace')}
        self.assertEqual(checks['databases-closed']['status'], 'fail')
        self.assertIn('archive_2024', checks['databases-closed']['message'])
        with self.assertRaises(BackupError) as caught:
            adapter.restore(manifest, extract, mode='inplace', unchecked_databases_ok=True)
        self.assertIn('archive_2024', caught.exception.message)
        self.assertFalse(adapter.destructive_started)
        self.assertIn('woowbk-demo-pgdata', owner.volumes, 'the volume was not removed')

    def test_preflight_names_what_comes_back_and_what_goes(self):
        owner = StrengthOwner(instance=True)
        manifest, _extract, adapter = self.restore_case(owner)
        owner.instance['added_later'] = {'owner': 'notes', 'data': b'PGDMP', 'extensions': []}
        owner.available = ['plpgsql']
        checks = {c['id'].split('/', 1)[1]: c for c in adapter.preflight(manifest, mode='inplace')}
        self.assertEqual(checks['instance']['status'], 'ok')
        self.assertIn('4 個資料庫', checks['instance']['message'])
        self.assertEqual(checks['databases']['status'], 'warn')
        self.assertIn('added_later', checks['databases']['message'])
        self.assertEqual(checks['extensions']['status'], 'fail')
        self.assertNotIn('maintenance-db', checks, 'nothing of the instance is left out')
        self.assertNotIn('bootstrap', checks)
        bootstrapped = copy.deepcopy(manifest)
        bootstrapped['postgres'][0]['bootstrap_user'] = 'postgres'
        owner.bootstrap = 'postgres'
        checks = {c['id'].split('/', 1)[1]: c for c in adapter.preflight(bootstrapped, mode='inplace')}
        self.assertEqual((checks['bootstrap']['status'], checks['bootstrap-current']['status']), ('fail', 'fail'))
        owner.bootstrap = 'notes'
        demoted = copy.deepcopy(manifest)
        demoted['postgres'][0]['roles'][0]['superuser'] = False
        checks = {c['id'].split('/', 1)[1]: c for c in adapter.preflight(demoted, mode='inplace')}
        self.assertEqual(checks['roles']['status'], 'fail')
        single = copy.deepcopy(manifest)
        del single['postgres'][0]['scope']
        checks = {c['id'].split('/', 1)[1]: c for c in adapter.preflight(single, mode='inplace')}
        self.assertEqual(checks['postgres-scope']['status'], 'fail')


class ReviewFixTests(StrengthCase):
    """Fixes of the 2026-11-14 review of the strengthened engine (H1, F2, F6, L4/F7: the digest SQL; H2/F3: capture
    moments and volumes another container writes to; M3: the preflight names a backup of another account; M4: the
    listing budget; F16: http-json-only apps)."""

    def test_rows_are_hashed_with_the_row_types_own_output_function(self):
        sql = digests.tables_sql()
        # `t::text` ran a cast a table owner can create as the digest's superuser, and named a column `t` instead of
        # the row (H1, F2). The lab probe (strengthen-final evidence) shows equal digests for every other table.
        self.assertIn("md5(convert_to(pg_catalog.record_out(t.*)::text, CASE WHEN pg_catalog.getdatabaseencoding() = "
                      "''SQL_ASCII'' THEN ''SQL_ASCII'' ELSE ''UTF8'' END))", sql)
        self.assertNotIn('t::text', sql)
        self.assertIn('-c lc_monetary=C', digests.PG_OPTIONS)
        self.run_backup()
        digest_calls = [a for a in self.owner.argvs() if is_digest_sql(a)]
        self.assertTrue(digest_calls and all(a[5:7] == ['-e', 'PGCLIENTENCODING=UTF8'] for a in digest_calls))

    def test_a_database_written_to_during_the_dump_keeps_no_digest(self):
        self.owner.writes_between = 1
        manifest, entries = self.run_backup()
        self.assertEqual([item['id'] for item in manifest['verify_digests']], ['files'])
        self.assertEqual(self.adapter.unstable_digests, ['db'])
        self.assertIn('資料摘要 db 兩次讀取的結果不同', self.everything_logged())
        self.assertEqual(sorted(e.path for e in entries if '/verify/' in e.path), ['apps/woowbk-demo/verify/files.txt'])
        self.assertFalse(list((self.staging / 'app' / 'verify').glob('*.first.txt')), 'the first reads are removed')

    def test_files_that_change_during_the_export_keep_no_digest(self):
        self.owner.files_change = 'woowbk-demo-files'
        manifest, _entries = self.run_backup()
        self.assertEqual([item['id'] for item in manifest['verify_digests']], ['db'])
        self.assertEqual(self.adapter.unstable_digests, ['files'])

    def test_a_cold_database_that_changes_while_it_is_read_keeps_no_digest(self):
        def cold(entry):
            entry['postgres'] = []
            entry['writer_units'] = list(entry['units'])
            entry['volumes'].append({'name': 'woowbk-demo-pgdata'})
            entry['verify'] = [{'id': 'db', 'type': 'postgres-digest', 'container': 'woowbk-demo-db',
                                'unit': 'woowbk-demo-db.service', 'user': 'notes'}]
        self.app = self.make_app(cold)
        self.owner.volumes['woowbk-demo-pgdata'] = self.owner.volumes['woowbk-demo-files']
        self.owner.writes_between = 1
        manifest, _ = self.make_adapter().backup(self.staging / 'cold', include_images=False)
        self.assertNotIn('verify_digests', manifest)
        self.assertIn('資料庫在讀取摘要期間有變動', self.everything_logged())

    def test_another_container_writing_to_a_volume_refuses_the_backup(self):
        self.owner.bind_mounts = [{'id': 'c' * 12, 'name': 'sidecar', 'unit': None, 'volume': 'woowbk-demo-files',
                                   'rw': True}]
        with self.assertRaises(BackupError) as caught:
            self.run_backup()
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertIn('資料卷 woowbk-demo-files', caught.exception.message)
        self.assertFalse([a for a in self.owner.argvs() if is_stop(a)], 'refused before any writer stops')
        self.owner.bind_mounts[0]['rw'] = False  # mounted read-only: it cannot write
        self.make_adapter().backup(self.staging / 'ro', include_images=False)
        self.owner.bind_mounts[0].update(rw=True, unit='woowbk-demo-app.service')  # a writer: the backup stops it
        self.make_adapter().backup(self.staging / 'writer', include_images=False)

    def test_a_backup_from_another_account_is_named_in_the_preflight(self):
        manifest, _ = self.run_backup()
        checks = {c['id'].split('/', 1)[1]: c for c in self.adapter.preflight(manifest, mode='inplace')}
        self.assertNotIn('owner-changed', checks)
        moved = copy.deepcopy(manifest)
        moved['owner']['name'] = 'otheruser'
        checks = {c['id'].split('/', 1)[1]: c for c in self.adapter.preflight(moved, mode='inplace')}
        self.assertEqual(checks['owner-changed']['status'], 'warn')
        self.assertIn('otheruser', checks['owner-changed']['message'])

    def test_a_files_listing_is_capped_whatever_the_free_space(self):
        self.run_backup()
        budgets = {call['max_output'] for call in self.owner.calls if is_volume_digest(call['argv'])}
        self.assertEqual(budgets, {qp.DIGEST_LISTING_MAX}, 'not the free space (10**12 bytes here)')
        self.owner.listing_overflow = True
        with self.assertRaises(BackupError) as caught:
            self.make_adapter().backup(self.staging / 'big', include_images=False)
        self.assertEqual(caught.exception.code, 'limit-exceeded')
        self.assertIn('1 GiB', caught.exception.message)
        self.assertEqual(self.owner.units['woowbk-demo-app.service'], 'active')

    def test_an_app_checked_only_by_http_json_is_told_its_rollback_compares_no_data(self):
        # review F16: the safety backup keeps the writers stopped (the downtime win), so it stores no http-json snapshot;
        # the preflight says before the restore that a rollback is checked by the health checks only
        self.app = catalog.validate_entry(demo_entry(self.paths), paths=self.paths, user_lookup=user_lookup)
        adapter = self.make_adapter()
        manifest, _ = adapter.backup(self.staging / 'h', include_images=False, keep_stopped=True)
        self.assertEqual(adapter.kept_stopped, ['woowbk-demo-app.service'])
        self.assertEqual(manifest['verify_snapshot'], {})
        self.assertIn('不比對資料', self.everything_logged())
        checks = {c['id'].split('/', 1)[1]: c for c in adapter.preflight(manifest, mode='inplace')}
        self.assertEqual(checks['rollback-unverified']['status'], 'warn')
        self.app = self.make_app()  # with digest checks: the rollback compares them, no such warning
        checks = {c['id'].split('/', 1)[1]: c for c in self.make_adapter().preflight(manifest, mode='inplace')}
        self.assertNotIn('rollback-unverified', checks)

    def test_a_digest_read_on_postgresql_11_is_not_compared_on_12_or_newer(self):
        manifest, entries = self.run_backup()
        db = next(item for item in manifest['verify_digests'] if item['id'] == 'db')
        self.assertEqual(db['server_major'], 16)
        manifest = copy.deepcopy(manifest)
        next(item for item in manifest['verify_digests'] if item['id'] == 'db')['server_major'] = 11
        manifest['postgres'][0]['major'] = 11
        extract = self.root / 'job' / 'extract'
        extract.mkdir(parents=True)
        extract_entries(entries, extract)
        owner = StrengthOwner()
        owner.volumes['woowbk-demo-files'] = self.owner.volumes['woowbk-demo-files']
        adapter = self.make_adapter(owner)
        adapter.restore(manifest, extract, mode='inplace')
        result = next(item for item in adapter.digest_results if item['id'] == 'db')
        self.assertIsNone(result['match'])
        self.assertIn('PostgreSQL 11', result['note'])


class GlobalsScriptTests(unittest.TestCase):
    def test_the_real_layout_passes_and_is_reconciled(self):
        statements = qp.globals_statements(GLOBALS, session_user='notes')
        self.assertEqual(statements[:3], ['SET default_transaction_read_only = off', "SET client_encoding = 'UTF8'",
                                          'SET standard_conforming_strings = on'])
        self.assertNotIn('CREATE ROLE notes', statements)
        self.assertIn("ALTER ROLE oc_admin SET search_path TO 'public', 'pg_catalog'", statements)
        self.assertEqual(len(qp.globals_statements(GLOBALS)), len(statements) + 1, 'without a session user: kept')
        spaced = b"ALTER ROLE x SET search_path TO 'a  b';\n"
        self.assertEqual(qp.globals_statements(spaced), ["ALTER ROLE x SET search_path TO 'a  b'"],
                         'literal contents stay byte for byte')
        quoted = b'CREATE ROLE "Mixed Case";\nALTER ROLE "Mixed Case" WITH LOGIN;\n'
        self.assertEqual(len(qp.globals_statements(quoted, session_user='Mixed Case')), 1)

    def test_anything_psql_could_run_besides_role_statements_is_refused(self):
        hostile = [b'SELECT 1;', b'CREATE ROLE x; \\! id\n', b"ALTER ROLE x SET a TO E'\\' ; \\! id';",
                   b"COMMENT ON ROLE x IS U&'\\0041';", b'COMMENT ON ROLE x IS $$a$$;', b'/* x */ CREATE ROLE x;',
                   b'SET standard_conforming_strings = off;', b"SET search_path = 'x';", b'CREATE ROLE x',
                   b'COPY x TO PROGRAM \'id\';', b'CREATE ROLE "a\nb";', b'\\connect other\nCREATE ROLE x;',
                   b'CREATE ROLE x;\x00', b'\xff']
        for script in hostile:
            with self.subTest(script), self.assertRaises(BackupError) as caught:
                qp.globals_statements(script, session_user='notes')
            self.assertEqual(caught.exception.code, 'incompatible')

    def test_role_tricks_that_reach_the_session_user_indirectly_are_refused(self):
        # review L2, F8: keywords in any case, special role names, U& identifiers, renames and library settings
        hostile = [b'ALTER ROLE CURRENT_USER WITH NOSUPERUSER;', b'ALTER ROLE SESSION_USER NOLOGIN;',
                   b'ALTER ROLE current_role NOLOGIN;', b'ALTER ROLE U&"\\0070ostgres" NOSUPERUSER;',
                   b"ALTER ROLE ALL SET default_transaction_read_only TO 'on';", b'alter role notes nologin;',
                   b'ALTER ROLE notes WITH nosuperuser login;', b"ALTER ROLE notes SET session_preload_libraries = 'x';",
                   b"ALTER ROLE other SET local_preload_libraries TO 'x';", b'ALTER ROLE notes RENAME TO x;',
                   b"ALTER ROLE other IN DATABASE db SET \"session_preload_libraries\" TO 'x';"]
        for script in hostile:
            with self.subTest(script), self.assertRaises(BackupError) as caught:
                qp.globals_statements(script, session_user='notes')
            self.assertEqual(caught.exception.code, 'incompatible')
        kept = qp.globals_statements(b"ALTER ROLE app SET \"pgaudit.log\" TO 'all';\nALTER ROLE app IN DATABASE db SET "
                                     b"work_mem TO '64MB';\n", session_user='notes')
        self.assertEqual(len(kept), 2, "pg_dumpall's other role settings stay accepted")

    def test_the_session_user_keeps_superuser_and_login(self):
        for word in ('NOSUPERUSER', 'NOLOGIN'):
            with self.subTest(word), self.assertRaises(BackupError):
                qp.globals_statements(f'ALTER ROLE notes WITH {word};'.encode(), session_user='notes')
        self.assertEqual(qp.globals_statements(b'ALTER ROLE other WITH NOLOGIN;', session_user='notes'),
                         ['ALTER ROLE other WITH NOLOGIN'])


if __name__ == '__main__':
    unittest.main()
