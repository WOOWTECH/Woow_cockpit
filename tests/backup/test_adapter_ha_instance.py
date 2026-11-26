"""N8-01/L-03: complete conversion payloads, live instance preservation and full safety rollback.

The owner models rows, database ownership and role/password state; no host containers or services are used.
"""
import base64
import copy
import hashlib
import json
import re

from woowbackup import catalog, flows, haimport, podman, ha_instance_access as access
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError

from .test_adapter import PODMAN, VOLUME_TAR, extract_entries
from .test_flows import FakeArchive, FakeKeys, FakeReporter, FakeStorage, HOST, ha_registry_row
from .test_strengthen import StrengthCase, StrengthOwner, dump_of
from .test_catalog import lookup as user_lookup


def encoded(name, info):
    body = dict(info, data=base64.b64encode(info['data']).decode())
    return dump_of(name, json.dumps(body, sort_keys=True).encode())


def access_plan(owner='notes', *, table_owner=None, app_role=None, extension=False):
    grants = lambda role, kind: [[role, p, False] for p in sorted(access.PRIVILEGES[kind])]
    plan = {'database': [owner, grants(owner, 'database') + [[None, 'CONNECT', False], [None, 'TEMPORARY', False]]],
            'schemas': [['public', owner, grants(owner, 'schema') + [[None, 'USAGE', False]]]],
            'relations': [], 'columns': [], 'extensions': [['pgstattuple', '1.5', 'public']] if extension else []}
    if table_owner:
        plan['relations'] = [['public', 'marker', 'r', table_owner, grants(table_owner, 'r')]]
    if app_role:
        plan['schemas'][0][-1].append([app_role, 'CREATE', False])
        plan['relations'][0][-1] += [[app_role, p, False] for p in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')]
    return plan


class InstanceOwner(StrengthOwner):
    application_database = 'notes'
    def __init__(self):
        super().__init__(instance=True)
        self.roles = {name: {'superuser': name == 'notes', 'login': name != 'readonly',
                             'password': hashlib.sha256(name.encode()).hexdigest()}
                      for name in ('notes', 'oc_admin', 'readonly')}
        self.fail_import_once = False
        self.extension_controls = [['pgstattuple', '1.5', None, None]]
        self.preseeded = []
        self.toc_files = {}

    def access(self, database):
        info = self.instance[database]
        default = access_plan(info['owner'])
        default['extensions'] = [[n, v, 'public'] for n, v in info['extensions']]
        return copy.deepcopy(info.get('access', default))

    def reinit(self):
        super().reinit()
        if self.application_database != 'notes':
            self.instance[self.application_database] = self.instance.pop('notes')
        self.roles = {'notes': {'superuser': True, 'login': True, 'password': 'image-default'}}

    def role_rows(self):
        return [[[name, row['superuser'], True, False, False, row['login'], False, False, -1, None,
                  hashlib.md5(row['password'].encode()).hexdigest()] for name, row in sorted(self.roles.items())], []]

    def psql_file(self, database, sql, stdout):
        if sql.startswith("SELECT json_build_object('database',"):
            return self.json(self.access(database), stdout)
        if 'FROM pg_available_extension_versions' in sql:
            return self.json(self.extension_controls, stdout)
        if sql == "SELECT coalesce(json_agg(rolname ORDER BY rolname),'[]'::json) FROM pg_roles":
            return self.json(sorted([*self.roles, 'pg_database_owner']), stdout)
        if sql.startswith('BEGIN;\n') and any(s in sql for s in ('CREATE EXTENSION ', 'REVOKE ALL ON ', 'SELECT 1 FROM ')):
            state = self.instance[database]
            plan = state.setdefault('access', self.access(database))
            statements = sql.split(';')
            for statement in statements:
                statement = statement.strip()
                ext = re.fullmatch(r'CREATE EXTENSION "([^"]+)" WITH SCHEMA "([^"]+)" VERSION \'([^\']+)\'', statement)
                if ext:
                    name, schema, version = ext.groups()
                    plan['extensions'].append([name, version, schema])
                    state['extensions'].append([name, version])
                    self.preseeded.append(name)
                owner = re.fullmatch(r'ALTER (SCHEMA|TABLE|SEQUENCE) "([^"]+)"(?:\."([^"]+)")? OWNER TO "([^"]+)"', statement)
                if owner:
                    kind, schema, name, role = owner.groups()
                    row = next(r for r in plan['schemas'] if r[0] == schema) if kind == 'SCHEMA' else next(
                        r for r in plan['relations'] if r[:2] == [schema, name])
                    old_owner = row[-2]
                    row[-1] = [[role if g == old_owner else g, p, grantable] for g, p, grantable in row[-1]]
                    row[-2] = role
                privilege = re.fullmatch(r'(REVOKE ALL|GRANT (\w+)) ON (DATABASE|SCHEMA|TABLE|SEQUENCE) '
                    r'"([^"]+)"(?:\."([^"]+)")? (?:FROM|TO) (PUBLIC|"[^"]+")( WITH GRANT OPTION)?', statement)
                if privilege:
                    action, permission, kind, first, second, role, grantable = privilege.groups()
                    role = None if role == 'PUBLIC' else role[1:-1]
                    row = plan['database'] if kind == 'DATABASE' else (next(r for r in plan['schemas'] if r[0] == first)
                        if kind == 'SCHEMA' else next(r for r in plan['relations'] if r[:2] == [first, second]))
                    row[-1] = [g for g in row[-1] if g[0] != role or (action != 'REVOKE ALL' and g[1] != permission)]
                    if action != 'REVOKE ALL':
                        row[-1].append([role, permission, bool(grantable)])
                read = re.fullmatch(r'SELECT 1 FROM "([^"]+)"\."([^"]+)" LIMIT 0', statement)
                if read:
                    role = re.findall(r'SET LOCAL ROLE "([^"]+)"', sql[:sql.index(statement)])[-1]
                    row = next(r for r in plan['relations'] if r[:2] == list(read.groups()))
                    if role != row[-2] and [role, 'SELECT', False] not in row[-1]:
                        return podman.Result(1, b'', b'permission denied for actual app role')
            mark = sql.rsplit('\\echo ', 1)[1].strip()
            return self.out(0, (mark + '\n').encode(), stdout)
        if sql.startswith('SELECT json_build_array(r.rolname) FROM pg_database'):
            name = re.search(r"d.datname='([^']+)'", sql)[1]
            info = self.instance.get(name, {})
            owner = info.get('owner')
            return self.json([owner] if owner in self.roles and not info.get('template') else None, stdout)
        if sql == qp.ROLE_FLAGS_SQL:
            return self.json([[n, r['superuser'], r['login']] for n, r in sorted(self.roles.items())], stdout)
        if 'ALTER ROLE' in sql:
            for name, flags, password in re.findall(r"ALTER ROLE (\w+) WITH (.*?) PASSWORD '([^']+)';", sql):
                self.roles[name] = {'superuser': 'NOSUPERUSER' not in flags, 'login': 'NOLOGIN' not in flags,
                                    'password': password}
        return super().psql_file(database, sql, stdout)

    def podman(self, args, data, stdout):
        if args[0] == 'exec':
            if 'pg_dumpall' in args:
                text = ''.join(f"CREATE ROLE {n};\nALTER ROLE {n} WITH "
                               f"{'SUPERUSER' if r['superuser'] else 'NOSUPERUSER'} "
                               f"{'LOGIN' if r['login'] else 'NOLOGIN'} PASSWORD '{r['password']}';\n"
                               for n, r in sorted(self.roles.items()))
                return self.out(0, text.encode(), stdout)
            if 'pg_dump' in args:
                name = args[args.index('-d') + 1]
                return self.out(0, encoded(name, self.instance[name]), stdout)
            if 'createdb' in args:
                owner = args[args.index('-O') + 1]
                if owner not in self.roles:
                    return podman.Result(1, b'', b'owner role is missing')
                self.instance[args[-1]] = {'owner': owner, 'data': b'', 'extensions': []}
                return podman.Result(0, b'', b'')
            if args[args.index('exec') + 1:][:1] == ['rm'] or 'rm' in args:
                self.toc_files.pop(args[-1], None)
                return podman.Result(0, b'', b'')
            if 'woowbk-ha-toc' in args:
                self.toc_files[args[-1]] = data
                return podman.Result(0, b'', b'')
            if 'pg_restore' in args and '--list' in args:
                _name, raw = data.split(b':', 2)[1:]
                info = json.loads(raw)
                toc = ''.join(f'{i}; 3079 100 EXTENSION - {n} \n' for i, (n, _v) in enumerate(info['extensions'], 1))
                return self.out(0, toc.encode(), stdout)
            if 'pg_restore' in args and '-f' not in args:
                name, raw = data.split(b':', 2)[1:]
                info = json.loads(raw)
                info['data'] = base64.b64decode(info['data'])
                for arg in args:
                    if arg.startswith('--role='):
                        info['owner'] = arg.split('=', 1)[1]
                if '--single-transaction' in args:
                    current = self.instance[name.decode()]
                    if info['extensions'] and not all(n in self.preseeded for n, _v in info['extensions']):
                        return podman.Result(1, b'', b'untrusted extension requires administrator setup')
                    if info['extensions'] and '--no-comments' not in args:
                        return podman.Result(1, b'', b'must be owner of extension')
                    loaded = access_plan(info['owner'])
                    loaded['relations'] = [[s, n, k, info['owner'], [[info['owner'], p, False] for p in sorted(access.PRIVILEGES[k])]]
                        for s, n, k, _o, _grants in info.get('access', {}).get('relations', [])]
                    loaded['extensions'] = current.get('access', {}).get('extensions', [])
                    info['access'] = loaded
                    info['extensions'] = current['extensions']
                self.instance[name.decode()] = info
                if self.fail_import_once and '--single-transaction' in args:
                    self.fail_import_once = False
                    self.instance[name.decode()]['data'] = b'partial import'
                    return podman.Result(1, b'', b'injected import failure')
                return podman.Result(0, b'', b'')
        return super().podman(args, data, stdout)


def conversion_adapter(app, pg, database, major=16):
    """A real adapter reading a separate live instance during the real converter's product flow."""
    owner = InstanceOwner()
    owner.instance[database] = owner.instance.pop('notes')
    owner.bootstrap = pg['user']
    owner.roles[pg['user']] = dict(owner.roles['notes'])
    owner.containers[pg['container']] = 'woowbk-demo-db.service'
    owner.db.update(num=str(major * 10000 + 15), version=f'{major}.15')
    runner = podman.OwnerRunner('appowner', runner=owner, user_lookup=user_lookup)
    return qp.QuadletPostgresAdapter(app, runner, lambda _line: None), owner


class HaInstanceTests(StrengthCase):
    instance = True
    app_id = 'n8n'
    application_database = 'notes'

    def make_app(self, mutate=None):
        def change(entry):
            entry.update(id=self.app_id, verify=[{'id': 'db', 'type': 'postgres-digest', 'postgres': 'main'}])
            if self.app_id == 'litellm':
                entry['secrets'].append({'name': 'litellm-salt-key'})
            for item in entry['config_files']:
                item['path'] = item['path'].replace('/woowbk-demo/', f'/{self.app_id}/')
            if mutate:
                mutate(entry)
        return super().make_app(change)

    def setUp(self):
        super().setUp()
        self.owner = InstanceOwner()
        self.owner.application_database = self.application_database
        self.owner.files[f'.config/{self.app_id}/app.env'] = self.owner.files.pop('.config/woowbk-demo/app.env')
        if self.app_id == 'litellm':
            self.owner.secrets['litellm-salt-key'] = b'original-device-salt'
        if self.application_database != 'notes':
            self.owner.instance[self.application_database] = self.owner.instance.pop('notes')
        self.adapter = self.make_adapter()
        self.adapter.ha_import = True

    def converted(self, name=None):
        name = name or self.application_database
        (self.staging / 'postgres').mkdir(exist_ok=True)
        converted = self.root / 'converted.dump'
        converted.write_bytes(encoded(name, dict(self.owner.instance[name], data=b'HA rows')))
        dump = self.adapter.import_instance_database(self.app.postgres[0], {'database': name, 'file': converted}, self.staging)
        files = self.root / 'files.tar'
        files.write_bytes(VOLUME_TAR)
        secrets = {}
        if self.app_id == 'litellm':
            salt = self.root / 'ha-salt'
            salt.write_bytes(b'HA salt fixture')
            secrets['litellm-salt-key'] = salt
        manifest, entries = self.adapter.import_manifest(
            self.staging, postgres={'main': dump}, volumes={'woowbk-demo-files': files}, secrets=secrets)
        folder = self.root / 'extract-converted'
        folder.mkdir()
        extract_entries(entries, folder)
        return manifest, folder, entries

    def later_changes(self):
        self.owner.instance['nextcloud']['data'] = b'committed after conversion'
        self.owner.instance['postgres']['data'] = b'new maintenance rows'
        del self.owner.instance['tmpl_custom']
        self.owner.roles['oc_admin']['password'] = hashlib.sha256(b'rotated').hexdigest()
        self.owner.roles['notes']['password'] = hashlib.sha256(b'rotated-bootstrap').hexdigest()
        self.owner.secrets['woowbk-demo-db-password'] = b'rotated-device-database-password'
        self.owner.files[f'.config/{self.app_id}/app.env'] = b'DB_PASSWORD=rotated-device-database-password\n'
        if self.app_id == 'litellm':
            self.owner.secrets['litellm-salt-key'] = b'rotated-device-salt'
        self.owner.roles['new_owner'] = {'superuser': False, 'login': True, 'password': 'new-password-hash'}
        self.owner.instance['new_db'] = {'owner': 'new_owner', 'data': b'new rows', 'extensions': []}
        self.owner.instance[self.application_database]['owner'] = 'new_owner'
        if 'access' in self.owner.instance[self.application_database]:
            plan = self.owner.instance[self.application_database]['access']
            old_owner = plan['database'][0]
            plan['database'][0] = 'new_owner'
            plan['database'][1] = [['new_owner' if r == old_owner else r, p, g] for r, p, g in plan['database'][1]]

    def test_complete_payload_contains_every_database_and_all_current_roles(self):
        manifest, _folder, entries = self.converted()
        item = manifest['postgres'][0]
        self.assertEqual((item['database'], item['ha_database']), ('postgres', self.application_database))
        self.assertEqual({d['name'] for d in item['databases']}, set(self.owner.instance))
        self.assertEqual({r['name'] for r in item['roles']}, set(self.owner.roles))
        contents = {entry.path: entry.source.read_bytes() for entry in entries}
        for db in item['databases']:
            expected = b'HA rows' if db['name'] == self.application_database else self.owner.instance[db['name']]['data']
            wire = json.loads(contents[db['entry']].split(b':', 2)[2])
            self.assertEqual(base64.b64decode(wire['data']), expected)
        self.assertNotIn('verify_digests', manifest, 'conversion never claims a digest of the later live instance')

    def test_ordinary_owner_installed_untrusted_extension_and_separate_app_access(self):
        name = self.application_database
        self.owner.roles.update({r: {'superuser': False, 'login': r == 'app_login', 'password': 'live-hash'}
                                 for r in ('db_owner', 'table_owner', 'app_login')})
        plan = access_plan('db_owner', table_owner='table_owner', app_role='app_login', extension=True)
        self.owner.instance[name].update(owner='db_owner', extensions=[['pgstattuple', '1.5']], access=plan)
        (self.staging / 'postgres').mkdir(exist_ok=True)
        converted = self.root / 'ordinary-owner.dump'
        converted.write_bytes(encoded(name, dict(self.owner.instance[name], data=b'HA rows')))
        item = self.adapter.import_instance_database(self.app.postgres[0], {'database': name, 'file': converted}, self.staging)
        db = next(d for d in item['databases'] if d['name'] == name)
        self.adapter._restore_ha_instance_database(self.app.postgres[0], db, converted)
        self.assertEqual(self.owner.instance[name]['data'], b'HA rows')
        self.assertEqual(self.owner.preseeded, ['pgstattuple'])
        self.assertEqual(access.comparable(self.owner.access(name), plan), access.comparable(plan, plan))
        self.assertFalse(self.owner.roles['db_owner']['superuser'])
        self.assertEqual(self.owner.toc_files, {})

    def test_missing_installed_extension_version_refuses_before_app_drop(self):
        name = self.application_database
        self.owner.instance[name]['access'] = access_plan(extension=True)
        manifest, folder, _entries = self.converted()
        self.owner.extension_controls = []
        with self.assertRaises(BackupError):
            self.adapter.restore(manifest, folder, mode='inplace')
        self.assertFalse(self.owner.dropped)

    def test_fresh_restore_replays_captured_app_ownership_and_access_after_extension_setup(self):
        name = self.application_database
        self.owner.roles.update({r: {'superuser': False, 'login': r == 'app_login', 'password': 'live-hash'}
                                 for r in ('db_owner', 'table_owner', 'app_login')})
        plan = access_plan('db_owner', table_owner='table_owner', app_role='app_login', extension=True)
        self.owner.instance[name].update(owner='db_owner', extensions=[['pgstattuple', '1.5']], access=plan)
        self.owner.available.append('pgstattuple')
        manifest, folder, _entries = self.converted()
        self.adapter.restore(manifest, folder, mode='fresh')
        self.assertEqual(self.owner.instance[name]['data'], b'HA rows')
        self.assertEqual(access.comparable(self.owner.access(name), plan), access.comparable(plan, plan))

    def test_old_marker_without_access_requires_reconversion_for_fresh_restore(self):
        manifest, folder, _entries = self.converted()
        del manifest['postgres'][0]['ha_access']
        count = len(self.owner.argvs())
        with self.assertRaises(BackupError):
            self.adapter.restore(manifest, folder, mode='fresh')
        self.assertEqual(len(self.owner.argvs()), count)

    def test_converted_extension_version_is_recorded_and_checked_against_installed_controls(self):
        name = self.application_database
        self.owner.instance[name]['extensions'] = [['pgstattuple', '1.5']]
        (self.staging / 'postgres').mkdir(exist_ok=True)
        converted = self.root / 'version.dump'
        converted.write_bytes(encoded(name, dict(self.owner.instance[name], data=b'HA rows')))
        dump = self.adapter.import_instance_database(self.app.postgres[0],
            {'database': name, 'file': converted, 'ha_extensions': [['pgstattuple', '1.6', 'public']]}, self.staging)
        db = next(d for d in dump['databases'] if d['name'] == name)
        self.assertEqual(db['extensions'], [{'name': 'pgstattuple', 'version': '1.6'}])
        self.assertEqual(dump['ha_access']['extensions'], [['pgstattuple', '1.6', 'public']])
        with self.assertRaises(BackupError):
            self.adapter._restore_ha_instance_database(self.app.postgres[0], db, converted)
        self.assertFalse(self.owner.dropped, 'only 1.5 control is installed; 1.6 must stop before DROP')

    def test_later_outside_writes_databases_owners_and_passwords_are_preserved(self):
        manifest, folder, _entries = self.converted()
        self.later_changes()
        outside = {n: copy.deepcopy(v) for n, v in self.owner.instance.items() if n != self.application_database}
        roles = copy.deepcopy(self.owner.roles)
        config = self.owner.files[f'.config/{self.app_id}/app.env']
        secrets = copy.deepcopy(self.owner.secrets)
        if self.app_id == 'litellm':
            secrets['litellm-salt-key'] = b'HA salt fixture'
        self.adapter.restore(manifest, folder, mode='inplace')
        self.assertEqual({n: v for n, v in self.owner.instance.items() if n != self.application_database}, outside)
        self.assertEqual(self.owner.roles, roles)
        self.assertEqual(self.owner.secrets, secrets)
        self.assertEqual(self.owner.files[f'.config/{self.app_id}/app.env'], config,
                         'retained live role passwords must keep their current environment/password files')
        self.assertEqual(self.owner.instance[self.application_database]['data'], b'HA rows')
        self.assertEqual(self.owner.instance[self.application_database]['owner'], 'new_owner')
        self.assertEqual(self.owner.dropped, [self.application_database])
        self.assertFalse(self.owner.applied_globals)
        self.assertFalse(any(a[:4] == [PODMAN, 'volume', 'rm', '-f'] and a[-1] == 'woowbk-demo-pgdata'
                             for a in self.owner.argvs()))

    def test_missing_app_database_or_owner_stops_before_the_database_is_dropped(self):
        manifest, folder, _entries = self.converted()
        original = copy.deepcopy(self.owner.instance)
        for missing in ('database', 'owner'):
            self.owner.instance = copy.deepcopy(original)
            if missing == 'database':
                del self.owner.instance[self.application_database]
            else:
                self.owner.instance[self.application_database]['owner'] = 'missing_role'
            before = copy.deepcopy(self.owner.instance)
            with self.subTest(missing=missing), self.assertRaises(BackupError):
                self.adapter.restore(manifest, folder, mode='inplace')
            self.assertEqual(self.owner.instance, before)
            self.assertFalse(self.owner.dropped)
            self.assertFalse(self.owner.applied_globals)

    def test_fresh_restore_uses_the_explicit_complete_snapshot_in_a_new_cluster(self):
        manifest, folder, _entries = self.converted()
        config = self.owner.files[f'.config/{self.app_id}/app.env']
        original = copy.deepcopy(self.owner.instance)
        roles = copy.deepcopy(self.owner.roles)
        self.later_changes()
        checks = []
        self.adapter._preflight_instance(self.app.postgres[0], manifest['postgres'][0],
                                          lambda *row: checks.append(row), running=False, fresh=True)
        self.assertTrue(any(row[0] == 'instance-snapshot' for row in checks))
        self.adapter.restore(manifest, folder, mode='fresh')
        self.assertEqual(set(self.owner.instance), set(original))
        self.assertEqual(self.owner.instance['nextcloud'], original['nextcloud'])
        self.assertEqual(self.owner.instance[self.application_database]['data'], b'HA rows')
        self.assertEqual(self.owner.instance[self.application_database]['owner'], original[self.application_database]['owner'])
        self.assertEqual(self.owner.roles, roles)
        self.assertEqual(self.owner.files[f'.config/{self.app_id}/app.env'], config)
        self.assertTrue(self.owner.applied_globals)

    def test_ordinary_restore_keeps_its_full_instance_semantics(self):
        manifest, folder, _entries = self.converted()
        config = self.owner.files[f'.config/{self.app_id}/app.env']
        original = copy.deepcopy(self.owner.instance)
        roles = copy.deepcopy(self.owner.roles)
        self.later_changes()
        self.adapter.ha_import = False
        self.adapter.restore(manifest, folder, mode='inplace')
        self.assertEqual(set(self.owner.instance), set(original))
        self.assertEqual(self.owner.instance['nextcloud'], original['nextcloud'])
        self.assertEqual(self.owner.roles, roles)
        self.assertEqual(self.owner.files[f'.config/{self.app_id}/app.env'], config)

    def test_bad_markers_are_refused_before_any_owner_command(self):
        manifest, folder, _entries = self.converted()
        for value in (None, True, [], 'template1', 'absent', 'notes\n'):
            bad = copy.deepcopy(manifest)
            bad['postgres'][0]['ha_database'] = value
            count = len(self.owner.argvs())
            with self.subTest(value=value), self.assertRaises(BackupError):
                self.adapter.restore(bad, folder, mode='inplace')
            self.assertEqual(len(self.owner.argvs()), count)

    def test_a_converted_snapshot_cannot_be_used_as_an_automatic_rollback_source(self):
        manifest, folder, _entries = self.converted()
        count = len(self.owner.argvs())
        with self.assertRaises(BackupError):
            self.adapter.restore(manifest, folder, mode='inplace', rollback=True)
        self.assertEqual(len(self.owner.argvs()), count)

    def test_flow_failure_restores_the_current_full_safety_instance_and_checks_its_digest(self):
        self.owner.roles.update({r: {'superuser': False, 'login': r == 'app_login', 'password': 'live-hash'}
                                 for r in ('db_owner', 'table_owner', 'app_login')})
        self.owner.instance[self.application_database].update(owner='db_owner', extensions=[['pgstattuple', '1.5']],
            access=access_plan('db_owner', table_owner='table_owner', app_role='app_login', extension=True))
        self.owner.available.append('pgstattuple')
        manifest, _folder, entries = self.converted()
        self.later_changes()
        original, roles = copy.deepcopy(self.owner.instance), copy.deepcopy(self.owner.roles)
        original_secrets = copy.deepcopy(self.owner.secrets)
        original_config = self.owner.files[f'.config/{self.app_id}/app.env']
        storage, keys, archive = FakeStorage(self.root / 'storage'), FakeKeys(self.root), FakeArchive()
        storage.ensure_layout()
        adapters = []

        def factory(app, **kwargs):
            adapter = self.make_adapter()
            adapter.runner.ensure_user_manager = lambda: False  # the synthetic owner's user manager is already running
            for key, value in kwargs.items():
                if value is not None:
                    setattr(adapter, key, value)
            adapters.append(adapter)
            return adapter

        deps = flows.Deps(storage=storage, keys=keys, archive=archive,
                          load_catalog=lambda: catalog.Catalog({self.app.id: self.app}), adapter_factory=factory,
                          host_info=lambda: dict(HOST))
        ctx = flows.FlowContext(self.paths, 'j20261127T010000Z-1234abcd', deps, FakeReporter())
        packed = flows._package(ctx, [self.app], self.staging, include_images=False, note=haimport.NOTE_PREFIX + 'instance',
                               backup_type='manual', key=keys.device_key(), phases=False, manifest_apps=[manifest],
                               entries=entries, downtime=0)
        self.paths.data.mkdir(mode=0o700, parents=True, exist_ok=True)
        haimport.register(self.paths, packed['backup_id'], ha_registry_row(apps=(self.app.id,)))
        self.assertTrue(flows.from_ha(self.paths, packed['backup_id']), 'use the real converted-backup registry boundary')
        self.owner.fail_import_once = True
        with self.assertRaises(flows.RolledBack):
            flows.run_restore(ctx, {'backup_id': packed['backup_id'], 'apps': [self.app.id]})
        self.assertEqual(self.owner.instance, original)
        self.assertEqual(self.owner.roles, roles)
        self.assertEqual(self.owner.secrets, original_secrets)
        self.assertEqual(self.owner.files[f'.config/{self.app_id}/app.env'], original_config,
                         'full current safety rollback restores the current authentication config too')
        safety = [w['manifest']['apps'][0] for w in archive.writes if w['manifest']['type'] == 'safety']
        self.assertTrue(safety)
        self.assertNotIn('ha_database', safety[-1]['postgres'][0])
        self.assertTrue(safety[-1]['verify_digests'][0]['roles'])
        self.assertTrue(any(any(r['match'] is True for r in a.digest_results) for a in adapters),
                        'rollback compares the current full-instance digest, including password hashes')


class LiteLlmInstanceTests(HaInstanceTests):
    app_id = 'litellm'
    application_database = 'litellm'

