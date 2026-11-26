"""N8-01/L-03: complete conversion payloads, live instance preservation and full safety rollback.

The owner models rows, database ownership and role/password state; no host containers or services are used.
"""
import base64
import copy
import hashlib
import json
import re

from woowbackup import catalog, flows, haimport, podman
from woowbackup.adapters import quadlet_postgres as qp
from woowbackup.errors import BackupError

from .test_adapter import PODMAN, VOLUME_TAR, extract_entries
from .test_flows import FakeArchive, FakeKeys, FakeReporter, FakeStorage, HOST, ha_registry_row
from .test_strengthen import StrengthCase, StrengthOwner, dump_of
from .test_catalog import lookup as user_lookup


def encoded(name, info):
    body = dict(info, data=base64.b64encode(info['data']).decode())
    return dump_of(name, json.dumps(body, sort_keys=True).encode())


class InstanceOwner(StrengthOwner):
    application_database = 'notes'
    def __init__(self):
        super().__init__(instance=True)
        self.roles = {name: {'superuser': name == 'notes', 'login': name != 'readonly',
                             'password': hashlib.sha256(name.encode()).hexdigest()}
                      for name in ('notes', 'oc_admin', 'readonly')}
        self.fail_import_once = False

    def reinit(self):
        super().reinit()
        if self.application_database != 'notes':
            self.instance[self.application_database] = self.instance.pop('notes')
        self.roles = {'notes': {'superuser': True, 'login': True, 'password': 'image-default'}}

    def role_rows(self):
        return [[[name, row['superuser'], True, False, False, row['login'], False, False, -1, None,
                  hashlib.md5(row['password'].encode()).hexdigest()] for name, row in sorted(self.roles.items())], []]

    def psql_file(self, database, sql, stdout):
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
            if 'pg_restore' in args and '-f' not in args:
                name, raw = data.split(b':', 2)[1:]
                info = json.loads(raw)
                info['data'] = base64.b64decode(info['data'])
                for arg in args:
                    if arg.startswith('--role='):
                        info['owner'] = arg.split('=', 1)[1]
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
        converted.write_bytes(encoded(name, {'owner': 'notes', 'data': b'HA rows', 'extensions': []}))
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
        if self.app_id == 'litellm':
            self.owner.secrets['litellm-salt-key'] = b'rotated-device-salt'
        self.owner.roles['new_owner'] = {'superuser': False, 'login': True, 'password': 'new-password-hash'}
        self.owner.instance['new_db'] = {'owner': 'new_owner', 'data': b'new rows', 'extensions': []}
        self.owner.instance[self.application_database]['owner'] = 'new_owner'

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

    def test_later_outside_writes_databases_owners_and_passwords_are_preserved(self):
        manifest, folder, _entries = self.converted()
        self.later_changes()
        outside = {n: copy.deepcopy(v) for n, v in self.owner.instance.items() if n != self.application_database}
        roles = copy.deepcopy(self.owner.roles)
        secrets = copy.deepcopy(self.owner.secrets)
        if self.app_id == 'litellm':
            secrets['litellm-salt-key'] = b'HA salt fixture'
        self.adapter.restore(manifest, folder, mode='inplace')
        self.assertEqual({n: v for n, v in self.owner.instance.items() if n != self.application_database}, outside)
        self.assertEqual(self.owner.roles, roles)
        self.assertEqual(self.owner.secrets, secrets)
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
        self.assertTrue(self.owner.applied_globals)

    def test_ordinary_restore_keeps_its_full_instance_semantics(self):
        manifest, folder, _entries = self.converted()
        original = copy.deepcopy(self.owner.instance)
        roles = copy.deepcopy(self.owner.roles)
        self.later_changes()
        self.adapter.ha_import = False
        self.adapter.restore(manifest, folder, mode='inplace')
        self.assertEqual(set(self.owner.instance), set(original))
        self.assertEqual(self.owner.instance['nextcloud'], original['nextcloud'])
        self.assertEqual(self.owner.roles, roles)

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
        manifest, _folder, entries = self.converted()
        self.later_changes()
        original, roles = copy.deepcopy(self.owner.instance), copy.deepcopy(self.owner.roles)
        original_secrets = copy.deepcopy(self.owner.secrets)
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
        safety = [w['manifest']['apps'][0] for w in archive.writes if w['manifest']['type'] == 'safety']
        self.assertTrue(safety)
        self.assertNotIn('ha_database', safety[-1]['postgres'][0])
        self.assertTrue(safety[-1]['verify_digests'][0]['roles'])
        self.assertTrue(any(any(r['match'] is True for r in a.digest_results) for a in adapters),
                        'rollback compares the current full-instance digest, including password hashes')


class LiteLlmInstanceTests(HaInstanceTests):
    app_id = 'litellm'
    application_database = 'litellm'

