"""Trusted catalog validation and loading (CONTRACT section 4). Owner: E2."""
import copy
import hashlib
import json
import os
import tempfile
import types
import unittest
from pathlib import Path

from woowbackup import catalog
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

USERS = {
    'appowner': types.SimpleNamespace(pw_name='appowner', pw_uid=1001, pw_gid=1001, pw_dir='/home/appowner'),
    'rootalias': types.SimpleNamespace(pw_name='rootalias', pw_uid=0, pw_gid=0, pw_dir='/root'),
}


def lookup(name):
    return USERS[name]


def demo_entry(paths):
    return {
        'schema': 1, 'id': 'woowbk-demo', 'name': '示範筆記應用', 'description': 'PostgreSQL、檔案與密鑰的備份還原示範應用',
        'owner': 'appowner', 'adapter': 'quadlet-postgres',
        'quadlet': {'files': ['woowbk-demo.network', 'woowbk-demo-db.container', 'woowbk-demo-app.container'],
                    'template_dir': str(paths.templates / 'woowbk-demo' / 'quadlet')},
        'units': ['woowbk-demo-db.service', 'woowbk-demo-app.service'],
        'writer_units': ['woowbk-demo-app.service'],
        'postgres': [{'id': 'main', 'container': 'woowbk-demo-db', 'unit': 'woowbk-demo-db.service',
                      'database': 'notes', 'user': 'notes', 'data_volume': 'woowbk-demo-pgdata'}],
        'volumes': [{'name': 'woowbk-demo-files', 'label': '上傳檔案'}],
        'secrets': [{'name': 'woowbk-demo-db-password'}, {'name': 'woowbk-demo-app-key'}],
        'config_files': [{'path': '.config/woowbk-demo/app.env', 'mode': '0600'}],
        'health': [{'type': 'http', 'url': 'http://127.0.0.1:18090/healthz', 'expect_status': 200, 'timeout_seconds': 90}],
        'verify': [{'id': 'summary', 'type': 'http-json', 'url': 'http://127.0.0.1:18090/api/summary',
                    'compare': ['notes', 'files', 'digest', 'title', 'signatures_valid']}],
    }


class CatalogCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = Paths(base=Path(self.tmp.name))
        os.makedirs(self.paths.catalog, mode=0o755)
        os.chmod(self.paths.config, 0o755)
        os.chmod(self.paths.catalog, 0o755)
        self.uid = os.getuid()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data, mode=0o644):
        path = Path(self.paths.catalog) / name
        raw = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        path.write_bytes(raw)
        os.chmod(path, mode)
        return raw

    def load(self, **kwargs):
        kwargs.setdefault('trusted_uid', self.uid)
        kwargs.setdefault('user_lookup', lookup)
        return catalog.load_catalog(self.paths, **kwargs)

    def assert_rejected(self, mutate, code='invalid-request'):
        entry = demo_entry(self.paths)
        mutate(entry)
        with self.assertRaises(BackupError) as caught:
            catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        return caught.exception


class ValidEntryTests(CatalogCase):
    def test_contract_example_loads_with_defaults_and_file_digest(self):
        raw = self.write('woowbk-demo.json', demo_entry(self.paths))
        loaded = self.load()
        self.assertEqual(loaded.problems, [])
        app = loaded['woowbk-demo']
        self.assertEqual(app.owner, 'appowner')
        self.assertEqual(app.units, ('woowbk-demo-db.service', 'woowbk-demo-app.service'))
        self.assertEqual(app.writer_units, ('woowbk-demo-app.service',))
        self.assertEqual(app.postgres[0]['data_volume'], 'woowbk-demo-pgdata')
        self.assertEqual(app.health[0]['timeout_seconds'], 90)
        self.assertEqual(app.verify[0]['compare'][0], 'notes')
        self.assertEqual(app.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(app.template_dir, str(self.paths.templates / 'woowbk-demo' / 'quadlet'))

    def test_optional_sections_default_to_empty(self):
        entry = demo_entry(self.paths)
        for key in ('description', 'writer_units', 'postgres', 'volumes', 'secrets', 'config_files', 'health', 'verify'):
            entry.pop(key)
        entry['quadlet'].pop('template_dir')
        app = catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)
        self.assertEqual((app.postgres, app.secrets, app.template_dir, app.description), ((), (), None, ''))

    def test_health_defaults(self):
        entry = demo_entry(self.paths)
        entry['health'] = [{'type': 'http', 'url': 'http://localhost:8080/'}]
        app = catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)
        self.assertEqual(app.health[0], {'type': 'http', 'url': 'http://localhost:8080/', 'expect_status': 200,
                                         'timeout_seconds': 60})

    def test_missing_directory_is_an_empty_catalog(self):
        paths = Paths(base=Path(self.tmp.name) / 'nothing')
        loaded = catalog.load_catalog(paths, trusted_uid=self.uid, user_lookup=lookup)
        self.assertEqual((dict(loaded), loaded.problems), ({}, []))


class StrictValidationTests(CatalogCase):
    def test_unknown_keys_rejected_everywhere(self):
        self.assert_rejected(lambda e: e.update(extra=1))
        self.assert_rejected(lambda e: e['quadlet'].update(more='x'))
        self.assert_rejected(lambda e: e['postgres'][0].update(password='x'))
        self.assert_rejected(lambda e: e['volumes'][0].update(path='/x'))
        self.assert_rejected(lambda e: e['secrets'][0].update(value='x'))
        self.assert_rejected(lambda e: e['config_files'][0].update(owner='root'))
        self.assert_rejected(lambda e: e['health'][0].update(method='POST'))
        self.assert_rejected(lambda e: e['verify'][0].update(headers={}))

    def test_missing_required_and_schema(self):
        self.assert_rejected(lambda e: e.pop('units'))
        self.assert_rejected(lambda e: e['postgres'][0].pop('data_volume'))
        self.assert_rejected(lambda e: e.update(schema=2))
        self.assert_rejected(lambda e: e.update(schema=True))

    def test_id_rules(self):
        for bad in ('A-demo', 'a', '-demo', 'demo_app', 'x' * 42, 'de mo', 7):
            self.assert_rejected(lambda e, bad=bad: e.update(id=bad))

    def test_text_fields(self):
        self.assert_rejected(lambda e: e.update(name=''))
        self.assert_rejected(lambda e: e.update(name='bad\nname'))
        self.assert_rejected(lambda e: e.update(description='x' * 501))
        self.assert_rejected(lambda e: e.update(adapter='shell-script'))

    def test_owner_rules(self):
        self.assert_rejected(lambda e: e.update(owner='root'))
        self.assert_rejected(lambda e: e.update(owner='Bad'))
        self.assert_rejected(lambda e: e.update(owner='rootalias'))
        error = self.assert_rejected(lambda e: e.update(owner='ghost'), code='owner-missing')
        self.assertIn('ghost', error.message)

    def test_unit_rules(self):
        self.assert_rejected(lambda e: e.update(units=['woowbk-demo.socket']))
        self.assert_rejected(lambda e: e.update(units=['../x.service']))
        self.assert_rejected(lambda e: e.update(units=[]))
        self.assert_rejected(lambda e: e.update(units=['a.service', 'a.service']))
        self.assert_rejected(lambda e: e.update(writer_units=['other.service']))
        self.assert_rejected(lambda e: e.update(writer_units=['woowbk-demo-db.service', 'woowbk-demo-app.service']))

    def test_postgres_rules(self):
        self.assert_rejected(lambda e: e['postgres'][0].update(unit='other.service'))
        self.assert_rejected(lambda e: e['postgres'][0].update(database='notes; drop'))
        self.assert_rejected(lambda e: e['postgres'][0].update(user='-U'))
        self.assert_rejected(lambda e: e['postgres'][0].update(container='-it'))
        self.assert_rejected(lambda e: e['postgres'].append(dict(e['postgres'][0])))
        self.assert_rejected(lambda e: e['volumes'].append({'name': 'woowbk-demo-pgdata'}))

    def test_name_rules(self):
        self.assert_rejected(lambda e: e['volumes'][0].update(name='-v'))
        self.assert_rejected(lambda e: e['volumes'].append({'name': 'woowbk-demo-files'}))
        self.assert_rejected(lambda e: e['secrets'][0].update(name='a/b'))
        self.assert_rejected(lambda e: e['secrets'].append({'name': 'woowbk-demo-app-key'}))
        self.assert_rejected(lambda e: e['quadlet'].update(files=['x.service']))
        self.assert_rejected(lambda e: e['quadlet'].update(files=['../x.container']))
        self.assert_rejected(lambda e: e['quadlet'].update(files=[]))

    def test_config_path_rules(self):
        for bad in ('/etc/passwd', '.config/../.ssh/authorized_keys', '.config//x', '.config/./x', '.ssh/config',
                    'Documents/x', '.config/systemd/user/evil.service', '.config/containers/systemd/x.container',
                    '.config/x\ny', '.local/share/'):
            self.assert_rejected(lambda e, bad=bad: e['config_files'][0].update(path=bad))
        entry = demo_entry(self.paths)
        entry['config_files'][0]['path'] = '.local/share/woowbk-demo/state.json'
        catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)

    def test_config_paths_stay_in_the_apps_own_directories(self):
        # Review SEC-8: user units, the user manager's environment, the Podman configuration and autostart
        # entries could be defined by archive bytes when a catalog declared such a path.
        for bad in ('.local/share/systemd/user/x.service', '.config/environment.d/50-x.conf',
                    '.config/containers/containers.conf', '.config/autostart/x.desktop', '.config/other-app/app.env',
                    '.config/woowbk-demo-evil/app.env', '.config/woowbk-demo'):
            self.assert_rejected(lambda e, bad=bad: e['config_files'][0].update(path=bad))
        for app_id in ('systemd', 'containers', 'autostart'):
            entry = demo_entry(self.paths)
            entry['id'] = app_id
            entry['config_files'][0]['path'] = f'.config/{app_id}/x.conf'
            with self.assertRaises(BackupError):
                catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)
        entry = demo_entry(self.paths)
        entry['config_files'][0]['path'] = '.config/woowbk-demo/nested/dir/app.toml'
        catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)

    def test_mode_rules(self):
        for good in ('0644', '0600', '0400', '0640'):
            entry = demo_entry(self.paths)
            entry['config_files'][0]['mode'] = good
            catalog.validate_entry(entry, paths=self.paths, user_lookup=lookup)
        for bad in ('0664', '0755', '0622', '0611', '0700', '644', '0o644', 0o644, '06444'):
            self.assert_rejected(lambda e, bad=bad: e['config_files'][0].update(mode=bad))

    def test_template_dir_rules(self):
        root = str(self.paths.templates)
        for bad in ('/usr/share/evil', f'{root}/../evil', f'{root}', 'relative/dir', f'{root}/demo/../../x',
                    f'{root}//demo'):
            self.assert_rejected(lambda e, bad=bad: e['quadlet'].update(template_dir=bad))

    def test_url_rules(self):
        for bad in ('https://127.0.0.1:8080/x', 'http://10.0.0.1:8080/x', 'http://127.0.0.1/x', 'http://127.0.0.1:0/x',
                    'http://127.0.0.1:70000/x', 'http://127.0.0.1:80@evil.example/x', 'http://localhost:80/x#frag',
                    'http://LOCALHOST:80/x', 'http://127.0.0.1:80', 'http://127.0.0.1:80/a b', 'http://[::1]:80/'):
            self.assert_rejected(lambda e, bad=bad: e['health'][0].update(url=bad))
            self.assert_rejected(lambda e, bad=bad: e['verify'][0].update(url=bad))

    def test_health_and_verify_types(self):
        self.assert_rejected(lambda e: e['health'][0].update(expect_status=True))
        self.assert_rejected(lambda e: e['health'][0].update(expect_status='200'))
        self.assert_rejected(lambda e: e['health'][0].update(timeout_seconds=0))
        self.assert_rejected(lambda e: e['health'][0].update(type='tcp'))
        self.assert_rejected(lambda e: e['verify'][0].update(type='http'))
        self.assert_rejected(lambda e: e['verify'][0].update(compare=[]))
        self.assert_rejected(lambda e: e['verify'][0].update(compare=['a', 'a']))
        self.assert_rejected(lambda e: e['verify'].append(copy.deepcopy(e['verify'][0])))


class FileSecurityTests(CatalogCase):
    def problems(self, loaded):
        return [(p['file'], p['code']) for p in loaded.problems]

    def test_symlinked_entry_is_reported_not_loaded(self):
        real = Path(self.tmp.name) / 'elsewhere.json'
        real.write_text(json.dumps(demo_entry(self.paths)))
        os.symlink(real, Path(self.paths.catalog) / 'woowbk-demo.json')
        loaded = self.load()
        self.assertEqual(dict(loaded), {})
        self.assertEqual(self.problems(loaded), [('woowbk-demo.json', 'permission-denied')])

    def test_group_or_world_writable_entry_rejected(self):
        for mode in (0o664, 0o646):
            self.write('woowbk-demo.json', demo_entry(self.paths), mode=mode)
            loaded = self.load()
            self.assertNotIn('woowbk-demo', loaded)
            self.assertEqual(self.problems(loaded), [('woowbk-demo.json', 'permission-denied')])

    def test_wrong_owner_rejected_unless_trusted_uid_matches(self):
        self.write('woowbk-demo.json', demo_entry(self.paths))
        self.assertNotIn('woowbk-demo', self.load(trusted_uid=self.uid + 4242))
        self.assertIn('woowbk-demo', self.load(trusted_uid=self.uid))

    def test_production_default_requires_root_owner(self):
        self.write('woowbk-demo.json', demo_entry(self.paths))
        if self.uid == 0:
            self.skipTest('running as root')
        loaded = catalog.load_catalog(self.paths, user_lookup=lookup)
        self.assertEqual(dict(loaded), {})
        self.assertEqual(loaded.problems[0]['code'], 'permission-denied')

    def test_unsafe_catalog_directory_loads_nothing(self):
        self.write('woowbk-demo.json', demo_entry(self.paths))
        os.chmod(self.paths.catalog, 0o777)
        loaded = self.load()
        self.assertEqual(dict(loaded), {})
        self.assertEqual(loaded.problems[0]['code'], 'permission-denied')

    def test_symlinked_catalog_directory_loads_nothing(self):
        real = Path(self.tmp.name) / 'real-apps'
        real.mkdir(mode=0o755)
        (real / 'woowbk-demo.json').write_text(json.dumps(demo_entry(self.paths)))
        os.rmdir(self.paths.catalog)
        os.symlink(real, self.paths.catalog)
        loaded = self.load()
        self.assertEqual(dict(loaded), {})
        self.assertEqual(loaded.problems[0]['code'], 'permission-denied')

    def test_unsafe_config_parent_loads_nothing(self):
        self.write('woowbk-demo.json', demo_entry(self.paths))
        os.chmod(self.paths.config, 0o775)
        loaded = self.load()
        self.assertEqual(dict(loaded), {})

    def test_filename_must_match_id_and_duplicates(self):
        self.write('other-name.json', demo_entry(self.paths))
        loaded = self.load()
        self.assertEqual(dict(loaded), {})
        self.assertIn('woowbk-demo.json', loaded.problems[0]['message'])

    def test_bad_json_variants(self):
        good = json.dumps(demo_entry(self.paths))
        cases = {
            'dup': good[:-1] + ', "id": "woowbk-demo"}',
            'nan': good.replace('"expect_status": 200', '"expect_status": NaN'),
            'trunc': good[:50],
        }
        for label, text in cases.items():
            self.write('woowbk-demo.json', text.encode())
            loaded = self.load()
            self.assertEqual(dict(loaded), {}, label)
            self.assertEqual(loaded.problems[0]['code'], 'invalid-request', label)
        self.write('woowbk-demo.json', b'\xff\xfe{}')
        self.assertEqual(self.load().problems[0]['code'], 'invalid-request')

    def test_oversized_entry(self):
        entry = demo_entry(self.paths)
        entry['description'] = 'x' * 400
        raw = json.dumps(entry).encode() + b' ' * (catalog.MAX_ENTRY_BYTES + 10)
        self.write('woowbk-demo.json', raw)
        self.assertEqual(self.load().problems[0]['code'], 'limit-exceeded')

    def test_owner_missing_is_reported_with_app_id(self):
        entry = demo_entry(self.paths)
        entry['owner'] = 'ghost'
        self.write('woowbk-demo.json', entry)
        loaded = self.load()
        self.assertEqual(dict(loaded), {})
        problem = loaded.problem_for('woowbk-demo')
        self.assertEqual(problem['code'], 'owner-missing')

    def test_non_json_files_and_hidden_files_ignored(self):
        self.write('README.txt', b'not a catalog')
        self.write('.woowbk-demo.json.tmp', demo_entry(self.paths))
        self.write('woowbk-demo.json', demo_entry(self.paths))
        loaded = self.load()
        self.assertEqual(list(loaded), ['woowbk-demo'])
        self.assertEqual(loaded.problems, [])

    def test_directory_named_json_is_reported(self):
        os.mkdir(Path(self.paths.catalog) / 'woowbk-x.json')
        loaded = self.load()
        self.assertEqual(loaded.problems[0]['code'], 'invalid-request')


if __name__ == '__main__':
    unittest.main()
