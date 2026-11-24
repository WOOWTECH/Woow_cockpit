"""Offline rules of litellm_negative_flow.py (no device, no Podman): the crafted backup is one the product's readers
take as the LiteLLM add-on, the expected messages are the product's own texts, and no label leaves the fixed
evidence vocabulary."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'backup-engine'))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


neg = _load('litellm_negative_flow')
capture = _load('services_a_capture')

from woowbackup import habackup, ha_litellm, ha_odoo, hacommon, hastore  # noqa: E402

FILES = {'salt_key': 'sk-' + 'a1' * 32, 'master_key': 'sk-' + 'b2' * 32, 'pg_password': 'c3' * 24, 'ui_password': 'd4' * 24}


def fake_export(path):
    """A `podman volume export`-shaped tar of a tiny cluster directory named craft."""
    with tarfile.open(path, 'w') as tar:
        def add(name, data=None):
            info = tarfile.TarInfo(name)
            info.mode, info.uid, info.gid = 0o700 if data is None else 0o600, 70, 70
            info.type = tarfile.DIRTYPE if data is None else tarfile.REGTYPE
            info.size = len(data or b'')
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
        add('./')
        add('./craft')
        add('./craft/PG_VERSION', b'18\n')
        add('./craft/global')
        add('./craft/global/pg_control', b'x' * 8192)
        add('./craft/base')
        add('./craft/base/1')


class CraftedBackup(unittest.TestCase):
    def build(self, base, **kw):
        export = base / 'clean-volume.tar'
        fake_export(export)
        return neg.write_backup(export, base / 'neg.tar', FILES, **kw)

    def test_the_product_readers_take_it_as_the_litellm_add_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            path = self.build(base)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(p.name for p in base.iterdir()), ['clean-volume.tar', 'neg.tar'])
            with habackup.open_backup(path) as ha:
                members = [m for m in ha.layout.members if m.role == 'addon']
                self.assertEqual([hastore.addon_suffix(m.slug) for m in members], ['woow-litellm'])
                with ha.open_member(members[0].name) as stream:
                    info = habackup.read_addon_info(stream)
                self.assertEqual((info.slug, info.version), ('woow-litellm', neg.VERSION))
                with ha.open_member(members[0].name) as stream:
                    out = io.BytesIO()
                    sink = ha_odoo.PgSink(out, 70, 70)
                    src = ha_litellm.scan_member(stream, habackup.Report(), pg=sink)
                    sink.close()
        self.assertEqual((src.pg_version, src.symlinks, src.salt_valid, src.state_version), ('18', 0, True, '1.104.0'))
        self.assertEqual(src.salt().decode(), FILES['salt_key'])

    def test_the_version_and_salt_cases_change_only_what_they_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.build(Path(tmp), version=neg.OTHER_VERSION)
            with habackup.open_backup(path) as ha:
                member = [m for m in ha.layout.members if m.role == 'addon'][0]
                with ha.open_member(member.name) as stream:
                    self.assertEqual(habackup.read_addon_info(stream).version, neg.OTHER_VERSION)
        self.assertIsNone(ha_litellm.VERSIONS.upstream(neg.OTHER_VERSION))
        self.assertEqual(ha_litellm.VERSIONS.upstream(neg.VERSION), neg.UPSTREAM)

    def test_a_special_file_in_the_cluster_is_never_packed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            export = base / 'x-volume.tar'
            with tarfile.open(export, 'w') as tar:
                info = tarfile.TarInfo('craft/pg_wal')
                info.type, info.linkname = tarfile.SYMTYPE, '/etc'
                tar.addfile(info)
            with self.assertRaises(neg.Failed):
                neg.write_backup(export, base / 'neg.tar', FILES)


class Expectations(unittest.TestCase):
    def run_(self):
        return neg.NegativeRun(mock.Mock(), mock.Mock())

    def test_the_wanted_words_are_the_products_own_texts(self):
        run = self.run_()
        self.assertIn(run.wanted('salt')[0], ha_litellm.SALT_MISMATCH)
        self.assertTrue(run.wanted('salt')[0].startswith('HA 備份裡的加密金鑰（salt_key）'))
        blocker = ha_litellm.VERSIONS.blocker(neg.OTHER_VERSION, neg.UPSTREAM)
        self.assertIn(run.wanted('version')[0], blocker)
        self.assertIn(neg.OTHER_VERSION, run.wanted('version')[0])
        words, labels = run.wanted('hooks')
        text = ha_litellm.stored_hooks_blocker({'hooks': list(labels)})
        self.assertIn(words, text)
        self.assertTrue(all(label in text for label in labels))
        self.assertLessEqual(len(labels), 10, 'hacommon.names shows ten names')
        self.assertIn('等', hacommon.names([str(n) for n in range(11)]))
        # an unreadable answer is another message: the real run must see the hooks themselves
        self.assertNotIn(words, ha_litellm.stored_hooks_blocker(dict(ha_litellm.UNREADABLE)))

    def test_every_hook_kind_is_one_the_product_lists(self):
        known = {f'{a}.{b}' for a, b in ha_litellm.MODULE_HOOKS} | {f'{a}.{b}' for a, b, _p in ha_litellm.NESTED_HOOKS}
        known |= {f'litellm_settings.{key}' for key in ha_litellm.CALLBACK_KEYS}
        self.assertLessEqual(set(neg.HOOK_LABELS) | set(neg.HIDDEN_LABELS), known)
        plain = neg.HOOK_ROWS['litellm_settings']['success_callback'][:-1]
        self.assertEqual((len(plain), [v for v in plain if '.' in v]), (60, []))

    def test_the_operator_edit_is_the_reviews_and_hides_exactly_the_hidden_hooks(self):
        self.assertTrue(neg.OPERATOR_SQL.startswith('CREATE FUNCTION public.woowbk_texteq'))
        self.assertIn('pg_operator', neg.OPERATOR_SQL)
        self.assertNotIn('LiteLLM_Config', neg.OPERATOR_SQL)
        for label in neg.HIDDEN_LABELS:
            self.assertIn(f"'{label.split('.', 1)[1]}'", neg.OPERATOR_SQL)
        sql = neg.config_sql(neg.HIDDEN_ROWS)
        self.assertEqual(sql.count('INSERT INTO'), 2)
        self.assertTrue(sql.startswith('DELETE FROM public."LiteLLM_Config";'))

    def test_the_salt_binding_is_the_one_the_product_checks(self):
        sql = neg.bind_sql(FILES['salt_key'])
        import hashlib
        self.assertIn(hashlib.sha256(b'woow-litellm-salt-v1:' + FILES['salt_key'].encode()).hexdigest()[:16], sql)
        self.assertIn("WHERE key = 'litellm_salt_key'", sql)

    def test_generated_secrets_only_and_the_leak_scan_has_enough_names(self):
        class Values(dict):
            names = frozenset()

            def __init__(self):
                super().__init__(HA_BACKUP_KEY='k', LITELLM_TEST_VKEY='v')
                self.values = dict(self)

            def register(self, name, value):
                self[name] = value
                self.values = {**self.values, name: value}
        run = self.run_()
        run.args.secrets = Values()
        with mock.patch.object(neg.flow, 'ha_secret_files', side_effect=AssertionError('the real backup is never read')):
            run.load_secrets()
        wanted = [n for n in run.args.secrets.values if n.startswith(
            ('HA_BACKUP_KEY', 'LITELLM_TEST_VKEY', 'HA_LITELLM_', 'OWN_', 'WRONG_SALT'))]
        self.assertGreaterEqual(len(wanted), 8)
        self.assertNotEqual(run.files['salt_key'], run.args.secrets['HA_LITELLM_CRAFTED_OTHER_SALT'])
        self.assertTrue(ha_litellm.SALT_RE.fullmatch(run.files['salt_key'].encode()))

    def test_every_public_label_fits_the_fixed_evidence_vocabulary(self):
        source = (HERE / 'litellm_negative_flow.py').read_text(encoding='utf-8')
        self.assertGreater(source.count('ev.check('), 12)
        for case in ('salt', 'version', 'hooks', 'hidden'):
            for text in (f'{case}: the check refuses with the specific message',
                         f'{case}: the conversion ends failed with the specific message (nothing converted)'):
                line = f'{neg.flow.label(text)}: PASS'
                self.assertEqual(capture.status_lines(line), [line])
        self.assertEqual(capture.status_lines('litellm negative flow: 60/60 PASS'), ['litellm negative flow: 60/60 PASS'])


class PlantedObjects(unittest.TestCase):
    """litellm_sandbox_review.py --case planted_objects (the lane verifier's list, 2026-11-24 02:14)."""

    def test_every_named_kind_is_planted_by_the_database_owner_and_counted(self):
        review = neg.review
        sql = review.PLANTED_SQL
        self.assertTrue(sql.strip().startswith('SET ROLE litellm;') and sql.strip().endswith('RESET ROLE;'))
        for words in ('CREATE DOMAIN', 'CREATE TRIGGER', 'ENABLE ALWAYS TRIGGER', 'CREATE POLICY', 'FORCE ROW LEVEL SECURITY',
                      'CREATE RULE', 'CREATE INDEX', 'ADD CONSTRAINT', 'CREATE EXTENSION', 'lo_create'):
            self.assertIn(words, sql)
        self.assertNotIn('SUPERUSER', sql)
        for key in ('domains', 'triggers', 'policies', 'rules', 'expression_indexes', 'check_constraints', 'extensions',
                    'large_objects'):
            self.assertIn(f"'{key}'", review.PLANTED_OBJECTS_SQL)

    def test_the_data_shape_rule_names_a_planted_domain_and_table(self):
        empty = {key: [] for key in ha_litellm.SIGNATURE_KEYS}
        base = [['public', 't', 'a', 'text', False, '', '']]
        clean = ha_litellm.Schema(base, dict(empty, types=[]), ['m1'])
        planted = ha_litellm.Schema(base + [['public', 'woowbk_domain_table', 'v', 'public.woowbk_domain', False, '', '']],
                                    dict(empty, types=[['public', 'woowbk_domain', 'd', 'text', False, '', []]]), ['m1'])
        self.assertEqual(ha_litellm.schema_differences(planted, clean),
                         ['public.woowbk_domain', 'public.woowbk_domain_table'])


if __name__ == '__main__':
    unittest.main()
