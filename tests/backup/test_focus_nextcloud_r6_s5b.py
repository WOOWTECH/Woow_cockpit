"""Offline tests of the S5-B import-acceptance driver (focus_nextcloud_r6_s5b). No lab, device, credential or host podman.

The product is THIS repository's backup-engine (tests/backup/__init__.py). Device programs run locally against
temporary directories (rendered with `programs(overrides)`); the end-to-end simulation drives the real R6 machinery
(focus_nextcloud_r6_case.run, focus_nextcloud_r6.run_locked) with every device boundary replaced by a fake dev-e.
"""
import base64
import contextlib
import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1] / 'e2e/lab'
sys.path.insert(0, str(LAB))
import focus_nextcloud_r6 as r6   # noqa: E402
import focus_nextcloud_r6_case as case   # noqa: E402
import focus_nextcloud_r6_cold as cold   # noqa: E402
import focus_nextcloud_r6_s5 as s5   # noqa: E402
import focus_nextcloud_r6_s5b as s5b   # noqa: E402
import focus_nextcloud_r6_source as source   # noqa: E402
import focus_nextcloud_r6_upload as upload   # noqa: E402
import focus_nextcloud_r6_wake as wake   # noqa: E402
from focus_nextcloud_r6_plan import lease_check   # noqa: E402
from woowbackup import cli, haimport, haissues, hacommon, habackup, ha_nextcloud, ha_odoo   # noqa: E402
from woowbackup.errors import BackupError   # noqa: E402

REPO = Path(__file__).resolve().parents[2]
MASTER = 'master_0123abcd'
LIBRARIES = lambda: (habackup, ha_nextcloud, ha_odoo)   # noqa: E731 - the repository's own engine
GIB = 1024 ** 3


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def key_bytes(seed):
    """A key file in the native layout (hex ciphertext|hex iv|hex hmac|3); not key material."""
    h = sha(seed.encode())
    return (h * 2 + '|' + h[:32] + '|' + h + '|3').encode()


def header_block(fields=None):
    fields = dict(s5.HEADER) if fields is None else fields
    raw = ('HBEGIN:' + ''.join(k + ':' + v + ':' for k, v in fields.items()) + 'HEND').encode()
    return raw + b'-' * (s5.HEADER_SIZE - len(raw))


def provenance():
    """A compact provenance (what the state program returns) of a small structural S5-A source."""
    plain = s5.plaintexts()
    before = {n: {'bytes': len(v), 'sha256': sha(v)} for n, v in plain['before'].items()}
    encrypted = {n: {'bytes': len(v), 'sha256': sha(v)} for n, v in plain['encrypted'].items()}
    user = dict(before)
    for n, v in plain['encrypted'].items():
        user[n] = {'bytes': len(v) + 8192 + 64, 'sha256': sha(b'cipher:' + n.encode())}
    for i in range(12):
        user[f'Skeleton/file {i:02d}.txt'] = {'bytes': 100 + i, 'sha256': sha(b'skeleton %d' % i)}
    keys = {}
    for suffix in ('publicKey', 'privateKey'):
        keys[f'files_encryption/OC_DEFAULT_MODULE/{MASTER}.{suffix}'] = {'bytes': 200, 'sha256': sha(suffix.encode())}
        keys[f'files_encryption/OC_DEFAULT_MODULE/pubShare_89abcdef.{suffix}'] = {'bytes': 201, 'sha256': sha(b'p' + suffix.encode())}
    for n in encrypted:
        keys[f'{s5b.USER}/files_encryption/keys/files/{n}/OC_DEFAULT_MODULE/{MASTER}.shareKey'] = {'bytes': 300, 'sha256': sha(n.encode())}
    return {'master_key_id': MASTER, 'plaintext': {'before': before, 'encrypted': encrypted}, 'encrypted': sorted(encrypted),
            'user_files': user, 'key_files': keys, 'data_files': len(user) + len(keys) + 2,
            'facts': {'core_encryption_enabled': {'value': '1', 'type': 'boolean'}}}


def sse_issue():
    """The confirmation exactly as the product's check emits it (haissues.Issue.view)."""
    return haissues.Issue(s5b.SSE_ID, 'confirm', ha_nextcloud.MSG_ENCRYPTION, list(s5b.SSE_REASONS))


def settings_text(keys=('memcache.distributed', 'memcache.locking', 'redis', 'upgrade.disable-web')):
    return f'HA 的 Nextcloud 設定 {hacommon.names(keys)} 不會搬過來（以這台的設定為準）。'


def lists_text(container='nextcloud-app'):
    return (ha_nextcloud.MSG_LISTS.format(count=1, names=hacommon.names([s5b.USER])) + '匯入後請在這台執行一次檔案掃描（'
            + ha_nextcloud.SCAN_COMMAND.format(container=container) + '）。')


def check_job(issues=None, *, state='succeeded', section=None, **app):
    issues = [sse_issue(), *haissues.from_legacy(warnings=[settings_text()])] if issues is None else issues
    row = {'app_id': 'nextcloud', 'arch': 'amd64', 'version': '0.2.3', 'target_version': '35.0.1.1',
           'nextcloud': dict(s5b.SECTION, files=80, custom_apps=[]) if section is None else section,
           **haissues.check_fields('nextcloud', issues)}
    row.update(app)
    return {'id': 'j20261128T100000Z-00000001', 'state': state, 'result': {'ha_check': {'apps': [row]}}}


# ====================================================================== bindings and the lease

class ProductBindingTests(unittest.TestCase):
    def test_the_frozen_product_is_b058df27_with_the_fix_and_its_nextcloud_bytes(self):
        rows = s5b.git_manifest(REPO)
        self.assertEqual(rows['woowbackup/ha_nextcloud.py']['sha256'], s5b.NC_SHA)
        self.assertEqual(len(rows), 53)   # 51 engine modules, the helper, VERSION
        self.assertTrue(s5b.fix_included(REPO))
        blob = subprocess.check_output(['git', '-C', str(REPO), 'show', s5b.PRODUCT_COMMIT + ':backup-engine/woowbackup/ha_nextcloud.py'])
        self.assertIn(b"value.lower() in ('1', 'true', 'yes', 'on')", blob)
        self.assertEqual(sha(blob), s5b.NC_SHA)
        parent = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', s5b.FIX_COMMIT + '^'], text=True).strip()
        self.assertFalse(s5b.fix_included(REPO, commit=parent))      # a product without the fix is refused
        with self.assertRaisesRegex(ValueError, 'product-nextcloud-sha'):
            s5b.git_manifest(REPO, commit=s5b.S5A_ENGINE_COMMIT)     # an engine without the fix: the old ha_nextcloud.py

    def checkout(self, commit, root):
        """The files of `commit` as a clean checkout would hold them (git objects), without creating a worktree."""
        listing = subprocess.check_output(['git', '-C', str(REPO), 'ls-tree', '-r', '--name-only', commit, '--',
                                           'backup-engine/woowbackup', 'backup-engine/woowtech-cockpit-backup', 'VERSION'],
                                          text=True).split()
        for name in listing:
            p = root / name; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(subprocess.check_output(['git', '-C', str(REPO), 'show', f'{commit}:{name}']))

    def test_the_frozen_checkout_reader_gives_the_git_manifest_and_refuses_anything_else(self):
        rows = s5b.git_manifest(REPO)
        real = subprocess.check_output
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.checkout(s5b.PRODUCT_COMMIT, root)
            for head, dirty, reason in ((s5b.PRODUCT_COMMIT, '', None), ('0' * 40, '', 'clean-product'),
                                        (s5b.PRODUCT_COMMIT, ' M x', 'clean-product')):
                def fake(argv, **kwargs):
                    if argv[:2] == ['git', 'rev-parse']: return head + '\n'
                    if argv[:2] == ['git', 'status']: return dirty
                    return real(argv, **kwargs)
                with self.subTest(head=head, dirty=dirty), patch.object(source.subprocess, 'check_output', fake):
                    if reason:
                        with self.assertRaisesRegex(ValueError, reason): s5b.frozen_manifest(root)
                    else:
                        self.assertEqual(s5b.frozen_manifest(root)[1], rows)
            (root / 'backup-engine/woowbackup/ha_nextcloud.py').write_bytes(
                subprocess.check_output(['git', '-C', str(REPO), 'show', s5b.S5A_ENGINE_COMMIT + ':backup-engine/woowbackup/ha_nextcloud.py']))
            with patch.object(source.subprocess, 'check_output', lambda argv, **kw: s5b.PRODUCT_COMMIT if 'rev-parse' in argv else ''):
                with self.assertRaisesRegex(ValueError, 'nextcloud-sha'): s5b.frozen_manifest(root)

    def test_r6s_own_binding_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.checkout(source.PRODUCT_COMMIT, root)
            with patch.object(source.subprocess, 'check_output', lambda argv, **kw: source.PRODUCT_COMMIT if 'rev-parse' in argv else ''):
                paths, rows = source.frozen_manifest(root)
            self.assertEqual(rows['woowbackup/ha_nextcloud.py']['sha256'], source.NC_SHA)
            with patch.object(source.subprocess, 'check_output', lambda argv, **kw: source.PRODUCT_COMMIT if 'rev-parse' in argv else ''):
                with self.assertRaisesRegex(ValueError, 'clean-product'): s5b.frozen_manifest(root)   # R6's commit
            with patch.object(source.subprocess, 'check_output', lambda argv, **kw: s5b.PRODUCT_COMMIT if 'rev-parse' in argv else ''):
                with self.assertRaisesRegex(ValueError, 'nextcloud-sha'): s5b.frozen_manifest(root)   # R6's bytes
        self.assertNotEqual(s5b.PRODUCT_COMMIT, source.PRODUCT_COMMIT)
        self.assertEqual(s5b.BINDING.product_commit, s5b.PRODUCT_COMMIT)

    def test_the_s5a_result_binds_the_fixture_and_its_root(self):
        self.assertEqual(s5b.s5a_result(), sha(s5b.S5A_RESULT.read_bytes()))
        doc = json.loads(s5b.S5A_RESULT.read_text())
        self.assertTrue(s5b.FIXTURE.startswith(s5b.PROOF_ROOT + '/owned/'))
        self.assertRegex(s5b.PROOF_ROOT, s5.ROOT_RE)
        self.assertEqual(doc['fixture']['archive'], s5b.FIXTURE)
        for change in ({'status': 'failed'}, {'fixture': dict(doc['fixture'], sha256='0' * 64)},
                       {'owned_leftovers': dict(doc['owned_leftovers'], command_records=1)}, {'engine_commit': '0' * 40}):
            with self.subTest(change=sorted(change)), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / 'result.json'; p.write_text(json.dumps(dict(doc, **change)))
                with self.assertRaisesRegex(ValueError, 's5a-result'): s5b.s5a_result(p)


class LeaseTests(unittest.TestCase):
    TEMPLATE = None

    def setUp(self):
        self.now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        stack = contextlib.ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch.object(s5, 'checkout', lambda repo: ('c' * 40, True)))
        if LeaseTests.TEMPLATE is None:   # the real template once (git objects); admit_lease compares against it
            LeaseTests.TEMPLATE = (s5b.lease_template(REPO), s5b.git_manifest(REPO))
        template, self.rows = LeaseTests.TEMPLATE
        stack.enter_context(patch.object(s5b, 'lease_template', lambda repo: copy.deepcopy(template)))
        self.lease = copy.deepcopy(template)
        self.lease.update(not_before_utc=self.iso(-60), expires_utc=self.iso(120 * 60))

    def iso(self, delta):
        return datetime.datetime.fromtimestamp(self.now + delta, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')

    def admit(self, lease, rows=None, now=None):
        return s5b.admit_lease(lease, 'c' * 40, REPO, self.rows if rows is None else rows, now=self.now if now is None else now)

    def test_the_template_binds_this_checkout_and_the_recorded_s5a_engine(self):
        template = copy.deepcopy(LeaseTests.TEMPLATE[0])
        self.assertEqual(template['source_commit'], 'c' * 40)   # a clean checkout's HEAD (patched here)
        self.assertEqual(sorted(template), sorted(s5b.LEASE_KEYS))
        self.assertEqual(template['phases'], ['s5-import-acceptance'])
        self.assertEqual(template['product_manifest_sha256'], source.manifest_hash(self.rows))
        # No prior engine is bound (another lane may deploy its own before S5-B): it is captured at run time.
        self.assertFalse(any(k.startswith('prior_engine') for k in template))
        self.assertNotIn(s5.ENGINE_COMMIT, json.dumps(template))
        self.assertTrue(template['not_before_utc'].startswith('REQUIRES_') and template['expires_utc'].startswith('REQUIRES_'))
        self.assertEqual(template['original_inactive_units'], list(r6.INACTIVE_UNITS))
        self.assertIs(template['host_fixture_copy'], False)

    def test_exactly_this_lease_is_admitted_and_every_field_matters(self):
        expires = datetime.datetime.fromisoformat(self.lease['expires_utc'].replace('Z', '+00:00')).timestamp()
        self.assertEqual(self.admit(self.lease), expires)
        mutations = {'lane': 'nextcloud-s5', 'device': 'woowbk-dev-d', 'phases': ['s5-import-acceptance', 'fullshare'],
                     'source_commit': 'd' * 40, 'product_commit': source.PRODUCT_COMMIT, 'product_checkout': '/tmp/other',
                     'product_manifest_sha256': '0' * 64, 'fix_commit': '0' * 40,
                     'fixture_sha256': '0' * 64, 'fixture_bytes': 1,
                     'proof_root': '/var/lib/woowbk-nextcloud-s5-0123456789abcdef', 's5a_result_sha256': '0' * 64,
                     'provenance_sha256': '0' * 64, 'source_policy': 'keep', 'pin_refresh_policy': 'none',
                     'recovery_grace_seconds': 60, 'original_inactive_units': [], 'reserve_bytes': 12 * GIB,
                     'memory_cap_bytes': 4 * GIB, 'proof_root_removal': 'always', 'image_operations': ['pull'],
                     'host_fixture_copy': True}
        self.assertEqual(sorted(mutations), sorted(set(s5b.LEASE_KEYS) - {'not_before_utc', 'expires_utc'}))
        for field, value in mutations.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.admit(dict(self.lease, **{field: value}))
        with self.assertRaisesRegex(ValueError, 'lease-fields'):
            self.admit(dict(self.lease, retain_verified_ha_on_preconversion_refusal=True))
        with self.assertRaisesRegex(ValueError, 'lease-fields'):
            self.admit({k: v for k, v in self.lease.items() if k != 'proof_root_removal'})

    def test_the_window_is_timezone_aware_current_and_leaves_headroom(self):
        for field, value in (('expires_utc', self.iso(-1)), ('not_before_utc', self.iso(60)),
                             ('expires_utc', self.iso(120 * 60).replace('Z', '')), ('not_before_utc', 'soon')):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'lease'):
                self.admit(dict(self.lease, **{field: value}))
        with self.assertRaisesRegex(ValueError, 'lease-headroom'):
            self.admit(dict(self.lease, expires_utc=self.iso(74 * 60)))
        deadline = self.admit(self.lease)
        with self.assertRaisesRegex(ValueError, 'lease-headroom-after-lock'):
            s5b.locked_admission(self.lease, 'c' * 40, deadline, now=self.now + 50 * 60)
        s5b.locked_admission(self.lease, 'c' * 40, deadline, now=self.now + 30 * 60)

    def test_the_frozen_checkout_must_be_the_bound_one_and_contain_the_fix(self):
        other = dict(self.rows, VERSION={'size': 3, 'sha256': '0' * 64})
        with self.assertRaisesRegex(ValueError, 'frozen-checkout-manifest'):
            self.admit(self.lease, rows=other)
        with patch.object(s5b, 'fix_included', lambda repo: False), self.assertRaisesRegex(ValueError, 'fix-not-in-product'):
            self.admit(self.lease)

    def test_run_needs_the_heavy_seat_and_rechecks_after_the_blocking_lock(self):
        flags = []
        with tempfile.TemporaryDirectory() as tmp:
            lease = Path(tmp) / 'lease.json'; lease.write_text(json.dumps(self.lease))
            lock = str(Path(tmp) / 'lock')
            with patch.object(s5b, 'frozen_manifest', lambda path: ({}, self.rows)), patch.object(s5b, 'LOCK', lock), \
                    patch.object(s5b, 'run_case', side_effect=AssertionError('no device step')):
                with patch.dict(os.environ, {'HEAVY_FREE': '/tmp/other.lock'}), self.assertRaisesRegex(ValueError, 'heavy-seat'):
                    s5b.main(['--run', '--lease', str(lease)])
                def late(fd, flag):
                    flags.append(flag); self.now += 50 * 60
                with patch.dict(os.environ, {'HEAVY_FREE': lock}), patch.object(s5b.fcntl, 'flock', late), \
                        patch.object(s5b.time, 'time', lambda: self.now), \
                        self.assertRaisesRegex(ValueError, 'lease-headroom-after-lock'):
                    s5b.main(['--run', '--lease', str(lease)])
        self.assertEqual(flags, [s5b.fcntl.LOCK_EX])


class OfflineEntryTests(unittest.TestCase):
    def test_default_and_template_modes_touch_no_device(self):
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no process')), \
                patch.object(wake, 'device', side_effect=AssertionError('no device')), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(s5b.main([]), 0)
        contract = json.loads(out.getvalue())
        self.assertEqual(contract['confirmation']['key'], s5b.SSE_KEY)
        self.assertIs(contract['ha_key_needed'], False)
        self.assertEqual(contract['mutations'], 0)

    def test_script_runs_isolated_like_the_heavy_command(self):
        out = subprocess.run([sys.executable, '-B', '-I', str(LAB / 'focus_nextcloud_r6_s5b.py'), '--lease-template'],
                             cwd=REPO, capture_output=True, timeout=300, check=True)
        template = json.loads(out.stdout)
        self.assertEqual(template['product_commit'], s5b.PRODUCT_COMMIT)
        self.assertEqual(template['phases'], [s5b.PHASE])


# ====================================================================== what the product says

class ProductTextTests(unittest.TestCase):
    def test_the_driver_constants_are_the_products_own(self):
        self.assertEqual(s5b.SSE_TEXT, ha_nextcloud.MSG_ENCRYPTION)
        self.assertIn(s5b.UNTESTED, ha_nextcloud.MSG_ENCRYPTION)
        self.assertEqual(ha_nextcloud.ISSUES[s5b.SSE_ID], 'confirm')
        self.assertEqual(s5b.SECRET_KEYS, ha_nextcloud.SECRET_KEYS)
        self.assertEqual(s5b.KEY_LAYOUT, s5.KEY_RE.pattern)
        self.assertEqual(s5b.SSE_KEY, sse_issue().key('nextcloud'))
        for items in ([], ['a'], ['b', 'a'], ['中文', 'x y']):
            for database in (None, 'db'):
                self.assertEqual(s5b.confirm_key('odoo', 'odoo.thing', items, database),
                                 haissues.confirm_key('odoo', 'odoo.thing', items, database))
        self.assertTrue(haissues.valid_key(s5b.SSE_KEY))

    def test_the_two_reviewed_notices_match_the_products_texts_and_nothing_else(self):
        self.assertIsNotNone(s5b.NOTICES['file-lists-differ'].fullmatch(lists_text()))
        self.assertIsNone(s5b.NOTICES['file-lists-differ'].fullmatch(lists_text().replace(s5b.USER, 'admin')))
        for keys in (['redis'], ['apps_paths', 'memcache.local', 'upgrade.disable-web'], [f'key{i}' for i in range(12)]):
            self.assertIsNotNone(s5b.NOTICES['settings-not-carried'].fullmatch(settings_text(keys)), keys)
        self.assertIsNone(s5b.NOTICES['settings-not-carried'].fullmatch('HA 啟用的 Nextcloud 應用 gone 在這台沒有程式，匯入後不會載入。'))


class CheckVerdictTests(unittest.TestCase):
    def verdict(self, job):
        return s5b.judge_check(job)

    def test_exactly_the_encryption_line_with_both_reasons_and_reviewed_notices_passes(self):
        for extra in ([], [settings_text()], [settings_text(), lists_text()], [lists_text()]):
            with self.subTest(extra=len(extra)):
                v = self.verdict(check_job([sse_issue(), *haissues.from_legacy(warnings=extra)]))
                self.assertTrue(all(v[k] for k in ('base', 'sse', 'others', 'section', 'versions')), v)
                self.assertEqual(sum(len(x) for x in v['notices'].values()), len(extra))
                self.assertEqual(len(v['lines']), 1 + len(extra))   # every line recorded

    def test_the_reason_set_must_be_exact(self):
        for reasons in (['files_encryption'], ['encryption_enabled'], ['files_encryption', 'encryption_enabled', 'other'],
                        ['files_encryption', 'files_encryption'], []):
            with self.subTest(reasons=reasons):
                issue = haissues.Issue(s5b.SSE_ID, 'confirm', ha_nextcloud.MSG_ENCRYPTION, reasons)
                self.assertFalse(self.verdict(check_job([issue]))['sse'])
        swapped = haissues.Issue(s5b.SSE_ID, 'confirm', ha_nextcloud.MSG_ENCRYPTION, ['encryption_enabled', 'files_encryption'])
        self.assertTrue(self.verdict(check_job([swapped]))['sse'])   # the product sorts the names into the key

    def test_text_key_and_level_must_be_the_products(self):
        job = check_job(); app = job['result']['ha_check']['apps'][0]
        for change in ('message', 'key', 'level', 'id'):
            with self.subTest(change=change):
                j = copy.deepcopy(job); issue = j['result']['ha_check']['apps'][0]['issues'][0]
                if change == 'message': issue['message'] = ha_nextcloud.MSG_ENCRYPTION.replace(s5b.UNTESTED, '已經實測過')
                if change == 'key': issue['key'] = s5b.SSE_ID + ':0123456789abcdef'
                if change == 'level': issue['level'] = 'notice'
                if change == 'id': issue['id'] = 'nextcloud.no-share'
                self.assertFalse(self.verdict(j)['sse'])
        self.assertEqual(app['issues'][0]['key'], s5b.SSE_KEY)

    def test_any_stop_another_confirmation_or_an_unreviewed_line_refuses(self):
        stop = haissues.Issue('nextcloud.version-different', 'stop', 'x', action='y')
        other_confirm = haissues.Issue('nextcloud.symlinks-skipped', 'confirm', 'x', ['a'])
        lists_confirm = haissues.Issue('nextcloud.no-share', 'confirm', lists_text())
        lists_stop = haissues.Issue('legacy.blocker', 'stop', lists_text())
        unexpected = haissues.from_legacy(warnings=['HA 啟用的 Nextcloud 應用 gone 在這台沒有程式，匯入後不會載入。'])
        auto = haissues.Issue('nextcloud.extension-enabled', 'auto', 'x', ['pg_trgm'])
        more = haissues.Issue('shared.more-lines', 'notice', '另有 3 項沒有列出，請看作業紀錄。')
        cases = {'stop': ([sse_issue(), stop], 'base'), 'two-confirms': ([sse_issue(), other_confirm], 'sse'),
                 'file-lists-as-confirm': ([sse_issue(), lists_confirm], 'sse'),
                 'file-lists-as-stop': ([sse_issue(), lists_stop], 'base'),
                 'unreviewed-notice': ([sse_issue(), *unexpected], 'others'), 'unreviewed-auto': ([sse_issue(), auto], 'others'),
                 'more-lines': ([sse_issue(), more], 'others'), 'no-confirmation': ([], 'sse')}
        for name, (issues, verdict) in cases.items():
            with self.subTest(case=name):
                v = self.verdict(check_job(issues))
                self.assertFalse(v[verdict], v)
        self.assertIn('unexpected', self.verdict(check_job([sse_issue(), *unexpected]))['notices'])

    def test_failed_job_other_app_section_and_versions_refuse(self):
        self.assertFalse(self.verdict(check_job(state='failed'))['base'])
        self.assertFalse(self.verdict(check_job(app_id='odoo'))['base'])
        job = check_job(); job['result']['ha_check']['apps'][0]['importable'] = False
        self.assertFalse(self.verdict(job)['base'])
        for key, value in (('users', 2), ('pg_version', '15'), ('datadir_in_backup', False), ('shares', 1)):
            with self.subTest(key=key):
                self.assertFalse(self.verdict(check_job(section=dict(s5b.SECTION, **{key: value})))['section'])
        self.assertFalse(self.verdict(check_job(arch='aarch64'))['versions'])


class ConversionRequestTests(unittest.TestCase):
    def test_both_requests_carry_schema_fields_only_and_never_a_key(self):
        ha = 'ha-' + 'a' * 20
        for keys, acknowledged in ((None, None), ([s5b.SSE_KEY], {'nextcloud': [s5b.SSE_KEY]})):
            with self.subTest(keys=keys):
                request = s5b.convert_request(ha, ['nextcloud'], False, keys, 'b1-e2e-focus-s5b-1795785941965')
                cli.validate('ha-convert-start', request)
                self.assertNotIn('key', request)
                self.assertEqual(request.get('acknowledged'), acknowledged)
        built = s5b.Variant.convert_request(ha, ['nextcloud'], False, 'HA-KEY-NOT-NEEDED', [s5b.SSE_KEY], 'b1-e2e-x-1')
        self.assertNotIn('key', built)
        self.assertNotIn('HA-KEY-NOT-NEEDED', json.dumps(built))

    def refusal_job(self, issues=None, code='confirmation-required', status='skipped'):
        issues = [sse_issue()] if issues is None else issues
        return {'state': 'failed', 'error': {'code': code}, 'result': {'results': [
            {'app_id': 'nextcloud', 'status': status, 'code': code, 'issues': haissues.views('nextcloud', issues)}]}}

    def test_the_unacknowledged_conversion_must_be_refused_by_exactly_the_encryption_line(self):
        ok, detail = s5b.judge_refusal(0, {'job_id': 'j1'}, self.refusal_job(), {'a'}, {'a'})
        self.assertTrue(ok, detail)
        ok, _ = s5b.judge_refusal(1, {'error': {'code': 'confirmation-required'}}, None, {'a'}, {'a'})
        self.assertTrue(ok)   # refused at the start is fine too
        faults = {'converted': (0, {'job_id': 'j1'}, dict(self.refusal_job(), state='succeeded'), {'a'}, {'a', 'b'}),
                  'other-code': (0, {'job_id': 'j1'}, self.refusal_job(code='incompatible', status='failed'), {'a'}, {'a'}),
                  'backup-added': (0, {'job_id': 'j1'}, self.refusal_job(), {'a'}, {'a', 'b'}),
                  'other-line': (0, {'job_id': 'j1'}, self.refusal_job(
                      [haissues.Issue('nextcloud.symlinks-skipped', 'confirm', 'x', ['l'])]), {'a'}, {'a'}),
                  'with-a-stop': (0, {'job_id': 'j1'}, self.refusal_job(
                      [sse_issue(), haissues.Issue('nextcloud.db-objects', 'stop', 'x')]), {'a'}, {'a'}),
                  'start-refused-otherwise': (1, {'error': {'code': 'invalid-request'}}, None, {'a'}, {'a'}),
                  'no-job': (0, {}, None, {'a'}, {'a'})}
        for name, arguments in faults.items():
            with self.subTest(fault=name):
                self.assertFalse(s5b.judge_refusal(*arguments)[0])


# ====================================================================== the product's own check and conversion

from tests.backup import test_ha_nextcloud as product_case   # noqa: E402  (its NextcloudCase: the product with a fake world)


class ProductCheckTests(product_case.NextcloudCase):
    """The product's real check and conversion (fake world) of an S5-shaped backup -- master-key key files in the share
    folder, core/encryption_enabled '1' as Nextcloud 35 stores it -- against the driver's verdicts."""

    def s5_backup(self):
        self.world.ha_details = dict(self.world.ha_details, encryption='1', enabled=['dav', 'files', 'notes', 'richdocuments'])
        keys = [{'name': f'nextcloud/files_encryption/OC_DEFAULT_MODULE/{MASTER}.{s}', 'data': key_bytes(s)}
                for s in ('publicKey', 'privateKey')]
        return self.upload_nextcloud(share=product_case.share_tar(extra=keys))

    def test_the_products_check_of_an_s5_shaped_backup_is_what_the_driver_accepts(self):
        row = self.check(self.s5_backup(), ['nextcloud'])[0]
        issue = product_case.issue_of(row, s5b.SSE_ID)
        self.assertEqual((issue['level'], issue['items'], issue['key'], issue['message']),
                         ('confirm', list(s5b.SSE_REASONS), s5b.SSE_KEY, s5b.SSE_TEXT))
        verdict = s5b.judge_check({'state': 'succeeded', 'result': {'ha_check': {'apps': [row]}}})
        self.assertTrue(verdict['base'] and verdict['sse'], verdict)
        self.assertEqual([i['id'] for i in row['issues'] if i['level'] == 'confirm'], [s5b.SSE_ID])

    def test_the_products_conversion_refuses_without_the_key_and_takes_exactly_the_bound_one(self):
        backup = self.s5_backup()
        for acknowledged in (None, {'nextcloud': []}, {'nextcloud': [s5b.SSE_ID + ':0123456789abcdef']}):
            with self.subTest(acknowledged=acknowledged), self.assertRaises(BackupError) as caught:
                self.convert(backup, ['nextcloud'], **({} if acknowledged is None else {'acknowledged': acknowledged}))
            self.assertEqual(caught.exception.code, 'confirmation-required')
            job = {'state': 'failed', 'error': caught.exception.as_dict(), 'result': caught.exception.result}
            ok, detail = s5b.judge_refusal(0, {'job_id': 'j1'}, job, set(), set())
            self.assertTrue(ok, detail)
        result = self.convert(backup, ['nextcloud'], acknowledged={'nextcloud': [s5b.SSE_KEY]})
        row = result['results'][0]
        self.assertEqual(row['status'], 'converted')
        self.assertEqual([i['key'] for i in row['issues'] if i['level'] == 'confirm'], [s5b.SSE_KEY])

    def test_without_the_fix_the_setting_alone_would_not_be_a_reason(self):
        # An engine without 50a29370 (e.g. 4cf97c25, which S5-A ran next to) read only 'yes': the reasons would be
        # files_encryption alone, another key, which the driver refuses -- the reason the lease binds the frozen product.
        with patch.object(ha_nextcloud, 'nc_true', lambda value: value == 'yes'):
            row = self.check(self.s5_backup(), ['nextcloud'])[0]
        self.assertEqual(product_case.issue_of(row, s5b.SSE_ID)['items'], ['files_encryption'])
        self.assertFalse(s5b.judge_check({'state': 'succeeded', 'result': {'ha_check': {'apps': [row]}}})['sse'])


# ====================================================================== device programs, run locally

class DeviceRoot:
    """A local stand-in for the S5-A proof root, made by S5-A's own build_fixture from a small structural source."""

    def __init__(self, test, records=3):
        self.tmp = Path(tempfile.mkdtemp()); test.addCleanup(shutil.rmtree, self.tmp, True)
        os.chmod(self.tmp, 0o700)
        self.varlib = self.tmp / 'varlib'; self.varlib.mkdir(mode=0o755)
        self.root = self.varlib / 'woowbk-nextcloud-s5-0123456789abcdef'; self.root.mkdir(mode=0o711)
        work = self.root / 'owned'; work.mkdir(mode=0o700); self.work = work
        self.password = 'a1' * 24
        self.dbpassword = 'b2' * 24
        for path in ('html/config', 'html/custom_apps', 'pg', 'data'):
            (work / path).mkdir(parents=True)
        self.write('pg/PG_VERSION', b'16\n'); self.write('pg/base/1/123', b'structural unit input only')
        self.write('html/config/config.php', ("<?php\n$CONFIG = array (\n  'instanceid' => 'ocs5structural',\n"
                                              "  'passwordsalt' => 'unit-salt-0123456789',\n  'secret' => 'unit-secret-it\\'s',\n"
                                              "  'version' => '35.0.1.1',\n  'installed' => true,\n  'dbtype' => 'pgsql',\n"
                                              "  'dbtableprefix' => 'oc_',\n  'dbname' => 'nextcloud',\n"
                                              f"  'dbpassword' => '{self.dbpassword}',\n"
                                              "  'datadirectory' => '/share/nextcloud',\n);\n").encode())
        self.write('data/.ncdata', b'# Nextcloud data directory')
        plain = s5.plaintexts(); self.plain = plain
        for name, value in plain['before'].items():
            self.write('data/s5owner/files/' + name, value)
        self.write('data/s5owner/files/Readme.md', b'skeleton file copied by the installer\n')
        self.write('data/s5owner/files/Photos/Frog.jpg', b'\xff\xd8 not a real jpeg')
        for name, value in plain['encrypted'].items():
            self.write('data/s5owner/files/' + name, header_block() + hashlib.sha512(value).digest() * (len(value) // 64 + 2))
            self.write(f'data/s5owner/files_encryption/keys/files/{name}/OC_DEFAULT_MODULE/{MASTER}.shareKey', key_bytes(name))
        for suffix in ('publicKey', 'privateKey'):
            self.write(f'data/files_encryption/OC_DEFAULT_MODULE/{MASTER}.{suffix}', key_bytes(suffix))
            self.write(f'data/files_encryption/OC_DEFAULT_MODULE/pubShare_89abcdef.{suffix}', key_bytes('p' + suffix))
        digests = {kind: {n: {'bytes': len(v), 'sha256': sha(v)} for n, v in rows.items()} for kind, rows in plain.items()}
        found = s5.classify_source(work / 'data', digests['before'], digests['encrypted'], MASTER)
        proof = {'webdav_before': True, 'webdav_after_restart': True, 'plaintext_before_encryption': True,
                 'master_key_mode': True, 'pg_shutdown': True, 'master_key_id': MASTER, 'plaintext': digests,
                 'encrypted_files': found['encrypted'], 'plaintext_files': found['plaintext'],
                 'cipher_and_keys': found['cipher_and_keys'], 'facts': {'core_encryption_enabled': {'value': '1'}}}
        with patch.object(s5, 'product', side_effect=AssertionError('never the installed product')):
            self.built = s5.build_fixture(work, proof, libraries=LIBRARIES)
        s5.discard_owned(work, ('html', 'pg', 'data'))
        self.write('credentials.private.json', json.dumps({'user': 's5owner', 'password': self.password,
                                                           'use': 'S5-B WebDAV reads; removed with the owned root'}).encode())
        for name in s5b.S5A_LEAVES:
            if name not in ('artifact', 'credentials.private.json'):
                self.write(name, b'{}')
        for number in range(1, records + 1):
            for suffix in ('json', 'stdout.private', 'stderr.private'):
                self.write(f'command-{number:04d}.{suffix}', b'{}')
        self.store = self.tmp / 'store'
        for name in ('uploads', 'ha-backups'):
            (self.store / name).mkdir(parents=True)
        self.memory = self.tmp / 'memory.current'; self.memory.write_text('1000\n')
        self.fixture = work / 'artifact/generated-s5-source.tar'
        self.provenance = work / 'artifact/provenance.private.json'

    def write(self, name, raw):
        p = self.work / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw); p.chmod(0o600)
        return p

    def overrides(self, **extra):
        return dict({'PROOF_ROOT': str(self.root), 'FIXTURE': str(self.fixture), 'PROVENANCE': str(self.provenance),
                     'CREDENTIALS': str(self.work / 'credentials.private.json'), 'FIXTURE_SHA': self.built['sha256'],
                     'FIXTURE_BYTES': self.built['bytes'], 'PROVENANCE_SHA': sha(self.provenance.read_bytes()),
                     'S5A_COMMAND_RECORDS': 9, 'OWNER': pwd.getpwuid(os.getuid()).pw_name, 'ROOT_UID': os.getuid(),
                     'STORE': str(self.store), 'FLOOR': 0, 'MEMORY_CAP': 10 ** 12, 'MEMORY_FILE': str(self.memory),
                     'DISKS': (str(self.tmp),)}, **extra)

    def run(self, name, request=None, **extra):
        program = s5b.programs(self.overrides(**extra))[name]
        p = subprocess.run([sys.executable, '-I', '-c', program], input=json.dumps(request or {}).encode(),
                           capture_output=True, timeout=300)
        if p.returncode:
            raise ValueError(p.stderr.decode('utf-8', 'replace').strip().splitlines()[-1])
        return json.loads(p.stdout)


class DeviceProgramTests(unittest.TestCase):
    def test_programs_compile_fit_one_argv_and_bind_the_real_paths(self):
        for name, program in s5b.PROGRAMS.items():
            with self.subTest(program=name):
                compile(program, name, 'exec')
                self.assertLess(len(program.encode()), 120 * 1024)
                self.assertIn(f'PROOF_ROOT={s5b.PROOF_ROOT!r}', program)
        self.assertIn("EXEC=('podman', 'exec', '-u', 'www-data', 'nextcloud-app')", s5b.PROGRAMS['disk'])
        self.assertIn("DAV_BASE='http://127.0.0.1:18081'", s5b.PROGRAMS['dav'])
        self.assertIn('FLOOR=%d' % (s5b.RESERVE + s5b.MARGIN), s5b.PROGRAMS['copy'])

    def test_state_reads_the_real_s5a_output_format_without_any_secret(self):
        dev = DeviceRoot(self)
        state = dev.run('state')
        self.assertEqual(state['fixture']['sha256'], dev.built['sha256'])
        self.assertTrue(state['ha_store_entry_absent'])
        p = state['provenance']
        self.assertEqual(p['master_key_id'], MASTER)
        self.assertEqual(sorted(p['user_files']), sorted(['Photos/Frog.jpg', 'Readme.md', 's5-before-encryption.txt',
                                                          's5-binary.bin', 's5-utf8.txt']))
        self.assertEqual(len(p['key_files']), 6)
        text = json.dumps(state)
        for secret in (dev.password, dev.dbpassword, 'unit-secret', key_bytes('privateKey').decode()):
            self.assertNotIn(secret, text)
        self.assertEqual(state['proof_root']['files'], 2 + 7 + 9)   # artifact, the other leaves, 3 commands x 3 records

    def test_secrets_gives_the_needles_and_says_the_fixture_needs_no_ha_key(self):
        dev = DeviceRoot(self)
        found = dev.run('secrets')
        self.assertEqual(found['password'], dev.password)
        self.assertEqual(found['config'], {'secret': "unit-secret-it's", 'passwordsalt': 'unit-salt-0123456789',
                                           'dbpassword': dev.dbpassword})
        self.assertEqual(found['private_keys'], {MASTER: key_bytes('privateKey').decode(),
                                                 'pubShare_89abcdef': key_bytes('pprivateKey').decode()})
        with tarfile.open(dev.fixture) as tar:
            doc = json.load(tar.extractfile('./backup.json'))
        self.assertEqual((doc['protected'], doc['compressed']), (False, False))

    def test_any_change_of_the_proof_root_refuses(self):
        faults = {'extra-leaf': lambda d: d.write('extra.json', b'{}'),
                  'missing-record': lambda d: (d.work / 'command-0001.json').unlink(),
                  'symlink': lambda d: (d.work / 'link').symlink_to('/etc/passwd'),
                  'hardlink': lambda d: os.link(d.work / 'fixed-result.json', d.work / 'artifact/x'),
                  'subdir': lambda d: (d.work / 'html').mkdir(),
                  'credentials-mode': lambda d: (d.work / 'credentials.private.json').chmod(0o644),
                  'credentials-content': lambda d: d.write('credentials.private.json', b'{"user":"s5owner","password":"x","use":""}'),
                  'fixture-bytes': lambda d: d.fixture.write_bytes(d.fixture.read_bytes()[:-1] + b'\x01'),
                  'provenance': lambda d: d.provenance.write_bytes(d.provenance.read_bytes() + b' ')}
        for name, fault in faults.items():
            with self.subTest(fault=name):
                dev = DeviceRoot(self)
                expected = dev.overrides()
                fault(dev)
                program = s5b.programs(expected)['state']
                p = subprocess.run([sys.executable, '-I', '-c', program], input=b'{}', capture_output=True, timeout=300)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(b'fixed-s5b-', p.stderr)
        dev = DeviceRoot(self)
        (dev.store / 'ha-backups' / (s5b.HA_ID + '.json')).write_text('{}')
        self.assertFalse(dev.run('state', HA_ID=s5b.HA_ID)['ha_store_entry_absent'])

    def test_copy_writes_the_fixture_into_the_owned_upload_file_inside_the_device(self):
        dev = DeviceRoot(self)
        uid = 'u' + '0' * 16
        part = dev.store / 'uploads' / (uid + '.part')
        fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.close(fd)
        request = {'source': str(dev.fixture), 'part': str(part), 'upload_id': uid, 'size': dev.built['bytes'],
                   'sha256': dev.built['sha256'], 'deadline': 4e9}
        result = dev.run('copy', request)
        self.assertEqual((result['bytes'], result['sha256']), (dev.built['bytes'], dev.built['sha256']))
        self.assertEqual(part.read_bytes(), dev.fixture.read_bytes())
        self.assertEqual(result['identity'], {'dev': part.stat().st_dev, 'ino': part.stat().st_ino})
        self.assertLess(len(json.dumps(request)), 1024)   # paths and numbers only: no fixture byte crosses the host
        for change, reason in (({'part': str(dev.store / 'uploads/other.part')}, 'copy-binding'),
                               ({'upload_id': 'u1'}, 'copy-binding'), ({'source': '/etc/passwd'}, 'copy-fixture-binding'),
                               ({'deadline': 1.0}, 'watch-expired')):
            with self.subTest(change=sorted(change)):
                part.write_bytes(b'')
                with self.assertRaisesRegex(ValueError, reason):
                    dev.run('copy', dict(request, **change))
        part.write_bytes(b'already written')
        with self.assertRaisesRegex(ValueError, 'copy-target'):
            dev.run('copy', request)
        part.write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'watch-reserve'):
            dev.run('copy', request, FLOOR=10 ** 18)

    def test_disk_reader_hashes_the_live_data_dir_and_keeps_key_bytes_inside(self):
        data = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, data, True)
        files = {'s5owner/files/a b.txt': b'plain', 's5owner/files/enc.bin': header_block() + b'c' * 100,
                 f'files_encryption/OC_DEFAULT_MODULE/{MASTER}.privateKey': key_bytes('k'),
                 f's5owner/files_encryption/keys/files/enc.bin/OC_DEFAULT_MODULE/{MASTER}.shareKey': b'not a key layout'}
        for rel, raw in files.items():
            (data / rel).parent.mkdir(parents=True, exist_ok=True); (data / rel).write_bytes(raw)
        (data / 's5owner/files/link').symlink_to('a b.txt')
        program = s5b.programs({'EXEC': (), 'DATA_ROOT': str(data)})['disk']
        p = subprocess.run([sys.executable, '-I', '-c', program], input=json.dumps({'headers': ['s5owner/files/enc.bin']}).encode(),
                           capture_output=True, timeout=120, check=True)
        out = json.loads(p.stdout)
        self.assertEqual(out['files'], {rel: {'bytes': len(raw), 'sha256': sha(raw)} for rel, raw in files.items()})
        self.assertEqual(out['special'], ['s5owner/files/link'])
        self.assertEqual(s5.native_header(base64.b64decode(out['headers']['s5owner/files/enc.bin'])), s5.HEADER)
        self.assertEqual(out['layouts'], {f'files_encryption/OC_DEFAULT_MODULE/{MASTER}.privateKey': True,
                                          f's5owner/files_encryption/keys/files/enc.bin/OC_DEFAULT_MODULE/{MASTER}.shareKey': False})
        self.assertNotIn(key_bytes('k').decode(), p.stdout.decode())

    def test_dav_sends_the_password_only_in_the_authorization_header(self):
        seen = []

        class Reply(io.BytesIO):
            status = 201
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def opener(request, timeout):
            seen.append((request.get_method(), request.full_url, request.get_header('Authorization'), request.data))
            return Reply(b'')
        out = s5b.dav('http://127.0.0.1:18081', 's5owner', 'pw-123456', [
            {'method': 'PUT', 'name': 'n.txt', 'data': base64.b64encode(b'x').decode()},
            {'method': 'GET', 'name': 'n.txt', 'suffix': '-wrong'}], opener)
        self.assertEqual([o['status'] for o in out], [201, 201])
        self.assertEqual(seen[0][:2], ('PUT', 'http://127.0.0.1:18081/remote.php/dav/files/s5owner/n.txt'))
        self.assertEqual(base64.b64decode(seen[1][2].split()[1]), b's5owner:pw-123456-wrong')
        self.assertNotIn('pw-123456', json.dumps(out))
        with self.assertRaisesRegex(ValueError, 'dav-op'):
            s5b.dav('http://x', 's5owner', 'p', [{'method': 'DELETE', 'name': 'n.txt'}], opener)
        with self.assertRaisesRegex(ValueError, 'dav-op'):
            s5b.dav('http://x', 's5owner', 'p', [{'method': 'GET', 'name': '../escape'}], opener)

    def test_remove_takes_exactly_the_proven_root_and_nothing_that_appeared(self):
        dev = DeviceRoot(self)
        with self.assertRaisesRegex(ValueError, 'remove-binding'):
            dev.run('remove', {'root': str(dev.root), 'removal': 'always'})
        self.assertTrue(dev.root.exists())
        dev.write('appeared.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'proof-root-leaves'):
            dev.run('remove', {'root': str(dev.root), 'removal': s5b.REMOVAL})
        (dev.work / 'appeared.json').unlink()
        result = dev.run('remove', {'root': str(dev.root), 'removal': s5b.REMOVAL})
        self.assertEqual(result['status'], 'removed')
        self.assertFalse(dev.root.exists())
        self.assertTrue(dev.varlib.exists())


# ====================================================================== the S5 verification verdicts

class VerifyVerdictTests(unittest.TestCase):
    def disk(self, p, new=None, change=None):
        files = {s5b.USER + '/files/' + n: dict(r) for n, r in p['user_files'].items()}
        files.update({k: dict(r) for k, r in p['key_files'].items()})
        headers = {}
        if new:
            name, plain = new
            files[s5b.USER + '/files/' + name] = {'bytes': len(plain) + 8192 + 32, 'sha256': sha(b'cipher' + plain)}
            files[f'{s5b.USER}/files_encryption/keys/files/{name}/OC_DEFAULT_MODULE/{MASTER}.shareKey'] = {'bytes': 300, 'sha256': 'f' * 64}
            headers[s5b.USER + '/files/' + name] = base64.b64encode(header_block()).decode()
        if change:
            change(files, headers)
        return {'files': files, 'special': [], 'headers': headers,
                'layouts': {k: True for k in files if 'files_encryption' in k.split('/')[:2]}}

    def test_disk_must_hold_every_s5a_file_and_key_byte_for_byte(self):
        p = provenance()
        self.assertTrue(s5b.judge_disk(self.disk(p), p)[0])
        key = next(iter(p['key_files']))
        faults = {'changed-key': lambda f, h: f[key].update(sha256='0' * 64),
                  'missing-cipher': lambda f, h: f.pop(s5b.USER + '/files/s5-binary.bin'),
                  'regenerated-master': lambda f, h: f.update({f'files_encryption/OC_DEFAULT_MODULE/master_ffffffff.publicKey': {'bytes': 1, 'sha256': 'e' * 64}}),
                  'plaintext-changed': lambda f, h: f[s5b.USER + '/files/s5-before-encryption.txt'].update(bytes=1)}
        for name, fault in faults.items():
            with self.subTest(fault=name):
                self.assertFalse(s5b.judge_disk(self.disk(p, change=fault), p)[0])
        special = self.disk(p); special['special'] = ['s5owner/files/link']
        self.assertFalse(s5b.judge_disk(special, p)[0])
        layout = self.disk(p); layout['layouts'][key] = False
        self.assertFalse(s5b.judge_disk(layout, p)[0])

    def test_the_new_file_must_be_encrypted_with_only_its_master_share_key(self):
        p = provenance(); name, plain = 's5b-new.txt', b'new plaintext ' * 100
        ops = [{'status': 201, 'bytes': 0, 'sha256': sha(b'')}, {'status': 200, 'bytes': len(plain), 'sha256': sha(plain)},
               {'status': 401, 'bytes': 0, 'sha256': sha(b'')}]
        ok, record, new = s5b.judge_new_file(self.disk(p, (name, plain)), p, name, plain, ops)
        self.assertTrue(ok, record)
        self.assertEqual(new['share_key'], f'{s5b.USER}/files_encryption/keys/files/{name}/OC_DEFAULT_MODULE/{MASTER}.shareKey')
        share = new['share_key']; rel = s5b.USER + '/files/' + name
        faults = {'plaintext-on-disk': lambda f, h: f[rel].update(bytes=len(plain), sha256=sha(plain)),
                  'no-header': lambda f, h: h.update({rel: base64.b64encode(b'x' * 8192).decode()}),
                  'other-cipher': lambda f, h: h.update({rel: base64.b64encode(header_block(dict(s5.HEADER, cipher='AES-128-CFB'))).decode()}),
                  'file-key-too': lambda f, h: f.update({share.rsplit('/', 1)[0] + '/fileKey': {'bytes': 1, 'sha256': 'a' * 64}}),
                  'user-share-key': lambda f, h: f.update({share.replace(MASTER, s5b.USER): {'bytes': 1, 'sha256': 'a' * 64}}),
                  'no-share-key': lambda f, h: f.pop(share),
                  'old-key-changed': lambda f, h: f[next(iter(p['key_files']))].update(sha256='0' * 64)}
        for fault_name, fault in faults.items():
            with self.subTest(fault=fault_name):
                self.assertFalse(s5b.judge_new_file(self.disk(p, (name, plain), fault), p, name, plain, ops)[0])
        for i, bad in ((0, {'status': 204}), (1, {'status': 200, 'bytes': 1, 'sha256': 'x'}), (2, {'status': 200})):
            with self.subTest(op=i):
                broken = list(ops); broken[i] = bad
                self.assertFalse(s5b.judge_new_file(self.disk(p, (name, plain)), p, name, plain, broken)[0])

    def test_webdav_expectations_are_the_plaintexts_and_a_spread_skeleton_sample(self):
        p = provenance()
        want = s5b.webdav_expectations(p)
        for kind in ('before', 'encrypted'):
            for n, r in p['plaintext'][kind].items():
                self.assertEqual(want[n], r['sha256'])   # the plaintext, never the ciphertext on disk
        skeleton = [n for n in want if n.startswith('Skeleton/')]
        self.assertGreaterEqual(len(skeleton), s5b.SAMPLE)
        self.assertIn('Skeleton/file 11.txt', skeleton)   # the largest
        self.assertEqual(want, s5b.webdav_expectations(copy.deepcopy(p)))
        new = {'name': 'n.txt', 'plain_sha256': 'b' * 64}
        self.assertEqual(s5b.webdav_expectations(p, new)['n.txt'], 'b' * 64)

    def test_the_manifest_digest_is_the_clients_shell_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = {}
            for rel, raw in (('a.txt', b'1'), ('Sub dir/b.bin', b'2' * 3000), ('Sub dir/z/c', b''), ('B.md', b'x'), ('中文.txt', b'y')):
                (root / rel).parent.mkdir(parents=True, exist_ok=True); (root / rel).write_bytes(raw); rows[rel] = sha(raw)
            out = subprocess.run(['sh', '-c', 'cd "$1" || exit 3; find . -type f -print0 | LC_ALL=C sort -z | '
                                  'xargs -0 -r sha256sum | sha256sum | cut -c1-64', 'sh', tmp],
                                 capture_output=True, check=True).stdout.decode().strip()
        self.assertEqual(s5b.showcase_digest(rows), out)
        with self.assertRaisesRegex(ValueError, 'digest-name'):
            s5b.showcase_digest({'a\\b': 'a' * 64})

    def test_owned_store_cleanup_allows_only_this_runs_traces(self):
        row = lambda name: [name, 0o100600, 0, 0, 1, 1, 0, 0, 1]   # noqa: E731
        before = {'archives': [row('b.json'), row('b.tar')], 'ha-backups': [], 'uploads': [row('uold.done')],
                  'jobs': [row('j1.json')]}
        state = {'jobs': {'j20261128T000000Z-00000001': {}}, 'finished_upload_id': 'u' + '1' * 16}
        after = copy.deepcopy(before)
        after['jobs'] += [row('j20261128T000000Z-00000001.json'), row('j20261128T000000Z-00000001.log')]
        after['uploads'] = [row('u' + '1' * 16 + '.done')]   # the old cache went (24 h cleanup), ours came
        ok, delta = s5b.owned_store_clean(before, after, state)
        self.assertTrue(ok, delta)
        self.assertEqual(delta['uploads']['removed'], ['uold.done'])
        for kind, extra in (('archives', 'c.tar'), ('ha-backups', s5b.HA_ID + '.tar'), ('jobs', 'jforeign.json'),
                            ('uploads', 'uforeign.part')):
            with self.subTest(kind=kind):
                bad = copy.deepcopy(after); bad[kind].append(row(extra))
                self.assertFalse(s5b.owned_store_clean(before, bad, state)[0])
        gone = copy.deepcopy(after); gone['archives'] = [row('b.json')]
        self.assertFalse(s5b.owned_store_clean(before, gone, state)[0])

    def test_the_evidence_scan_finds_raw_and_json_escaped_needles_and_refuses_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'area'; (root / 'run').mkdir(parents=True)
            (root / 'run/clean.json').write_text('{"ok": true}')
            self.assertEqual(s5b.scan_evidence([root, Path(tmp) / 'absent'], ['pass/"word']), {'files': 1, 'hits': 0})
            (root / 'run/raw.log').write_text('x pass/"word y')
            (root / 'run/escaped.json').write_text(json.dumps({'v': 'pass/"word'}))
            self.assertEqual(s5b.scan_evidence([root], ['pass/"word'])['hits'], 2)
            (root / 'run/link').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'evidence-link'):
                s5b.scan_evidence([root], ['pass/"word'])


# ====================================================================== end to end against a fake dev-e

def proc(code, out=b''):
    return types.SimpleNamespace(returncode=code, stdout=out, stderr=b'')


class FakeDevE:
    """dev-e for one whole S5-B run: its helper, device programs, inventory, source transaction and owner commands.
    It starts with ANOTHER lane's engine (the OpenDesign pilot deploys its own checkout before S5-B): no prior engine is
    assumed. `mode` breaks one thing: 'check-extra-confirm', 'disk-changed', 'converts-unacknowledged',
    'source-restore-fails', 'wrong-engine-back'."""
    BASE_USERS = ['admin', 'woowbk-lab-baseline']

    def __init__(self, engines, rows, mode='pass'):
        self.mode, self.rows = mode, rows
        self.prior_engine, self.product_engine = engines
        self.p = provenance()
        self.password, self.config = 'c3' * 24, {'secret': 'fake-secret-0123456789', 'passwordsalt': 'fake-salt-01234',
                                                 'dbpassword': 'd4' * 24}
        self.private_keys = {MASTER: key_bytes('fake-master').decode(), 'pubShare_89abcdef': key_bytes('fake-pub').decode()}
        self.events, self.engine, self.nc, self.new = [], 'prior', 'original', {}
        self.backups = ['20261123T084036Z-5ebb7283', '20261123T121327Z-74c471c6', case.BASELINE]
        self.ha, self.uploads, self.jobs, self.count = set(), {'u' + '9' * 16 + '.done'}, {}, 0
        self.injected, self.converted, self.import_safety, self.removed, self.nc_module = False, None, None, False, None

    # ---------------------------------------------------------------- dev-e as root/owner programs
    def device(self, program, request=None, *, root=False, timeout=300):
        if program == s5.ENGINE_PROGRAM:
            if self.engine == 'stale':
                return dict(self.prior_engine, helper='3' * 64)
            return dict(self.product_engine if self.engine == 'product' else self.prior_engine)
        if program == s5b.PROGRAMS['state']:
            self.events.append('s5a-state')
            return {'proof_root': {'files': 18, 'bytes': 1, 'paths': []}, 'provenance': self.p,
                    'credentials': {'present': True, 'mode': '0600'}, 'ha_store_entry_absent': True,
                    'fixture': {'sha256': s5b.FIXTURE_SHA, 'identity': [1, 2]}}
        if program == s5b.PROGRAMS['secrets']:
            return {'password': self.password, 'config': dict(self.config), 'private_keys': dict(self.private_keys)}
        if program == s5.TARGET_STATE:
            rows = lambda names: [[n, 0o100600, 0, 0, 1, 1, 0, 0, i] for i, n in enumerate(sorted(names))]   # noqa: E731
            return {'archives': rows(f'{b}.{s}' for b in self.backups for s in ('json', 'tar')),
                    'ha-backups': rows(f'{h}.{s}' for h in self.ha for s in ('json', 'tar')), 'uploads': rows(self.uploads),
                    'jobs': rows(f'{j}.{s}' for j in self.jobs for s in ('json', 'log', 'lock'))}
        if program == case.QUIESCENT:
            return {'active_jobs': 0}
        if program == case.RESOURCE:
            return {'free': 30 * GIB, 'memory': GIB}
        if program == case.BASELINE_INSPECT:
            return {'status': 'passed', 'encrypted_manifest_opened': True}
        if program == wake.BASELINE_HASH:
            return [{'name': case.BASELINE + '.json', 'size': 655, 'sha256': 'a' * 64},
                    {'name': case.BASELINE + '.tar', 'size': 422031360, 'sha256': 'b' * 64}]
        if program == wake.unit_program():
            self.events.append('units-' + request['action'])
            return {'rows': [{'name': n} for n in wake.FILES]} if request['action'] == 'snapshot' else {'status': 'ok'}
        if program == wake.CONTROL:
            self.events.append('wake'); return {'status': 'started'}
        if program == cold.CLAIM:
            return {'ActiveState': 'active', 'MainPID': '42', 'InvocationID': 'a' * 32}
        if program == cold.STOP:
            self.events.append('cold-stop'); return {'status': 'stopped'}
        if program == s5b.PROGRAMS['copy']:
            assert sorted(request) == ['deadline', 'part', 'sha256', 'size', 'source', 'upload_id'] and root
            assert request['source'] == s5b.FIXTURE and request['part'].endswith(request['upload_id'] + '.part')
            self.events.append('copy-inside-dev-e')
            return {'status': 'passed', 'bytes': s5b.FIXTURE_BYTES, 'sha256': s5b.FIXTURE_SHA, 'identity': {'dev': 1, 'ino': 99}}
        if program == s5b.PROGRAMS['remove']:
            assert request == {'root': s5b.PROOF_ROOT, 'removal': s5b.REMOVAL} and root
            self.events.append('remove-proof-root'); self.removed = True
            return {'status': 'removed', 'files': 348, 'bytes': 127600640}
        raise AssertionError('unexpected device program')

    def collect(self):
        return {'isolation': {'running': True, 'network': 'none', 'ports': {}, 'memory_limit': case.DEVICE_CAP},
                'root': {'memory_max': str(case.DEVICE_CAP), 'memory_current': 500 * 1024 ** 2, 'varlib_free_bytes': 30 * GIB,
                         'catalog_sha256': '3a7af03b966f90a172e417a3ea69d7b36bf98a23af8d27b0c074bd01b6f335d6',
                         'installed_hashes': {'ha_nextcloud.py': self.engine}},
                'host_memory_available_mib': 3500, 'host_free_bytes': 30 * GIB,
                'owner': {'units': {n: {'ActiveState': 'inactive', 'UnitFileState': 'generated'} for n in r6.INACTIVE_UNITS},
                          'quadlets': {'nextcloud-app.container': {'sha256': 'q' * 64}},
                          'images': [{'ref': r, 'present': True, 'identity': {'id': 'sha256:' + v, 'architecture': 'amd64',
                                                                             'os': 'linux'}} for r, v in case.ORIGINALS.items()]}}

    def transact(self, action, nonce, paths, manifest, expires):
        self.events.append('source-' + action)
        if action == 'install':
            assert manifest == self.rows
            self.engine = 'product'; return {'status': 'installed'}
        if self.mode == 'source-restore-fails':
            raise RuntimeError('fixed-source-exact-prior-return-failed')
        self.engine = 'stale' if self.mode == 'wrong-engine-back' else 'prior'
        return {'status': 'restored'}

    # ---------------------------------------------------------------- the helper
    def job(self, kind, state, result=None, error=None):
        self.count += 1
        job_id = 'j20261128T%06dZ-%08x' % (100000 + self.count, self.count)
        self.jobs[job_id] = {'id': job_id, 'type': kind, 'state': state, 'phase': 'done', 'progress': {'message': ''},
                             'result': result, 'error': error}
        return job_id

    def new_backup(self):
        self.count += 1
        backup_id = '20261128T%06dZ-%08x' % (100000 + self.count, self.count)
        self.backups.append(backup_id)
        return backup_id

    def check_row(self):
        issues = [sse_issue(), *haissues.from_legacy(warnings=[settings_text(), lists_text()])]
        if self.mode == 'check-extra-confirm':
            issues.append(haissues.Issue('nextcloud.symlinks-skipped', 'confirm', 'x', ['s5owner/files/link']))
        return {'app_id': 'nextcloud', 'arch': 'amd64', 'version': '0.2.3', 'target_version': '35.0.1.1',
                'nextcloud': dict(s5b.SECTION, files=80, custom_apps=[], datadir_bytes=50 * 1024 ** 2),
                **haissues.check_fields('nextcloud', issues)}

    def helper(self, command, request=None, *, timeout=1800):
        self.events.append(command)
        if command == 'jobs':
            return 0, {'jobs': [{'id': j['id'], 'state': j['state']} for j in self.jobs.values()]}
        if command == 'job-status':
            return 0, {'job': copy.deepcopy(self.jobs[request['job_id']]), 'log': []}
        if command == 'list':
            return 0, {'backups': [{'id': b, 'size': 10 ** 6} for b in self.backups]}
        if command == 'upload-begin':
            assert request == {'filename': 'generated-s5-source.tar', 'size': s5b.FIXTURE_BYTES}
            self.upload_id = 'u' + 'a' * 16
            return 0, {'upload_id': self.upload_id, 'path': f'/var/lib/woowtech-backup/uploads/{self.upload_id}.part',
                       'max_size': 10 ** 12}
        if command == 'upload-finish':
            assert request == {'upload_id': self.upload_id} and 'copy-inside-dev-e' in self.events
            self.ha.add(s5b.HA_ID); self.uploads.add(self.upload_id + '.done')
            return 0, {'ha_backup': {'id': s5b.HA_ID, 'sha256': s5b.FIXTURE_SHA, 'size': s5b.FIXTURE_BYTES,
                                     'importable_apps': [{'app_id': 'nextcloud', 'installed': True}]}}
        if command == 'ha-check-start':
            assert 'key' not in request
            return 0, {'job_id': self.job('verify', 'succeeded', {'ha_check': {'apps': [self.check_row()]}})}
        if command == 'ha-convert-start':
            cli.validate('ha-convert-start', request)
            assert 'key' not in request
            if request.get('acknowledged') == {'nextcloud': [s5b.SSE_KEY]} or self.mode == 'converts-unacknowledged':
                backup = self.new_backup(); self.converted = backup
                result = {'backup_id': backup, 'size': 10 ** 6, 'apps': ['nextcloud'], 'encrypted': True,
                          'ha_import': {'notes': ['Nextcloud 會標示資料是從備份還原的（新的資料指紋）。', 'Office 會改用這台的 Collabora。'],
                                        'reminders_by_app': {'nextcloud': ['請到「Woow Nextcloud MCP Server」確認連線資料。']}},
                          'results': [haimport.convert_result('nextcloud', None, [sse_issue()])]}
                return 0, {'job_id': self.job('backup', 'succeeded', result)}
            error = haissues.confirmation_required({'nextcloud': [sse_issue()]}, 'x')
            result = {'results': [haimport.convert_result('nextcloud', error, [sse_issue()])]}
            return 0, {'job_id': self.job('backup', 'failed', result, {'code': 'confirmation-required', 'message': 'x'})}
        if command == 'inspect':
            return 0, {'preflight': {'ok': True, 'checks': [], 'apps': [{'id': 'nextcloud', 'mode': 'inplace',
                                                                          'settings': {'state': 'same'}}]}, 'manifest': {}}
        if command == 'ha-delete':
            assert request == {'ha_backup_id': s5b.HA_ID, 'confirm': True}
            self.ha.discard(s5b.HA_ID); return 0, {}
        if command == 'restore-start':
            safety = self.new_backup()
            if self.injected:
                self.injected = False
                return 0, {'job_id': self.job('restore', 'rolled-back', {'rolled_back': True, 'safety_backup_id': safety})}
            if request['backup_id'] == self.converted:
                self.nc, self.new = 'imported', {}
                self.import_safety = self.import_safety or safety
            else:
                assert request['backup_id'] == self.import_safety
                self.nc, self.new = 'original', {}
            return 0, {'job_id': self.job('restore', 'succeeded', {'safety_backup_id': safety, 'health': [{'status': 'ok'}]})}
        if command == 'delete':
            self.backups.remove(request['backup_id']); return 0, {}
        if command in ('job-cancel', 'upload-abort'):
            return 0, {}
        raise AssertionError(command)

    # ---------------------------------------------------------------- appowner probes
    def user_rows(self):
        rows = dict(self.p['user_files'])
        rows.update({n: {'bytes': len(v) + 8192 + 16, 'sha256': sha(b'cipher' + v)} for n, v in self.new.items()})
        return rows

    def key_rows(self):
        rows = dict(self.p['key_files'])
        rows.update({f'{s5b.USER}/files_encryption/keys/files/{n}/OC_DEFAULT_MODULE/{MASTER}.shareKey':
                     {'bytes': 300, 'sha256': sha(b'share' + n.encode())} for n in self.new})
        if self.mode == 'disk-changed':
            rows[next(iter(self.p['key_files']))] = {'bytes': 1, 'sha256': '0' * 64}
        return rows

    def plaintext(self, name):
        p = self.p
        if name in self.new: return sha(self.new[name])
        for kind in ('before', 'encrypted'):
            if name in p['plaintext'][kind]: return p['plaintext'][kind][name]['sha256']
        return p['user_files'][name]['sha256'] if name in p['user_files'] else 'HTTP404'

    def device_python(self, script, request=None, *, as_owner=True, timeout=600):
        nc = self.nc_module
        if script == nc.ENGINE_HASHES:
            source_rows = self.rows if self.engine == 'product' else {}
            return {n[len('woowbackup/'):]: r['sha256'] for n, r in source_rows.items() if n.startswith('woowbackup/')}
        if script == nc.STATE:
            imported = self.nc == 'imported'
            return {'config_sha256': 'cfg-' + self.nc, 'users': ['s5owner'] if imported else self.BASE_USERS,
                    'status': {'installed': True, 'version': '35.0.1.1', 'maintenance': False, 'needsDbUpgrade': False},
                    'db': {'storages': ['home::x'], 'users': 1 if imported else 2}, 'data_top': ['a', 'b'],
                    'units': {u: 'active' for u in nc.UNITS}, 'office': {'core.backgroundjobs_mode': 'cron'},
                    'fingerprint': 'fp-' + self.nc, 'filecache_rows': 10}
        if script == nc.CLIENT:
            if request['user'] == nc.BASE_USER:
                return {'ocs': {'password': [200, True], 'wrong': [401, False]}, 'fingerprint': [207, 'fp-original'],
                        'capabilities': [200, {}], 'discovery': [200, True]}
            assert request['user'] == s5b.USER and request['user_pw'] == self.password and self.nc == 'imported'
            return {'status': {'installed': True, 'version': '35.0.1.1', 'maintenance': False, 'needsDbUpgrade': False},
                    'ocs': {'password': [200, True], 'wrong': [401, False]}, 'capabilities': [200, {}],
                    'fingerprint': [207, 'fp-imported'], 'discovery': [200, True],
                    'files': {n: self.plaintext(n) for n in request['files']},
                    'digests': {s5b.USER: s5b.showcase_digest({n: r['sha256'] for n, r in self.user_rows().items()})},
                    'web': {'control': 200, 'picked': True, 'codes': [404, 403, 404, 403],
                            'htaccess': sha(ha_nextcloud.DATA_HTACCESS), 'htaccess_below': '0'},
                    'scan': {'folders': 3, 'files': 20, 'new': 0, 'updated': 0, 'removed': 0, 'errors': 0, 'rc': 0},
                    'setup': {'checks': 30, 'data_dir': 'success', 'not_success': []},
                    'storage': 'local::/var/www/html/data/', 'owners': 'oc_admin', 'lastcron': '1'}
        if script == nc.LEAKS:
            self.events.append('leak-scan')
            return {'scanned': 12, 'journal_bytes': 1000, 'names': len([v for v in request['secrets'].values() if v]),
                    'hits': 0, 'url_token_access_log_hits': 0, 'url_token_hits_elsewhere': 0}
        if script == nc.drv.RUN_LIST:
            return {'/var/lib/woowtech-backup/staging': [], '/run/woowtech-backup': []}
        if script == s5b.PROGRAMS['disk']:
            files = {s5b.USER + '/files/' + n: r for n, r in self.user_rows().items()}
            files.update(self.key_rows())
            return {'files': files, 'special': [], 'layouts': {k: True for k in files if 'files_encryption' in k.split('/')[:2]},
                    'headers': {rel: base64.b64encode(header_block()).decode() for rel in request['headers'] if rel in files}}
        if script == s5b.PROGRAMS['dav']:
            assert request['password'] == self.password
            out = []
            for op in request['ops']:
                if op['method'] == 'PUT':
                    self.new[op['name']] = base64.b64decode(op['data']); out.append({'status': 201, 'bytes': 0, 'sha256': sha(b'')})
                elif op.get('suffix'):
                    out.append({'status': 401, 'bytes': 0, 'sha256': sha(b'')})
                else:
                    body = self.new.get(op['name'], b'')
                    out.append({'status': 200 if op['name'] in self.new else 404, 'bytes': len(body), 'sha256': sha(body)})
            return out
        raise AssertionError('unexpected owner program')

    def owner(self, *argv, input=None, timeout=600, check=False):
        argv = [str(a) for a in argv]
        if argv[:2] == ['python3', '-I'] and argv[-2:] == ['nextcloud', 'read']:
            return proc(0, json.dumps({'users': ['woowbk-lab-baseline'], 'files': {'marker.txt': 'e' * 64}}).encode())
        if argv[:3] == ['podman', 'unshare', 'du']:
            return proc(0, f'{100 * 1024 ** 2}\t{argv[-1]}\n'.encode())
        if argv[0] == 'podman':
            return proc(0, b'')
        if argv[0] == 'test':
            return proc(1)
        if argv[0] == 'sh':
            self.injected = self.injected or argv[4].endswith(self.nc_module.FAIL_MARKER_REL)
            return proc(0)
        if argv[0] in ('mkdir', 'rm', 'rmdir', 'systemctl'):
            return proc(0)
        raise AssertionError(argv)

    def trace(self, body, request, ev, prefix, timeout):
        assert body is upload.VERIFY and request['expected_id'] == s5b.HA_ID
        return {'status': 'passed', 'ha_backup_id': s5b.HA_ID, 'bytes': s5b.FIXTURE_BYTES, 'sha256': s5b.FIXTURE_SHA,
                'identity': {'dev': 1, 'ino': 99}, 'sidecar_sha256': 'c' * 64, 'allocated_bytes': s5b.FIXTURE_BYTES}


class EndToEndSimulationTests(unittest.TestCase):
    """The whole S5-B run -- main(), the read-only proofs, R6's cold-to-cold path and case body with the S5-B variant,
    the end checks and the proof-root removal -- against FakeDevE. Every lab boundary is a fake; the guard refuses any
    host podman/labpodman process."""
    CACHE = None

    def setUp(self):
        if EndToEndSimulationTests.CACHE is None:
            with patch.object(s5, 'checkout', lambda repo: ('c' * 40, True)):
                # dev-e's engine when S5-B starts: another checkout's (as after the OpenDesign pilot's deploy-src.sh)
                other_lane = dict(s5.engine_manifest(REPO, s5.ENGINE_COMMIT), **{'lib/woowbackup/cli.py': '1' * 64,
                                                                                 'helper': '2' * 64})
                EndToEndSimulationTests.CACHE = (s5b.lease_template(REPO), s5b.git_manifest(REPO),
                                                 (other_lane, s5.engine_manifest(REPO, s5b.PRODUCT_COMMIT)))

    def run_s5b(self, mode='pass'):
        template, rows, engines = EndToEndSimulationTests.CACHE
        fake = FakeDevE(engines, rows, mode)
        home = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, home, True)
        lab = home / '.woowbk-lab'; secrets_dir = lab / 'secrets'; secrets_dir.mkdir(parents=True)
        (secrets_dir / 'ha-import-creds.env').write_text('HA_BACKUP_KEY=AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG\n'
                                                         'B2_NC_X86_NOSHARE_USER_PW=noshare-user-pw-1\n'
                                                         'B2_NC_X86_NOSHARE_APP_PW=noshare-app-pw-12\n')
        (secrets_dir / 'b1-creds.env').write_text('')
        (secrets_dir / 'dev-e-markers.json').write_text(json.dumps({'nextcloud': 'marker-password-1'}))
        (secrets_dir / 'dev-e-kit.txt').write_text('# kit\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ\n')
        now = datetime.datetime.now(datetime.timezone.utc)
        lease = dict(template, not_before_utc=(now - datetime.timedelta(minutes=1)).isoformat(),
                     expires_utc=(now + datetime.timedelta(minutes=120)).isoformat())
        lease_path = home / 'lease.json'; lease_path.write_text(json.dumps(lease))
        original_load = r6.load_flow

        def load_flow(receipt=None):
            mod = original_load(receipt)
            mod.drv.helper, mod.drv.device_python, mod.drv.owner = fake.helper, fake.device_python, fake.owner
            mod.drv.root = lambda *a, **k: (_ for _ in ()).throw(AssertionError('no root command'))
            fake.nc_module = mod
            return mod
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(Path, 'home', return_value=home))   # every evidence folder and receipt here
            for target, name, value in (
                    (s5b, 'LAB', lab), (s5b, 'RECEIPT', lab / 'run/focus_nextcloud_r6_s5b.json'), (r6, 'LAB', lab),
                    (r6, 'RECEIPT', lab / 'run/focus_nextcloud_r6.json'), (s5b, 'LOCK', str(home / 'lock')),
                    (s5, 'checkout', lambda repo: ('c' * 40, True)), (s5b, 'lease_template', lambda repo: copy.deepcopy(template)),
                    (s5b, 'frozen_manifest', lambda path: ({}, rows)), (wake, 'device', fake.device), (cold, 'device', fake.device),
                    (case, 'collect', fake.collect), (case.source, 'transact', fake.transact),
                    (case, 'reload_units', lambda: fake.events.append('reload')), (r6, 'baseline_verify', lambda: True),
                    (r6, 'load_flow', load_flow), (s5b, 'trace', fake.trace)):
                stack.enter_context(patch.object(target, name, value))
            stack.enter_context(patch.dict(os.environ, {'HEAVY_FREE': str(home / 'lock')}))
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            rc = s5b.main(['--run', '--lease', str(lease_path)])
        records = sorted((lab / 'evidence').glob(s5b.AREA + '-run/*/fixed-result.json'))
        result = json.loads(records[-1].read_text())
        checks = json.loads(next((lab / 'evidence').glob(s5b.AREA + '/*/results.json')).read_text())
        return rc, fake, result, checks, home, out.getvalue()

    def assert_no_secret_in_any_record(self, fake, home):
        needles = [fake.password, *fake.config.values(), *fake.private_keys.values(), 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG',
                   'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ', 'marker-password-1', 'noshare-user-pw-1']
        for path in home.rglob('*'):
            if path.is_file() and 'secrets' not in path.parts and path.name != 'lease.json':
                text = path.read_bytes()
                for needle in needles:
                    self.assertNotIn(needle.encode(), text, path)

    def test_a_passing_run_imports_verifies_rolls_back_returns_cold_and_only_then_removes_the_proof_root(self):
        rc, fake, result, checks, home, out = self.run_s5b()
        self.assertEqual(checks['failed'], 0, [(c['check'], c['detail']) for c in checks['results'] if not c['ok']])
        self.assertEqual(rc, 0, result)
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['proof_root_removed'] and result['prior_engine_returned_exactly'] and result['owned_store_clean'])
        self.assertEqual(result['evidence_leak_scan']['hits'], 0)
        self.assertGreater(result['evidence_leak_scan']['files'], 20)
        self.assertEqual(result['store_delta']['uploads']['added'], ['u' + 'a' * 16 + '.done'])
        self.assertEqual(result['prior_engine_manifest_sha256'], s5.manifest_hash(fake.prior_engine))   # captured, not bound
        binding = json.loads(next((home / '.woowbk-lab/evidence').glob(s5b.AREA + '-run/*/binding.json')).read_text())
        self.assertEqual(binding['prior_engine_captured'], fake.prior_engine)
        self.assertIn('helper', binding['prior_differs_from_frozen_product'])
        e = fake.events
        order = ['s5a-state', 'source-install', 'wake', 'upload-begin', 'copy-inside-dev-e', 'upload-finish', 'ha-check-start',
                 'ha-convert-start', 'cold-stop', 'source-restore', 'remove-proof-root']
        self.assertEqual(sorted(e.index(x) for x in order), [e.index(x) for x in order])
        self.assertEqual(e.count('ha-convert-start'), 2)                 # refused without, then with the bound key
        self.assertEqual(e[-1], 'remove-proof-root')                     # the very last device step
        self.assertLess(max(i for i, x in enumerate(e) if x == 'leak-scan'), e.index('source-restore'))
        self.assertEqual((fake.engine, fake.nc, fake.ha), ('prior', 'original', set()))
        self.assertEqual(sorted(fake.backups), sorted(['20261123T084036Z-5ebb7283', '20261123T121327Z-74c471c6', case.BASELINE]))
        self.assertEqual(len(fake.new), 0)                               # the manual rollback took the new file too
        names = [c['check'] for c in checks['results']]
        # import: 5 of R6's import_real + the conversion's own line + 10 verification lines + the new encrypted file;
        # restart: the restart + 10 + the new file still there; auto rollback: the rollback + 10 + the new file + its
        # own safety backup deleted.
        for phase, count in (('import', 17), ('restart', 12), ('auto rollback', 13), ('check', 5), ('upload', 3)):
            self.assertEqual(sum(n.startswith(phase + ':') for n in names), count, phase)
        self.assertIn('convert: without the acknowledgement the conversion is refused (confirmation-required, Nextcloud '
                      'skipped by exactly the encryption line, no stop, no backup added)', names)
        self.assertEqual(checks['passed'], 96)                           # the expected fixed lines of a real passing run
        self.assert_no_secret_in_any_record(fake, home)

    def test_an_unexpected_check_line_stops_before_any_conversion_and_keeps_the_proof_root(self):
        rc, fake, result, checks, home, _ = self.run_s5b('check-extra-confirm')
        self.assertEqual(rc, 1)
        self.assertNotIn('ha-convert-start', fake.events)
        self.assertNotIn('remove-proof-root', fake.events)
        self.assertFalse(result['proof_root_removed'])
        self.assertEqual((fake.engine, fake.ha), ('prior', set()))       # the HA record of the run is gone, engine back
        self.assertIn('check: exactly one confirmation: nextcloud.server-side-encryption, reasons exactly files_encryption '
                      'and encryption_enabled, its bound key, the not-yet-tested text', checks['failed_checks'])
        self.assert_no_secret_in_any_record(fake, home)

    def test_a_verification_failure_still_rolls_back_cleans_up_and_keeps_the_proof_root(self):
        rc, fake, result, checks, home, _ = self.run_s5b('disk-changed')
        self.assertEqual(rc, 1)
        self.assertNotIn('remove-proof-root', fake.events)
        self.assertIn('restore-start', fake.events)
        self.assertEqual((fake.engine, fake.nc, fake.ha), ('prior', 'original', set()))
        self.assertEqual(sorted(fake.backups), sorted(['20261123T084036Z-5ebb7283', '20261123T121327Z-74c471c6', case.BASELINE]))
        self.assertTrue(any('byte for byte' in c for c in checks['failed_checks']))

    def test_a_conversion_without_the_acknowledgement_that_succeeds_fails_the_run(self):
        rc, fake, result, checks, home, _ = self.run_s5b('converts-unacknowledged')
        self.assertEqual(rc, 1)
        self.assertEqual(fake.events.count('ha-convert-start'), 1)       # the step stopped the case
        self.assertNotIn('remove-proof-root', fake.events)
        self.assertEqual(sorted(fake.backups), sorted(['20261123T084036Z-5ebb7283', '20261123T121327Z-74c471c6', case.BASELINE]))

    def test_an_engine_that_did_not_come_back_keeps_the_proof_root(self):
        rc, fake, result, checks, home, _ = self.run_s5b('source-restore-fails')
        self.assertEqual(checks['failed'], 0)                            # the case itself passed
        self.assertEqual(rc, 1)
        self.assertFalse(result['prior_engine_returned_exactly'])
        self.assertNotIn('remove-proof-root', fake.events)

    def test_another_engine_than_the_captured_prior_back_keeps_the_proof_root(self):
        rc, fake, result, checks, home, _ = self.run_s5b('wrong-engine-back')
        self.assertEqual((rc, result['prior_engine_returned_exactly'], result['proof_root_removed']), (1, False, False))
        self.assertNotIn('remove-proof-root', fake.events)


if __name__ == '__main__':
    unittest.main()
