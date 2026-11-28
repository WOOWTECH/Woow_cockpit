"""Offline: the b12 lease generator writes exactly the leases the CURRENT tools admit, from the successor's prepared files, and
refuses every missing or unfitting input before writing anything. The quiescence tool's own main() runs on every generated
pause/resume lease up to the point right after its admission (it is stopped there); the controller's and the engine patch's
own validators run on theirs. No device, lock or secret; every value generated."""
import copy
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
import focus_litellm_instance_acceptance_leases as gen   # noqa: E402

DRIVER = 'd' * 40
OLD = 'e' * 40
PRIOR = 'woowbk_focus_litellm_79c2701a7740'


class Stop(Exception):
    """The quiescence tool reached the step right after its lease admission."""


class Case:
    """A temporary leases folder with the successor's real receipts of a new case (prepared by the real successor code)."""

    def __init__(self, root, d):
        self.root, self.d = Path(root), d
        self.leases = self.root / 'leases'
        self.leases.mkdir(mode=0o700)
        succ = sys.modules.get('focus_litellm_instance_acceptance_successor')
        if succ is None or Path(succ.__file__).resolve().parent != d.lab:
            import importlib
            succ = importlib.import_module('focus_litellm_instance_acceptance_successor')
        q = d.quiesce
        self.before = {'catalogs': {'emqx.json': 'c' * 64}, 'files': {q.QFILE: {'sha256': '4' * 64, 'mode': 420, 'uid': 1019,
                                                                                 'gid': 1019}},
                       'containers': {'hermes-agent': '1' * 64}, 'external_containers': {'hermes-agent': '1' * 64},
                       'secrets': {'headscale-headplane-api-key': 'a1'}, 'volumes': {'headscale-data': 't1'},
                       'networks': {'headscale-net': 'n1'}, 'running': ['hermes-agent'], 'units': {}, 'active_jobs': [],
                       'timer': {'UnitFileState': 'masked'}, 'images': ['f' * 64], 'image_refs': {}, 'package': False,
                       'config_directory': False}
        reuse = dict(d.source.ops.common.RETAINED_IMAGE)
        prior = {'name': PRIOR, 'device': d.plan.DEVICE, 'before': self.before, 'complete': True, 'recovery_verified': True,
                 'pending': None, 'pending_operation': None, 'catalog_intent': False, 'pg_tag_intent': False,
                 'hook_intent': False, 'timer_intent': False, 'images_ready': True, 'owned_images': [],
                 'derived_image': reuse['derived_image'], 'image_reuse': reuse, 'created_backups': [], 'before_backups': [],
                 'store_id': 'ha-own', 'before_uploads': []}
        checks = sorted(succ.RECOVERY_CHECKS | {'outer_isolation_returned'})
        output = {'phase': 'flow', 'phase_succeeded': True, 'flow_verified': True, 'complete': True, 'recovery_verified': True,
                  'baseline_sha256': d.digest(self.before), 'checks': [{'check': c, 'ok': True} for c in checks]}
        self.live = copy.deepcopy(self.before)
        self.live['secrets']['headscale-headplane-api-key'] = 'a2'          # the Headscale page run recreated its secret
        live = {'device': d.plan.DEVICE, 'case': 'x', 'at': 1, 'inventory': self.live, 'inventory_sha256': d.digest(self.live),
                'backup_ids': [], 'ha_upload_ids': []}
        files = {}
        for key, value in (('prior', prior), ('output', output), ('live', live)):
            files[key] = self.root / f'{key}.private.json'
            files[key].write_bytes(d.source.ops.canonical(value))
            files[key].chmod(0o600)
        self.name = 'woowbk_focus_litellm_0123456789ab'
        self.flow = self.leases / f'litellm-instance-{self.name[-12:]}.private.json'
        self.pause = self.leases / f'litellm-instance-{self.name[-12:]}.pause-admission.private.json'
        sha = lambda p: d.source.ops.digest(p.read_bytes())
        self.prepared = succ.prepare(prior_receipt=files['prior'], prior_receipt_sha=sha(files['prior']),
                                     prior_output=files['output'], prior_output_sha=sha(files['output']), live=files['live'],
                                     live_sha=sha(files['live']), new_name=self.name, flow_receipt=self.flow,
                                     pause_receipt=self.pause, adopt=('headscale',))
        self.journal = gen.journal_path(self.name, self.leases)

    def write_journal(self, **state):
        value = {'name': self.name, 'driver_commit': DRIVER, 'source_commit': self.d.plan.FROZEN_PRODUCT,
                 'baseline_sha256': self.d.digest(self.live), 'state': state}
        self.journal.write_bytes(self.d.source.ops.canonical(value))
        self.journal.chmod(0o600)

    def after_flow(self, **changes):
        """The flow receipt as the controller leaves it after a complete flow and recovery (its own capture = the original)."""
        r = json.loads(self.flow.read_text())
        r.update(before=copy.deepcopy(self.live), install_intent=True, complete=True, recovery_verified=True, page_intent=True,
                 pending=None, jobs={'j20261128T120000Z-0000aaa1': {'state': 'succeeded', 'type': 'backup'}})
        r.update(changes)
        self.flow.write_bytes(self.d.source.ops.canonical(r))
        self.flow.chmod(0o600)


def fake_git(d, product):
    """Clean checkouts with fixed HEADs: the driver, the old engine checkout and the frozen product (also PRODUCT_DIR)."""
    heads = {str(Path(d.checkout).resolve()): DRIVER, str(Path(product).resolve()): d.plan.FROZEN_PRODUCT,
             str(Path(d.plan.PRODUCT_DIR)): d.plan.FROZEN_PRODUCT}

    def git(path, *args):
        key = str(Path(path).resolve()) if Path(path).exists() else str(path)
        if args == ('status', '--porcelain'):
            return ''
        if args == ('rev-parse', 'HEAD'):
            return heads.get(key, OLD)
        raise AssertionError(args)
    return git


class GeneratorCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = gen.Driver(REPO)
        self.product = Path(self.tmp.name) / 'product'
        self.product.mkdir()
        (self.product / '.git').write_text('gitdir: elsewhere\n')
        self.case = Case(self.tmp.name, self.d)
        stack = patch.object(gen, 'git', fake_git(self.d, self.product))
        stack.start()
        self.addCleanup(stack.stop)
        exists = Path.exists
        # The controller's PRODUCT_DIR is a real path on the coordinator's host; here it counts as a checkout.
        stack = patch.object(gen.Path, 'exists', lambda p: True if p == Path(self.d.plan.PRODUCT_DIR) / '.git' else exists(p))
        stack.start()
        self.addCleanup(stack.stop)
        self.now = datetime.now(timezone.utc)

    def admitted_by_quiesce(self, lease, receipt, phase):
        """Run the quiescence tool's main() on the files; it must pass its lease admission and stop at the next step."""
        q, source = self.d.quiesce, self.d.source
        output = Path(self.tmp.name) / f'{phase}-output.json'

        def git(*args, raw=False):
            if args == ('rev-parse', 'HEAD'):
                return DRIVER
            raise Stop(args)
        with patch.object(source, 'git', git):
            with self.assertRaises(Stop) as caught:
                q.main(['--execute', '--phase', phase, '--lease', str(lease), '--receipt', str(receipt), '--journal',
                        str(self.case.journal), '--output', str(output)])
        self.assertEqual(caught.exception.args[0], ('status', '--porcelain'))   # the step right after the admission

    @staticmethod
    def lease(path):
        path = Path(path)
        assert path.stat().st_mode & 0o777 == 0o600, oct(path.stat().st_mode)
        return json.loads(path.read_text())


class StepTests(GeneratorCase):
    def test_the_whole_b12_sequence_writes_exactly_what_each_tool_admits(self):
        d, c = self.d, self.case
        # 1. Headscale pause, from the successor's pause-admission receipt (its re-adopted original).
        got = gen.pause(d, admission_path=c.pause, label='b12', leases=c.leases, now=self.now)
        lease = self.lease(got['lease'])
        self.assertEqual(Path(got['lease']).name, 'lease-litellm-quiescence-b12-pause-dev-d.json')
        self.assertEqual({k: v for k, v in lease.items() if k not in ('expires_utc', 'coordinator_review')}, {
            'granted': True, 'case': 'litellm-instance-quiesce', 'device': 'woowbk-dev-d', 'driver_commit': DRIVER,
            'source_commit': d.plan.FROZEN_PRODUCT, 'method': d.quiesce.METHOD, 'name': c.name, 'unit': 'headscale.service',
            'bounds': d.quiesce.BOUNDS, 'source_path': d.quiesce.QFILE, 'source_sha256': '4' * 64,
            'baseline_sha256': c.prepared['baseline_sha256'], 'phases': ['pause'],
            'journal_filename': f'litellm-headscale-quiescence-{c.name[-12:]}.private.json'})
        self.assertEqual(datetime.fromisoformat(lease['expires_utc']) - self.now, timedelta(minutes=40))
        self.admitted_by_quiesce(got['lease'], c.pause, 'pause')
        self.assertIn('focus_litellm_instance_acceptance_quiesce.py --execute --phase pause', got['next'])
        self.assertIn('HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock', got['next'])
        self.assertIn('litellm-headscale-b12-pause-01.json', got['next'])
        # 2. The flow, only after a proven pause (the journal says paused).
        with self.assertRaisesRegex(gen.Refused, 'journal missing'):
            gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause, label='b12', leases=c.leases, now=self.now)
        c.write_journal(original={'unit': {}}, paused=True, pending=None, resumed=False)
        got = gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause, label='b12', leases=c.leases,
                       now=self.now)
        lease = self.lease(got['lease'])
        self.assertEqual({k: v for k, v in lease.items() if k not in ('expires_utc', 'coordinator_review')}, {
            'granted': True, 'case': 'litellm-instance-original', 'device': 'woowbk-dev-d', 'phases': ['flow', 'recover'],
            'driver_commit': DRIVER, 'name': c.name, 'fixture_sha256': d.plan.FIXTURE_SHA,
            'derivation_sha256': d.plan.DERIVATION_SHA, 'package_commit': d.plan.PACKAGE_COMMIT,
            'baseline_sha256': c.prepared['baseline_sha256'], 'source_commit': d.plan.FROZEN_PRODUCT,
            'baseline_policy': 'require-litellm-absent', 'image_policy': 'retain-for-case', 'import_path': 'page'})
        self.assertEqual(datetime.fromisoformat(lease['expires_utc']) - self.now, timedelta(minutes=79))
        for phase in ('flow', 'recover'):
            d.run.validate_lease(lease, phase, now=self.now.timestamp() + 60, driver_commit=DRIVER,
                                 source_commit=d.plan.FROZEN_PRODUCT, via_page=True)
        with self.assertRaisesRegex(ValueError, 'import_path'):
            d.run.validate_lease(lease, 'flow', now=self.now.timestamp(), driver_commit=DRIVER,
                                 source_commit=d.plan.FROZEN_PRODUCT)   # never without --via-page
        self.assertIn('--phase flow --via-page --source', got['next'])
        self.assertIn('timeout --signal=TERM --kill-after=1200 3300', got['next'])
        # 3. The resume, from the flow receipt after a complete flow and recovery.
        with self.assertRaisesRegex(gen.Refused, 'after the flow'):
            gen.resume(d, flow_path=c.flow, label='b12', leases=c.leases, now=self.now)
        c.after_flow()
        got = gen.resume(d, flow_path=c.flow, label='b12', leases=c.leases, now=self.now)
        lease = self.lease(got['lease'])
        self.assertEqual((lease['phases'], lease['baseline_sha256'], lease['name']),
                         (['resume'], c.prepared['baseline_sha256'], c.name))
        self.admitted_by_quiesce(got['lease'], c.flow, 'resume')
        # Every lease is new, private and never overwritten.
        with self.assertRaisesRegex(gen.Refused, 'never overwritten'):
            gen.resume(d, flow_path=c.flow, label='b12', leases=c.leases, now=self.now)
        self.assertEqual(sorted(p.name for p in c.leases.glob('lease-*')), [
            'lease-litellm-fullflow-b12-dev-d.json', 'lease-litellm-quiescence-b12-pause-dev-d.json',
            'lease-litellm-quiescence-b12-resume-dev-d.json'])

    def test_the_engine_patch_lease_names_exactly_the_files_that_differ(self):
        old, new = Path(self.tmp.name) / 'old', self.product
        for root, changed in ((old, 'old'), (new, 'new')):
            lib = root / 'backup-engine' / 'woowbackup'
            lib.mkdir(parents=True)
            (lib / 'cli.py').write_text('same\n')
            (lib / 'ha_n8n.py').write_text(changed + '\n')
            (lib / 'ha_nextcloud.py').write_text(changed + '\n')
            (root / 'backup-engine' / 'woowtech-cockpit-backup').write_text('helper\n')
        (old / '.git').write_text('gitdir: elsewhere\n')
        got = gen.engine_patch(self.d, old_source=old, product=new, label='b12', leases=self.case.leases, now=self.now)
        lease = self.lease(got['lease'])
        self.assertEqual(got['files'], ['ha_n8n.py', 'ha_nextcloud.py'])
        self.assertEqual((lease['case'], lease['device'], lease['phases'], lease['driver_commit'], lease['source_commit'],
                          lease['old_source_commit'], lease['files']),
                         ('engine-patch', 'woowbk-dev-d', ['engine-patch', 'engine-patch-restore'], DRIVER,
                          self.d.plan.FROZEN_PRODUCT, OLD, ['ha_n8n.py', 'ha_nextcloud.py']))
        self.assertRegex(lease['name'], r'woowbk_focus_n8n_[0-9a-f]{12}\Z')
        for phase in self.d.patch.PHASES:
            self.d.patch.validate(lease, phase, device_name='woowbk-dev-d', driver=DRIVER, source_commit=self.d.plan.FROZEN_PRODUCT,
                                  old_commit=OLD, names=lease['files'], now=self.now.timestamp() + 60)
        self.assertEqual(datetime.fromisoformat(lease['expires_utc']) - self.now, timedelta(minutes=30))
        self.assertIn('focus_engine_patch.py --execute --device d --phase engine-patch', got['next'])
        self.assertIn('focus_engine_patch.ll-b12-dev-d.json', got['next'])
        # The same engine on both sides is no patch at all.
        shutil.rmtree(old / 'backup-engine')
        shutil.copytree(new / 'backup-engine', old / 'backup-engine')
        with self.assertRaisesRegex(gen.Refused, 'changed engine files'):
            gen.engine_patch(self.d, old_source=old, product=new, label='b12x', leases=self.case.leases, now=self.now)

    def test_a_recover_lease_for_an_expired_flow_window(self):
        d, c = self.d, self.case
        got = gen.recover(d, product=self.product, flow_path=c.flow, admission_path=c.pause, label='b12', leases=c.leases,
                          now=self.now)
        lease = self.lease(got['lease'])
        self.assertEqual((lease['phases'], lease['import_path'], lease['baseline_sha256']),
                         (['recover'], 'page', c.prepared['baseline_sha256']))
        d.run.validate_lease(lease, 'recover', now=self.now.timestamp() + 60, driver_commit=DRIVER,
                             source_commit=d.plan.FROZEN_PRODUCT, via_page=True)
        with self.assertRaises(ValueError):
            d.run.validate_lease(lease, 'flow', now=self.now.timestamp() + 60, driver_commit=DRIVER,
                                 source_commit=d.plan.FROZEN_PRODUCT, via_page=True)
        self.assertIn('--phase recover --via-page', got['next'])


class RefusalTests(GeneratorCase):
    def refused(self, pattern, call):
        before = sorted(p.name for p in self.case.leases.glob('lease-*'))
        with self.assertRaisesRegex(gen.Refused, pattern):
            call()
        self.assertEqual(sorted(p.name for p in self.case.leases.glob('lease-*')), before)   # nothing written

    def test_missing_foreign_or_unproven_inputs_write_nothing(self):
        d, c = self.d, self.case
        self.refused('pause-admission receipt missing',
                     lambda: gen.pause(d, admission_path=c.leases / 'absent.json', label='b12', leases=c.leases, now=self.now))
        c.pause.chmod(0o644)
        self.refused('private 0600', lambda: gen.pause(d, admission_path=c.pause, label='b12', leases=c.leases, now=self.now))
        c.pause.chmod(0o600)
        self.refused('not a pause-admission receipt',
                     lambda: gen.pause(d, admission_path=c.flow, label='b12', leases=c.leases, now=self.now))
        c.write_journal(original={}, paused=False, pending='pause', resumed=False)
        self.refused('journal exists', lambda: gen.pause(d, admission_path=c.pause, label='b12', leases=c.leases, now=self.now))
        self.refused('pause is not proven', lambda: gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause,
                                                              label='b12', leases=c.leases, now=self.now))
        c.write_journal(original={}, paused=True, pending=None, resumed=False)
        other = json.loads(c.flow.read_text())
        other['name'] = 'woowbk_focus_litellm_ffffffffffff'
        stranger = c.leases / 'stranger.private.json'
        stranger.write_text(json.dumps(other))
        stranger.chmod(0o600)
        self.refused('not the one the successor prepared', lambda: gen.flow(
            d, product=self.product, flow_path=stranger, admission_path=c.pause, label='b12', leases=c.leases, now=self.now))
        for minutes in (0, 29, 81):
            self.refused('window', lambda: gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause,
                                                     label='b12', leases=c.leases, minutes=minutes, now=self.now))
        for minutes in (6, 91):
            c.journal.unlink(missing_ok=True)
            self.refused('window', lambda: gen.pause(d, admission_path=c.pause, label='b12', leases=c.leases,
                                                      minutes=minutes, now=self.now))

    def test_checkouts_must_be_clean_and_the_product_the_frozen_one(self):
        d, c = self.d, self.case
        c.write_journal(original={}, paused=True, pending=None, resumed=False)
        heads = fake_git(d, self.product)

        def dirty_driver(path, *args):
            if args == ('status', '--porcelain') and Path(path).resolve() == Path(d.checkout).resolve():
                return ' M tests/e2e/lab/x.py'
            return heads(path, *args)

        def old_product(path, *args):
            if args == ('rev-parse', 'HEAD') and Path(path).resolve() == self.product.resolve():
                return '0' * 40
            return heads(path, *args)
        with patch.object(gen, 'git', dirty_driver):
            self.refused('uncommitted', lambda: gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause,
                                                          label='b12', leases=c.leases, now=self.now))
        with patch.object(gen, 'git', old_product):
            self.refused('frozen to', lambda: gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause,
                                                        label='b12', leases=c.leases, now=self.now))
        (self.product / '.git').unlink()
        self.refused('not a git checkout', lambda: gen.flow(d, product=self.product, flow_path=c.flow, admission_path=c.pause,
                                                             label='b12', leases=c.leases, now=self.now))

    def test_the_resume_waits_for_a_finished_flow_and_its_recovery(self):
        d, c = self.d, self.case
        c.write_journal(original={'unit': {}}, paused=True, pending=None, resumed=False)
        for label, changes, pattern in (
                ('running job', {'jobs': {'j20261128T120000Z-0000aaa1': {'state': 'running', 'type': 'restore'}}}, 'recover first'),
                ('pending start', {'pending': {'tag': 'import'}}, 'recover first'),
                ('recovery incomplete', {'complete': False}, 'recovery is incomplete')):
            with self.subTest(label):
                c.after_flow(**changes)
                self.refused(pattern, lambda: gen.resume(d, flow_path=c.flow, label='b12', leases=c.leases, now=self.now))
        c.after_flow(complete=True, pending=None, jobs={})
        c.write_journal(original={'unit': {}}, paused=False, pending=None, resumed=True)
        self.refused('resume is complete', lambda: gen.resume(d, flow_path=c.flow, label='b12', leases=c.leases, now=self.now))
        c.write_journal(original={'unit': {}}, paused=True, pending=None, resumed=False)
        changed = json.loads(c.flow.read_text())
        changed['before']['running'] = []
        c.flow.write_bytes(d.source.ops.canonical(changed))
        self.refused('another case, baseline', lambda: gen.resume(d, flow_path=c.flow, label='b12', leases=c.leases,
                                                                   now=self.now))

    def test_the_command_line_refuses_missing_inputs_and_names_a_fresh_case(self):
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(gen.main(['name', '--driver', str(REPO)]), 0)
        self.assertRegex(json.loads(out.getvalue())['name'], r'woowbk_focus_litellm_[0-9a-f]{12}\Z')
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(gen.main(['flow', '--driver', str(REPO), '--leases', str(self.case.leases)]), 2)
        self.assertEqual(json.loads(out.getvalue()), {'written': False,
                                                      'refused': 'missing: --product, --flow-receipt, --pause-receipt'})
        with self.assertRaises(SystemExit):
            with patch('sys.stderr', new_callable=io.StringIO):
                gen.main(['pause', '--driver', str(REPO), '--label', 'B12/../x'])
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(gen.main(['pause', '--driver', str(Path(self.tmp.name) / 'nothing')]), 2)
        self.assertIn('no LiteLLM controller', json.loads(out.getvalue())['refused'])

    def test_every_tool_bound_comes_from_the_driver_checkouts_code(self):
        self.assertEqual(Path(self.d.run.__file__).resolve().parent, HERE)
        self.assertEqual(Path(self.d.quiesce.__file__).resolve().parent, HERE)
        self.assertEqual(Path(self.d.patch.__file__).resolve().parent, HERE)
        # A value the tools keep as a module constant is never written here: it is read from the driver checkout.
        text = (HERE / 'focus_litellm_instance_acceptance_leases.py').read_text()
        p, q = self.d.plan, self.d.quiesce
        for constant in (p.FROZEN_PRODUCT[:8], p.FIXTURE_SHA[:8], p.DERIVATION_SHA[:8], p.PACKAGE_COMMIT[:8], q.UNIT, q.METHOD,
                         q.QFILE):   # (case names are built in the regexes' form and checked by the tools' validators)
            self.assertNotIn(constant, text)
        self.assertIsNone(re.search(r'\b%d\b' % q.BOUNDS['outer_seconds'], text))   # the pause/resume outer bound too


if __name__ == '__main__':
    unittest.main()
