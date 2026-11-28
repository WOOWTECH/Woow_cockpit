"""Successor b12 after b11: a predecessor whose flow PASSED, and the stack-scoped re-adoption of a dev-d that other reviewed lanes
restored or restarted after it. No device; every value generated."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import focus_litellm_instance_acceptance_successor as s

PRIOR = 'woowbk_focus_litellm_79c2701a7740'
NEW = 'woowbk_focus_litellm_0123456789ab'
STACKS = ('headscale', 'headplane', 'woow-emqx', 'woow_emqx', 'hermes', 'omnigent')


def digest(value):
    return s.source.ops.digest(s.source.ops.canonical(value))


def inventory():
    """The shape of b11's verified original (names as on dev-d, ids generated)."""
    return {'catalogs': {'emqx.json': 'c' * 64, 'hermes.json': 'd' * 64},
            'files': {'/home/appowner/.config/containers/systemd/headscale.container': {'sha256': 'e' * 64, 'mode': 420,
                                                                                         'uid': 1019, 'gid': 1019}},
            'containers': {'hermes-agent': '1' * 64, 'omnigent-server': '2' * 64, 'woow-emqx': '3' * 64},
            'external_containers': {'hermes-agent': '1' * 64, 'omnigent-server': '2' * 64, 'woow-emqx': '3' * 64},
            'secrets': {'headscale-headplane-api-key': 'a1', 'hermes-postgres-password': 'b1', 'woow-emqx-node-cookie': 'c1'},
            'volumes': {'headscale-data': '2026-11-19 07:00:00 +0800 CST', 'headplane-data': '2026-11-19 07:00:01 +0800 CST',
                        'woow_emqx_data': '2026-11-20 08:00:00 +0800 CST', '0' * 64: '2026-11-18 01:00:00 +0800 CST'},
            'networks': {'headscale-net': 'n1', 'hermes': 'n2', 'woow_emqx_network': 'n3', 'podman': 'n4'},
            'running': ['hermes-agent', 'omnigent-server', 'woow-emqx'], 'units': {'litellm.service': {'ActiveState': 'inactive'}},
            'timer': {'UnitFileState': 'masked', 'ActiveState': 'inactive'}, 'images': ['f' * 64], 'image_refs': {'x': 'f' * 64},
            'active_jobs': [], 'package': False, 'config_directory': False}


def restored(before):
    """dev-d after R1, page-emqx and the Headscale page run: the same names, new ids and volume creation times."""
    live = copy.deepcopy(before)
    live['containers'].update({'hermes-agent': '7' * 64, 'woow-emqx': '8' * 64})
    live['external_containers'].update({'hermes-agent': '7' * 64, 'woow-emqx': '8' * 64})
    live['secrets'].update({'headscale-headplane-api-key': 'a2', 'woow-emqx-node-cookie': 'c2'})
    live['volumes'].update({'headscale-data': '2026-11-28 10:00:00 +0800 CST', 'woow_emqx_data': '2026-11-28 09:00:00 +0800 CST'})
    live['networks'].update({'headscale-net': 'n9'})
    return live


class Fixture:
    def __init__(self, root, *, passed=True):
        self.root = Path(root)
        self.before = inventory()
        reuse = dict(s.source.ops.common.RETAINED_IMAGE)
        self.prior = {'name': PRIOR, 'device': s.plan.DEVICE, 'before': self.before, 'complete': True, 'recovery_verified': True,
                      'pending': None, 'pending_operation': None, 'catalog_intent': False, 'pg_tag_intent': False,
                      'hook_intent': False, 'timer_intent': False, 'images_ready': True, 'owned_images': [],
                      'derived_image': reuse['derived_image'], 'image_reuse': reuse, 'created_backups': ['20261127T094500Z-0a0a0a0a'],
                      'before_backups': ['20260101T000000Z-aaaaaaaa'], 'store_id': 'ha-own', 'before_uploads': ['ha-old'],
                      'generated_credentials': {'OLD_CASE_TEST_ONLY': 'never-copied'}}
        # b11's fullflow-07: the flow passed, its recovery completed in the same run, up to the outer isolation.
        checks = sorted(s.RECOVERY_CHECKS | {'outer_isolation_returned', 'selective_instance_import'})
        self.output = {'phase': 'flow', 'phase_succeeded': passed, 'flow_verified': passed, 'complete': True,
                       'recovery_verified': True, 'baseline_sha256': digest(self.before),
                       'checks': [{'check': c, 'ok': True} for c in checks]}
        self.live = {'device': s.plan.DEVICE, 'case': NEW, 'at': 1, 'inventory': restored(self.before),
                     'backup_ids': ['20260101T000000Z-aaaaaaaa'], 'ha_upload_ids': ['ha-old']}

    def write(self):
        self.live['inventory_sha256'] = digest(self.live['inventory'])
        paths = {}
        for key, value in (('prior_receipt', self.prior), ('prior_output', self.output), ('live', self.live)):
            paths[key] = self.root / (key + '.json')
            paths[key].write_bytes(s.source.ops.canonical(value))
            paths[key].chmod(0o600)
        return paths

    def arguments(self, paths, **changes):
        sha = lambda key: s.source.ops.digest(paths[key].read_bytes())
        return dict(dict(prior_receipt=paths['prior_receipt'], prior_receipt_sha=sha('prior_receipt'),
                         prior_output=paths['prior_output'], prior_output_sha=sha('prior_output'), live=paths['live'],
                         live_sha=sha('live'), new_name=NEW, flow_receipt=self.root / 'flow.private.json',
                         pause_receipt=self.root / 'pause.private.json'), **changes)


class PassedPredecessorTests(unittest.TestCase):
    def test_a_passed_flow_with_its_own_completed_recovery_is_an_accepted_predecessor(self):
        with tempfile.TemporaryDirectory() as root:
            f = Fixture(root)
            f.live['inventory'] = copy.deepcopy(f.before)   # an exact successor: nothing changed on dev-d
            kwargs = f.arguments(f.write())
            result = s.prepare(**kwargs)
            self.assertEqual((result['predecessor'], result['baseline_sha256']), (PRIOR, digest(f.before)))
            self.assertNotIn('adopted', result)
            self.assertEqual(json.loads(kwargs['pause_receipt'].read_text())['before'], f.before)

    def test_a_passed_flow_must_also_be_verified_and_reach_the_outer_isolation(self):
        for label, mutate in (('flow not verified', lambda o: o.update(flow_verified=False)),
                              ('flow verification unknown', lambda o: o.pop('flow_verified')),
                              ('no outer isolation', lambda o: o.update(checks=[c for c in o['checks']
                                                                                if c['check'] != 'outer_isolation_returned'])),
                              ('recovery incomplete', lambda o: o.update(complete=False)),
                              ('a recovery check missing', lambda o: o.update(checks=[c for c in o['checks']
                                                                                      if c['check'] != 'all_jobs_terminal']))):
            with self.subTest(label), tempfile.TemporaryDirectory() as root:
                f = Fixture(root)
                f.live['inventory'] = copy.deepcopy(f.before)
                mutate(f.output)
                kwargs = f.arguments(f.write())
                with self.assertRaisesRegex(ValueError, 'predecessor recovery'):
                    s.prepare(**kwargs)
                self.assertFalse(os.path.lexists(kwargs['flow_receipt']))

    def test_the_recovered_rule_keeps_every_earlier_case(self):
        base = {'complete': True, 'recovery_verified': True}
        checks = set(s.RECOVERY_CHECKS)
        self.assertTrue(s.recovered(dict(base, phase='recover', phase_succeeded=True), checks | {'outer_isolation_returned'}))
        self.assertTrue(s.recovered(dict(base, phase='flow', phase_succeeded=False, flow_verified=False), checks))
        self.assertTrue(s.recovered(dict(base, phase='flow', phase_succeeded=True, flow_verified=True),
                                    checks | {'outer_isolation_returned'}))
        for output in (dict(base, phase='flow', phase_succeeded=True, flow_verified=False),
                       dict(base, phase='flow', phase_succeeded=False, flow_verified=True),
                       dict(base, phase='images', phase_succeeded=True, flow_verified=True)):
            self.assertFalse(s.recovered(output, checks | {'outer_isolation_returned'}), output)


class AdoptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(self.tmp.name)

    def test_without_prefixes_any_difference_still_refuses_with_the_exact_message(self):
        kwargs = self.f.arguments(self.f.write())
        with self.assertRaisesRegex(ValueError, r'differs from the verified original at: \.containers\.hermes-agent'):
            s.prepare(**kwargs)
        self.assertFalse(os.path.lexists(kwargs['flow_receipt']) or os.path.lexists(kwargs['pause_receipt']))

    def test_only_ids_of_the_named_restored_stacks_are_re_adopted_and_the_live_inventory_becomes_the_original(self):
        kwargs = self.f.arguments(self.f.write())
        result = s.prepare(**kwargs, adopt=STACKS)
        live = self.f.live['inventory']
        pause = json.loads(kwargs['pause_receipt'].read_text())
        flow = json.loads(kwargs['flow_receipt'].read_text())
        self.assertEqual(pause['before'], live)
        self.assertNotIn('before', flow)
        self.assertEqual(result['baseline_sha256'], digest(live))
        self.assertEqual(result['adopted_prefixes'], sorted(STACKS))
        self.assertEqual(result['adopted'], ['.containers.hermes-agent', '.containers.woow-emqx',
                                             '.external_containers.hermes-agent', '.external_containers.woow-emqx',
                                             '.networks.headscale-net', '.secrets.headscale-headplane-api-key',
                                             '.secrets.woow-emqx-node-cookie', '.volumes.headscale-data',
                                             '.volumes.woow_emqx_data'])
        self.assertNotIn('never-copied', kwargs['flow_receipt'].read_text() + kwargs['pause_receipt'].read_text())

    def test_anything_but_an_id_of_a_name_on_both_sides_of_a_named_stack_refuses(self):
        cases = {
            'a file changed': lambda live: live['files'][next(iter(live['files']))].update(sha256='9' * 64),
            'a catalog appeared': lambda live: live['catalogs'].update({'headscale.json': '9' * 64}),
            'the timer changed': lambda live: live['timer'].update(UnitFileState='enabled'),
            'a unit changed': lambda live: live['units']['litellm.service'].update(ActiveState='active'),
            'an image appeared': lambda live: live['images'].append('9' * 64),
            'the failing unit\'s own container caught': lambda live: (live['containers'].update({'headscale': '9' * 64}),
                                                                     live['running'].append('headscale')),
            'a container of a named stack removed': lambda live: live['containers'].pop('omnigent-server'),
            'a new volume of a named stack': lambda live: live['volumes'].update({'headscale-extra': 'x'}),
            'an anonymous volume recreated': lambda live: live['volumes'].update({'0' * 64: 'x'}),
            'a stack nobody restored': lambda live: live['networks'].update({'podman': 'n0'}),
            'a lookalike name': lambda live: (live['containers'].update({'hermesx-agent': '5' * 64}),
                                              self.f.before['containers'].update({'hermesx-agent': '6' * 64})),
        }
        for label, mutate in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as root:
                self.f = Fixture(root)
                mutate(self.f.live['inventory'])
                self.f.output['baseline_sha256'] = digest(self.f.before)
                kwargs = self.f.arguments(self.f.write())
                with self.assertRaisesRegex(ValueError, 'outside the restored stacks'):
                    s.prepare(**kwargs, adopt=STACKS)
                self.assertFalse(os.path.lexists(kwargs['flow_receipt']) or os.path.lexists(kwargs['pause_receipt']))

    def test_prefixes_are_plain_distinct_names(self):
        kwargs = self.f.arguments(self.f.write())
        for adopt in (('Headscale',), ('headscale', 'headscale'), ('',), ('a',), ('head scale',), ('../x',)):
            with self.subTest(adopt=adopt), self.assertRaisesRegex(ValueError, 'prefixes'):
                s.prepare(**kwargs, adopt=adopt)
        self.assertTrue(s.owned_by('woow-emqx-entrance', ('woow-emqx',)))
        self.assertTrue(s.owned_by('woow_emqx_data', ('woow_emqx',)))
        self.assertTrue(s.owned_by('hermes', ('hermes',)))
        for name in ('woow-emqx2', 'hermesx-agent', 'headscal', 'xheadscale-net'):
            self.assertFalse(s.owned_by(name, ('woow-emqx', 'hermes', 'headscale')), name)

    def test_differences_lists_every_path_and_what_the_prefixes_would_accept(self):
        self.f.live['inventory']['files'][next(iter(self.f.live['inventory']['files']))]['mode'] = 384
        paths = self.f.write()
        kwargs = self.f.arguments(paths)
        report = s.differences(prior_receipt=kwargs['prior_receipt'], prior_receipt_sha=kwargs['prior_receipt_sha'],
                               live=kwargs['live'], live_sha=kwargs['live_sha'], adopt=STACKS)
        self.assertEqual(report['predecessor'], PRIOR)
        self.assertEqual(len(report['differences']), 10)
        self.assertEqual(report['refused'], ['.files./home/appowner/.config/containers/systemd/headscale.container.mode'])
        self.assertEqual(len(report['adoptable']), 9)
        plain = s.differences(prior_receipt=kwargs['prior_receipt'], prior_receipt_sha=kwargs['prior_receipt_sha'],
                              live=kwargs['live'], live_sha=kwargs['live_sha'])
        self.assertEqual((plain['adoptable'], len(plain['refused'])), ([], 10))
        text = json.dumps(report)
        for value in ('7' * 64, 'a2', 'n9', '2026-11-28'):
            self.assertNotIn(value, text)   # names only, never an id or a time


class QuietCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.lock = self.root / 'lock'
        self.lock.write_bytes(b'')

    def transport(self, answers):
        calls = []

        def root(*argv, input=None, timeout=0):
            calls.append(json.loads(input))
            return SimpleNamespace(returncode=0, stdout=json.dumps(answers.pop(0) if len(answers) > 1 else answers[0]).encode(),
                                   stderr=b'')
        return SimpleNamespace(DEVICE=None, root=root, calls=calls, require_isolated_device=lambda: None,
                               helper=lambda command, request=None, timeout=0: (0, {'ok': True, 'backups': [], 'ha_backups': []}))

    def test_with_no_exact_look_the_first_quiet_look_is_kept(self):
        old = {'containers': {'a': '1'}, 'running': []}
        flapping = {'containers': {'a': '2', 'headscale': '9'}, 'running': ['headscale']}
        quiet = {'containers': {'a': '2'}, 'running': []}
        t = self.transport([flapping, quiet, flapping])
        out = self.root / 'live.private.json'
        s.capture(out, transport=t, case=NEW, lock=str(self.lock), expect=digest(old), tries=3, sleep=lambda n: None,
                  without=('headscale',))
        value = json.loads(out.read_text())
        self.assertEqual((value['inventory'], value['looks'], value['without_containers'], len(t.calls)), (quiet, 2, ['headscale'], 3))
        # Without an expected baseline the first quiet look ends the capture at once.
        t = self.transport([flapping, quiet])
        out = self.root / 'live2.private.json'
        s.capture(out, transport=t, case=NEW, lock=str(self.lock), tries=5, sleep=lambda n: None, without=('headscale',))
        self.assertEqual((json.loads(out.read_text())['looks'], len(t.calls)), (2, 2))
        # An exact look still wins over a quiet one.
        t = self.transport([quiet, old])
        out = self.root / 'live3.private.json'
        s.capture(out, transport=t, case=NEW, lock=str(self.lock), expect=digest(old), tries=5, sleep=lambda n: None,
                  without=('headscale',))
        self.assertEqual(json.loads(out.read_text())['inventory'], old)

    def test_every_look_flapping_refuses_and_writes_nothing(self):
        flapping = {'containers': {'headscale': '9'}, 'external_containers': {}, 'running': []}
        t = self.transport([flapping])
        out = self.root / 'live.private.json'
        with self.assertRaisesRegex(RuntimeError, 'capture again'):
            s.capture(out, transport=t, case=NEW, lock=str(self.lock), tries=3, sleep=lambda n: None, without=('headscale',))
        self.assertFalse(out.exists())

    def test_the_command_line_offers_the_three_steps_and_parses_the_new_options(self):
        with patch.object(s.source, 'git', side_effect=AssertionError('no runtime')), \
                patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(s.main([]), 0)
        self.assertEqual(json.loads(out.getvalue())['steps'], ['--capture (device, read-only)', '--differences (host only)',
                                                               '--prepare (host only)'])
        seen = {}
        with patch.object(s.source, 'git', return_value=''), \
                patch.object(s, 'differences', lambda **kw: seen.update(kw) or {'host_only': True}), \
                patch('sys.stdout', new_callable=io.StringIO):
            s.main(['--differences', '--prior-receipt', '/r', '--prior-receipt-sha', '1', '--live', '/l', '--live-sha', '2',
                    '--adopt-restored', 'headscale,woow-emqx'])
        self.assertEqual(seen['adopt'], ('headscale', 'woow-emqx'))
        with patch.object(s.source, 'git', return_value=''), \
                patch.object(s, 'prepare', lambda **kw: seen.update(prepare=kw) or {'host_only': True}), \
                patch('sys.stdout', new_callable=io.StringIO):
            s.main(['--prepare', '--prior-receipt', '/r', '--prior-receipt-sha', '1', '--prior-output', '/o',
                    '--prior-output-sha', '3', '--live', '/l', '--live-sha', '2', '--new-name', NEW, '--flow-receipt', '/f',
                    '--pause-receipt', '/p'])
        self.assertEqual(seen['prepare']['adopt'], ())   # no option: the exact successor of before


if __name__ == '__main__':
    unittest.main()
