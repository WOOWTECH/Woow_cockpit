"""Offline safety boundaries only; no browser, relay listener or lab device."""
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


ui = module('prepared_ui', 'focus_acceptance_ui.py')
relay = module('prepared_relay', 'focus_acceptance_ui_relay.py')


class OfflineSafetyTests(unittest.TestCase):
    def test_default_does_not_enter_runtime(self):
        with patch.object(ui, 'run', side_effect=AssertionError('unleased runtime')) as run:
            self.assertEqual(ui.main([]), 0)
            run.assert_not_called()

    def test_relay_object_does_not_start_a_listener(self):
        with patch.object(relay.asyncio, 'start_server', side_effect=AssertionError('unleased listener')) as start:
            value = relay.Relay()
            self.assertIsNone(value.thread)
            self.assertEqual(value.children, set())
            start.assert_not_called()

    def test_fixed_stdio_command_uses_unprivileged_lab_exec(self):
        cmd = relay.command()
        self.assertEqual(cmd[:7], [str(relay.LP), 'exec', '-i', '--user', 'devadmin', 'woowbk-dev-d', 'python3'])
        self.assertEqual(cmd[7:9], ['-I', '-c'])
        self.assertIn('socket.create_connection(("127.0.0.1", 9090)', cmd[9])
        self.assertNotIn('.bind(', cmd[9])
        self.assertNotIn('podman run', cmd[9])
        compile(cmd[9], '<fixed remote client>', 'exec')


class DerivedCopyTests(unittest.TestCase):
    def original(self, folder, *, omit=False, link=False):
        path = folder/'original.tar'
        with tarfile.open(path, 'w') as archive:
            for name in ['backup.json', 'homeassistant.tar.gz', 'omni.tar.gz', 'hermes.tar.gz', 'headscale.tar.gz'] + ([] if omit else [ui.BROKEN]):
                info = tarfile.TarInfo(name)
                data = (name.encode()+b'\x00\xff')*100
                info.size = len(data)
                if link and name == ui.BROKEN:
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/outside'
                    info.size = 0
                archive.addfile(info, io.BytesIO(data) if info.isfile() else None)
        return path

    def test_copy_changes_only_last64bytes_of_reviewed_member(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            original = self.original(folder)
            before = original.read_bytes()
            output = folder/'derived.tar'
            ui.derive(original, output)
            self.assertEqual(original.read_bytes(), before)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with tarfile.open(original) as left, tarfile.open(output) as right:
                self.assertEqual(left.getnames(), right.getnames())
                for name in left.getnames():
                    want = left.extractfile(name).read()
                    self.assertEqual(right.extractfile(name).read(), want[:-64] if name == ui.BROKEN else want)

    def test_original_and_existing_destination_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            original = self.original(Path(folder))
            with self.assertRaises(ValueError):
                ui.derive(original, original)
            other = Path(folder)/'existing.tar'
            other.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                ui.derive(original, other)
            self.assertEqual(other.read_bytes(), b'keep')

    def test_missing_member_and_outer_link_are_refused(self):
        for options in ({'omit':True}, {'link':True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as folder:
                original = self.original(Path(folder), **options)
                before = original.read_bytes()
                with self.assertRaises(ValueError):
                    ui.derive(original, Path(folder)/'derived.tar')
                self.assertEqual(original.read_bytes(), before)


class CurrentPageContractTests(unittest.TestCase):
    def test_only_nonpersistent_oneshot_probe_is_outside_durable_state_gate(self):
        rows=[{'unit':name,'active':state,'sub':'dead' if state=='inactive' else 'running'} for name,state in (
            ('omnigent-server-health.service','inactive'),('hermes-agent.service','inactive'),
            ('hermes-image-setup.service','active'),('omnigent-server-health.timer','active'),
            ('headscale.service','activating'))]
        props={'omnigent-server-health.service':{'Type':'oneshot','RemainAfterExit':'no'},
               'hermes-image-setup.service':{'Type':'oneshot','RemainAfterExit':'yes'}}
        states=ui.stable_units(rows,props)
        self.assertNotIn('omnigent-server-health.service',states)
        self.assertNotIn('headscale.service',states)
        self.assertEqual(states['hermes-agent.service'][0],'inactive')
        self.assertEqual(states['hermes-image-setup.service'][0],'active')
        self.assertEqual(states['omnigent-server-health.timer'][0],'active')
        self.assertIn('omnigent-server-health.service',ui.stable_units(rows,{}))

    def records(self):
        rows = [{'type':kind,'state':'succeeded'} for kind in ('backup','restore','backup','restore')]
        rows[-1]['result']={'group':{'results':[{'app_id':x,'status':'imported'} for x in ('hermes','omnigent')]}}
        return rows

    def test_two_importable_apps_make_four_jobs(self):
        self.assertTrue(ui.chain_complete(self.records()))

    def test_old_five_job_assumption_and_partial_success_are_not_accepted(self):
        rows = self.records()
        self.assertFalse(ui.chain_complete([{'type':'backup','state':'failed'}]+rows))
        rows[1]['state']='rolled-back'
        self.assertFalse(ui.chain_complete(rows))
        rows = self.records()
        rows[-1]['result']['group']['results'][0]['app_id']='emqx'
        self.assertFalse(ui.chain_complete(rows))

    def test_read_only_marker_wrapper_requires_known_producer_boundary(self):
        source = Path(__file__).with_name('batch1_markers.py').read_text()
        prepared = ui.marker_program(source)
        compile(prepared, '<observed existing markers>', 'exec')
        self.assertIn('issued.append(token)', prepared)
        with self.assertRaises(ValueError):
            ui.marker_program('unreviewed_call()')


class RecoveryReadinessTests(unittest.TestCase):
    def proof(self, root):
        case = root/'focus-acceptance-ui/old-case'
        case.mkdir(parents=True)
        (case/'recovery.json').write_text('{"phase":"recovery-retained"}')
        (case/'summary.json').write_text('{"failed":3}')
        old = {'evidence_dir':str(case),'phase':'recovery-retained','baseline_restored':True,
               'inflight':None,'created_backups':['backup-%d'%i for i in range(6)],'source_commit':'frozen'}
        guard = json.dumps(old).encode()
        facts = dict.fromkeys(('data_recovery_verified','original_markers_equal','original_units_equal',
                              'original_images_equal','original_timer_equal','original_catalog_equal',
                              'original_fixture_hash_equal','network_isolation_preserved','old_ha_retained',
                              'old_captures_unchanged','old_guard_unchanged','old_summary_unchanged',
                              'scan_covers_archive_index_sidecars','scan_covers_requests_pending_exports'),True)
        facts.update(scope='r8-independent-recovery-only',acceptance_passed=False,guard_override_performed=False,
                     cookie_coverage_of_old_attempt=False,old_cookie_coverage='absent-not-retroactively-proved',
                     active_jobs=0,old_archives_retained=6,scan={'hits':0,'scanned':30,'archive_index_sidecars_scanned':6},
                     source_commit='frozen',old_guard_sha256=hashlib.sha256(guard).hexdigest(),
                     old_receipt_sha256=ui.sha(case/'recovery.json'),old_summary_sha256=ui.sha(case/'summary.json'))
        path = root/'focus-acceptance-ui-recovery/new-proof/receipt.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(facts)); path.chmod(0o600)
        return guard,path,facts

    def test_exact_independent_recovery_allows_readiness_without_acceptance_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); guard,path,_=self.proof(root)
            before=path.read_bytes()
            old,provenance=ui.verified_recovery(guard,path,ui.sha(path),root)
            self.assertEqual(old['phase'],'recovery-retained')
            self.assertFalse(provenance['acceptance_passed'])
            self.assertEqual(provenance['old_guard_sha256'],hashlib.sha256(guard).hexdigest())
            self.assertEqual(path.read_bytes(),before)

    def test_wrong_proof_sha_or_changed_failed_files_do_not_allow_readiness(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); guard,path,_=self.proof(root)
            with self.assertRaises(ValueError):ui.verified_recovery(guard,path,'0'*64,root)
            with self.assertRaises(ValueError):ui.verified_recovery(guard+b' ',path,ui.sha(path),root)
            old=json.loads(guard)
            (Path(old['evidence_dir'])/'summary.json').write_text('changed')
            with self.assertRaises(ValueError):ui.verified_recovery(guard,path,ui.sha(path),root)

    def test_acceptance_claim_or_missing_index_coverage_cannot_replace_recovery_facts(self):
        changes=({'acceptance_passed':True},{'original_catalog_equal':False},
                 {'cookie_coverage_of_old_attempt':True},{'active_jobs':1},
                 {'scan':{'hits':0,'scanned':30,'archive_index_sidecars_scanned':0}})
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                root=Path(folder); guard,path,facts=self.proof(root)
                facts.update(change); path.write_text(json.dumps(facts))
                with self.assertRaises(ValueError):ui.verified_recovery(guard,path,ui.sha(path),root)

    def test_shared_or_symlinked_receipt_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); guard,path,_=self.proof(root)
            path.chmod(0o644)
            with self.assertRaises(ValueError):ui.verified_recovery(guard,path,ui.sha(path),root)
            path.chmod(0o600)
            target=path.with_name('target.json'); path.rename(target); path.symlink_to(target)
            with self.assertRaises(ValueError):ui.verified_recovery(guard,path,ui.sha(path),root)


class RetainedHAOwnershipTests(unittest.TestCase):
    digest='1234567890abcdef'*4
    ha_id='ha-'+digest[:20]

    def test_absent_record_is_owned_but_exact_retained_record_is_never_owned(self):
        self.assertTrue(ui.ha_record_owned([],self.ha_id,self.digest))
        previous={'ha_id':self.ha_id,'derived_fixture_sha256':self.digest}
        rows=[{'id':self.ha_id,'sha256':self.digest}]
        self.assertFalse(ui.ha_record_owned(rows,self.ha_id,self.digest,previous))

    def test_unproved_or_changed_existing_record_refuses_reuse(self):
        row={'id':self.ha_id,'sha256':self.digest}
        previous={'ha_id':self.ha_id,'derived_fixture_sha256':self.digest}
        for rows,old in (([row],None),([dict(row,sha256='0'*64)],previous),
                         ([row],dict(previous,derived_fixture_sha256='0'*64)),([row,row],previous)):
            with self.subTest(rows=len(rows),old=old), self.assertRaises(ValueError):
                ui.ha_record_owned(rows,self.ha_id,self.digest,old)


class SelectedImageScopeTests(unittest.TestCase):
    def bindings(self):
        return {unit:{'source':'/home/appowner/.config/containers/systemd/'+unit.removesuffix('.service')+'.container',
                      'container_name':name} for unit,name in ui.IMAGE_UNITS.items()}

    def images(self):
        return {name:'image-%d'%n for n,name in enumerate(ui.IMAGE_UNITS.values())}

    def test_unrelated_crashloop_arrival_does_not_change_selected_image_map(self):
        before=self.images(); during=dict(before,headscale='unrelated-image')
        self.assertEqual(ui.project_images(before,self.bindings()),before)
        self.assertEqual(ui.project_images(during,self.bindings()),before)
        self.assertEqual(len(ui.project_images(during,self.bindings())),8)

    def test_missing_any_selected_image_or_binding_is_refused(self):
        for unit,name in ui.IMAGE_UNITS.items():
            with self.subTest(unit=unit):
                images=self.images();del images[name]
                with self.assertRaises(ValueError):ui.project_images(images,self.bindings())
                bindings=self.bindings();del bindings[unit]
                with self.assertRaises(ValueError):ui.project_images(self.images(),bindings)

    def test_changed_trusted_source_or_container_name_is_refused(self):
        for field,value in (('source','/tmp/untrusted.container'),('container_name','headscale')):
            with self.subTest(field=field):
                bindings=self.bindings();bindings['emqx.service'][field]=value
                with self.assertRaises(ValueError):ui.project_images(self.images(),bindings)


class HealthTimerPhaseTests(unittest.TestCase):
    def properties(self):
        return {ui.HEALTH_TIMER:{'Unit':ui.HEALTH_PROBE,'UnitFileState':'enabled'},
                ui.HEALTH_PROBE:{'Type':'oneshot','RemainAfterExit':'no'}}

    def states(self, phase='waiting'):
        return {ui.HEALTH_TIMER:['active',phase],'omnigent-server.service':['active','running']}

    def test_observed_active_timer_phases_are_equal_without_changing_raw_snapshots(self):
        waiting=self.states();running=self.states('running')
        self.assertTrue(ui.units_equal(waiting,running,self.properties()))
        self.assertEqual(running[ui.HEALTH_TIMER],['active','running'])
        self.assertEqual(waiting[ui.HEALTH_TIMER],['active','waiting'])

    def test_enablement_active_state_or_probe_metadata_changes_are_refused(self):
        for key,value in (('UnitFileState','disabled'),('UnitFileState','masked'),('Unit','other.service')):
            with self.subTest(key=key,value=value):
                props=self.properties();props[ui.HEALTH_TIMER][key]=value
                self.assertFalse(ui.units_equal(self.states(),self.states(),props))
        props=self.properties();props[ui.HEALTH_PROBE]['RemainAfterExit']='yes'
        self.assertFalse(ui.units_equal(self.states(),self.states(),props))
        for state in (['inactive','dead'],['active','elapsed'],['failed','failed']):
            current=self.states();current[ui.HEALTH_TIMER]=state
            self.assertFalse(ui.units_equal(current,self.states(),self.properties()))

    def test_every_other_unit_and_missing_health_timer_stay_exact(self):
        current=self.states();current['omnigent-server.service']=['inactive','dead']
        self.assertFalse(ui.units_equal(current,self.states(),self.properties()))
        current=self.states();del current[ui.HEALTH_TIMER]
        self.assertFalse(ui.units_equal(current,self.states(),self.properties()))
        self.assertFalse(ui.units_equal(self.states(),self.states(),{}))


if __name__ == '__main__':
    unittest.main()
