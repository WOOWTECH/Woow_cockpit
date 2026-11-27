"""Local checks of the ARM54 final-lane coordinator (pure helpers and static safety properties).

These are unit tests of the harness only; they are not acceptance of any service restore.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import unittest

import arm54_final_control as control

LAB = Path(__file__).resolve().parent


def local(slug, **over):
    doc = {'bytes': 10, 'sha256': 'a' * 64, 'backup_json_sha256': 'b' * 64, 'slug': slug,
           'date': '2026-11-19T07:00:20.955461+00:00', 'addons': [('1b7b4ce7_woow-headscale', '0.1.3')]}
    doc.update(over)
    return doc


def seen(**over):
    doc = {'listed': True, 'info_result': 'ok', 'file_bytes': 10, 'size_bytes': 10, 'file_sha256': 'a' * 64,
           'backup_json_sha256': 'b' * 64, 'date': '2026-11-19T07:00:20.955461+00:00',
           'addons': [['1b7b4ce7_woow-headscale', '0.1.3']]}
    doc.update(over)
    return doc


class ProvenanceTest(unittest.TestCase):
    def test_exact_match_is_verified(self):
        verdict = control.compare_provenance({'backups': {'45670371': seen()}}, {'45670371': local('45670371')})
        self.assertTrue(verdict['45670371']['verified'])

    def test_any_difference_refuses(self):
        cases = [seen(file_sha256='c' * 64), seen(file_bytes=11), seen(size_bytes=11), seen(listed=False),
                 seen(date='2026-11-19T07:00:21+00:00'), seen(addons=[]), seen(backup_json_sha256='d' * 64),
                 seen(info_result='error')]
        for case in cases:
            verdict = control.compare_provenance({'backups': {'45670371': case}}, {'45670371': local('45670371')})
            self.assertFalse(verdict['45670371']['verified'], case)

    def test_missing_source_row_refuses(self):
        verdict = control.compare_provenance({'backups': {}}, {'45670371': local('45670371')})
        self.assertFalse(verdict['45670371']['verified'])

    def test_slug_must_match_archive_metadata(self):
        verdict = control.compare_provenance({'backups': {'45670371': seen()}},
                                             {'45670371': local('a2dc9bfd')})
        self.assertFalse(verdict['45670371']['verified'])


class InventoryTest(unittest.TestCase):
    def test_identical_ignores_samples_only(self):
        before = {'containers': ['a'], 'free_bytes': 1, 'workspace': '/x', 'started_epoch': 1.0}
        after = {'containers': ['a'], 'free_bytes': 2}
        self.assertTrue(control.compare_inventory(before, after)['identical'])

    def test_strict_difference_is_reported(self):
        result = control.compare_inventory({'containers': ['a'], 'modules': ['tun']},
                                           {'containers': ['a'], 'modules': ['tun', 'dummy']})
        self.assertFalse(result['identical'])
        self.assertEqual(result['differing_keys'], ['modules'])

    def test_missing_key_is_a_difference(self):
        self.assertFalse(control.compare_inventory({'run_netns': []}, {})['identical'])

    def test_listening_is_informational(self):
        result = control.compare_inventory({'listening': ['tcp a']}, {'listening': ['tcp b']})
        self.assertTrue(result['identical'])
        self.assertEqual(result['informational_differences'], ['listening'])


class TransportTest(unittest.TestCase):
    def test_fixed_diagnostics_never_echo_text(self):
        result = control.fixed_diagnostics(b'root@192.168.2.54: Permission denied (publickey,password).')
        self.assertEqual(set(result.values()), {True, False})
        self.assertTrue(result['authentication_denied'])
        self.assertTrue(all(isinstance(v, bool) for v in result.values()))

    def test_ssh_uses_pinned_known_hosts_and_no_password_argument(self):
        argv = control.ssh_argv(control.HOST54)
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('UserKnownHostsFile=/tmp/ha-test-54-known-hosts', argv)
        secret = os.environ.get('ARMHA_PW')
        self.assertFalse(any('ARMHA_PW' in a or (secret and secret in a) for a in argv))

    def test_only_authorized_hosts(self):
        self.assertEqual({control.HOST54, control.HOST34}, {'192.168.2.54', '192.168.2.34'})


class RemoteScriptSafetyTest(unittest.TestCase):
    def source(self, name):
        return (LAB / name).read_text()

    def test_no_test_only_network_knob(self):
        for name in control.CODE_FILES:
            self.assertNotIn('TS_ASSUME_NETWORK_UP_FOR_TEST=true', self.source(name).replace(' ', ''))
            self.assertNotIn("'TS_ASSUME_NETWORK_UP_FOR_TEST'", self.source(name))

    def test_runtime_containers_have_no_network_or_ports(self):
        text = self.source('arm54_final_headscale.py')
        self.assertIn("'--network', 'none'", text)
        self.assertNotIn('--publish', text)
        self.assertNotIn('-p ', text)
        self.assertNotIn("'--network', 'host'", text)

    def test_private_store_only(self):
        runtime = self.source('arm54_final_runtime.py')
        self.assertIn("'--root', str(ROOT / 'store')", runtime)
        self.assertIn("'--runroot', str(ROOT / 'run')", runtime)
        for name in control.CODE_FILES[1:]:
            tree = ast.parse(self.source(name))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn('/var/lib/containers/storage', node.value)

    def test_original_containers_never_named(self):
        for name in control.CODE_FILES:
            text = self.source(name)
            for original in ('homeassistant', 'matter-server', 'woow-auth-gateway', 'pi-web'):
                self.assertNotIn("'" + original + "'", text)

    def test_public_import_holds_are_replaced_by_the_product_paths_that_enforce_them(self):
        """Until 2026-11-23 this test asserted the source text of both public holds (SECURITY_BLOCKER in ha_omnigent,
        PRESERVATION_BLOCKER in ha_emqx), and this lane's Omnigent runs up to owner-omnigent-attempt2 were made while
        they were on. The owner's decision 1 (2026-11-23, 「決定1 做」) replaced the holds by product paths that enforce
        every protection themselves (integration 97c22c9 Omnigent, 9bf8f5e EMQX, both after their security review):
        neither hold may come back half-way, and neither path may lose a step of its protection chain."""
        package = LAB.parents[2] / 'backup-engine/woowbackup'

        def calls(module, function):
            tree = ast.parse((package / module).read_text())
            node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function)
            return {c.func.id for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}

        self.assertNotIn('SECURITY_BLOCKER', (package / 'ha_omnigent.py').read_text())
        self.assertLessEqual({'require_registered_secrets', '_prepare', 'verdict', 'read_schema', 'trusted_schema',
                              'schema_differences', 'restore_trusted_data', 'require_schema', 'require_answers',
                              'carry_accounts_restricted', 'finish_trusted_data', 'audit_new_cluster'},
                             calls('ha_omnigent.py', 'convert'))
        self.assertNotIn('PRESERVATION_BLOCKER', (package / 'ha_emqx.py').read_text())
        self.assertLessEqual({'target_preflight', 'analyse'}, calls('ha_emqx.py', 'check'))
        self.assertLessEqual({'target_profile', '_build_candidate', '_package_candidate'}, calls('ha_emqx.py', 'convert'))
        self.assertLessEqual({'_source_analysis', 'acl_blocker', 'candidate_from_target', 'check_counts',
                              'candidate_readback'}, calls('ha_emqx.py', '_build_candidate'))

    def test_omnigent_run_is_isolated_and_uses_internal_candidate_only(self):
        text = self.source('arm54_final_omnigent.py')
        self.assertIn("'--network', 'none'", text)
        for word in ('--publish', "'--network', 'host'", 'PublishPort=', "'--net'"):
            self.assertNotIn(word, text)
        self.assertIn('_convert_candidate(work, app, False, converted_dir, schema_ddl_quiesced=True)', text)
        self.assertIn("must('public_convert_still_refuses_security_blocker'", text)
        self.assertIn("must('product_check_only_blocker_is_security_blocker'", text)
        self.assertNotIn('ha_omnigent.convert(work', text)
        # The quiescence stop happens inside the product's own discovery wrapper, before any schema capture.
        self.assertIn("podman('stop', '--time', '30', SERVER", text)

    def test_omnigent_login_values_never_in_argv(self):
        text = self.source('arm54_final_omnigent.py')
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'podman':
                names = {n.id for arg in node.args for n in ast.walk(arg) if isinstance(n, ast.Name)}
                self.assertFalse(names & {'passwords', 'creds', 'db_url', 'token', 'admin', 'member'}, ast.dump(node)[:120])


class OmnigentInputsTest(unittest.TestCase):
    SUMMARY = {'server_version': '0.21.0', 'alembic': 'abc', 'pg': '16.16',
               'admin': 'woow (is_admin, password B1_OMNI_ADMIN_PW)', 'member': 'b1member (invited, B1_OMNI_MEMBER_PW)',
               'users': [{'id': 'b1member', 'is_admin': False}, {'id': 'woow', 'is_admin': True}],
               'agent': {'id': 'a'}, 'scheduled_task': {'id': 't'}, 'admin_session': {'id': 's'},
               'attachment': {'file_id': 'f'}, 'member_sessions': [{'id': 'm'}],
               'db_counts': {'users': 3, 'account_tokens': 1}, 'runner_host': {'host_id': 'h'}, 'artifact_store': '/x'}

    def test_expectation_drops_free_text_and_derives_ids(self):
        doc = control.omni_expect(self.SUMMARY)
        self.assertEqual((doc['admin'], doc['member']), ('woow', 'b1member'))
        self.assertNotIn('B1_OMNI', json_text(doc))
        self.assertNotIn('runner_host', doc)

    def test_expectation_refuses_credential_fields(self):
        bad = dict(self.SUMMARY, agent={'id': 'a', 'password': 'x'})
        with self.assertRaises(SystemExit):
            control.omni_expect(bad)

    def test_expectation_needs_one_admin_and_one_member(self):
        bad = dict(self.SUMMARY, users=[{'id': 'woow', 'is_admin': True}])
        with self.assertRaises(SystemExit):
            control.omni_expect(bad)

    def test_store_driver_choices(self):
        self.assertEqual(control.DRIVERS, ('vfs', 'overlay'))
        runtime = (LAB / 'arm54_final_runtime.py').read_text()
        self.assertIn("overlay.skip_mount_home=true", runtime)

    def test_lab_logins_never_in_lane_sources_or_evidence(self):
        import ha_import_b1_e2e as b1
        paths = [b1.SECRET_DIR / 'b1-creds.env', b1.SECRET_DIR / 'ha-import-creds.env']
        if not all(p.exists() for p in paths):
            self.skipTest('lab secret files not on this machine')
        # Both files the lane reads: HA's Omnigent test logins and the B1 HA backup key.
        secrets = b1.Secrets(paths, b1.SECRET_DIR / 'dev-d-markers.json')
        values = [v.encode() for v in secrets.secret_values() if len(v) >= 6]
        files = [LAB / n for n in control.CODE_FILES] + [LAB / 'test_arm54_final.py', LAB / 'arm54_final_control.py']
        files += [p for p in control.EVIDENCE.rglob('*') if p.is_file()]
        hits = [str(p.name) for p in files if any(v in p.read_bytes() for v in values)]
        self.assertEqual(hits, [])


class PrivateWheelsTest(unittest.TestCase):
    def test_wheels_are_pinned_to_pypi_digests(self):
        self.assertEqual(sorted(control.WHEELS), [
            'PyNaCl-1.5.0-cp36-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl',
            'cffi-1.17.1-cp311-cp311-manylinux_2_17_aarch64.manylinux2014_aarch64.whl'])
        self.assertTrue(all(len(v) == 64 for v in control.WHEELS.values()))

    def test_other_bytes_are_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for name in control.WHEELS:
                Path(tmp, name).write_bytes(b'not the pinned wheel')
            with self.assertRaises(SystemExit):
                control.pydeps_tar(tmp, Path(tmp) / 'out.tar')

    def test_runtime_uses_workspace_wheels_only(self):
        runtime = (LAB / 'arm54_final_runtime.py').read_text()
        self.assertIn("sys.path.insert(0, str(ROOT / 'pydeps'))", runtime)
        self.assertNotIn('pip install', runtime)


class LargeArchiveTest(unittest.TestCase):
    """Item A (lane arm54-2): the >8GiB incompressible outer-archive probe on .54 with workspace-private tools."""

    def test_debs_are_pinned_to_debian_bookworm_entries(self):
        self.assertEqual(sorted(control.DEBS), ['age_1.1.1-1+b3_arm64.deb', 'zstd_1.5.4+dfsg2-5_arm64.deb'])
        for target, digest, pool in control.DEBS.values():
            self.assertIn(target, ('age.deb', 'zstd.deb'))
            self.assertEqual(len(digest), 64)
            self.assertTrue(pool.startswith('pool/main/'))
        import arm54_final_large_outer_static as static
        self.assertEqual(static.wrapper_digests(), {t: d for t, d, _ in control.DEBS.values()})

    def test_packages_and_inrelease_parsers(self):
        text = ('Package: age\nVersion: 1.1.1-1+b3\nFilename: pool/main/a/age/age_1.1.1-1+b3_arm64.deb\n'
                'Size: 12\nSHA256: ' + 'c' * 64 + '\nDescription: x\n continued\n\nPackage: other\n')
        rows = control.packages_entries(text)
        self.assertEqual(rows, {'pool/main/a/age/age_1.1.1-1+b3_arm64.deb': {
            'sha256': 'c' * 64, 'size': 12, 'package': 'age', 'version': '1.1.1-1+b3'}})
        release = ('Codename: bookworm\nMD5Sum:\n ' + 'a' * 32 + ' 5 main/binary-arm64/Packages.xz\nSHA256:\n '
                   + 'd' * 64 + ' 5 main/binary-arm64/Packages\n ' + 'e' * 64 + ' 7 main/binary-arm64/Packages.xz\n'
                   'Acquire-By-Hash: yes\n')
        self.assertEqual(control.inrelease_sha256(release, 'main/binary-arm64/Packages.xz'), ('e' * 64, 7))
        self.assertIsNone(control.inrelease_sha256(release, 'main/binary-armhf/Packages.xz'))

    def test_upload_large_refuses_other_bytes_before_any_transfer(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            for name in control.DEBS:
                Path(tmp, name).write_bytes(b'not the pinned package')
            with mock.patch.object(control, 'workspace', return_value='/var/tmp/x'), \
                 mock.patch.object(control, 'code_bundle', return_value={}), \
                 mock.patch.object(control, 'scp') as scp, mock.patch.object(control, 'remote') as remote:
                with self.assertRaises(SystemExit):
                    control.upload_large(tmp, 'never-written')
            scp.assert_not_called()
            remote.assert_not_called()

    def test_run_passes_and_records_script_args(self):
        from unittest import mock
        import subprocess
        seen = {}

        def fake_remote(host, code, timeout):
            seen['code'] = code
            return subprocess.CompletedProcess([], 0, b'{"status": "passed"}\n', b'')

        with mock.patch.object(control, 'require_clean', return_value='h'), \
             mock.patch.object(control, 'workspace', return_value='/var/tmp/woow-arm54-final-20261123-x'), \
             mock.patch.object(control, 'remote', side_effect=fake_remote), \
             mock.patch.object(control, 'write_result', return_value={'exit': 0, 'elapsed_seconds': 1,
                                                                       'stdout_sha256': 'x', 'source_commit': 'h'}) as wr:
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                control.run('arm54_final_large_outer.py', 'o', 10, ['--mib', '128'])
        self.assertIn("sys.argv = ['arm54_final_large_outer.py', '/var/tmp/woow-arm54-final-20261123-x', '--mib', "
                      "'128']", seen['code'])
        self.assertEqual(wr.call_args.kwargs['extra'], {'script_args': ['--mib', '128']})

    def test_large_bundle_carries_the_probe_but_no_evidence(self):
        import tarfile
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            hashes = control.code_bundle(Path(tmp) / 'c.tar.gz', large=True)
            with tarfile.open(Path(tmp) / 'c.tar.gz') as tar:
                names = tar.getnames()
        self.assertIn('tests/backup/bounded_incompressible_outer.py', names)
        self.assertIn('tests/__init__.py', names)
        self.assertIn('tests/e2e/lab/arm54_final_large_outer.py', names)
        self.assertFalse([n for n in names if n.startswith('tests/backup/evidence/')])
        self.assertEqual(sorted(hashes), sorted(names))

    def test_large_wrapper_static_safety(self):
        text = (LAB / 'arm54_final_large_outer.py').read_text()
        for needed in ("FLOOR = 4 * GIB", "'unshare', '--mount', '--propagation', 'private'", "'nice', '-n', '19'",
                       "'ionice', '-c3'", "'--reserve-gib', str(args.reserve_gib)", "'dpkg-deb', '--fsys-tarfile'",
                       "assert args.reserve_gib >= FLOOR // GIB", "'tools_installed_system_wide': False"):
            self.assertIn(needed, text)
        for banned in ('apt-get', 'apt install', "'dpkg', '-i'", 'dpkg -i', '--publish', "'--network', 'host'",
                       'rm -rf /', '/var/lib/containers/storage'):
            self.assertNotIn(banned, text)


class ArmOdooN8nTest(unittest.TestCase):
    """Item B (lane arm54-2): the 2026-11-19 RPi5 backups and the n8n restore script on .54."""

    def test_sources_are_pinned_to_the_2026_11_19_records(self):
        self.assertEqual(sorted(control.ARM_SOURCES), ['arm-enc', 'arm-native', 'arm-plain', 'arm-unc'])
        for stem, slug, digest, encrypted in control.ARM_SOURCES.values():
            self.assertEqual((len(slug), len(digest)), (8, 64))
        import ast as ast_
        tree = ast_.parse((LAB / 'arm54_final_n8n.py').read_text())
        recorded = next(ast_.literal_eval(n.value) for n in tree.body if isinstance(n, ast_.Assign)
                        and any(getattr(t, 'id', None) == 'RECORDED' for t in n.targets))
        for kind in ('arm-plain', 'arm-enc'):
            _stem, slug, digest, _enc = control.ARM_SOURCES[kind]
            self.assertEqual(recorded[slug], digest)

    def test_other_bytes_are_refused(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            stem = control.ARM_SOURCES['arm-plain'][0]
            Path(tmp, stem).mkdir()
            Path(tmp, stem, stem + '.tar').write_bytes(b'not the recorded backup')
            with mock.patch.object(control, 'ARM_FIXTURES', Path(tmp)):
                with self.assertRaises(SystemExit):
                    control.arm_fixture('arm-plain')

    def test_n8n_script_isolation_and_product_paths(self):
        text = (LAB / 'arm54_final_n8n.py').read_text()
        for needed in ("'--network', 'none'", "'DB_POSTGRESDB_HOST=127.0.0.1'", 'ha_n8n.check(work, app)',
                       'ha_n8n.convert(work, app, False, converted_dir)', 'adapter._recreate_volume(',
                       'adapter._restore_database(pg,', 'adapter._ensure_database(pg)', "must('rollback_restores_", 'enter_private_netns()', "must('run_in_its_own_netns_not_the_hosts'",
                       "'runner': 'rootful private store (RootfulRunner); not production OwnerRunner/rootless'"):
            self.assertIn(needed, text)
        for banned in ('--publish', "'--network', 'host'", 'PublishPort=', 'unpublish:workflow',
                       '/var/lib/containers/storage'):
            self.assertNotIn(banned, text.replace("'PublishPort'", ''))

    def test_n8n_values_never_in_podman_argv(self):
        tree = ast.parse((LAB / 'arm54_final_n8n.py').read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'podman':
                names = {n.id for arg in node.args for n in ast.walk(arg) if isinstance(n, ast.Name)}
                self.assertFalse(names & {'creds', 'target_password', 'cookie', 'key_text', 'raw'},
                                 ast.dump(node)[:120])

    def test_n8n_lab_values_never_in_lane_sources_or_evidence(self):
        import ha_import_e2e as e2e
        paths = (e2e.SECRET_DIR / 'ha-import-creds.env', e2e.SECRET_DIR / 'ha-import-n8n-testdata.sh')
        if not all(p.exists() for p in paths):
            self.skipTest('lab secret files not on this machine')
        secrets = e2e.Secrets(*paths)
        values = [secrets[k].encode() for k in ('N8N_OWNER_PW', 'N8N_CREDENTIAL_VALUE', 'HA_BACKUP_KEY')
                  if len(secrets[k]) >= 6]
        files = [LAB / n for n in control.CODE_FILES] + [LAB / 'test_arm54_final.py', LAB / 'arm54_final_control.py']
        files += [p for p in control.EVIDENCE.rglob('*') if p.is_file()]
        self.assertEqual([p.name for p in files if any(v in p.read_bytes() for v in values)], [])


def json_text(doc):
    import json
    return json.dumps(doc)


if __name__ == '__main__':
    unittest.main()


class OwnerRunnerItemCTest(unittest.TestCase):
    """Item C (OwnerRunner rootless on .54): code identity of runs, the uidmap pin, static safety of the scripts."""

    def test_committed_code_hashes_cover_engine_and_owner_scripts(self):
        hashes = control.committed_code_hashes()
        for name in ('backup-engine/woowbackup/podman.py', 'tests/e2e/lab/arm54_final_owner_setup.py',
                     'tests/e2e/lab/arm54_final_owner_headscale.py', 'tests/e2e/lab/arm54_final_owner_cleanup.py',
                     'tests/e2e/lab/arm54_final_owner_common.py'):
            self.assertIn(name, hashes)

    def test_remote_code_check_refuses_other_bytes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'source/x'
            src.mkdir(parents=True)
            (src / 'a.py').write_text('print(1)\n')
            good = {'x/a.py': __import__('hashlib').sha256(b'print(1)\n').hexdigest()}
            exec(control.REMOTE_CODE_CHECK.replace('WANT', repr(good)).replace('ROOT', repr(tmp)), {})
            with self.assertRaises(AssertionError):
                exec(control.REMOTE_CODE_CHECK.replace('WANT', repr({'x/a.py': '0' * 64})).replace('ROOT', repr(tmp)), {})
            with self.assertRaises(AssertionError):
                exec(control.REMOTE_CODE_CHECK.replace('WANT', repr({'x/missing.py': '0' * 64})).replace('ROOT', repr(tmp)), {})

    def test_uidmap_pin_equals_owner_common(self):
        import arm54_final_owner_common as oc
        self.assertEqual(control.OWNER_DEB[1], oc.UIDMAP_SHA256)
        self.assertIn('uidmap', control.OWNER_DEB[0])

    def test_safe_tail_masks_tokens_and_drops_secret_lines(self):
        import arm54_final_owner_common as oc
        text = oc.safe_tail(b'Error: TOKEN=abc\nplain failure abcdefghijklmnopqrstuvwxyz0123456789ab\nok')
        self.assertNotIn('TOKEN', text)
        self.assertNotIn('abcdefghijklmnopqrstuvwxyz0123456789ab', text)
        self.assertIn('<masked>', text)

    def test_owner_images_are_pinned_by_digest_and_arm64(self):
        source = (LAB / 'arm54_final_owner_images.py').read_text()
        tree = ast.parse(source)
        images = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                      and getattr(node.targets[0], 'id', None) == 'IMAGES')
        for kind, rows in images.items():
            for ref, arm64, _tag in rows:
                self.assertRegex(ref, r'@sha256:[0-9a-f]{64}$', kind)
                self.assertTrue(arm64.startswith('sha256:'), kind)
        self.assertIn("'--arch', 'arm64'", source)
        self.assertIn('arm54_final_owner_images.py', control.CODE_FILES)

    def test_tool_debs_equal_the_item_a_pins(self):
        import arm54_final_owner_common as oc
        pins = {target: digest for _name, (target, digest, _pool) in control.DEBS.items()}
        self.assertEqual({name: want for name, (want, _members) in oc.TOOL_DEBS.items()}, pins)

    def test_tools_check_refuses_other_bytes(self):
        import hashlib
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'input').mkdir()
            (Path(tmp) / 'input' / 'age.deb').write_bytes(b'age')
            good = {'age.deb': hashlib.sha256(b'age').hexdigest()}
            exec(control.TOOLS_CHECK.replace('ROOT', repr(tmp)).replace('WANT', repr(good)), {})
            with self.assertRaises(AssertionError):
                exec(control.TOOLS_CHECK.replace('ROOT', repr(tmp)).replace('WANT', repr({'age.deb': '0' * 64})), {})

    def test_modules_to_unload_only_allowlisted_new_ones(self):
        import arm54_final_owner_common as oc
        self.assertEqual(oc.modules_to_unload(['tun', 'nft_ct'], ['tun', 'nft_ct', 'veth', 'nft_nat', 'zram']),
                         ['nft_nat', 'veth'])
        self.assertEqual(oc.modules_to_unload(['veth'], ['veth']), [])

    def test_owner_scripts_static_safety(self):
        for name in ('arm54_final_owner_setup.py', 'arm54_final_owner_headscale.py', 'arm54_final_owner_cleanup.py',
                     'arm54_final_owner_common.py', 'arm54_final_owner_images.py', 'arm54_final_owner_reset.py',
                     'arm54_final_owner_omnigent.py', 'arm54_final_owner_secret_probe.py',
                     'arm54_final_owner_n8n.py', 'arm54_final_owner_omnigent_public.py', 'arm54_final_owner_odoo.py'):
            source = (LAB / name).read_text()
            ast.parse(source)
            self.assertNotIn('shell=True', source, name)
            self.assertNotIn("'0.0.0.0", source, name)  # nothing published on all addresses
            self.assertNotIn('omnigent stop', source, name)
        setup = (LAB / 'arm54_final_owner_setup.py').read_text()
        self.assertIn('PrivateNetwork', (LAB / 'arm54_final_owner_common.py').read_text())
        self.assertIn("'useradd', '-l'", setup)  # no lastlog/faillog records for the test account
        cleanup = (LAB / 'arm54_final_owner_cleanup.py').read_text()
        for step in ("'disable-linger'", "'userdel', '-r'", "'dpkg', '--purge', 'uidmap'", "'system', 'reset'"):
            self.assertIn(step, cleanup)
        # never unload kernel modules on .54 (incident-54-kernel-oops-nft-masq)
        for name in ('arm54_final_owner_cleanup.py', 'arm54_final_n8n.py', 'arm54_final_cleanup.py',
                     'arm54_final_netprobe.py'):
            self.assertNotIn("'modprobe', '-r'", (LAB / name).read_text(), name)
            self.assertNotIn("'rmmod'", (LAB / name).read_text(), name)
        engine = (LAB / 'arm54_final_owner_headscale.py').read_text()
        for command in ('key-init', 'catalog-suggest', 'catalog-install', 'upload-begin', 'upload-finish',
                        'ha-check-start', 'ha-convert-start', 'restore-start', 'job-status', "'run-job'"):
            self.assertIn(command, engine)
        # the production dependencies (default_adapter_factory -> OwnerRunner) are used: nothing is injected
        self.assertNotIn('adapter_factory=', engine)
        self.assertNotIn('deps=', engine)
        reset = (LAB / 'arm54_final_owner_reset.py').read_text()
        for command in ("'restore-start'", "'run-job'", "'confirm': True"):
            self.assertIn(command, reset)
        self.assertNotIn('adapter_factory=', reset)
        self.assertNotIn('deps=', reset)
        self.assertNotIn('rmtree', reset)  # the failed attempt's engine directory is kept (moved aside)
        self.assertIn("'--accept-dns=false'", engine)  # the client's non-default pref (attempt 7)
        omni = (LAB / 'arm54_final_owner_omnigent.py').read_text()
        for command in ('key-init', 'catalog-suggest', 'catalog-install', 'upload-begin', 'upload-finish',
                        'ha-check-start', 'ha-convert-start', 'restore-start', 'job-status', "'run-job'"):
            self.assertIn(command, omni)
        # public guard asserted, internal candidate only through the job runner with quiescence
        self.assertIn('public_check_reports_security_blocker', omni)
        self.assertIn('public_convert_refused_with_security_blocker', omni)
        self.assertIn('_run_omnigent_candidate(ctx, params, schema_ddl_quiesced=True)', omni)
        self.assertNotIn('schema_ddl_quiesced=False', omni)
        self.assertNotIn('SECURITY_BLOCKER =', omni)  # never redefined
        self.assertNotIn('adapter_factory=', omni)
        self.assertNotIn("'omnigent', 'stop'", omni)
        self.assertIn("'127.0.0.1'", omni)


class NetprobeTest(unittest.TestCase):
    """arm54-2 iteration 3: the internal-network probe after the .54 kernel oops stays away from what the oops left
    locked (masquerade, conntrack helpers, module unloads) and from .54's own network namespace."""

    def test_probe_is_internal_only_in_a_private_namespace(self):
        source = (LAB / 'arm54_final_netprobe.py').read_text()
        tree = ast.parse(source)
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertIn('--internal', strings)
        self.assertIn('--pull=never', strings)
        for word in ('--publish', '-p', 'host', 'masquerade', 'MASQUERADE', 'modprobe', 'rmmod', 'helper'):
            self.assertNotIn(word, strings, word)
        self.assertNotIn('shell=True', source)
        # the namespace is private before the first podman call that creates anything
        self.assertLess(source.index('LIBC.unshare(CLONE_NEWNET)'), source.index("'network', 'create'"))
        self.assertIn('arm54_final_netprobe.py', control.CODE_FILES)

    def test_kernel_state_is_read_only(self):
        source = (LAB / 'arm54_final_runtime.py').read_text()
        body = source[source.index('def kernel_state'):source.index('def store_objects')]
        self.assertNotIn('write', body)
        self.assertNotIn('modprobe', body)
        self.assertIn("'dmesg'", body)


class OdooSubstituteTest(unittest.TestCase):
    """arm54-2 item B Odoo (owner decision 3A): substitute images are labelled, pinned arm64, the run stays
    network-free and the product paths are the unmodified ha_odoo ones."""

    def test_build_pins_substitutes_by_index_digest(self):
        source = (LAB / 'arm54_final_odoo_build.py').read_text()
        self.assertIn('substitute images, not the product service', source)
        for ref in ('docker.io/library/odoo:18.0-20260926@sha256:60eb1b5006df85f900e300b6cc120d51ebd979379ee9588340adc2a84ffcd718',
                    'docker.io/pgvector/pgvector:0.8.6-pg17@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f',
                    'docker.io/pgvector/pgvector:0.8.6-pg16@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b'):
            self.assertIn(ref.split('@')[1], source.replace("'\n        '", ''))
        self.assertIn("'--arch', 'arm64'", source)

    def test_run_is_network_free_and_uses_product_paths(self):
        source = (LAB / 'arm54_final_odoo.py').read_text()
        tree = ast.parse(source)
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertIn('substitute images, not the product service (owner decision 3A)', strings)
        self.assertNotIn('--publish', strings)
        self.assertNotIn('network', [s for s in strings if s == 'network'])  # no `podman network ...` call
        self.assertNotIn("'network', 'create'", source)
        self.assertIn("'--network', 'none'", source)
        self.assertLess(source.index('enter_private_netns()\nr = OdooRunner()'), source.index("'pod', 'create'"))
        for call in ('ha_odoo.check(work, app)', 'ha_odoo.check_blockers(found)',
                     'ha_odoo.convert(work, app, HA_DB, TEST_MODE, converted_dir)', 'adapter._recreate_volume(',
                     'adapter._unpack_dir(', 'adapter._swap_dir(', 'ha_odoo.member_pass(', 'ha_odoo.start_ha_cluster('):
            self.assertIn(call, source)
        self.assertNotIn('test_mode=True', source)
        self.assertIn("TEST_MODE = '--test-mode' in sys.argv[2:]", source)  # normal mode unless asked
        self.assertNotIn("'modprobe'", source)
        self.assertNotIn('shell=True', source)
        # product guards and checks are never redefined here
        self.assertNotIn('ha_odoo.check =', source)
        self.assertNotIn('ha_odoo.marker_ok =', source)
        self.assertNotIn('ha_odoo.database_verdict =', source)
        self.assertIn('odoo-package-c578b8a', source)
        self.assertIn('arm54_final_odoo.py', control.CODE_FILES)
        self.assertIn('arm54_final_odoo_build.py', control.CODE_FILES)

    def test_dir_helper_runner_only_runs_the_product_helper(self):
        source = (LAB / 'arm54_final_odoo.py').read_text()
        self.assertIn("assert argv[:3] == [sys.executable, '-I', '-c'] and argv[3] == podman_mod.DIR_HELPER", source)

    def test_secrets_reach_stdin_only(self):
        source = (LAB / 'arm54_final_odoo.py').read_text()
        self.assertIn("'-f', '-'", source)              # SQL with the generated role password goes on stdin
        self.assertIn("SUPER_SECRET, '-', input=", source)
        self.assertIn("CONF_SECRET, '-',", source)
        self.assertIn('CREDS_FILE.unlink()', source)

    def test_quadlet_render_and_conf(self):
        quad = (control.ODOO_PACKAGE / 'quadlet/odoo.container').read_text()
        self.assertIn('target=/etc/odoo/odoo.conf', quad)
        conf = (control.ODOO_PACKAGE / 'config/odoo.conf.template').read_text()
        self.assertIn('@@POSTGRES_PASSWORD@@', conf)      # placeholders only in the copied package
        sums = (control.ODOO_PACKAGE / 'SHA256SUMS').read_text().splitlines()
        for line in sums:
            digest, name = line.split()
            self.assertEqual(hashlib.sha256((control.ODOO_PACKAGE / name).read_bytes()).hexdigest(), digest)



class EmqxItemDTest(unittest.TestCase):
    """arm54-2 item D (EMQX on .54): the product image and package, the dev-d probe reused with asserted
    substitutions, a network-free run through the unmodified product paths, secrets only in files/stdin."""

    @classmethod
    def setUpClass(cls):
        import arm54_final_emqx_lib as lib
        cls.lib = lib
        cls.product_source = (LAB / 'emqx_product_real_ha.py').read_text()
        cls.b1_source = (LAB / 'ha_import_b1_e2e.py').read_text()
        cls.run_source = (LAB / 'arm54_final_emqx.py').read_text()

    def test_probe_is_the_dev_d_probe_with_two_asserted_substitutions(self):
        program = self.lib.probe_program(self.product_source, self.b1_source)
        body = self.lib.probe_body(self.product_source)
        self.assertIn('E = "http://127.0.0.1:18093"', program)
        self.assertNotIn('E = "http://127.0.0.1:18083"', program)
        self.assertIn('REQ["acl_path"]', program)
        self.assertNotIn('~/.config/emqx/acl.conf', program)
        # everything else of the probe body is byte-identical
        rebuilt = body
        for old, new in self.lib.PROBE_SUBSTITUTIONS:
            rebuilt = rebuilt.replace(old, new)
        self.assertTrue(program.endswith(rebuilt))
        # the device overrides come after PROBE_COMMON's own secret()/pexec() and before the probe uses them
        common = self.lib.string_constant(self.b1_source, 'PROBE_COMMON')
        self.assertTrue(program.startswith(common + self.lib.PROBE_OVERRIDES))
        self.assertIn('REQ["device_secrets"][name]', self.lib.PROBE_OVERRIDES)
        self.assertIn('REQ["podman"] + ["exec", "-i", *argv]', self.lib.PROBE_OVERRIDES)

    def test_substitution_must_hit_exactly_once(self):
        broken = self.product_source.replace('E = "http://127.0.0.1:18083"', 'E = "http://127.0.0.1:9"')
        with self.assertRaises(ValueError):
            self.lib.probe_program(broken, self.b1_source)

    def test_acceptance_function_is_the_dev_d_one(self):
        evaluate = self.lib.function_from(self.product_source, 'evaluate_imported')
        src = {'mqtt_users': [{'user_id': 'b1-sensor', 'is_superuser': False}], 'retained_messages': ['b1/r'],
               'rules': ['r1'], 'dashboard_users': ['admin']}
        results = evaluate({}, src, 'builtin')
        self.assertGreaterEqual(len(results), 20)
        self.assertFalse(any(ok for _name, ok, _detail in results))   # an empty probe passes nothing

    def test_bootstrap_csv_is_install_sh_format(self):
        self.assertEqual(self.lib.bootstrap_csv('woow', 'pw'), 'user_id,password,is_superuser\nwoow,pw,false')
        install = (control.EMQX_PACKAGE / 'MANIFEST.json').read_text()
        self.assertIn('ea5886c58ef2c6ab1f4e6a4d01908cc9dc4525de', install)

    def test_container_args_from_the_product_quadlet(self):
        text = (control.EMQX_PACKAGE / 'quadlet/emqx.container').read_bytes()
        name, image, args, skipped = self.lib.container_args(text, '/var/tmp/w', 'io.test=x')
        self.assertEqual((name, image), ('woow-emqx', self.lib.IMAGE))
        joined = ' '.join(args)
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertNotIn('--publish', args)
        self.assertNotIn('-p', args)
        for secret in ('woow-emqx-dashboard-password,type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD',
                       'woow-emqx-node-cookie,type=env,target=EMQX_NODE__COOKIE',
                       'woow-emqx-mqtt-bootstrap,type=mount,target=/opt/emqx/etc/woow-mqtt-bootstrap.csv,uid=1000,'
                       'gid=1000,mode=0400'):
            self.assertIn(secret, args)
        for volume in ('/var/tmp/w/.config/emqx/base.hocon:/opt/emqx/etc/base.hocon:ro,Z',
                       '/var/tmp/w/.config/emqx/acl.conf:/opt/emqx/etc/acl.conf:ro,Z',
                       'woow_emqx_data:/opt/emqx/data', 'woow_emqx_log:/opt/emqx/log'):
            self.assertIn(volume, args)
        self.assertIn('EMQX_NODE__NAME=emqx@127.0.0.1', args)
        self.assertIn('--env-file /var/tmp/w/.config/emqx/emqx.env', joined)
        self.assertIn('no-new-privileges', args)
        self.assertEqual(skipped, ['HealthCmd', 'HealthInterval', 'HealthRetries', 'HealthStartPeriod',
                                   'HealthTimeout', 'Network', 'PublishPort'])

    def test_run_is_network_free_and_uses_the_product_paths(self):
        source = self.run_source
        for word in ('--publish', "'network', 'create'", "'--network', 'host'", 'modprobe', 'rmmod', 'shell=True'):
            self.assertNotIn(word, source)
        self.assertIn("network='none'", (LAB / 'arm54_final_emqx_lib.py').read_text())
        self.assertIn("must('broker_network_none'", source)
        self.assertLess(source.index('enter_private_netns()'), source.index("start('deploy')"))
        for call in ('ha_emqx.check(work, app)', 'ha_emqx.convert(work, app, False, converted_dir)',
                     'adapter._recreate_volume(volume, converted[', 'haimport.verify_import(app, adapter, check_doc',
                     "ha_emqx.ACL_NEEDS_BUILTIN]", 'evaluate_imported'):
            self.assertIn(call, source)
        for redefinition in ('ha_emqx.check =', 'ha_emqx.convert =', 'ha_emqx.acl_blocker =', 'ha_emqx.ACL_NEEDS_BUILTIN =',
                             'ha_emqx.verify_restored =', 'haimport.verify_import =', 'ha_emqx.target_profile ='):
            self.assertNotIn(redefinition, source)
        self.assertIn('arm54_final_emqx.py', control.CODE_FILES)
        self.assertIn('arm54_final_emqx_lib.py', control.CODE_FILES)
        self.assertIn('arm54_final_emqx_build.py', control.CODE_FILES)
        self.assertNotIn('emqx_product_real_ha.py', control.CODE_FILES)   # read as data, never runnable on .54

    def test_throwaways_run_under_the_production_cpu_limit_and_leave_nothing(self):
        source = self.run_source
        # the product formula itself (tempctr.default_cpus) for an owner with the cpu controller delegated
        self.assertIn("tempctr.default_cpus(1000, controllers=str(listing))", source)
        self.assertIn("'cpuset cpu io memory pids\\n'", source)
        self.assertIn('tempctr.TempObjects(r, job, memory=\'1g\', pids=1024, cpus=PRODUCTION_CPUS)', source)
        self.assertIn("must('throwaway_cpu_limit_below_the_devices_online_schedulers'", source)
        self.assertIn('ha_emqx.schedulers(', source)
        self.assertIn("'no_new_hung_task_report', 'no_product_anonymous_volume')", source)
        from woowbackup import tempctr
        import tempfile
        with tempfile.NamedTemporaryFile('w') as listing:
            listing.write('cpuset cpu io memory pids\n')
            listing.flush()
            self.assertEqual(tempctr.default_cpus(1000, controllers=listing.name, cpu_count=lambda: 4), '2')

    def test_secrets_reach_files_and_stdin_only(self):
        source = self.run_source
        self.assertIn("podman('secret', 'create', '--label', LABEL, secret_name, '-', input=", source)
        self.assertIn('CREDS_FILE.unlink()', source)
        self.assertIn('os.unlink(KEY_FILE)', source)
        self.assertIn("input=(json.dumps(req) + '\\n').encode()", source)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'podman':
                names = {n.id for arg in node.args for n in ast.walk(arg) if isinstance(n, ast.Name)}
                self.assertFalse(names & {'creds', 'values', 'device', 'raw', 'req'}, ast.dump(node)[:120])

    def test_emqx_sources_equal_the_b1_record(self):
        record = __import__('json').loads(control.B1_BACKUPS.read_text())
        for kind, (machine, stem, slug, sha) in control.EMQX_SOURCES.items():
            entry = [b for b in record[machine] if b['slug'] == slug]
            self.assertEqual(len(entry), 1, kind)
            self.assertEqual((entry[0]['file'], entry[0]['sha256'], entry[0]['protected']), (stem + '.tar', sha, True))

    def test_build_pins_the_product_index_and_arm64_manifest(self):
        source = (LAB / 'arm54_final_emqx_build.py').read_text()
        self.assertIn('35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b', source)
        self.assertIn('c455c60feced3452a5fa81a761f840983039118b1c126fdad6c86f93467a3be5', source)
        index = __import__('json').loads((control.EVIDENCE / 'emqx-image-index-35b46f7a.json').read_text())
        arm = [m['digest'] for m in index['manifests'] if m['platform']['architecture'] == 'arm64']
        self.assertEqual(arm, ['sha256:c455c60feced3452a5fa81a761f840983039118b1c126fdad6c86f93467a3be5'])
        self.assertEqual(hashlib.sha256((control.EVIDENCE / 'emqx-image-index-35b46f7a.json').read_bytes()).hexdigest(),
                         '35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b')
        quadlet = (control.EMQX_PACKAGE / 'quadlet/emqx.container').read_text()
        self.assertIn('Image=docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b',
                      quadlet)

    def test_package_manifest_matches_files(self):
        doc = __import__('json').loads((control.EMQX_PACKAGE / 'MANIFEST.json').read_text())
        for name, digest in doc['files'].items():
            self.assertEqual(hashlib.sha256((control.EMQX_PACKAGE / name).read_bytes()).hexdigest(), digest, name)


class EmqxVolumeProbeTest(unittest.TestCase):
    def test_probe_is_network_free_and_cleans_up(self):
        source = (LAB / 'arm54_final_emqx_volume_probe.py').read_text()
        self.assertIn("'--network', 'none'", source)
        self.assertIn("'--read-only'", source)
        for word in ('--publish', 'modprobe', 'shell=True', "'network', 'create'", 'secret'):
            self.assertNotIn(word, source.replace("no secret", ''))
        self.assertIn("r.podman('unshare', 'chown', '--no-dereference', '1000:1000', '--', mount)", source)
        self.assertIn('arm54_final_emqx_volume_probe.py', control.CODE_FILES)


class EmqxBootFormDiagnosticTest(unittest.TestCase):
    def test_config_diff_names_paths_never_secret_values(self):
        import arm54_final_emqx_lib as lib
        target = {'log': {'console': {'level': 'warning'}}, 'node': {'cookie': 'cookie-value-1'},
                  'dashboard': {'default_password': 'pw-value-123'}, 'listeners': {'tcp': {'bind': '0.0.0.0:1883'}}}
        candidate = {'log': {'console': {}}, 'node': {'cookie': 'cookie-value-2'},
                     'dashboard': {'default_password': 'pw-value-456'}, 'listeners': {'tcp': {'bind': '0.0.0.0:1884'}}}
        rows = lib.config_diff(target, candidate)
        text = repr(rows)
        for value in ('cookie-value-1', 'cookie-value-2', 'pw-value-123', 'pw-value-456'):
            self.assertNotIn(value, text)
        self.assertIn(['log.console.level', 'only-target', 'str:warning', None], rows)
        self.assertIn(['listeners.tcp.bind', 'differs', 'str:0.0.0.0:1883', 'str:0.0.0.0:1884'], rows)
        self.assertEqual(lib.config_diff({'a': 1}, {'a': 1}), [])

    def test_recording_wrapper_returns_the_product_value_unchanged(self):
        source = (LAB / 'arm54_final_emqx.py').read_text()
        self.assertIn("RECORD_BOOT_FORMS = '--record-boot-forms' in sys.argv[2:]", source)
        self.assertIn('            value = product_boot_form(execute)\n            BOOT_FORMS.append(value)\n'
                      '            return value\n', source)


class EmqxCpuDefaultTest(unittest.TestCase):
    def test_throwaways_use_the_product_job_runner_cpu_default(self):
        # attempts 4/5: the rootful default (none); since the product's ERL_AFLAGS fix (92f2461 + be2c92d) the run uses
        # what a production owner's job runner passes (tempctr.default_cpus with the cpu controller delegated)
        source = (LAB / 'arm54_final_emqx.py').read_text()
        self.assertIn("tempctr.TempObjects(r, job, memory='1g', pids=1024, cpus=PRODUCTION_CPUS)\n", source)
        self.assertNotIn("cpus='1'", source.split('def work_for', 1)[1].split('def temp_cleanup', 1)[0])


class CleanupAfterRebootTest(unittest.TestCase):
    """arm54_final_cleanup.py --after-reboot: only Podman's own boot-ID refusal, only this run's workspace."""

    REFUSAL = b'Error: current system boot ID differs from cached boot ID; an unhandled reboot has occurred.'

    def function(self, root, exit_code, stderr, pids=()):
        import shutil
        tree = ast.parse((LAB / 'arm54_final_cleanup.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'reset_runtime_after_reboot')

        class Runner:
            def podman(self, *args, **kwargs):
                return type('R', (), {'returncode': exit_code, 'stderr': stderr})()
        space = {'r': Runner(), 'out': {}, 'ROOT': root, 'Path': Path, 'shutil': shutil,
                 'BOOT_ID_REFUSAL': b'current system boot ID differs from cached boot ID',
                 'pids_naming_root': lambda: list(pids)}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'cleanup', 'exec'), space)
        return space

    def workspace(self, tmp):
        root = Path(tmp) / 'woow-arm54-final-20261123-x'
        for name in ('run', 'tmp', 'store', 'input'):
            (root / name).mkdir(parents=True)
            (root / name / 'old').write_text('x')
        return root

    def test_resets_only_run_and_tmp_after_the_boot_id_refusal(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = self.workspace(tmp)
            space = self.function(root, 125, self.REFUSAL)
            space['reset_runtime_after_reboot']()
            self.assertEqual(space['out']['after_reboot']['runtime_directories_reset'], ['run', 'tmp'])
            self.assertEqual([sorted(p.name for p in (root / n).iterdir()) for n in ('run', 'tmp', 'store', 'input')],
                             [[], [], ['old'], ['old']])
            self.assertEqual({(root / n).stat().st_mode & 0o777 for n in ('run', 'tmp')}, {0o700})

    def test_any_other_podman_error_or_a_used_workspace_refuses(self):
        import tempfile
        for stderr, pids in ((b'Error: something else', ()), (self.REFUSAL, (4242,))):
            with tempfile.TemporaryDirectory() as tmp:
                root = self.workspace(tmp)
                space = self.function(root, 125, stderr, pids)
                with self.assertRaises(AssertionError):
                    space['reset_runtime_after_reboot']()
                self.assertTrue((root / 'run/old').exists() and (root / 'tmp/old').exists())

    def test_a_working_store_is_left_alone(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = self.workspace(tmp)
            space = self.function(root, 0, b'')
            space['reset_runtime_after_reboot']()
            self.assertNotIn('runtime_directories_reset', space['out']['after_reboot'])
            self.assertTrue((root / 'run/old').exists())

    def test_the_step_needs_the_explicit_argument(self):
        source = (LAB / 'arm54_final_cleanup.py').read_text()
        self.assertIn("AFTER_REBOOT = '--after-reboot' in sys.argv[2:]", source)
        self.assertIn('    if AFTER_REBOOT:\n        reset_runtime_after_reboot()\n', source)


class CgroupParentCleanupTest(unittest.TestCase):
    """arm54_final_cleanup.py remove_own_cgroup_parent: only this cycle's own, empty cgroup directories, rmdir only."""

    def function(self):
        tree = ast.parse((LAB / 'arm54_final_cleanup.py').read_text())
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'remove_own_cgroup_parent')
        space = {'os': os, 'Path': Path}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'cleanup', 'exec'), space)
        return space['remove_own_cgroup_parent']

    def tree(self, tmp, *, populated=(), procs=()):
        parent = Path(tmp) / 'libpod_parent'
        for name in ('', 'conmon', 'libpod-x', 'libpod-x/container'):
            path = parent / name if name else parent
            path.mkdir()
            (path / 'cgroup.events').write_text('populated %d\nfrozen 0\n' % (name in populated))
            (path / 'cgroup.procs').write_text('4242\n' if name in procs else '')
        return parent

    @staticmethod
    def kernel_rmdir(seen):
        def rmdir(path):  # cgroupfs control files vanish with their directory; child directories refuse it
            path = Path(path)
            assert not any(p.is_dir() for p in path.iterdir())
            for name in ('cgroup.events', 'cgroup.procs'):
                (path / name).unlink()
            path.rmdir()
            seen.append(path.name)
        return rmdir

    def test_an_empty_leftover_of_this_cycle_goes_deepest_first(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            parent, seen = self.tree(tmp), []
            report = self.function()(['system.slice'], parent, self.kernel_rmdir(seen))
            self.assertEqual(report, {'present': True, 'in_baseline': False, 'directories': 4, 'populated': False,
                                      'removed': True})
            self.assertEqual((seen[0], seen[-1]), ('container', 'libpod_parent'))
            self.assertFalse(parent.exists())

    def test_one_that_the_baseline_had_is_never_touched(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            parent, seen = self.tree(tmp), []
            report = self.function()(['libpod_parent', 'system.slice'], parent, self.kernel_rmdir(seen))
            self.assertEqual((report['in_baseline'], report['removed'], seen), (True, False, []))
            self.assertTrue(parent.exists())

    def test_a_used_one_is_left_alone(self):
        import tempfile
        for populated, procs in ((('conmon',), ()), ((), ('libpod-x/container',)), (('',), ())):
            with tempfile.TemporaryDirectory() as tmp:
                parent, seen = self.tree(tmp, populated=populated, procs=procs), []
                report = self.function()([], parent, self.kernel_rmdir(seen))
                self.assertEqual((report['populated'], report['removed'], seen), (True, False, []))
                self.assertTrue((parent / 'libpod-x/container').exists())

    def test_nothing_there(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            report = self.function()([], Path(tmp) / 'libpod_parent', self.kernel_rmdir([]))
            self.assertEqual(report, {'present': False, 'in_baseline': False, 'removed': False})

    def test_a_missing_baseline_key_means_untouched_and_the_order_is_after_the_store_is_empty(self):
        source = (LAB / 'arm54_final_cleanup.py').read_text()
        self.assertIn("remove_own_cgroup_parent(baseline.get('cgroup_top') or ['libpod_parent'])", source)
        self.assertLess(source.index("    after = store_objects(r)\n"), source.index("out['cgroup_parent'] ="))
        self.assertIn("    if not any(after.values()) and not out['helper_processes_left']:\n        baseline =", source)


class OwnerN8nFlowTest(unittest.TestCase):
    """arm54_final_owner_n8n.py: the rendered package and the production flow (static and rendering checks only)."""

    def space(self):
        import tempfile
        tree = ast.parse((LAB / 'arm54_final_owner_n8n.py').read_text())
        wanted_funcs = {'render', 'package_files'}
        wanted_names = {'RENDER', 'QUADLET_DIR', 'CONFIG_DIR', 'USER_UNIT_DIR', 'TARGET', 'PORT', 'CONTAINERS', 'UNITS'}
        body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in wanted_funcs)
                or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in wanted_names for t in n.targets))]
        space = {'PACKAGE': control.N8N_PACKAGE, 'PACKAGE_PODMAN': '/usr/bin/podman ',
                 'HOST_PODMAN': '/usr/local/bin/podman ', 'PACKAGE_LOG': 'LogDriver=journald\n',
                 'HOST_LOG': 'LogDriver=k8s-file\n'}
        exec(compile(ast.Module(body=body, type_ignores=[]), 'owner-n8n', 'exec'), space)
        return space

    def test_queue_mode_package_is_rendered_like_app_render(self):
        space = self.space()
        files, repointed = space['package_files']()
        self.assertEqual(repointed, {'n8n-worker.container': 1, 'n8n.container': 2})
        quadlets = sorted(k.rsplit('/', 1)[-1] for k in files if k.startswith('.config/containers/systemd/'))
        self.assertEqual(quadlets, sorted(['n8n.container', 'n8n-postgres.container', 'n8n-runners.container',
                                           'n8n-valkey.container', 'n8n-worker.container', 'n8n-worker-runners.container',
                                           'n8n-data.volume', 'n8n-postgres-data.volume', 'n8n-valkey-data.volume',
                                           'n8n.network']))
        self.assertEqual(sorted(k for k in files if not k.startswith('.config/containers/systemd/')),
                         ['.config/n8n/n8n-task-runners.json', '.config/n8n/n8n.env', '.config/n8n/start-valkey.sh',
                          '.config/systemd/user/n8n.target'])
        self.assertEqual(files['.config/n8n/n8n.env'][0], '0600')
        self.assertIn('\nEXECUTIONS_MODE=queue\n', files['.config/n8n/n8n.env'][1])
        publish = [l for _m, t in files.values() for l in t.splitlines() if l.startswith('PublishPort=')]
        self.assertEqual(publish, ['PublishPort=127.0.0.1:15678:5678'])
        self.assertTrue(all('@@' not in t for _m, t in files.values()))
        self.assertTrue(all('/usr/bin/podman ' not in t for _m, t in files.values()))
        # everything but the re-pointed ExecStartPre lines and the rendered variables is the package's own text
        worker = (control.N8N_PACKAGE / 'quadlet/queue/n8n-worker.container').read_text()
        for key, value in space['RENDER'].items():
            worker = worker.replace('@@%s@@' % key, value)
        self.assertEqual(files['.config/containers/systemd/n8n-worker.container'][1],
                         worker.replace('/usr/bin/podman ', '/usr/local/bin/podman ')
                         .replace('LogDriver=journald\n', 'LogDriver=k8s-file\n'))
        logs = [l for k, (_m, t) in files.items() if k.endswith('.container') for l in t.splitlines()
                if l.startswith('LogDriver=')]
        self.assertEqual(logs, ['LogDriver=k8s-file'] * 6)

    def test_images_are_the_packages_images(self):
        source = (LAB / 'arm54_final_owner_images.py').read_text()
        space = self.space()
        files, _ = space['package_files']()
        named = {l.split('=', 1)[1] for _m, t in files.values() for l in t.splitlines() if l.startswith('Image=')}
        self.assertEqual(len(named), 4)
        for ref in named:
            self.assertIn("'%s'" % ref, source)

    def test_production_flow_nothing_injected_and_secrets_not_printed(self):
        source = (LAB / 'arm54_final_owner_n8n.py').read_text()
        for command in ('key-init', 'catalog-suggest', 'catalog-install', 'upload-begin', 'upload-finish',
                        'ha-check-start', 'ha-convert-start', 'restore-start', 'job-status', "'run-job'"):
            self.assertIn(command, source)
        for word in ('adapter_factory=', 'deps=', "'modprobe'", "'rmmod'", "'insmod'", 'mock.patch', 'handlers='):
            self.assertNotIn(word, source)
        self.assertIn('secret_in_output_suppressed', source)
        self.assertIn('KEY_FILE.unlink()', source)
        self.assertIn('CREDS_FILE.unlink()', source)
        setup = (LAB / 'arm54_final_owner_setup.py').read_text()
        self.assertIn("oc.DROPIN_TEXT + (oc.MEMORY_CAP_TEXT if APP in ('n8n', 'all') else '')", setup)

    def test_memory_cap_and_stage_archive_check(self):
        import tempfile
        import arm54_final_owner_common as oc
        self.assertEqual(oc.MEMORY_CAP_TEXT, 'MemoryMax=1600M\nMemorySwapMax=900M\n')
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'input').mkdir()
            (Path(tmp) / 'input/chain-arm-enc.json').write_text('{}')
            (Path(tmp) / 'input/ha-key').write_text('x')
            os.chmod(Path(tmp) / 'input/ha-key', 0o600)
            good = {'chain-arm-enc.json': hashlib.sha256(b'{}').hexdigest()}
            code = control.STAGED_ARCHIVE_CHECK.replace('ROOT', repr(tmp))
            exec(code.replace('WANT', repr(good)), {})
            with self.assertRaises(AssertionError):
                exec(code.replace('WANT', repr({'chain-arm-enc.json': '0' * 64})), {})
            os.chmod(Path(tmp) / 'input/ha-key', 0o644)
            with self.assertRaises(AssertionError):
                exec(code.replace('WANT', repr(good)), {})


class OwnerOmnigentPublicFlowTest(unittest.TestCase):
    """arm54_final_owner_omnigent_public.py: the public product path only (static and pure checks), stage-b1."""

    NAME = 'arm54_final_owner_omnigent_public.py'

    def functions(self, *names, **space):
        tree = ast.parse((LAB / self.NAME).read_text())
        body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
        exec(compile(ast.Module(body=body, type_ignores=[]), 'owner-omnigent-public', 'exec'), space)
        return space

    def test_production_flow_nothing_injected_and_no_candidate(self):
        source = (LAB / self.NAME).read_text()
        for command in ('key-init', 'catalog-suggest', 'catalog-install', 'upload-begin', 'upload-finish',
                        'ha-check-start', 'ha-convert-start', 'restore-start', 'job-status', "'run-job'"):
            self.assertIn(command, source)
        for word in ('adapter_factory=', 'deps=', "'modprobe'", "'rmmod'", "'insmod'", 'mock.patch', 'handlers=', 'shell=True',
                     "'0.0.0.0", 'omnigent stop', "'omnigent', 'stop'", 'schema_ddl_quiesced', '_run_omnigent_candidate',
                     '_convert_candidate', '_install_omnigent_candidate'):
            self.assertNotIn(word, source)
        tree = ast.parse(source)
        # the engine's modules are only called through the CLI and run-job: no attribute of haimport/ha_omnigent but these
        used = {(n.value.id, n.attr) for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                and n.value.id in ('haimport', 'ha_omnigent', 'jobs', 'flows')}
        self.assertEqual(used, {('haimport', 'read_key_file'), ('ha_omnigent', 'TABLES')})
        self.assertIn('secret_in_output_suppressed', source)
        self.assertIn(self.NAME, control.CODE_FILES)
        # the target runs during check and conversion: nothing stops a unit between engine-setup and the restore phase
        between = source[source.index("out['phase'] = 'engine-setup'"):source.index("out['phase'] = 'restore'")]
        self.assertNotIn("'stop'", between)
        self.assertNotIn('stop_stack', between)

    def test_attested_digests_equal_the_rpi5_attestation(self):
        tree = ast.parse((LAB / self.NAME).read_text())
        attested = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                        and getattr(n.targets[0], 'id', None) == 'ATTESTED')
        doc = json.loads((control.EVIDENCE / 'source-provenance-34.json').read_text())
        self.assertEqual(sorted(attested), sorted(control.B1_KINDS))
        for kind, (slug, digest) in attested.items():
            self.assertEqual(slug, control.RESTORE_SOURCES[control.B1_KINDS[kind]][0])
            self.assertTrue(doc['verdicts'][slug]['verified'])
            self.assertEqual(doc['source']['backups'][slug]['file_sha256'], digest)

    def test_schema_digest_ignores_only_comments_and_restrict_tokens(self):
        def digest(text):
            class Oc:
                @staticmethod
                def podman(*args, **kwargs):
                    return type('R', (), {'stdout': text.encode()})()
            return self.functions('schema_digest', oc=Oc, DB='db', hashlib=hashlib)['schema_digest']()
        base = '--\n-- dump\n\\restrict abc\nCREATE TABLE a (id int);\n\n\\unrestrict abc\n'
        same = '-- other comment\n\\restrict xyz\n\nCREATE TABLE a (id int);\n\\unrestrict xyz\n'
        self.assertEqual(digest(base), digest(same))
        self.assertEqual(digest(base)['lines'], 1)
        for other in (base.replace('id int', 'id int DEFAULT 1'), base + 'CREATE FUNCTION f() RETURNS int;\n'):
            self.assertNotEqual(digest(base)['sha256'], digest(other)['sha256'])

    def test_anonymous_volumes_are_podmans_generated_names_only(self):
        class Oc:
            @staticmethod
            def podman(*args, **kwargs):
                return type('R', (), {'stdout': ('a' * 64 + '\nomnigent-pi-data\n' + 'g' * 64 + '\n' + 'b' * 63).encode()})()
        self.assertEqual(self.functions('anonymous_volumes', oc=Oc)['anonymous_volumes'](), ['a' * 64])

    def test_stage_b1_refuses_bytes_that_were_not_attested_before_any_transfer(self):
        from unittest import mock
        calls = []
        fixture = {'path': '/nonexistent', 'sha256': '0' * 64}
        with mock.patch.object(control, 'workspace', lambda: '/var/tmp/x'), \
                mock.patch.object(control, 'local_fixture', lambda slug: fixture), \
                mock.patch.object(control, 'scp', lambda *a, **k: calls.append(a)), \
                mock.patch.object(control, 'remote', lambda *a, **k: calls.append(a)), self.assertRaises(SystemExit):
            control.stage_b1('b1-enc', 'never-written')
        self.assertEqual(calls, [])
        self.assertFalse((control.EVIDENCE / 'never-written.json').exists())

    def test_b1_staged_check_wants_private_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'input').mkdir()
            (Path(tmp) / 'input/chain-b1-enc.json').write_text('{}')
            for name in ('ha-key', 'omni-creds.json'):
                (Path(tmp) / 'input' / name).write_text('x')
                os.chmod(Path(tmp) / 'input' / name, 0o600)
            good = {'chain-b1-enc.json': hashlib.sha256(b'{}').hexdigest()}
            code = control.B1_STAGED_CHECK.replace('ROOT', repr(tmp)).replace('WANT', repr(good))
            exec(code, {})
            os.chmod(Path(tmp) / 'input/omni-creds.json', 0o640)
            with self.assertRaises(AssertionError):
                exec(code, {})

    def test_setup_all_is_headscale_with_the_memory_cap(self):
        setup = (LAB / 'arm54_final_owner_setup.py').read_text()
        self.assertIn("assert APP in ('headscale', 'n8n', 'all'), 'app-refused'", setup)
        self.assertIn("oc.MEMORY_CAP_TEXT if APP in ('n8n', 'all') else ''", setup)
        self.assertIn("    if APP in ('headscale', 'all'):\n", setup)


class OwnerOdooFlowTest(unittest.TestCase):
    """arm54_final_owner_odoo.py (SUBSTITUTE images, owner decision 3A): rendering, the cold comparison inside the restore,
    the production flow (static and pure checks only)."""

    NAME = 'arm54_final_owner_odoo.py'

    def space(self, *functions, **extra):
        tree = ast.parse((LAB / self.NAME).read_text())
        names = {'QUADLET_DIR', 'ADDONS_REL', 'PORT', 'QUADLET_VALUES', 'ODOO_IMAGE', 'DB_IMAGE', 'PG16_IMAGE', 'IMAGES', 'DBVOL',
                 'SUPER_SECRET', 'GATE_TEXT', 'GATE_ARMED', 'DROPDIR', 'USER_UNIT_DIR', 'IMPORT_KEYS', 'PRINTS_SQL', 'ICP_SQL',
                 'MODULES_SQL', 'COUNTS_SQL'}

        def wanted(node):
            if isinstance(node, ast.FunctionDef):
                return node.name in functions
            if not isinstance(node, ast.Assign):
                return False
            targets = node.targets[0].elts if isinstance(node.targets[0], ast.Tuple) else node.targets
            return any(getattr(t, 'id', None) in names for t in targets)
        space = {'PACKAGE': control.ODOO_PACKAGE, **extra}
        exec(compile(ast.Module(body=[n for n in tree.body if wanted(n)], type_ignores=[]), 'owner-odoo', 'exec'), space)
        return space

    def test_quadlets_render_for_loopback_with_the_substitute_images(self):
        space = self.space('render', 'package_files')
        files = space['package_files']()
        self.assertEqual(sorted(k.rsplit('/', 1)[-1] for k in files),
                         ['odoo-db-data.volume', 'odoo-db.container', 'odoo-web-data.volume', 'odoo.container', 'odoo.network'])
        text = '\n'.join(t for _m, t in files.values())
        self.assertIn('PublishPort=127.0.0.1:18069:8069', text)
        self.assertIn('Volume=%h/.local/share/odoo18/addons:/mnt/extra-addons:ro,Z', text)
        self.assertEqual(sorted(l for l in text.splitlines() if l.startswith('Image=')),
                         ['Image=docker.io/library/odoo:18.0-20260926', 'Image=docker.io/pgvector/pgvector:0.8.6-pg17'])
        conf = self.space('render', 'odoo_conf')['odoo_conf']('dbpw', 'adminpw')
        self.assertIn('db_host = odoo18-db\n', conf)
        self.assertIn('db_name = odoo\n', conf)

    def test_images_are_the_pinned_substitutes_of_the_rootful_run(self):
        build = (LAB / 'arm54_final_odoo_build.py').read_text()
        rows = next(ast.literal_eval(n.value) for n in ast.parse((LAB / 'arm54_final_owner_images.py').read_text()).body
                    if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', None) == 'IMAGES')['odoo']
        self.assertEqual({tag for _r, _a, tag in rows}, set(self.space()['IMAGES']))
        for ref, arm64, tag in rows:
            self.assertEqual(ref.split('@')[0], tag)
            self.assertIn(ref.split('@')[1], build)
            self.assertIn(arm64, build)

    def test_strict_comparison_queries_equal_the_rootful_run(self):
        tree = ast.parse((LAB / 'arm54_final_odoo.py').read_text())
        rootful = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                   and getattr(n.targets[0], 'id', None) in ('PRINTS_SQL', 'ICP_SQL', 'MODULES_SQL', 'COUNTS_SQL')}
        space = self.space()
        self.assertEqual({k: space[k] for k in rootful}, rootful)
        for name in ('compare_cold', 'prints_map'):
            mine = next(n for n in ast.parse((LAB / self.NAME).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == name)
            theirs = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(ast.dump(mine), ast.dump(theirs), name)

    def test_gate_holds_only_when_armed_and_opens(self):
        import subprocess
        import tempfile
        gate = self.space()['GATE_TEXT']
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / '.config').mkdir()
            script = Path(home) / '.config/a54-odoo-gate.sh'
            script.write_text(gate)

            def run(timeout):
                return subprocess.run(['/bin/sh', str(script)], env={'HOME': home, 'PATH': '/usr/bin:/bin'}, timeout=timeout).returncode
            self.assertEqual(run(10), 0)  # not armed: no wait
            self.assertFalse((Path(home) / '.config/a54-odoo-gate-reached').exists())
            (Path(home) / '.config/a54-odoo-gate-armed').write_text('armed\n')
            with self.assertRaises(subprocess.TimeoutExpired):
                run(2)
            self.assertTrue((Path(home) / '.config/a54-odoo-gate-reached').exists())
            (Path(home) / '.config/a54-odoo-gate-open').write_text('')
            self.assertEqual(run(10), 0)

    def test_the_gate_always_opens_and_the_job_is_always_awaited(self):
        source = (LAB / self.NAME).read_text()
        self.assertIn('        finally:\n            open_gate()\n', source)
        run_job = source[source.index('def run_job('):source.index('def verification_view')]
        self.assertLess(run_job.index('p.wait(timeout=timeout)'), run_job.index('raise problem'))

    def test_production_flow_nothing_injected(self):
        source = (LAB / self.NAME).read_text()
        for command in ('key-init', 'catalog-suggest', 'catalog-install', 'upload-begin', 'upload-finish',
                        'ha-check-start', 'ha-convert-start', 'restore-start', 'job-status', "'run-job'"):
            self.assertIn(command, source)
        for word in ('adapter_factory=', 'deps=', "'modprobe'", "'rmmod'", "'insmod'", 'mock.patch', 'handlers=', 'shell=True',
                     'ha_odoo.convert(', 'ha_odoo.check('):
            self.assertNotIn(word, source)
        self.assertTrue(source.startswith('"""SUBSTITUTE IMAGES, NOT THE PRODUCT SERVICE'))
        self.assertIn("'label': LABEL_TEXT", source)
        self.assertIn('secret_in_output_suppressed', source)
        self.assertIn(self.NAME, control.CODE_FILES)


class FirstImportRollbackTest(unittest.TestCase):
    """Every OwnerRunner run starts with a FIRST import that fails once and must give this device's own state back (a rollback
    that starts from the imported state cannot tell "rolled back" from "nothing changed"): static order and content checks."""

    SCRIPTS = {'arm54_final_owner_omnigent_public.py': "own_state('first_import_rolled_back', own)",
               'arm54_final_owner_odoo.py': "own_state('first_import_rolled_back', creds",
               'arm54_final_owner_n8n.py': "own_state('first_import_rolled_back')",
               'arm54_final_owner_emqx.py': "own_state('first-import-rolled-back')",
               'arm54_final_owner_headscale.py': "must('own_state_back_after_first_import_rollback'"}

    def test_the_first_restore_is_the_one_that_fails_and_the_own_state_is_checked(self):
        for name, own in self.SCRIPTS.items():
            source = (LAB / name).read_text()
            first = source.index("out['phase'] = 'first-import-rollback'")
            restore = source.index("out['phase'] = 'restore'")
            self.assertLess(source.index("converted_backup_made_encrypted"), first, name)
            self.assertLess(first, restore, name)
            self.assertEqual(source[:first].count("'restore-start'"), 0, name)  # no restore before it
            part = source[first:restore]
            for text in ("expect='rolled-back'", 'first_import_failure_armed', own, 'n == 2 for n in', "get('changed') is True"):
                self.assertIn(text, part, name)

    def test_emqx_also_has_a_first_import_readback_rollback(self):
        source = (LAB / 'arm54_final_owner_emqx.py').read_text()
        part = source[source.index("out['phase'] = 'first-import-readback-rollback'"):source.index("out['phase'] = 'restore'")]
        for text in ('設定（log）', "own_state('first-import-readback-rolled-back')", 'first_import_tamper_armed'):
            self.assertIn(text, part)


class OwnerEmqxFlowTest(unittest.TestCase):
    """arm54_final_owner_emqx.py: package rendering, the dev-d probe unchanged, the production flow (static checks)."""

    def space(self):
        tree = ast.parse((LAB / 'arm54_final_owner_emqx.py').read_text())
        names = {'PORTS', 'QUADLET_DIR', 'CONFIG_DIR', 'USER_UNIT_DIR', 'IMAGES', 'DIGEST_KEYS', 'TAMPER_MARKER', 'TAMPER'}
        body = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in ('package_files', 'digest', 'stable'))
                or (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets))
                or (isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Tuple)
                    and any(getattr(e, 'id', None) in names for e in n.targets[0].elts))]
        space = {'PACKAGE': control.EMQX_PACKAGE, 'DROPDIR': '.config/systemd/user/emqx.service.d'}
        exec(compile(ast.Module(body=body, type_ignores=[]), 'owner-emqx', 'exec'), space)
        return space

    def test_package_is_rendered_for_loopback_with_its_entrance(self):
        space = self.space()
        files = space['package_files']()
        quadlets = sorted(k.rsplit('/', 1)[-1] for k in files if k.startswith('.config/containers/systemd/'))
        self.assertEqual(quadlets, ['emqx-data.volume', 'emqx-entrance.container', 'emqx-log.volume', 'emqx.container',
                                    'emqx.network'])
        self.assertEqual({k: v[0] for k, v in files.items() if k.startswith('.config/emqx/')},
                         {'.config/emqx/acl.conf': '0644', '.config/emqx/base.hocon': '0644',
                          '.config/emqx/entrance.conf': '0644', '.config/emqx/emqx.env': '0600'})
        publish = sorted(l for _m, t in files.values() for l in t.splitlines() if l.startswith('PublishPort='))
        self.assertEqual(publish, sorted('PublishPort=127.0.0.1:%d:%d' % (p, p) for p in (1883, 8883, 8083, 8084, 18083)))
        named = sorted(l.split('=', 1)[1] for _m, t in files.values() for l in t.splitlines() if l.startswith('Image='))
        self.assertEqual(named, sorted(space['IMAGES'].values()))
        images = (LAB / 'arm54_final_owner_images.py').read_text()
        for ref in named:
            self.assertIn(ref.split('@')[1], images)

    def test_digest_keys_and_probe_are_the_dev_d_harness_ones(self):
        import arm54_final_emqx_lib as lib
        product = (LAB / 'emqx_product_real_ha.py').read_text()
        b1 = (LAB / 'ha_import_b1_e2e.py').read_text()
        tree = ast.parse(product)
        keys = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                    and getattr(n.targets[0], 'id', None) == 'DIGEST_KEYS')
        space = self.space()
        self.assertEqual(tuple(keys), tuple(space['DIGEST_KEYS']))
        program = lib.dev_d_probe_program(product, b1)
        self.assertIn('E = "http://127.0.0.1:18083"', program)
        self.assertIn('os.path.expanduser("~/.config/emqx/acl.conf")', program)
        self.assertNotIn('REQ["device_secrets"]', program)

    def test_digest_and_stable(self):
        space = self.space()
        doc = {'retained_api': {'$SYS/x': '1', 'b1/r': '2'}, 'native_counts': {'emqx_acl': 4, 'emqx_retainer_message': 9},
               'config_sha256': 'c', 'rules': []}
        digest, stable = space['digest'](doc), space['stable'](doc)
        self.assertEqual(digest['retained_api'], {'b1/r': '2'})
        self.assertEqual(digest['native_counts'], {'emqx_acl': 4})
        self.assertNotIn('config_sha256', digest)
        self.assertEqual(stable['config_sha256'], 'c')
        self.assertNotIn('native_counts', stable)

    def test_tamper_script_is_the_dev_d_one(self):
        product = (LAB / 'emqx_product_real_ha.py').read_text()
        tree = ast.parse(product)
        tamper = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                      and getattr(n.targets[0], 'id', None) == 'TAMPER').decode()
        self.assertEqual(self.space()['TAMPER'], tamper.replace('.config/emqx-woowbk-tamper-once',
                                                               '.config/a54-emqx-tamper-once'))

    def test_production_flow_nothing_injected(self):
        source = (LAB / 'arm54_final_owner_emqx.py').read_text()
        ast.parse(source)
        for command in ('key-init', 'catalog-suggest', 'catalog-install', 'upload-begin', 'upload-finish',
                        'ha-check-start', 'ha-convert-start', 'restore-start', 'job-status', "'run-job'"):
            self.assertIn(command, source)
        for word in ('adapter_factory=', 'deps=', "'modprobe'", "'rmmod'", "'insmod'", 'mock.patch', 'handlers=', 'shell=True'):
            self.assertNotIn(word, source)
        self.assertIn('secret_in_output_suppressed', source)
        self.assertIn('arm54_final_owner_emqx.py', control.CODE_FILES)
        self.assertIn("'stage-emqx'", (LAB / 'arm54_final_control.py').read_text())

