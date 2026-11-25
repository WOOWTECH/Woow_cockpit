#!/usr/bin/env python3
"""F1-foundation, offline probes on REAL Home Assistant backups (no container, no device, no key; only counts and codes are printed).

  python3 -I real_file_probes.py <repository> selection <folder with .tar files>   what a start decides without a key / with a wrong one
  python3 -I real_file_probes.py <repository> isolation <one unencrypted .tar>     the check job with one add-on damaged (one flipped byte);
                                                                                   every module's check is replaced by a complete read
"""
import collections, contextlib, json, os, shutil, sys
from pathlib import Path
from unittest import mock

REPO, MODE, SOURCE = sys.argv[1], sys.argv[2], Path(sys.argv[3])
sys.path.insert(0, REPO + '/backup-engine')
sys.path.insert(0, REPO)
from woowbackup import flows, haapps, habackup, haimport, hasecuretar  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402


def selection():
    out, opened = collections.Counter(), 0
    for path in sorted(p for p in SOURCE.rglob('*.tar') if not p.is_symlink()):
        try:
            backup = habackup.open_backup(path)
        except BackupError as error:
            out[f'not read: {error.code}'] += 1
            continue
        opened += 1
        with backup:
            members = {i.app_id: haimport.addon_members(backup.layout, i.slug)[0] for i in haapps.IMPORTERS
                       if haimport.addon_members(backup.layout, i.slug)}
            wanted = haimport.needed_members(backup.layout, members)
            kinds = sorted({m.encryption for _app, m in wanted})
            share = sum(1 for _app, m in wanted if m.role == 'folder')
            for label, keys in (('no key', None), ('a wrong key', hasecuretar.Keys('not the key of this backup'))):
                try:
                    haimport.key_problems(backup, keys, wanted)
                    answer = 'can start'
                except BackupError as error:
                    answer = f'{error.code} job_wide={getattr(error, "job_wide", False)}'
                out[f'members {kinds}, share folder read by {share} app(s), {label}: {answer}'] += 1
    print('real HA backups opened:', opened)
    for key, value in sorted(out.items()):
        print(value, key)


def isolation():
    from tests.backup import test_ha_import as t

    class Probe(t.FlowCase):
        def runTest(self):
            pass

    def read_all(suffix):
        def check(work, app):
            files = 0
            with work.open(work.addon_member(suffix)) as stream:
                for entry in habackup.iter_entries(stream, habackup.Select(), habackup.Report(), checkpoint=work.checkpoint):
                    if entry.kind == 'file':
                        files += 1
                        while entry.read(1 << 20):
                            pass
            return {'target_version': '', app.id: {'files': files}}
        return check

    def run(damage):
        probe = Probe()
        probe.setUp()
        try:
            probe.catalog = {i.app_id: t.app(i.app_id, i.name) for i in haapps.IMPORTERS}
            info = probe.storage.begin_upload('ha.tar', SOURCE.stat().st_size)
            shutil.copyfile(SOURCE, info['path'])
            with habackup.open_backup(info['path']) as backup:
                members = {i.app_id: haimport.addon_members(backup.layout, i.slug) for i in haapps.IMPORTERS}
            apps = [app_id for app_id, found in members.items() if found]
            if damage:
                at = members[damage][0].offset + members[damage][0].size // 2
                with open(info['path'], 'r+b') as handle:
                    handle.seek(at)
                    byte = handle.read(1)
                    handle.seek(at)
                    handle.write(bytes([byte[0] ^ 0xFF]))
            ha_id = probe.storage.finish_upload(info['upload_id'])['id']
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(haimport.SpaceGuard, 'free', lambda guard: 1024 ** 4))
                for i in haapps.IMPORTERS:
                    stack.enter_context(mock.patch.object(i.load(), 'check', read_all(i.slug)))
                check = flows.run_verify(probe.ctx(), {'source': 'ha', 'ha_backup_id': ha_id, 'apps': apps,
                                                       'key_provided': False})['ha_check']
            return {'damaged': damage, 'staging_left': os.path.exists(Path(probe.paths.staging) / probe.job_id),
                    'apps': {row['app_id']: {'importable': row['importable'], 'issues': [i['id'] for i in row['issues']],
                                             'section': row['app_id'] in row} for row in check['apps']}}
        finally:
            probe.tearDown()

    out = [run(None)]
    out += [run(app_id) for app_id in out[0]['apps']]
    ok = (all(app['importable'] for app in out[0]['apps'].values()) and not any(r['staging_left'] for r in out)
          and all((name != r['damaged']) == app['importable'] for r in out[1:] for name, app in r['apps'].items()))
    print(json.dumps({'result': 'pass' if ok else 'fail', 'runs': out}, indent=1))


{'selection': selection, 'isolation': isolation}[MODE]()
