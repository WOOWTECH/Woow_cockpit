"""Build a candidate from a synthetic HA backup and a scoped synthetic target.

Called only by the dev-d driver. Uses the product member reader, conversion and
output packager; never calls the guarded public HA conversion entry point.
"""
import io
import json
import tarfile
from types import SimpleNamespace

from woowbackup import habackup, ha_emqx, ha_n8n, tempctr

SLUG = '1b7b4ce7_woow-emqx'


class Budget:
    def __init__(self):
        self.used = 0

    def budget(self):
        return 2 * 1024 ** 3 - self.used

    def wrote(self, size):
        self.used += size
        if self.budget() < 0:
            raise RuntimeError('synthetic staging budget exceeded')


def backup_from_volume(runner, fixture, root):
    """Wrap the stopped, synthetic source volume in a Home Assistant backup."""
    raw = root / 'synthetic-source-volume.tar'
    with raw.open('xb') as handle:
        runner.relay(['volume', 'export', fixture.volumes[0]], stdout=handle, timeout=600,
                     max_output=2 * 1024 ** 3)

    def add(archive, name, data):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    member_path = root / 'synthetic-addon.tar.gz'
    addon = {'user': {'version': '5.9.1', 'image': 'synthetic'},
             'system': {'slug': 'woow-emqx', 'name': 'Synthetic EMQX'},
             'version': '5.9.1', 'state': 'stopped'}
    with tarfile.open(member_path, 'w:gz', format=tarfile.PAX_FORMAT) as dest:
        add(dest, 'addon.json', json.dumps(addon).encode())
        add(dest, 'data/emqx/node.name', b'emqx@127.0.0.1')
        with tarfile.open(raw, 'r:') as source:
            for member in source:
                name = ha_emqx.ha_odoo._norm(member.name)
                if name == '.':
                    continue
                if name is None or not (member.isfile() or member.isdir()):
                    raise RuntimeError('unexpected synthetic source volume entry')
                info = ha_emqx.ha_odoo._copy_info(member, 'data/emqx/data/' + name)
                dest.addfile(info, source.extractfile(member) if member.isfile() else None)
    raw.unlink()
    doc = {'slug': 'c0ffee00', 'version': 2, 'name': 'synthetic-emqx',
           'date': '2026-11-20T08:36:08+00:00', 'type': 'partial',
           'supervisor_version': '2026.11.0', 'compressed': True, 'protected': False,
           'homeassistant': None, 'folders': [], 'repositories': [],
           'addons': [{'slug': SLUG, 'name': 'Synthetic EMQX', 'version': '5.9.1', 'size': 0.0}]}
    backup = root / 'synthetic-ha.tar'
    with tarfile.open(backup, 'x') as dest:
        info = tarfile.TarInfo(SLUG + '.tar.gz')
        info.size = member_path.stat().st_size
        with member_path.open('rb') as handle:
            dest.addfile(info, handle)
        add(dest, 'backup.json', json.dumps(doc).encode())
    member_path.unlink()
    return backup


def build_candidate(runner, fixture, app, adapter, backup, root, job_id):
    """Call the actual HA candidate builder and packager, then clean all temp roles."""
    config = runner.home + '/.config/' + fixture.prefix
    target = SimpleNamespace(container=fixture.prefix, data_volume=fixture.volumes[0],
        log_volume=fixture.volumes[1], image='sha256:' + fixture.image_id,
        env={'EMQX_NODE__NAME': 'emqx@127.0.0.1'},
        files=[(config + '/base.hocon', '/opt/emqx/etc/base.hocon', 'ro'),
               (config + '/acl.conf', '/opt/emqx/etc/lab-acl.conf', 'ro')],
        secrets=[fixture.secret + ',type=mount,target=/opt/emqx/etc/lab-bootstrap.csv,uid=1000,gid=1000,mode=0400',
                 fixture.dashboard_secret + ',type=env,target=EMQX_DASHBOARD__DEFAULT_PASSWORD'])
    work = SimpleNamespace(runner=lambda _app: runner, guard=Budget(), abort=None,
                           checkpoint=lambda: None, phase=lambda _name: None, log=lambda _message: None,
                           addon_member=lambda _slug: SLUG,
                           addon_info=lambda _slug: SimpleNamespace(version='5.9.1'))
    tmp = tempctr.TempObjects(runner, job_id, memory='768m', pids=512, cpus='1')
    try:
        with habackup.open_backup(backup) as opened:
            work.open = lambda member: opened.open_addon(member)
            built = ha_emqx._build_candidate(work, app, tmp, target, root, version='5.8.9')
        log_root = ha_n8n.volume_root(work, app, fixture.volumes[1])
        return ha_emqx._package_candidate(work, tmp, target, root, root / 'candidate-output', built[3],
                                          ids=adapter.owner_ids(), log_root=log_root)
    finally:
        if tmp.cleanup():
            raise RuntimeError('synthetic temporary objects remain')
