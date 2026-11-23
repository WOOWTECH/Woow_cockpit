"""T4: crafted add-on members through the product's real member reader (ha_emqx.scan_member -> habackup.iter_entries)
into a collecting sink (what member_pass would import into HA's broker volume). No container is needed.
Run: python3 -I t4_members.py <codebase>"""
import io
import json
import os
import sys
import tarfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L

D = 'data/emqx/data/'
ADDON = json.dumps({'system': {'slug': 'woow-emqx', 'name': 'EMQX'}, 'version': '5.9.1', 'state': 'stopped'}).encode()


def build(entries):
    """entries: [(name, kind, data/linkname, mode)] in order, raw (no normalisation, no implied parents)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, kind, value, mode in [('addon.json', 'file', ADDON, 0o644)] + entries:
            info = tarfile.TarInfo(name)
            info.mode, info.mtime = mode, int(time.time())
            if kind == 'file':
                info.size = len(value); tar.addfile(info, io.BytesIO(value)); continue
            info.type = {'dir': tarfile.DIRTYPE, 'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                         'chr': tarfile.CHRTYPE, 'fifo': tarfile.FIFOTYPE, 'blk': tarfile.BLKTYPE}[kind]
            if kind in ('symlink', 'hardlink'):
                info.linkname = value
            tar.addfile(info)
    return buf.getvalue()


def pax_path_override():
    """A PAX `path` record that renames a harmless header name to a traversal."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo('addon.json'); info.size = len(ADDON); tar.addfile(info, io.BytesIO(ADDON))
        info = tarfile.TarInfo(D + 'certs/ok.pem'); data = b'x'
        info.pax_headers = {'path': D + 'certs/../../../../etc/cron.d/x'}; info.size = 1
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Sink:
    def __init__(self):
        self.names, self.members = set(), {}

    def add_member(self, info, fileobj=None):
        if info.name in self.names:
            raise L.BackupError('corrupt-archive', 'dup')
        self.names.add(info.name)
        self.members[info.name] = (info.type.decode() if isinstance(info.type, bytes) else str(info.type),
                                   oct(info.mode), info.uid, info.gid, info.size)
        if fileobj is not None:
            fileobj.read(info.size)

    def add_entry(self, name, entry, *, mode, uid, gid):
        from woowbackup import hacommon
        self.add_member(hacommon.info(name, 'file', mode=mode, uid=uid, gid=gid, mtime=entry.mtime, size=entry.size),
                        hacommon._Exact(entry))


CASES = {
    'absolute_symlink_acl': [(D + 'authz', 'dir', None, 0o755), (D + 'authz/acl.conf', 'symlink', '/etc/shadow', 0o777)],
    'relative_symlink_escape': [(D + 'certs', 'dir', None, 0o755), (D + 'certs/up', 'symlink', '../../../../../etc', 0o777)],
    'hardlink_to_node_file': [('data/emqx/node.name', 'file', b'emqx@127.0.0.1', 0o644),
                              (D + 'certs/h', 'hardlink', 'data/emqx/node.name', 0o644)],
    'dotdot_name': [(D + '../../../etc/passwd', 'file', b'x', 0o644)],
    'absolute_name': [('/' + D + 'configs/cluster.hocon', 'file', b'x', 0o644)],
    'duplicate_cluster_hocon': [(D + 'configs/cluster.hocon', 'file', b'a = 1', 0o644),
                                (D + 'configs/cluster.hocon', 'file', b'plugins {}', 0o644)],
    'entry_below_file': [(D + 'certs', 'file', b'x', 0o644), (D + 'certs/key.pem', 'file', b'k', 0o644)],
    'control_char_name': [(D + 'certs/a\nb', 'file', b'x', 0o644)],
    'char_device': [(D + 'certs/null', 'chr', None, 0o666)],
    'block_device': [(D + 'certs/sda', 'blk', None, 0o666)],
    'fifo': [(D + 'certs/fifo', 'fifo', None, 0o666)],
    'setuid_executable_cert': [(D + 'certs/run.sh', 'file', b'#!/bin/sh\n', 0o6755)],
    'setuid_executable_mnesia': [(D + 'mnesia/emqx@127.0.0.1/x', 'file', b'#!/bin/sh\n', 0o4755)],
    'oversized_cluster_hocon': [(D + 'configs/cluster.hocon', 'file', b'#' * (8 * 1024 * 1024 + 1), 0o644)],
    'generated_configs_never_staged': [(D + 'configs/app.2026.config', 'file', b'x', 0o644),
                                       (D + 'configs/vm.2026.args', 'file', b'-setcookie x', 0o644),
                                       (D + 'configs/cluster.hocon.bak', 'file', b'x', 0o644),
                                       ('data/emqx/plugins/evil-1.0.tar.gz', 'file', b'x', 0o644),
                                       ('data/emqx/patches/evil.beam', 'file', b'x', 0o644)],
}


def run_case(ha_emqx, habackup, name, raw):
    sink, report = Sink(), habackup.Report()
    try:
        ha_emqx.scan_member(io.BytesIO(raw), report, sink)
        return {'outcome': 'accepted', 'staged': sink.members, 'skipped_symlinks': report.skipped_symlinks,
                'skipped_other': report.skipped_other}
    except L.BackupError as error:
        return {'outcome': 'refused', 'code': error.code, 'message': error.message[:160]}


def main(codebase):
    ha_emqx = L.use(codebase)
    from woowbackup import habackup
    results = {name: run_case(ha_emqx, habackup, name, build(entries)) for name, entries in CASES.items()}
    results['pax_path_override'] = run_case(ha_emqx, habackup, 'pax', pax_path_override())
    record = {'test': 'T4 crafted add-on members through scan_member', 'codebase': codebase, 'cases': results}
    print(json.dumps(record, ensure_ascii=False, indent=1)[:6000])
    L.evidence(os.path.join(L.SR, 'runs', f't4-{codebase}.json'), record)


if __name__ == '__main__':
    main(sys.argv[1])
