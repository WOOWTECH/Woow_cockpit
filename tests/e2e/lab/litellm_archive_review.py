#!/usr/bin/env python3
"""LiteLLM HA import security review (2026-11-23), part 1: crafted add-on members against the REAL product reader
(ha_litellm.scan_member -> habackup.iter_entries -> ha_odoo.PgSink). Offline: no container, no network, no secret.

  PYTHONPATH=backup-engine:tests python3 -I tests/e2e/lab/litellm_archive_review.py > out.json

Every case builds an add-on inner tar the way a malicious HA backup could, runs scan_member with a real PgSink writing
into memory, and records only the outcome class: refused (error code), or accepted (what the Source says, which names
reached the cluster volume tar and their modes/owners). No salt value is printed (only whether one was accepted)."""
import io
import json
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
for _p in (str(REPO / 'backup-engine'), str(REPO / 'tests')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from woowbackup import habackup, ha_litellm, ha_odoo  # noqa: E402
from woowbackup.errors import BackupError  # noqa: E402
from backup import hafixtures as hx  # noqa: E402

SALT = b'sk-' + b'5a' * 32  # a generated test value (not a real key)
ADDON = {'user': {'version': '0.1.15', 'image': 'ghcr.io/woowtech/woow-ha-litellm-amd64', 'options': {}},
         'system': {'slug': 'woow-litellm', 'name': 'Woow LiteLLM'}, 'version': '0.1.15'}


def base(extra=(), *, salt=True, state=True, pg_version=b'18\n'):
    entries = [{'name': '.', 'type': 'dir'}, {'name': './addon.json', 'data': json.dumps(ADDON).encode()},
               {'name': 'data', 'type': 'dir'}, {'name': 'data/secrets', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/secrets/master_key', 'data': b'sk-ha-master-file\n', 'mode': 0o600},
               {'name': 'data/woow', 'type': 'dir'}, {'name': 'data/postgres', 'type': 'dir', 'mode': 0o700},
               {'name': 'data/postgres/PG_VERSION', 'data': pg_version},
               {'name': 'data/postgres/base', 'type': 'dir'}, {'name': 'data/postgres/base/1', 'type': 'dir'},
               {'name': 'data/postgres/base/1/1259', 'data': b'page'}]
    if salt:
        entries.append({'name': 'data/secrets/salt_key', 'data': SALT + b'\n', 'mode': 0o600})
    if state:
        entries.append({'name': 'data/woow/state.json', 'data': b'{"litellm_version": "1.104.0"}'})
    return entries + list(extra)


def run(entries, **kw):
    raw = hx.tar_bytes(entries, **kw) if isinstance(entries, list) else entries
    out = io.BytesIO()
    sink = ha_odoo.PgSink(out, 70, 70)
    report = habackup.Report()
    try:
        src = ha_litellm.scan_member(io.BytesIO(raw), report, pg=sink)
        sink.close()
    except BackupError as error:
        return {'outcome': 'refused', 'code': error.code, 'detail': {k: str(v)[:80] for k, v in
                                                                     (getattr(error, 'details', None) or {}).items()
                                                                     if k in ('reason', 'member', 'type')}}
    except Exception as error:  # noqa: BLE001 - a crash is a finding
        return {'outcome': 'CRASH', 'error': type(error).__name__}
    names = []
    with tarfile.open(fileobj=io.BytesIO(out.getvalue()), mode='r|') as tar:
        for info in tar:
            names.append([info.name, info.type.decode(), oct(info.mode), info.uid, info.gid, info.linkname or ''])
    return {'outcome': 'accepted', 'pg_version': src.pg_version, 'pg_files': src.pg_files, 'salt_valid': src.salt_valid,
            'salt_present': src.salt() is not None, 'state_version': src.state_version, 'symlinks': src.symlinks,
            'skipped_other': report.skipped_other, 'volume_names': names}


def big_json(depth):
    return ('[' * depth + ']' * depth).encode()


CASES = {
    'baseline': base(),
    'traversal_dotdot': base([{'name': 'data/postgres/../../../tmp/evil', 'data': b'x'}]),
    'absolute_name': base([{'name': '/data/postgres/base/1/9999', 'data': b'x'}]),
    'pax_path_traversal': base([{'name': 'data/postgres/base/1/ok', 'data': b'x',
                                 'pax': {'path': 'data/postgres/../../escape'}}]),
    'control_char_name': base([{'name': 'data/postgres/base/1/a\nb', 'data': b'x'}]),
    'tablespace_symlink_out': base([{'name': 'data/postgres/pg_tblspc', 'type': 'dir'},
                                    {'name': 'data/postgres/pg_tblspc/16400', 'type': 'symlink',
                                     'linkname': '/etc'}]),
    'tablespace_symlink_relative_in': base([{'name': 'data/postgres/pg_tblspc', 'type': 'dir'},
                                            {'name': 'data/postgres/pg_tblspc/16400', 'type': 'symlink',
                                             'linkname': '../base'}]),
    'salt_symlink': base([{'name': 'data/secrets/salt_key', 'type': 'symlink', 'linkname': 'master_key'}],
                         salt=False),
    'salt_hardlink_to_master': base([{'name': 'data/secrets/salt_key', 'type': 'hardlink',
                                      'linkname': 'data/secrets/master_key'}], salt=False),
    'pg_hardlink_to_master_key': base([{'name': 'data/postgres/base/1/16500', 'type': 'hardlink',
                                        'linkname': 'data/secrets/master_key'}]),
    'pg_fifo': base([{'name': 'data/postgres/base/1/fifo', 'type': 'fifo'}]),
    'pg_char_device': base([{'name': 'data/postgres/base/1/dev', 'type': 'chr'}]),
    'pg_block_device': base([{'name': 'data/postgres/base/1/blk', 'type': 'blk'}]),
    'pg_sparse_gnu_type': base([{'name': 'data/postgres/base/1/sparse', 'type': b'S', 'data': b''}]),
    'pg_setuid_mode_and_owner': base([{'name': 'data/postgres/base/1/suid', 'data': b'x', 'mode': 0o4755,
                                       'uid': 0, 'gid': 0}]),
    'salt_duplicate': base([{'name': 'data/secrets/salt_key', 'data': SALT + b'\n'}]),
    'salt_directory': base([{'name': 'data/secrets/salt_key', 'type': 'dir'}], salt=False),
    'salt_oversized_1025': base([{'name': 'data/secrets/salt_key', 'data': b'a' * 1025}], salt=False),
    'salt_bad_charset': base([{'name': 'data/secrets/salt_key', 'data': b"sk-'; DROP TABLE x; --aaaaaaaa\n"}],
                             salt=False),
    'salt_short_15': base([{'name': 'data/secrets/salt_key', 'data': b'a' * 15}], salt=False),
    'salt_with_nul': base([{'name': 'data/secrets/salt_key', 'data': b'sk-aaaaaaaaaaaaaaaa\x00bbbb'}], salt=False),
    'state_oversized': base([{'name': 'data/woow/state.json', 'data': b' ' * 65537}], state=False),
    'state_deep_nesting': base([{'name': 'data/woow/state.json', 'data': big_json(60000)[:65536]}], state=False),
    'state_duplicate_keys': base([{'name': 'data/woow/state.json',
                                   'data': b'{"litellm_version": "1.104.0", "litellm_version": "9.9.9"}'}],
                                 state=False),
    'state_duplicate_entry': base([{'name': 'data/woow/state.json', 'data': b'{"litellm_version": "9.9.9"}'}]),
    'pg_version_oversized': base(pg_version=b'18\n' + b' ' * 100000),
    'pg_version_not_a_number': base(pg_version=b'18.7; select 1\n'),
    'pg_version_duplicate': base([{'name': 'data/postgres/PG_VERSION', 'data': b'17\n'}]),
    'replaced_conf_as_dir': base([{'name': 'data/postgres/postgresql.auto.conf', 'type': 'dir'},
                                  {'name': 'data/postgres/postgresql.auto.conf/evil', 'data': b'x'}]),
    'hba_and_conf_d': base([{'name': 'data/postgres/pg_hba.conf', 'data': b'host all all 0.0.0.0/0 trust\n'},
                            {'name': 'data/postgres/conf.d', 'type': 'dir'},
                            {'name': 'data/postgres/conf.d/evil.conf', 'data': b"archive_command='id'\n"}]),
    'recovery_and_backup_label': base([{'name': 'data/postgres/backup_label', 'data': b'START WAL LOCATION: 0/2\n'},
                                       {'name': 'data/postgres/tablespace_map', 'data': b'16400 /tmp/evil\n'},
                                       {'name': 'data/postgres/recovery.signal', 'data': b''},
                                       {'name': 'data/postgres/standby.signal', 'data': b''},
                                       {'name': 'data/postgres/postmaster.opts', 'data': b'x'}]),
    'other_member_paths_ignored': base([{'name': 'data/options.json', 'data': b'{"master_key": "x"}'},
                                        {'name': 'data/secrets/pg_password', 'data': b'p\n'},
                                        {'name': 'data/pre-upgrade-dumps', 'type': 'dir'},
                                        {'name': 'data/pre-upgrade-dumps/x.dump', 'data': b'PGDMP'}]),
    'wrong_slug': [{'name': '.', 'type': 'dir'},
                   {'name': './addon.json', 'data': json.dumps({**ADDON, 'system': {'slug': 'woow-odoo'}}).encode()}],
    'no_addon_json': [{'name': '.', 'type': 'dir'}, {'name': 'data', 'type': 'dir'}],
}


def main():
    results = {name: run(entries) for name, entries in CASES.items()}
    raw = hx.tar_bytes(base([{'name': 'data/postgres/base/1/16600', 'data': b'z' * 5000}]))
    cut = raw.index(b'z' * 5000) + 2000
    results['truncated_mid_file'] = run(raw[:cut])
    results['no_end_of_archive_marker'] = run(raw[:raw.index(b'z' * 5000) + 5120])
    import hashlib
    import subprocess
    head = subprocess.run(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], capture_output=True, text=True,
                          timeout=60).stdout.strip()
    dirty = bool(subprocess.run(['git', '-C', str(REPO), 'status', '--porcelain', '--untracked-files=no'],
                                capture_output=True, text=True, timeout=60).stdout.strip())
    product = hashlib.sha256((REPO / 'backup-engine/woowbackup/ha_litellm.py').read_bytes()).hexdigest()
    json.dump({'reviewed': 'ha_litellm.scan_member + ha_odoo.PgSink (real code)', 'cases': results,
               'source': {'commit': head, 'tracked_changes': dirty, 'ha_litellm_sha256': product}}, sys.stdout,
              indent=1, sort_keys=True)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
