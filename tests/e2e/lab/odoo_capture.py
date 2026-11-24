#!/usr/bin/env python3
"""Private same-run Odoo capture and fail-closed cell comparison; no table exemptions.

run is HOST-only through labpodman; requires an allocated heavyweight slot. It only captures (status "captured");
fetch copies the private files out and compares them, compare does the same offline. Schema version 2 captures
(odoo_capture.sql) carry a small plaintext projection of non-secret columns and every table's count and md5 in the
same snapshot, so differences are explained row by row by odoo_explain.py (vendor file:line there); a version 1
capture (2026-11-21) can only be equal or unverified. Private artifacts contain cell hashes (not anonymized).
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

TABLES = {'public.' + t for t in ('ir_config_parameter', 'ir_cron', 'ir_cron_progress', 'bus_bus')}
# Captured row by row since the x86 run of 2026-11-23 (an Odoo job can queue mail at runtime); older captures lack them.
OPTIONAL_TABLES = {'public.mail_mail', 'public.mail_message'}
STAGES = ('target_before', 'source_cold', 'restored_cold', 'converted_cold', 'runtime', 'quiescent')
HEX = re.compile(r'[0-9a-f]{64}')


def require(ok):
    if not ok:
        raise ValueError('capture contract rejected; contents withheld')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def unique(pairs):
    obj = {}
    for k, v in pairs:
        require(k not in obj)
        obj[k] = v
    return obj


def loads(text):
    return json.loads(text, object_pairs_hook=unique)


def private_write(path, data):
    # Exclusive creation: never reuse a previous successful capture.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


FINGERPRINT_LINE = re.compile(r'(public\.[A-Za-z_][A-Za-z_0-9]*) (0|[1-9][0-9]*) ([0-9a-f]{32})')


def fingerprints(records):
    """{table: (count, md5)} of a schema_version 2 capture (all user tables, same snapshot as the rows)."""
    out = {}
    for r in records:
        if r.get('kind') != 'table_fingerprint':
            continue
        line = r.get('line')
        match = FINGERPRINT_LINE.fullmatch(line) if isinstance(line, str) else None
        require(match is not None and match.group(1) not in out)
        out[match.group(1)] = (match.group(2), match.group(3))
    return out


def validate(records, *, quiet=False):
    meta = [r for r in records if r.get('kind') == 'capture_metadata']
    require(len(meta) == 1 and meta[0].get('schema_version') in (1, 2))
    version = meta[0]['schema_version']
    require(isinstance(meta[0].get('database'), str) and bool(meta[0]['database']))
    require(type(meta[0].get('other_clients')) is int and meta[0]['other_clients'] >= 0)
    if quiet:
        require(meta[0]['other_clients'] == 0)
    if version == 2:
        found = fingerprints(records)
        require(bool(found) and set(TABLES) <= set(found))
    optional = {r.get('table') for r in records if r.get('kind') == 'column'} & OPTIONAL_TABLES
    require(not optional or (version == 2 and optional == OPTIONAL_TABLES))
    known = TABLES | optional
    tables = {t: {'schema': {}, 'rows': {}, 'count': None} for t in known}
    for r in records:
        kind = r.get('kind')
        if kind == 'capture_metadata' or (version == 2 and kind == 'table_fingerprint'):
            continue
        require(kind in ('column', 'row', 'count') and r.get('table') in known)
        table = tables[r['table']]
        if kind == 'column':
            name = r.get('name')
            require(isinstance(name, str) and name and name not in table['schema'])
            require(type(r.get('position')) is int and r['position'] > 0)
            require(isinstance(r.get('type'), str) and r['type'])
            require(type(r.get('primary_key')) is bool and type(r.get('not_null')) is bool)
            table['schema'][name] = {k: r[k] for k in ('position', 'type', 'not_null', 'primary_key', 'identity', 'generated', 'collation', 'default_sha256')}
        elif kind == 'count':
            require(table['count'] is None and type(r.get('count')) is int and r['count'] >= 0)
            table['count'] = r['count']
        else:
            ident = r.get('id')
            require(type(ident) is int and str(ident) not in table['rows'])
            require(isinstance(r.get('row_sha256'), str) and HEX.fullmatch(r['row_sha256']))
            fields = r.get('field_sha256')
            require(isinstance(fields, dict) and all(isinstance(v, str) and HEX.fullmatch(v) for v in fields.values()))
            safe = r.get('safe') if version == 2 else {}
            require(isinstance(safe, dict))
            table['rows'][str(ident)] = {'hash': r['row_sha256'], 'fields': fields, 'safe': safe}
    for table in tables.values():
        schema = table['schema']
        require(schema and [k for k, v in schema.items() if v['primary_key']] == ['id'])
        require(schema['id']['not_null'])
        require(len({c['position'] for c in schema.values()}) == len(schema))
        require(table['count'] == len(table['rows']))
        require(all(set(row['fields']) == set(schema) for row in table['rows'].values()))
    return tables


def differences(left, right):
    out = []
    require(set(left) == set(right))
    for table in sorted(left):
        a, b = left[table], right[table]
        if a['schema'] != b['schema']:
            out.append({'table': table, 'kind': 'schema'})
        for ident in sorted(set(a['rows']) | set(b['rows'])):
            x, y = a['rows'].get(ident), b['rows'].get(ident)
            if x is None or y is None:
                out.append({'table': table, 'id': ident, 'kind': 'added' if x is None else 'removed'})
                continue
            fields = sorted(k for k in set(x['fields']) | set(y['fields']) if x['fields'].get(k) != y['fields'].get(k))
            if fields or x['hash'] != y['hash']:
                out.append({'table': table, 'id': ident, 'kind': 'changed', 'fields': fields,
                            'hash_consistent': bool(fields) == (x['hash'] != y['hash'])})
    return out


def compare(directory, fingerprint_text=None):
    directory = Path(directory)
    manifest = loads((directory / 'complete.json').read_bytes())
    require(manifest['status'] == 'complete' and manifest['baseline_restored'] is True)
    captures, previous, common, raws = {}, None, None, {}
    for stage in STAGES:
        raw = (directory / (stage + '.json')).read_bytes()
        require(manifest['files'].get(stage + '.json') == digest(raw))
        cap = loads(raw)
        require(cap['stage'] == stage and cap['previous'] == previous)
        require(cap['run_id'] == manifest['run_id'])
        require(all(isinstance(cap[k], str) and HEX.fullmatch(cap[k]) for k in ('archive_sha256', 'engine_sha256', 'sql_sha256')))
        identity = tuple(cap[k] for k in ('run_id', 'archive_sha256', 'ha_backup_id', 'engine_sha256', 'sql_sha256', 'convert_job'))
        require(common is None or common == identity)
        common = identity
        require(cap['end_ns'] >= cap['start_ns'] and (previous is None or cap['start_ns'] >= prior_end))
        if stage in ('runtime', 'quiescent'):
            require(cap.get('restore_job') == manifest['restore_job'] and cap['restore_job'])
            require(cap.get('converted_backup_id') == manifest['converted_backup_id'] and cap['converted_backup_id'])
        if stage == 'quiescent':
            require(cap.get('odoo_active') == 'inactive')
        captures[stage] = validate(cap['records'], quiet=stage in ('source_cold', 'restored_cold', 'converted_cold', 'quiescent'))
        meta = next(r for r in cap['records'] if r['kind'] == 'capture_metadata')
        require(meta['database'] == (manifest['source_database'] if stage == 'source_cold' else 'odoo'))
        prior_end, previous = cap['end_ns'], digest(raw)
        raws[stage] = cap
    require(manifest['files'].get('runtime-journal.bin') == file_hash(directory / 'runtime-journal.bin'))
    edges = [('source_cold', 'restored_cold'), ('restored_cold', 'converted_cold'),
             ('converted_cold', 'runtime'), ('runtime', 'quiescent'),
             ('source_cold', 'quiescent'), ('converted_cold', 'quiescent')]
    delta = {a + '->' + b: differences(captures[a], captures[b]) for a, b in edges}
    versions = {next(r for r in raws[s]['records'] if r['kind'] == 'capture_metadata')['schema_version']
                for s in STAGES}
    if versions != {2}:
        # schema_version 1 (2026-11-21): hashes only, no row evidence; any difference stays unverified.
        return {'status': 'unverified_differences' if any(delta.values()) else 'equal_four_table_cells',
                'acceptance': not any(delta.values()), 'run_id': manifest['run_id'], 'differences': delta,
                'limits': 'Four table schema/cells only. Runtime journal is evidence, never an exemption. No full application parity claim.'}
    return explain_run(raws, captures, manifest, delta, edges, fingerprint_text)


EDGE_RULES = {'source_cold->restored_cold': (), 'restored_cold->converted_cold': ('import',),
              'converted_cold->runtime': ('runtime',), 'runtime->quiescent': ('runtime',),
              'source_cold->quiescent': ('import', 'runtime'), 'converted_cold->quiescent': ('runtime',)}


def live_values(tables):
    """The device's own import-settings values (its target_before capture; plain text only for PLAIN_KEYS)."""
    rows = {r['safe'].get('key'): r['safe'] for r in tables['public.ir_config_parameter']['rows'].values()}
    return {key: (rows[key].get('value') if key in rows else None)
            for key in ('web.base.url', 'web.base.url.freeze', 'woow_paas_platform.upgrade_done')}


def source_fingerprint(text, database='woowtest'):
    """The HA-side fingerprint file (ha_import_e2e --fingerprint): exactly one `#DB <database>` section."""
    out, current, sections = {}, None, 0
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('#DB '):
            parts = line.split()
            require(len(parts) == 2)
            current = parts[1]
            sections += current == database
            continue
        if not line or line.startswith('#') or current != database:
            continue
        match = FINGERPRINT_LINE.fullmatch(line)
        require(match is not None and match.group(1) not in out)
        out[match.group(1)] = (match.group(2), match.group(3))
    require(sections == 1 and bool(out))
    return out


def table_delta(left, right, *, skip=()):
    """Tables (outside `skip`) whose count or md5 differ, or that exist on one side only."""
    return sorted(t for t in set(left) | set(right) if t not in skip and left.get(t) != right.get(t))


def sibling(name):
    """A module next to this file (also under `python3 -I`, which leaves the script folder off sys.path)."""
    if name in sys.modules:
        return sys.modules[name]
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[name] = module
    return module


def explain_run(raws, captures, manifest, delta, edges, fingerprint_text):
    odoo_explain = sibling('odoo_explain')
    prints = {s: fingerprints(raws[s]['records']) for s in STAGES}
    runtime = raws['runtime']
    restore_start = odoo_explain.ts(runtime.get('restore_start_utc'))
    cron_log = raws['quiescent'].get('cron_log') or {}
    started = cron_log.get('started')
    require(restore_start is not None and isinstance(started, list) and all(type(i) is int for i in started))
    live = live_values(captures['target_before'])
    report, ok = {}, True
    for a, b in edges:
        name = a + '->' + b
        meta = next(r for r in raws[b]['records'] if r['kind'] == 'capture_metadata')
        rules = EDGE_RULES[name]
        events = odoo_explain.explain(captures[a], captures[b], rules=rules, live=live,
                                      restore_start=restore_start,
                                      captured_at=odoo_explain.ts(meta.get('snapshot_at') or meta['captured_at']),
                                      cron_log_ids=started)
        other = table_delta(prints[a], prints[b], skip=odoo_explain.row_tables(captures[a], captures[b]))
        edge_ok = all(e['explained'] for e in events) and not other
        ok &= edge_ok
        report[name] = {'rules': list(rules), 'ok': edge_ok, 'other_tables_differ': other,
                        'summary': odoo_explain.summary(events),
                        'events': [odoo_explain.public_event(e) for e in events]}
    binding = None
    if fingerprint_text is not None:
        ha_side = source_fingerprint(fingerprint_text)
        binding = {'tables': len(ha_side), 'differ': table_delta(ha_side, prints['source_cold'])}
        ok &= not binding['differ']
    return {'status': 'explained_row_differences' if ok else 'unverified_differences', 'acceptance': ok,
            'run_id': manifest['run_id'], 'schema_version': 2, 'edges': report,
            'source_vs_ha_fingerprint': binding, 'restore_start_utc': runtime.get('restore_start_utc'),
            'runtime_wait_seconds': runtime.get('runtime_wait_seconds'), 'cron_log': cron_log,
            'limits': 'Four tables row by row, every other table by count and md5 in the same snapshot. Explained '
                      'rows follow odoo_explain rules (vendor file:line there); anything else fails.'}


class Recorder:
    def __init__(self, directory, identity, sql):
        self.directory, self.identity, self.sql = Path(directory), identity, sql
        self.previous = None
        self.files = {}
        self.index = 0

    def capture(self, stage, query, **extra):
        require(stage == STAGES[self.index])
        start = time.time_ns()
        data = query(self.sql)
        records = [loads(line) for line in data.splitlines() if line.strip()]
        validate(records, quiet=stage in ('source_cold', 'restored_cold', 'converted_cold', 'quiescent'))
        cap = dict(self.identity, stage=stage, previous=self.previous, start_ns=start, end_ns=time.time_ns(),
                   records=records, **extra)
        raw = encoded(cap)
        private_write(self.directory / (stage + '.json'), raw)
        self.files[stage + '.json'] = self.previous = digest(raw)
        self.index += 1


@contextlib.contextmanager
def conversion_hooks(module, recorder, database):
    """In-process only: existing hardened member_pass/start_ha_cluster opens real archive.
    Capture the same ephemeral source and destination used by this conversion job.
    No alternate source path or baseline-as-source parameter exists.
    """
    from unittest.mock import patch
    original_start, original_restore = module.start_ha_cluster, module.restore_dump
    original_live, original_carry = module.live_settings, module.carry_settings

    def temporary(cluster, db):
        def query(sql):
            return cluster.tmp.exec(cluster.role, ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                '-U', cluster.superuser, '-d', db, '-f', '-'], user='postgres', input=sql.encode(),
                timeout=120, max_output=32 * 1024 * 1024).stdout
        return query

    def live(work, app, config, image):
        def query(sql):
            return work.runner(app).podman('exec', '-i', config.db_container, 'psql', '-X', '-qAt',
                '-v', 'ON_ERROR_STOP=1', '-U', config.db_user, '-d', 'odoo', '-f', '-',
                input=sql.encode(), timeout=120, max_output=32 * 1024 * 1024).stdout
        recorder.capture('target_before', query)
        return original_live(work, app, config, image)

    def source(work, tmp, image):
        cluster = original_start(work, tmp, image)
        recorder.capture('source_cold', temporary(cluster, database))
        return cluster

    def restored(work, tmp, dump, db):
        result = original_restore(work, tmp, dump, db)
        recorder.capture('restored_cold', temporary(module.Cluster(tmp, 'odoo-db'), 'odoo'))
        return result

    def converted(work, app, config, cluster):
        result = original_carry(work, app, config, cluster)
        recorder.capture('converted_cold', temporary(cluster, 'odoo'))
        return result

    with patch.object(module, 'live_settings', live), patch.object(module, 'start_ha_cluster', source), \
         patch.object(module, 'restore_dump', restored), patch.object(module, 'carry_settings', converted):
        yield


def checked(argv, **kwargs):
    p = subprocess.run(argv, capture_output=True, timeout=kwargs.pop('timeout', 120), **kwargs)
    require(p.returncode == 0)
    return p.stdout


def device_run(request, sql):
    # Called only by the host guard below, in dev-c's private mount namespace.
    sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
    from woowbackup import jobs, ha_odoo, hastore
    from woowbackup.paths import Paths
    paths = Paths()
    run_id = uuid.uuid4().hex
    directory = Path('/var/lib/woowtech-backup/odoo-captures') / run_id
    directory.mkdir(parents=True, mode=0o700)
    archive = hastore.HaStore(paths).file_path(request['ha_backup_id'])
    archive_hash = file_hash(archive)
    require(archive_hash == request['archive_sha256'])
    engine = Path('/usr/local/lib/woowtech-cockpit-backup/woowbackup')
    engine_files = {str(p.relative_to(engine)): file_hash(p) for p in sorted(engine.rglob('*.py'))}
    require(bool(engine_files))
    engine_hash = digest(encoded(engine_files))
    def job(kind, params, key=None):
        reply = jobs.start_job(paths, kind, params, str(uuid.uuid4()), key_text=key,
                               key_kind='ha', launcher=lambda ident: None)
        return reply['job_id']
    def execute(ident):
        result = jobs.run_job(paths, ident)
        require(result['state'] == 'succeeded')
        return result.get('result') or {}
    params = {'source': 'ha', 'ha_backup_id': request['ha_backup_id'], 'apps': ['odoo'],
              'odoo_database': request['database'], 'test_mode': False, 'encrypt': True,
              'key_provided': request.get('key') is not None}
    convert_job = job('backup', params, request.get('key'))
    identity = dict(run_id=run_id, archive_sha256=archive_hash, engine_sha256=engine_hash,
                    sql_sha256=digest(sql.encode()), ha_backup_id=request['ha_backup_id'], convert_job=convert_job)
    recorder = Recorder(directory, identity, sql)
    owner = ['/usr/local/bin/woowbk-owner']
    def live_query(query):
        return checked(owner + ['podman', 'exec', '-i', 'odoo18-db', 'psql', '-X', '-qAt', '-v',
            'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'odoo', '-f', '-'], input=query.encode())
    touched = False
    restore_job = None
    baseline_ok = False
    start = str(int(time.time()))
    try:
        with conversion_hooks(ha_odoo, recorder, request['database']):
            converted = execute(convert_job)
        require(file_hash(archive) == archive_hash)
        restore_job = job('restore', {'backup_id': converted['backup_id'], 'apps': ['odoo'], 'key_provided': False})
        touched = True
        wait = request.get('runtime_wait_seconds', 0)
        require(type(wait) is int and 0 <= wait <= 900)
        restore_epoch = time.time()
        restore_start = datetime.fromtimestamp(restore_epoch, timezone.utc).replace(tzinfo=None).isoformat()
        execute(restore_job)
        # Odoo's cron threads poll every 60 s (service/server.py:65): wait so the capture sees what they do.
        time.sleep(wait)
        recorder.capture('runtime', live_query, restore_job=restore_job, converted_backup_id=converted['backup_id'],
                         restore_start_utc=restore_start, runtime_wait_seconds=wait)
        checked(owner + ['systemctl', '--user', 'stop', 'odoo.service'])
        state = checked(owner + ['systemctl', '--user', 'show', 'odoo.service', '-p', 'ActiveState', '--value']).decode().strip()
        require(state == 'inactive')
        recorder.capture('quiescent', live_query, restore_job=restore_job, odoo_active=state,
                         converted_backup_id=converted['backup_id'], cron_log=cron_log(int(restore_epoch) - 5))
        journal = checked(['journalctl', '--since', '@' + start, '--no-pager', '-o', 'json'], timeout=120)
        private_write(directory / 'runtime-journal.bin', journal)
        recorder.files['runtime-journal.bin'] = digest(journal)
    finally:
        try:
            if touched:
                # Recover even when capture or the candidate restore fails.
                baseline = job('restore', {'backup_id': request['baseline'], 'apps': ['odoo'], 'key_provided': False})
                execute(baseline)
                checked(owner + ['systemctl', '--user', 'start', 'odoo.service'])
                baseline_ok = True
        finally:
            private_write(directory / 'outcome.json', encoded({'run_id': run_id, 'baseline_restored': baseline_ok,
                                                               'stages': recorder.index, 'restore_job': restore_job}))
    require(recorder.index == len(STAGES) and baseline_ok and file_hash(archive) == archive_hash)
    require(engine_files == {str(p.relative_to(engine)): file_hash(p) for p in sorted(engine.rglob('*.py'))})
    private_write(directory / 'complete.json', encoded({'status': 'complete', 'run_id': run_id,
        'files': recorder.files, 'baseline_restored': baseline_ok, 'restore_job': restore_job, 'source_database': request['database'],
        'converted_backup_id': converted['backup_id'], 'baseline_backup_id': request['baseline']}))
    # The explanation runs on the host (fetch / compare): odoo_explain.py is not copied into the device.
    return {'directory': str(directory), 'run_id': run_id, 'status': 'captured', 'acceptance': None}


CRON_LINE = re.compile(r"odoo\.addons\.base\.models\.ir_cron: Job (?:'[^']*'|\"[^\"]*\") \((\d+)\) "
                       r"(starting|done in|processed|completed|timed out)")


def cron_log(since_epoch):
    """Which ir.cron jobs Odoo's own log shows since a moment (ir_cron.py:568 'starting', :524 'completed')."""
    data = checked(['journalctl', '--since', '@%d' % since_epoch, '--no-pager', '-o', 'cat',
                    'CONTAINER_NAME=odoo18-web'], timeout=120)
    started, completed, lines = set(), set(), 0
    for line in data.decode('utf-8', 'replace').splitlines():
        match = CRON_LINE.search(line)
        if not match:
            continue
        lines += 1
        (started if match.group(2) == 'starting' else completed).add(int(match.group(1)))
    return {'started': sorted(started), 'completed': sorted(completed), 'lines': lines}


CREDS = Path.home() / '.woowbk-lab/secrets/ha-import-creds.env'


def creds_key(path, name='HA_BACKUP_KEY'):
    """The lab HA archive key from the e2e driver's creds file (the same parsing as ha_import_e2e.Secrets).

    Used when the request says "key_source": "creds", so no new file ever holds the key: the value only travels in
    memory and on the device process's stdin, never into the request, the output or the evidence."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0)
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        key, sep, value = line.strip().partition('=')
        if sep and not key.startswith('#'):
            values[key.strip()] = value.strip().strip('"\'')
    require(bool(values.get(name)))
    return values[name]


def with_key(request, creds):
    """A request whose key comes from the creds file; an inline key and a creds reference never mix."""
    source = request.get('key_source')
    require(source in (None, 'creds'))
    if source is None:
        return request
    require('key' not in request)
    result = {k: v for k, v in request.items() if k != 'key_source'}
    result['key'] = creds_key(creds)
    return result


def isolation(lp):
    require(checked([lp, 'container', 'inspect', 'woowbk-dev-c', '--format',
        '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}']).strip() == b'true none {}')


def fetch(lp, run_id, destination, fingerprint_text=None):
    isolation(lp)
    require(re.fullmatch(r'[0-9a-f]{32}', run_id))
    destination = Path(destination)
    destination.mkdir(mode=0o700)  # no mixing runs or stale files
    for name in [stage + '.json' for stage in STAGES] + ['runtime-journal.bin', 'outcome.json', 'complete.json']:
        data = checked([lp, 'exec', 'woowbk-dev-c', 'cat',
                        '/var/lib/woowtech-backup/odoo-captures/' + run_id + '/' + name])
        private_write(destination / name, data)
    return compare(destination, fingerprint_text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    offline = sub.add_parser('compare')
    offline.add_argument('directory')
    offline.add_argument('--fingerprint', help='HA-side fingerprint file: the source capture must equal it')
    run = sub.add_parser('run')
    run.add_argument('--slot-granted', action='store_true', required=True)
    run.add_argument('--request', required=True, help='0600 JSON: ha_backup_id, archive_sha256, database, baseline, '
                     'optional lab key or "key_source": "creds" (the key is then read from --creds)')
    run.add_argument('--creds', default=str(CREDS), help='0600 lab creds file holding HA_BACKUP_KEY (key_source creds)')
    download = sub.add_parser('fetch')
    download.add_argument('--run-id', required=True)
    download.add_argument('--output', required=True)
    download.add_argument('--fingerprint', help='HA-side fingerprint file: the source capture must equal it')
    args = parser.parse_args()
    text = Path(args.fingerprint).read_text(encoding='utf-8') if getattr(args, 'fingerprint', None) else None
    if args.command == 'compare':
        result = compare(args.directory, text)
    elif args.command == 'fetch':
        result = fetch(str(Path.home() / '.woowbk-lab/bin/labpodman'), args.run_id, args.output, text)
    else:
        lp = str(Path.home() / '.woowbk-lab/bin/labpodman')
        isolation(lp)
        path = Path(args.request)
        require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0)
        request = loads(path.read_bytes())
        require(HEX.fullmatch(request['archive_sha256']) and re.fullmatch(r'woowtest(?:2)?', request['database']))
        request = with_key(request, args.creds)
        # No host Podman store, shell command construction, or persistent runner modification.
        script = Path(__file__).read_text()
        sql = Path(__file__).with_name('odoo_capture.sql').read_text()
        bootstrap = "import json,sys; p=json.load(sys.stdin); n={'__name__':'capture_module'}; exec(p['script'],n); print(json.dumps(n['device_run'](p['request'],p['sql'])))"
        data = checked([lp, 'exec', '-i', 'woowbk-dev-c', 'python3', '-I', '-c', bootstrap],
                       input=encoded({'script': script, 'sql': sql, 'request': request}), timeout=14400)
        result = loads(data)
    if args.command == 'run':
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get('status') == 'captured' else 1
    destination = Path(args.output if args.command == 'fetch' else args.directory)
    if args.command == 'fetch':
        private_write(destination / 'comparison.json', encoded(result))
    print(json.dumps({k: result.get(k) for k in ('status', 'acceptance', 'run_id')}, sort_keys=True))
    return 0 if result['acceptance'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('{"status":"invalid_or_incomplete","acceptance":false}', file=sys.stderr)
        sys.exit(2)
