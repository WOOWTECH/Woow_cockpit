"""Lab driver: backup format 2, the encryption choice, unencrypted copies and deep verify (CONTRACT sections 5, 7, 8;
acceptance S4-S6, F13-F15) on the lab devices with the installed helper (root, stdin JSON), like the page.

    python3 -I tests/e2e/lab/format_e2e.py <v1|encrypted|plain|export|deep|partial|cleanup|all>

Needs the working tree deployed on both devices (tests/e2e/lab/deploy-src.sh a; deploy-src.sh b), woowbk-demo running on
both, woowbk-dirs on dev-a (`partial`), and the dev-a emergency kit (lab key) in ~/.woowbk-lab/secrets/dev-a-kit.txt.
Evidence: ~/.woowbk-lab/evidence/format/<time>-<scenario>/. Plaintext unpacked on the host lives only in a 0700
directory below ~/.woowbk-lab/run/format and is deleted before the scenario ends; every backup a scenario creates is
deleted again by `cleanup` (state in the evidence directory).
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402

e2e.EVIDENCE = e2e.LAB / 'evidence' / 'format'
from cli_e2e import (APP, DOWNLOADS, KIT_FILE, Evidence, Failed, app_post, bridge_download, compare, helper,  # noqa: E402
                     kit_secret, ok, request_id, sh, summary, upload_file, wait_healthy, wait_job)
from hardening import file_sha256, private_dir, py, write_private_stream  # noqa: E402

STATE = e2e.EVIDENCE / 'state.json'
WORK = e2e.LAB / 'run' / 'format'
DIRS_APP = 'woowbk-dirs'
ARCHIVES = '/var/lib/woowtech-backup/archives'
EXPORTS = '/var/lib/woowtech-backup/exports'
NAME_RE = re.compile(r'woowtech-backup-woowbk-dev-[ab]-[0-9]{8}-[0-9]{6}(-unencrypted)?\.tar\Z')


# ------------------------------------------------------------------ small helpers

def load_state():
    try:
        return json.loads(STATE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def remember(dev, backup_id):
    state = load_state()
    state.setdefault('created', []).append([dev, backup_id])
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=1) + '\n', encoding='utf-8')


def run_job(dev, ev, command, request, label, timeout=1800):
    start = ok(dev, command, dict(request, request_id=request_id()), ev=ev)
    job, log = wait_job(dev, start['job_id'], ev=ev, label=label, timeout=timeout)
    ev.save(f'{label}-job', {'job': job, 'log': log})
    return job, log


def backup(dev, ev, label, apps=(APP,), **extra):
    job, log = run_job(dev, ev, 'backup-start', {'apps': list(apps), 'include_images': False, 'note': label, **extra},
                       label)
    if job['state'] == 'succeeded':
        remember(dev, job['result']['backup_id'])
    return job, log


def restore(dev, ev, backup_id, label, apps=(APP,), **extra):
    job, log = run_job(dev, ev, 'restore-start', {'backup_id': backup_id, 'apps': list(apps), 'confirm': True,
                                                  **extra}, label, timeout=2400)
    safety = (job.get('result') or {}).get('safety_backup_id')
    if safety:
        remember(dev, safety)  # the safety backups of these test restores go with `cleanup` too
    return job, log


def restore_b(ev, backup_id, label, scenario, **extra):
    """An in-place restore on dev-b. dev-b holds no device key in this lab, so while 預設加密備份 is on its safety backup
    cannot be made and the job stops before any change (`no-device-key`); with the setting off (acknowledged) the safety
    backup is made unencrypted and the restore runs. The setting is switched back on afterwards."""
    if ok('b', 'status', ev=ev)['key'] is not None:
        return restore('b', ev, backup_id, label, **extra)
    job, _log = restore('b', ev, backup_id, f'{label}-encrypted-safety', **extra)
    ev.check(f'{scenario} dev-b without a device key: with the setting on the restore stops before any change '
             '(no-device-key)', job['state'] == 'failed' and (job.get('error') or {}).get('code') == 'no-device-key'
             and (job.get('result') or {}).get('changed') is False, job.get('error'))
    ok('b', 'settings-set', {'encrypt_by_default': False, 'acknowledge_plaintext': True}, ev=ev)
    try:
        job, log = restore('b', ev, backup_id, label, **extra)
        safety = meta_of('b', ev, (job.get('result') or {}).get('safety_backup_id'))
        ev.check(f'{scenario} dev-b with the setting off: the safety backup is unencrypted (no device key needed)',
                 safety is not None and safety['encrypted'] is False and safety['key_id'] is None, safety)
    finally:
        ok('b', 'settings-set', {'encrypt_by_default': True}, ev=ev)
    return job, log


def meta_of(dev, ev, backup_id):
    return next((b for b in ok(dev, 'list', ev=ev)['backups'] if b['id'] == backup_id), None)


def device_now(dev):
    return sh(dev, 'date -u "+%Y-%m-%d %H:%M:%S"').stdout.decode().strip()


def journal(dev, since):
    proc = sh(dev, f'journalctl -q -t woowtech-cockpit-backup -o cat --since "{since} UTC" 2>/dev/null || true',
              check=False)
    return proc.stdout.decode('utf-8', 'replace').splitlines()


def download(dev, ev, backup_id, label):
    info = ok(dev, 'download-info', {'backup_id': backup_id}, ev=ev)
    meta = meta_of(dev, ev, backup_id)
    private_dir(DOWNLOADS)
    target = DOWNLOADS / f'format-{info["filename"]}'
    got = bridge_download(dev, info['path'], target, ev=ev)
    ev.check(f'{label}: download through fsread1 equals the index (size, sha256)',
             got['bytes'] == info['size'] == meta['size'] and got['sha256'] == meta['sha256'], got)
    return info, meta, target


def kit_recipient():
    out = subprocess.run(['age-keygen', '-y', str(KIT_FILE)], capture_output=True, text=True, check=True).stdout
    return out.split()[0]


def readme_commands(readme):
    block = readme.split('-' * 70)[0]
    return [line.strip() for line in block.splitlines()
            if line.startswith('  ') and line.strip().split(' ')[0] in ('tar', 'mkdir', 'age')]


def manual_unpack(ev, path, label, kit=None):
    """Run README.txt's commands on the host (plaintext in a private directory the caller deletes)."""
    with tarfile.open(path) as tar:
        readme = tar.extractfile('README.txt').read().decode('utf-8')
        doc = json.loads(tar.extractfile('backup.json').read())
        names = tar.getnames()
    commands = readme_commands(readme)
    work = private_dir(WORK / f'{label}-{int(time.time())}')
    script = '\n'.join(line.replace('<backup-file>.tar', str(path)).replace('<emergency-kit>.txt', str(kit or ''))
                       for line in commands)
    proc = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], cwd=work, capture_output=True, text=True)
    ev.check(f'{label}: the README commands ({len(commands)} lines) unpack the file with plain tools',
             proc.returncode == 0, proc.stderr[-300:])
    return work, doc, names, readme


def entries_match(ev, work, label):
    """Every per-app manifest unpacked by hand lists its entries with matching size and sha256."""
    checked, bad = 0, []
    for manifest in work.glob('*/manifest.json'):
        inner = json.loads(manifest.read_text(encoding='utf-8'))
        for entry in inner['entries']:
            local = manifest.parent / entry['path']
            if not local.is_file() or local.stat().st_size != entry['size'] or file_sha256(local) != entry['sha256']:
                bad.append(entry['path'])
            checked += 1
    ev.check(f'{label}: {checked} unpacked entries match their manifest (size and sha256)', checked and not bad, bad)
    return checked


def mutate(dev, label):
    status, _ = app_post(dev, '/api/notes', json.dumps({'title': f'{label} 之後', 'body': '還原後應消失'}).encode(),
                         'application/json')
    return status == 201


# ------------------------------------------------------------------ scenarios

def scenario_v1(ev):
    """F15: a format 1 backup the previous engine made still verifies (deeply) and restores."""
    old = [b for b in ok('a', 'list', ev=ev)['backups'] if b['format'] == 1 and APP in {a['id'] for a in b['apps']}
           and b['type'] in ('manual', 'safety') and b['key_available']]
    if not old:
        ev.log('no format 1 backup of woowbk-demo on dev-a: F15 skipped')
        return {'skipped': True}
    backup_id = old[0]['id']
    ev.check('F15: listed as format 1 (`.woowbackup`, encrypted)', old[0]['filename'].endswith('.woowbackup')
             and old[0]['encrypted'] is True, old[0])
    inspected = ok('a', 'inspect', {'backup_id': backup_id}, ev=ev)
    ev.check('F15: inspect reads it (format 1, age-x25519)',
             (inspected['manifest']['format'], inspected['manifest']['encryption']) == (1, 'age-x25519'))
    job, _log = run_job('a', ev, 'verify-start', {'backup_id': backup_id}, 'verify[v1]')
    ev.check('F15: the deep verify job passes on the format 1 file', job['state'] == 'succeeded'
             and job['result']['deep'] is True and job['result']['format'] == 1, job.get('result') or job.get('error'))
    ev.check('F15: the index records verified.deep', (meta_of('a', ev, backup_id)['verified'] or {}).get('deep') is True)
    expected = (inspected['manifest']['apps'][0].get('verify_snapshot') or {}).get('summary') or {}
    ev.require('F15: dev-a app healthy before the restore', wait_healthy('a', 120))
    mutate('a', 'F15')
    job, _log = restore('a', ev, backup_id, 'restore[v1]')
    ev.check('F15: the format 1 backup restores in place', job['state'] == 'succeeded', job.get('error'))
    if expected:
        ev.check('F15: data equals the backup-time snapshot', compare(summary('a'), expected) == {},
                 compare(summary('a'), expected))
    return {'backup_id': backup_id}


def scenario_encrypted(ev):
    """S4: an encrypted format 2 backup opens with tar, its README decrypts it with the kit, it verifies deeply on dev-a
    and restores on dev-b."""
    status = ok('a', 'status', ev=ev)
    ev.require('S4 dev-a: device key present, setting 預設加密備份 on, no active job',
               status['key'] and status['settings']['encrypt_by_default'] is True and status['active_job'] is None,
               status.get('settings'))
    ev.require('S4 dev-a app healthy', wait_healthy('a', 120))
    snap = summary('a')
    started = time.monotonic()
    job, log = backup('a', ev, 'backup[s4]')
    ev.require('S4 backup succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.timings['s4_backup_job_s'] = round(time.monotonic() - started, 1)
    result = job['result']
    backup_id = result['backup_id']
    ev.check('S4 result says encrypted', result['encrypted'] is True)
    meta = meta_of('a', ev, backup_id)
    ev.check('S4 index: format 2, encrypted, key id, per-app archive size, verified at creation',
             meta['format'] == 2 and meta['encrypted'] is True and meta['key_id'] == status['key']['key_id']
             and meta['apps'][0].get('size', 0) > 0 and meta['verified']['ok'] is True, meta)
    info, meta, local = download('a', ev, backup_id, 'S4')
    ev.check('S4 stored as archives/<id>.tar with a .tar download name',
             info['path'] == f'{ARCHIVES}/{backup_id}.tar' and NAME_RE.match(info['filename']), info)
    listing = subprocess.run(['tar', '-tvf', str(local)], capture_output=True, text=True)
    names = [line.split()[-1] for line in listing.stdout.splitlines()]
    ev.check('S4 GNU tar lists backup.json, README.txt and the encrypted app archive',
             listing.returncode == 0 and names == ['backup.json', 'README.txt', f'apps/{APP}.tar.zst.age'], names)
    recipient = kit_recipient()
    work = None
    try:
        work, doc, _names, readme = manual_unpack(ev, local, 'S4', KIT_FILE)
        raw = json.dumps(doc, ensure_ascii=False) + readme
        ev.check('S4 backup.json: format 2, age-x25519, names only; no recipient or secret key text in it or README',
                 doc['format'] == 2 and doc['encryption'] == 'age-x25519' and doc['apps'][0]['secrets']
                 and recipient not in raw and 'AGE-SECRET-KEY' not in raw, {k: doc[k] for k in ('format', 'encryption')})
        entries_match(ev, work, 'S4 manual decrypt (age -d -i kit | zstd -d | tar -x)')
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
    ev.check('S4 the plaintext unpacked on the host is gone', work is None or not work.exists())
    job, _log = run_job('a', ev, 'verify-start', {'backup_id': backup_id}, 'verify[s4]')
    checked = ((job.get('result') or {}).get('apps') or [{}])[0].get('checked') or {}
    ev.check('S4 deep verify job succeeded and checked the volume, dump and secrets like a restore',
             job['state'] == 'succeeded' and job['result']['deep'] is True and checked.get('volumes') == 1
             and checked.get('dumps') == 1 and checked.get('secrets', 0) >= 1, job.get('result') or job.get('error'))
    ev.check('S4 index: verified {ok, deep}', (meta_of('a', ev, backup_id)['verified'] or {}).get('deep') is True)

    # dev-b: upload the .tar, inspect with the dev-a kit, restore (in place or fresh) with the key.
    before_b = ok('b', 'list', ev=ev)['backups']
    _begin, (_rc, reply) = upload_file('b', local, ev=ev, filename=info['filename'])
    ev.require('S4 dev-b upload-finish accepts the format 2 file', reply.get('ok'), reply.get('error'))
    uploaded = reply['backup']
    remember('b', uploaded['id'])
    ev.check('S4 dev-b index: uploaded, format 2, encrypted, key not on dev-b, name kept',
             uploaded['type'] == 'uploaded' and uploaded['format'] == 2 and uploaded['encrypted'] is True
             and uploaded['key_available'] is False and uploaded['filename'] == info['filename']
             and uploaded['unauthenticated'] is False, uploaded)
    secret = kit_secret()
    inspected = ok('b', 'inspect', {'backup_id': uploaded['id'], 'key': secret}, ev=ev)
    ev.check('S4 dev-b inspect with the kit: format 2, apps sizes filled', inspected['manifest']['format'] == 2
             and inspected['backup']['apps'][0].get('size') == meta['apps'][0]['size'], inspected['backup']['apps'])
    mode = inspected['preflight']['apps'][0]['mode']
    if mode == 'inplace':
        mutate('b', 'S4')
        job, _log = restore_b(ev, uploaded['id'], 'restore[s4-b]', 'S4', key=secret)
    else:
        job, _log = restore('b', ev, uploaded['id'], 'restore[s4-b]', key=secret)
    ev.check(f'S4 dev-b restore ({mode}) succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.check('S4 dev-b data equals the dev-a backup-time state', wait_healthy('b', 180)
             and compare(summary('b'), snap) == {}, compare(summary('b'), snap))
    ev.save('s4-dev-b-before', before_b)
    return {'backup_id': backup_id, 'download': str(local)}


def scenario_plain(ev):
    """S5: unencrypted backups (per backup and by the setting), restores in place, an upload as unauthenticated."""
    ev.require('S5 dev-a app healthy', wait_healthy('a', 120))
    rc, refused = helper('a', 'backup-start', {'apps': [APP], 'include_images': False, 'note': 'S5',
                                               'encrypt': False, 'request_id': request_id()}, ev=ev)
    ev.check('S5 encrypt:false while the setting is on needs acknowledge_plaintext',
             rc == 1 and refused['error']['code'] == 'invalid-request'
             and refused['error']['details'].get('field') == 'acknowledge_plaintext', refused.get('error'))
    snap = summary('a')
    started = time.monotonic()
    job, log = backup('a', ev, 'backup[s5]', encrypt=False, acknowledge_plaintext=True)
    ev.require('S5 unencrypted backup succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.timings['s5_backup_job_s'] = round(time.monotonic() - started, 1)
    backup_id = job['result']['backup_id']
    meta = meta_of('a', ev, backup_id)
    ev.check('S5 index: format 2, not encrypted, key_id null, key_available, not unauthenticated (made here)',
             (meta['format'], meta['encrypted'], meta['key_id'], meta['key_available'], meta['unauthenticated'])
             == (2, False, None, True, False), meta)
    ev.check('S5 job log says the secrets are stored in plain text', any('明文' in line for line in log))
    info, meta, local = download('a', ev, backup_id, 'S5')
    work = None
    try:
        work, doc, names, _readme = manual_unpack(ev, local, 'S5')
        ev.check('S5 backup.json says encryption none; the app archive is .tar.gz',
                 doc['encryption'] == 'none' and doc['key_id'] is None and names[-1] == f'apps/{APP}.tar.gz', names)
        entries_match(ev, work, 'S5 tar -xzf without any key')
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
    mutate('a', 'S5')
    job, _log = restore('a', ev, backup_id, 'restore[s5]')
    ev.check('S5 in-place restore of the unencrypted backup succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.check('S5 data equals the backup-time state', compare(summary('a'), snap) == {}, compare(summary('a'), snap))
    safety = meta_of('a', ev, (job.get('result') or {}).get('safety_backup_id'))
    ev.check('S5 its safety backup follows the setting (encrypted)', safety and safety['encrypted'] is True, safety)

    # dev-b: an unencrypted upload is unauthenticated.
    _begin, (_rc, reply) = upload_file('b', local, ev=ev)
    ev.require('S5 dev-b accepts the unencrypted upload', reply.get('ok'), reply.get('error'))
    uploaded = reply['backup']
    remember('b', uploaded['id'])
    ev.check('S5 dev-b index: unencrypted, unauthenticated, no key needed',
             (uploaded['encrypted'], uploaded['unauthenticated'], uploaded['key_available']) == (False, True, True),
             uploaded)
    inspected = ok('b', 'inspect', {'backup_id': uploaded['id']}, ev=ev)
    warn = [c for c in inspected['preflight']['checks'] if c['id'] == 'unauthenticated']
    ev.check('S5 dev-b preflight warns that the content cannot be authenticated', warn and warn[0]['status'] == 'warn',
             inspected['preflight']['checks'])
    rc, refused = helper('b', 'restore-start', {'backup_id': uploaded['id'], 'apps': [APP], 'confirm': True,
                                                'request_id': request_id()}, ev=ev)
    ev.check('S5 dev-b restore without accept_unauthenticated is refused',
             rc == 1 and refused['error']['details'].get('field') == 'accept_unauthenticated', refused.get('error'))
    if inspected['preflight']['apps'][0]['mode'] == 'inplace':
        mutate('b', 'S5')
        job, _log = restore_b(ev, uploaded['id'], 'restore[s5-b]', 'S5', accept_unauthenticated=True)
    else:
        job, _log = restore('b', ev, uploaded['id'], 'restore[s5-b]', accept_unauthenticated=True)
    ev.check('S5 dev-b restore with the acknowledgement succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.check('S5 dev-b data equals the backup-time state', wait_healthy('b', 180) and compare(summary('b'), snap) == {})

    # The setting: off (acknowledged, audited) -> backups and safety backups unencrypted; then on again.
    since = device_now('a')
    rc, refused = helper('a', 'settings-set', {'encrypt_by_default': False}, ev=ev)
    ev.check('S5 turning 預設加密備份 off needs acknowledge_plaintext', rc == 1
             and refused['error']['details'].get('field') == 'acknowledge_plaintext', refused.get('error'))
    try:
        changed = ok('a', 'settings-set', {'encrypt_by_default': False, 'acknowledge_plaintext': True}, ev=ev)
        ev.check('S5 setting off; status shows it', changed['settings']['encrypt_by_default'] is False
                 and ok('a', 'status', ev=ev)['settings']['encrypt_by_default'] is False)
        mode = sh('a', 'stat -c "%a %U %G" /etc/woowtech-cockpit/backup/settings.json').stdout.decode().strip()
        ev.check('S5 settings.json is root 0644', mode == '644 root root', mode)
        job, _log = backup('a', ev, 'backup[s5-default-off]')
        off_id = (job.get('result') or {}).get('backup_id')
        ev.check('S5 with the setting off a backup is unencrypted by default', job['state'] == 'succeeded'
                 and job['result']['encrypted'] is False, job.get('error'))
        mutate('a', 'S5-off')
        job, _log = restore('a', ev, off_id, 'restore[s5-off]')
        safety = meta_of('a', ev, (job.get('result') or {}).get('safety_backup_id'))
        ev.check('S5 with the setting off the safety backup is unencrypted', job['state'] == 'succeeded'
                 and safety and safety['encrypted'] is False and safety['key_id'] is None, safety)
    finally:
        back = ok('a', 'settings-set', {'encrypt_by_default': True}, ev=ev)
        ev.check('S5 setting back on', back['settings']['encrypt_by_default'] is True)
    lines = journal('a', since)
    ev.save('s5-journal', lines)
    ev.check('S5 journal records both setting changes with the previous value',
             any('settings encrypt_by_default=false previous=true' in line for line in lines)
             and any('settings encrypt_by_default=true previous=false' in line for line in lines), lines[-5:])
    return {'backup_id': backup_id}


SET_EXPIRED = r'''
import json, os, sys
path = '/var/lib/woowtech-backup/exports/%s.json' % sys.argv[1]
record = json.load(open(path))
record['expires'] = 1
tmp = path + '.tmp'
with open(tmp, 'w') as handle:
    json.dump(record, handle)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
'''


def scenario_export(ev):
    """S6: an unencrypted copy of an encrypted backup: 0600, downloadable, deleted by the timer or the next status,
    audited."""
    job, _log = backup('a', ev, 'backup[s6]')
    ev.require('S6 encrypted source backup', job['state'] == 'succeeded' and job['result']['encrypted'] is True)
    backup_id = job['result']['backup_id']
    since = device_now('a')
    rc, refused = helper('a', 'export-start', {'backup_id': backup_id, 'request_id': request_id()}, ev=ev)
    ev.check('S6 export-start needs confirm:true', rc == 1 and refused['error']['code'] == 'invalid-request')
    started = time.monotonic()
    job, _log = run_job('a', ev, 'export-start', {'backup_id': backup_id, 'confirm': True}, 'export[s6]')
    ev.require('S6 export job succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.timings['s6_export_job_s'] = round(time.monotonic() - started, 1)
    copy = job['result']
    ev.check('S6 phases prepare/decrypt/package/verify all done',
             [(p['id'], p['state']) for p in job['phases']] == [(p, 'done') for p in
                                                                ('prepare', 'decrypt', 'package', 'verify')])
    info = ok('a', 'export-info', {'export_id': copy['export_id']}, ev=ev)
    ev.check('S6 export-info: path in exports/, -unencrypted.tar name, expires in ~15 min',
             info['path'] == f'{EXPORTS}/{copy["export_id"]}.tar' and NAME_RE.match(info['filename'])
             and info['filename'].endswith('-unencrypted.tar') and 800 < info['expires'] - time.time() < 1000, info)
    perms = sh('a', f'stat -c "%a %U %G" {EXPORTS} {info["path"]}').stdout.decode().split('\n')
    ev.check('S6 exports/ is root 0700 and the copy root 0600', perms[:2] == ['700 root root', '600 root root'], perms)
    timers = sh('a', 'systemctl list-timers --all --no-legend 2>/dev/null || true', check=False).stdout.decode()
    ev.check('S6 a transient timer will delete the copy', f'woowtech-backup-export-clean-{copy["export_id"]}' in timers,
             timers[-400:])
    private_dir(DOWNLOADS)
    local = DOWNLOADS / f'format-{info["filename"]}'
    got = bridge_download('a', info['path'], local, ev=ev)
    ev.check('S6 the copy downloads through fsread1', got['bytes'] == info['size'], got)
    work = None
    try:
        work, doc, names, _readme = manual_unpack(ev, local, 'S6')
        ev.check('S6 the copy is format 2 without encryption (.tar.gz inside), same backup id',
                 doc['encryption'] == 'none' and doc['backup_id'] == backup_id and names[-1].endswith('.tar.gz'), names)
        entries_match(ev, work, 'S6 copy unpacked with tar -xzf')
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        local.unlink(missing_ok=True)
    # Expired: the timer's service and the next status delete copies (simulated expiry; the TTL itself is 15 min).
    py('a', SET_EXPIRED, copy['export_id'])
    unit = f'woowtech-backup-export-clean-{copy["export_id"]}.service'
    started = sh('a', f'systemctl start --wait {unit}; echo rc=$?', check=False).stdout.decode().strip()
    gone = sh('a', f'ls -A {EXPORTS}').stdout.decode().split()
    ev.check("S6 the timer's service (export-cleanup) deleted the expired copy",
             started.endswith('rc=0') and f'{copy["export_id"]}.tar' not in gone, {'start': started, 'left': gone})
    job, _log = run_job('a', ev, 'export-start', {'backup_id': backup_id, 'confirm': True}, 'export[s6-2]')
    second = job['result']['export_id']
    py('a', SET_EXPIRED, second)
    ok('a', 'status', ev=ev)
    gone = sh('a', f'ls -A {EXPORTS}').stdout.decode().split()
    ev.check('S6 the next status deleted the second expired copy', not any(second in n for n in gone), gone)
    rc, missing = helper('a', 'export-info', {'export_id': second}, ev=ev)
    ev.check('S6 export-info of an expired copy is not-found', rc == 1 and missing['error']['code'] == 'not-found')
    lines = journal('a', since)
    ev.save('s6-journal', lines)
    for needle in (f'export-unencrypted-request backup={backup_id}', f'export-unencrypted-created backup={backup_id} '
                   f'export={copy["export_id"]}', f'export-unencrypted-download export={copy["export_id"]}',
                   f'export-unencrypted-deleted export={copy["export_id"]} reason=expired',
                   f'export-unencrypted-deleted export={second} reason=expired'):
        ev.check(f'S6 journal: {needle[:60]}…', any(needle in line for line in lines))
    plain = ok('a', 'list', ev=ev)
    ev.check('S6 list shows no copy any more', plain['exports'] == [], plain['exports'])
    return {'backup_id': backup_id}


CRAFT_F13 = r'''
import glob, hashlib, io, json, os, secrets, subprocess, sys, tarfile, time
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
from woowbackup import archive as warchive
base_id, work = sys.argv[1:3]
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
keyfile = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))[0]
recipient = subprocess.run(['age-keygen', '-y', keyfile], capture_output=True, env=ENV, check=True).stdout.decode().split()[0]
os.mkdir(work, 0o700)
try:
    outer = tarfile.open('/var/lib/woowtech-backup/archives/%s.tar' % base_id)
    doc = json.loads(outer.extractfile('backup.json').read())
    sealed = outer.extractfile(doc['apps'][0]['file']).read()
    plain = subprocess.run(['age', '-d', '-i', keyfile], input=sealed, capture_output=True, env=ENV, check=True).stdout
    plain = subprocess.run(['zstd', '-d', '-c', '-q'], input=plain, capture_output=True, env=ENV, check=True).stdout
    inner_tar = tarfile.open(fileobj=io.BytesIO(plain))
    members = inner_tar.getmembers()
    inner = json.loads(inner_tar.extractfile(members[0]).read())
    app = inner['app']
    volume = app['volumes'][0]['entry']
    files = {}
    for index, member in enumerate(members[1:]):
        path = os.path.join(work, 'm%d' % index)
        with open(path, 'wb') as out:
            out.write(inner_tar.extractfile(member).read())
        files[member.name] = path
    hostile = os.path.join(work, 'hostile.tar')
    with tarfile.open(files[volume]) as src, tarfile.open(hostile, 'w', format=tarfile.PAX_FORMAT) as dst:
        for member in src.getmembers():
            dst.addfile(member, src.extractfile(member) if member.isreg() else None)
        evil = tarfile.TarInfo('woowbk-f13-escape')
        evil.type, evil.linkname = tarfile.SYMTYPE, '../../../../etc'
        dst.addfile(evil)
    files[volume] = hostile
    entries = []
    for entry in inner['entries']:
        data = open(files[entry['path']], 'rb').read()
        entries.append(warchive.Entry(entry['path'], files[entry['path']], len(data), hashlib.sha256(data).hexdigest()))
    now = time.gmtime()
    new_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
    head = {key: inner[key] for key in warchive.HEAD_FIELDS}
    head.update(backup_id=new_id, created=time.strftime('%Y-%m-%dT%H:%M:%SZ', now), note='F13 hostile volume')
    out_path = os.path.join(work, 'f13.tar')
    with warchive.ArchiveWriter(out_path, head, [app], recipient, tmp_dir=work) as writer:
        writer.add_app(app, entries)
        writer.finish()
    print(json.dumps({'backup_id': new_id, 'path': out_path, 'volume': volume}))
finally:
    for name in os.listdir(work):
        if name != 'f13.tar':
            os.unlink(os.path.join(work, name))
'''


def scenario_deep(ev):
    """F13: a backup whose volume tar a restore would refuse (re-encrypted to the device key, valid checksums) fails the
    verify job; the old shallow verify would have called it verified."""
    job, _log = backup('a', ev, 'backup[f13-base]')
    ev.require('F13 base backup', job['state'] == 'succeeded')
    work = '/var/tmp/woowbk-f13'
    sh('a', f'rm -rf {work}')
    try:
        crafted = json.loads(py('a', CRAFT_F13, job['result']['backup_id'], work, timeout=900).stdout)
        local = private_dir(WORK) / 'f13.tar'
        write_private_stream('a', crafted['path'], local)
    finally:
        sh('a', f'rm -rf {work}', check=False)
    _begin, (_rc, reply) = upload_file('a', local, ev=ev, filename='woowtech-backup-f13.tar')
    local.unlink(missing_ok=True)
    ev.require('F13 the crafted file uploads (its outer structure and checksums are valid)', reply.get('ok'),
               reply.get('error'))
    remember('a', crafted['backup_id'])
    ok('a', 'inspect', {'backup_id': crafted['backup_id']}, ev=ev)
    job, log = run_job('a', ev, 'verify-start', {'backup_id': crafted['backup_id']}, 'verify[f13]')
    error = job.get('error') or {}
    ev.check('F13 the deep verify job fails with corrupt-archive naming the volume check',
             job['state'] == 'failed' and error.get('code') == 'corrupt-archive' and '資料卷' in error.get('message', ''),
             error)
    meta = meta_of('a', ev, crafted['backup_id'])
    ev.check('F13 index: verified {ok: false, deep: true}', meta['verified'] and meta['verified']['ok'] is False
             and meta['verified'].get('deep') is True, meta['verified'])
    before = summary('a')
    job, _log = restore('a', ev, crafted['backup_id'], 'restore[f13]')
    ev.check('F13 a restore refuses it before any change', job['state'] == 'failed'
             and (job.get('result') or {}).get('changed') is False, job.get('error'))
    ev.check('F13 app data unchanged', compare(summary('a'), before) == {})
    return {'backup_id': crafted['backup_id']}


DAMAGE = r'''
import sys, tarfile
path, member = sys.argv[1:3]
with tarfile.open(path) as tar:
    info = tar.getmember(member)
    offset = info.offset_data + info.size // 2
with open(path, 'r+b') as handle:
    handle.seek(offset)
    byte = handle.read(1)
    handle.seek(offset)
    handle.write(bytes([byte[0] ^ 0xFF]))
print(offset)
'''


def scenario_partial(ev):
    """F14: restoring one app of a two-app backup whose other application archive is damaged reads only that app."""
    apps = {a['id']: a for a in ok('a', 'status', ev=ev)['apps']}
    if apps.get(DIRS_APP, {}).get('state') != 'running':
        ev.log('woowbk-dirs is not running on dev-a: F14 skipped')
        return {'skipped': True}
    snap = summary('a')
    job, _log = backup('a', ev, 'backup[f14]', apps=(APP, DIRS_APP))
    ev.require('F14 two-app backup', job['state'] == 'succeeded', job.get('error'))
    backup_id = job['result']['backup_id']
    meta = meta_of('a', ev, backup_id)
    ev.check('F14 index lists both app archive sizes', all(a.get('size') for a in meta['apps']), meta['apps'])
    offset = py('a', DAMAGE, f'{ARCHIVES}/{backup_id}.tar', f'apps/{DIRS_APP}.tar.zst.age').stdout.decode().strip()
    ev.log(f'F14 flipped one byte of apps/{DIRS_APP}.tar.zst.age at offset {offset}')
    mutate('a', 'F14')
    job, log = restore('a', ev, backup_id, 'restore[f14-demo]', apps=(APP,))
    ev.check('F14 restoring woowbk-demo alone succeeds', job['state'] == 'succeeded', job.get('error'))
    ev.check('F14 woowbk-demo data equals the backup', compare(summary('a'), snap) == {})
    job, _log = run_job('a', ev, 'verify-start', {'backup_id': backup_id}, 'verify[f14]')
    ev.check('F14 the verify job finds the damage in the other app', job['state'] == 'failed'
             and (job.get('error') or {}).get('code') == 'corrupt-archive', job.get('error'))
    job, _log = restore('a', ev, backup_id, 'restore[f14-dirs]', apps=(DIRS_APP,))
    ev.check('F14 restoring the damaged app fails before any change', job['state'] == 'failed'
             and (job.get('result') or {}).get('changed') is False, job.get('error'))
    ev.check('F14 woowbk-dirs still running', next(a for a in ok('a', 'status', ev=ev)['apps']
                                                    if a['id'] == DIRS_APP)['state'] == 'running')
    return {'backup_id': backup_id}


def scenario_cleanup(ev):
    """Delete the backups the scenarios created (and any export copy); restore the setting."""
    state = load_state()
    for dev, backup_id in state.get('created', []):
        rc, reply = helper(dev, 'delete', {'backup_id': backup_id}, ev=ev)
        ev.check(f'cleanup: dev-{dev} {backup_id} deleted or already gone',
                 rc == 0 or reply['error']['code'] == 'not-found', reply.get('error'))
    for dev in ('a', 'b'):
        for item in ok(dev, 'list', ev=ev).get('exports', []):
            ok(dev, 'export-delete', {'export_id': item['export_id']}, ev=ev)
        settings = ok(dev, 'status', ev=ev)['settings']
        if not settings['encrypt_by_default']:
            ok(dev, 'settings-set', {'encrypt_by_default': True}, ev=ev)
        ev.check(f'cleanup: dev-{dev} no active job, staging empty', ok(dev, 'status', ev=ev)['active_job'] is None
                 and sh(dev, 'ls -A /var/lib/woowtech-backup/staging').stdout.strip() == b'')
    shutil.rmtree(WORK, ignore_errors=True)
    for path in DOWNLOADS.glob('format-*'):
        path.unlink(missing_ok=True)
    STATE.unlink(missing_ok=True)
    return {'deleted': len(state.get('created', []))}


SCENARIOS = {'v1': scenario_v1, 'encrypted': scenario_encrypted, 'plain': scenario_plain, 'export': scenario_export,
             'deep': scenario_deep, 'partial': scenario_partial, 'cleanup': scenario_cleanup}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', choices=[*SCENARIOS, 'all'])
    args = parser.parse_args()
    names = list(SCENARIOS) if args.scenario == 'all' else [args.scenario]
    all_ok = True
    for name in names:
        ev = Evidence(name)
        try:
            extra = SCENARIOS[name](ev) or {}
        except Failed as error:
            ev.log(f'ABORTED: {error}')
            extra = {'aborted': str(error)}
        except Exception as error:  # noqa: BLE001 - record and continue to the summary
            ev.log(f'ABORTED with {type(error).__name__}: {e2e.redact(str(error))}')
            extra = {'aborted': f'{type(error).__name__}: {e2e.redact(str(error))}'}
        all_ok = ev.finish(extra) and 'aborted' not in extra and all_ok
    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
