#!/usr/bin/env python3
"""Lab scenarios of the backup-strengthen phase (integrator): built-in data digests, downtime, PostgreSQL instance
mode, deep verify, catalog drafts, retention, the encryption choice and format 2 edge cases.

Every engine call is made the way the Cockpit page makes it (cli_e2e.py: the installed helper as root, request JSON
on stdin, one JSON object back; downloads and uploads through the device's real cockpit-bridge). The page itself is
driven by strengthen_ui.mjs.

    python3 -I tests/e2e/lab/strengthen_e2e.py catalog-apply  # catalog-suggest -> catalog-install (preview, confirm)
                                                               # of woowbk-demo and woowbk-dirs on dev-a and dev-b
    python3 -I tests/e2e/lab/strengthen_e2e.py digests        # postgres-digest + files-digest, in place (dev-a) and
                                                               # cross-device fresh (dev-b), single and cold database
    python3 -I tests/e2e/lab/strengthen_e2e.py mismatch       # a re-sealed archive whose file content differs: the
                                                               # restore compares, refuses before the app starts and
                                                               # rolls back; a database written during the backup
                                                               # keeps no digest; that rollback chain completes
    python3 -I tests/e2e/lab/strengthen_e2e.py instance       # instance mode: Odoo-like (two databases, owner role)
                                                               # and Nextcloud-like (pgvector, oc_admin used by the
                                                               # app) in one cluster, in place and cross-device
    python3 -I tests/e2e/lab/strengthen_e2e.py deep           # deep verify rejects tampered inner tars (volume, host
                                                               # directory, digest listing, dump); inspect stays fast
    python3 -I tests/e2e/lab/strengthen_e2e.py retention      # keep-last-N: plan, apply, a manual backup's policy
    python3 -I tests/e2e/lab/strengthen_e2e.py keyless        # dev-b without a device key: unencrypted backups and
                                                               # safety backups by the setting, encrypted ones refused
    python3 -I tests/e2e/lab/strengthen_e2e.py tampered-json  # format 2 backup.json changed outside the device
    python3 -I tests/e2e/lab/strengthen_e2e.py e4             # downtime of whatever engine is installed (E4_LABEL)
    python3 -I tests/e2e/lab/strengthen_e2e.py e4-cleanup
    python3 -I tests/e2e/lab/strengthen_e2e.py cleanup        # backups this driver made, lab app woowbk-inst, setting

Prerequisites: both devices deployed with the working tree (deploy-src.sh a|b), woowbk-demo and woowbk-dirs running
on dev-a (dirs_e2e.py prep), dev-a's device key and the throwaway emergency kit ~/.woowbk-lab/secrets/dev-a-kit.txt
(cli_e2e.py s1). Evidence: ~/.woowbk-lab/evidence/strengthen/<time>-<scenario>/ (driver.log, result.json, job
records). Key material never leaves the devices except the kit secret, which only travels in the stdin field `key`;
hostile archives are built inside dev-a with its own device key (only ciphertext reaches the host). Only labpodman
is used; nested containers this driver starts always carry --memory.
"""
import argparse
import calendar
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cli_e2e as e2e  # noqa: E402
from cli_e2e import (DOWNLOADS, LAB, Failed, app_json, app_post, bridge_download, helper, kit_secret, ok,  # noqa: E402
                     owner, request_id, sh, upload_file, wait_healthy, wait_job)

e2e.EVIDENCE = LAB / 'evidence' / 'strengthen'
EVIDENCE = e2e.EVIDENCE
STATE = EVIDENCE / 'state.json'
WORK = LAB / 'run' / 'strengthen'
REPO = Path(__file__).resolve().parents[3]
DEMO, DIRS = 'woowbk-demo', 'woowbk-dirs'
CATALOG_DIR = '/etc/woowtech-cockpit/backup/apps'
ARCHIVES = '/var/lib/woowtech-backup/archives'
DEMO_COMPARE = ('notes', 'files', 'digest', 'title', 'signatures_valid')
MIN_AVAILABLE_MB = 1200


class Evidence(e2e.Evidence):
    """cli_e2e's evidence directory, under evidence/strengthen/."""


def load_state():
    try:
        return json.loads(STATE.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def save_state(**fields):
    state = load_state()
    state.update(fields)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(e2e.redact(state), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')


def remember(dev, backup_id):
    """Backups this driver made (deleted by `cleanup`)."""
    if backup_id:
        created = load_state().get('created', [])
        if [dev, backup_id] not in created:
            created.append([dev, backup_id])
        save_state(created=created)


def memory_ok():
    with open('/proc/meminfo', encoding='ascii') as handle:
        for line in handle:
            if line.startswith('MemAvailable:'):
                available = int(line.split()[1]) // 1024
                break
    if available < MIN_AVAILABLE_MB:
        raise Failed(f'host MemAvailable {available} MB < {MIN_AVAILABLE_MB} MB: not starting more containers')
    return available


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def run_job(dev, ev, command, request, label, timeout=1800):
    started = ok(dev, command, {**request, 'request_id': request_id()}, ev=ev)
    job, log = wait_job(dev, started['job_id'], ev=ev, label=label, timeout=timeout)
    ev.save(label.replace('[', '-').replace(']', ''), {'job': job, 'log': log})
    return job, log


def backup(dev, ev, label, apps=(DEMO,), **extra):
    job, log = run_job(dev, ev, 'backup-start', {'apps': list(apps), 'include_images': False, 'note': label, **extra},
                       label)
    if job['state'] == 'succeeded':
        remember(dev, job['result']['backup_id'])
    return job, log


def restore(dev, ev, backup_id, label, apps=(DEMO,), **extra):
    job, log = run_job(dev, ev, 'restore-start', {'backup_id': backup_id, 'apps': list(apps), 'confirm': True, **extra},
                       label, timeout=2400)
    remember(dev, (job.get('result') or {}).get('safety_backup_id'))
    return job, log


def lines(log, *needles):
    return [line for line in log if any(n in line for n in needles)]


def checks_of(job, app):
    """{check id: DigestCheck} of an app in a restore result."""
    entry = next((v for v in (job.get('result') or {}).get('verification') or [] if v.get('app') == app), {})
    return {c['id']: c for c in entry.get('checks') or []}, entry


def demo_summary(dev):
    return {k: v for k, v in app_json(dev, '/api/summary').items() if k in DEMO_COMPARE}


def catalog_entry(dev, app_id):
    proc = sh(dev, f'cat {CATALOG_DIR}/{app_id}.json', check=False)
    return json.loads(proc.stdout) if proc.returncode == 0 else None


def write_catalog(dev, app_id, entry):
    """Root writes a trusted entry directly (lab-only shortcut used for measurement variants; the product path is
    catalog-install)."""
    data = json.dumps(entry, ensure_ascii=False, indent=1).encode('utf-8') + b'\n'
    path = f'{CATALOG_DIR}/{app_id}.json'
    sh(dev, f'cat > {path}.tmp && chown root:root {path}.tmp && chmod 0644 {path}.tmp && mv {path}.tmp {path}',
       input=data)


def download(dev, ev, backup_id, label):
    info = ok(dev, 'download-info', {'backup_id': backup_id}, ev=ev)
    local = private_dir(DOWNLOADS) / f'strengthen-{label}-{info["filename"]}'
    got = bridge_download(dev, info['path'], local, ev=ev)
    ev.check(f'{label}: download through the bridge has the indexed size', got['bytes'] == info['size'],
             {'bytes': got['bytes'], 'size': info['size']})
    return local, info


def upload(dev, ev, local, filename):
    _begin, (_rc, reply) = upload_file(dev, local, ev=ev, filename=filename)
    return reply


# ------------------------------------------------------------------ scenarios: filled in below
SCENARIOS = {}


def scenario(name):
    def register(func):
        SCENARIOS[name] = func
        return func
    return register


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('scenario', nargs='+')
    args = parser.parse_args()
    names = []
    for name in args.scenario:
        if name == 'all':
            names += [n for n in ALL if n not in names]
        elif name in SCENARIOS:
            names.append(name)
        else:
            parser.error(f'unknown scenario {name} (one of {", ".join(SCENARIOS)}, all)')
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


# ------------------------------------------------------------------ E4: downtime before/after (slow writer units)

SLOW_QUADLET = """[Unit]
Description=lab writer that takes 15 s to stop (like n8n's task runners)
{after}[Container]
ContainerName={name}
Image=docker.io/library/postgres:16-alpine
Exec=sleep infinity
PodmanArgs=--memory 16m --stop-timeout 15
[Service]
Restart=no
[Install]
WantedBy=default.target
"""
SLOW = ('woowbk-slow1', 'woowbk-slow2')
BIG = 'woowbk-dirs/big'


def e4_prepare(ev, dev):
    import dirs_e2e
    # E4_AFTER=1: the helpers declare `After=` the app, like production's n8n-runners (`After=n8n.service`): systemd
    # then stops them before the app and starts them after it. Without it they declare nothing.
    after = 'After=woowbk-dirs-app.service\n' if os.environ.get('E4_AFTER') == '1' else ''
    for name in SLOW:
        owner(dev, 'sh', '-c', f'cat > "$HOME/.config/containers/systemd/{name}.container"',
              input=SLOW_QUADLET.format(name=name, after=after).encode())
    owner(dev, 'systemctl', '--user', 'daemon-reload')
    owner(dev, 'systemctl', '--user', 'start', *[f'{n}.service' for n in SLOW], timeout=600)
    owner(dev, 'sh', '-c', f'mkdir -p "$HOME/{BIG}" && cd "$HOME/{BIG}" && for i in $(seq 1 30); do '
                           f'[ -s f$i ] || head -c 10485760 /dev/urandom > f$i; done', timeout=600)
    state = load_state()
    if 'e4_catalog' not in state:
        save_state(e4_catalog=catalog_entry(dev, DIRS))
    base = load_state()['e4_catalog']
    entry = json.loads(json.dumps(base))
    # The same entry for both engines: the measurement compares stops and starts, not digests (an engine before
    # 2026-11-13 refuses digest checks).
    entry['verify'] = [item for item in entry['verify'] if item.get('type', 'http-json') == 'http-json']
    entry['quadlet']['files'] += [f'{n}.container' for n in SLOW]
    entry['units'] += [f'{n}.service' for n in SLOW]
    entry['writer_units'] += [f'{n}.service' for n in SLOW]
    entry['data_dirs'].append({'path': BIG, 'label': '大量資料（實驗室量測）'})
    write_catalog(dev, DIRS, entry)
    status = ok(dev, 'status', ev=ev)
    app = next(a for a in status['apps'] if a['id'] == DIRS)
    ev.log(f'E4 prepared: woowbk-dirs {app["state"]} units {[u["name"] for u in app["units"]]} '
           f'warnings {status["warnings"]}')
    return app, dirs_e2e


def windows(samples):
    """[(start, end)] of unhealthy runs, from a HealthMonitor's samples."""
    runs, start, last = [], None, None
    for t, status in samples:
        if status != 200 and start is None:
            start = t
        elif status == 200 and start is not None:
            runs.append((start, t))
            start = None
        last = t
    if start is not None:
        runs.append((start, last))
    return runs


@scenario('e4')
def scenario_e4(ev):
    """Before/after: the same app, data and device with whichever engine is installed (`E4_LABEL`)."""
    dev = 'a'
    label = os.environ.get('E4_LABEL', 'engine') + ('-after' if os.environ.get('E4_AFTER') == '1' else '')
    memory_ok()
    app, dirs_e2e = e4_prepare(ev, dev)
    ev.require('E4 woowbk-dirs (with the slow writers and the large directory) running', app['state'] == 'running', app)
    ev.require('E4 app healthy', dirs_e2e.wait_healthy(dev, 120))
    version = ok(dev, 'status', ev=ev)['version']
    monitor = dirs_e2e.HealthMonitor(dev, 1800)
    try:
        start = ok(dev, 'backup-start', {'apps': [DIRS], 'include_images': False, 'note': f'E4 {label}',
                                         'request_id': request_id()}, ev=ev)
        t0 = time.monotonic()
        job, log = wait_job(dev, start['job_id'], ev=ev, label=f'backup[e4-{label}]')
        backup_wall = time.monotonic() - t0
        ev.save(f'e4-{label}-backup', {'job': job, 'log': log})
        ev.require('E4 backup succeeded', job['state'] == 'succeeded', job.get('error'))
        time.sleep(3)
        mark = time.time()
        start = ok(dev, 'restore-start', {'backup_id': job['result']['backup_id'], 'apps': [DIRS],
                                          'request_id': request_id(), 'confirm': True}, ev=ev)
        t0 = time.monotonic()
        rjob, rlog = wait_job(dev, start['job_id'], ev=ev, label=f'restore[e4-{label}]')
        restore_wall = time.monotonic() - t0
        ev.save(f'e4-{label}-restore', {'job': rjob, 'log': rlog})
        ev.require('E4 restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
        dirs_e2e.wait_healthy(dev, 240)
        time.sleep(2)
    finally:
        monitor.stop()
    restore_runs = [(a, b) for a, b in windows(monitor.samples) if b >= mark]
    backup_runs = [(a, b) for a, b in windows(monitor.samples) if b < mark]

    def stopped_window(log_lines):
        """[first stop, last stop-to-health line] of a job log (UTC ISO prefixes) as epoch seconds."""
        stamps = [(line[:20], line) for line in log_lines if re.match(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ ', line)]
        first = next((t for t, line in stamps if '暫停寫入服務' in line or '停止服務' in line), None)
        last = next((t for t, line in reversed(stamps) if '已恢復服務' in line or '啟動服務' in line), None)
        to_epoch = lambda t: calendar.timegm(time.strptime(t, '%Y-%m-%dT%H:%M:%SZ'))  # noqa: E731
        return (to_epoch(first), to_epoch(last)) if first and last else None

    def split(runs, window):
        """Unhealthy seconds inside the stop window (+5 s for the health check) and outside it (load while running)."""
        if window is None:
            return None
        lo, hi = window[0] - 1, window[1] + 5
        inside = sum(max(0.0, min(b, hi) - max(a, lo)) for a, b in runs)
        return {'inside_stop_window_s': round(inside, 1),
                'outside_stop_window_s': round(sum(b - a for a, b in runs) - inside, 1)}

    result = {
        'engine': version, 'label': label,
        'backup_wall_s': round(backup_wall, 1), 'backup_downtime_seconds': job['result'].get('downtime_seconds'),
        'backup_timing': job['result'].get('timing'),
        'backup_healthz_unhealthy_s': round(sum(b - a for a, b in backup_runs), 1),
        'restore_wall_s': round(restore_wall, 1), 'restore_timing': rjob['result'].get('timing'),
        'restore_healthz_outages': len(restore_runs),
        'restore_healthz_unhealthy_s': round(sum(b - a for a, b in restore_runs), 1),
        'restore_healthz_span_s': round(restore_runs[-1][1] - restore_runs[0][0], 1) if restore_runs else 0,
        'backup_healthz_split': split(backup_runs, stopped_window(log)),
        'restore_healthz_split': split(restore_runs, stopped_window(rlog)),
        'backup_windows': [[round(a, 2), round(b, 2)] for a, b in backup_runs],
        'restore_windows': [[round(a, 2), round(b, 2)] for a, b in restore_runs],
        'stop_lines': [line for line in log + rlog if any(k in line for k in ('暫停寫入服務', '停止服務', '已恢復服務',
                                                                               '啟動服務', '寫入主機資料夾', '階段'))],
    }
    ev.timings.update({f'e4_{label}_{k}': v for k, v in result.items() if isinstance(v, (int, float))})
    ev.save(f'e4-{label}-measure', result)
    ev.log(f'E4 {label} ({version}): ' + json.dumps({k: v for k, v in result.items()
                                                      if k not in ('stop_lines', 'backup_windows', 'restore_windows')},
                                                     ensure_ascii=False))
    for backup_id in (job['result']['backup_id'], rjob['result'].get('safety_backup_id')):
        if backup_id:
            helper(dev, 'delete', {'backup_id': backup_id}, ev=ev)
    return {'measure': {k: v for k, v in result.items() if k != 'stop_lines'}}


@scenario('e4-cleanup')
def scenario_e4_cleanup(ev):
    dev = 'a'
    state = load_state()
    base = state.get('e4_catalog')
    if base:
        write_catalog(dev, DIRS, base)
    owner(dev, 'systemctl', '--user', 'stop', *[f'{n}.service' for n in SLOW], check=False, timeout=600)
    owner(dev, 'sh', '-c', 'rm -f ' + ' '.join(f'"$HOME/.config/containers/systemd/{n}.container"' for n in SLOW)
          + f' && systemctl --user daemon-reload && rm -rf "$HOME/{BIG}"')
    left = owner(dev, 'sh', '-c', f'ls -d "$HOME/{BIG}"* 2>/dev/null; podman ps -a --format "{{{{.Names}}}}"').stdout
    ev.check('E4 cleanup: the woowbk-dirs entry from before E4, slow units and the large directory removed',
             b'woowbk-slow' not in left and b'big' not in left and catalog_entry(dev, DIRS) == base, left)
    state.pop('e4_catalog', None)
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')



# ------------------------------------------------------------------ catalog drafts (catalog-suggest -> catalog-install)

OWNER = 'appowner'


def suggestion(dev, ev, app_id):
    reply = ok(dev, 'catalog-suggest', {'owner': OWNER}, ev=ev, timeout=300)
    return reply, next((draft for draft in reply['apps'] if draft['id'] == app_id), None)


def install_entry(dev, ev, entry, label):
    """catalog-install as the page does it: preview (the loader's validation, diff), then confirm with the previewed
    digest. Returns (preview, confirmed reply or None when the file already equals the entry)."""
    preview = ok(dev, 'catalog-install', {'entry': entry}, ev=ev)
    ev.require(f'{label}: catalog-install preview is valid', preview['valid'], preview.get('error'))
    if preview['current'] and preview['expected_sha256'] == preview['new_sha256']:
        return preview, None
    done = ok(dev, 'catalog-install', {'entry': entry, 'confirm': True, 'expected_sha256': preview['expected_sha256']},
              ev=ev)
    return preview, done


@scenario('catalog-apply')
def scenario_catalog_apply(ev):
    """The drafts of the two demo apps (installed entries + the built-in digest checks the generator appends) are
    installed through catalog-install on both devices; both devices end with the same entries."""
    installed = {}
    for dev in ('a', 'b'):
        owners = ok(dev, 'catalog-suggest', {}, ev=ev)['owners']
        ev.check(f'dev-{dev}: catalog-suggest {{}} lists appowner (never root)',
                 any(o['name'] == OWNER for o in owners) and not any(o['name'] == 'root' for o in owners), owners)
        for app_id in (DEMO, DIRS):
            reply, draft = suggestion(dev, ev, app_id)
            ev.save(f'suggest-{dev}-{app_id}', draft)
            ev.require(f'dev-{dev} {app_id}: a valid draft for the installed app', draft and draft['valid']
                       and draft['installed'], draft and {k: draft[k] for k in ('valid', 'problem', 'variant')})
            before = catalog_entry(dev, app_id)
            added = [c['path'] for c in draft['installed']['changes']]
            if draft['installed']['same']:
                ev.check(f'dev-{dev} {app_id}: installed entry already equals the draft', True)
            else:
                ev.check(f'dev-{dev} {app_id}: the draft only adds built-in digest checks to the installed entry',
                         added and all(path.startswith('verify[id=') for path in added)
                         and not draft['installed']['drift'], {'changes': added, 'drift': draft['installed']['drift']})
            preview, done = install_entry(dev, ev, draft['entry'], f'dev-{dev} {app_id}')
            if done:
                ev.check(f'dev-{dev} {app_id}: installed (previous entry kept in apps-history)',
                         done['installed'] and (before is None or done['previous']), done)
            after = catalog_entry(dev, app_id)
            types = sorted(item.get('type', 'http-json') for item in after['verify'])
            ev.check(f'dev-{dev} {app_id}: the trusted entry now has http-json + postgres-digest + files-digest',
                     types == ['files-digest', 'http-json', 'postgres-digest'], types)
            mode = sh(dev, f'stat -c "%U %a" {CATALOG_DIR}/{app_id}.json').stdout.decode().strip()
            ev.check(f'dev-{dev} {app_id}: entry file root 0644', mode == 'root 644', mode)
            installed[(dev, app_id)] = after
        status = ok(dev, 'status', ev=ev)
        ev.check(f'dev-{dev}: both apps load (no catalog warnings)', not status['warnings']
                 and {DEMO, DIRS} <= {a['id'] for a in status['apps']}, status['warnings'])
    for app_id in (DEMO, DIRS):
        ev.check(f'{app_id}: dev-a and dev-b hold the same entry', installed[('a', app_id)] == installed[('b', app_id)])
    journal = sh('a', 'journalctl -t woowtech-cockpit-backup --since "-30 min" --no-pager -o cat | '
                      'grep -c "^catalog-install " || true').stdout.decode().strip()
    ev.log(f'dev-a journal catalog-install lines (30 min): {journal}')
    return {'verify': {app_id: installed[('a', app_id)]['verify'] for app_id in (DEMO, DIRS)}}


def ensure_digest_entries(ev):
    """The digest proofs need the generated checks on both devices (deploy-src resets woowbk-demo's entry)."""
    for dev in ('a', 'b'):
        for app_id in (DEMO, DIRS):
            entry = catalog_entry(dev, app_id) or {}
            if not any(item.get('type') == 'postgres-digest' for item in entry.get('verify', [])):
                _reply, draft = suggestion(dev, ev, app_id)
                if not draft or not draft['valid']:
                    raise Failed(f'no valid draft for {app_id} on dev-{dev}')
                install_entry(dev, ev, draft['entry'], f'dev-{dev} {app_id} (digest checks)')
                ev.log(f'dev-{dev} {app_id}: installed the generated digest checks')


# ------------------------------------------------------------------ digests: exact comparisons, in place and fresh

TEARDOWN_DEMO_KEEP_IMAGE = e2e.TEARDOWN.replace('podman rmi -f localhost/woowbk-demo-app:1 >/dev/null 2>&1\n', '')


def digest_report(ev, label, job, app):
    checks, entry = checks_of(job, app)
    ev.save(f'{label}-checks', {'entry': entry})
    pg = next((c for c in checks.values() if c['type'] == 'postgres-digest'), {})
    files = next((c for c in checks.values() if c['type'] == 'files-digest'), {})
    ev.check(f'{label}: postgres-digest matches exactly ({pg.get("after")})',
             pg.get('match') is True and pg.get('before') and pg.get('before') == pg.get('after')
             and not pg.get('differences'), pg)
    ev.check(f'{label}: files-digest matches exactly ({files.get("after")})',
             files.get('match') is True and files.get('before') and files.get('before') == files.get('after')
             and not files.get('differences'), files)
    ev.check(f'{label}: http-json data check also matches', entry.get('match') is True, entry.get('match'))
    return pg, files


def started_before(log, digest_needle, unit):
    """True when every digest line of the restore came before the first start of `unit` (the app)."""
    first_app = next((i for i, line in enumerate(log) if f'啟動服務 {unit}' in line), None)
    digests = [i for i, line in enumerate(log) if digest_needle in line]
    return first_app is not None and digests and max(digests) < first_app, {'first_app_start': first_app,
                                                                            'digest_lines': digests[-3:]}


@scenario('digests')
def scenario_digests(ev):
    """postgres-digest and files-digest, captured while the writers are stopped and compared before the app starts:
    woowbk-demo (single database) and woowbk-dirs (cold database in a host directory), in place on dev-a and
    fresh on dev-b (other uid and subordinate ids)."""
    memory_ok()
    ensure_digest_entries(ev)
    secret = kit_secret()
    results = {}
    # ---- woowbk-demo in place (dev-a)
    ev.require('dev-a woowbk-demo healthy', wait_healthy('a', 180))
    app_post('a', '/api/notes', json.dumps({'title': 'digests 備份前', 'body': '資料摘要'}).encode(), 'application/json')
    snap = demo_summary('a')
    job, log = backup('a', ev, 'backup[demo]')
    ev.require('woowbk-demo backup succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.check('woowbk-demo backup log: both digests computed while the writers were stopped',
             len(lines(log, '已計算資料摘要')) == 2, lines(log, '已計算資料摘要', '暫停寫入服務', '已恢復服務'))
    demo_id = job['result']['backup_id']
    inspect = ok('a', 'inspect', {'backup_id': demo_id}, ev=ev)
    ev.save('demo-inspect', inspect)
    digests = {d['type']: d for d in inspect['manifest']['apps'][0]['verify_digests']}
    ev.check('inspect lists postgres:main and volume:woowbk-demo-files with their summaries',
             digests.get('postgres-digest', {}).get('target') == 'postgres:main'
             and digests.get('files-digest', {}).get('target') == 'volume:woowbk-demo-files'
             and all(d['summary'] for d in digests.values()), digests)
    checks = {c['id'].split('/', 1)[1]: c for a in inspect['preflight']['apps'] for c in a['checks']}
    ev.check('preflight: the restore compares the digests', checks.get('digests', {}).get('status') == 'ok',
             checks.get('digests'))
    app_post('a', '/api/notes', json.dumps({'title': 'digests 備份後', 'body': '還原後應消失'}).encode(),
             'application/json')
    app_post('a', '/api/files?name=digests-after.bin', secrets.token_bytes(4096), 'application/octet-stream')
    ev.check('woowbk-demo data changed after the backup', demo_summary('a') != snap)
    rjob, rlog = restore('a', ev, demo_id, 'restore[demo-inplace]')
    ev.require('woowbk-demo in-place restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
    results['demo_inplace'] = digest_report(ev, 'demo in place', rjob, DEMO)
    ok_order, order = started_before(rlog, '資料摘要', 'woowbk-demo-app.service')
    ev.check('demo in place: every digest comparison came before the app unit started', ok_order, order)
    ev.check('demo in place: data equals the backup (http-json summary)', demo_summary('a') == snap)
    ev.timings['demo_inplace_restore'] = (rjob['result'].get('timing') or [{}])[0]
    # ---- woowbk-demo cross-device, fresh on dev-b
    local, info = download('a', ev, demo_id, 'demo')
    owner('b', 'sh', '-c', TEARDOWN_DEMO_KEEP_IMAGE, timeout=600)
    app_b = next(a for a in ok('b', 'status', ev=ev)['apps'] if a['id'] == DEMO)
    ev.require('dev-b: woowbk-demo not deployed (fresh target, app image kept)', app_b['state'] == 'not-deployed', app_b)
    reply = upload('b', ev, local, info['filename'])
    local.unlink(missing_ok=True)
    ev.require('dev-b: upload of the dev-a backup accepted', reply.get('ok'), reply.get('error'))
    remember('b', demo_id)
    inspect_b = ok('b', 'inspect', {'backup_id': demo_id, 'key': secret}, ev=ev)
    pf = inspect_b['preflight']['apps'][0]
    ev.check('dev-b preflight: fresh, restorable, digests compared', pf['mode'] == 'fresh' and pf['restorable']
             and any(c['id'].endswith('/digests') and c['status'] == 'ok' for c in pf['checks']), pf)
    rjob, rlog = restore('b', ev, demo_id, 'restore[demo-fresh-b]', key=secret)
    ev.require('dev-b fresh restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
    results['demo_fresh_b'] = digest_report(ev, 'demo fresh on dev-b', rjob, DEMO)
    ev.check('demo fresh on dev-b: data equals the dev-a backup', wait_healthy('b', 180) and demo_summary('b') == snap)
    # ---- woowbk-dirs in place (dev-a)
    import dirs_e2e
    ev.require('dev-a woowbk-dirs healthy', dirs_e2e.wait_healthy('a', 240))
    dirs_e2e.post_item('a', 'digests-before', '資料摘要')
    dsnap = dirs_e2e.summary('a')
    job, log = backup('a', ev, 'backup[dirs]', apps=(DIRS,))
    ev.require('woowbk-dirs backup succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.check('woowbk-dirs backup log: the cold database digest was read between the two stops, then the files digest',
             len(lines(log, '已計算資料摘要')) == 2, lines(log, '已計算資料摘要', '暫停寫入服務', '停止資料庫'))
    dirs_id = job['result']['backup_id']
    dirs_e2e.post_item('a', 'digests-after', '還原後應消失')
    dirs_e2e.psql('a', 'CREATE TABLE IF NOT EXISTS digests_extra(x int); INSERT INTO digests_extra VALUES (1);')
    rjob, rlog = restore('a', ev, dirs_id, 'restore[dirs-inplace]', apps=(DIRS,))
    ev.require('woowbk-dirs in-place restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
    results['dirs_inplace'] = digest_report(ev, 'dirs in place', rjob, DIRS)
    ok_order, order = started_before(rlog, '資料摘要', 'woowbk-dirs-app.service')
    ev.check('dirs in place: every digest comparison came before the app unit started', ok_order, order)
    ev.check('dirs in place: data equals the backup', dirs_e2e.wait_healthy('a', 240)
             and dirs_e2e.compare(dirs_e2e.summary('a'), dsnap) == {})
    # ---- woowbk-dirs cross-device, fresh on dev-b
    local, info = download('a', ev, dirs_id, 'dirs')
    out = subprocess.run([str(Path(__file__).resolve().parent / 'teardown-dirs.sh'), 'b', '--keep-image'],
                         capture_output=True, timeout=900)
    ev.check('dev-b: woowbk-dirs torn down (image kept)', out.returncode == 0, out.stderr.decode()[-300:])
    reply = upload('b', ev, local, info['filename'])
    local.unlink(missing_ok=True)
    ev.require('dev-b: upload of the woowbk-dirs backup accepted', reply.get('ok'), reply.get('error'))
    remember('b', dirs_id)
    rjob, rlog = restore('b', ev, dirs_id, 'restore[dirs-fresh-b]', apps=(DIRS,), key=secret)
    ev.require('dev-b woowbk-dirs fresh restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
    results['dirs_fresh_b'] = digest_report(ev, 'dirs fresh on dev-b', rjob, DIRS)
    ev.check('dirs fresh on dev-b: data equals the dev-a backup', dirs_e2e.wait_healthy('b', 240)
             and dirs_e2e.compare(dirs_e2e.summary('b'), dsnap) == {})
    return {'summaries': {name: {'postgres': pg.get('after'), 'files': files.get('after')}
                          for name, (pg, files) in results.items()}}


# ------------------------------------------------------------------ hostile and corrupted archives, re-sealed in dev-a

CRAFT = r"""
import glob, hashlib, io, json, os, secrets, subprocess, sys, tarfile, time
sys.path.insert(0, '/usr/local/lib/woowtech-cockpit-backup')
sys.dont_write_bytecode = True
from woowbackup import archive as warchive
base_id, work, case = sys.argv[1:4]
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
keyfile = sorted(glob.glob('/etc/woowtech-cockpit/backup/keys/device-*.key'))[0]
recipient = subprocess.run(['age-keygen', '-y', keyfile], capture_output=True, env=ENV, check=True).stdout.decode().split()[0]
os.mkdir(work, 0o700)
out_name = case + '.tar'
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
    files = {}
    for index, member in enumerate(members[1:]):
        path = os.path.join(work, 'm%d' % index)
        with open(path, 'wb') as out:
            out.write(inner_tar.extractfile(member).read())
        files[member.name] = path
    detail = {}

    def rewrite(entry, change):
        src_path, dst_path = files[entry], files[entry] + '.new'
        with tarfile.open(src_path) as src, tarfile.open(dst_path, 'w', format=tarfile.PAX_FORMAT) as dst:
            change(src, dst)
        files[entry] = dst_path

    if case == 'flip-file':
        entry = app['volumes'][0]['entry']
        def change(src, dst):
            done = False
            for member in src.getmembers():
                data = src.extractfile(member).read() if member.isreg() else None
                if not done and member.isreg() and member.size > 16 and '/files/' in '/' + member.name:
                    data = bytearray(data)
                    data[member.size // 2] ^= 0x01
                    data = bytes(data)
                    detail['file'] = member.name
                    done = True
                dst.addfile(member, io.BytesIO(data) if data is not None else None)
        rewrite(entry, change)
    elif case == 'volume-escape':
        entry = app['volumes'][0]['entry']
        def change(src, dst):
            for member in src.getmembers():
                dst.addfile(member, src.extractfile(member) if member.isreg() else None)
            evil = tarfile.TarInfo('woowbk-deep-escape')
            evil.type, evil.linkname = tarfile.SYMTYPE, '../../../../etc'
            dst.addfile(evil)
        rewrite(entry, change)
    elif case == 'dir-absolute':
        entry = next(d['entry'] for d in app['data_dirs'] if d['path'] == 'woowbk-dirs/data')
        def change(src, dst):
            for member in src.getmembers():
                dst.addfile(member, src.extractfile(member) if member.isreg() else None)
            link = tarfile.TarInfo('woowbk-deep-abs')
            link.type, link.linkname, link.uid, link.gid = tarfile.SYMTYPE, '/home/appowner/.config/systemd', 0, 0
            dst.addfile(link)
            data = b'[Service]\nExecStart=/bin/true\n'
            planted = tarfile.TarInfo('woowbk-deep-abs/user/woowbk-deep-planted.service')
            planted.size, planted.mode = len(data), 0o644
            dst.addfile(planted, io.BytesIO(data))
        rewrite(entry, change)
    elif case == 'digest-listing':
        item = next(d for d in app['verify_digests'] if d['type'] == 'files-digest')
        entry = item['entry']
        text = open(files[entry], 'rb').read().split(b'\n')
        index = next(i for i, line in enumerate(text) if line.startswith(b'f '))
        fields = text[index].split(b' ')
        fields[4] = str(int(fields[4]) + 1).encode()
        text[index] = b' '.join(fields)
        data = b'\n'.join(text)
        open(files[entry], 'wb').write(data)
        item['digest'] = hashlib.sha256(data).hexdigest()
        detail['line'] = index
    elif case == 'dump-junk':
        entry = app['postgres'][0]['entry']
        open(files[entry], 'wb').write(b'not a pg_dump archive (woowbk deep verify test)\n' * 8)
    elif case != 'control':
        sys.exit('unknown case ' + case)
    entries = []
    for item in inner['entries']:
        data = open(files[item['path']], 'rb').read()
        entries.append(warchive.Entry(item['path'], files[item['path']], len(data), hashlib.sha256(data).hexdigest()))
    now = time.gmtime()
    new_id = time.strftime('%Y%m%dT%H%M%SZ', now) + '-' + secrets.token_hex(4)
    head = {key: inner[key] for key in warchive.HEAD_FIELDS}
    head.update(backup_id=new_id, created=time.strftime('%Y-%m-%dT%H:%M:%SZ', now), note='strengthen ' + case)
    out_path = os.path.join(work, out_name)
    with warchive.ArchiveWriter(out_path, head, [app], recipient, tmp_dir=work) as writer:
        writer.add_app(app, entries)
        writer.finish()
    print(json.dumps({'backup_id': new_id, 'path': out_path, 'case': case, 'detail': detail}))
finally:
    for name in os.listdir(work):
        if name != out_name:
            os.unlink(os.path.join(work, name))
"""


def craft(ev, base_id, case):
    """A re-sealed copy of a dev-a backup (device key, valid checksums) with one change, uploaded through the bridge;
    returns the crafted backup id and what was changed."""
    from hardening import py, write_private_stream
    work = f'/var/tmp/woowbk-strengthen-{case}'
    sh('a', f'rm -rf {work}')
    try:
        crafted = json.loads(py('a', CRAFT, base_id, work, case, timeout=900).stdout)
        local = private_dir(WORK) / f'{case}.tar'
        write_private_stream('a', crafted['path'], local)
    finally:
        sh('a', f'rm -rf {work}', check=False)
    reply = upload('a', ev, local, f'woowtech-backup-strengthen-{case}.tar')
    local.unlink(missing_ok=True)
    ev.require(f'{case}: the re-sealed file uploads (outer structure and checksums valid)', reply.get('ok'),
               reply.get('error'))
    remember('a', crafted['backup_id'])
    return crafted


SIDE_WRITER = ('woowbk-mm-writer', 'while true; do psql -h woowbk-demo-db -U notes -d notes -qc '
                                   '"INSERT INTO woowbk_mm(t) VALUES (clock_timestamp())"; sleep 0.05; done')
# A job inside the database container itself (like pg_cron), over the local socket: it keeps writing while other
# containers of the app stop -- the separate writer container lost its connections for a few seconds right after the
# app container stopped (network change on the shared Podman network), lab 2026-11-14 -- and it ends with the database
# container (a restore stops it).
IN_DB_WRITER = ('while true; do psql -X -q -U notes -d notes -c "INSERT INTO woowbk_mm(t) VALUES (clock_timestamp())" '
                '>/dev/null 2>&1; sleep 0.05; done')


@scenario('mismatch')
def scenario_mismatch(ev):
    """Deliberate corruption the checksums cannot see: (a) a backup re-sealed with one byte of an uploaded file
    changed (valid sha256 everywhere): the restore finds the difference before the app starts and rolls back to the
    data before the restore. (b) A database another container and a job inside the database container (like pg_cron)
    keep writing while the backup runs: the two digest reads differ and the backup keeps no database digest (review
    H2/F3), so its restore succeeds. (c) The flip-file restore again while they write: its safety backup keeps no
    database digest either, and the rollback completes instead of leaving the app masked. (d) A stable backup restored
    while the writer container keeps inserting: a digest that differs is read again, moving data is reported as not
    compared and the restore completes."""
    memory_ok()
    ensure_digest_entries(ev)
    ev.require('dev-a woowbk-demo healthy', wait_healthy('a', 180))
    job, _log = backup('a', ev, 'backup[mismatch-base]')
    ev.require('base backup', job['state'] == 'succeeded', job.get('error'))
    crafted = craft(ev, job['result']['backup_id'], 'flip-file')
    ev.log(f'flip-file changed one byte of {crafted["detail"].get("file")}')
    vjob, _vlog = run_job('a', ev, 'verify-start', {'backup_id': crafted['backup_id']}, 'verify[flip-file]')
    ev.check('flip-file: the deep verify passes (every checksum is consistent; only the data digest can tell)',
             vjob['state'] == 'succeeded', vjob.get('error'))
    app_post('a', '/api/notes', json.dumps({'title': 'mismatch 還原前', 'body': '回復後應保留'}).encode(),
             'application/json')
    before = demo_summary('a')
    rjob, rlog = restore('a', ev, crafted['backup_id'], 'restore[flip-file]')
    files = next((c for c in checks_of(rjob, DEMO)[0].values() if c['type'] == 'files-digest'), {})
    ev.save('flip-file-check', files)
    samples = (files.get('differences') or {}).get('samples') or []
    ev.check('flip-file: restore rolled back', rjob['state'] == 'rolled-back', rjob.get('error'))
    ev.check('flip-file: the files digest names the changed file (changed, sha256)', files.get('match') is False
             and any(crafted['detail'].get('file', '#').split('/')[-1] in s['item'] and s['change'] == 'changed'
                     for s in samples), samples)
    rollback_at = next((i for i, line in enumerate(rlog) if '自動回復' in line), len(rlog))
    ev.check('flip-file: the app never started on the corrupted data',
             not [line for line in rlog[:rollback_at] if '啟動服務 woowbk-demo-app' in line])
    ev.check('flip-file: after the rollback the app runs with the data from before the restore',
             wait_healthy('a', 180) and demo_summary('a') == before)
    # (b) a container the catalog does not know, and a job inside the database container, write during the backup
    def mm_rows():
        proc = owner('a', 'podman', 'exec', '-i', 'woowbk-demo-db', 'psql', '-X', '-A', '-t', '-U', 'notes', '-d', 'notes',
                     '-c', 'SELECT count(*) FROM woowbk_mm', check=False)
        return int(proc.stdout.decode().strip() or -1) if proc.returncode == 0 else -1

    owner('a', 'podman', 'exec', '-i', 'woowbk-demo-db', 'psql', '-X', '-q', '-U', 'notes', '-d', 'notes', '-c',
          'DROP TABLE IF EXISTS woowbk_mm; CREATE TABLE woowbk_mm (id bigserial PRIMARY KEY, t timestamptz)')
    # A backup with the table and a stable database digest (nothing writes yet), restored in (d).
    stable, _slog = backup('a', ev, 'backup[mismatch-stable]')
    ev.require('stable backup with the table', stable['state'] == 'succeeded', stable.get('error'))
    owner('a', 'podman', 'rm', '-f', SIDE_WRITER[0], check=False)
    owner('a', 'podman', 'run', '-d', '--name', SIDE_WRITER[0], '--memory', '32m', '--network', 'woowbk-demo',
          '--secret', 'woowbk-demo-db-password,type=env,target=PGPASSWORD', '--entrypoint', 'sh',
          'docker.io/library/postgres:16-alpine', '-c', SIDE_WRITER[1])
    owner('a', 'podman', 'exec', '-d', 'woowbk-demo-db', 'sh', '-c', IN_DB_WRITER)
    try:
        first = mm_rows()
        time.sleep(2)
        ev.require('the undeclared writers really write the database (rows growing)', mm_rows() > max(first, 0),
                   {'before': first, 'logs': owner('a', 'podman', 'logs', '--tail', '3', SIDE_WRITER[0],
                                                   check=False).stderr.decode()[-300:]})
        job, blog = backup('a', ev, 'backup[mismatch-writer]')
        ev.require('backup while an undeclared container writes the database', job['state'] == 'succeeded',
                   job.get('error'))
        # The engine reads the database digest before and after the dump; the reads differ, so the backup keeps no
        # database digest (review H2/F3: it used to keep one that every restore of the backup then failed on).
        ev.check('writer: the two database digest reads differ, the backup keeps no database digest and says why',
                 bool(lines(blog, '兩次讀取的結果不同')), lines(blog, '資料摘要'))
        # (c) The rollback chain of H2: an in-place restore that fails (the flip-file backup) while the writer still
        # runs. Its safety backup is taken with the writer running, so it keeps no database digest either, and the
        # rollback restores it and completes. Before the fix the safety backup's digest failed the rollback, which
        # left the app stopped and masked (需人工處理).
        cjob, clog = restore('a', ev, crafted['backup_id'], 'restore[flip-file-writer-running]')
        ev.check('writer running: the failed restore rolls back completely (rolled-back, not 需人工處理)',
                 cjob['state'] == 'rolled-back' and (cjob.get('result') or {}).get('rolled_back') is True,
                 {'state': cjob['state'], 'error': cjob.get('error')})
        ev.check('writer running: the safety backup noticed the database changing and kept no database digest',
                 bool(lines(clog, '兩次讀取的結果不同')), lines(clog, '資料摘要')[-6:])
        states = owner('a', 'systemctl', '--user', 'show', '--property=LoadState,ActiveState', '--',
                       'woowbk-demo-app.service', check=False).stdout.decode()
        ev.check('writer running: the app is not left masked after the rollback', 'LoadState=masked' not in states,
                 states)
        # (d) The writer container keeps inserting into the restored database (it reconnects once the database runs
        # again): a restore of the stable backup reads a differing digest twice; reads that differ from each other
        # mean moving data -- not compared, the restore completes (it used to fail and its rollback met the same
        # writer). If the writer reconnected only after both reads, the digest simply matches.
        ev.require('the writer container still runs', wait_healthy('a', 180) and mm_rows() >= 0)
        djob, dlog = restore('a', ev, stable['result']['backup_id'], 'restore[stable-writer-running]')
        pg = next((c for c in checks_of(djob, DEMO)[0].values() if c['type'] == 'postgres-digest'), {})
        ev.save('stable-writer-check', pg)
        moving = pg.get('match') is None and '仍在變動' in (pg.get('note') or '')
        ev.log(f'(d) database digest after the restore: {"moving data, not compared" if moving else pg.get("match")}')
        ev.check('writer running: the restore of a stable backup completes (moving data is not a failed comparison)',
                 djob['state'] == 'succeeded' and (moving or pg.get('match') is True),
                 {'state': djob['state'], 'error': djob.get('error'), 'check': pg})
        ev.check('writer running: when the data was moving, the result says so in its warnings',
                 not moving or any('仍在變動' in w for w in (djob.get('result') or {}).get('warnings') or []),
                 (djob.get('result') or {}).get('warnings'))
    finally:
        owner('a', 'podman', 'rm', '-f', SIDE_WRITER[0], check=False)
        owner('a', 'podman', 'exec', 'woowbk-demo-db', 'pkill', '-f', 'woowbk_mm', check=False)
    ev.require('app healthy again after the restores', wait_healthy('a', 180))
    rjob, _rlog = restore('a', ev, job['result']['backup_id'], 'restore[writer]')
    pg = next((c for c in checks_of(rjob, DEMO)[0].values() if c['type'] == 'postgres-digest'), {})
    files = next((c for c in checks_of(rjob, DEMO)[0].values() if c['type'] == 'files-digest'), {})
    ev.save('writer-check', {'postgres': pg, 'files': files})
    ev.check('writer: the restore of that backup succeeds (nothing the backup cannot vouch for is compared)',
             rjob['state'] == 'succeeded', rjob.get('error'))
    ev.check('writer: the database digest is reported as not compared, the files digest still matches',
             pg.get('match') is None and '備份沒有這個項目的資料摘要' in (pg.get('note') or '')
             and files.get('match') is True, {'postgres': pg, 'files': files})
    ev.check('writer: the app runs after the restore', wait_healthy('a', 180))
    owner('a', 'podman', 'exec', '-i', 'woowbk-demo-db', 'psql', '-X', '-q', '-U', 'notes', '-d', 'notes', '-c',
          'DROP TABLE IF EXISTS woowbk_mm')


@scenario('deep')
def scenario_deep(ev):
    """The verify job checks every nested tar like a restore: re-sealed backups (valid checksums) with an escaping
    volume symlink, an absolute symlink with a member below it in a host-directory tar, a digest listing that
    disagrees with its summary and a database dump that is not one all fail it; an untouched re-seal passes.
    inspect stays fast (it reads only the manifests)."""
    memory_ok()
    ensure_digest_entries(ev)
    demo, _ = backup('a', ev, 'backup[deep-demo]')
    dirs, _ = backup('a', ev, 'backup[deep-dirs]', apps=(DIRS,))
    ev.require('base backups', demo['state'] == dirs['state'] == 'succeeded')
    cases = [('control', demo, None), ('volume-escape', demo, 'volumes'), ('dir-absolute', dirs, 'dirs'),
             ('digest-listing', demo, 'digests'), ('dump-junk', demo, 'dumps')]
    results = {}
    for case, base, check in cases:
        crafted = craft(ev, base['result']['backup_id'], case)
        t0 = time.monotonic()
        inspected = helper('a', 'inspect', {'backup_id': crafted['backup_id']}, ev=ev)[1]
        inspect_s = round(time.monotonic() - t0, 1)
        job, _log = run_job('a', ev, 'verify-start', {'backup_id': crafted['backup_id']}, f'verify[{case}]')
        meta = next(b for b in ok('a', 'list', ev=ev)['backups'] if b['id'] == crafted['backup_id'])
        error = job.get('error') or {}
        results[case] = {'inspect_ok': inspected.get('ok'), 'inspect_s': inspect_s, 'verify': job['state'],
                         'error': error, 'verified': meta.get('verified'),
                         'verify_s': (job.get('_phase_first_seen_s') or {})}
        if check is None:
            ev.check(f'{case}: inspect fast and ok, the deep verify passes', inspected.get('ok') and job['state'] ==
                     'succeeded' and (meta.get('verified') or {}).get('deep') is True, results[case])
            continue
        ev.check(f'{case}: inspect (manifests only) still accepts it', inspected.get('ok'), inspected.get('error'))
        ev.check(f'{case}: the verify job fails with corrupt-archive (check {check})', job['state'] == 'failed'
                 and error.get('code') == 'corrupt-archive', error)
        ev.check(f'{case}: index verified {{ok: false, deep: true}}', (meta.get('verified') or {}).get('ok') is False
                 and (meta.get('verified') or {}).get('deep') is True, meta.get('verified'))
    return {'cases': results}


# ------------------------------------------------------------------ dev-b without a device key; retention

DEFAULT_POLICY = {'schema': 1, 'default_keep_last': None, 'apps': {}}


@scenario('keyless')
def scenario_keyless(ev):
    """dev-b holds no device key (a device that never set one up): unencrypted backups need none (per backup while
    預設加密備份 is on, by the setting when it is off), its safety backups follow the setting, and anything
    encrypted still needs the key."""
    dev = 'b'
    memory_ok()
    status = ok(dev, 'status', ev=ev)
    ev.require('dev-b has no device key and 預設加密備份 is on', status['key'] is None
               and status['settings']['encrypt_by_default'] is True, {'key': status['key'], 'settings': status['settings']})
    ev.require('dev-b woowbk-demo running', wait_healthy(dev, 180))
    rc, reply = helper(dev, 'backup-start', {'apps': [DEMO], 'request_id': request_id()}, ev=ev)
    ev.check('backup with the default (encrypted) -> no-device-key', rc == 1 and reply['error']['code'] == 'no-device-key',
             reply.get('error'))
    rc, reply = helper(dev, 'backup-start', {'apps': [DEMO], 'request_id': request_id(), 'encrypt': True}, ev=ev)
    ev.check('backup with encrypt:true -> no-device-key', rc == 1 and reply['error']['code'] == 'no-device-key',
             reply.get('error'))
    rc, reply = helper(dev, 'backup-start', {'apps': [DEMO], 'request_id': request_id(), 'encrypt': False}, ev=ev)
    ev.check('encrypt:false while the setting is on needs acknowledge_plaintext', rc == 1
             and reply['error']['details'].get('field') == 'acknowledge_plaintext', reply.get('error'))
    job, log = backup(dev, ev, 'backup[keyless-ack]', encrypt=False, acknowledge_plaintext=True)
    ev.require('unencrypted backup without any device key succeeded', job['state'] == 'succeeded', job.get('error'))
    ev.check('job result encrypted false', job['result'].get('encrypted') is False, job['result'])
    meta = next(b for b in ok(dev, 'list', ev=ev)['backups'] if b['id'] == job['result']['backup_id'])
    ev.check('list: format 2, not encrypted, key_id null, key available, made here (not unauthenticated)',
             meta['format'] == 2 and meta['encrypted'] is False and meta['key_id'] is None and meta['key_available']
             and meta['unauthenticated'] is False, meta)
    inspected = ok(dev, 'inspect', {'backup_id': meta['id']}, ev=ev)
    checks = {c['id'].split('/', 1)[1]: c for a in inspected['preflight']['apps'] for c in a['checks']}
    ev.check('preflight (setting on): an in-place restore needs the device key for its safety backup',
             checks.get('device-key', {}).get('status') == 'fail', checks.get('device-key'))
    rjob, _log = restore(dev, ev, meta['id'], 'restore[keyless-setting-on]')
    ev.check('in-place restore while the setting is on and no key exists fails before any change',
             rjob['state'] == 'failed' and (rjob.get('result') or {}).get('changed') is False, rjob.get('error'))
    rc, reply = helper(dev, 'settings-set', {'encrypt_by_default': False}, ev=ev)
    ev.check('turning 預設加密備份 off needs the acknowledgement', rc == 1
             and reply['error']['details'].get('field') == 'acknowledge_plaintext', reply.get('error'))
    view = ok(dev, 'settings-set', {'encrypt_by_default': False, 'acknowledge_plaintext': True}, ev=ev)['settings']
    mode = sh(dev, 'stat -c "%U %a" /etc/woowtech-cockpit/backup/settings.json').stdout.decode().strip()
    ev.check('setting off: settings.json root 0644, warning text present', view['encrypt_by_default'] is False
             and mode == 'root 644' and '明文' in view['plaintext_warning'], {'mode': mode})
    try:
        job, _log = backup(dev, ev, 'backup[keyless-setting-off]')
        ev.require('setting off: a backup without `encrypt` is unencrypted, no acknowledgement needed',
                   job['state'] == 'succeeded' and job['result'].get('encrypted') is False, job.get('error'))
        app_post(dev, '/api/notes', json.dumps({'title': 'keyless 備份後', 'body': 'x'}).encode(), 'application/json')
        snap_after_change = demo_summary(dev)
        rjob, rlog = restore(dev, ev, job['result']['backup_id'], 'restore[keyless-setting-off]')
        ev.require('setting off: in-place restore without a device key succeeded', rjob['state'] == 'succeeded',
                   rjob.get('error'))
        safety = rjob['result'].get('safety_backup_id')
        smeta = next((b for b in ok(dev, 'list', ev=ev)['backups'] if b['id'] == safety), {})
        ev.check('setting off: the safety backup follows the setting (unencrypted, made without a key)',
                 smeta.get('type') == 'safety' and smeta.get('encrypted') is False and smeta.get('key_id') is None, smeta)
        ev.check('restored data differs from the state before the restore (the note posted after the backup is gone)',
                 demo_summary(dev) != snap_after_change)
    finally:
        view = ok(dev, 'settings-set', {'encrypt_by_default': True}, ev=ev)['settings']
    ev.check('setting back on (no acknowledgement needed)', view['encrypt_by_default'] is True)
    rc, reply = helper(dev, 'backup-start', {'apps': [DEMO], 'request_id': request_id()}, ev=ev)
    ev.check('setting on again: an encrypted backup still needs the device key', rc == 1
             and reply['error']['code'] == 'no-device-key', reply.get('error'))
    journal = sh(dev, 'journalctl -t woowtech-cockpit-backup --since "-20 min" --no-pager -o cat | grep "^settings "',
                 check=False).stdout.decode().strip().splitlines()
    ev.check('journal: both setting changes audited', any('encrypt_by_default=false' in line for line in journal)
             and any('encrypt_by_default=true' in line for line in journal), journal[-3:])


@scenario('retention')
def scenario_retention(ev):
    """Keep-last-N on dev-b: the saved policy deletes the oldest manual backup after a new one, a preview names the
    candidates and protected backups, and the safety backup a killed restore still needs (and that restore's source)
    is never deleted until a later restore of the app succeeded."""
    dev = 'b'
    memory_ok()
    ev.require('dev-b woowbk-demo running', wait_healthy(dev, 180))
    # dev-b has no device key: its safety backups (the killed restore below) are unencrypted, by the setting.
    ok(dev, 'settings-set', {'encrypt_by_default': False, 'acknowledge_plaintext': True}, ev=ev)
    try:
        return retention_steps(ev, dev)
    finally:
        ok(dev, 'settings-set', {'encrypt_by_default': True}, ev=ev)


def manual_of(dev, ev, app_id):
    return sorted((b for b in ok(dev, 'list', ev=ev)['backups'] if b['type'] == 'manual'
                   and app_id in {a['id'] for a in b.get('apps') or []}), key=lambda b: (b['created'], b['id']))


def retention_steps(ev, dev):
    earlier = [b['id'] for b in manual_of(dev, ev, DEMO)]
    ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [], 'policy': {**DEFAULT_POLICY, 'apps': {DEMO: {'keep_last': 2}}}},
       ev=ev)
    made = []
    for n in range(3):
        job, _log = backup(dev, ev, f'backup[retention-{n}]')
        ev.require(f'manual backup {n + 1}', job['state'] == 'succeeded', job.get('error'))
        made.append(job['result'])
    deleted = [backup_id for m in made for backup_id in m['retention_deleted']]
    ev.check('policy keep 2: each manual backup deleted the manual backups of the app beyond the newest 2 '
             '(older ones first, never the new one)', sorted(deleted) == sorted(earlier + [made[0]['backup_id']])
             and all(m['backup_id'] not in m['retention_deleted'] for m in made),
             {'earlier': earlier, 'deleted_per_backup': [m['retention_deleted'] for m in made]})
    left = [b['id'] for b in manual_of(dev, ev, DEMO)]
    ev.check('list: exactly the two newest manual backups of the app stay', left == [made[1]['backup_id'],
                                                                                     made[2]['backup_id']], left)
    journal = sh(dev, 'journalctl -t woowtech-cockpit-backup --since "-20 min" --no-pager -o cat | grep "retention-"',
                 check=False).stdout.decode()
    ev.check('journal: policy change and every policy deletion are audited', 'retention-policy' in journal
             and all(f'retention-delete backup={backup_id}' in journal for backup_id in deleted)
             and 'reason=policy' in journal)
    # A killed in-place restore pins its safety backup and its source.
    target = made[1]['backup_id']
    start = ok(dev, 'restore-start', {'backup_id': target, 'apps': [DEMO], 'request_id': request_id(), 'confirm': True},
               ev=ev)
    job_id, killed = start['job_id'], None
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        job = helper(dev, 'job-status', {'job_id': job_id})[1]['job']
        if job['phase'] in ('restore', 'start') and job['state'] == 'running':
            sh(dev, f'systemctl kill --signal=SIGKILL woowtech-backup-{job_id}.service')
            killed = job['phase']
            break
        if job['state'] not in ('queued', 'running'):
            break
        time.sleep(0.2)
    ev.require('restore killed after its destructive step began', killed, job.get('phase'))
    time.sleep(2)
    job, _log = wait_job(dev, job_id, ev=ev, timeout=180, label='killed-restore')
    safety = (job.get('result') or {}).get('safety_backup_id')
    remember(dev, safety)
    ev.require('killed restore is interrupted and names its safety backup', job['state'] == 'interrupted' and safety,
               job.get('error'))
    plan = ok(dev, 'retention-plan', {'policy': {**DEFAULT_POLICY, 'default_keep_last': 1}}, ev=ev)
    ev.save('retention-plan-pinned', plan)
    protected = {item['id']: item.get('reason') for item in plan['protected']}
    ev.check('plan: the pinned safety backup and the killed restore\'s source are protected',
             safety in protected and target in protected, protected)
    ev.check('plan: a candidate that is protected is listed as blocked, not as a candidate',
             target not in {c['id'] for c in plan['candidates']}
             and (target in {b['id'] for b in plan['blocked']} or made[2]['backup_id'] != target), plan['blocked'])
    applied = ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [safety, target]}, ev=ev)
    ev.check('apply: both are skipped with a reason, nothing deleted', applied['deleted'] == []
             and {s['id'] for s in applied['skipped']} == {safety, target}, applied['skipped'])
    rjob, _log = restore(dev, ev, safety, 'restore[pinned-safety]')
    ev.require('restoring the safety backup succeeds', rjob['state'] == 'succeeded', rjob.get('error'))
    plan = ok(dev, 'retention-plan', {}, ev=ev)
    ev.check('after a successful restore of the app the safety backup is no longer protected',
             safety not in {item['id'] for item in plan['protected']}, plan['protected'])
    applied = ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [safety]}, ev=ev)
    ev.check('apply: the selected safety backup is deleted now', [d['id'] for d in applied['deleted']] == [safety],
             applied)
    applied = ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [], 'policy': DEFAULT_POLICY}, ev=ev)
    ev.check('policy back to keep everything', applied['policy']['apps'] == {}
             and applied['policy']['default_keep_last'] is None)


# ------------------------------------------------------------------ format 2: backup.json changed outside the device

def edit_backup_json(path, change):
    """Rewrite backup.json in place inside its member (same size: padded with spaces), like an editor would."""
    import tarfile
    with tarfile.open(path) as tar:
        info = tar.getmember('backup.json')
        offset, size = info.offset_data, info.size
    with open(path, 'r+b') as handle:
        handle.seek(offset)
        raw = handle.read(size)
        doc = json.loads(raw)
        change(doc)
        data = json.dumps(doc, ensure_ascii=False, indent=2).encode('utf-8')
        if len(data) + 1 > size:
            raise Failed('edited backup.json does not fit its member')
        handle.seek(offset)
        handle.write(data + b' ' * (size - len(data) - 1) + b'\n')


@scenario('tampered-json')
def scenario_tampered_json(ev):
    """backup.json is display data: a changed note is caught by the authenticated manifests (inspect, verify and
    restore refuse it), a changed member checksum is refused at upload, and the untouched copy still works."""
    memory_ok()
    job, _log = backup('a', ev, 'backup[tamper-base]')
    ev.require('base backup', job['state'] == 'succeeded', job.get('error'))
    local, info = download('a', ev, job['result']['backup_id'], 'tamper')
    ok('a', 'delete', {'backup_id': job['result']['backup_id']}, ev=ev)  # the upload brings the same id back
    try:
        note_copy = local.with_name(local.name + '.note')
        sum_copy = local.with_name(local.name + '.sum')
        shutil.copyfile(local, note_copy)
        shutil.copyfile(local, sum_copy)
        edit_backup_json(note_copy, lambda doc: doc.update(note='已被修改的說明'))
        edit_backup_json(sum_copy, lambda doc: doc['apps'][0].update(sha256='0' * 64))
        reply = upload('a', ev, sum_copy, 'woowtech-backup-tampered-sum.tar')
        ev.check('member checksum changed in backup.json: upload-finish refuses it (corrupt-archive)',
                 not reply.get('ok') and reply['error']['code'] == 'corrupt-archive', reply.get('error'))
        reply = upload('a', ev, note_copy, 'woowtech-backup-tampered-note.tar')
        ev.require('note changed in backup.json: the outer structure is intact, the upload is stored', reply.get('ok'),
                   reply.get('error'))
        backup_id = reply['backup']['id']
        remember('a', backup_id)
        rc, inspected = helper('a', 'inspect', {'backup_id': backup_id}, ev=ev)
        ev.check('inspect compares backup.json with the authenticated manifests -> corrupt-archive', rc == 1
                 and inspected['error']['code'] == 'corrupt-archive', inspected.get('error'))
        vjob, _log = run_job('a', ev, 'verify-start', {'backup_id': backup_id}, 'verify[tampered-note]')
        ev.check('verify job fails with corrupt-archive', vjob['state'] == 'failed'
                 and (vjob.get('error') or {}).get('code') == 'corrupt-archive', vjob.get('error'))
        before = demo_summary('a')
        rjob, _log = restore('a', ev, backup_id, 'restore[tampered-note]')
        ev.check('restore refuses it before any change', rjob['state'] == 'failed'
                 and (rjob.get('result') or {}).get('changed') is False, rjob.get('error'))
        ev.check('app data unchanged', demo_summary('a') == before)
        ok('a', 'delete', {'backup_id': backup_id}, ev=ev)
        reply = upload('a', ev, local, info['filename'])
        ev.check('the untouched download uploads again and inspects fine', reply.get('ok')
                 and helper('a', 'inspect', {'backup_id': reply['backup']['id']}, ev=ev)[1].get('ok'),
                 reply.get('error'))
    finally:
        for path in (local, local.with_name(local.name + '.note'), local.with_name(local.name + '.sum')):
            path.unlink(missing_ok=True)


# ------------------------------------------------------------------ PostgreSQL instance mode (lab app woowbk-inst)

INST = 'woowbk-inst'
INST_FIXTURE = REPO / 'catalog-examples' / INST
INST_TEMPLATES = '/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-inst'
INST_URL = 'http://127.0.0.1:18092'
PGVECTOR = 'docker.io/pgvector/pgvector:pg16'
INST_DB = ['podman', 'exec', '-i', 'woowbk-inst-db', 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-U', 'ncadmin']
INST_UNITS = ('woowbk-inst-app.service', 'woowbk-inst-db.service', 'woowbk-inst-network.service')
INST_TEARDOWN = r"""
set -u
cd "$HOME"
systemctl --user stop woowbk-inst-app.service woowbk-inst-db.service woowbk-inst-network.service 2>/dev/null
systemctl --user unmask woowbk-inst-app.service woowbk-inst-db.service 2>/dev/null
rm -f .config/containers/systemd/woowbk-inst.network .config/containers/systemd/woowbk-inst-db.container \
      .config/containers/systemd/woowbk-inst-app.container
systemctl --user daemon-reload
systemctl --user reset-failed 2>/dev/null
podman rm -f woowbk-inst-app woowbk-inst-db >/dev/null 2>&1
podman volume rm -f woowbk-inst-files woowbk-inst-pgdata >/dev/null 2>&1
podman secret rm woowbk-inst-db-password woowbk-inst-app-key >/dev/null 2>&1
podman network rm -f woowbk-inst >/dev/null 2>&1
true
"""
INST_SETUP_SQL = """
CREATE ROLE oc_admin LOGIN PASSWORD '{oc}';
CREATE ROLE nc_readonly NOLOGIN;
GRANT nc_readonly TO oc_admin;
CREATE ROLE odoo LOGIN CREATEDB PASSWORD '{odoo}' CONNECTION LIMIT 50;
ALTER ROLE odoo SET statement_timeout = '60s';
CREATE DATABASE nextcloud OWNER oc_admin;
ALTER ROLE oc_admin IN DATABASE nextcloud SET search_path = public, pg_catalog;
CREATE DATABASE odoo_prod OWNER odoo ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
CREATE DATABASE odoo_test OWNER odoo TEMPLATE template0;
ALTER DATABASE odoo_prod SET timezone = 'UTC';
COMMENT ON DATABASE odoo_prod IS 'odoo company database';
REVOKE CONNECT ON DATABASE odoo_prod FROM PUBLIC;
GRANT CONNECT ON DATABASE odoo_prod TO odoo;
\\c nextcloud
CREATE EXTENSION vector;
CREATE EXTENSION pg_trgm;
SET ROLE oc_admin;
CREATE TABLE oc_embeddings (id bigserial PRIMARY KEY, path text, mtime timestamptz, size bigint, embedding vector(8),
                            meta jsonb);
INSERT INTO oc_embeddings (path, mtime, size, embedding, meta)
  SELECT 'files/' || g, '2026-11-13 10:00:00+08'::timestamptz + g * interval '1 minute', g * 17,
         ('[' || array_to_string(ARRAY(SELECT round(((g * k) % 97) / 97.0, 4) FROM generate_series(1, 8) k), ',') || ']')::vector,
         jsonb_build_object('n', g) FROM generate_series(1, 3000) g;
CREATE INDEX oc_embeddings_hnsw ON oc_embeddings USING hnsw (embedding vector_l2_ops);
CREATE INDEX oc_embeddings_trgm ON oc_embeddings USING gin (path gin_trgm_ops);
GRANT SELECT ON oc_embeddings TO nc_readonly;
RESET ROLE;
\\c odoo_prod
SET ROLE odoo;
CREATE TABLE res_partner (id serial PRIMARY KEY, name text, active bool, write_date timestamp);
INSERT INTO res_partner (name, active, write_date) SELECT 'P' || g, g % 3 > 0, '2026-01-01'::timestamp + g * interval '1 hour'
  FROM generate_series(1, 500) g;
RESET ROLE;
\\c odoo_test
SET ROLE odoo;
CREATE TABLE res_partner (id serial PRIMARY KEY, name text);
INSERT INTO res_partner (name) SELECT 'T' || g FROM generate_series(1, 50) g;
"""
INST_STATE_SQL = {
    'roles': "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolconnlimit, "
             "md5(coalesce(rolpassword, '')) FROM pg_authid WHERE rolname !~ '^pg_' ORDER BY 1",
    'members': "SELECT r.rolname, m.rolname, a.admin_option FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid "
               "JOIN pg_roles m ON m.oid = a.member WHERE r.rolname !~ '^pg_' ORDER BY 1, 2",
    'settings': "SELECT coalesce(d.datname, '-'), coalesce(r.rolname, '-'), s.setconfig FROM pg_db_role_setting s "
                "LEFT JOIN pg_database d ON d.oid = s.setdatabase LEFT JOIN pg_roles r ON r.oid = s.setrole ORDER BY 1, 2",
    'databases': "SELECT datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding), datcollate, datctype, "
                 "(SELECT array_agg(a ORDER BY a::text) FROM unnest(datacl) a), shobj_description(oid, 'pg_database') "
                 "FROM pg_database WHERE NOT datistemplate ORDER BY 1",
}


def inst_psql(dev, sql, database='ncadmin', check=True):
    proc = owner(dev, *INST_DB, '-d', database, '-f', '-', input=sql.encode(), check=check, timeout=300)
    if proc.returncode != 0:
        return f'(failed: {proc.stderr.decode("utf-8", "replace").strip()[-160:]})'
    return proc.stdout.decode('utf-8', 'replace').strip()


def inst_state(dev):
    state = {key: inst_psql(dev, sql, 'postgres') for key, sql in INST_STATE_SQL.items()}
    state['nextcloud'] = inst_psql(dev, "SELECT count(*), md5(string_agg(md5(t::text), '' ORDER BY id)) FROM oc_embeddings t; "
                                        "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'oc_embeddings'; "
                                        "SELECT count(*) FROM notes", 'nextcloud', check=False)
    # Exact nearest neighbours (ties broken by id): HNSW is approximate and its graph is rebuilt by the restore,
    # so the index is only checked for being there and valid, and for being chosen by the planner.
    state['nn'] = inst_psql(dev, "SET enable_indexscan = off; SET enable_bitmapscan = off; SELECT id FROM oc_embeddings "
                                 "ORDER BY embedding <-> '[0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5]', id LIMIT 3", 'nextcloud',
                            check=False)
    state['indexes'] = inst_psql(dev, "SELECT c.relname, am.amname, i.indisvalid FROM pg_index i JOIN pg_class c ON "
                                      "c.oid = i.indexrelid JOIN pg_am am ON am.oid = c.relam WHERE i.indrelid = "
                                      "'oc_embeddings'::regclass ORDER BY 1", 'nextcloud', check=False)
    state['odoo_prod'] = inst_psql(dev, "SELECT count(*), md5(string_agg(md5(t::text), '' ORDER BY id)) FROM res_partner t",
                                   'odoo_prod', check=False)
    state['odoo_test'] = inst_psql(dev, 'SELECT count(*) FROM res_partner', 'odoo_test', check=False)
    state['extensions'] = inst_psql(dev, 'SELECT extname, extversion FROM pg_extension ORDER BY 1', 'nextcloud', check=False)
    return state


def hnsw_used(dev):
    plan = inst_psql(dev, "SET enable_seqscan = off; EXPLAIN SELECT id FROM oc_embeddings ORDER BY embedding <-> "
                          "'[0.5,0.5,0.5,0.5,0.5,0.5,0.5,0.5]' LIMIT 3", 'nextcloud', check=False)
    return 'oc_embeddings_hnsw' in plan


def inst_get(dev, path):
    proc = sh(dev, f'curl -sS --max-time 20 -o - -w "\\n%{{http_code}}" {INST_URL}{path}', check=False, timeout=60)
    body, _, status = proc.stdout.decode('utf-8', 'replace').rpartition('\n')
    return int(status or 0), body


def inst_healthy(dev, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if inst_get(dev, '/healthz')[0] == 200:
            return True
        time.sleep(2)
    return False


def inst_summary(dev):
    status, body = inst_get(dev, '/api/summary')
    return {k: v for k, v in json.loads(body).items() if k in DEMO_COMPARE} if status == 200 else None


def inst_post_note(dev, title):
    proc = sh(dev, f'curl -sS --max-time 30 -o /dev/null -w "%{{http_code}}" -X POST -H "Content-Type: application/json" '
                   f'--data-binary @- {INST_URL}/api/notes',
              input=json.dumps({'title': title, 'body': '執行個體模式'}, ensure_ascii=False).encode(), check=False)
    return proc.stdout.decode().strip()


def odoo_login(dev, password):
    """Log in as `odoo` with a password over the network (scram), from a one-shot client container (stdin only)."""
    proc = owner(dev, 'podman', 'run', '--rm', '-i', '--memory', '32m', '--network', 'woowbk-inst', '--entrypoint', 'sh',
                 'docker.io/library/postgres:16-alpine', '-c',
                 'read -r PGPASSWORD; export PGPASSWORD; psql -X -A -t -h woowbk-inst-db -U odoo -d odoo_prod '
                 '-c "SELECT count(*) FROM res_partner"', input=(password + '\n').encode(), check=False, timeout=180)
    return proc.returncode == 0 and proc.stdout.decode().strip() == '500'


def inst_templates(dev):
    import subprocess as sp
    files = sorted(path.name for path in (INST_FIXTURE / 'quadlet').iterdir())
    tar = sp.run(['tar', '-C', str(INST_FIXTURE / 'quadlet'), '-cf', '-', *files], capture_output=True, check=True).stdout
    sh(dev, f'set -e; work=$(mktemp -d /var/tmp/woowbk-inst.XXXXXX); tar -C "$work" --no-same-owner -xf -; '
            f'install -d -o root -g root -m 0755 {INST_TEMPLATES} {INST_TEMPLATES}/quadlet; '
            f'install -o root -g root -m 0644 "$work"/* {INST_TEMPLATES}/quadlet/; rm -rf "$work"', input=tar)


def inst_images(dev, ev):
    proc = owner(dev, 'sh', '-c', f'podman image exists {PGVECTOR} || podman pull -q {PGVECTOR}', check=False, timeout=1200)
    ev.require(f'dev-{dev}: {PGVECTOR} available', proc.returncode == 0, proc.stderr.decode()[-300:])
    proc = owner(dev, 'podman', 'image', 'exists', 'localhost/woowbk-demo-app:1', check=False)
    ev.require(f'dev-{dev}: localhost/woowbk-demo-app:1 available (woowbk-demo deployed)', proc.returncode == 0)


def inst_deploy(dev, ev):
    """Deploy woowbk-inst on dev-a as the owner and fill the cluster; returns the odoo password (memory only)."""
    owner(dev, 'sh', '-c', INST_TEARDOWN, timeout=600)
    owner(dev, 'sh', '-c', 'set -e; for n in woowbk-inst-db-password woowbk-inst-app-key; do '
                           'head -c 24 /dev/urandom | base64 | tr -d "\\n/+=" | podman secret create "$n" - >/dev/null; done')
    for name in sorted(path.name for path in (INST_FIXTURE / 'quadlet').iterdir()):
        owner(dev, 'sh', '-c', f'umask 022; cat > "$HOME/.config/containers/systemd/{name}"',
              input=(INST_FIXTURE / 'quadlet' / name).read_bytes())
    owner(dev, 'systemctl', '--user', 'daemon-reload')
    owner(dev, 'systemctl', '--user', 'start', 'woowbk-inst-db.service', timeout=900)
    deadline = time.monotonic() + 180
    while owner(dev, 'podman', 'exec', 'woowbk-inst-db', 'pg_isready', '-h', '127.0.0.1', '-U', 'ncadmin', '-d', 'ncadmin',
                check=False).returncode != 0:
        if time.monotonic() > deadline:
            raise Failed('woowbk-inst-db did not become ready')
        time.sleep(2)
    oc, odoo = secrets.token_hex(16), secrets.token_hex(16)
    inst_psql(dev, INST_SETUP_SQL.format(oc=oc, odoo=odoo))
    # The app's own copy of its database password (Nextcloud keeps it in config.php in its volume).
    owner(dev, 'podman', 'run', '--rm', '-i', '--memory', '32m', '-v', 'woowbk-inst-files:/data', '--entrypoint', 'sh',
          'docker.io/library/postgres:16-alpine', '-c', 'mkdir -p /data/config && umask 077 && cat > /data/config/dbpassword',
          input=oc.encode())
    owner(dev, 'systemctl', '--user', 'start', 'woowbk-inst-app.service', timeout=600)
    ev.require(f'dev-{dev}: woowbk-inst app healthy (logged in as oc_admin)', inst_healthy(dev, 240))
    for n in range(5):
        inst_post_note(dev, f'執行個體筆記 {n}')
    return odoo


def inst_entry(dev, ev):
    """The generator's instance-mode draft of woowbk-inst plus what an administrator adds in the editor: the
    deployment templates (fresh restores elsewhere), the app's own summary check and its health URL."""
    _reply, draft = suggestion(dev, ev, INST)
    ev.save(f'inst-draft-{dev}', draft)
    ev.require(f'dev-{dev}: a draft for woowbk-inst with an instance variant', draft and any(
        v['id'] == 'instance' and v['valid'] for v in draft.get('variants') or []), draft and draft.get('variants'))
    db = next((d for d in draft['databases'] if d['kind'] == 'postgres'), {})
    ev.check(f'dev-{dev}: the draft detects PostgreSQL from the pgvector image (user ncadmin, major 16, data volume)',
             db.get('user') == 'ncadmin' and db.get('major') == 16 and (db.get('data') or {}).get('volume') == 'woowbk-inst-pgdata',
             db)
    entry = json.loads(json.dumps(next(v['entry'] for v in draft['variants'] if v['id'] == 'instance')))
    ev.check(f'dev-{dev}: instance variant: scope instance, no database key, postgres-digest + files-digest proposed',
             entry['postgres'][0].get('scope') == 'instance' and 'database' not in entry['postgres'][0]
             and {v.get('type') for v in entry.get('verify', [])} >= {'postgres-digest', 'files-digest'}, entry['postgres'])
    entry['name'] = '示範執行個體模式應用'
    entry['description'] = 'PostgreSQL 整個執行個體（角色、密碼雜湊與所有資料庫）的備份還原示範應用'
    entry['quadlet']['template_dir'] = f'{INST_TEMPLATES}/quadlet'
    entry['health'] = [{'type': 'http', 'url': f'{INST_URL}/healthz', 'expect_status': 200, 'timeout_seconds': 180}]
    entry['verify'] = [{'id': 'summary', 'type': 'http-json', 'url': f'{INST_URL}/api/summary',
                        'compare': list(DEMO_COMPARE)}] + [v for v in entry['verify'] if v.get('type') != 'http-json']
    return entry


@scenario('instance')
def scenario_instance(ev):
    """Instance mode with an Odoo-like part (two databases owned by role odoo, C collation, revoked CONNECT, settings,
    comment) and a Nextcloud-like part (database owned by oc_admin, the role the app logs in with, its password only
    in the app's volume; pgvector and pg_trgm with HNSW and GIN indexes) in one cluster: backup with the database
    running, in-place restore on dev-a after damage, fresh restore on dev-b."""
    memory_ok()
    secret = kit_secret()
    for dev in ('a', 'b'):
        inst_templates(dev)
        inst_images(dev, ev)
    owner('b', 'sh', '-c', INST_TEARDOWN, timeout=600)  # dev-b is the fresh target: it never runs the app
    odoo = inst_deploy('a', ev)
    entry = inst_entry('a', ev)
    for dev in ('a', 'b'):
        preview, done = install_entry(dev, ev, entry, f'dev-{dev} woowbk-inst')
        ev.check(f'dev-{dev}: woowbk-inst entry installed (or already this exact entry)',
                 (done and done['installed']) or (preview['current'] and preview['expected_sha256'] == preview['new_sha256']),
                 done or preview['expected_sha256'])
    ev.save('inst-entry', entry)
    ev.check('odoo logs in with its password before the backup', odoo_login('a', odoo))
    before = inst_state('a')
    app_before = inst_summary('a')
    ev.save('inst-state-backup-time', before)
    job, log = backup('a', ev, 'backup[instance]', apps=(INST,))
    ev.require('instance backup succeeded (database kept running)', job['state'] == 'succeeded', job.get('error'))
    ev.check('backup log: the whole instance was exported (every database, every role)', lines(log, '的整個執行個體'),
             lines(log, '匯出資料庫', '資料摘要'))
    ev.check('the database unit was never stopped by the backup', not lines(log, '暫停寫入服務 woowbk-inst-db'))
    backup_id = job['result']['backup_id']
    inspect = ok('a', 'inspect', {'backup_id': backup_id}, ev=ev)
    ev.save('inst-inspect', inspect)
    pg = inspect['manifest']['apps'][0]['postgres'][0]
    owners = {d['name']: d['owner'] for d in pg.get('databases') or []}
    ev.check('manifest: scope instance, every database with its owner, roles counted',
             pg.get('scope') == 'instance' and owners.get('nextcloud') == 'oc_admin' and owners.get('odoo_prod') == 'odoo'
             and owners.get('odoo_test') == 'odoo' and pg.get('roles_count', 0) >= 4, pg)
    # Damage everything single-database mode would lose.
    inst_psql('a', f"ALTER ROLE odoo PASSWORD '{secrets.token_hex(16)}'", 'postgres')
    inst_psql('a', 'DROP DATABASE odoo_test', 'postgres')
    inst_psql('a', 'DELETE FROM oc_embeddings WHERE id % 7 = 0', 'nextcloud')
    inst_psql('a', 'CREATE DATABASE added_later', 'postgres')
    inst_psql('a', "CREATE ROLE intruder LOGIN PASSWORD 'x'", 'postgres')
    inst_post_note('a', '備份後的筆記')
    ev.check('instance changed after the backup, odoo\'s old password no longer works',
             inst_state('a') != before and not odoo_login('a', odoo))
    inspect = ok('a', 'inspect', {'backup_id': backup_id}, ev=ev)
    checks = {c['id'].split('/', 1)[1]: c for a in inspect['preflight']['apps'] for c in a['checks']}
    ev.save('inst-preflight', checks)
    ev.check('preflight: instance ok, the database added later is named (it goes), vector/pg_trgm available',
             checks.get('instance', {}).get('status') == 'ok'
             and 'added_later' in checks.get('databases', {}).get('message', '')
             and checks.get('extensions', {}).get('status') == 'ok', checks)
    rjob, rlog = restore('a', ev, backup_id, 'restore[instance-inplace]', apps=(INST,))
    ev.require('instance in-place restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
    after = inst_state('a')
    ev.save('inst-state-after-inplace', after)
    for key in before:
        ev.check(f'in place: {key} equal to the backup time', after[key] == before[key],
                 {'before': before[key][:300], 'after': after[key][:300]})
    ev.check('in place: odoo logs in again with its backed-up password', odoo_login('a', odoo))
    ev.check('in place: the app (oc_admin) is healthy and its summary equals the backup', inst_healthy('a')
             and inst_summary('a') == app_before)
    digests = checks_of(rjob, INST)[0]
    db_check = next((c for c in digests.values() if c['type'] == 'postgres-digest'), {})
    # The digest compares every role except the connecting (bootstrap) superuser, whose hash the restore reconciles.
    ev.check('in place: the instance digest (5 databases, 3 roles besides the bootstrap superuser) matches',
             db_check.get('match') is True and (db_check.get('before') or {}).get('databases') == 5
             and (db_check.get('before') or {}).get('roles') == 3 and db_check.get('before') == db_check.get('after'),
             db_check)
    ev.check('in place: the HNSW index came back valid and the planner uses it', hnsw_used('a'), after.get('indexes'))
    ev.check('in place: bootstrap superuser reconciled, not recreated', bool(lines(rlog, '只更新它的屬性與密碼')),
             lines(rlog, '角色')[:3])
    # Cross-device: dev-b has the entry and templates, never had the app.
    local, info = download('a', ev, backup_id, 'instance')
    reply = upload('b', ev, local, info['filename'])
    local.unlink(missing_ok=True)
    ev.require('dev-b: upload accepted', reply.get('ok'), reply.get('error'))
    remember('b', backup_id)
    inspect_b = ok('b', 'inspect', {'backup_id': backup_id, 'key': secret}, ev=ev)
    pf = inspect_b['preflight']['apps'][0]
    ev.save('inst-preflight-b', pf)
    ev.check('dev-b preflight: fresh and restorable', pf['mode'] == 'fresh' and pf['restorable'], pf)
    rjob, _rlog = restore('b', ev, backup_id, 'restore[instance-fresh-b]', apps=(INST,), key=secret)
    ev.require('dev-b fresh instance restore succeeded', rjob['state'] == 'succeeded', rjob.get('error'))
    after_b = inst_state('b')
    ev.save('inst-state-after-b', after_b)
    for key in before:
        ev.check(f'dev-b: {key} equal to the dev-a backup', after_b[key] == before[key],
                 {'before': before[key][:300], 'after': after_b[key][:300]})
    ev.check('dev-b: odoo logs in with the backed-up password', odoo_login('b', odoo))
    ev.check('dev-b: the app (oc_admin) is healthy and its summary equals the backup', inst_healthy('b')
             and inst_summary('b') == app_before)
    digests = checks_of(rjob, INST)[0]
    ev.check('dev-b: postgres-digest and files-digest match', all(c.get('match') is True for c in digests.values())
             and len(digests) == 2, {k: c.get('match') for k, c in digests.items()})
    ev.check('dev-b: the HNSW index came back valid and the planner uses it', hnsw_used('b'), after_b.get('indexes'))
    return {'roles': before['roles'].count('\n') + 1}


@scenario('cleanup')
def scenario_cleanup(ev):
    """Delete the backups this driver made, remove the lab app woowbk-inst (deployment, entry, templates, pgvector
    image), put 預設加密備份 and the retention policy back."""
    state = load_state()
    for dev, backup_id in state.get('created', []):
        rc, reply = helper(dev, 'delete', {'backup_id': backup_id}, ev=ev)
        ev.check(f'dev-{dev} {backup_id} deleted or already gone', rc == 0 or reply['error']['code'] == 'not-found',
                 reply.get('error'))
    for dev in ('a', 'b'):
        owner(dev, 'sh', '-c', INST_TEARDOWN, timeout=600, check=False)
        rc, reply = helper(dev, 'catalog-remove', {'id': INST}, ev=ev)
        if rc == 0:
            ok(dev, 'catalog-remove', {'id': INST, 'confirm': True, 'expected_sha256': reply['expected_sha256']}, ev=ev)
        sh(dev, f'rm -rf {INST_TEMPLATES}', check=False)
        owner(dev, 'podman', 'rmi', '-f', PGVECTOR, check=False, timeout=300)
        for item in ok(dev, 'list', ev=ev).get('exports', []):
            ok(dev, 'export-delete', {'export_id': item['export_id']}, ev=ev)
        status = ok(dev, 'status', ev=ev)
        if not status['settings']['encrypt_by_default']:
            ok(dev, 'settings-set', {'encrypt_by_default': True}, ev=ev)
        ok(dev, 'retention-apply', {'confirm': True, 'backup_ids': [], 'policy': DEFAULT_POLICY}, ev=ev)
        status = ok(dev, 'status', ev=ev)
        left = owner(dev, 'sh', '-c', 'podman ps -a --format "{{.Names}}"; podman volume ls -q; ls "$HOME/.config/containers/systemd"',
                     check=False).stdout.decode()
        ev.check(f'dev-{dev}: no woowbk-inst leftovers, no active job, staging empty, setting on',
                 'woowbk-inst' not in left and status['active_job'] is None and status['settings']['encrypt_by_default']
                 and sh(dev, 'ls -A /var/lib/woowtech-backup/staging').stdout.strip() == b''
                 and INST not in {a['id'] for a in status['apps']}, left)
    shutil.rmtree(WORK, ignore_errors=True)
    for path in DOWNLOADS.glob('strengthen-*'):
        path.unlink(missing_ok=True)
    STATE.unlink(missing_ok=True)
    return {'deleted': len(state.get('created', []))}

ALL = ['catalog-apply', 'digests', 'mismatch', 'deep', 'instance', 'keyless', 'retention', 'tampered-json']


if __name__ == '__main__':
    sys.exit(main())
