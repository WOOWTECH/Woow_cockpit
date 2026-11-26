#!/usr/bin/env python3
"""R8 preparation: actual Cockpit upload/check/one-confirmation import on dev-d.

No device access, credentials or listener without --run. Requires a reviewed
commit and separate dev-d lease; existing heavy guard and device lock suffice.
Installed source must already equal --source; no deploy/install/pull here.
"""
import argparse
import ast
import copy
import datetime
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
FIXTURE = LAB / 'ha-fixtures/20261119-b1/x86/woow-b1-x86-enc/woow-b1-x86-enc.tar'
FIXTURE_SHA = 'f82422e327f151ec819d8e626011af965e40bf1ac78da3fa7a7bd0f869b69e1d'
BROKEN = 'e2bba4b7_woow-emqx.tar.gz'
BASELINES = {'hermes': '20261119T072434Z-45b29e52', 'omnigent': '20261119T072103Z-ea792b52'}
APPS = ('emqx', 'omnigent', 'hermes')
TIMER = 'woowtech-cockpit-backup-schedule.timer'
LOCK = '/tmp/woowbk-dev-d-mutation.lock'
STATE = LAB / 'run/focus_acceptance_ui.json'
LEASE = Path('/tmp/parity-focus-20261127/lease-r8-dev-d.json')
PLAYWRIGHT = Path('/home/woowtechopenclaw/Woow_cockpit/node_modules/playwright-core/index.mjs')
CHROMIUM = Path.home() / '.cache/ms-playwright/chromium-1208/chrome-linux64/chrome'


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(8 * 1024**2), b''):
            digest.update(chunk)
    return digest.hexdigest()


def derive(source, destination):
    """Copy real outer members; only the EMQX encrypted payload loses64bytes."""
    if source.resolve() == destination.resolve():
        raise ValueError('original fixture cannot be overwritten')
    with destination.open('xb') as handle:
        os.chmod(destination, 0o600)
        with tarfile.open(source, 'r:') as original, tarfile.open(fileobj=handle, mode='w') as changed:
            names = []
            for info in original:
                if not info.isfile() or info.name in names:
                    raise ValueError('unexpected original outer member')
                names.append(info.name)
                member = copy.copy(info)
                if info.name == BROKEN:
                    if info.size <= 128:
                        raise ValueError('EMQX member too small')
                    member.size -= 64
                with original.extractfile(info) as data:
                    changed.addfile(member, data)
            if len(names) != 6 or names.count(BROKEN) != 1:
                raise ValueError('unexpected full HA fixture layout')
    with tarfile.open(source, 'r:') as original, tarfile.open(destination, 'r:') as changed:
        for before, after in zip(original, changed):
            if before.name != after.name or after.size != before.size - (64 if before.name == BROKEN else 0):
                raise ValueError('derived outer layout differs')
            with original.extractfile(before) as left, changed.extractfile(after) as right:
                remaining = after.size
                while remaining:
                    size = min(8 * 1024**2, remaining)
                    if left.read(size) != right.read(size):
                        raise ValueError('derived member bytes differ')
                    remaining -= size


def marker_program(source):
    # Reuse the actual read-only R1 marker logic, intercept every EMQX login's
    # issued token before it can be forgotten. Values travel in the private pipe
    # only, then are registered before any probe output is saved.
    tree = ast.parse(source)
    last = tree.body.pop()
    if not (isinstance(last, ast.Expr) and isinstance(last.value, ast.Call)
            and isinstance(last.value.func, ast.Name) and last.value.func.id == 'print'):
        raise ValueError('marker producer changed; review required')
    return ast.unparse(tree) + '''
issued = []
original_http = http
def observed_http(method, url, *args, **kwargs):
    result = original_http(method, url, *args, **kwargs)
    if method == "POST" and url.endswith("/api/v5/login"):
        token = result[1].get("token")
        if not isinstance(token, str) or len(token) < 6:
            raise RuntimeError("issued value missing")
        issued.append(token)
    return result
http = observed_http
found = HANDLERS[(APP, ACTION)]()
print(json.dumps({"markers": found, "issued": issued}))
'''


def chain_complete(records):
    return (len(records) == 4 and [j.get('type') for j in records] == ['backup', 'restore', 'backup', 'restore']
            and all(j.get('state') == 'succeeded' for j in records)
            and {r.get('app_id'): r.get('status') for r in
                 ((records[-1].get('result') or {}).get('group') or {}).get('results', [])}
            == {'hermes': 'imported', 'omnigent': 'imported'})


def stable_units(rows, properties):
    """Scheduled nonpersistent probes naturally return inactive between ticks.

    Keep every application service and timer, including persistent oneshot setup
    units. Only Type=oneshot + RemainAfterExit=no probes have no durable active
    state to preserve. Unknown metadata never relaxes the active-service gate.
    """
    result={}
    for row in rows:
        name=row['unit']
        if not name.startswith(('hermes-','omnigent-','emqx.','emqx-')) or not name.endswith(('.service','.timer')):
            continue
        kind=properties.get(name,{})
        if name.endswith('.service') and kind.get('Type')=='oneshot' and kind.get('RemainAfterExit')=='no':
            continue
        result[name]=[row['active'],row['sub']]
    return result


def scan_program(needle_source):
    """Strict current storage roots; index sidecars are in archives/."""
    return 'import json\n' + needle_source + r'''
import json, os, subprocess, sys
req=json.load(sys.stdin)
values=list(req["values"])
for name in req.get("podman_secrets",[]):
    p=subprocess.run(["/usr/local/bin/woowbk-owner","podman","secret","inspect","--showsecret","--format","{{.SecretData}}",name],capture_output=True,check=True)
    values.append(p.stdout.rstrip(b"\n"))
needles=secret_scan_needles(values)
hits=scanned=index_sidecars=0
base="/var/lib/woowtech-backup/"
def walk_error(error): raise RuntimeError("scan enumeration failed") from None
for root in [base+x for x in ("jobs","ha-backups","ha-imports.json","requests.json","archives","uploads","staging","pending","exports")]+["/run/woowtech-backup"]:
    if not os.path.exists(root) or os.path.islink(root): raise RuntimeError("scan root unsafe")
    paths=[root] if os.path.isfile(root) else []
    for d,dirs,files in os.walk(root,onerror=walk_error,followlinks=False):
        if any(os.path.islink(os.path.join(d,x)) for x in dirs): raise RuntimeError("scan path unsafe")
        paths.extend(os.path.join(d,x) for x in files)
    for p in paths:
        if os.path.islink(p): raise RuntimeError("scan path unsafe")
        if p.endswith(".tar") and ("/archives/" in p or "/ha-backups/" in p): continue
        data=open(p,"rb").read(); scanned+=1
        if "/archives/" in p and p.endswith(".json"): index_sidecars+=1
        hits+=sum(data.count(x) for x in needles)
j=subprocess.run(["journalctl","--no-pager","-o","cat","--since","@%d"%req["since"]],capture_output=True,check=True).stdout
hits+=sum(j.count(x) for x in needles)
print(json.dumps({"scanned":scanned,"hits":hits,"journal_bytes":len(j),"archive_index_sidecars_scanned":index_sidecars}))
'''


def verified_recovery(guard, proof, expected_sha, evidence_root=LAB/'evidence'):
    """Read the reviewed independent receipt; never rewrite the failed case."""
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha or ''):
        raise ValueError('explicit reviewed recovery receipt SHA required')
    proof = Path(proof)
    if (proof.is_symlink() or proof.name != 'receipt.json'
            or proof.parent.parent != evidence_root/'focus-acceptance-ui-recovery'
            or proof.resolve() != proof.absolute()
            or proof.stat().st_uid != os.getuid() or proof.stat().st_mode & 0o077):
        raise ValueError('private independent recovery receipt path or mode invalid')
    raw = proof.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError('independent recovery receipt SHA mismatch')
    old = json.loads(guard)
    facts = json.loads(raw)
    case = Path(old['evidence_dir'])
    if (case.parent != evidence_root/'focus-acceptance-ui' or case.resolve() != case.absolute()
            or old.get('phase') != 'recovery-retained' or old.get('baseline_restored') is not True
            or old.get('inflight') or len(set(old.get('created_backups', []))) != 6):
        raise ValueError('failed case does not match recovery-only scope')
    required = ('data_recovery_verified', 'original_markers_equal', 'original_units_equal',
                'original_images_equal', 'original_timer_equal', 'original_catalog_equal',
                'original_fixture_hash_equal', 'network_isolation_preserved', 'old_ha_retained',
                'old_captures_unchanged', 'old_guard_unchanged', 'old_summary_unchanged',
                'scan_covers_archive_index_sidecars', 'scan_covers_requests_pending_exports')
    scan = facts.get('scan', {})
    if (facts.get('scope') != 'r8-independent-recovery-only'
            or any(facts.get(key) is not True for key in required)
            or facts.get('acceptance_passed') is not False
            or facts.get('guard_override_performed') is not False
            or facts.get('cookie_coverage_of_old_attempt') is not False
            or facts.get('old_cookie_coverage') != 'absent-not-retroactively-proved'
            or facts.get('active_jobs') != 0 or facts.get('old_archives_retained') != 6
            or scan.get('hits') != 0 or scan.get('scanned', 0) <= 0
            or scan.get('archive_index_sidecars_scanned', 0) < 6
            or facts.get('source_commit') != old.get('source_commit')
            or facts.get('old_guard_sha256') != hashlib.sha256(guard).hexdigest()
            or facts.get('old_receipt_sha256') != sha(case/'recovery.json')
            or facts.get('old_summary_sha256') != sha(case/'summary.json')):
        raise ValueError('independent data recovery facts do not match protected case')
    return old, {'path': str(proof), 'sha256': expected_sha,
                 'old_guard_sha256': facts['old_guard_sha256'], 'acceptance_passed': False}


def ha_record_owned(records, ha_id, digest, previous=None):
    """A deduplicated retained upload is existing data, never this run's own."""
    matches = [row for row in records if row.get('id') == ha_id]
    if ha_id != 'ha-'+digest[:20] or len(matches) > 1:
        raise ValueError('derived HA identity invalid')
    if not matches:
        return True
    if (previous is None or previous.get('ha_id') != ha_id
            or previous.get('derived_fixture_sha256') != digest
            or matches[0].get('sha256') != digest):
        raise ValueError('existing HA record lacks exact recovered ownership proof')
    return False

def run(source, recovery_proof=None, recovery_proof_sha256=None):
    sys.path.insert(0, str(HERE))
    import ha_import_e2e as h
    import ha_import_b1_e2e as b1
    from focus_acceptance_ui_relay import Relay
    h.DEVICE = 'woowbk-dev-d'
    h.require_isolated_device()  # before credentials or mutation lock
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError('dev-d mutation lock busy') from None
    os.umask(0o077)
    previous = provenance = None
    prior_guard = STATE.read_bytes() if STATE.exists() else None
    try:
        lease = json.loads(LEASE.read_text())
        pinned = subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
        if (lease['device'] != h.DEVICE or Path(lease['source']).resolve() != source
                or not pinned.startswith(lease['source_commit'])
                or (datetime.datetime.fromisoformat(lease['expires'])-datetime.datetime.now(datetime.timezone.utc)).total_seconds() < 45*60):
            raise ValueError('current exact R8 device/source lease needs45minutes for flow and recovery')
        pending = prior_guard is not None and json.loads(prior_guard).get('recovery_verified') is not True
        if pending:
            if not recovery_proof:
                raise ValueError('previous R8 recovery pending; explicit verified receipt required')
            previous, provenance = verified_recovery(prior_guard, recovery_proof, recovery_proof_sha256)
        elif recovery_proof or recovery_proof_sha256:
            raise ValueError('independent recovery proof does not match a pending failed case')
    except Exception:
        os.close(fd)
        raise
    secrets = b1.Secrets([LAB/'secrets/b1-creds.env', LAB/'secrets/ha-import-creds.env'], LAB/'secrets/dev-d-markers.json')
    secrets.redact_tree = secrets.redact_structure
    secrets.register('COCKPIT_PASSWORD', (LAB/'secrets/devadmin.pass').read_text().strip())
    secrets.register('DEV_D_KIT', (LAB/'secrets/dev-d-kit.txt').read_text().strip())
    class Evidence(h.Evidence):
        def log(self, text):
            with self.log_path.open('a', encoding='utf-8') as handle:
                handle.write(time.strftime('%H:%M:%S')+' '+self.secrets.redact(str(text))+'\n')

        def check(self, name, condition, detail=''):
            result = super().check(name, condition, detail)
            print(name+(': PASS' if result else ': FAIL'), flush=True)
            return result

    ev = Evidence(secrets, 'focus-acceptance-ui')
    started = int(time.time()) - 1
    receipt = {'device': h.DEVICE, 'phase': 'preconditions', 'created_backups': [], 'ha_id': None,
               'ha_record_owned': False, 'catalog_added': False, 'baseline_restored': False,
               'driver_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip()}
    before = {}
    before_backups = before_uploads = before_jobs = None
    original_catalog = original_units = original_images = original_timer = None
    records = []
    derived = ev.dir/'full-ha-corrupt-emqx.tar'
    timer_changed = False
    safe = False
    uploaded = False
    state_armed = False
    recovery_deadline = None
    if provenance:
        receipt['previous_independent_recovery'] = provenance
        receipt['protected_existing_backups'] = previous['created_backups']
        # Preserve the pointer bytes in the NEW private case before any approved
        # new state can replace it. Old case files remain byte-identical.
        with (ev.dir/'previous-guard.json').open('xb') as handle:
            handle.write(prior_guard)

    def save():
        ev.save('recovery.json', receipt)
        if not state_armed:
            return
        with os.fdopen(os.open(STATE,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600),'w') as handle:
            json.dump(dict(receipt,evidence_dir=str(ev.dir)),handle)

    def require(name, condition):
        if not ev.check(name, condition):
            raise h.Failed(name)

    def ok(command, request=None, timeout=120):
        return h.ok(command, request, ev=ev, timeout=timeout)

    def root_json(script, request=None):
        proc = h.root('python3', '-I', '-c', script,
                      input=json.dumps(request or {}).encode(), timeout=180)
        if proc.returncode:
            raise h.Failed('fixed device probe failed')
        return json.loads(proc.stdout)

    def resources(peak_gib=8):
        mem = root_json('from pathlib import Path; import json; s=Path("/sys/fs/cgroup/memory.stat").read_text().splitlines(); used=sum(int(x.split()[1]) for x in s if x.startswith(("anon ","kernel "))); print(json.dumps(int(Path("/sys/fs/cgroup/memory.max").read_text())-used))')
        host = next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
        stat = os.statvfs(REPO)
        require('resources: device headroom at least1900MiB', mem >= 1900*1024**2)
        require('resources: host available memory at least1200MiB', host >= 1200*1024)
        require('resources: host keeps13GiB plus bounded phase writes', stat.f_bavail*stat.f_frsize >= (13+peak_gib)*1024**3)

    def catalog():
        return root_json('import hashlib,json; from pathlib import Path; p=Path("/etc/woowtech-cockpit/backup/apps"); print(json.dumps({x.name:hashlib.sha256(x.read_bytes()).hexdigest() for x in p.glob("*.json")}))')

    def units():
        proc = h.owner('systemctl', '--user', 'list-units', '--all', '--output=json', '--no-pager', timeout=60)
        if proc.returncode:
            raise h.Failed('unit state probe failed')
        rows=json.loads(proc.stdout)
        names=[x['unit'] for x in rows if x['unit'].startswith(('hermes-','omnigent-','emqx.','emqx-')) and x['unit'].endswith('.service')]
        meta=h.owner('systemctl','--user','show','--property=Id,Type,RemainAfterExit','--',*names,timeout=60)
        if meta.returncode:
            raise h.Failed('unit type probe failed')
        properties={}
        for block in meta.stdout.decode().strip().split('\n\n'):
            fields=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
            if fields.get('Id'):
                properties[fields['Id']]=fields
        return stable_units(rows,properties)

    def images():
        proc = h.owner('podman', 'ps', '--format', '{{.Names}} {{.ImageID}}', timeout=60)
        if proc.returncode:
            raise h.Failed('image config probe failed')
        return dict(line.split() for line in proc.stdout.decode().splitlines())

    def timer():
        proc = h.root('systemctl', 'show', TIMER, '--property=UnitFileState,ActiveState', timeout=60)
        if proc.returncode:
            raise h.Failed('schedule state probe failed')
        return dict(x.split('=', 1) for x in proc.stdout.decode().splitlines())

    marker = marker_program((HERE/'batch1_markers.py').read_text())

    def markers(app):
        proc = h.owner('python3', '-I', '-c', marker, app, 'read', input=b'{}', timeout=180)
        if proc.returncode:
            raise h.Failed('read-only marker probe failed')
        reply = json.loads(proc.stdout)
        secrets.register_issued(reply['issued'])
        if app == 'emqx' and not reply['issued']:
            raise h.Failed('EMQX marker token issuance not observed')
        return reply['markers']

    def remember(job):
        for key in ('backup_id', 'safety_backup_id'):
            bid = (job.get('result') or {}).get(key)
            if bid and before_backups is not None and bid not in before_backups and bid not in receipt['created_backups']:
                receipt['created_backups'].append(bid)
        save()

    def wait(job_id):
        remaining = 600 if recovery_deadline is None else min(600,int(recovery_deadline-time.monotonic()))
        if remaining <= 0:
            raise h.Failed('bounded recovery budget exhausted; retain copies')
        return h.wait_job(job_id,ev=ev,timeout=remaining)

    def follow(first):
        chain, seen = [], set()
        current = first
        while current:
            if current in seen or len(chain) >= 4:
                raise h.Failed('unexpected R8 chain layout')
            seen.add(current)
            receipt['inflight'] = current
            save()
            job = wait(current)
            chain.append(job)
            receipt['chain_job_ids']=[j['id'] for j in chain]
            remember(job)
            current = ((job.get('result') or {}).get('group') or {}).get('next_job_id')
        receipt['inflight'] = None
        save()
        return chain

    # Same strict scan for static/moved values and the Cockpit cookie scan, using
    # the existing encoded-needle builder. Only counts return from the device.
    scan = scan_program(inspect.getsource(b1.secret_scan_needles))
    try:
        save()
        require('source: both reviewed checkouts clean', all(not subprocess.check_output(['git','-C',str(p),'status','--porcelain','--untracked-files=no'], text=True).strip() for p in (source, REPO)))
        require('fixture: original recorded full encrypted HA hash matches', FIXTURE.is_file() and sha(FIXTURE) == FIXTURE_SHA)
        require('browser: existing package and Chromium ready', PLAYWRIGHT.is_file() and CHROMIUM.is_file())
        resources()
        installed = root_json(__import__('focus_acceptance_n8n').ENGINE_HASHES)
        lib = source/'backup-engine/woowbackup'
        require('source: installed helper and every module equal frozen source', installed.get('lib') == {str(p.relative_to(lib)):sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts}
                and installed.get('helper') == sha(source/'backup-engine/woowtech-cockpit-backup'))
        ui = root_json('import hashlib,json; from pathlib import Path; p=Path("/usr/local/share/cockpit/woowtechbackup"); print(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ("backup.js","backup.css","index.html","manifest.json")}))')
        require('source: installed actual page equals frozen source', ui == {n:sha(source/'backup'/n) for n in ui})
        require('Cockpit: existing socket active', h.root('systemctl','is-active','--quiet','cockpit.socket',timeout=60).returncode == 0)
        status = ok('status')
        require('before: no active backup job', not status.get('active_job'))
        original_catalog, original_units, original_images, original_timer = catalog(), units(), images(), timer()
        require('before: app services already active and image configs present', len(original_images) >= 8 and original_units and all(v[0]=='active' for k,v in original_units.items() if k.endswith('.service')))
        require('before: schedule inactive or failed', original_timer.get('ActiveState') in ('inactive','failed'))
        if previous:
            require('replay: original catalog units images and timer still match independent receipt',
                    original_catalog == previous['original_catalog'] and original_units == previous['original_units']
                    and original_images == previous['original_images'] and original_timer == previous['original_timer'])
        receipt.update(original_catalog=original_catalog, original_units=original_units, original_images=original_images, original_timer=original_timer,
                       source_commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip())
        listing=ok('list')
        before_backups={x['id'] for x in listing.get('backups',[])}
        before_uploads={x['id'] for x in listing.get('ha_backups',[])}
        if previous:
            require('replay: all six old archives remain protected existing backups',set(previous['created_backups']) <= before_backups)
            require('replay: old HA record retained at exact derived SHA',
                    any(x['id'] == previous['ha_id'] and x.get('sha256') == previous['derived_fixture_sha256']
                        for x in listing.get('ha_backups',[])))
        before_jobs={x['id'] for x in ok('jobs').get('jobs',[])}
        for app in APPS:
            before[app]=markers(app)
            have=b1.marker_names(before[app])
            require('before: exact original '+app+' marker baseline', have == b1.BASELINE_MARKERS[app])
            if previous:
                require('replay: exact recovered original '+app+' markers still match',before[app] == previous['before_markers'][app])
            ev.save('before-'+app+'.json',before[app])
        receipt['before_markers']=before
        state_armed=True  # fresh originals proved; next phase may add own catalog
        save()
        for app,bid in BASELINES.items():
            pre=ok('inspect',{'backup_id':bid,'key':secrets['DEV_D_KIT']})
            require('before: encrypted '+app+' baseline opens', pre.get('ok') is True)
            if app+'.json' not in original_catalog:
                require('catalog: only missing Omnigent can be added', app=='omnigent')
                carried=next((x.get('settings',{}).get('entry') for x in pre.get('preflight',{}).get('apps',[]) if x.get('id')==app),None)
                require('catalog: trusted carried entry matches appowner', isinstance(carried,dict) and carried.get('id')==app and carried.get('owner')=='appowner')
                preview=ok('catalog-install',{'entry':carried})
                require('catalog: carried entry preview valid', preview.get('valid') is True)
                receipt['catalog_added']=True
                receipt['catalog_expected_sha256']=preview['new_sha256']
                save()  # intent before helper call, so a lost reply retains recovery
                ok('catalog-install',{'entry':carried,'confirm':True,'expected_sha256':preview['expected_sha256']})
            ready=ok('inspect',{'backup_id':bid,'key':secrets['DEV_D_KIT']})
            require('before: '+app+' original baseline restore preflight ready', ready.get('preflight',{}).get('ok') is True)
        if original_timer.get('UnitFileState') not in ('masked','masked-runtime'):
            timer_changed=True
            require('setup: schedule masked as a bounded case', h.root('systemctl','mask',TIMER,timeout=60).returncode==0)
        receipt['phase']='derive-and-ui'
        save()
        derive(FIXTURE,derived)
        receipt['ha_id']='ha-'+sha(derived)[:20]
        receipt['original_fixture_sha256']=FIXTURE_SHA
        receipt['derived_fixture_sha256']=sha(derived)
        receipt['ha_record_owned']=ha_record_owned(listing.get('ha_backups',[]),receipt['ha_id'],receipt['derived_fixture_sha256'],previous)
        require('upload: ownership is new or exact protected retained record',
                receipt['ha_record_owned'] or (previous is not None and receipt['ha_id'] in before_uploads))
        save()
        config={'ha_id':receipt['ha_id'],'fixture':str(derived),'password':secrets['COCKPIT_PASSWORD'],
                'key':secrets['HA_BACKUP_KEY'],'evidence':str(ev.dir),'result':str(ev.dir/'browser.json'),
                'playwright':str(PLAYWRIGHT),'chromium':str(CHROMIUM),'since':started,'cookie_scan':scan}
        resources()
        with Relay() as relay:
            config['base']=relay.base
            proc=subprocess.Popen(['node',str(HERE/'focus_acceptance_ui_page.mjs'),'--run'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                proc.communicate(json.dumps(config).encode(),timeout=20*60)
            except subprocess.TimeoutExpired:
                # SIGTERM lets Playwright close its Chromium children. Never
                # use subprocess.run's immediate SIGKILL on a browser owner.
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.communicate()
                raise h.Failed('bounded page timeout; adopt own jobs before recovery') from None
        require('transport: private relay closed all exec children', not relay.children and not relay.thread.is_alive())
        require('UI: real page completed one bounded flow',proc.returncode==0)
        browser=json.loads((ev.dir/'browser.json').read_text())
        for item in browser['checks']:
            require(item['check'],item['ok'])
        require('UI: browser result and issued-value scan complete',browser['completed'] and browser['issued_values_scanned'])
    except Exception as error:
        ev.check('R8: bounded real page flow completed',False,type(error).__name__)
    finally:
        if not state_armed:
            ev.check('preconditions: old guard retained without device mutation',
                     (STATE.read_bytes() if STATE.exists() else None) == prior_guard)
            receipt['phase']='preconditions-stopped'
            save()
            ev.finish()
            ev.save('summary.json',{'driver_commit':receipt['driver_commit'],'passed':sum(x['ok'] for x in ev.results),
                                   'failed':sum(not x['ok'] for x in ev.results),'baseline_restored':False,
                                   'recovery_verified':False,'previous_guard_unchanged':True,
                                   'commercial_acceptance':'not-complete'})
            os.close(fd)
            print('R8 preconditions stopped; previous failed case retained')
            return 1
        recovery_deadline=time.monotonic()+20*60
        try:
            # Adopt only new jobs for this exact derived HA. This works even if
            # the browser timed out after sending its intent or before saving.
            if receipt['ha_id'] and before_jobs is not None:
                listing=ok('list')
                uploaded=receipt['ha_id'] in {x['id'] for x in listing.get('ha_backups',[])}
                own=[x for x in ok('jobs').get('jobs',[]) if x['id'] not in before_jobs and x.get('params',{}).get('ha_backup_id')==receipt['ha_id']]
                receipt['check_jobs']=[x['id'] for x in own if x.get('type')=='verify']
                save()
                roots=[x for x in own if x.get('type')=='backup' and x.get('params',{}).get('source')=='ha']
                roots.sort(key=lambda x:x['id'])
                if roots:
                    records=follow(roots[0]['id'])
                    ev.check('chain: two real conversions and restores succeeded',chain_complete(records))
                    job_units=root_json('import json,re,sys; from pathlib import Path; ids=json.load(sys.stdin)["ids"]; assert all(re.fullmatch(r"j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",x) for x in ids); p=Path("/var/lib/woowtech-backup/jobs"); print(json.dumps([json.loads((p/(x+".json")).read_text()).get("unit") for x in ids]))',{'ids':[j['id'] for j in records]})
                    ev.check('chain: every job shares the first systemd unit',job_units==['woowtech-backup-'+records[0]['id']+'.service']*len(records))
                    ev.check('chain: each restore has its own safety backup',all(j.get('result',{}).get('safety_backup_id') for j in records if j.get('type')=='restore'))
                    ev.check('live: Hermes HA sessions replaced original marker',markers('hermes').get('session_count',0)>=5 and 'woowbk-lab-baseline' not in markers('hermes').get('sessions',{}))
                    ev.check('live: Omnigent data changed from original baseline',markers('omnigent')!=before['omnigent'])
                # A check may still run after the browser exited. Wait for it,
                # and refuse unknown active jobs before any baseline restore.
                for j in own:
                    if j.get('type')=='verify':
                        wait(j['id'])
                require('recovery: no active job before baseline restore',not ok('status').get('active_job'))
            receipt['phase']='baseline-recovery'
            save()
            for app,bid in BASELINES.items():
                if app not in before:
                    continue
                if markers(app)!=before[app]:
                    resources(2)
                    pre=ok('inspect',{'backup_id':bid,'key':secrets['DEV_D_KIT']}).get('preflight',{})
                    require('recovery: original baseline has no unreviewed confirmation',pre.get('ok') is True and not any(i.get('level') in ('confirm','stop') for a in pre.get('apps',[]) for i in a.get('issues',[])))
                    reply=ok('restore-start',{'backup_id':bid,'apps':[app],'confirm':True,'key':secrets['DEV_D_KIT'],'request_id':h.request_id('focus-ui-'+app+'-baseline')},timeout=300)
                    receipt['inflight']=reply['job_id']; save()
                    job=wait(reply['job_id']); remember(job)
                    require('recovery: original '+app+' restore succeeded',job.get('state')=='succeeded')
                    receipt['inflight']=None; save()
                require('recovery: exact original '+app+' markers returned',markers(app)==before[app])
            require('recovery: excluded EMQX unchanged', 'emqx' in before and markers('emqx')==before['emqx'])
            require('recovery: original app unit states and image configs returned',units()==original_units and images()==original_images)
            require('recovery: original full HA fixture hash retained',sha(FIXTURE)==FIXTURE_SHA)
            receipt['baseline_restored']=True
            save()
            report=root_json(scan,{'values':secrets.secret_values(),'since':started,'podman_secrets':[
                'omnigent-postgres-password','omnigent-admin-password','omnigent-runner-password',
                'hermes-api-server-key','hermes-webhook-secret','hermes-dashboard-session-secret','hermes-dashboard-password',
                'hermes-postgres-password','woow-emqx-dashboard-password','woow-emqx-node-cookie','woow-emqx-mqtt-password']})
            ev.save('leaks.json',report)
            # The encrypted child archive contains secrets by design. Scan all
            # other artifacts, including the browser's fixed-field result.
            host_hits=0
            needles=b1.secret_scan_needles(secrets.secret_values())
            for p in ev.dir.iterdir():
                if p.is_file() and p!=derived:
                    data=p.read_bytes(); host_hits+=sum(data.count(v) for v in needles)
            require('leaks: registered and observed values absent from records journal and text evidence',
                    report['hits']==0 and report['scanned']>0 and host_hits==0
                    and report['archive_index_sidecars_scanned'] >= len(before_backups)+len(receipt['created_backups']))
            browser_file=ev.dir/'browser.json'
            require('leaks: browser issued-value scan completed before deletion',browser_file.is_file() and json.loads(browser_file.read_text()).get('issued_values_scanned') is True)
            after={x['id'] for x in ok('list').get('backups',[])}
            require('recovery: backup inventory contains no untracked new archive', before_backups is not None and after-before_backups==set(receipt['created_backups']))
            safe=True
            receipt['phase']='owned-cleanup'; save()
            if receipt['catalog_added']:
                current=catalog()
                require('catalog: only own new entry changed', {k:v for k,v in current.items() if k!='omnigent.json'}==original_catalog)
                preview=ok('catalog-remove',{'id':'omnigent'})
                require('catalog: remove matches own installed entry',preview.get('expected_sha256')==receipt['catalog_expected_sha256'])
                ok('catalog-remove',{'id':'omnigent','confirm':True,'expected_sha256':preview['expected_sha256']})
            require('recovery: original catalog hashes returned',catalog()==original_catalog)
            for bid in receipt['created_backups']:
                ok('delete',{'backup_id':bid})
            if uploaded and receipt['ha_record_owned']:
                ok('ha-delete',{'ha_backup_id':receipt['ha_id'],'confirm':True})
            derived.unlink(missing_ok=True)
            h.scenario_cleanup(ev,None)
            require('cleanup: original backup inventory retained',{x['id'] for x in ok('list').get('backups',[])}==before_backups)
            retained_uploads=ok('list').get('ha_backups',[])
            require('cleanup: original HA inventory retained',{x['id'] for x in retained_uploads}==before_uploads)
            if previous:
                require('cleanup: protected old HA remains at exact derived SHA',
                        any(x['id']==previous['ha_id'] and x.get('sha256')==previous['derived_fixture_sha256'] for x in retained_uploads))
        except Exception as error:
            safe=False
            ev.check('recovery: copies and receipt retained on uncertainty',False,type(error).__name__)
        try:
            if timer_changed:
                require('recovery: own schedule mask removed',h.root('systemctl','unmask',TIMER,timeout=60).returncode==0)
            if original_timer is not None:
                require('recovery: original schedule state returned',timer()==original_timer)
            h.require_isolated_device()
            require('after: networknone and zero published ports preserved',True)
        except Exception as error:
            safe=False
            ev.check('after: timer and isolation verified',False,type(error).__name__)
        receipt['phase']='complete' if safe else 'recovery-retained'
        receipt['recovery_verified']=safe
        save()
        good=ev.finish()
        ev.save('summary.json',{'source_commit':receipt.get('source_commit'),'driver_commit':receipt['driver_commit'],
                               'passed':sum(x['ok'] for x in ev.results),'failed':sum(not x['ok'] for x in ev.results),
                               'baseline_restored':receipt['baseline_restored'],'recovery_verified':safe,
                               'commercial_acceptance':'not-complete'})
        os.close(fd)
        print('R8 real Cockpit: '+str(sum(x['ok'] for x in ev.results))+'/'+str(len(ev.results))+(' PASS' if good and safe else ' FAIL'))
    return 0 if good and safe else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--source',type=Path,default=REPO)
    parser.add_argument('--recovery-proof',type=Path)
    parser.add_argument('--recovery-proof-sha256')
    args=parser.parse_args(argv)
    if not args.run:
        for p in (Path(__file__),HERE/'focus_acceptance_ui_relay.py'):
            compile(p.read_text(),str(p),'exec')
        print('R8 controller prepared: offline syntax PASS; review and dev-d lease required')
        return 0
    return run(args.source.resolve(),args.recovery_proof,args.recovery_proof_sha256)


if __name__=='__main__':
    raise SystemExit(main())
