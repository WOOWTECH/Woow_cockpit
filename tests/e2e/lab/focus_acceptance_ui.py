#!/usr/bin/env python3
"""R8 preparation: actual Cockpit upload/check/one-confirmation import on dev-d.

No device access, credentials or listener without --run. Requires a reviewed
commit and separate dev-d lease; existing heavy guard and device lock suffice.
Installed source must already equal --source; no deploy/install/pull here.
--page-emqx: the same real page imports only EMQX from the ORIGINAL B1 backup
under its own lease and guard (focus_acceptance_ui_page_emqx.py).
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
# Read-only installed SourcePath/ContainerName proof: r8-attempt2-scope-metadata.
# Every selected app container is mandatory; unrelated services stay outside R8.
IMAGE_UNITS = {'emqx-entrance.service':'woow-emqx-entrance', 'emqx.service':'woow-emqx',
               'hermes-agent.service':'hermes-agent', 'hermes-postgres.service':'hermes-postgresql',
               'hermes-redis.service':'hermes-redis', 'omnigent-postgres.service':'omnigent-postgres',
               'omnigent-runner.service':'omnigent-runner', 'omnigent-server.service':'omnigent-server'}
HEALTH_TIMER = 'omnigent-server-health.timer'
HEALTH_PROBE = 'omnigent-server-health.service'


def project_images(images, bindings):
    """Select all eight containers from their exact trusted installed Quadlets."""
    if set(bindings) != set(IMAGE_UNITS):
        raise ValueError('selected container unit binding incomplete')
    for unit, name in IMAGE_UNITS.items():
        source = '/home/appowner/.config/containers/systemd/'+unit.removesuffix('.service')+'.container'
        if bindings[unit].get('source') != source or bindings[unit].get('container_name') != name:
            raise ValueError('selected trusted Quadlet container binding changed')
        if name not in images or not images[name]:
            raise ValueError('selected container image missing')
    return {name:images[name] for name in IMAGE_UNITS.values()}


def units_equal(current, reference, properties):
    """Only the proven enabled health timer's active phases are equivalent.

    Real read-only sampling observed active/running -> active/waiting. Its
    triggered service is a nonpersistent oneshot. Enablement, ActiveState,
    target/type metadata and every other durable unit state stay strict.
    """
    timer, probe = properties.get(HEALTH_TIMER, {}), properties.get(HEALTH_PROBE, {})
    if (timer.get('Unit') != HEALTH_PROBE or timer.get('UnitFileState') != 'enabled'
            or probe.get('Type') != 'oneshot' or probe.get('RemainAfterExit') != 'no'):
        return False
    left, right = dict(current), dict(reference)
    for states in (left, right):
        state = states.get(HEALTH_TIMER)
        if not state or state[0] != 'active' or state[1] not in ('running', 'waiting'):
            return False
        states[HEALTH_TIMER] = ['active', 'waiting']
    return left == right


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


def scan_paths(root):
    """A required JSON file is read directly; only directories are walked."""
    if not os.path.exists(root) or os.path.islink(root):
        raise RuntimeError('scan root unsafe')
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        raise RuntimeError('scan root nonregular')
    def walk_error(error):
        raise RuntimeError('scan enumeration failed') from None
    paths=[]
    for directory, dirs, files in os.walk(root,onerror=walk_error,followlinks=False):
        if any(os.path.islink(os.path.join(directory,name)) for name in dirs):
            raise RuntimeError('scan path unsafe')
        paths.extend(os.path.join(directory,name) for name in files)
    return paths


def scan_program(needle_source):
    """Strict current storage roots; index sidecars are in archives/."""
    return 'import json, os\n' + needle_source + '\n' + inspect.getsource(scan_paths) + r'''
import json, os, subprocess, sys
req=json.load(sys.stdin)
values=list(req["values"])
for name in req.get("podman_secrets",[]):
    p=subprocess.run(["/usr/local/bin/woowbk-owner","podman","secret","inspect","--showsecret","--format","{{.SecretData}}",name],capture_output=True,check=True)
    values.append(p.stdout.rstrip(b"\n"))
needles=secret_scan_needles(values)
hits=scanned=index_sidecars=json_roots=0
base="/var/lib/woowtech-backup/"
for root in [base+x for x in ("jobs","ha-backups","ha-imports.json","requests.json","archives","uploads","staging","pending","exports")]+["/run/woowtech-backup"]:
    for p in scan_paths(root):
        if os.path.islink(p): raise RuntimeError("scan path unsafe")
        if p.endswith(".tar") and ("/archives/" in p or "/ha-backups/" in p): continue
        data=open(p,"rb").read(); scanned+=1
        if p in (base+"ha-imports.json",base+"requests.json"): json_roots+=1
        if "/archives/" in p and p.endswith(".json"): index_sidecars+=1
        hits+=sum(data.count(x) for x in needles)
j=subprocess.run(["journalctl","--no-pager","-o","cat","--since","@%d"%req["since"]],capture_output=True,check=True).stdout
hits+=sum(j.count(x) for x in needles)
print(json.dumps({"scanned":scanned,"hits":hits,"journal_bytes":len(j),"archive_index_sidecars_scanned":index_sidecars,"regular_json_roots_scanned":json_roots}))
'''


def verified_recovery(guard, proof, expected_sha, evidence_root=LAB/'evidence'):
    """Read the reviewed independent receipt; never rewrite the failed case."""
    if expected_sha == '420b9d4fe582af93eef3aa37b958d6b71b57a0580e8775eda39c0478720490fb':
        from focus_acceptance_ui_parent_recovery import verify
        return verify(guard, proof, expected_sha, evidence_root)
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
    declared=set(old['created_backups'])|set(old.get('protected_existing_backups',[]))
    retained=set(facts.get('retained_case_archive_ids',declared))
    pruned={p['id'] for p in facts.get('old_case_safety_pruning',[])}
    if (not set(old['created_backups'])<=retained or retained&pruned or retained|pruned!=declared
            or pruned-{'20261126T225103Z-3036ed2b','20261126T224900Z-4f1206af'}):
        raise ValueError('retained/pruned prior test archive accounting invalid')
    return old, {'path': str(proof), 'sha256': expected_sha,
                 'old_guard_sha256': facts['old_guard_sha256'], 'acceptance_passed': False,
                 'retained_case_archive_ids':sorted(retained)}


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


def case_safety_prunes(before, after, owned_prior, captured_jobs):
    """Explain only prior OWN test safety copies pruned by actual successful jobs.

    No missing manual backup, original lab baseline, unknown archive or failed
    deletion is accepted. Product retention itself is neither changed nor pinned.
    """
    missing=set(before)-set(after)
    if any(bid not in set(owned_prior) or before[bid].get('type')!='safety'
           or bid in BASELINES.values() for bid in missing):
        raise ValueError('unexplained original backup loss')
    proof=[]
    for bid in sorted(missing):
        matches=[]
        for name,raw in captured_jobs.items():
            doc=json.loads(raw);job=doc.get('job',{})
            if (job.get('state')=='succeeded' and job.get('type')=='restore'
                    and any(isinstance(line,str) and line.endswith('已刪除較舊的還原前備份 '+bid)
                            for line in doc.get('log',[]))):
                matches.append({'file':name,'sha256':hashlib.sha256(raw).hexdigest(),'job_id':job['id']})
        if not matches:
            raise ValueError('actual successful safety pruning event missing')
        proof.append({'id':bid,'type':'safety','events':matches})
    return proof

def run(source, recovery_proof=None, recovery_proof_sha256=None, *, helper_three_selected=False, helper_lease_path=None,
        page_emqx=False, page_emqx_lease_path=None):
    sys.path.insert(0, str(HERE))
    import ha_import_e2e as h
    import ha_import_b1_e2e as b1
    if helper_three_selected and page_emqx:
        raise ValueError('one mode per run')
    if helper_three_selected:
        import focus_acceptance_ui_helper as helper
        helper_lease_path = helper_lease_path or Path('/tmp/parity-focus-20261127/lease-r1-helper-dev-d.json')
        helper_lease = json.loads(helper_lease_path.read_bytes())
        helper.validate_lease(helper_lease, subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
            subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(), time.time())
    else:
        from focus_acceptance_ui_relay import Relay
        if page_emqx:
            # Its own lease, checked before any device access (focus_acceptance_ui_page_emqx.validate_lease).
            import focus_acceptance_ui_helper as helper
            import focus_acceptance_ui_page_emqx as pe
            page_emqx_lease_path = page_emqx_lease_path or pe.LEASE
            pe.validate_lease(json.loads(page_emqx_lease_path.read_bytes()),
                subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
                subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip(), source, time.time())
    state_path = LAB/'run/focus_acceptance_r1_helper.json' if helper_three_selected else STATE
    if page_emqx:
        state_path = LAB/'run'/pe.STATE_NAME
    h.DEVICE = 'woowbk-dev-d'
    h.require_isolated_device()  # before credentials or mutation lock
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError('dev-d mutation lock busy') from None
    os.umask(0o077)
    if helper_three_selected and os.path.lexists(state_path):
        os.close(fd)
        raise ValueError('helper guard already exists; preserve it and stop')
    if page_emqx and os.path.lexists(state_path):
        os.close(fd)
        raise ValueError('page-emqx guard already exists; preserve it and stop')
    previous = provenance = None
    prior_guard = state_path.read_bytes() if state_path.exists() else None
    predecessor_guard = prior_guard
    protected_page_files = {}
    page_guard = page_provenance = None
    try:
        lease = json.loads((helper_lease_path if helper_three_selected else page_emqx_lease_path if page_emqx else LEASE).read_text())
        pinned = subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
        if (lease['device'] != h.DEVICE or Path(lease['source']).resolve() != source
                or not pinned.startswith(lease['source_commit'])
                or (datetime.datetime.fromisoformat(lease['expires'])-datetime.datetime.now(datetime.timezone.utc)).total_seconds() < 45*60):
            raise ValueError('current exact R8 device/source lease needs45minutes for flow and recovery')
        if helper_three_selected:
            helper.validate_lease(lease, subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(), pinned, time.time())
            if prior_guard is not None or recovery_proof or recovery_proof_sha256:
                raise ValueError('helper requires a fresh guard; no old helper override')
            predecessor_guard = STATE.read_bytes()
            previous, provenance, protected_page_files = helper.predecessor(lease, predecessor_guard, STATE, LAB/'evidence')
        elif page_emqx:
            pe.validate_lease(lease, subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
                pinned, source, time.time())
            if prior_guard is not None or recovery_proof or recovery_proof_sha256:
                raise ValueError('page-emqx requires a fresh guard; no old override')
            # PAGE5's terminal page guard (bound by the lease) and R1's terminal helper guard that followed it: both stay
            # byte-for-byte; R1's records are the newest original state this case replays against.
            page_guard = STATE.read_bytes()
            _page_old, page_provenance, protected_page_files = helper.predecessor(lease, page_guard, STATE, LAB/'evidence')
            r1_guard_path = LAB/'run'/pe.R1_STATE_NAME
            predecessor_guard = r1_guard_path.read_bytes()
            previous, provenance, protected_r1 = pe.r1_predecessor(lease, predecessor_guard, r1_guard_path, LAB/'evidence')
            protected_page_files = {**protected_page_files, **protected_r1}
        else:
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
    if not helper_three_selected:
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

    ev = Evidence(secrets, 'focus-acceptance-r1-helper' if helper_three_selected else pe.EVIDENCE_AREA if page_emqx else 'focus-acceptance-ui')
    started = int(time.time()) - 1
    receipt = {'device': h.DEVICE, 'phase': 'preconditions', 'created_backups': [], 'ha_id': None,
               'ha_record_owned': False, 'catalog_added': False, 'baseline_restored': False,
               'driver_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip()}
    if page_emqx:
        receipt['mode'] = 'page-emqx'
    # The mode's own baseline and catalog entry; the default R8 case keeps its two baselines and Omnigent's entry.
    baselines = {pe.APP: pe.BASELINE} if page_emqx else BASELINES
    catalog_app, catalog_label = ('emqx', 'EMQX') if page_emqx else ('omnigent', 'Omnigent')
    page_trace = {'mode':'page-emqx','browser_used':True,'completed':False}
    before = {}
    before_backups = before_uploads = before_jobs = None
    original_catalog = original_units = original_images = original_timer = None
    image_sample = 0
    unit_sample = 0
    unit_metadata = {}
    records = []
    derived = ev.dir/'full-ha-corrupt-emqx.tar'
    timer_changed = False
    safe = False
    uploaded = False
    state_armed = False
    recovery_deadline = None
    helper_deadline = None
    helper_trace = {'mode':'helper-three-selected','browser_used':False,'completed':False}
    observed_marker_tokens = []
    if provenance:
        receipt['previous_independent_recovery'] = provenance
        receipt['protected_existing_backups'] = provenance['retained_case_archive_ids']
        # Preserve the pointer bytes in the NEW private case before any approved
        # new state can replace it. Old case files remain byte-identical.
        with (ev.dir/'previous-guard.json').open('xb') as handle:
            handle.write(predecessor_guard)
    if page_provenance:
        receipt['page_guard_provenance'] = page_provenance
        with (ev.dir/'previous-page-guard.json').open('xb') as handle:
            handle.write(page_guard)

    def save():
        ev.save('recovery.json', receipt)
        if not state_armed:
            return
        with os.fdopen(os.open(state_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600),'w') as handle:
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
        nonlocal unit_sample, unit_metadata
        proc = h.owner('systemctl', '--user', 'list-units', '--all', '--output=json', '--no-pager', timeout=60)
        if proc.returncode:
            raise h.Failed('unit state probe failed')
        rows=json.loads(proc.stdout)
        names=[x['unit'] for x in rows if x['unit'].startswith(('hermes-','omnigent-','emqx.','emqx-')) and x['unit'].endswith(('.service','.timer'))]
        meta=h.owner('systemctl','--user','show','--property=Id,Type,RemainAfterExit,Unit,UnitFileState','--',*names,timeout=60)
        if meta.returncode:
            raise h.Failed('unit type probe failed')
        properties={}
        for block in meta.stdout.decode().strip().split('\n\n'):
            fields=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
            if fields.get('Id'):
                properties[fields['Id']]=fields
        unit_metadata=properties
        result=stable_units(rows,properties)
        unit_sample+=1
        ev.save('unit-scope-%02d.json'%unit_sample,{'states':result,'metadata':properties})
        return result

    def images():
        nonlocal image_sample
        # Bind selection to systemd's actual SourcePath, then read only
        # ContainerName and a hash from that exact installed regular Quadlet.
        proc = h.owner('systemctl','--user','show','--property=Id,SourcePath','--',*IMAGE_UNITS,timeout=60)
        if proc.returncode:
            raise h.Failed('selected container source probe failed')
        sources={}
        for block in proc.stdout.decode().strip().split('\n\n'):
            fields=dict(x.split('=',1) for x in block.splitlines() if '=' in x)
            if fields.get('Id') in IMAGE_UNITS:
                sources[fields['Id']]=fields.get('SourcePath')
        bindings=root_json('''import configparser,hashlib,json,sys
from pathlib import Path
sources=json.load(sys.stdin)["sources"];out={}
for unit,value in sources.items():
 p=Path(value)
 assert p.parent==Path("/home/appowner/.config/containers/systemd") and not p.is_symlink() and p.resolve()==p
 data=p.read_bytes();c=configparser.ConfigParser(interpolation=None,strict=False);c.read_string(data.decode())
 out[unit]={"source":str(p),"source_sha256":hashlib.sha256(data).hexdigest(),"container_name":c["Container"]["ContainerName"]}
print(json.dumps(out))''',{'sources':sources})
        proc = h.owner('podman', 'ps', '--format', '{{.Names}} {{.ImageID}}', timeout=60)
        if proc.returncode:
            raise h.Failed('image config probe failed')
        raw=dict(line.split() for line in proc.stdout.decode().splitlines())
        selected=project_images(raw,bindings)
        image_sample+=1
        ev.save('image-scope-%02d.json'%image_sample,{'bindings':bindings,'selected':selected,
                'unrelated':{name:value for name,value in raw.items() if name not in selected}})
        return selected

    def timer():
        proc = h.root('systemctl', 'show', TIMER, '--property=UnitFileState,ActiveState', timeout=60)
        if proc.returncode:
            raise h.Failed('schedule state probe failed')
        return dict(x.split('=', 1) for x in proc.stdout.decode().splitlines())

    marker = marker_program((HERE/'batch1_markers.py').read_text())
    ha_marker = pe.ha_admin_marker_program(marker) if page_emqx else None

    def markers(app):
        proc = h.owner('python3', '-I', '-c', marker, app, 'read', input=b'{}', timeout=180)
        if proc.returncode:
            raise h.Failed('read-only marker probe failed')
        reply = json.loads(proc.stdout)
        secrets.register_issued(reply['issued'])
        if helper_three_selected or page_emqx:
            for token in reply['issued']:
                observed_marker_tokens.append({'app':app,'sha256':hashlib.sha256(token.encode()).hexdigest(),
                    'length':len(token),'registered':token in secrets.secret_values()})
        if app == 'emqx' and not reply['issued']:
            raise h.Failed('EMQX marker token issuance not observed')
        return reply['markers']

    def ha_markers():
        # The same read-only EMQX marker read after the import, as HA's Dashboard admin (dev-d's admin password no
        # longer logs in while HA's administrator table is live); the password travels on stdin only.
        proc = h.owner('python3', '-I', '-c', ha_marker, pe.APP, 'read',
                       input=json.dumps({'ha_dashboard_password':secrets['B1_EMQX_ADMIN_PW']}).encode(), timeout=180)
        if proc.returncode:
            raise h.Failed('read-only HA-admin marker probe failed')
        reply = json.loads(proc.stdout)
        secrets.register_issued(reply['issued'])
        for token in reply['issued']:
            observed_marker_tokens.append({'app':'emqx-ha-admin','sha256':hashlib.sha256(token.encode()).hexdigest(),
                'length':len(token),'registered':token in secrets.secret_values()})
        if not reply['issued']:
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
        if helper_three_selected and recovery_deadline is None and helper_deadline is not None:
            remaining = min(remaining, int(helper_deadline-time.monotonic()))
        if remaining <= 0:
            raise h.Failed('bounded recovery budget exhausted; retain copies')
        return h.wait_job(job_id,ev=ev,timeout=remaining)

    def follow(first):
        chain, seen = [], set()
        current = first
        while current:
            if current in seen or len(chain) >= (5 if helper_three_selected else 2 if page_emqx else 4):
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
    old_helper_signals = {}
    if helper_three_selected or page_emqx:
        def interrupt_helper(_signum, _frame):
            raise h.Failed('page flow interrupted; recover own jobs' if page_emqx else 'helper flow interrupted; recover own jobs')
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_helper_signals[signum] = signal.signal(signum, interrupt_helper)
    try:
        save()
        require('scan: exact reviewed rendered program parity',(REPO/'snippets/focus-acceptance/r8-scan-rendered.py').read_text()==scan)
        require('source: both reviewed checkouts clean', all(not subprocess.check_output(['git','-C',str(p),'status','--porcelain','--untracked-files=no'], text=True).strip() for p in (source, REPO)))
        require('fixture: original recorded full encrypted HA hash matches', FIXTURE.is_file() and sha(FIXTURE) == FIXTURE_SHA)
        if not helper_three_selected:
            require('browser: existing package and Chromium ready', PLAYWRIGHT.is_file() and CHROMIUM.is_file())
        if page_emqx:
            require('secrets: HA EMQX admin credential registered for the live data read',
                    len(secrets.values.get('B1_EMQX_ADMIN_PW') or '') >= 6 and 'B1_EMQX_ADMIN_PW' not in secrets.names)
        resources()
        installed = root_json(__import__('focus_acceptance_n8n').ENGINE_HASHES)
        lib = source/'backup-engine/woowbackup'
        require('source: installed helper and every module equal frozen source', installed.get('lib') == {str(p.relative_to(lib)):sha(p) for p in lib.rglob('*.py') if '__pycache__' not in p.parts}
                and installed.get('helper') == sha(source/'backup-engine/woowtech-cockpit-backup'))
        ui = root_json('import hashlib,json; from pathlib import Path; p=Path("/usr/local/share/cockpit/woowtechbackup"); print(json.dumps({n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in ("backup.js","backup.css","index.html","manifest.json")}))')
        require('source: installed actual page equals frozen source', ui == {n:sha(source/'backup'/n) for n in ui})
        if not helper_three_selected:
            require('Cockpit: existing socket active', h.root('systemctl','is-active','--quiet','cockpit.socket',timeout=60).returncode == 0)
        status = ok('status')
        require('before: no active backup job', not status.get('active_job'))
        original_catalog, original_units, original_images, original_timer = catalog(), units(), images(), timer()
        require('before: app services already active and all eight selected image configs present', len(original_images) == 8 and original_units and all(v[0]=='active' for k,v in original_units.items() if k.endswith('.service')))
        require('before: selected health timer enabled active and bound to its nonpersistent probe',units_equal(original_units,original_units,unit_metadata))
        require('before: schedule inactive or failed', original_timer.get('ActiveState') in ('inactive','failed'))
        fresh={'catalog':original_catalog,'units':original_units,'unit_metadata':unit_metadata,'images':original_images,'timer':original_timer}
        if previous:
            # Explicit scope projection of the IMMUTABLE old map. Every selected
            # name must exist in it; no selected image may be silently dropped.
            old_images={name:previous['original_images'][name] for name in IMAGE_UNITS.values()}
            projection={'selected_names':sorted(old_images),'old_map_sha256':hashlib.sha256(json.dumps(previous['original_images'],sort_keys=True).encode()).hexdigest(),
                        'old_unrelated_names':sorted(set(previous['original_images'])-set(old_images)),
                        'all_eight_selected_images_preserved':True}
            receipt['previous_image_scope_projection']=projection
            receipt['previous_timer_phase_projection']={'unit':HEALTH_TIMER,'required_unit_file_state':'enabled',
                  'required_active_state':'active','equivalent_substates':['waiting','running'],
                  'old_raw_state':previous['original_units'].get(HEALTH_TIMER),'new_raw_state':original_units.get(HEALTH_TIMER)}
            fresh['previous_equal']={'catalog':original_catalog==previous['original_catalog'],
                                     'units':units_equal(original_units,previous['original_units'],unit_metadata),
                                     'images':original_images==old_images,'timer':original_timer==previous['original_timer']}
            ev.save('fresh-originals.json',fresh)  # retain exact failed sample
            require('replay: original catalog units images and timer still match independent receipt',
                    original_catalog == previous['original_catalog'] and units_equal(original_units,previous['original_units'],unit_metadata)
                    and original_images == old_images and original_timer == previous['original_timer'])
        else:
            ev.save('fresh-originals.json',fresh)
        receipt.update(original_catalog=original_catalog, original_units=original_units, original_unit_metadata=unit_metadata, original_images=original_images, original_timer=original_timer,
                       source_commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip())
        listing=ok('list')
        before_backups={x['id'] for x in listing.get('backups',[])}
        before_backup_rows={x['id']:x for x in listing.get('backups',[])}
        before_uploads={x['id'] for x in listing.get('ha_backups',[])}
        if previous:
            require('replay: every old archive remains a protected existing backup',set(receipt['protected_existing_backups']) <= before_backups)
            if not helper_three_selected or previous.get('ha_record_owned') is not True:
                require('replay: old HA record retained at exact derived SHA',
                        any(x['id'] == previous['ha_id'] and x.get('sha256') == previous['derived_fixture_sha256']
                            for x in listing.get('ha_backups',[])))
        if page_emqx:
            # The product keeps the newest three safety backups per app; this run adds two of EMQX. No archive this run
            # does not own may disappear by that, so stop here when one could.
            page_trace['safety_copies_at_risk']=pe.safety_at_risk(listing.get('backups',[]),receipt.get('protected_existing_backups',[]))
            require('before: no unowned EMQX safety backup can be pruned by this run',not page_trace['safety_copies_at_risk'])
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
        for app,bid in baselines.items():
            pre=ok('inspect',{'backup_id':bid,'key':secrets['DEV_D_KIT']})
            require('before: encrypted '+app+' baseline opens', pre.get('ok') is True)
            if app+'.json' not in original_catalog:
                require('catalog: only missing '+catalog_label+' can be added', app==catalog_app)
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
            if page_emqx:
                # Recovery restores this baseline without asking anyone: prove now, before any import, that it can.
                require('before: '+app+' original baseline has no unreviewed confirmation', pe.baseline_ready(ready.get('preflight',{})))
        if original_timer.get('UnitFileState') not in ('masked','masked-runtime'):
            timer_changed=True
            require('setup: schedule masked as a bounded case', h.root('systemctl','mask',TIMER,timeout=60).returncode==0)
        receipt['phase']='derive-and-helper' if helper_three_selected else 'page-emqx-ui' if page_emqx else 'derive-and-ui'
        save()
        if page_emqx:
            # The ORIGINAL fixture, never a derived copy: an upload of it may already be dev-d's protected record.
            receipt['ha_id']='ha-'+FIXTURE_SHA[:20]
            receipt['original_fixture_sha256']=FIXTURE_SHA
            receipt['uploaded_fixture_sha256']=FIXTURE_SHA
            receipt['ha_record_owned']=pe.original_record_owned(listing.get('ha_backups',[]),receipt['ha_id'],FIXTURE_SHA)
            require('upload: original HA record is new or an exact protected existing record',
                    receipt['ha_record_owned'] or receipt['ha_id'] in before_uploads)
        else:
            derive(FIXTURE,derived)
            receipt['ha_id']='ha-'+sha(derived)[:20]
            receipt['original_fixture_sha256']=FIXTURE_SHA
            receipt['derived_fixture_sha256']=sha(derived)
            receipt['ha_record_owned']=ha_record_owned(listing.get('ha_backups',[]),receipt['ha_id'],receipt['derived_fixture_sha256'],previous)
            require('upload: ownership is new or exact protected retained record',
                    receipt['ha_record_owned'] or (previous is not None and receipt['ha_id'] in before_uploads))
        save()
        if helper_three_selected:
            helper_deadline = time.monotonic()+20*60
            receipt['mode']='helper-three-selected';save()
            resources()
            rc, uploaded_reply = h.upload(derived,ev=ev)
            require('helper: exact derived real HA uploaded',rc==0 and uploaded_reply.get('ha_backup',{}).get('id')==receipt['ha_id'])
            receipt['helper_check_request_id']=h.request_id('focus-r1-helper-check');save()
            reply=ok('ha-check-start',{'ha_backup_id':receipt['ha_id'],'apps':helper.APPS,
                'key':secrets['HA_BACKUP_KEY'],'request_id':receipt['helper_check_request_id']})
            receipt['check_jobs']=[reply['job_id']];save()
            checked=wait(reply['job_id'])
            require('helper: current exact three-app check and no unreviewed confirmation',helper.check_ready(checked,receipt['ha_id']))
            receipt['helper_import_request_id']=h.request_id('focus-r1-helper-import');save()
            reply=ok('ha-import-start',{'ha_backup_id':receipt['ha_id'],'apps':helper.APPS,
                'key':secrets['HA_BACKUP_KEY'],'request_id':receipt['helper_import_request_id'],
                'check_job_id':checked['id'],'test_mode':False,'confirm':True,'then_restore':True,'overwrite':True})
            receipt['helper_root_job_id']=reply['job_id'];save()
            helper_trace['first_job_id']=reply['job_id']
            sampler=helper.FirstUnitMemory(reply['job_id'],h.root);sampler.thread.start()
            terminal=False
            try:
                records=follow(reply['job_id']);terminal=True
                require('helper: failed EMQX followed by both linked successful pairs',helper.chain_complete(records))
                helper_trace['completed']=True
            finally:
                helper_trace['memory']=sampler.finish(terminal)
                ev.save('helper-trace.json',helper_trace)
        elif page_emqx:
            # The same real page and private relay as R8, told to select only EMQX and what to expect (page_settings).
            config={'ha_id':receipt['ha_id'],'fixture':str(FIXTURE),'password':secrets['COCKPIT_PASSWORD'],
                    'key':secrets['HA_BACKUP_KEY'],'evidence':str(ev.dir),'result':str(ev.dir/'browser.json'),
                    'playwright':str(PLAYWRIGHT),'chromium':str(CHROMIUM),'since':started,'cookie_scan':scan,
                    **pe.page_settings()}
            resources()
            with Relay() as relay:
                config['base']=relay.base
                proc=subprocess.Popen(['node',str(HERE/'focus_acceptance_ui_page.mjs'),'--run'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                try:
                    proc.communicate(json.dumps(config).encode(),timeout=20*60)
                except BaseException as error:
                    # A timeout or a soft stop never orphans the browser: further soft signals are ignored, SIGTERM lets
                    # Playwright close its Chromium children, SIGKILL only after 15 seconds.
                    for signum in old_helper_signals:
                        signal.signal(signum, signal.SIG_IGN)
                    proc.send_signal(signal.SIGTERM)
                    try:
                        proc.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.communicate()
                    if isinstance(error, subprocess.TimeoutExpired):
                        raise h.Failed('bounded page timeout; adopt own jobs before recovery') from None
                    raise
            require('transport: private relay closed all exec children', not relay.children and not relay.thread.is_alive())
            require('UI: real page completed one bounded flow',proc.returncode==0)
            browser=json.loads((ev.dir/'browser.json').read_text())
            for item in browser['checks']:
                require(item['check'],item['ok'])
            require('UI: browser result and issued-value scan complete',browser['completed'] and browser['issued_values_scanned'])
            page_trace['completed']=True
        else:
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
        ev.check('R1 helper: bounded flow completed' if helper_three_selected else 'page-emqx: bounded real page flow completed' if page_emqx
                 else 'R8: bounded real page flow completed',False,type(error).__name__)
    finally:
        if helper_three_selected or page_emqx:
            # One soft stop enters bounded recovery. Further soft signals must
            # not race its ordinary baseline restores; hard loss retains guard.
            for signum in old_helper_signals:
                signal.signal(signum, signal.SIG_IGN)
        if not state_armed:
            ev.check('preconditions: old guard retained without device mutation',
                     (state_path.read_bytes() if state_path.exists() else None) == prior_guard)
            receipt['phase']='preconditions-stopped'
            save()
            ev.finish()
            ev.save('summary.json',{'driver_commit':receipt['driver_commit'],'passed':sum(x['ok'] for x in ev.results),
                                   'failed':sum(not x['ok'] for x in ev.results),'baseline_restored':False,
                                   'recovery_verified':False,'previous_guard_unchanged':True,
                                   'commercial_acceptance':'not-complete'})
            os.close(fd)
            for signum, handler in old_helper_signals.items():
                signal.signal(signum, handler)
            print('page-emqx preconditions stopped; no device mutation' if page_emqx else 'R8 preconditions stopped; previous failed case retained')
            return 1
        recovery_deadline=time.monotonic()+20*60
        try:
            # Adopt only new jobs for this exact derived HA. This works even if
            # the browser timed out after sending its intent or before saving.
            if receipt['ha_id'] and before_jobs is not None:
                listing=ok('list')
                uploaded=receipt['ha_id'] in {x['id'] for x in listing.get('ha_backups',[])}
                if helper_three_selected:
                    intents={kind:receipt[name] for kind,name in (('check','helper_check_request_id'),('import','helper_import_request_id')) if name in receipt}
                    resolved=root_json(helper.RESOLVE,{'requests':intents,'ha_id':receipt['ha_id']})
                    receipt['check_jobs']=[resolved['check']] if 'check' in resolved else []
                    own=[{'id':jid,'type':'verify'} for kind,jid in resolved.items() if kind=='check']
                    roots=[{'id':resolved['import']}] if 'import' in resolved else []
                    save()
                else:
                    own=[x for x in ok('jobs').get('jobs',[]) if x['id'] not in before_jobs and x.get('params',{}).get('ha_backup_id')==receipt['ha_id']]
                    receipt['check_jobs']=[x['id'] for x in own if x.get('type')=='verify']
                    save()
                    roots=[x for x in own if x.get('type')=='backup' and x.get('params',{}).get('source')=='ha']
                    roots.sort(key=lambda x:x['id'])
                if page_emqx:
                    # The page's own check ended before its import could start; its record is what the import is judged by.
                    checked=[wait(j['id']) for j in own if j.get('type')=='verify']
                if roots:
                    records=follow(roots[0]['id'])
                    if helper_three_selected:
                        helper_trace['chain_verified']=helper.chain_complete(records)
                        ev.check('helper: five actual linked jobs with isolated EMQX failure',helper_trace['chain_verified'])
                        try:
                            native=root_json('import json,re,sys; from pathlib import Path; ids=json.load(sys.stdin)["ids"]; assert len(ids)==5 and all(re.fullmatch(r"j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",x) for x in ids); p=Path("/var/lib/woowtech-backup/jobs"); rows=[json.loads((p/(x+".json")).read_bytes()) for x in ids]; print(json.dumps([{k:r.get(k) for k in ("id","unit","type","state")} for r in rows]))',{'ids':[j['id'] for j in records]})
                            helper_trace['native_units']=[j['unit'] for j in native]
                            helper_trace['native_units_verified']=(len(native)==5 and all(n['id']==r['id'] and n['type']==r['type'] and n['state']==r['state'] for n,r in zip(native,records))
                                and helper_trace['native_units']==['woowtech-backup-'+records[0]['id']+'.service']*5)
                            ev.save('helper-native-jobs.json',native)
                        except Exception as error:
                            helper_trace['native_units_verified']=False
                            helper_trace['native_units_error_class']=type(error).__name__
                        ev.check('helper: native actual job metadata shares the first unit',helper_trace.get('native_units_verified') is True)
                        memory=helper_trace.get('memory',{})
                        ev.check('helper: first unit sampled through terminal chain below1GiB',memory.get('samples',0)>0
                            and 0<memory.get('peak_bytes',0)<1024**3 and memory.get('through_terminal_chain') is True and memory.get('sampler_stopped') is True)
                        ev.save('helper-trace.json',helper_trace)
                    elif page_emqx:
                        page_trace['first_job_id']=records[0].get('id')
                        page_trace['check_jobs']=[j.get('id') for j in checked]
                        try:
                            expected,section=pe.check_accepted(checked[0] if len(checked)==1 else {},receipt['ha_id'])
                        except ValueError as error:
                            expected=section=None
                            page_trace['check_refusal']=str(error)
                        page_trace['check_accepted']=expected is not None
                        page_trace['expected_acknowledged']=expected
                        ev.check('check: one current EMQX-only check, EMQX importable, every confirmation line keyed',page_trace['check_accepted'])
                        browser_file=ev.dir/'browser.json'
                        sent=(json.loads(browser_file.read_text()).get('confirmations') or {}).get('sent_keys') if browser_file.is_file() else None
                        page_trace['acknowledged_exact']=expected is not None and pe.acknowledged_exactly(expected,records[0].get('params') or {},sent)
                        ev.check('confirmation: page and import carry every listed confirmation key exactly once',page_trace['acknowledged_exact'])
                        page_trace['chain_verified']=pe.chain_complete(records,receipt['ha_id'])
                        ev.check('chain: one EMQX conversion and its restore succeeded as two linked jobs',page_trace['chain_verified'])
                        try:
                            native=root_json(pe.NATIVE_UNITS,{'ids':[j['id'] for j in records]})
                            page_trace['native_units']=[n.get('unit') for n in native]
                            page_trace['native_units_verified']=pe.native_units_ok(native,records)
                            ev.save('page-emqx-native-jobs.json',native)
                        except Exception as error:
                            page_trace['native_units_verified']=False
                            page_trace['native_units_error_class']=type(error).__name__
                        ev.check('chain: both jobs share the first systemd unit',page_trace['native_units_verified'] is True)
                        safety=(records[-1].get('result') or {}).get('safety_backup_id')
                        page_trace['restore_safety_verified']=records[-1].get('type')=='restore' and isinstance(safety,str) and bool(safety)
                        ev.check('chain: the EMQX restore has its own safety backup',page_trace['restore_safety_verified'])
                        ev.save('page-emqx-trace.json',page_trace)
                    else:
                        ev.check('chain: two real conversions and restores succeeded',chain_complete(records))
                        job_units=root_json('import json,re,sys; from pathlib import Path; ids=json.load(sys.stdin)["ids"]; assert all(re.fullmatch(r"j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",x) for x in ids); p=Path("/var/lib/woowtech-backup/jobs"); print(json.dumps([json.loads((p/(x+".json")).read_text()).get("unit") for x in ids]))',{'ids':[j['id'] for j in records]})
                        ev.check('chain: every job shares the first systemd unit',job_units==['woowtech-backup-'+records[0]['id']+'.service']*len(records))
                    if helper_three_selected:
                        safeties=[j.get('result',{}).get('safety_backup_id') for j in records if j.get('type')=='restore']
                        helper_trace['distinct_restore_safeties_verified']=len(safeties)==2 and all(safeties) and len(set(safeties))==2
                        hermes_live,omni_live=markers('hermes'),markers('omnigent')
                        helper_trace['live_data_verified']=(hermes_live.get('session_count',0)>=5
                            and 'woowbk-lab-baseline' not in hermes_live.get('sessions',{}) and omni_live!=before['omnigent'])
                        ev.check('helper: distinct safety backups and both actual HA live data',
                            helper_trace['distinct_restore_safeties_verified'] and helper_trace['live_data_verified'])
                    elif page_emqx:
                        try:
                            live=ha_markers()
                            ev.save('live-emqx.json',live)
                            page_trace['live_data_verified']=section is not None and pe.live_matches_ha(live,section,before['emqx'])
                        except Exception as error:
                            page_trace['live_data_verified']=False
                            page_trace['live_error_class']=type(error).__name__
                        ev.check('live: EMQX holds HA data (HA admin logs in, no dev-d marker left, every HA MQTT account present)',
                                 page_trace['live_data_verified'])
                        ev.save('page-emqx-trace.json',page_trace)
                    else:
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
            for app,bid in baselines.items():
                if app not in before:
                    continue
                if page_emqx:
                    # Once the import's restore ran, HA's administrator table may be live and dev-d's own admin cannot read
                    # the markers: restore the baseline without probing. Otherwise an unreadable or changed EMQX restores too.
                    changed=any(j.get('type')=='restore' for j in records)
                    if not changed:
                        try:
                            changed=markers(app)!=before[app]
                        except h.Failed:
                            changed=True
                else:
                    changed=markers(app)!=before[app]
                if changed:
                    resources(2)
                    pre=ok('inspect',{'backup_id':bid,'key':secrets['DEV_D_KIT']}).get('preflight',{})
                    require('recovery: original baseline has no unreviewed confirmation',pre.get('ok') is True and not any(i.get('level') in ('confirm','stop') for a in pre.get('apps',[]) for i in a.get('issues',[])))
                    reply=ok('restore-start',{'backup_id':bid,'apps':[app],'confirm':True,'key':secrets['DEV_D_KIT'],'request_id':h.request_id('focus-ui-'+app+'-baseline')},timeout=300)
                    receipt['inflight']=reply['job_id']; save()
                    job=wait(reply['job_id']); remember(job)
                    require('recovery: original '+app+' restore succeeded',job.get('state')=='succeeded')
                    receipt['inflight']=None; save()
                require('recovery: exact original '+app+' markers returned',markers(app)==before[app])
            if page_emqx:
                require('recovery: unselected Omnigent and Hermes unchanged',
                        markers('omnigent')==before['omnigent'] and markers('hermes')==before['hermes'])
            else:
                require('recovery: excluded EMQX unchanged', 'emqx' in before and markers('emqx')==before['emqx'])
            require('recovery: original app unit states and image configs returned',units_equal(units(),original_units,unit_metadata) and images()==original_images)
            require('recovery: original full HA fixture hash retained',sha(FIXTURE)==FIXTURE_SHA)
            receipt['baseline_restored']=True
            save()
            report=root_json(scan,{'values':secrets.secret_values(),'since':started,'podman_secrets':[
                'omnigent-postgres-password','omnigent-admin-password','omnigent-runner-password',
                'hermes-api-server-key','hermes-webhook-secret','hermes-dashboard-session-secret','hermes-dashboard-password',
                'hermes-postgres-password','woow-emqx-dashboard-password','woow-emqx-node-cookie','woow-emqx-mqtt-password']})
            ev.save('leaks.json',report)
            after={x['id'] for x in ok('list').get('backups',[])}
            pruning=case_safety_prunes(before_backup_rows,after,receipt.get('protected_existing_backups',[]),
                                      {p.name:p.read_bytes() for p in ev.dir.glob('job-*.json')})
            receipt['prior_case_safety_pruning']=pruning;save()
            expected_prior=before_backups-{p['id'] for p in pruning}
            sidecars=root_json('from pathlib import Path; import json; print(json.dumps(len(list(Path("/var/lib/woowtech-backup/archives").rglob("*.json")))))')
            # The encrypted child archive contains secrets by design. Scan all
            # other artifacts, including the browser's fixed-field result.
            host_hits=0
            needles=b1.secret_scan_needles(secrets.secret_values())
            for p in ev.dir.iterdir():
                if p.is_file() and p!=derived:
                    data=p.read_bytes(); host_hits+=sum(data.count(v) for v in needles)
            require('leaks: registered and observed values absent from records journal and text evidence',
                    report['hits']==0 and report['scanned']>0 and host_hits==0
                    and report['regular_json_roots_scanned']==2
                    and report['archive_index_sidecars_scanned'] == sidecars
                    and sidecars >= len(after))
            if helper_three_selected:
                helper_trace.update(observed_marker_tokens=len(observed_marker_tokens),
                    all_observed_marker_tokens_registered=bool(observed_marker_tokens) and all(t['registered'] for t in observed_marker_tokens),
                    marker_token_metadata=observed_marker_tokens,actual_sidecars=sidecars,
                    registered_token_scan=report,host_registered_value_hits=host_hits,
                    cookie_coverage='not-applicable-no-browser-or-relay')
                ev.save('helper-trace.json',helper_trace)
                require('helper: actual chain memory metadata baseline and registered-token scan before deletion',
                    helper.cleanup_ready(helper_trace,receipt,report,host_hits))
                require('helper: terminal page guard and evidence remain byte unchanged',
                    all(sha(Path(path))==digest for path,digest in protected_page_files.items()))
            elif page_emqx:
                browser_file=ev.dir/'browser.json'
                browser_doc=json.loads(browser_file.read_text()) if browser_file.is_file() else {}
                require('leaks: browser issued-value scan completed before deletion',browser_doc.get('issued_values_scanned') is True)
                page_trace.update(observed_marker_tokens=len(observed_marker_tokens),
                    all_observed_marker_tokens_registered=bool(observed_marker_tokens) and all(t['registered'] for t in observed_marker_tokens),
                    marker_token_metadata=observed_marker_tokens,actual_sidecars=sidecars,
                    registered_token_scan=report,host_registered_value_hits=host_hits)
                ev.save('page-emqx-trace.json',page_trace)
                require('page-emqx: check, keys, chain, live data, baseline and scans complete before deletion',
                    pe.cleanup_ready(page_trace,receipt,report,host_hits,browser_doc))
                require('page-emqx: PAGE5 and R1 guards and evidence remain byte unchanged',
                    all(sha(Path(path))==digest for path,digest in protected_page_files.items()))
            else:
                browser_file=ev.dir/'browser.json'
                require('leaks: browser issued-value scan completed before deletion',browser_file.is_file() and json.loads(browser_file.read_text()).get('issued_values_scanned') is True)
            require('recovery: backup inventory contains no untracked new archive', before_backups is not None and after-before_backups==set(receipt['created_backups']))
            safe=True
            receipt['phase']='owned-cleanup'; save()
            if receipt['catalog_added']:
                current=catalog()
                require('catalog: only own new entry changed', {k:v for k,v in current.items() if k!=catalog_app+'.json'}==original_catalog)
                preview=ok('catalog-remove',{'id':catalog_app})
                require('catalog: remove matches own installed entry',preview.get('expected_sha256')==receipt['catalog_expected_sha256'])
                ok('catalog-remove',{'id':catalog_app,'confirm':True,'expected_sha256':preview['expected_sha256']})
            require('recovery: original catalog hashes returned',catalog()==original_catalog)
            for bid in receipt['created_backups']:
                ok('delete',{'backup_id':bid})
            if uploaded and receipt['ha_record_owned']:
                ok('ha-delete',{'ha_backup_id':receipt['ha_id'],'confirm':True})
            derived.unlink(missing_ok=True)
            h.scenario_cleanup(ev,None)
            require('cleanup: original backups retained except proved prior test safety pruning',
                    {x['id'] for x in ok('list').get('backups',[])}==expected_prior)
            retained_uploads=ok('list').get('ha_backups',[])
            require('cleanup: original HA inventory retained',{x['id'] for x in retained_uploads}==before_uploads)
            if page_emqx and not receipt['ha_record_owned']:
                require('cleanup: protected original HA record remains at exact fixture SHA',
                        any(x['id']==receipt['ha_id'] and x.get('sha256')==FIXTURE_SHA for x in retained_uploads))
            if previous and (not helper_three_selected or previous.get('ha_record_owned') is not True):
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
            if helper_three_selected:
                require('helper: terminal page guard and evidence unchanged after recovery',
                    all(sha(Path(path))==digest for path,digest in protected_page_files.items()))
            elif page_emqx:
                require('page-emqx: PAGE5 and R1 guards and evidence unchanged after recovery',
                    all(sha(Path(path))==digest for path,digest in protected_page_files.items()))
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
        for signum, handler in old_helper_signals.items():
            signal.signal(signum, handler)
        print(('R1 helper: ' if helper_three_selected else 'page-emqx real Cockpit: ' if page_emqx else 'R8 real Cockpit: ')
              +str(sum(x['ok'] for x in ev.results))+'/'+str(len(ev.results))+(' PASS' if good and safe else ' FAIL'))
    return 0 if good and safe else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--source',type=Path,default=REPO)
    parser.add_argument('--recovery-proof',type=Path)
    parser.add_argument('--recovery-proof-sha256')
    parser.add_argument('--helper-three-selected',action='store_true')
    parser.add_argument('--page-emqx',action='store_true',help='real page: the original B1 backup, EMQX only, normal import')
    parser.add_argument('--lease',type=Path,help='separate exact R1 helper or page-emqx lease only')
    args=parser.parse_args(argv)
    if args.helper_three_selected and args.page_emqx:
        parser.error('--helper-three-selected and --page-emqx are separate cases')
    if not args.run:
        for p in (Path(__file__),HERE/'focus_acceptance_ui_relay.py'):
            compile(p.read_text(),str(p),'exec')
        print('R8 controller prepared: offline syntax PASS; review and dev-d lease required')
        return 0
    if args.helper_three_selected:
        return run(args.source.resolve(),args.recovery_proof,args.recovery_proof_sha256,
            helper_three_selected=True,helper_lease_path=args.lease)
    if args.page_emqx:
        return run(args.source.resolve(),args.recovery_proof,args.recovery_proof_sha256,
            page_emqx=True,page_emqx_lease_path=args.lease)
    if args.lease:
        parser.error('--lease is only for --helper-three-selected or --page-emqx')
    return run(args.source.resolve(),args.recovery_proof,args.recovery_proof_sha256)


if __name__=='__main__':
    raise SystemExit(main())
