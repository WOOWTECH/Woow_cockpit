"""Only the real-page normal EMQX import (page-emqx); imports perform no I/O.

The ORIGINAL encrypted B1 HA backup is uploaded through the real Cockpit page, only EMQX is selected, the check must
call EMQX importable, the one acknowledgement must carry every confirmation key the check lists exactly once, one click
runs the chain of two jobs (conversion and restore in the first job's unit), EMQX then holds HA's data, and dev-d's own
EMQX baseline backup brings dev-d's markers back. The controller (focus_acceptance_ui.py --page-emqx) does the device
work; this module holds the pure gates it is judged by.
"""
import hashlib
import json
import os
from pathlib import Path
import re
from datetime import datetime

APP = 'emqx'
CASE = PHASE = 'page-emqx'
DEVICE = 'woowbk-dev-d'
# dev-d's own EMQX baseline backup: ha_import_b1_e2e.BASELINE_IDS['emqx'] (11-19 device key, the offline test pins it).
BASELINE = '20261119T072831Z-168aaa02'
LEASE = Path('/tmp/parity-focus-20261127/lease-page-emqx-dev-d.json')
STATE_NAME = 'focus_acceptance_page_emqx.json'          # ~/.woowbk-lab/run/, absent before a run
R1_STATE_NAME = 'focus_acceptance_r1_helper.json'       # the terminal R1 helper guard, protected byte for byte
EVIDENCE_AREA = 'focus-acceptance-page-emqx'
SHARED = '_shared'                                      # haissues.SHARED
LEVELS = ('stop', 'confirm', 'auto', 'notice')          # haissues.LEVELS
KEY = re.compile(r'[a-z0-9.-]{4,70}:[0-9a-f]{16}\Z')    # haissues.KEY_RE
JOB = re.compile(r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
SAFETY_KEEP = 3          # flows.SAFETY_KEEP: the newest safety backups the product keeps per app
NEW_SAFETY_COPIES = 2    # this run's own EMQX safety backups: the import's restore and the baseline restore
MIN_LEASE_SECONDS = 45 * 60


def validate_lease(lease, driver_commit, source_commit, source, now):
    """The separate page-emqx lease: granted for dev-d, this case and phase, the source checkout, both full commits,
    the terminal page guard's digest and a timezone-aware expiry with at least 45 minutes left."""
    try:
        expiry = datetime.fromisoformat(lease['expires'])
        source_ok = (isinstance(lease.get('source'), str) and os.path.isabs(lease['source'])
                     and Path(lease['source']).resolve() == Path(source).resolve())
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError('exact fresh page-emqx lease required') from None
    if (lease.get('granted') is not True or lease.get('device') != DEVICE or lease.get('case') != CASE
            or lease.get('phase') != PHASE or not source_ok
            or not isinstance(driver_commit, str) or not COMMIT.fullmatch(driver_commit)
            or lease.get('driver_commit') != driver_commit
            or not isinstance(source_commit, str) or not COMMIT.fullmatch(source_commit)
            or lease.get('source_commit') != source_commit
            or not isinstance(lease.get('page_guard_sha256'), str) or not SHA.fullmatch(lease['page_guard_sha256'])
            or expiry.tzinfo is None or expiry.timestamp() - now < MIN_LEASE_SECONDS):
        raise ValueError('exact fresh page-emqx lease required')


def _private_file(path):
    return (not path.is_symlink() and path.is_file() and path.stat().st_uid == os.getuid()
            and not path.stat().st_mode & 0o077)


def r1_predecessor(lease, raw, guard_path, evidence_root):
    """Read only the terminal R1 helper guard that followed the leased page guard; never override it.

    Returns (old guard, provenance, {path: sha256} of the guard and its evidence files to keep byte-unchanged)."""
    if (guard_path.resolve() != guard_path.absolute() or not _private_file(guard_path)
            or hashlib.sha256(guard_path.read_bytes()).hexdigest() != hashlib.sha256(raw).hexdigest()):
        raise ValueError('exact terminal R1 guard required')
    old = json.loads(raw)
    case = Path(old.get('evidence_dir') or '/')
    link = old.get('previous_independent_recovery') or {}
    if (old.get('phase') != 'complete' or old.get('mode') != 'helper-three-selected'
            or old.get('baseline_restored') is not True or old.get('recovery_verified') is not True
            or old.get('inflight') or old.get('ha_record_owned') is not False
            or link.get('sha256') != lease.get('page_guard_sha256')
            or case.parent != evidence_root/'focus-acceptance-r1-helper' or case.resolve() != case):
        raise ValueError('R1 recovery must be complete and bound to the leased page guard')
    protected = {str(guard_path): hashlib.sha256(raw).hexdigest()}
    docs = {}
    for name in ('summary.json', 'recovery.json', 'results.json', 'leaks.json', 'helper-trace.json'):
        path = case/name
        if not _private_file(path):
            raise ValueError('unsafe R1 evidence')
        data = path.read_bytes()
        protected[str(path)] = hashlib.sha256(data).hexdigest()
        docs[name] = json.loads(data)
    summary, results, scan, trace = docs['summary.json'], docs['results.json'], docs['leaks.json'], docs['helper-trace.json']
    if (summary.get('baseline_restored') is not True or summary.get('recovery_verified') is not True
            or summary.get('failed') != 0 or results.get('failed') != 0 or trace.get('completed') is not True
            or scan.get('hits') != 0 or scan.get('scanned', 0) <= 0 or scan.get('regular_json_roots_scanned') != 2
            or scan.get('archive_index_sidecars_scanned', 0) <= 0):
        raise ValueError('terminal R1 baseline and privacy proof missing')
    prior = set(old.get('protected_existing_backups', []))
    pruned = {row.get('id') for row in old.get('prior_case_safety_pruning', [])}
    if pruned - prior:
        raise ValueError('R1 prior-owned pruning accounting invalid')
    return old, {'path': str(guard_path), 'sha256': protected[str(guard_path)], 'acceptance_passed': False,
                 'retained_case_archive_ids': sorted(prior - pruned)}, protected


def original_record_owned(records, ha_id, digest):
    """True when the original upload is new (this run owns and later deletes it); False for exactly one existing record
    at the fixture's own SHA-256, which is protected and stays. Anything else refuses."""
    if not isinstance(digest, str) or not SHA.fullmatch(digest) or ha_id != 'ha-' + digest[:20]:
        raise ValueError('original HA identity invalid')
    matches = [row for row in records if isinstance(row, dict) and row.get('id') == ha_id]
    if not matches:
        return True
    if len(matches) == 1 and matches[0].get('sha256') == digest:
        return False
    raise ValueError('existing original HA record differs; never reused or deleted')


def baseline_ready(preflight):
    """dev-d's EMQX baseline can be restored without any confirmation (the same rule recovery applies)."""
    return (isinstance(preflight, dict) and preflight.get('ok') is True
            and not any(issue.get('level') in ('confirm', 'stop') for app in preflight.get('apps', [])
                        for issue in app.get('issues', [])))


def check_accepted(job, ha_id):
    """(expected acknowledgement {group: sorted distinct keys}, EMQX section) of the one current EMQX-only check.

    EMQX must be importable with its section, nothing may stop it, and every confirmation line the check lists (shared
    or EMQX's) must carry a valid key: those keys, each once, are what the one acknowledgement has to send."""
    job = job if isinstance(job, dict) else {}
    params = job.get('params') or {}
    result = (job.get('result') or {}).get('ha_check') or {}
    rows, shared = result.get('apps'), result.get('shared')
    if (job.get('type') != 'verify' or job.get('state') != 'succeeded' or params.get('source') != 'ha'
            or params.get('ha_backup_id') != ha_id or params.get('apps') != [APP]
            or result.get('schema') != 2 or result.get('ha_backup_id') != ha_id
            or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict)
            or rows[0].get('app_id') != APP or not isinstance(shared, list)):
        raise ValueError('one current EMQX-only check required')
    row = rows[0]
    if (row.get('importable') is not True or not isinstance(row.get('issues'), list)
            or not isinstance(row.get(APP), dict)):
        raise ValueError('EMQX must be importable with its section')
    expected = {}
    for group, issues in ((SHARED, shared), (APP, row['issues'])):
        keys = []
        for issue in issues:
            if not isinstance(issue, dict) or issue.get('level') not in LEVELS:
                raise ValueError('unknown check line')
            if issue['level'] == 'stop':
                raise ValueError('a stop line in an importable EMQX check')
            if issue['level'] == 'confirm':
                if (not isinstance(issue.get('message'), str) or not issue['message'] or issue.get('database') is not None
                        or not isinstance(issue.get('key'), str) or not KEY.fullmatch(issue['key'])):
                    raise ValueError('confirmation line without a valid key')
                keys.append(issue['key'])
        if keys:
            expected[group] = sorted(set(keys))
    return expected, row[APP]


def _keys_equal(expected, given):
    """`given` ({group: [keys]}, None = nothing sent) holds exactly the expected keys, each exactly once."""
    if given is None:
        given = {}
    if not isinstance(given, dict):
        return False
    seen = {}
    for group, keys in given.items():
        if (not isinstance(keys, list) or not keys or len(set(keys)) != len(keys)
                or not all(isinstance(key, str) and KEY.fullmatch(key) for key in keys)):
            return False
        seen[group] = sorted(keys)
    return seen == expected


def acknowledged_exactly(expected, params, sent):
    """The import's first job (`params`, its chain too) and the request the page sent (`sent`, as the page observed it)
    carry every expected confirmation key exactly once and nothing else."""
    chain = params.get('chain') if isinstance(params, dict) else None
    return (isinstance(expected, dict) and isinstance(chain, dict) and isinstance(sent, dict)
            and _keys_equal(expected, params.get('acknowledged')) and _keys_equal(expected, chain.get('acknowledged'))
            and _keys_equal(expected, sent))


def chain_complete(records, ha_id):
    """Exactly the two linked jobs of one EMQX import: its conversion and the restore of that converted backup, both
    succeeded, the restore the last job, EMQX imported and nothing else in the group's results."""
    ids = [job.get('id') for job in records]
    if (len(records) != 2 or len(set(ids)) != 2
            or not all(isinstance(job_id, str) and JOB.fullmatch(job_id) for job_id in ids)):
        return False
    first, second = records
    p1, p2 = first.get('params') or {}, second.get('params') or {}
    chain = p1.get('chain') or {}
    g1, g2 = (first.get('result') or {}).get('group') or {}, (second.get('result') or {}).get('group') or {}
    converted = (first.get('result') or {}).get('backup_id')
    results = g2.get('results')
    return ([job.get('type') for job in records] == ['backup', 'restore']
            and [job.get('state') for job in records] == ['succeeded', 'succeeded']
            and p1.get('source') == 'ha' and p1.get('ha_backup_id') == ha_id and p1.get('apps') == [APP]
            and p1.get('test_mode') is False and chain.get('apps') == [APP] and chain.get('then_restore') is True
            and chain.get('test_mode') is False
            and isinstance(converted, str) and bool(converted) and p2.get('backup_id') == converted
            and p2.get('apps') == [APP] and p2.get('ha_backup_id') == ha_id
            and g1.get('next_job_id') == ids[1] and g2.get('next_job_id') is None
            and isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict)
            and results[0].get('app_id') == APP and results[0].get('status') == 'imported')


# Read-only native job metadata of exactly the two chain jobs (fixed program; values never leave the device).
NATIVE_UNITS = ('import json,re,sys; from pathlib import Path; ids=json.load(sys.stdin)["ids"]; '
                'assert len(ids)==2 and all(re.fullmatch(r"j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}",x) for x in ids); '
                'p=Path("/var/lib/woowtech-backup/jobs"); rows=[json.loads((p/(x+".json")).read_bytes()) for x in ids]; '
                'print(json.dumps([{k:r.get(k) for k in ("id","unit","type","state")} for r in rows]))')


def native_units_ok(native, records):
    """Both jobs' own records agree with the followed chain and both run in the first job's unit."""
    if not isinstance(native, list) or len(native) != 2 or len(records) != 2:
        return False
    unit = 'woowtech-backup-' + str(records[0].get('id')) + '.service'
    return all(isinstance(n, dict) and n.get('id') == r.get('id') and n.get('type') == r.get('type')
               and n.get('state') == r.get('state') and n.get('unit') == unit for n, r in zip(native, records))


def live_matches_ha(live, section, before):
    """EMQX holds HA's data, read with batch1_markers' own EMQX read as HA's Dashboard admin: none of dev-d's lab
    markers is left, and the MQTT accounts number at least HA's (the check counted them in HA's broker) and at most HA's
    plus dev-d's own non-marker accounts (its bootstrap file stays attached to HA's database)."""
    if not all(isinstance(value, dict) for value in (live, section, before)):
        return False
    users, count, mine = section.get('mqtt_users'), live.get('mqtt_user_count'), before.get('mqtt_user_count')
    own_markers = before.get('mqtt_users')
    if (not all(isinstance(n, int) and not isinstance(n, bool) for n in (users, count, mine))
            or not isinstance(own_markers, list)):
        return False
    return (users > 0 and live.get('mqtt_users') == [] and live.get('retained') == [] and live.get('banned') == []
            and users <= count <= users + mine - len(own_markers))


def safety_at_risk(rows, owned_prior, app=APP, new=NEW_SAFETY_COPIES, keep=SAFETY_KEEP):
    """The existing safety backups of `app` the product's keep-newest rule could delete once this run adds `new` of its
    own, minus prior owned test copies whose pruning recovery accounts for. Pinned and kept copies are never pruned, so
    this is a superset: an empty list means no unowned archive can disappear."""
    prior = set(owned_prior)
    safeties = [row for row in rows if isinstance(row, dict) and row.get('type') == 'safety' and row.get('kept') is not True
                and app in {item.get('id') for item in row.get('apps') or [] if isinstance(item, dict)}]
    safeties.sort(key=lambda row: (row.get('created') or '', row.get('id') or ''), reverse=True)
    return sorted(str(row.get('id')) for row in safeties[max(keep - new, 0):] if row.get('id') not in prior)


# The HA Dashboard admin's password reaches batch1_markers' EMQX read on stdin only, right before its handler runs:
# after the import HA's administrator table is live and dev-d's own admin password no longer logs in.
HA_LOGIN_OVERRIDE = '''
_page_emqx_request = json.loads(sys.stdin.read() or "{}")
_page_emqx_device_secret = secret
def secret(name):
    if name == "woow-emqx-dashboard-password":
        value = _page_emqx_request.get("ha_dashboard_password")
        if not isinstance(value, str) or len(value) < 6:
            raise SystemExit("HA dashboard credential unavailable")
        return value
    return _page_emqx_device_secret(name)
'''
ANCHOR = '\nfound = HANDLERS[(APP, ACTION)]()\n'
TAIL = 'print(json.dumps({"markers": found, "issued": issued}))\n'


def ha_admin_marker_program(program):
    """The harness's own marker program (marker_program: batch1_markers plus issued-token interception) logging in as
    HA's Dashboard admin instead of dev-d's; everything else, including the interception, stays as it is."""
    if program.count(ANCHOR) != 1 or not program.endswith(ANCHOR.lstrip('\n') + TAIL) or 'def secret(' not in program:
        raise ValueError('marker producer changed; review required')
    head, tail = program.split(ANCHOR)
    return head + '\n' + HA_LOGIN_OVERRIDE + ANCHOR + tail


def page_settings():
    """What the page is told to select and expect (focus_acceptance_ui_protocol.pageExpectations)."""
    return {'apps': [APP], 'importable': [APP], 'blocked': [], 'result_rows': [[APP, 'imported']], 'exact': True,
            'select_stage': 'select-emqx',
            'texts': {'upload': 'UI uploaded original real fixture through actual page',
                      'select': 'UI selects only EMQX',
                      'view': 'UI check shows EMQX importable',
                      'result': 'UI result shows EMQX imported as the only row',
                      'intent': 'UI one click sends one real acknowledged import intent for EMQX only',
                      'lines': 'UI lists every confirmation line of the EMQX check',
                      'keys': 'UI import carries every listed confirmation key exactly once'}}


def cleanup_ready(trace, receipt, report, host_hits, browser):
    """Owned archives are deleted only after the whole case is proved: the page's flow and scan, the check, the keys,
    the two-job chain in one unit, HA's live data, dev-d's baseline back, and the strict scans before deletion."""
    first = trace.get('first_job_id')
    if not isinstance(first, str) or not JOB.fullmatch(first) or not isinstance(browser, dict):
        return False
    unit = 'woowtech-backup-' + first + '.service'
    return (trace.get('completed') is True and trace.get('browser_used') is True
            and browser.get('completed') is True and browser.get('issued_values_scanned') is True
            and trace.get('check_accepted') is True and trace.get('acknowledged_exact') is True
            and trace.get('chain_verified') is True and trace.get('native_units_verified') is True
            and trace.get('native_units') == [unit] * 2 and trace.get('restore_safety_verified') is True
            and trace.get('live_data_verified') is True
            and trace.get('all_observed_marker_tokens_registered') is True and trace.get('observed_marker_tokens', 0) > 0
            and receipt.get('baseline_restored') is True and not receipt.get('inflight')
            and report.get('hits') == 0 and report.get('scanned', 0) > 0 and host_hits == 0
            and report.get('regular_json_roots_scanned') == 2
            and report.get('archive_index_sidecars_scanned', 0) > 0
            and report.get('archive_index_sidecars_scanned') == trace.get('actual_sidecars'))
