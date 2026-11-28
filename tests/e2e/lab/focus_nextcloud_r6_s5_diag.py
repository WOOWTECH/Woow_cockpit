#!/usr/bin/env python3
"""ONE diagnostic run on dev-e (the coordinator's): why the product's check stopped on the S5-A fixture's PostgreSQL.

S5-B (focus_nextcloud_r6_s5b.py) stopped at ha-check-start: the check marked the generated server-side-encryption fixture
not importable with "podman exec postgres PGOPTIONS=-c search_path=pg_catalog 執行失敗（結束碼 2）：資料庫還沒有準備好（還在
啟動，或沒有在執行）。" about 11 s after the add-on member was read. This tool repeats the product's steps for the fixture's
PostgreSQL with the engine INSTALLED in dev-e and records what every step answered.

Leading suspicion (offline, see the tests): S5-A initialised its cluster with POSTGRES_USER=nextcloud
(focus_nextcloud_r6_s5.Native.source_args), so the bootstrap superuser is `nextcloud` and there is no role `postgres`;
the product opens HA's cluster as `postgres` (ha_odoo.Cluster), pg_isready answers "accepting connections" for a role
that does not exist (it only asks whether the server is up), the first psql fails at connect (exit 2) and
podman.classify files "connection to server on socket ... failed: FATAL: role "postgres" does not exist" under
db-not-ready, because that needle comes before role-missing in podman.REASONS.

Where (everything inside woowbk-dev-e, nothing through the host; one `labpodman exec`):
  launcher (root)  the S5-A proof root exactly as S5-A left it and the fixture's SHA-256 and provenance (else: refused,
                   nothing started); the fixture opened with the INSTALLED habackup (the product's own reader) and its
                   add-on member streamed on stdin to the worker (no copy anywhere); the proof root again afterwards
  worker (appowner through /usr/local/bin/woowbk-owner)  the installed engine as a library and the owner's rootless
                   Podman through podman.OwnerRunner.run (the product's runner; only runuser is left out: it already
                   runs as the owner):
      TempObjects(job j<utc>Z-5d1a<hex>)    the first of ha_odoo.PG16_IMAGES + PG16_PINNED already present (never a pull)
      tmp.user_ids('ids-pg', image, 'postgres'), volume 'hapg' <- ha_odoo.PgSink(ha_nextcloud.scan_member(member))
      [diag] pg_controldata of the volume and a listing of it (top level, pg_wal, archive_status), mounted read-only
      ha_odoo.start_ha_cluster(work, ha_nextcloud.Pinned(tmp, 'hapg'), image)            (wait_ready: pg_isready)
      ha_nextcloud.ha_database(cluster, dbname) (PINNED_OPTIONS): attempt 1 is the product's own call, right after
          wait_ready; again after SCHEDULE seconds while it fails
      [diag] pg_isready's answer in words; who can connect (-U postgres, config.php's dbuser, S5-A's POSTGRES_USER)
          and the bootstrap superuser (pg_roles oid 10); pg_controldata inside the running server; the container's
          state and its log
      tmp.remove('hapg'), tmp.remove_volume('hapg') (the check's own finally), then TempObjects.cleanup()
  host  lock (blocking, with a timeout), then cold/quiescent admission; after the run the product's own tempctr.sweep
        of THIS job id only, and engine, store, units, Quadlets, images, catalog and proof root compared with before.

Default-deny: nothing the cluster, a log or a command prints is kept as text. Log and stderr lines are kept only as ids
of a fixed list of PostgreSQL/psql messages (names only when they are one of a few known ones); pg_controldata only its
listed fields; config.php only whether dbname/dbuser are usable. Full detail: ~/.woowbk-lab/evidence/
focus-nextcloud-r6-s5-diag/<time>/ (0700, files 0600). One fixed JSON line on stdout.

  python3 -B -I tests/e2e/lab/focus_nextcloud_r6_s5_diag.py            the contract (offline)
  HEAVY_FREE=/tmp/woowbk-dev-e-mutation.lock heavy.sh python3 -B -I tests/e2e/lab/focus_nextcloud_r6_s5_diag.py --run
  ... --remove-retired-root --diagnostic-evidence ~/.woowbk-lab/evidence/focus-nextcloud-r6-s5-diag/<time>-<hex>
      after a diagnosed run: the first build's proof root (s5b.HISTORY, a literal path), proven exactly as S5-A left it,
      removed entry by entry (retire); nothing else.

The fixture is always the FIRST S5-A build's (s5b.HISTORY, its committed result kept as history), never S5-B's active
one. S5-A's rebuild reuses this machinery as its acceptance gate (open_check: layout 'fresh-build', one attempt) and keeps
the first build's root untouched while it is there (RETIRED_STATE in its before/after snapshot).
"""
import argparse
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))   # python3 -I puts no script directory on the path; only this committed directory
import focus_nextcloud_r6_case as case   # noqa: E402
import focus_nextcloud_r6_s5 as s5   # noqa: E402
import focus_nextcloud_r6_s5b as s5b   # noqa: E402
import focus_nextcloud_r6_upload as upload   # noqa: E402
import focus_nextcloud_r6_wake as wake   # noqa: E402
from focus_nextcloud_r6_inventory import DEVICE, LP, collect   # noqa: E402

REPO = HERE.parents[2]
LAB = Path.home() / '.woowbk-lab'
PHASE = 's5-check-postgres-diagnosis'
AREA = 'focus-nextcloud-r6-s5-diag'
EVIDENCE = LAB / 'evidence' / AREA
MARKERS = LAB / 'run' / (AREA + '-runs')
LOCK = '/tmp/woowbk-dev-e-mutation.lock'
LOCK_TIMEOUT = 1800
LOCK_POLL = 2
OWNER = 'appowner'
OWNER_EXEC = ('/usr/local/bin/woowbk-owner',)
PRODUCT_LIB = s5.PRODUCT_LIB
JOB_TAG = '5d1a'                       # the hex of this tool's job ids: j<utc>Z-5d1a<4 hex>
JOB_PATTERN = r'j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}'    # tempctr.JOB_RE
SCHEDULE = (0, 5, 10, 20, 40, 60)      # seconds after wait_ready returned: attempt 1 = the product's own call
WORKER_BUDGET = 900                    # the worker's own deadline (TempObjects abort hook), cleanup excluded
LAUNCH_GRACE = 600                     # the launcher waits this much longer before it gives up waiting (never kills)
S5A_POSTGRES_USER = 'nextcloud'        # focus_nextcloud_r6_s5.Native.source_args('pg'): --env=POSTGRES_USER=nextcloud
S5B_STOP = ('podman exec postgres PGOPTIONS=-c search_path=pg_catalog 執行失敗（結束碼 2）：'
            '資料庫還沒有準備好（還在啟動，或沒有在執行）。')
DEVIATIONS = (
    ('hapg-log-driver-k8s-file', 'the throwaway server logs to a bounded k8s-file log (not none) so podman logs can read it'),
    ('member-streamed-by-root-launcher', 'the fixture is opened with the installed habackup inside dev-e, not uploaded'),
    ('no-target-read', "this device's Nextcloud is neither read nor started (the product reads it before HA's cluster)"),
    ('no-share-member-walk', 'the data directory member is not walked (it never reaches the cluster)'),
    ('extra-read-only-containers', 'pg_controldata and a listing of the volume before the start, mounted read-only'),
    ('diagnostic-attempts-and-role-probe', 'the product makes one attempt; the later ones and the role probe are extra'),
    ('present-images-only', 'no bundled image load and no pull: only an image that is already present'),
)
# The modules the worker's path runs (an installed engine that differs here is reported, not refused).
RELEVANT = tuple('lib/woowbackup/' + name for name in (
    'errors.py', 'habackup.py', 'hacommon.py', 'haissues.py', 'ha_nextcloud.py', 'ha_odoo.py', 'hatarget.py', 'jobs.py',
    'podman.py', 'tempctr.py', 'util.py'))
DEVICE_OUTPUT = 8 * 1024 * 1024
HISTORY_RESULT = s5b.HISTORY_RESULT    # the first S5-A build's committed result: the fixture this tool diagnoses
RETIRE_AREA = 'focus-nextcloud-r6-s5-retire'
OPEN_BUDGET = 900                      # the product-path open check's worker deadline (S5-A keeps s5.OPEN_RESERVE for it)

# ---------------------------------------------------------------------- default-deny vocabulary (rendered on the device)
LSN = r'[0-9A-F]{1,8}/[0-9A-F]{1,8}'
MESSAGE_IDS = (
    ('role-missing', r'role "(?P<name>[^"]{1,128})" does not exist'),
    ('database-missing', r'database "(?P<name>[^"]{1,128})" does not exist'),
    ('starting-up', r'the database system is starting up'),
    ('in-recovery', r'the database system is in recovery mode'),
    ('not-yet-accepting', r'the database system is not yet accepting connections'),
    ('not-accepting', r'the database system is not accepting connections'),
    ('shutting-down', r'the database system is shutting down'),
    ('too-many-clients', r'sorry, too many clients already'),
    ('no-hba-entry', r'no pg_hba\.conf entry for .{0,300}'),
    ('auth-failed', r'(?:password|peer|ident|trust) authentication failed for user .{0,200}'),
    ('locale-incompatible', r'database locale is incompatible with operating system'),
    ('admin-terminate', r'terminating connection due to administrator command'),
    ('crash-of-another', r'terminating connection because of crash of another server process'),
    ('ready', r'database system is ready to accept connections'),
    ('ready-read-only', r'database system is ready to accept read-only connections'),
    ('starting', r'starting PostgreSQL (?P<version>[0-9]{2}\.[0-9]{1,3})\b.{0,300}'),
    ('listening-socket', r'listening on Unix socket "(?P<path>[^"]{1,120})"'),
    ('listening-ip', r'listening on IPv[46] address .{0,120}'),
    ('was-shut-down', r'database system was shut down at .{1,60}'),
    ('was-shut-down-in-recovery', r'database system was shut down in recovery at .{1,60}'),
    ('was-interrupted', r'database system was interrupted; last known up at .{1,60}'),
    ('interrupted-in-recovery', r'database system was interrupted while in recovery.{0,120}'),
    ('not-properly-shut-down', r'database system was not properly shut down; automatic recovery in progress'),
    ('redo-starts', r'redo starts at (?P<lsn>' + LSN + r')'),
    ('redo-done', r'redo done at (?P<lsn>' + LSN + r').{0,300}'),
    ('redo-not-required', r'redo is not required'),
    ('invalid-record-length', r'invalid record length at (?P<lsn>' + LSN + r').{0,120}'),
    ('checkpoint-starting', r'checkpoint starting:(?P<flags>(?: [a-z-]{1,20}){0,8})'),
    ('checkpoint-complete', r'checkpoint complete: .{0,600}'),
    ('shutdown-request', r'received (?P<kind>smart|fast|immediate) shutdown request'),
    ('aborting-transactions', r'aborting any active transactions'),
    ('shutting-down-log', r'shutting down'),
    ('is-shut-down', r'database system is shut down'),
    ('process-ended', r'(?P<proc>server process|startup process|checkpointer process|background writer process'
                      r'|WAL writer process|walwriter process|autovacuum launcher process|autovacuum worker process'
                      r'|archiver process|logical replication launcher|background worker "[A-Za-z ]{1,60}") '
                      r'\(PID [0-9]{1,10}\) (?P<how>was terminated by signal [0-9]{1,3}(?:: [A-Za-z ]{1,40})?'
                      r'|exited with exit code [0-9]{1,3})'),
    ('terminating-others', r'terminating any other active server processes'),
    ('reinitializing', r'all server processes terminated; reinitializing'),
    ('startup-aborted', r'aborting startup due to startup process failure'),
    ('no-valid-checkpoint', r'could not locate a valid checkpoint record.{0,120}'),
    ('invalid-checkpoint', r'invalid (?:primary |secondary )?checkpoint record.{0,120}'),
    ('data-dir-permissions', r'data directory "[^"]{1,200}" has invalid permissions'),
    ('data-dir-ownership', r'data directory "[^"]{1,200}" has wrong ownership'),
    ('incompatible-files', r'database files are incompatible with server'),
    ('invalid-parameter', r'invalid value for parameter "(?P<param>[a-z_.]{1,63})".{0,200}'),
    ('unrecognized-parameter', r'unrecognized configuration parameter "(?P<param>[a-z_.]{1,63})".{0,100}'),
    ('lockfile-exists', r'lock file "[^"]{1,120}" already exists'),
    ('out-of-memory', r'out of memory'),
    ('collation-mismatch', r'database "(?P<name>[^"]{1,128})" has a collation version mismatch'),
    ('relation-missing', r'relation "(?P<name>[^"]{1,128})" does not exist'),
    ('could-not', r'could not (?P<verb>[a-z]{2,12})(?: [a-z]{1,24}){0,5} "(?P<path>[^"]{1,200})"'
                  r'(?:: (?P<errno>[A-Za-z ]{2,60}))?\.?'),
    ('could-not', r'could not (?P<verb>[a-z]{2,12})\b.{0,300}'),
    ('hba-line', r'Connection matched (?:file "[^"]{1,200}" )?line (?P<n>[0-9]{1,4}): .{0,300}'),
    ('db-subdir-missing', r'The database subdirectory "(?P<path>[^"]{1,120})" is missing\.'),
    ('failed-process-running', r'Failed process was running: [\s\S]*'),
    ('hint-corrupted', r'This probably means that some data is corrupted.{0,300}'),
    ('hint-reconnect', r'In a moment you should be able to reconnect to the database and repeat your command\.'),
    ('hint-other-postmaster', r'Is another postmaster .{0,300}'),
    ('detail-rollback', r'The postmaster has commanded this server process to roll back.{0,300}'),
    ('detail-version', r'The data directory was initialized by PostgreSQL version (?P<version>[0-9]{1,2}).{0,300}'),
)
EXTRA_PATTERNS = {
    'version': r'[0-9]{1,2}(?:\.[0-9]{1,3})?', 'lsn': LSN, 'flags': r'(?: (?:shutdown|end-of-recovery|immediate|force|wait'
    r'|time|wal|xlog|flush-all|fast)){0,8}', 'kind': r'smart|fast|immediate', 'proc': r'[A-Za-z "]{3,80}',
    'how': r'[A-Za-z0-9 :]{3,80}', 'param': r'[a-z_.]{1,63}', 'verb': r'[a-z]{2,12}', 'errno': r'[A-Za-z ]{2,60}',
    'n': r'[0-9]{1,4}',
    'path': (r'(?:/var/lib/postgresql/data/)?(?:base|global|pg_[a-z_]{2,20}|PG_VERSION|postmaster\.(?:pid|opts)'
             r'|postgresql(?:\.auto)?\.conf|pg_hba\.conf|pg_ident\.conf)(?:/[A-Za-z0-9_.]{1,40}){0,4}'
             r'|/var/run/postgresql/\.s\.PGSQL\.5432(?:\.lock)?|/var/lib/postgresql/data'),
}
SAFE_NAMES = ('postgres', 'nextcloud', 'template0', 'template1')
SAFE_NAME_RE = r'oc_[a-z0-9_]{1,40}'                   # Nextcloud's own: its role oc_<admin>, its tables oc_*
LOG_LINE = (r'(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})? [A-Za-z0-9+-]{1,8}) '
            r'\[(?P<pid>[0-9]{1,10})\] (?P<level>[A-Z]{3,9}):  (?P<msg>.*)')
PLAIN_LINE = (r'(?P<level>FATAL|PANIC|ERROR|WARNING|LOG|DETAIL|HINT|NOTICE|INFO|DEBUG[1-5]?|STATEMENT|CONTEXT|QUERY'
              r'|LOCATION):  ?(?P<msg>.*)')
PSQL_LINE = r'psql: error: connection to server on socket "(?P<socket>[^"]{1,160})" failed: (?P<rest>.*)'
KEPT_LEVELS = ('LOG', 'FATAL', 'PANIC', 'ERROR', 'WARNING', 'HINT', 'DETAIL')
SOCKET = '/var/run/postgresql/.s.PGSQL.5432'
PSQL_REST = {'No such file or directory': 'no-socket-file', 'Connection refused': 'connection-refused',
             'server closed the connection unexpectedly': 'server-closed',
             'Resource temporarily unavailable': 'socket-busy', 'Permission denied': 'socket-permission'}
FIXED_LINES = {
    'PostgreSQL Database directory appears to contain a database; Skipping initialization': 'entrypoint-skip-init',
    'Is the server running locally and accepting connections on that socket?': 'hint-is-server-running',
    'This probably means the server terminated abnormally': 'hint-terminated-abnormally',
    'before or while processing the request.': 'hint-before-or-while',
    'server closed the connection unexpectedly': 'server-closed',
    'connection to server was lost': 'connection-lost',
}
TS_RE = r'[A-Za-z0-9 :+.,-]{5,48}'
CONTROL_FIELDS = (
    ('pg_control version number', 'pg_control_version', r'[0-9]{1,6}'),
    ('Catalog version number', 'catalog_version', r'[0-9]{1,12}'),
    ('Database cluster state', 'state', r'starting up|shut down|shut down in recovery|shutting down|in crash recovery'
                                        r'|in archive recovery|in production'),
    ('pg_control last modified', 'last_modified', TS_RE),
    ('Latest checkpoint location', 'checkpoint', LSN),
    ("Latest checkpoint's REDO location", 'redo', LSN),
    ("Latest checkpoint's REDO WAL file", 'redo_wal_file', r'[0-9A-F]{24}'),
    ("Latest checkpoint's TimeLineID", 'timeline', r'[0-9]{1,10}'),
    ("Latest checkpoint's PrevTimeLineID", 'prev_timeline', r'[0-9]{1,10}'),
    ("Latest checkpoint's full_page_writes", 'full_page_writes', r'on|off'),
    ("Latest checkpoint's NextXID", 'next_xid', r'[0-9]{1,10}:[0-9]{1,10}'),
    ('Time of latest checkpoint', 'checkpoint_time', TS_RE),
    ('Minimum recovery ending location', 'min_recovery_end', LSN),
    ('Backup start location', 'backup_start', LSN),
    ('Backup end location', 'backup_end', LSN),
    ('End-of-backup record required', 'end_of_backup_required', r'yes|no'),
    ('wal_level setting', 'wal_level', r'minimal|replica|logical'),
    ('Data page checksum version', 'checksum_version', r'[0-9]{1,3}'),
    ('Bytes per WAL segment', 'wal_segment_bytes', r'[0-9]{1,12}'),
    ('Database block size', 'block_size', r'[0-9]{1,6}'),
)
DATA_DIR = '/var/lib/postgresql/data'   # ha_odoo.HA_DATA (the tests compare)
LISTING_SH = ('cd ' + DATA_DIR + ' || exit 3; stat -c "%F|%a|%u|%g|%s|%n" . 2>/dev/null; '
              'for f in * pg_wal/* pg_wal/archive_status/* pg_logical/* pg_multixact/*; do '
              '[ -e "$f" ] || [ -L "$f" ] || continue; stat -c "%F|%a|%u|%g|%s|%n" "$f" 2>/dev/null; done; exit 0')
LISTING_RE = (r'(?P<type>directory|regular file|regular empty file|symbolic link|fifo|socket|block special file'
              r'|character special file)\|(?P<mode>[0-7]{1,4})\|(?P<uid>[0-9]{1,10})\|(?P<gid>[0-9]{1,10})'
              r'\|(?P<size>[0-9]{1,15})\|(?P<name>.{1,200})')
EXPECTED_DIRS = ('base', 'global', 'pg_commit_ts', 'pg_dynshmem', 'pg_logical', 'pg_multixact', 'pg_notify', 'pg_replslot',
                 'pg_serial', 'pg_snapshots', 'pg_stat', 'pg_stat_tmp', 'pg_subtrans', 'pg_tblspc', 'pg_twophase', 'pg_wal',
                 'pg_xact')
EXPECTED_FILES = ('PG_VERSION', 'pg_hba.conf', 'pg_ident.conf', 'postgresql.auto.conf', 'postgresql.conf')
EXPECTED_SUB = ('pg_logical/mappings', 'pg_logical/snapshots', 'pg_multixact/members', 'pg_multixact/offsets',
                'pg_wal/archive_status')
OTHER_TOP = ('postmaster.pid', 'postmaster.opts', 'backup_label', 'tablespace_map', 'recovery.signal', 'standby.signal',
             'current_logfiles', 'backup_label.old', 'pg_logical/replorigin_checkpoint')
WAL_RE = r'[0-9A-F]{24}(?:\.partial)?|[0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup'
ROLE_PROBE_SQL = ("SELECT json_build_object('bootstrap', (SELECT rolname FROM pg_catalog.pg_roles WHERE oid = 10), "
                  "'postgres_role', EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'postgres'), "
                  "'postgres_db', EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = 'postgres'), "
                  "'superusers', (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolsuper), "
                  "'roles', (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname !~ '^pg_'))")
INSPECT_FORMAT = ('{"status":"{{.State.Status}}","running":{{.State.Running}},"exit":{{.State.ExitCode}},'
                  '"oom":{{.State.OOMKilled}},"restarts":{{.RestartCount}}}')
STATUSES = ('created', 'running', 'paused', 'stopped', 'exited', 'stopping', 'removing', 'configured', 'initialized')
NAME_PATTERN = r'woowbk-(j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})-([a-z0-9][a-z0-9-]{0,30})'   # tempctr.NAME_RE
PROGRAMS = ('pg_isready', 'psql', 'pg_controldata', 'pg_dump', 'sh')
OPS = ('run', 'exec', 'volume', 'container', 'logs', 'rm', 'image', 'unshare', 'ps', 'network', 'stop', 'kill')
KNOWN_MESSAGES = ('暫用的 PostgreSQL 沒有啟動（資料可能不完整或版本不符）。', '暫用 PostgreSQL 的回應格式不正確。',
                  '無法讀取 HA 的資料庫清單。', '無法讀取 HA 的 Nextcloud 資料表。', '無法讀取 HA 的 Nextcloud 資料庫內容。',
                  '找不到這個作業的暫用容器。', '只能匯入這個作業建立的資料卷。', '暫存檔路徑不正確。')
MESSAGE_PATTERNS = (r'暫用的 PostgreSQL 在 [0-9]{1,6} 秒內沒有就緒。',
                    r'(?:podman|owner-file|owner-dir)(?: [^\x00-\x1f]{1,200})? 執行失敗（結束碼 -?[0-9]{1,3}）(?:：.{1,80}|。)',
                    r'(?:podman|owner-file|owner-dir)(?: [^\x00-\x1f]{1,200})? 執行逾時（[0-9]{1,6} 秒）.{0,80}',
                    r'fixed-s5(?:diag|b)-[a-z0-9-]{1,80}')
LOG_TAIL = 1000
LOG_KEEP = 400
MAX_CALLS = 3000
MEMBER_LIMIT = 1024 ** 3
WORKER_OUTPUT = 6 * 1024 * 1024


# ====================================================================== device functions (rendered; also unit-tested)

def need(ok, reason):
    if not ok:
        raise ValueError('fixed-s5diag-' + reason)


def safe_name(name):
    """A role, database or table name as it may be kept: one of the few known names, else only its length."""
    if not isinstance(name, str):
        return None
    if name in SAFE_NAMES or re.fullmatch(SAFE_NAME_RE, name):
        return name
    return 'other(len=%d)' % len(name)


def message_id(msg):
    """The id of a PostgreSQL message (MESSAGE_IDS) with the fields it may keep; 'unrecognized' otherwise. The text
    itself is never kept."""
    for ident, pattern in MESSAGE_IDS:
        match = re.fullmatch(pattern, msg)
        if not match:
            continue
        extras = []
        for key, value in sorted((k, v) for k, v in match.groupdict().items() if v is not None):
            if key == 'name':
                value = safe_name(value)
            elif not re.fullmatch(EXTRA_PATTERNS[key], value):
                value = 'other'
            extras.append('%s=%s' % (key, value.strip()))
        return ' '.join([ident] + extras)
    return 'unrecognized'


def line_fact(line):
    """One line of a server log or of a command's stderr as a fixed fact: {'id', ['ts', 'pid']}."""
    match = re.fullmatch(LOG_LINE, line)
    if match:
        level = match.group('level')
        return {'ts': match.group('ts'), 'pid': int(match.group('pid')),
                'id': level + ' ' + (message_id(match.group('msg')) if level in KEPT_LEVELS else 'dropped')}
    match = re.fullmatch(PSQL_LINE, line)
    if match:
        where = 'psql-connect' + ('' if match.group('socket') == SOCKET else ' other-socket')
        rest = match.group('rest').strip()
        inner = re.fullmatch(PLAIN_LINE, rest)
        if inner and inner.group('level') in KEPT_LEVELS:
            return {'id': where + ' ' + inner.group('level') + ' ' + message_id(inner.group('msg'))}
        return {'id': where + ' ' + PSQL_REST.get(rest, 'unrecognized')}
    match = re.fullmatch(PLAIN_LINE, line)
    if match:
        level = match.group('level')
        return {'id': level + ' ' + (message_id(match.group('msg')) if level in KEPT_LEVELS else 'dropped')}
    if line in FIXED_LINES:
        return {'id': FIXED_LINES[line]}
    if re.fullmatch(r'LINE [0-9]{1,6}: [\s\S]*|\^', line):
        return {'id': 'psql-line-dropped'}
    return {'id': 'unrecognized'}


def filter_lines(raw, limit=LOG_KEEP):
    """Every non-empty line as a fact (line_fact): the first `limit` in order, and how many of each id."""
    text = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else str(raw or '')
    kept, counts, total = [], {}, 0
    for line in text.splitlines()[-20000:]:
        line = line.strip()
        if not line:
            continue
        total += 1
        fact = line_fact(line)
        counts[fact['id']] = counts.get(fact['id'], 0) + 1
        if len(kept) < limit:
            kept.append(fact)
    return {'lines': total, 'kept': kept, 'counts': counts}


def parse_controldata(raw):
    """pg_controldata's output, only the CONTROL_FIELDS whose value has the expected form."""
    text = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else str(raw or '')
    wanted = {label: (key, pattern) for label, key, pattern in CONTROL_FIELDS}
    out, other = {}, 0
    for line in text.splitlines():
        label, sep, value = line.partition(':')
        if not sep or label.strip() not in wanted:
            other += bool(line.strip())
            continue
        key, pattern = wanted[label.strip()]
        value = value.strip()
        out[key] = value if re.fullmatch(pattern, value) else 'unreadable'
    out['other_lines'] = other
    return out


def parse_listing(raw):
    """LISTING_SH's lines: the data dir's root, the expected entries that are missing, pg_wal and archive_status."""
    text = raw.decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else str(raw or '')
    rows, unknown = {}, 0
    for line in text.splitlines():
        match = re.fullmatch(LISTING_RE, line.strip())
        if not match:
            unknown += bool(line.strip())
            continue
        rows[match.group('name')] = {k: (int(v) if k in ('uid', 'gid', 'size') else v)
                                     for k, v in match.groupdict().items() if k != 'name'}
    known = set(EXPECTED_DIRS) | set(EXPECTED_FILES) | set(EXPECTED_SUB) | set(OTHER_TOP) | {'.'}
    wal = [dict(rows[n], name=n.split('/', 1)[1]) for n in sorted(rows)
           if n.startswith('pg_wal/') and re.fullmatch(WAL_RE, n.split('/', 1)[1])]
    status = [n.split('/', 2)[2] for n in sorted(rows) if n.startswith('pg_wal/archive_status/')
              and re.fullmatch(r'(?:' + WAL_RE + r')\.(?:ready|done)', n.split('/', 2)[2])]
    listed = {n for n in rows if n in known} | {'pg_wal/' + w['name'] for w in wal} | {'pg_wal/archive_status/' + s
                                                                                       for s in status}
    out = {'root': rows.get('.'),
           'top': {n: rows[n] for n in sorted(rows) if n in known and n != '.'},
           'missing_dirs': [n for n in EXPECTED_DIRS + EXPECTED_SUB if (rows.get(n) or {}).get('type') != 'directory'],
           'missing_files': [n for n in EXPECTED_FILES if not (rows.get(n) or {}).get('type', '').startswith('regular')],
           'present_other': [n for n in OTHER_TOP if n in rows],
           'wal': wal, 'archive_status': status,
           'unknown_entries': len(set(rows) - listed), 'unparsed_lines': unknown}
    return out


def swap_log_driver(args):
    """A product `podman run` argument list with its `--log-driver none` switched to a bounded k8s-file log."""
    args = list(args)
    for index in range(len(args) - 1):
        if args[index] == '--log-driver' and args[index + 1] == 'none':
            return args[:index + 1] + ['k8s-file', '--log-opt', 'max-size=4mb'] + args[index + 2:]
    raise ValueError('fixed-s5diag-log-driver-not-found')


def _after(args, flag):
    for index in range(len(args) - 1):
        if args[index] == flag:
            return args[index + 1]
    return None


def call_facts(args, label_sql):
    """What a podman call was, as fixed facts (never a value of a secret or of the cluster)."""
    op = args[0] if args else ''
    row = {'op': op if op in OPS else 'other'}
    names = [a for a in args if re.fullmatch(NAME_PATTERN, a)]
    if names:
        row['role'] = re.fullmatch(NAME_PATTERN, names[0]).group(2)
    if op == 'run':
        row['log_driver'] = _after(args, '--log-driver')
    elif op == 'exec' and names:
        index = args.index(names[0])
        program, rest = (args[index + 1] if index + 1 < len(args) else ''), args[index + 2:]
        row['program'] = program if program in PROGRAMS else 'other'
        row['pinned'] = 'PGOPTIONS=-c search_path=pg_catalog' in args[:index]
        if program == 'pg_isready':
            row['quiet'] = '-q' in rest
        if program == 'psql':
            row['user'] = safe_name(_after(rest, '-U'))
            database = _after(rest, '-d')
            row['database'] = safe_name(database) if database else (
                'by-env' if any(a.startswith('PGDATABASE=') for a in args[:index]) else 'default')
            sql = _after(rest, '-c')
            row['sql'] = label_sql(sql) if sql is not None else ('stdin' if '-f' in rest else None)
    elif len(args) > 1 and op in ('volume', 'container', 'image', 'unshare', 'network'):
        row['sub'] = args[1] if re.fullmatch(r'[a-z]{2,12}', args[1]) else 'other'
    return row


def fixed_error(error):
    """An exception as fixed facts: its class, code, reason and exit code; its message only when it is one of the
    product's fixed sentences of this path (else its length and a digest prefix)."""
    message = getattr(error, 'message', None)
    if not isinstance(message, str):
        message = str(error)
    row = {'class': type(error).__name__, 'code': getattr(error, 'code', None),
           'reason': getattr(error, 'reason', None) or (getattr(error, 'details', None) or {}).get('reason'),
           'returncode': getattr(error, 'returncode', None), 'equals_s5b_stop': message == S5B_STOP}
    if message in KNOWN_MESSAGES or any(re.fullmatch(p, message) for p in MESSAGE_PATTERNS):
        row['message'] = message
    else:
        row['message_withheld'] = {'chars': len(message),
                                   'sha256_16': hashlib.sha256(message.encode('utf-8', 'replace')).hexdigest()[:16]}
    stderr = getattr(error, 'stderr', None)
    if stderr:
        row['stderr'] = filter_lines(stderr, limit=20)
    return row


class HashingReader:
    """The add-on member as the launcher sends it: read(n) hashes and counts what passes, at most `limit` bytes."""

    def __init__(self, stream, limit):
        self.stream, self.limit, self.count, self.hash = stream, limit, 0, hashlib.sha256()

    def read(self, n=-1):
        data = self.stream.read(n if n is not None and n >= 0 else 1024 * 1024)
        self.count += len(data)
        if self.count > self.limit:
            raise ValueError('fixed-s5diag-member-too-large')
        self.hash.update(data)
        return data

    def seekable(self):
        return False

    def drain(self):
        while self.read(1024 * 1024):
            pass
        return {'bytes': self.count, 'sha256': self.hash.hexdigest()}


class Recorder:
    """The owner's runner as TempObjects uses it: every podman call recorded as fixed facts (call_facts, rc, the
    classified reason, stderr ids); the `run` of a container named in `logged` gets a k8s-file log (swap_log_driver)."""

    def __init__(self, base, classify, clock):
        self.base, self.classify, self.clock = base, classify, clock
        self.t0 = clock()
        self.calls, self.logged, self.run_argv = [], set(), {}
        self.label_sql = lambda sql: 'other'

    def __getattr__(self, name):
        return getattr(self.base, name)

    def podman(self, *args, **kwargs):
        args = [str(a) for a in args]
        if args[:1] == ['run'] and any(name in args for name in self.logged):
            args = swap_log_driver(args)
            self.run_argv[_after(args, '--name')] = list(args)
        row = call_facts(args, self.label_sql)
        row['t'] = round(self.clock() - self.t0, 2)
        try:
            result = self.base.podman(*args, **kwargs)
        except Exception as error:
            row.update(rc=getattr(error, 'returncode', None), error=type(error).__name__,
                       reason=getattr(error, 'reason', None) or (getattr(error, 'details', None) or {}).get('reason'))
            if getattr(error, 'stderr', None):
                row['stderr'] = filter_lines(error.stderr, limit=10)
            self._keep(row)
            raise
        row['rc'] = result.returncode
        if result.returncode:
            row['reason'] = self.classify(result.stderr, result.returncode)[0]
            row['stderr'] = filter_lines(result.stderr, limit=10)
        self._keep(row)
        return result

    def _keep(self, row):
        if len(self.calls) < MAX_CALLS:
            self.calls.append(row)


def make_owner_runner(podman_module, owner, **kwargs):
    """podman.OwnerRunner of `owner`, run BY the owner: OwnerRunner.run (fixed environment, the product's budgets,
    classify and CommandError) without its `runuser -u <owner> --` (only root may use it; this process is the owner)."""
    class AsOwner(podman_module.OwnerRunner):
        def prefix(self):
            full = super().prefix()
            need(full[:4] == [podman_module.RUNUSER, '-u', self.owner, '--'], 'owner-runner-prefix')
            return full[4:]
    runner = AsOwner(owner, **kwargs)
    need(kwargs.get('runner') is not None or os.getuid() == runner.uid, 'not-the-owner')
    return runner


def details_shape(details):
    """What ha_database answered, as counts and known names only (the encryption flag read the way Nextcloud reads
    it, without ha_nextcloud.nc_true: an installed engine before 50a29370 has none)."""
    if not isinstance(details, dict):
        return {'database_found': details is not None, 'type': type(details).__name__}
    counts = details.get('counts') if isinstance(details.get('counts'), dict) else {}
    lists = details.get('lists')
    flag = details.get('encryption')
    nc_true = lambda value: isinstance(value, str) and value.lower() in ('1', 'true', 'yes', 'on')   # noqa: E731
    return {'database_found': True, 'nextcloud': details.get('nextcloud') is True,
            'tables': len(details.get('tables') or ()),
            'counts': {k: v for k, v in counts.items() if re.fullmatch(r'[a-z_]{1,40}', str(k)) and type(v) is int},
            'extensions': [e for e in details.get('extensions') or [] if isinstance(e, str)
                           and re.fullmatch(r'[a-z0-9_-]{1,63}', e)],
            'schemas': len(details.get('schemas') or ()), 'local_storages': len(details.get('local_storages') or ()),
            'enabled_apps': len(details.get('enabled') or ()), 'encryption_enabled': nc_true(flag),
            'skipped_objects': len(details.get('skipped') or ()),
            'shape_read': isinstance(details.get('shape'), dict),
            'file_lists': len(lists) if isinstance(lists, list) else None}


def isready_answer(pinned):
    """One more pg_isready, not quiet: its answer word (the product's wait_ready asks with -q)."""
    result = pinned.exec('hapg', ['pg_isready', '-U', 'postgres'], user='postgres', check=False, timeout=60,
                         max_output=64 * 1024)
    text = (result.stdout or b'').decode('utf-8', 'replace').strip()
    match = re.fullmatch(r'/var/run/postgresql:5432 - (accepting connections|rejecting connections|no response'
                         r'|no attempt)', text)
    return {'rc': result.returncode, 'answer': match.group(1) if match else ('empty' if not text else 'unrecognized')}


def role_probe(lib, pinned, config):
    """Diagnostic only: who can connect to HA's cluster (pinned, socket, trust) -- postgres, config.php's dbuser,
    S5-A's POSTGRES_USER -- and who its bootstrap superuser is (pg_roles oid 10); catalog views only."""
    config = config if isinstance(config, dict) else {}
    dbuser, dbname = config.get('dbuser'), config.get('dbname')
    candidates = [('postgres', 'postgres')]
    if isinstance(dbuser, str) and re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', dbuser) and dbuser != 'postgres':
        candidates.append(('config-dbuser', dbuser))
    if S5A_POSTGRES_USER not in [role for _label, role in candidates]:
        candidates.append(('s5a-postgres-user', S5A_POSTGRES_USER))
    databases = ['postgres']
    if isinstance(dbname, str) and re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', dbname) and dbname != 'postgres':
        databases.append(dbname)
    tried = []
    for label, role in candidates:
        for database in databases:
            try:
                doc = lib.ha_odoo.Cluster(pinned, 'hapg', superuser=role).query_json(ROLE_PROBE_SQL, database, timeout=60)
            except lib.errors.BackupError as error:
                tried.append({'as': label, 'database': safe_name(database), 'error': fixed_error(error)})
                continue
            if not isinstance(doc, dict):
                tried.append({'as': label, 'database': safe_name(database), 'error': 'unreadable-answer'})
                continue
            flag = lambda key: doc.get(key) if isinstance(doc.get(key), bool) else None   # noqa: E731
            number = lambda key: doc.get(key) if type(doc.get(key)) is int else None   # noqa: E731
            return {'connected_as': label, 'database': safe_name(database), 'tried': tried,
                    'bootstrap_superuser': safe_name(doc.get('bootstrap')), 'postgres_role': flag('postgres_role'),
                    'postgres_database': flag('postgres_db'), 'superusers': number('superusers'),
                    'roles': number('roles')}
    return {'connected_as': None, 'tried': tried}


def server_state(runner, name):
    """The throwaway server's container state and its log (filter_lines), read before anything is removed."""
    out = {}
    result = runner.podman('container', 'inspect', '--format', INSPECT_FORMAT, name, timeout=60, max_output=64 * 1024,
                           check=False)
    try:
        doc = json.loads(result.stdout or b'null') if result.returncode == 0 else None
    except ValueError:
        doc = None
    if isinstance(doc, dict):
        out['state'] = {'status': doc.get('status') if doc.get('status') in STATUSES else 'other',
                        'running': doc.get('running') is True, 'oom': doc.get('oom') is True,
                        'exit': doc.get('exit') if type(doc.get('exit')) is int else None,
                        'restarts': doc.get('restarts') if type(doc.get('restarts')) is int else None}
    else:
        out['state'] = {'readable': False, 'rc': result.returncode}
    result = runner.podman('logs', '--tail', str(LOG_TAIL), name, timeout=60, max_output=1024 * 1024, check=False)
    out['log_rc'] = result.returncode
    out['log'] = filter_lines((result.stdout or b'') + b'\n' + (result.stderr or b''))
    return out


def wait_until(target, clock, sleep, wall, deadline):
    while clock() < target:
        need(wall() < deadline, 'worker-deadline')
        sleep(min(1.0, max(0.0, target - clock())))


def diagnose(request, stream, lib, runner, *, clock=time.monotonic, sleep=time.sleep, wall=time.time):
    """The product's check steps for HA's PostgreSQL (ha_nextcloud.check: member_pass, start_ha_cluster, ha_database,
    its finally), the diagnostic reads around them, and the facts of every step. Never raises: a failure is recorded
    and the owned objects still go (the check's own finally, then TempObjects.cleanup and its context)."""
    out = {'status': 'failed', 'stage': 'start', 'deviations': [ident for ident, _why in DEVIATIONS], 'order': []}
    notes = []
    job = request.get('job_id')
    deadline = request.get('deadline')

    def note(text):
        if len(notes) < 50:
            notes.append(str(text)[:200])

    def stage(name):
        out['stage'] = name
        need(wall() < deadline, 'worker-deadline')

    def abort():
        return lib.errors.BackupError('job-failed', 'fixed-s5diag-worker-deadline') if wall() > deadline else None

    try:
        sql = {lib.ha_odoo.DATABASES_SQL: 'databases', lib.ha_nextcloud.TABLES_SQL: 'tables',
               lib.ha_nextcloud.SHAPE_SQL: 'shape', lib.ha_nextcloud.OBJECTS_SQL: 'objects', lib.ha_nextcloud.HA_SQL: 'ha',
               lib.ha_nextcloud.FILES_SQL: 'files', ROLE_PROBE_SQL: 'role-probe'}
        runner.label_sql = lambda text: sql.get(text) or ('counts' if text.startswith("SELECT json_build_object('")
                                                          else 'other')
        need(isinstance(job, str) and lib.tempctr.JOB_RE.fullmatch(job) and job.split('-')[1].startswith(JOB_TAG),
             'job-id')
        need(isinstance(deadline, (int, float)) and wall() < deadline, 'worker-deadline')
        need(lib.ha_odoo.HA_DATA == DATA_DIR, 'data-dir-differs')
        with lib.tempctr.TempObjects(runner, job, log=note, abort=abort) as tmp:
            hapg = tmp.name('hapg')
            runner.logged.add(hapg)
            lib.hatarget.scale_waits(tmp, SimpleNamespace(layout=SimpleNamespace(size=request.get('layout_size'))))
            try:
                stage('image')       # ha_odoo.pick_pg16: the first present (hatarget.image_present's own command)
                checked, image = [], None
                for ref in (*lib.ha_odoo.PG16_IMAGES, lib.ha_odoo.PG16_PINNED):
                    result = runner.podman('image', 'inspect', '--format', '{{.Id}}', ref, timeout=60,
                                           max_output=64 * 1024, check=False)
                    checked.append([ref, result.returncode == 0])
                    if result.returncode == 0:
                        image_id = (result.stdout or b'').decode('ascii', 'replace').strip()
                        image = ref
                        out['image'] = {'ref': ref, 'id': image_id if re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}', image_id)
                                        else 'unreadable', 'checked': checked}
                        break
                need(image is not None, 'no-pg16-image-present-never-pulled')
                stage('user-ids')    # ha_nextcloud.member_pass
                pg_ids = tmp.user_ids('ids-pg', image, 'postgres')
                out['pg_ids'] = list(pg_ids)
                stage('member-pass')
                report = lib.habackup.Report(names=lib.haissues.Names)
                holder = {}

                def produce(target):
                    sink = lib.ha_odoo.PgSink(target, *pg_ids, guard=None)
                    holder['src'] = lib.ha_nextcloud.scan_member(stream, report, pg=sink, apps=None,
                                                                 machine=lib.hacommon.host_elf_machine(), checkpoint=None)
                    sink.close()
                    holder['sink'] = {'root_entry_in_member': sink.root_written, 'replaced_in_member': sorted(sink.replaced)}

                tmp.volume('hapg')
                tmp.volume_import('hapg', produce)
                received = stream.drain()
                src = holder['src']
                config = src.config if isinstance(src.config, dict) else None
                dbname = config.get('dbname') if config else None
                dbuser = config.get('dbuser') if config else None
                out['member'] = dict(received, report_complete=report.complete, pg_version=src.pg_version,
                                     pg_files=src.pg_files, pg_bytes=src.pg_bytes, recovery_files=src.recovery_files,
                                     config_found=src.config_found, config_parsed=config is not None,
                                     dbname=safe_name(dbname), dbuser=safe_name(dbuser), custom_apps=len(src.apps),
                                     **holder['sink'])
                stage('controldata-before')    # diagnostic, read-only mount
                volume = [(tmp.name('hapg'), DATA_DIR, 'ro')]
                result = tmp.run('diag-ctl', image, [DATA_DIR], entrypoint='pg_controldata', user='postgres',
                                 read_only_root=True, volumes=volume, timeout=120, max_output=64 * 1024, check=False)
                out['controldata_before'] = dict(parse_controldata(result.stdout), rc=result.returncode)
                stage('listing-before')        # diagnostic, read-only mount
                result = tmp.run('diag-ls', image, ['-c', LISTING_SH], entrypoint='sh', user='0', read_only_root=True,
                                 volumes=volume, timeout=120, max_output=256 * 1024, check=False)
                out['listing_before'] = dict(parse_listing(result.stdout), rc=result.returncode)
                stage('product-condition')     # ha_nextcloud.check: the cluster is started only for a usable config
                condition = bool(config is not None and isinstance(dbname, str) and lib.ha_nextcloud.DB_RE.fullmatch(dbname)
                                 and lib.ha_odoo._ha_major(src) == 16 and not src.recovery_files)
                out['product_condition'] = condition
                need(condition, 'product-would-not-start-the-cluster')
                stage('start')                 # ha_nextcloud.check, exactly
                pinned = lib.ha_nextcloud.Pinned(tmp, 'hapg')
                work = SimpleNamespace(log=note, checkpoint=None)
                started = clock()
                try:
                    cluster = lib.ha_odoo.start_ha_cluster(work, pinned, image)
                except lib.errors.BackupError as error:
                    out['wait_ready'] = {'ok': False, 'seconds': round(clock() - started, 1), 'error': fixed_error(error)}
                    raise
                ready = clock()
                out['wait_ready'] = {'ok': True, 'seconds': round(ready - started, 1)}
                stage('details')               # attempt 1: the product's own call, right after wait_ready; then retries
                attempts = []
                for at in tuple(request.get('schedule') or (0,))[:8]:
                    wait_until(ready + at, clock, sleep, wall, deadline)
                    mark = len(runner.calls)
                    try:
                        details = lib.ha_nextcloud.ha_database(cluster, dbname)
                    except lib.errors.BackupError as error:
                        failed = [row for row in runner.calls[mark:] if row.get('rc') or row.get('error')]
                        attempts.append({'at': at, 'ok': False, 'error': fixed_error(error),
                                         'failed_call': failed[-1] if failed else None})
                        continue
                    attempts.append({'at': at, 'ok': True, 'details': details_shape(details)})
                    break
                out['attempts'] = attempts
                out['isready_after_attempts'] = isready_answer(pinned)
                stage('role-probe')            # diagnostic
                out['role_probe'] = role_probe(lib, pinned, config)
                stage('controldata-after')     # diagnostic, inside the running server, read-only
                result = tmp.exec('hapg', ['pg_controldata', DATA_DIR], user='postgres', check=False, timeout=60,
                                  max_output=64 * 1024)
                out['controldata_after'] = dict(parse_controldata(result.stdout), rc=result.returncode)
                out['isready_end'] = isready_answer(pinned)
                out['status'] = 'completed'
            except Exception as error:   # noqa: BLE001 - recorded; the owned objects still go below
                out['failure'] = {'stage': out['stage'], 'error': fixed_error(error)}
            finally:
                out['run_argv'] = runner.run_argv.get(hapg)    # the product's argv as sent (log driver switched)
                if hapg in tmp.containers:
                    out['order'].append('server-state')
                    try:
                        out['server'] = server_state(runner, hapg)
                    except Exception as error:   # noqa: BLE001
                        out['server'] = {'error': fixed_error(error)}
                out['order'].append('remove-container')     # ha_nextcloud.check's finally
                tmp.remove('hapg')
                out['order'].append('remove-volume')
                tmp.remove_volume('hapg')
                out['order'].append('cleanup')
                out['left'] = tmp.cleanup()
    except Exception as error:   # noqa: BLE001 - before or around TempObjects
        out.setdefault('failure', {'stage': out['stage'], 'error': fixed_error(error)})
    out['notes'] = notes
    out['calls'] = runner.calls
    return out


def worker_main():
    """Owner side: the request line, then the add-on member on stdin; one JSON document on stdout."""
    signal.signal(signal.SIGTERM, lambda *_args: sys.exit(143))   # unwinds: TempObjects removes what it made
    raw = sys.stdin.buffer
    request = json.loads(raw.readline(64 * 1024) or b'{}')
    sys.path.insert(0, PRODUCT_LIB)
    from woowbackup import errors, habackup, hacommon, haissues, ha_nextcloud, ha_odoo, hatarget, podman, tempctr
    lib = SimpleNamespace(errors=errors, habackup=habackup, hacommon=hacommon, haissues=haissues,
                          ha_nextcloud=ha_nextcloud, ha_odoo=ha_odoo, hatarget=hatarget, podman=podman, tempctr=tempctr)
    runner = Recorder(make_owner_runner(podman, OWNER), podman.classify, time.monotonic)
    result = diagnose(request, HashingReader(raw, MEMBER_LIMIT), lib, runner)
    result['owner_uid'] = os.getuid()
    print(json.dumps(result))


# ---------------------------------------------------------------------- launcher (root, inside dev-e)

def _drain(pipe, sink, limit, keep_tail, flags):
    """Read a worker pipe to its end, keeping at most `limit` bytes (its head, or its tail)."""
    for block in iter(lambda: pipe.read(65536), b''):
        sink += block
        if len(sink) > limit:
            if keep_tail:
                del sink[:-limit]
            else:
                del sink[limit:]
                flags['truncated'] = True


def stream_member(opened, request, worker, popen, timeout):
    """Start the worker as the owner, hand it the request line and the add-on member (the installed habackup's
    MemberStream), wait for it. The worker is never killed: its own deadline ends it and its cleanup still runs."""
    out, stdout, stderr, flags = {}, bytearray(), bytearray(), {}
    sent, count, broken = hashlib.sha256(), 0, None
    proc = popen([*OWNER_EXEC, PYTHON, '-I', '-c', worker], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE)
    readers = [threading.Thread(target=_drain, args=(proc.stdout, stdout, WORKER_OUTPUT, False, flags), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, stderr, 64 * 1024, True, {}), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        proc.stdin.write(json.dumps(request).encode() + b'\n')
        with opened.open_addon(SLUG) as member:
            for block in iter(lambda: member.read(1024 * 1024), b''):
                sent.update(block)
                count += len(block)
                proc.stdin.write(block)
    except BrokenPipeError:
        broken = 'worker-stopped-reading'
    except Exception as error:   # noqa: BLE001 - the reader failed: the worker sees the end of its input and cleans up
        broken = 'reader-' + type(error).__name__
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            broken = broken or 'worker-stopped-reading'
    try:
        out['worker_rc'] = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        out['worker_rc'], out['worker_timeout'] = None, True
    for reader in readers:
        reader.join(timeout=30)
    out['stream'] = {'bytes': count, 'sha256': sent.hexdigest(), 'broken': broken}
    out['worker_stdout_truncated'] = bool(flags.get('truncated'))
    lines = bytes(stdout).strip().splitlines()
    try:
        out['worker'] = json.loads(lines[-1]) if lines else None
    except ValueError:
        out['worker'] = None
    text = bytes(stderr).decode('utf-8', 'replace')
    out['worker_stderr'] = {'bytes': len(stderr),
                            'tokens': sorted(set(re.findall(r'fixed-s5(?:diag|b)-[a-z0-9-]{1,80}', text)))[:20],
                            'exceptions': sorted(set(re.findall(r'\b[A-Z][A-Za-z]{2,40}(?:Error|Exception|Exit)\b',
                                                                text)))[:20]}
    return out


def fresh_state(root, fixture, provenance, owner_uid, root_uid=0):
    """A fixture S5-A has just packed (its work dir still holds the source): the root (root's, nothing writable for
    others), `owned` (the owner's, 0700), and exactly the literal fixture and provenance paths as single-link regular
    files of the owner on the root's filesystem. Returns their identities."""
    top = Path(root); st = top.lstat(); owned = top / 'owned'; o = owned.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == root_uid and not st.st_mode & 0o022, 'fresh-root')
    need(stat.S_ISDIR(o.st_mode) and o.st_uid == owner_uid and stat.S_IMODE(o.st_mode) == 0o700 and o.st_dev == st.st_dev,
         'fresh-owned')
    rows = []
    for path, name in ((fixture, 'generated-s5-source.tar'), (provenance, 'provenance.private.json')):
        need(path == str(owned / 'artifact' / name), 'fresh-literal-path')
        s = os.lstat(path)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == owner_uid and s.st_dev == st.st_dev, 'fresh-file')
        rows.append([s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_size, s.st_mtime_ns, s.st_ctime_ns])
    return {'files': rows}


def launch(q, popen=subprocess.Popen):
    """Root side: the S5-A proof root and fixture exactly as bound (else refused, nothing started), the worker started
    as the owner with its request and the add-on member on stdin (stream_member), then the proof root and fixture
    again. LAYOUT 'retired-proof-root': the whole root as S5-A left it (proof_root_state); 'fresh-build': a fixture S5-A
    has just packed (fresh_state), for its product-path open check. Always one JSON document."""
    try:
        need(isinstance(q.get('worker'), str) and hashlib.sha256(q['worker'].encode()).hexdigest() == WORKER_SHA,
             'worker-binding')
        owner = pwd.getpwnam(OWNER).pw_uid
        state = ((lambda: proof_root_state(PROOF_ROOT, S5A_LEAVES, S5A_COMMAND_RECORDS, S5A_ARTIFACT, COMMAND_RE, owner,
                                           ROOT_UID)) if LAYOUT == 'retired-proof-root' else
                 (lambda: fresh_state(PROOF_ROOT, FIXTURE, PROVENANCE, owner, ROOT_UID)))
        need(LAYOUT in ('retired-proof-root', 'fresh-build'), 'layout')
        before = state()
        digest, identity = sealed_digest(FIXTURE, FIXTURE_BYTES, lambda: None)
        need(digest == FIXTURE_SHA, 'fixture-sha')
        need(hashlib.sha256(read_small(PROVENANCE, 64 * 1024 * 1024)).hexdigest() == PROVENANCE_SHA, 'provenance-sha')
    except (ValueError, OSError, KeyError) as error:
        return {'status': 'refused', 'reason': str(error) if str(error).startswith('fixed-')
                else 'fixed-s5diag-' + type(error).__name__}
    out = {'status': 'failed', 'proof_root_before': before, 'fixture': {'sha256': digest, 'identity': identity}}
    try:
        sys.path.insert(0, PRODUCT_LIB)
        from woowbackup import habackup
        with habackup.open_backup(FIXTURE) as opened:
            need(len(opened.layout.members) == 2 and not any(m.problem for m in opened.layout.members), 'outer-layout')
            request = dict(q['worker_request'], layout_size=opened.layout.size)
            out.update(stream_member(opened, request, q['worker'], popen, q['timeout']))
        out['status'] = 'ran'
    except Exception as error:   # noqa: BLE001 - recorded; the proof root is still checked below
        out['failure'] = str(error) if str(error).startswith('fixed-') else 'fixed-s5diag-launcher-' + type(error).__name__
    after = state()
    digest_after, identity_after = sealed_digest(FIXTURE, FIXTURE_BYTES, lambda: None)
    out['proof_root_unchanged'] = after == before and digest_after == digest and identity_after == identity
    return out


# ---------------------------------------------------------------------- the rendered programs

def render(functions, body, values):
    head = ('import hashlib,json,os,pwd,re,signal,stat,subprocess,sys,threading,time\nfrom pathlib import Path\n'
            'from types import SimpleNamespace\nsys.dont_write_bytecode=True\n'
            + ''.join(f'{k}={v!r}\n' for k, v in sorted(values.items())))
    return head + '\n'.join(inspect.getsource(f) for f in functions) + body


VOCABULARY = {name: globals()[name] for name in (
    'MESSAGE_IDS', 'EXTRA_PATTERNS', 'SAFE_NAMES', 'SAFE_NAME_RE', 'LOG_LINE', 'PLAIN_LINE', 'PSQL_LINE', 'KEPT_LEVELS',
    'SOCKET', 'PSQL_REST', 'FIXED_LINES', 'CONTROL_FIELDS', 'LISTING_RE', 'EXPECTED_DIRS', 'EXPECTED_FILES',
    'EXPECTED_SUB', 'OTHER_TOP', 'WAL_RE', 'NAME_PATTERN', 'PROGRAMS', 'OPS', 'KNOWN_MESSAGES', 'MESSAGE_PATTERNS',
    'LOG_KEEP', 'S5B_STOP')}
WORKER_FUNCTIONS = (need, safe_name, message_id, line_fact, filter_lines, parse_controldata, parse_listing,
                    swap_log_driver, _after, call_facts, fixed_error, HashingReader, Recorder, make_owner_runner,
                    details_shape, isready_answer, role_probe, server_state, wait_until, diagnose, worker_main)


def worker_program(overrides=None, call=True):
    values = dict(VOCABULARY, OWNER=OWNER, PRODUCT_LIB=PRODUCT_LIB, JOB_TAG=JOB_TAG, DATA_DIR=DATA_DIR,
                  LISTING_SH=LISTING_SH, ROLE_PROBE_SQL=ROLE_PROBE_SQL, INSPECT_FORMAT=INSPECT_FORMAT, STATUSES=STATUSES,
                  S5A_POSTGRES_USER=S5A_POSTGRES_USER, DEVIATIONS=DEVIATIONS, LOG_TAIL=LOG_TAIL, MAX_CALLS=MAX_CALLS,
                  MEMBER_LIMIT=MEMBER_LIMIT)
    values.update(overrides or {})
    return render(WORKER_FUNCTIONS, '\nworker_main()\n' if call else '\n', values)


WORKER = worker_program()
WORKER_SHA = hashlib.sha256(WORKER.encode()).hexdigest()


def history_values():
    """The first S5-A build's fixture (s5b.HISTORY): what the diagnostic and the retirement bind, never S5-B's active one."""
    h = s5b.HISTORY
    return dict(PROOF_ROOT=h.proof_root, FIXTURE=h.fixture, PROVENANCE=h.provenance, FIXTURE_SHA=h.fixture_sha,
                FIXTURE_BYTES=h.fixture_bytes, PROVENANCE_SHA=h.provenance_sha, S5A_LEAVES=s5b.S5A_LEAVES,
                S5A_COMMAND_RECORDS=h.command_records, S5A_ARTIFACT=s5b.S5A_ARTIFACT, COMMAND_RE=s5b.COMMAND_RE,
                OWNER=OWNER, ROOT_UID=0)


def launcher_program(overrides=None, call=True):
    values = dict(history_values(), PRODUCT_LIB=PRODUCT_LIB, SLUG=s5.SLUG, OWNER_EXEC=OWNER_EXEC, PYTHON='python3',
                  WORKER_SHA=WORKER_SHA, WORKER_OUTPUT=WORKER_OUTPUT, LAYOUT='retired-proof-root')
    values.update(overrides or {})
    functions = (need, s5b.ident, s5b.read_small, s5b.sealed_digest, s5b.proof_root_state, fresh_state, _drain,
                 stream_member, launch)
    body = '\nprint(json.dumps(launch(json.load(sys.stdin))))\n' if call else '\n'
    return render(functions, body, values)


LAUNCHER = launcher_program()
# Owner: the labelled throwaway objects of every job (names this engine gives only; nothing else is listed).
OWNER_OBJECTS = r'''
import json,re,subprocess,sys
q=json.load(sys.stdin)
NAME=re.compile(r'woowbk-(j[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})-([a-z0-9][a-z0-9-]{0,30})\Z')
LABEL='io.woowtech.backup.job'
def listing(args):
 p=subprocess.run(['podman',*args,'--filter','label='+LABEL,'--format','json'],stdin=subprocess.DEVNULL,
                  capture_output=True,timeout=60)
 if p.returncode!=0 or len(p.stdout)>8*1024*1024:raise SystemExit('fixed-s5diag-owner-objects-unreadable')
 rows=json.loads(p.stdout or b'[]') or []
 if not isinstance(rows,list):raise SystemExit('fixed-s5diag-owner-objects-unreadable')
 return [row for row in rows if isinstance(row,dict)]
out={'containers':[],'volumes':[],'networks':[],'unnamed':0}
for row in listing(['ps','--all']):
 names=row.get('Names') if isinstance(row.get('Names'),list) else []
 name=names[0] if names and isinstance(names[0],str) else ''
 labels=row.get('Labels') if isinstance(row.get('Labels'),dict) else {}
 m=NAME.fullmatch(name)
 if m and labels.get(LABEL)==m.group(1):out['containers'].append([name,m.group(1),str(row.get('State'))[:20]])
 else:out['unnamed']+=1
for kind,args,key,lab in (('volumes',['volume','ls'],'Name','Labels'),('networks',['network','ls'],'name','labels')):
 for row in listing(args):
  name=row.get(key) if isinstance(row.get(key),str) else ''
  labels=row.get(lab) if isinstance(row.get(lab),dict) else {}
  m=NAME.fullmatch(name)
  if m and labels.get(LABEL)==m.group(1):out[kind].append([name,m.group(1)])
  else:out['unnamed']+=1
print(json.dumps(out))
'''
SWEEP_BODY = r'''
q=json.load(sys.stdin)
need(isinstance(q.get('job_id'),str) and re.fullmatch(JOB_PATTERN,q['job_id']) is not None
     and q['job_id'].split('-')[1].startswith(JOB_TAG),'sweep-job')
sys.path.insert(0,PRODUCT_LIB)
from woowbackup import podman,tempctr
removed,left=tempctr.sweep(make_owner_runner(podman,OWNER),lambda job:False,only_job=q['job_id'])
print(json.dumps({'removed':removed,'left':left}))
'''
SWEEP = render((need, make_owner_runner), SWEEP_BODY, {'JOB_PATTERN': JOB_PATTERN, 'JOB_TAG': JOB_TAG,
                                                        'PRODUCT_LIB': PRODUCT_LIB, 'OWNER': OWNER})
# Root, read only: the first build's proof root while it is there (S5-A's rebuild keeps it untouched): absent, or its
# layout and fixture; a root that is no longer what S5-A left says so instead of failing the caller.
RETIRED_STATE_BODY = r'''
q=json.load(sys.stdin)
out={'present':os.path.lexists(PROOF_ROOT)}
if out['present']:
 try:
  owner=pwd.getpwnam(OWNER).pw_uid
  out['state']=proof_root_state(PROOF_ROOT,S5A_LEAVES,S5A_COMMAND_RECORDS,S5A_ARTIFACT,COMMAND_RE,owner,ROOT_UID)
  out['fixture_sha256'],out['identity']=sealed_digest(FIXTURE,FIXTURE_BYTES,lambda:None)
  out['valid']=out['fixture_sha256']==FIXTURE_SHA
 except (ValueError,OSError) as error:
  out['valid']=False;out['reason']=str(error) if str(error).startswith('fixed-') else type(error).__name__
print(json.dumps(out))
'''


def retired_state_program(overrides=None):
    return render((need, s5b.ident, s5b.read_small, s5b.sealed_digest, s5b.proof_root_state), RETIRED_STATE_BODY,
                  dict(history_values(), **(overrides or {})))


RETIRED_STATE = retired_state_program()
# Root: the first build's proof root, removed entry by entry after it was proven exactly as S5-A left it (s5b.remove_root);
# only through --remove-retired-root with the diagnostic's own evidence of a finished run on this root (retire).
RETIRE_BODY = r'''
q=json.load(sys.stdin)
need(q.get('root')==PROOF_ROOT and q.get('removal')=='retired-after-the-diagnostic','retire-binding')
owner=pwd.getpwnam(OWNER).pw_uid
print(json.dumps(remove_root(PROOF_ROOT,S5A_LEAVES,S5A_COMMAND_RECORDS,S5A_ARTIFACT,COMMAND_RE,owner,FIXTURE,FIXTURE_BYTES,
                             FIXTURE_SHA,PROVENANCE,PROVENANCE_SHA,lambda:None,ROOT_UID)))
'''


def retire_program(overrides=None):
    return render((need, s5b.ident, s5b.read_small, s5b.sealed_digest, s5b.proof_root_state, s5b.remove_root), RETIRE_BODY,
                  dict(history_values(), **(overrides or {})))


RETIRE = retire_program()


# ====================================================================== host side

def require(ok, reason):
    if not ok:
        raise ValueError('fixed-s5diag-' + reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def new_job_id(now=None):
    stamp = time.strftime('%Y%m%dT%H%M%S', time.gmtime(time.time() if now is None else now))
    return f'j{stamp}Z-{JOB_TAG}{secrets.token_hex(2)}'


def acquire(handle, timeout, *, clock=time.monotonic, sleep=time.sleep, flock=fcntl.flock):
    """The dev-e mutation lock, waited for (heavy.sh only waited until it was free) at most `timeout` seconds."""
    deadline = clock() + timeout
    while True:
        try:
            flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            require(clock() < deadline, 'lock-timeout')
            sleep(LOCK_POLL)


def tool_binding(commit):
    """What this run is bound to, offline: the first S5-A build's committed result (s5b.history_result: passed, exactly
    s5b.HISTORY's fixture, SHA-256, size, provenance and proof root, else refused), the programs' digests and the S5-B
    product commit the installed engine is compared with."""
    h = s5b.HISTORY
    return {'phase': PHASE, 'source_commit': commit, 'tool_sha256': sha(Path(__file__).read_bytes()),
            'worker_sha256': WORKER_SHA, 'launcher_sha256': sha(LAUNCHER.encode()), 'sweep_sha256': sha(SWEEP.encode()),
            's5a_result_sha256': s5b.history_result(HISTORY_RESULT), 'fixture': h.fixture, 'fixture_sha256': h.fixture_sha,
            'fixture_bytes': h.fixture_bytes, 'provenance_sha256': h.provenance_sha, 'proof_root': h.proof_root,
            'compared_product_commit': s5b.PRODUCT_COMMIT}


def device_call(program, request, ev, prefix, *, root, timeout, popen=subprocess.Popen):
    """One program inside dev-e (root, or the owner through woowbk-owner) with its request on stdin; its raw stdout and
    stderr kept privately first (0600). Returns the reply, or a fixed failure; never raises for the program's own end."""
    argv = [str(LP), 'exec', '-i', DEVICE, *([] if root else list(OWNER_EXEC)), 'python3', '-I', '-c', program]
    paths = {kind: ev.path / f'{prefix}.{kind}.private' for kind in ('stdout', 'stderr')}
    handles = {kind: os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
               for kind, path in paths.items()}
    with handles['stdout'] as out, handles['stderr'] as err:
        try:
            proc = popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err)
        except OSError as error:
            return {'status': 'failed', 'reason': 'fixed-s5diag-transport-' + type(error).__name__}
        try:
            proc.communicate(json.dumps(request).encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            # Only the transport is given up: the device programs end on their own deadlines and clean up after themselves.
            proc.kill()
            proc.wait()
            return {'status': 'failed', 'reason': 'fixed-s5diag-transport-timeout'}
    raw = paths['stdout'].read_bytes()
    if proc.returncode or len(raw) > DEVICE_OUTPUT:
        return {'status': 'failed', 'reason': 'fixed-s5diag-device-program-failed', 'returncode': proc.returncode,
                'stdout_bytes': len(raw)}
    try:
        return json.loads(raw)
    except ValueError:
        return {'status': 'failed', 'reason': 'fixed-s5diag-device-reply-unreadable'}


def attempt_ids(attempt):
    call = (attempt or {}).get('failed_call') or {}
    return sorted(((call.get('stderr') or {}).get('counts') or {}).keys())


def verdict(worker):
    """What the run shows, from the worker's facts."""
    if not isinstance(worker, dict):
        return 'no-worker-result'
    ready = worker.get('wait_ready') or {}
    attempts = worker.get('attempts') or []
    if not ready:
        return 'failed-before-start:' + str((worker.get('failure') or {}).get('stage') or worker.get('stage'))
    if not ready.get('ok'):
        return 'server-did-not-start'
    if not attempts:
        return 'no-attempt:' + str((worker.get('failure') or {}).get('stage'))
    counts = (((worker.get('server') or {}).get('log') or {}).get('counts') or {})
    crashed = any(k.split(' ', 1)[0] == 'PANIC' or k.split(' ')[1:2] in (['process-ended'], ['terminating-others'],
                                                                           ['reinitializing']) for k in counts)
    if attempts[0].get('ok'):
        return 'not-reproduced-query-succeeded'
    if any(a.get('ok') for a in attempts):
        return 'server-crashed-then-recovered' if crashed else 'transient-not-ready-then-ok'
    probe = worker.get('role_probe') or {}
    if (all(any('FATAL role-missing name=postgres' in i for i in attempt_ids(a)) for a in attempts)
            and probe.get('postgres_role') is False):
        return 'missing-postgres-role'
    if crashed:
        return 'server-crashed-crash-recovery'
    if any('database-missing' in i for a in attempts for i in attempt_ids(a)):
        return 'missing-database'
    return 'other-see-evidence'


def summary(record):
    """The fixed line printed at the end (everything else is in the private evidence)."""
    launcher = record.get('launcher') or {}
    worker = launcher.get('worker') if isinstance(launcher.get('worker'), dict) else {}
    ready = worker.get('wait_ready') or {}
    before = worker.get('controldata_before') or {}
    listing = worker.get('listing_before') or {}
    probe = worker.get('role_probe') or {}
    server = worker.get('server') or {}
    counts = ((server.get('log') or {}).get('counts') or {})
    isready = [c.get('rc') for c in worker.get('calls') or [] if c.get('program') == 'pg_isready' and c.get('quiet')]
    attempts = worker.get('attempts') or []
    return {
        'status': record.get('status'), 'phase': PHASE, 'verdict': record.get('verdict'),
        'reason': record.get('reason'), 'source_commit': record.get('source_commit'), 'job_id': record.get('job_id'),
        'proof_root_unchanged': launcher.get('proof_root_unchanged'), 'device_unchanged': record.get('device_unchanged'),
        'engine_relevant_differs_from_s5b_product': record.get('engine_relevant_differs'),
        'image': (worker.get('image') or {}).get('ref'), 'member_bytes': (worker.get('member') or {}).get('bytes'),
        'stream_intact': ((worker.get('member') or {}).get('sha256') == (launcher.get('stream') or {}).get('sha256')
                          if worker.get('member') else None),
        'controldata_before': {k: before.get(k) for k in ('state', 'checkpoint', 'redo', 'redo_wal_file', 'timeline')},
        'wal_files': [w.get('name') for w in listing.get('wal') or []],
        'missing_dirs': listing.get('missing_dirs'), 'root_entry_in_member': (worker.get('member') or {}).get(
            'root_entry_in_member'),
        'wait_ready': {k: ready.get(k) for k in ('ok', 'seconds')}, 'pg_isready_quiet_rcs': isready[:40],
        'pg_isready_answer': (worker.get('isready_after_attempts') or {}).get('answer'),
        'first_attempt_equals_s5b_stop': bool(attempts and (attempts[0].get('error') or {}).get('equals_s5b_stop')),
        'attempts': [{'at': a.get('at'), 'ok': a.get('ok'), 'reason': (a.get('error') or {}).get('reason'),
                      'stderr': attempt_ids(a)} for a in attempts],
        'role_probe': {k: probe.get(k) for k in ('connected_as', 'bootstrap_superuser', 'postgres_role',
                                                 'postgres_database')},
        'server': {'state': server.get('state'), 'log_counts': dict(sorted(counts.items())[:40])},
        'failure': (worker.get('failure') or {}).get('stage'),
        'cleanup': {'order': worker.get('order'), 'left': worker.get('left'), 'swept': record.get('sweep')},
        'deviations': worker.get('deviations') or [ident for ident, _why in DEVIATIONS],
        'private_evidence': record.get('private_evidence')}


def snapshot(device=wake.device, inventory=collect):
    """What must stay as it was: engine, the store's own folders, units, Quadlets, images, catalog, labelled objects."""
    found = inventory()
    return {'engine': device(s5.ENGINE_PROGRAM, root=True), 'store': device(s5.TARGET_STATE, root=True),
            'units': found['owner']['units'], 'quadlets': found['owner']['quadlets'], 'images': found['owner']['images'],
            'installed_hashes': found['root']['installed_hashes'], 'catalog_sha256': found['root']['catalog_sha256'],
            'objects': device(OWNER_OBJECTS, {}), 'inventory': found}


def unchanged(before, after, job_id):
    keys = ('engine', 'store', 'units', 'quadlets', 'images', 'installed_hashes', 'catalog_sha256')
    differs = [k for k in keys if before.get(k) != after.get(k)]
    ours = [row[0] for kind in ('containers', 'volumes', 'networks') for row in (after.get('objects') or {}).get(kind, [])
            if row[1] == job_id]
    return not differs and not ours, {'differs': differs, 'left_of_this_job': ours}


def run_locked(binding, *, device=wake.device, inventory=collect, call=device_call, evidence_root=EVIDENCE,
               markers=MARKERS, now=time.time):
    """Caller holds the dev-e mutex. Admission (cold, quiescent, nothing of a job running), the one launcher run, the
    owned sweep of this job id, the after-state; evidence first, one fixed line last."""
    job_id = new_job_id(now())
    ev = upload.Evidence(Path(evidence_root) / (time.strftime('%Y%m%dT%H%M%S') + '-' + job_id.rsplit('-', 1)[1]))
    record = {'status': 'failed', 'source_commit': binding['source_commit'], 'job_id': job_id,
              'private_evidence': str(ev.path)}
    ev.save('binding.json', dict(binding, job_id=job_id))
    try:
        before = snapshot(device, inventory)
        case.admission(before['inventory'])     # isolation, memory, disk, every unit inactive, the five original images
        require(device(case.QUIESCENT, root=True).get('active_jobs') == 0, 'active-product-job')
        running = [row[0] for row in before['objects']['containers'] if row[2] not in ('exited', 'created', 'stopped')]
        require(not running, 'throwaway-container-running')
        ev.save('before.private.json', before)
    except (ValueError, RuntimeError, KeyError, OSError) as error:
        record.update(status='refused', reason=str(error) if str(error).startswith('fixed-') else
                      'fixed-s5diag-admission-' + type(error).__name__)
        ev.save('fixed-result.json', summary(record))
        print(json.dumps(summary(record)))
        return 2
    markers = Path(markers)
    markers.mkdir(parents=True, mode=0o700, exist_ok=True)
    marker = markers / (sha(json.dumps(binding, sort_keys=True).encode()) + '.json')
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)   # one run per binding
    except FileExistsError:
        record.update(status='refused', reason='fixed-s5diag-already-run-once')
        ev.save('fixed-result.json', summary(record))
        print(json.dumps(summary(record)))
        return 2
    with os.fdopen(fd, 'w') as handle:
        json.dump({'job_id': job_id, 'private_evidence': str(ev.path)}, handle)
    request = {'worker': WORKER, 'timeout': WORKER_BUDGET + LAUNCH_GRACE,
               'worker_request': {'job_id': job_id, 'deadline': now() + WORKER_BUDGET, 'schedule': list(SCHEDULE)}}
    launcher = call(LAUNCHER, request, ev, 'launcher', root=True, timeout=WORKER_BUDGET + 2 * LAUNCH_GRACE)
    ev.save('launcher-result.private.json', launcher)
    record['launcher'] = launcher
    sweep = call(SWEEP, {'job_id': job_id}, ev, 'sweep', root=False, timeout=600)
    record['sweep'] = sweep
    try:
        after = snapshot(device, inventory)
        ev.save('after.private.json', after)
        record['device_unchanged'], detail = unchanged(before, after, job_id)
        record['device_detail'] = detail
        product = s5.engine_manifest(REPO, s5b.PRODUCT_COMMIT)
        record['engine_relevant_differs'] = [n for n in RELEVANT if before['engine'].get(n) != product.get(n)]
    except (ValueError, RuntimeError, KeyError, OSError) as error:
        record['device_unchanged'] = None
        record['after_error'] = type(error).__name__
    if launcher.get('status') == 'refused':
        record.update(status='refused', reason=launcher.get('reason'))
    elif launcher.get('status') == 'ran' and isinstance(launcher.get('worker'), dict):
        record['status'] = 'diagnosed'
        record['verdict'] = verdict(launcher['worker'])
    else:
        record['reason'] = launcher.get('reason') or 'fixed-s5diag-launcher-' + str(launcher.get('status'))
    line = summary(record)
    ev.save('record.private.json', {k: v for k, v in record.items() if k != 'launcher'})
    ev.save('fixed-result.json', line)
    print(json.dumps(line, ensure_ascii=False))
    return 0 if record['status'] == 'diagnosed' and record.get('device_unchanged') else 1


# ====================================================================== S5-A's gate: the product's own check opens a fixture

def open_check_binding():
    """What S5-A's lease binds of the open check: this tool's bytes and its device programs."""
    return {'tool_sha256': sha(Path(__file__).read_bytes()), 'worker_sha256': WORKER_SHA, 'sweep_sha256': sha(SWEEP.encode())}


def judge_open(launcher, sweep):
    """{s5.OPEN_CHECKS name: bool} of one open check (all true: the product's own check path opened the fixture)."""
    w = launcher.get('worker') if launcher.get('status') == 'ran' and isinstance(launcher.get('worker'), dict) else {}
    member, before = w.get('member') or {}, w.get('controldata_before') or {}
    first = (w.get('attempts') or [{}])[0]
    details, probe, stream = first.get('details') or {}, w.get('role_probe') or {}, launcher.get('stream') or {}
    counts = details.get('counts') if isinstance(details.get('counts'), dict) else {}
    checks = {
        'proof_unchanged': launcher.get('proof_root_unchanged') is True,
        'stream_intact': bool(member.get('sha256')) and member.get('sha256') == stream.get('sha256')
                         and stream.get('broken') is None,
        'member_root_entry': member.get('root_entry_in_member') is True,
        'config_dbuser': (member.get('dbuser'), member.get('dbname')) == (s5.NC_ROLE, s5.NC_DB),
        'clean_shutdown': before.get('state') == 'shut down',
        'started': (w.get('wait_ready') or {}).get('ok') is True,
        'product_call_answered': first.get('ok') is True and first.get('at') == 0,
        'nextcloud_database': all(details.get(k) is True for k in ('database_found', 'nextcloud', 'shape_read')),
        'users': type(counts.get('users')) is int and counts['users'] >= 1,
        'encryption': details.get('encryption_enabled') is True,
        'superuser': (probe.get('connected_as'), probe.get('bootstrap_superuser'), probe.get('postgres_role'))
                     == ('postgres', s5.SUPERUSER, True),
        'cleanup': w.get('left') == [] and w.get('order') == ['server-state', 'remove-container', 'remove-volume', 'cleanup']
                   and isinstance(sweep, dict) and sweep.get('left') == [],
    }
    require(tuple(checks) == s5.OPEN_CHECKS, 'open-checks-contract')
    return checks


def open_check(fixture, ev, *, deadline, call=device_call, now=time.time):
    """S5-A's acceptance gate (s5.run_locked, the dev-e mutex held): the fixture S5-A has just packed, opened through the
    product's own check path exactly as this diagnostic does it -- root reads it with the installed habackup (layout
    'fresh-build': the literal fixture and provenance, their SHA-256), the owner's worker runs TempObjects, PgSink,
    start_ha_cluster and ha_database with PINNED_OPTIONS once (schedule [0]) -- then the product's sweep of that job id
    only. Returns {status: passed|failed, job_id, checks, reason, facts, sweep}."""
    archive = fixture.get('archive') if isinstance(fixture, dict) else None
    root = archive[:-len(s5b.ARTIFACT_TAIL)] if isinstance(archive, str) and archive.endswith(s5b.ARTIFACT_TAIL) else ''
    require(re.fullmatch(s5.ROOT_RE, root) is not None and root != s5b.HISTORY.proof_root
            and re.fullmatch('[0-9a-f]{64}', str(fixture.get('sha256'))) is not None
            and re.fullmatch('[0-9a-f]{64}', str(fixture.get('provenance_sha256'))) is not None
            and type(fixture.get('bytes')) is int and fixture['bytes'] > 0, 'open-check-fixture')
    budget = min(OPEN_BUDGET, deadline - now() - 120)
    require(budget >= 300, 'open-check-no-time-left')
    program = launcher_program({'PROOF_ROOT': root, 'FIXTURE': archive,
                                'PROVENANCE': root + '/owned/artifact/provenance.private.json',
                                'FIXTURE_SHA': fixture['sha256'], 'FIXTURE_BYTES': fixture['bytes'],
                                'PROVENANCE_SHA': fixture['provenance_sha256'], 'LAYOUT': 'fresh-build'})
    job_id = new_job_id(now())
    request = {'worker': WORKER, 'timeout': budget + LAUNCH_GRACE,
               'worker_request': {'job_id': job_id, 'deadline': now() + budget, 'schedule': [0]}}
    launcher = call(program, request, ev, 'open-check', root=True, timeout=budget + 2 * LAUNCH_GRACE)
    ev.save('open-check-launcher.private.json', launcher)
    sweep = call(SWEEP, {'job_id': job_id}, ev, 'open-check-sweep', root=False, timeout=600)
    checks = judge_open(launcher, sweep)
    failed = [name for name, ok in checks.items() if not ok]
    w = launcher.get('worker') if isinstance(launcher.get('worker'), dict) else {}
    return {'status': 'failed' if failed else 'passed', 'job_id': job_id, 'checks': checks,
            'reason': ('fixed-s5diag-open-check-' + failed[0]) if failed else None,
            'facts': {'launcher': launcher.get('status'), 'launcher_reason': launcher.get('reason'),
                      'image': (w.get('image') or {}).get('ref'), 'wait_ready': w.get('wait_ready'),
                      'controldata_before': {k: (w.get('controldata_before') or {}).get(k)
                                             for k in ('state', 'checkpoint', 'redo_wal_file', 'timeline')},
                      'first_attempt': {k: ((w.get('attempts') or [{}])[0]).get(k) for k in ('ok', 'at', 'details')},
                      'role_probe': {k: (w.get('role_probe') or {}).get(k)
                                     for k in ('connected_as', 'bootstrap_superuser', 'postgres_role')},
                      'failure': w.get('failure')},
            'sweep': sweep}


# ====================================================================== retiring the first build's proof root

def diagnostic_evidence(path, *, evidence_root=EVIDENCE):
    """The diagnostic's own finished run on the first build's proof root: one folder of its evidence area holding its
    fixed result (diagnosed, the proof root unchanged) and its binding (exactly s5b.HISTORY's fixture and root)."""
    folder = Path(path)
    require(folder.is_dir() and not folder.is_symlink() and folder.parent.resolve() == Path(evidence_root).resolve(),
            'retire-diagnostic-evidence')
    docs = {}
    for name in ('fixed-result.json', 'binding.json'):
        p = folder / name
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= 1024 * 1024, 'retire-diagnostic-evidence')
        docs[name] = json.loads(p.read_text())
    line, binding, h = docs['fixed-result.json'], docs['binding.json'], s5b.HISTORY
    require(line.get('phase') == PHASE and line.get('status') == 'diagnosed' and line.get('proof_root_unchanged') is True
            and binding.get('phase') == PHASE and binding.get('fixture_sha256') == h.fixture_sha
            and binding.get('proof_root') == h.proof_root and binding.get('fixture') == h.fixture,
            'retire-diagnostic-evidence')
    return {'evidence': str(folder), 'job_id': line.get('job_id'), 'verdict': line.get('verdict')}


def retire(diagnostic, commit, *, device=wake.device, inventory=collect, evidence_root=LAB / 'evidence' / RETIRE_AREA):
    """Caller holds the dev-e mutex: the first build's proof root -- a literal path, s5b.HISTORY -- removed entry by entry
    (RETIRE: s5b.remove_root after proof_root_state and the fixture's and provenance's SHA-256), only when dev-e is cold
    and quiet and the root is still exactly as S5-A left it. Nothing else is touched."""
    ev = upload.Evidence(Path(evidence_root) / (time.strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3)))
    h = s5b.HISTORY
    record = {'status': 'failed', 'phase': 's5-retired-root-removal', 'source_commit': commit, 'root': h.proof_root,
              'diagnostic': diagnostic, 'private_evidence': str(ev.path)}
    try:
        found = inventory()
        case.admission(found)
        require(device(case.QUIESCENT, root=True).get('active_jobs') == 0, 'active-product-job')
        state = device(RETIRED_STATE, root=True, timeout=600)
        ev.save('before.private.json', {'inventory': found, 'retired': state})
        require(state.get('present') is True and state.get('valid') is True, 'retired-root-not-as-s5a-left-it')
        removal = device(RETIRE, {'root': h.proof_root, 'removal': 'retired-after-the-diagnostic'}, root=True, timeout=900)
        after = device(RETIRED_STATE, root=True, timeout=600)
        record.update(removal=removal, present_after=after.get('present'))
        if removal.get('status') == 'removed' and after.get('present') is False:
            record['status'] = 'removed'
    except (ValueError, RuntimeError, KeyError, OSError) as error:
        record['reason'] = str(error) if str(error).startswith('fixed-') else 'fixed-s5diag-retire-' + type(error).__name__
    ev.save('fixed-result.json', record)
    print(json.dumps(record))
    return 0 if record['status'] == 'removed' else 1


def contract():
    h = s5b.HISTORY
    return {'phase': PHASE, 'code_only_until_run': True, 'device': DEVICE, 'lock': LOCK, 'lock_timeout_seconds': LOCK_TIMEOUT,
            'fixture': h.fixture, 'fixture_sha256': h.fixture_sha, 'proof_root': h.proof_root, 'owner': OWNER,
            'retire': '--remove-retired-root --diagnostic-evidence <this tool\'s evidence folder of a diagnosed run>',
            'product_library': PRODUCT_LIB, 'job_ids': f'j<utc>Z-{JOB_TAG}<4 hex>', 'attempt_schedule_seconds': SCHEDULE,
            'worker_budget_seconds': WORKER_BUDGET, 'deviations_from_the_product_check': dict(DEVIATIONS),
            'worker_sha256': WORKER_SHA, 'launcher_sha256': sha(LAUNCHER.encode()), 'evidence': str(EVIDENCE),
            'device_changes': 'only throwaway objects of its own job id (TempObjects), removed; then swept by job id',
            'pulls': 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--remove-retired-root', action='store_true',
                        help='after a diagnosed run: remove the first build\'s proof root (s5b.HISTORY), nothing else')
    parser.add_argument('--diagnostic-evidence', type=Path, help='this tool\'s evidence folder of that diagnosed run')
    parser.add_argument('--lock-timeout', type=int, default=LOCK_TIMEOUT)
    args = parser.parse_args(argv)
    if not args.run and not args.remove_retired_root:
        print(json.dumps(contract(), indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    require(not (args.run and args.remove_retired_root), 'one-mode-at-a-time')
    require(os.environ.get('HEAVY_FREE') == LOCK, 'heavy-seat-required')
    commit, clean = s5.checkout(REPO)
    require(clean, 'clean-checkout')
    if args.remove_retired_root:
        require(args.diagnostic_evidence is not None, 'diagnostic-evidence-required')
        s5b.history_result(HISTORY_RESULT)                        # the committed history is the bound one
        diagnostic = diagnostic_evidence(args.diagnostic_evidence)  # refused before the lock when it is not a diagnosed run
        with open(LOCK, 'a') as lock:
            acquire(lock, args.lock_timeout)
            return retire(diagnostic, commit)
    binding = tool_binding(commit)
    with open(LOCK, 'a') as lock:
        acquire(lock, args.lock_timeout)
        return run_locked(binding)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print('fixed-s5diag-preflight-refused-no-mutation: '
              + (str(error) if str(error).startswith('fixed-') else type(error).__name__), file=sys.stderr)
        sys.exit(2)
