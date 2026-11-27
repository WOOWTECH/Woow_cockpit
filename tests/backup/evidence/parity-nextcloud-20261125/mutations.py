#!/usr/bin/env python3
"""Mutation check of lane NEXTCLOUD (HAOS parity, 2026-11-25, NC-OWNER-1905): each rule or protection listed in MUTATIONS is
removed, one place at a time, in a throwaway copy of the repository, and the unit tests of the lane must FAIL for each (and pass on
the unmodified copy). CONTROLS change a comment only and must go unnoticed. Nothing here touches Podman, a device or a secret (the
tests use doubles only).

  python3 -I mutations.py --repo <worktree> [--json OUT] [--only ID,ID] [--jobs N] [--check-text]
Run it through team/heavy.sh (it starts several copies of the test module).
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MOD = 'woowbackup/ha_nextcloud.py'
TESTS = ('tests.backup.test_ha_nextcloud',)

# (id, what is protected, exact text (once in ha_nextcloud.py), replacement)
MUTATIONS = [
    # --- config.php (NC-12)
    ('M01', 'a double-quoted text with a variable is refused', '''|(?P<dstring>"(?:[^"\\\\$]|\\\\.)*")''',
     '''|(?P<dstring>"(?:[^"\\\\]|\\\\.)*")'''),
    ('M02', 'an ambiguous interpolation is refused', "    if '{\\\\$' in body:\n        raise ValueError('ambiguous interpolation')\n",
     "    if False:\n        raise ValueError('ambiguous interpolation')\n"),
    ('M03', 'an unknown escape is refused', "            if body[i + 1] not in _DQ_ESCAPES:\n                raise ValueError('unsupported escape')\n",
     "            if body[i + 1] not in _DQ_ESCAPES:\n                _DQ_ESCAPES[body[i + 1]] = body[i + 1]\n"),
    ('M04', 'only texts are joined', "            if not isinstance(first, str) or not isinstance(other, str):\n                raise ValueError('only texts are joined')\n",
     "            if False:\n                raise ValueError('only texts are joined')\n"),
    ('M05', 'an unknown constant is refused', "            raise ValueError('unsupported word')", "            return None"),
    # --- config_issues (NC-13, NC-14, NC-20)
    ('M06', 'a Nextcloud that was never set up stops', "    if ha.get('installed') is not True:\n        sink.stop('nextcloud.not-installed',",
     "    if False:\n        sink.stop('nextcloud.not-installed',"),
    ('M07', 'maintenance mode with another version stops', "        else:\n            sink.stop('nextcloud.maintenance-upgrading',",
     "        elif False:\n            sink.stop('nextcloud.maintenance-upgrading',"),
    ('M08', 'maintenance mode is a notice only when the versions are equal', "        if consistent:\n            sink.notice('nextcloud.maintenance-mode',",
     "        if True:\n            sink.notice('nextcloud.maintenance-mode',"),
    ('M09', 'another version of HA stops', "        sink.stop('nextcloud.version-different',", "        sink.notice('nextcloud.version-different',"),
    ('M10', 'an unreadable version asks the add-on version', "        sink.extend(VERSIONS.issues(addon_version, hacommon.semver(_version3(live_version))))\n",
     "        pass\n"),
    ('M11', 'an unreadable version is told', "        sink.notice('nextcloud.version-unreadable',", "        sink.auto('nextcloud.version-unreadable',"),
    # --- the users' files (NC-22, NC-23, NC-25, NC-26, NC-27, NC-28, NC-29)
    ('M12', 'no share folder is a line to confirm', "        sink.confirm('nextcloud.no-share', MSG_NO_SHARE,", "        sink.notice('nextcloud.no-share', MSG_NO_SHARE,"),
    ('M13', 'a data folder without its marker is not moved', "    return isinstance(data, DataDir) and data.present and data.ncdata\n",
     "    return isinstance(data, DataDir) and data.present\n"),
    ('M14', 'a place no backup holds is a line to confirm', "        sink.confirm('nextcloud.datadir-elsewhere', MSG_ELSEWHERE,",
     "        sink.notice('nextcloud.datadir-elsewhere', MSG_ELSEWHERE,"),
    ('M15', 'a path with spaces is a path', "DATADIR_SEG_RE = re.compile(r'[^\\x00-\\x1f\\x7f/]{1,255}\\Z')",
     "DATADIR_SEG_RE = re.compile(r'[A-Za-z0-9._@+-]{1,255}\\Z')"),
    ('M16', 'symlinks are a line to confirm', "            sink.confirm('nextcloud.symlinks-skipped',", "            sink.notice('nextcloud.symlinks-skipped',"),
    ('M17', '.htaccess files are a line to confirm', "            sink.confirm('nextcloud.htaccess-skipped',", "            sink.notice('nextcloud.htaccess-skipped',"),
    ('M18', 'a .htaccess below the top is left out', "        if left == 'htaccess':\n            if len(parts) > 1 or entry.kind != 'file':",
     "        if left == 'htaccess' and parts == ['.htaccess']:\n            if len(parts) > 1 or entry.kind != 'file':"),
    ('M19', 'the names of the left-out .htaccess files make the key', "                data.htaccess_names.add(rel)\n", "                pass\n"),
    ('M20', 'server-side encryption is a line to confirm', "            sink.confirm('nextcloud.server-side-encryption', MSG_ENCRYPTION, reasons)",
     "            sink.notice('nextcloud.server-side-encryption', MSG_ENCRYPTION, reasons)"),
    ('M21', 'encryption of the files is seen', "        reasons = ['files_encryption'] if isinstance(data, DataDir) and data.encryption else []\n",
     "        reasons = []\n"),
    ('M22', 'encryption of the database is seen', "                reasons.append('encryption_enabled')\n", "                pass\n"),
    ('M23', 'a hard link to a file that is not moved is copied', "                entry.copy_later()\n                data.hardlinks_copied += 1\n                continue\n",
     "                data.hardlinks_copied += 1\n                continue\n"),
    ('M24', 'a hard link to an .htaccess that is left out is copied', "    return 'htaccess' if HTACCESS in parts else None\n",
     "    return None\n"),
    ('M25', 'what the reader left out of the data directory is one line', "            sink.skipped(data.report, *[kind for kind in habackup.SKIP_KINDS if kind != 'symlink'])\n",
     "            pass\n"),
    ('M26', 'what the reader left out of the add-on is one line', "    if src.report is not None:\n        sink.skipped(src.report)\n",
     "    if False:\n        sink.skipped(src.report)\n"),
    # --- the conversion's folders
    ('M27', 'the marker is written when the files do not move', "        if not userfiles_moved(data):\n            data_out.add('.ncdata',",
     "        if False:\n            data_out.add('.ncdata',"),
    ('M28', 'a folder without the marker is started again', "        if isinstance(data, DataDir) and data.present and not data.ncdata:\n            data_out.close()",
     "        if False:\n            data_out.close()"),
    ('M29', 'the data directory carries Nextcloud\'s own .htaccess', "                fileobj=io.BytesIO(DATA_HTACCESS))\n        return out\n",
     "                fileobj=io.BytesIO(b''))\n        return out\n"),
    ('M30', 'files that did not move are reminded', "    if data.get('userfiles') is False:\n", "    if False:\n"),
    ('M31', 'a stop after the add-on member stops the conversion', "    member_issues(sink, src, target)      # a stop stops this app, a line to confirm needs its key (haissues.Sink)\n    raise_stops(sink)\n",
     "    member_issues(sink, src, target)      # a stop stops this app, a line to confirm needs its key (haissues.Sink)\n"),
    ('M32', 'a stop after the data directory stops the conversion', "    datadir_issues(sink, src.config, data, ha_datadir_source(src))\n    raise_stops(sink)\n",
     "    datadir_issues(sink, src.config, data, ha_datadir_source(src))\n"),
    ('M33', 'a stop of the database stops the conversion', "    database_issues(sink, src, data, details, target)\n    raise_stops(sink)\n",
     "    database_issues(sink, src, data, details, target)\n"),
    # --- the database (NC-38, NC-39, NC-40, NC-45)
    ('M34', 'only functions and triggers may be left out', "SKIPPABLE = ('functions', 'triggers')", "SKIPPABLE = ('functions', 'triggers', 'types', 'relations', 'rules')"),
    ('M35', 'what is left out is a line to confirm', "                sink.confirm('nextcloud.db-objects-skipped',", "                sink.notice('nextcloud.db-objects-skipped',"),
    ('M36', 'what cannot be left out stops', "            sink.stop('nextcloud.db-objects', MSG_SHAPE.format(kinds=hacommon.names(split[1])))",
     "            sink.notice('nextcloud.db-objects', MSG_SHAPE.format(kinds=hacommon.names(split[1])))"),
    ('M37', 'an unreadable shape stops', "        elif split is None:\n            sink.stop('nextcloud.shape-unreadable'", "        elif split is None:\n            sink.notice('nextcloud.shape-unreadable'"),
    ('M38', 'HA\'s tables are not read when something cannot be left out', "    if split is None or split[1]:      # unreadable, or something that cannot be left out: nothing more is read\n",
     "    if split is None:      # unreadable, or something that cannot be left out: nothing more is read\n"),
    ('M39', 'the kinds of the dump that were not confirmed stop', "    odd = [kind for kind in toc_kinds(text) if kind not in TOC_ALLOWED and kind not in skip]\n",
     "    odd = [kind for kind in toc_kinds(text) if kind not in TOC_ALLOWED and kind not in SKIPPED_TOC]\n"),
    ('M40', 'the confirmed kinds are left out of the list', "    left = ha_odoo.filter_toc(skip_toc(text, skip))\n", "    left = ha_odoo.filter_toc(text)\n"),
    ('M41', 'the comments on a left-out program are left out too', "    comment = re.compile(rf'\\s*\\d+;\\s+\\d+\\s+\\d+\\s+COMMENT\\s+\\S+\\s+(?:{names})\\s')\n",
     "    comment = re.compile(r'(?!)')\n"),
    ('M42', 'the kinds are only left out when confirmed', "skip=SKIPPED_TOC if left_out and left_out[0] else ())", "skip=SKIPPED_TOC)"),
    ('M43', 'the new cluster is checked for foreign objects again', "    if shape:\n        raise BackupError('incompatible', MSG_SHAPE.format(kinds=hacommon.names(shape)))\n    removed =",
     "    if False:\n        raise BackupError('incompatible', MSG_SHAPE.format(kinds=hacommon.names(shape)))\n    removed ="),
    ('M44', 'an extension this device has is enabled', "            enable = [e for e in extra if e in target.db.get('available', ())]\n",
     "            enable = list(extra)\n"),
    ('M45', 'an extension this device lacks stops', "            if len(enable) < len(extra):\n", "            if False:\n"),
    ('M46', 'the enabled extensions are created', "    extras = [e for e in details.get('extensions') or [] if e not in EXTENSIONS_OK and e not in extensions\n              and e in db.get('available', ()) and EXT_RE.fullmatch(e)]\n",
     "    extras = []\n"),
    ('M47', 'other schemas are a line to confirm', "                sink.confirm('nextcloud.schemas-skipped', MSG_SCHEMAS, details['schemas'])",
     "                sink.notice('nextcloud.schemas-skipped', MSG_SCHEMAS, details['schemas'])"),
    ('M48', 'only the schema public is dumped when others exist', "(['-n', 'public'] if details.get('schemas') else [])", "[]"),
    # --- the live target (NC-04, NC-05, NC-07, NC-08, NC-09, NC-49)
    ('M49', 'a stopped Nextcloud is started', "        hatarget.ensure_running(work, app, self.live.app_container)\n", "        pass\n"),
    ('M50', 'a stopped database is started', "        hatarget.ensure_running(work, app, self.live.db_container, ready='postgres')\n", "        pass\n"),
    ('M51', 'a stopped Redis is started', "    hatarget.ensure_running(work, app, live.redis_container)      # NC-04", "    pass      # NC-04"),
    ('M52', 'a config.php that is not data is read by PHP', "        config = php_config(work, app, live)\n        if config is None:", "        config = None\n        if config is None:"),
    ('M53', 'the live config.php PHP gives is parsed strictly', "        out = _exec(work, app, live.app_container, ['php', '-d', 'display_errors=0', '-r', PHP_DUMP], '設定檔 config.php')\n        return parse_config(out)\n",
     "        out = _exec(work, app, live.app_container, ['php', '-d', 'display_errors=0', '-r', PHP_DUMP], '設定檔 config.php')\n        return {'dbuser': 'oc_admin'}\n"),
    ('M54', 'a missing role is made', "    if not (isinstance(password, str) and ha_odoo.VERIFIER_RE.fullmatch(password)):\n        plain =",
     "    if False:\n        plain ="),
    ('M55', 'a password SCRAM cannot take stops', "        if not (isinstance(plain, str) and PLAIN_PASSWORD_RE.fullmatch(plain)) or role.startswith('pg_'):",
     "        if not isinstance(plain, str) or not plain:"),
    ('M56', 'a role name of the system is not made', " or role.startswith('pg_'):", ":"),
    ('M57', 'the verifier uses the salted password keys', "    server = hmac.new(salted, b'Server Key', hashlib.sha256).digest()\n",
     "    server = hmac.new(salted, b'Client Key', hashlib.sha256).digest()\n"),
    ('M58', 'a superuser role is loaded by a plain one', "    plain = db['role'].get('super') is not True\n", "    plain = True\n"),
    ('M59', 'the data is handed over', "    if not plain:\n        admin.script(hand_over_sql(role), live.db_name)\n", "    if False:\n        admin.script(hand_over_sql(role), live.db_name)\n"),
    ('M60', 'the loader is a plain role', "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\\n'\n            + (f'GRANT CONNECT", "SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\\n'\n            + (f'GRANT CONNECT"),
    ('M61', 'the role must have the rights of the live one', "    if any(attrs.get(key) != db['role'].get(key) for key in ROLE_ATTRS):\n", "    if False:\n"),
    ('M62', 'the bootstrap superuser gets the live verifier', "    if own:      # the cluster's own superuser", "    if False:      # the cluster's own superuser"),
    ('M63', 'Office settings that cannot be read are told', "    if not any(issue.id == 'nextcloud.office-settings-unread' for issue in sink.found):\n        sink.notice(",
     "    if True:\n        pass\n    if False:\n        sink.notice("),
    ('M64', 'HA\'s Office settings are not deleted when this device\'s cannot be read', "    if live_rows is not None:      # None:", "    if True:      # None:"),
    ('M65', 'Office settings that were not read are not compared', "    if db.get('appconfig') is not None and _rows(doc.get('appconfig')) != _rows(db.get('appconfig')):",
     "    if _rows(doc.get('appconfig')) != _rows(db.get('appconfig')):"),
    ('M66', 'a setting the new cluster refuses is taken out', "            for name in bad:\n                cluster.statement(f'ALTER SYSTEM RESET {name};')\n",
     "            for name in bad:\n                pass\n"),
    ('M67', 'when what is left is refused too, none is kept', "                cluster.statement('ALTER SYSTEM RESET ALL;')\n", "                pass\n"),
    ('M68', 'a refused setting is told', "            sink.notice('nextcloud.settings-not-carried', '沿用這台 PostgreSQL 設定失敗，新的資料庫對它們改用預設值；資料沒有影響。',\n                        bad)\n",
     "            pass\n"),
    # --- pg-stdin follow-ups, NC-32
    ('M69', 'the listing is checked against its header', "    text = toc.decode('utf-8', 'surrogateescape')\n    check_listing(text)\n", "    text = toc.decode('utf-8', 'surrogateescape')\n"),
    ('M70', 'a listing without a header is refused', "    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:\n",
     "    if held_back is not None and not lowest <= held_back <= lowest + LISTING_SLACK:\n"),
    ('M75', 'a listing with more lines than its header says is refused', "    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:\n",
     "    if held_back is None or not held_back <= lowest + LISTING_SLACK:\n"),
    ('M76', 'a listing that is short by more than the slack is refused', "    if held_back is None or not lowest <= held_back <= lowest + LISTING_SLACK:\n",
     "    if held_back is None or not lowest <= held_back:\n"),
    ('M77', 'the slack of the listing stays small', "LISTING_SLACK = 9 ", "LISTING_SLACK = 90 "),
    ('M78', 'the cluster\'s own superuser as Nextcloud role: the plain loader is given no right to connect (nothing took it away)',
     "        pg.script(loader_sql(live.db_name, connect=not own))\n", "        pg.script(loader_sql(live.db_name, connect=True))\n"),
    ('M79', 'another superuser role: the plain loader is given the right to connect (role_sql took it from every role)',
     "        pg.script(loader_sql(live.db_name, connect=not own))\n", "        pg.script(loader_sql(live.db_name, connect=False))\n"),
    # --- the programs of a known app (NC-38, NC-45)
    ('M80', 'a known app alone is no line to confirm', "                if apps and not others:       # only what a known app makes again by itself",
     "                if False:       # only what a known app makes again by itself"),
    ('M81', 'a known app and another program are a line to confirm', "                if apps and not others:       # only",
     "                if apps:       # only"),
    ('M82', 'a list of names that is cut is not known to be whole', "    apps, others = set(), count is None or count != len(names)\n",
     "    apps, others = set(), False\n"),
    ('M83', 'only the exact names are the known ones', "if name.split(' ', 1)[-1] in objects), None)",
     "if name.split(' ', 1)[-1].split('.')[-1] in {o.split('.')[-1] for o in objects}), None)"),
    ('M84', 'both names of Memories are known', "frozenset({'public.memories_fcu_fun', 'oc_filecache.memories_fcu_trg'})",
     "frozenset({'public.memories_fcu_fun'})"),
    ('M85', 'the reminder with the repair command comes after the import', "    if apps:\n        reminders.append(MSG_REPAIR.format(",
     "    if False:\n        reminders.append(MSG_REPAIR.format("),
    ('M86', 'the reminder about the other programs comes after the import', "    if data.get('left_out_others'):\n        reminders.append(MSG_LEFT_OUT)",
     "    if False:\n        reminders.append(MSG_LEFT_OUT)"),
    ('M87', 'the conversion hands the known apps to the reminders', "'left_out_apps': left_apps if left_any else [],",
     "'left_out_apps': [],"),
    ('M88', 'a known app is told as a notice', "sink.notice('nextcloud.db-objects-known',", "sink.auto('nextcloud.db-objects-known',"),
    ('M71', 'the retry note of the listing file is in the log', "ha_odoo.Cluster(tmp, 'nc-db', log=work.log).write_file('/tmp/woowbk-nc.toc', left.encode('utf-8', 'surrogateescape'))",
     "ha_odoo.Cluster(tmp, 'nc-db').write_file('/tmp/woowbk-nc.toc', left.encode('utf-8', 'surrogateescape'))"),
    ('M72', 'a refused restore says why', "    if ha_major is not None and pg_major is not None and ha_major > pg_major:\n", "    if False:\n"),
    ('M73', 'a refused restore is a stop', "            raise BackupError('job-failed', restore_failed(majors)) from None", "            pass"),
    ('M74', 'the new cluster has the live extensions', "              + ''.join(f'CREATE EXTENSION IF NOT EXISTS {_ext_ident(e)};\\n' for e in extensions + extras), live.db_name)",
     "              + ''.join(f'CREATE EXTENSION IF NOT EXISTS {_ext_ident(e)};\\n' for e in extras), live.db_name)"),
]

CONTROLS = [
    ('K01', 'control: a comment', "# NC-32: HA's PostgreSQL against this device's is not asked here: the restore itself says (restore_dump).",
     "# NC-32: HA's PostgreSQL against this device's is not asked here (restore_dump says)."),
    ('K02', 'control: a docstring word', "    \"\"\"A conversion never goes on past a stop, whatever kind of sink it was given", "    \"\"\"A conversion never goes on past a stop, whichever kind of sink it was given"),
]


def prepare(repo, root):
    work = Path(root) / 'repo'
    work.mkdir()
    shutil.copytree(repo / 'backup-engine', work / 'backup-engine', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(repo / 'tests' / 'backup', work / 'tests' / 'backup', ignore=shutil.ignore_patterns('__pycache__', 'evidence'))
    for name in ('tests/__init__.py', 'VERSION'):
        if (repo / name).exists():
            (work / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(repo / name, work / name)
    (work / 'backup').mkdir()
    return work


def run(work, tests, failfast=True):
    env = {'PATH': os.environ['PATH'], 'HOME': os.environ.get('HOME', '/'), 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
           'PYTHONPATH': 'backup-engine', 'TMPDIR': str(work.parent)}
    argv = [sys.executable, '-m', 'unittest', *(['-f'] if failfast else []), *tests]
    done = subprocess.run(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1500)
    ran = re.search(r'^Ran (\d+) test', done.stderr, re.M)
    return done.returncode, int(ran.group(1)) if ran else 0, done.stderr[-1500:]


def one(repo, item):
    mid, what, old, new = item
    with tempfile.TemporaryDirectory(prefix='ncmut-', dir=os.environ.get('NCMUT_TMP')) as root:
        work = prepare(repo, root)
        path = work / 'backup-engine' / MOD
        text = path.read_text(encoding='utf-8')
        if text.count(old) != 1:
            return {'id': mid, 'what': what, 'caught': None, 'note': f'text found {text.count(old)} times'}
        path.write_text(text.replace(old, new), encoding='utf-8')
        t0 = time.monotonic()
        try:
            rc, ran, _tail = run(work, TESTS)
        except subprocess.TimeoutExpired:
            return {'id': mid, 'what': what, 'caught': True, 'tests_run': 0, 'note': 'timeout (a loop): noticed',
                    'seconds': round(time.monotonic() - t0, 1)}
        return {'id': mid, 'what': what, 'caught': rc != 0, 'tests_run': ran, 'seconds': round(time.monotonic() - t0, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', required=True)
    ap.add_argument('--json')
    ap.add_argument('--only')
    ap.add_argument('--jobs', type=int, default=2)
    ap.add_argument('--check-text', action='store_true')
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    only = set(args.only.split(',')) if args.only else None
    todo = [m for m in MUTATIONS + CONTROLS if only is None or m[0] in only]
    if args.check_text:
        text = (repo / 'backup-engine' / MOD).read_text(encoding='utf-8')
        bad = [(m[0], text.count(m[2])) for m in todo if text.count(m[2]) != 1]
        print('texts: ' + ('all found once' if not bad else f'NOT once: {bad}'))
        return 0 if not bad else 1
    with tempfile.TemporaryDirectory(prefix='ncmut-', dir=os.environ.get('NCMUT_TMP')) as root:
        work = prepare(repo, root)
        rc, ran, tail = run(work, TESTS, failfast=False)
    baseline = {'returncode': rc, 'tests': ran}
    print(f'baseline: {"pass" if rc == 0 else "FAIL"} ({ran} tests)', flush=True)
    if rc != 0:
        print(tail)
        return 2
    rows = []
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        for row in pool.map(lambda m: one(repo, m), todo):
            rows.append(row)
            print(f'{row["id"]} {row["what"]}: ' + ('NOT APPLIED ' + row['note'] if row['caught'] is None else
                                                    'caught' if row['caught'] else 'not noticed'), flush=True)
    controls = {m[0] for m in CONTROLS}
    missed = [r['id'] for r in rows if r['id'] not in controls and r['caught'] is not True]
    noisy = [r['id'] for r in rows if r['id'] in controls and r['caught'] is not False]
    total = sum(1 for r in rows if r['id'] not in controls)
    ok = not missed and not noisy
    if args.json:
        head = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        sources = {MOD: hashlib.sha256((repo / 'backup-engine' / MOD).read_bytes()).hexdigest()}
        Path(args.json).write_text(json.dumps({'lane': 'NEXTCLOUD', 'head': head, 'baseline': baseline, 'sources': sources,
                                               'tests': TESTS, 'caught': total - len(missed), 'total': total, 'missed': missed,
                                               'controls_noticed': noisy, 'rows': rows}, ensure_ascii=False, indent=1))
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({total - len(missed)}/{total} caught, missed {missed}, controls noticed {noisy})')
    return 0 if ok else 1


sys.exit(main())
