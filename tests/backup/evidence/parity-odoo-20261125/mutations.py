#!/usr/bin/env python3
"""Mutation check of lane ODOO (HAOS parity, 2026-11-25): each rule or protection listed in MUTATIONS is removed, one place at
a time, in a throwaway copy of the repository, and the unit tests of the lane must FAIL for each (and pass on the unmodified
copy). CONTROLS change a comment only and must go unnoticed. Nothing here touches Podman, a device or a secret (the tests use
doubles only).

  python3 -I mutations.py --repo <worktree> [--json OUT] [--only ID,ID] [--jobs N] [--check-text]
"""
import argparse, concurrent.futures, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

MOD = 'woowbackup/ha_odoo.py'
TESTS = ('tests.backup.test_ha_odoo', 'tests.backup.test_ha_pg_stdin', 'tests.backup.test_ha_flows')

# (id, what is protected, exact text (once in ha_odoo.py), replacement)
MUTATIONS = [
    ('M01', 'quadlet_mounts still refuses a time zone path for the other importers',
     "            if skipped is None:\n                raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援：{value[:80]}')\n",
     "            if False:\n                raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援：{value[:80]}')\n"),
    ('M02', 'quadlet_mounts still refuses a %h path with ..',
     "                if skipped is None:\n                    raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援。')\n",
     "                if False:\n                    raise BackupError('incompatible', f'{container_file} 的 Volume= 設定不受支援。')\n"),
    ('M03', 'a mount that is left out is listed', "            skipped.append((container_file, target))\n            continue\n        mounts.append(",
     "            continue\n        mounts.append("),
    ('M04', 'the data volume is the mount that holds the cluster',
     "        holder = next((m for m in db_mounts if wanted == m[1] or wanted.startswith(m[1].rstrip('/') + '/')), None)\n",
     "        holder = None\n"),
    ('M05', 'a cluster in a mount that was left out stops the app', "            if db_skipped:   # (also when nothing else is mounted)\n",
     "            if False:   # (also when nothing else is mounted)\n"),
    ('M06', 'a superuser name with a control character is refused',
     "        if (not self.db_user or len(self.db_user.encode('utf-8', 'surrogatepass')) > MAX_NAME_BYTES\n                or BAD_NAME_RE.search(self.db_user)):\n",
     "        if False:\n"),
    ('M07', 'a configuration name the tools cannot take stops the app',
     "            if value is not None and not pattern.fullmatch(value):\n", "            if False:\n"),
    ('M08', 'an odd database name goes through PGDATABASE',
     "    if not by_env and DB_NAME_RE.fullmatch(database):\n        return ['-d', database], None\n    return [], {'PGDATABASE': database}\n",
     "    return ['-d', database], None\n"),
    ('M09', 'a database name PostgreSQL cannot have is refused',
     "    if not isinstance(database, str) or not database or len(database.encode('utf-8', 'surrogatepass')) > MAX_NAME_BYTES \\\n            or BAD_NAME_RE.search(database):\n",
     "    if False:\n"),
    ('M10', 'query_json hands the name over by environment',
     "                                        self.superuser, *where, '-c', sql], user='postgres', timeout=timeout,\n",
     "                                        self.superuser, '-d', database, '-c', sql], user='postgres', timeout=timeout,\n"),
    ('M11', 'a script hands the name over by environment',
     "'-U', self.superuser, *where,\n                                        '-f', '-'], user='postgres',\n",
     "'-U', self.superuser, '-d', database,\n                                        '-f', '-'], user='postgres',\n"),
    ('M12', 'the details of an HA database are asked by environment',
     "        return cluster.query_json(sql, name, by_env=True, max_output=room)\n",
     "        return cluster.query_json(sql, name, max_output=room)\n"),
    ('M13', 'pg_dump takes the name by environment',
     "['pg_dump', '-U', 'postgres', '-Fc', *where], user='postgres', env=env, stdout=handle,",
     "['pg_dump', '-U', 'postgres', '-Fc', '-d', database], user='postgres', stdout=handle,"),
    ('M14', 'the old uuid is asked by environment', "                                  database, by_env=True)\n", "                                  database)\n"),
    ('M15', 'a module list without any module stops', "            or not doc['modules']):\n", "            ):\n"),
    ('M16', 'an empty module table stops', "    if not modules:\n        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。')\n",
     "    if False:\n        raise BackupError('job-failed', '無法讀取這台 Odoo 的模組清單。')\n"),
    ('M17', 'the scan waits longer for a big backup', "                     timeout=podman.scaled_timeout(600, size), max_output=room, read_only_root=True)\n",
     "                     timeout=600, max_output=room, read_only_root=True)\n"),
    ('M18', 'the configuration password is masked', "    if 'db_password' in conf:\n        jobs.mask_secret(conf['db_password'])\n",
     "    if False:\n        jobs.mask_secret(conf['db_password'])\n"),
    ('M19', 'a password with a control character is not used',
     "0 < len(value) <= 1024 and not re.search(r'[\\x00-\\x1f\\x7f]', value):", "0 < len(value) <= 1024:"),
    ('M20', 'only trusted extensions are created', "                       if ext not in offered or not (ext in EXTENSIONS_OK or offered[ext] is True)]\n",
     "                       if ext not in offered]\n"),
    ('M21', 'a database that uses vector stops without the image', "    if 'vector' in extensions and not vector_ok and 'vector' not in unsupported:\n",
     "    if False:\n"),
    ('M22', 'objects only a superuser can create are a line to confirm', "    if details.get('superuser_objects'):\n", "    if False:\n"),
    ('M23', 'the databases that stay on HA are a line to confirm', "    if others:\n        add('odoo.databases-left'", "    if False:\n        add('odoo.databases-left'"),
    ('M24', 'pending modules are said', "    if pending:\n        add('odoo.modules-pending'", "    if False:\n        add('odoo.modules-pending'"),
    ('M25', 'another version of a module stops the database', "    if mismatch:\n        add('odoo.module-version-different'",
     "    if False:\n        add('odoo.module-version-different'"),
    ('M26', 'a missing module is a line to confirm', "    if missing:\n        add('odoo.modules-missing'", "    if False:\n        add('odoo.modules-missing'"),
    ('M27', 'a missing Python package keeps the module out', "            elif target['python'].get(dep) is not True:\n                lacking.append(dep)\n",
     "            elif False:\n                lacking.append(dep)\n"),
    ('M28', 'a spelling that was never asked of Odoo is only said', "            if not PY_DEP_RE.fullmatch(dep):       # a spelling that was never asked of Odoo: only said\n",
     "            if False:       # a spelling that was never asked of Odoo: only said\n"),
    ('M29', 'what is missing is confirmed (verify accepts it)', "    unavailable.update(missing)\n", "    pass\n"),
    ('M30', 'a newer PostgreSQL of HA stops the database', "    if ha_major is None or target_major is None or ha_major > target_major:\n", "    if False:\n"),
    ('M31', 'no copy without a modules folder', "        if has_copy and can_copy and (effective is None", "        if has_copy and (effective is None"),
    ('M32', 'a database that cannot be read stops only itself',
     "                if error.code != 'job-failed' or haissues.is_job_wide(error):\n                    raise\n                message = error.message",
     "                if True:\n                    raise\n                message = error.message"),
    ('M33', 'a name with a control character stops that database', "        if not _valid_name(name):\n", "        if False:\n"),
    ('M34', 'not an Odoo database stops that database', "            if details is None:\n                stop('odoo.not-odoo'", "            if False:\n                stop('odoo.not-odoo'"),
    ('M35', 'a stop makes the database not ok', "        entry['ok'] = not any(issue.level == 'stop' for issue in entry['_issues'])\n", "        entry['ok'] = True\n"),
    ('M36', 'no database stops the app', "    if not databases:\n        sink.stop('odoo.no-database'", "    if False:\n        sink.stop('odoo.no-database'"),
    ('M37', 'no database that can move stops the app', "    elif not any(entry['ok'] for entry in databases):\n", "    elif False:\n"),
    ('M38', 'a name that cannot be passed cannot be chosen', "'ok': entry['ok'] and _valid_name(entry['name'])}", "'ok': True}"),
    ('M39', 'the vector image is fetched and the database read again', "    if 'pgvector' not in image16 and any(", "    if False and any("),
    ('M40', 'a second walk does not say a line twice', "            _unique(sink.found)   # the second walk of the same member said the same things again\n", ""),
    ('M41', 'a superuser role is made an ordinary one', "        else:\n            for key in ('login', 'createdb', 'createrole', 'replication', 'bypassrls', 'connlimit'):\n",
     "        if True:\n            for key in ('login', 'createdb', 'createrole', 'replication', 'bypassrls', 'connlimit'):\n"),
    ('M42', 'no password anywhere stops the app', "        if password is None:\n            sink.refuse('odoo.role-unusable'", "        if False:\n            sink.refuse('odoo.role-unusable'"),
    ('M43', 'only a verifier is taken over', "        if isinstance(verifier, str) and VERIFIER_RE.fullmatch(verifier):\n", "        if isinstance(verifier, str) and verifier:\n"),
    ('M44', 'the role password is masked', "    jobs.mask_secret(role['password'])\n    return role\n", "    return role\n"),
    ('M45', 'a marker of another image is written new', "    if not marker_ok(marker, image_id):\n        marker = engine_marker(", "    if False:\n        marker = engine_marker("),
    ('M46', 'no release no marker', "    if release is None:\n        sink.refuse('odoo.marker-unwritable'", "    if False:\n        sink.refuse('odoo.marker-unwritable'"),
    ('M47', 'a missing settings table gives the defaults', "    doc = _read_live_json(work, app, live, LIVE_SQL, live.db_name) if table is True else None\n",
     "    doc = _read_live_json(work, app, live, LIVE_SQL, live.db_name)\n"),
    ('M48', 'an address that is not text is replaced', "    if base_url is not None and (not isinstance(base_url, str) or len(base_url) > 2048):\n", "    if False:\n"),
    ('M49', 'the Odoo image is downloaded when missing', "    hatarget.ensure_image(work, app, live.web_image)\n    info = work.adapter(app)", "    info = work.adapter(app)"),
    ('M50', 'the database image is downloaded when missing', "    hatarget.ensure_image(work, app, live.db_image)\n    live_settings(work, app, live, image_id, sink)\n",
     "    live_settings(work, app, live, image_id, sink)\n"),
    ('M51', 'a PostgreSQL 16 image on the device is used', "        if hatarget.image_present(work, app, ref):\n            return ref\n", "        if False:\n            return ref\n"),
    ('M52', 'the PostgreSQL 16 image is downloaded', "    hatarget.ensure_image(work, app, PG16_PINNED)\n    return PG16_PINNED\n", "    return PG16_PINNED\n"),
    ('M53', 'the wait for HA cluster grows with its size', "timeout=podman.scaled_timeout(PG_READY_TIMEOUT, size))\n    return cluster\n",
     "timeout=PG_READY_TIMEOUT)\n    return cluster\n"),
    ('M54', 'other volumes of the settings are carried', "            app, handled_volumes=(self.db_volume, web),\n", "            app, handled_volumes=(self.db_volume, web, *declared),\n"),
    ('M55', 'a modules folder the settings do not list is not used', "        if self.addons_rel is not None and self.addons_rel not in dirs:\n", "        if False:\n"),
    ('M56', 'Odoo data not at /var/lib/odoo stops the app', "        if web is None:\n            problems.append('Odoo 的資料沒有掛在 /var/lib/odoo')\n",
     "        if False:\n            problems.append('Odoo 的資料沒有掛在 /var/lib/odoo')\n"),
    ('M57', 'an undeclared data volume stops the app', "        elif not {self.db_volume, web} <= set(declared):\n", "        elif False:\n"),
    ('M58', 'the conversion looks at its database again', "    sink.extend(entry['_issues'])\n    details, copy, unavailable", "    details, copy, unavailable"),
    ('M59', 'the restore list is checked against its header', "    check_listing(text)\n    kinds = superuser_kinds(text)\n", "    kinds = superuser_kinds(text)\n"),
    ('M60', 'a short list is refused', "    if declared is None or declared != entries + len(ARCHIVE_SETTINGS) - shown:\n", "    if declared is None:\n"),
    ('M61', 'the retry of the list write is in the job log', "    Cluster(tmp, 'odoo-db', log=work.log).write_file(", "    Cluster(tmp, 'odoo-db').write_file("),
    ('M62', 'objects only a superuser can create are left out of the list', "filter_toc(text, skip=kinds).encode(", "filter_toc(text).encode("),
    ('M63', 'a restore that fails stops this app with its issue', "            if sink is None:\n                raise BackupError('job-failed', message, database=database) from None\n",
     "            if True:\n                raise BackupError('job-failed', message, database=database) from None\n"),
    ('M64', 'the state of a module is as HA had it', "        if expected is not None and state != expected[1]:\n", "        if False:\n"),
    ('M65', 'the modules of the converted database are those of HA', "    if set(seen) != set(ha_rows):\n", "    if False:\n"),
    ('M66', 'an address that is not this device is a reminder', "    if doc.get('base_url') != live_values['base_url']:\n        notes.append(", "    if False:\n        notes.append("),
    ('M67', 'the same reminder is not said twice', "        if (issue_id, database) not in said:", "        if True:"),
    ('M68', 'a setting the new cluster refuses is taken out', "            for name in bad:\n                cluster.statement(f'ALTER SYSTEM RESET {name};')\n",
     "            for name in []:\n                cluster.statement(f'ALTER SYSTEM RESET {name};')\n"),
    ('M69', 'a setting that still has an error stops the job', "            if still:\n                raise BackupError('job-failed'", "            if False:\n                raise BackupError('job-failed'"),
    ('M70', 'what the reader left out is a line to confirm', "    sink.skipped(report)                              # IN-19, IN-27, IN-28, IN-35, IN-38, IN-39: the same line in the check and here\n", ""),
    ('M71', 'a manifest that is too large is left out and listed', "                data = entry.read_or_skip(MAX_MANIFEST)     # too large", "                data = entry.read_all(MAX_MANIFEST)     # too large"),
    ('M72', 'the databases that stay on HA are recorded', "            'left_databases': [db['name'] for db in databases if db['name'] != database][:100],\n", "            'left_databases': [],\n"),
    ('M73', 'a link of this device volume is one line to confirm', "                                 report=report, size=size)\n        sink.skipped(report)\n", "                                 report=report, size=size)\n"),
    ('M74', 'vector is created only when it is wanted', "    wanted = [ext for ext in EXTENSIONS_CREATED if offered is None or ext in offered or ext in details['extensions']]\n",
     "    wanted = list(EXTENSIONS_CREATED)\n"),
    ('M75', 'vector is updated only when it is there', "+ ('ALTER EXTENSION vector UPDATE;\\n' if 'vector' in extensions else '')", "+ 'ALTER EXTENSION vector UPDATE;\\n'"),
    ('M76', 'the restore runs as the role of the configuration', "            tmp.exec('odoo-db', ['pg_restore', '-U', role, '--no-owner'", "            tmp.exec('odoo-db', ['pg_restore', '-U', 'odoo', '--no-owner'"),
    ('M77', 'the database belongs to the role of the configuration', "'-O', live.db_role, '--template=template0'", "'-O', 'odoo', '--template=template0'"),
    ('M78', 'a role name is quoted', "    ident = name if name == DEFAULT_DB_ROLE else pg_ident(name)\n", "    ident = name\n"),
    ('M79', 'the dump list gets room by the dump size', "                       max_output=podman.scaled_limit(TOC_OUTPUT, size, ratio=TOC_OUTPUT_RATIO,\n                                                      ceiling=TOC_OUTPUT_CEILING)).stdout or b''\n",
     "                       max_output=TOC_OUTPUT).stdout or b''\n"),
    ('M80', 'the export waits longer for a big backup', "timeout=podman.scaled_timeout(3 * 3600, size),\n                     max_output=work.guard.budget(), abort=work.abort)\n",
     "timeout=3 * 3600,\n                     max_output=work.guard.budget(), abort=work.abort)\n"),
    ('M81', 'mail servers are said', "    if details['mail_servers_active']:\n        add('odoo.mail-servers-active'", "    if False:\n        add('odoo.mail-servers-active'"),
    ('M82', 'a layout the import cannot place stops the app', "        if problems:\n            raise haissues.stopped(Issue('odoo.layout-unsupported'", "        if False:\n            raise haissues.stopped(Issue('odoo.layout-unsupported'"),
    ('M83', 'the modules not installable are said', "        if not manifest.get('installable', True):\n            not_installable.append(module)\n", "        if False:\n            not_installable.append(module)\n"),
    ('M84', 'the target modules that cannot be read are said', "    if target.get('broken'):\n", "    if False:\n"),
    ('M85', 'a symlink that leaves a live copy is left out', "    if member.issym() and nested._escapes(name, member.linkname):\n", "    if False:\n"),
    ('M86', 'a hard link to what is not copied is left out', "    if member.islnk() and _norm(member.linkname) not in kept:\n", "    if False:\n"),
    ('M87', 'the links left out of the live copies are one line to confirm', "    sink.skipped(live_report)   # X-NS-08: the links that were left out of this device's own data dir and modules folder\n", ""),
    ('M88', 'a superuser password outside the secret is said at once', "        if ('POSTGRES_PASSWORD_FILE' not in self.db_env and not any('POSTGRES_PASSWORD' in spec for spec in self.db_secrets)\n                and _password_elsewhere(db_text)):\n", "        if False:\n"),
    ('M93', 'a secret that sets the password variable is no reason to stop', "and not any('POSTGRES_PASSWORD' in spec for spec in self.db_secrets)\n                and _password_elsewhere(db_text)):\n", "and _password_elsewhere(db_text)):\n"),
    ('M89', 'without a report nothing is left out', "    if report is None:\n        return False\n    if member.issym()", "    if report is None:\n        return True\n    if member.issym()"),
    ('M90', 'a copied member is a target for hard links', "            kept.add(name)\n            info = _copy_info(member, name)\n", "            info = _copy_info(member, name)\n"),
    ('M92', 'only the engine marker core date is the image release', "    return json.dumps({'digest': image_id, 'core_date': release}, separators=(',', ':'))\n", "    return json.dumps({'digest': image_id, 'core_date': 'x'}, separators=(',', ':'))\n"),
]
CONTROLS = [
    ('K01', 'a comment of the module', "# What is still to be written (review C-01)", "# (changed comment) What is still to be written (review C-01)"),
    ('K02', 'the text of a docstring', 'The check job\'s Odoo part:', 'The check job\'s Odoo part (changed):'),
]


def prepare(repo, root):
    work = Path(root) / 'repo'
    work.mkdir()
    shutil.copytree(repo / 'backup-engine', work / 'backup-engine', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(repo / 'tests' / 'backup', work / 'tests' / 'backup', ignore=shutil.ignore_patterns('__pycache__', 'evidence'))
    (work / 'tests' / 'e2e' / 'lab').mkdir(parents=True)
    ev = repo / 'tests' / 'e2e' / 'lab' / 'evidence' / 'arm54-final-20261123' / 'odoo-package-c578b8a' / 'config'
    (work / 'tests' / 'e2e' / 'lab' / 'evidence' / 'arm54-final-20261123' / 'odoo-package-c578b8a' / 'config').mkdir(parents=True)
    shutil.copy(ev / 'odoo.conf.template', work / 'tests' / 'e2e' / 'lab' / 'evidence' / 'arm54-final-20261123' / 'odoo-package-c578b8a' / 'config')
    for name in ('tests/__init__.py',):
        if (repo / name).exists():
            shutil.copy(repo / name, work / name)
    (work / 'backup').mkdir()
    shutil.copy(repo / 'VERSION', work / 'VERSION')
    return work


def run(work, tests, failfast=True):
    env = {'PATH': os.environ['PATH'], 'HOME': os.environ.get('HOME', '/'), 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
           'PYTHONPATH': 'backup-engine', 'TMPDIR': str(work.parent)}
    argv = [sys.executable, '-m', 'unittest', *(['-f'] if failfast else []), *tests]
    done = subprocess.run(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1200)
    ran = re.search(r'^Ran (\d+) test', done.stderr, re.M)
    return done.returncode, int(ran.group(1)) if ran else 0, done.stderr[-1500:]


def one(repo, item):
    mid, what, old, new = item
    with tempfile.TemporaryDirectory(prefix='odoomut-', dir=os.environ.get('ODOOMUT_TMP')) as root:
        work = prepare(repo, root)
        path = work / 'backup-engine' / MOD
        text = path.read_text(encoding='utf-8')
        if text.count(old) != 1:
            return {'id': mid, 'what': what, 'caught': None, 'note': f'text found {text.count(old)} times'}
        path.write_text(text.replace(old, new), encoding='utf-8')
        t0 = time.monotonic()
        try:
            rc, ran, tail = run(work, TESTS)
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
    with tempfile.TemporaryDirectory(prefix='odoomut-', dir=os.environ.get('ODOOMUT_TMP')) as root:
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
        Path(args.json).write_text(json.dumps({'lane': 'ODOO', 'head': head, 'baseline': baseline, 'sources': sources,
                                               'tests': TESTS, 'caught': total - len(missed), 'total': total, 'missed': missed,
                                               'controls_noticed': noisy, 'rows': rows}, ensure_ascii=False, indent=1))
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({total - len(missed)}/{total} caught, missed {missed}, controls noticed {noisy})')
    return 0 if ok else 1


sys.exit(main())
