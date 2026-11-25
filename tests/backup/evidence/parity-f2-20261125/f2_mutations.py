#!/usr/bin/env python3
"""Mutation check of lane F2-chain (HAOS parity, 2026-11-25): each rule of the chain is removed, one place at a time, in a
throwaway copy of the repository, and the unit tests must FAIL for each (and pass on the unmodified copy). CONTROLS change a
comment only and must go unnoticed. Nothing here touches Podman, a device or a secret.

  python3 -I f2_mutations.py --repo <worktree> [--json OUT] [--only ID,ID] [--jobs N] [--check]
"""
import argparse, concurrent.futures, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

HC, JB, CL = 'woowbackup/hachain.py', 'woowbackup/jobs.py', 'woowbackup/cli.py'
TESTS = ('tests.backup.test_ha_chain', 'tests.backup.test_jobs', 'tests.backup.test_ha_cli', 'tests.backup.test_cli')

# (id, protection, module, exact text, replacement)
MUTATIONS = [
    # ---------------------------------------------------------------- hachain.py: what follows a job
    ('C01', 'a conversion is followed by the restore of the same app', HC,
     "    inflight = (stop is None and step == 'convert'", "    inflight = (False and step == 'convert'"),
    ('C02', 'stop after this app never cuts an app between its conversion and its restore', HC,
     "    inflight = (stop is None and step == 'convert'",
     "    inflight = (stop is None and not store.stop_requested(group['id']) and step == 'convert'"),
    ('C03', 'one app\'s failure does not stop the others', HC,
     "            return Stop('corrupt-archive')\n        return None\n", "            return Stop('corrupt-archive')\n        return Stop(code or 'internal-error')\n"),
    ('C04', 'a cancel ends the import', HC, "    if outcome.state == 'cancelled':\n        return Stop('cancelled')\n",
     "    if outcome.state == 'cancelled':\n        return None\n"),
    ('C05', 'a termination ends the import', HC, "    if outcome.state == 'interrupted':\n        return Stop('interrupted')\n",
     "    if outcome.state == 'interrupted':\n        return None\n"),
    ('C06', 'a cancel that came a moment too late still ends the import', HC,
     "    if ctx.reporter.cancel_requested():\n        return Stop('cancelled')", "    if False:\n        return Stop('cancelled')"),
    ('C07', 'what is job-wide ends the import', HC, "    if not haissues.ends_job(exc):\n        if group['step']",
     "    if True:\n        if group['step']"),
    ('C08', 'a disk that is still full ends the import', HC,
     "        return None if _space_recovered(ctx) else Stop('insufficient-space')", "        return None"),
    ('C09', 'a disk that has room again only fails that app', HC,
     "        return None if _space_recovered(ctx) else Stop('insufficient-space')", "        return Stop('insufficient-space')"),
    ('C10', 'a damaged HA file ends the import', HC,
     "        if group['step'] == 'convert' and code == 'corrupt-archive' and _outer_file_damaged(ctx, chain):",
     "        if False:"),
    ('C11', 'a changed HA file is damaged', HC, "            return backup.layout.size != record['size']", "            return False"),
    ('C12', 'an HA file that cannot be read is damaged', HC,
     "    except Exception:  # noqa: BLE001 - what cannot be read is damaged enough: the import stops\n        return True",
     "    except Exception:  # noqa: BLE001 - what cannot be read is damaged enough: the import stops\n        return False"),
    ('C13', 'the apps not reached are listed as not started', HC,
     "            shown = shown + _remaining(group, chain, stop)\n", "            shown = shown\n"),
    ('C14', 'a restore chain restores the next app', HC,
     "                follow = ('restore' if group['kind'] == 'ha-restore' else 'convert', apps[index + 1])",
     "                follow = ('convert', apps[index + 1])"),
    ('C15', 'the next job runs in the unit of the first', HC,
     "    return store.create(job_type, params, now=now, unit=record.get('unit'))", "    return store.create(job_type, params, now=now)"),
    ('C16', 'the jobs of one import are in order', HC,
     "    now = max(time.time(), (jobs.parse_iso(record.get('created')) or 0) + 1)", "    now = time.time()"),
    ('C17', 'the restore of an app restores the backup its conversion made', HC,
     "    backup_id = entry['backup_id'] if step == 'restore' and group['step'] == 'convert' else None",
     "    backup_id = None"),
    ('C18', 'a restore chain restores the same backup for each app', HC,
     "        backup_id = (record.get('params') or {}).get('backup_id')  # a restore chain: the same backup, the next app",
     "        backup_id = None"),
    ('C19', 'a restore job carries only its own app\'s confirmed lines', HC,
     "if items and name in (app_id, haissues.SHARED)}", "if items}"),
    ('C20', 'a conversion job carries only its own app\'s confirmed lines', HC,
     "                    if keys and app_id in (*apps, haissues.SHARED)}", "                    if keys}"),
    ('C21', 'the Odoo database goes to Odoo only', HC,
     "    return (chain['choices'].get(app_id) or {}).get('database') if app_id == 'odoo' else None",
     "    return (chain['choices'].get(app_id) or {}).get('database')"),
    ('C22', 'a restore job keeps the HA file from being deleted', HC,
     "        params['ha_backup_id'] = chain['ha_backup_id']  # the HA file stays protected while any job of the import is queued",
     "        pass"),
    ('C23', 'a rolled back restore says rolled-back', HC,
     "        entry.update(status='rolled-back', message=_short(f'{_reason(error)}{ROLLED_BACK_TAIL}'))",
     "        entry.update(status='failed', message=_short(f'{_reason(error)}{ROLLED_BACK_TAIL}'))"),
    ('C24', 'a restore that changed something is not told that nothing changed', HC,
     "        if result.get('changed') is not True and error.get('message'):", "        if error.get('message'):"),
    ('C25', 'a conversion that names no backup is not restored', HC, "            elif backup_id is None:", "            elif False:"),
    ('C26', 'the apps of a record belong to its group', HC,
     "            or group['count'] != len(apps) or apps[group['index']] != group['app_id']):",
     "            or group['count'] != len(apps)):"),
    ('C27', 'an index outside the count is no group', HC, "or not 0 <= index < count <= MAX_APPS", "or False"),
    ('C28', 'the stop request has done its work when the import ends', HC,
     "    with contextlib.suppress(OSError):\n        store.clear_stop(group['id'])\n", "    pass\n"),
    ('C29', 'the room a job keeps free is measured', HC,
     "        return free is not None and int(free) >= flows.running_reserve(ctx) + haimport.WATCH_MARGIN",
     "        return free is not None"),
    ('C30', 'a job that never started says so', HC, "    if not started:\n        message = NOT_STARTED\n", "    if False:\n        message = NOT_STARTED\n"),
    ('C31', 'the results go into the converted backups\' rows', HC,
     "            haimport.update_row(paths, row['backup_id'], results=results)", "            pass"),
    ('C32', 'the groups results are in the finished record', HC,
     "        final = _with_group(outcome.result, _view(group, created['id'] if created else None, shown))",
     "        final = outcome.result"),
    ('C33', 'the key never reaches a restore job', HC,
     "    params = {'backup_id': backup_id, 'apps': [app_id], 'key_provided': bool(key_provided)}",
     "    params = {'backup_id': backup_id, 'apps': [app_id], 'key_provided': bool(key_provided), 'key': 'x'}"),
    # ---------------------------------------------------------------- jobs.py
    ('J01', 'the next job is written before the finished one', JB,
     "            try:\n                final, created = hachain.conclude(ctx, reporter.record, hachain.Outcome(state, result, error, exc))\n"
     "            except Exception:  # noqa: BLE001 - the job's own outcome is recorded all the same; the import ends here\n"
     "                traceback.print_exc(file=sys.stderr)\n                final, created = result, None\n"
     "            reporter.finish(state, result=final, error=error)\n",
     "            reporter.finish(state, result=result, error=error)\n"
     "            try:\n                final, created = hachain.conclude(ctx, reporter.record, hachain.Outcome(state, result, error, exc))\n"
     "            except Exception:  # noqa: BLE001 - the job's own outcome is recorded all the same; the import ends here\n"
     "                traceback.print_exc(file=sys.stderr)\n                final, created = result, None\n"),
    ('J02', 'the HA key file goes with the first job', JB,
     "        elif first:\n            _remove_key_file(self.store, reporter.job_id)  # the HA key lives in memory from here on\n",
     "        elif False:\n            _remove_key_file(self.store, reporter.job_id)\n"),
    ('J03', 'the HA key reaches the later jobs in memory', JB,
     "        if self.ha_key is not None:\n            ctx.ha_key = self.ha_key\n", "        if self.ha_key is not None:\n            pass\n"),
    ('J04', 'the key is masked for the whole run', JB,
     "                self.masks.enter_context(masked(self.ha_key))", "                pass"),
    ('J05', 'the age key of a restore chain stays for every job', JB,
     "            self.key_file = ctx.key_file\n", "            self.key_file = None\n"),
    ('J06', 'a cancel of any job of an import means its live job', JB,
     "            if group is not None:\n                member = hachain.active_member(store, group['id'])",
     "            if False:\n                member = hachain.active_member(store, group['id'])"),
    ('J07', 'a cancel finds the successor of a job that ended while it waited', JB,
     "                    continue  # the import's live job finished meanwhile: its successor is the one to ask",
     "                    return {'state': record['state']}"),
    ('J08', 'only an import can stop after this app', JB,
     "        if after_this and group is None:\n            raise BackupError(", "        if False:\n            raise BackupError("),
    ('J09', 'a job that was written but never began is finished at once when the process is told to end', JB,
     "        if created is not None and deferred.pending:", "        if False:"),
    ('J10', 'a signal in the critical section is only noted', JB,
     "        state.pending, state.signum = True, signum", "        raise Terminated(signum)"),
    ('J11', 'a job cancelled before it began tells what became of the import', JB,
     "                    hachain.unstarted(self.paths, store, reporter.record)", "                    pass"),
    ('J12', 'recovery says which apps of an import are done', JB,
     "    message, result = hachain.interrupted(record, message, result)  # a job of an import's chain: which apps are done",
     "    message, result = message, result"),
    ('J13', 'run_job answers with the job it was given', JB, "        return first\n", "        return record\n"),
    ('J14', 'the memory of one job is collected before the next', JB, "            gc.collect()  # one process", "            pass  # one process"),
    ('J15', 'the lock file names the job that runs', JB, "        os.pwrite(self.lock_fd, f'{job_id}\\n'.encode(), 0)", "        pass"),
    ('J16', 'a cancelled check keeps what it found', JB,
     "                state, result, exc = 'cancelled', getattr(caught, 'result', None), caught", "                state, result, exc = 'cancelled', None, caught"),
    ('J17', 'a terminated check keeps what it found', JB,
     "('interrupted', getattr(caught, 'result', None) or partial,", "('interrupted', partial,"),
    ('J18', 'a stop request of an import that is over is swept', JB,
     "and not (stop and stop.group(1) not in live_groups)", "and not False"),
    ('J19', 'a stop request of a live import is kept', JB,
     "and not (stop and stop.group(1) not in live_groups)", "and not (stop)"),
    ('J20', 'the stop request is a file of the group only', JB,
     "        if not isinstance(group_id, str) or not GROUP_ID_RE.fullmatch(group_id):", "        if False:"),
    ('J21', 'a job of an import is a chain job only with its group and chain', JB,
     "        chained = self.follow and hachain.in_chain(reporter.record)", "        chained = self.follow and bool(reporter.record['params'].get('group'))"),
    ('J22', 'a record names its unit', JB,
     "'unit': unit if isinstance(unit, str) and unit else unit_name(job_id),", "'unit': unit_name(job_id),"),
    ('J23', 'a recovery pass keeps the key file of a restore chain that is still running', JB,
     "    _sweep_key_files(paths, store, now, _live_groups(store.list(limit=None) if changed else records))",
     "    _sweep_key_files(paths, store, now)"),
    ('J26', 'the key file of an import that ended in this recovery pass goes in this pass', JB,
     "_live_groups(store.list(limit=None) if changed else records))", "_live_groups(records))"),
    ('J24', 'an import that cannot get the engine says which apps it did not reach', JB,
     "                            hachain.unstarted(paths, store, reporter.record, hachain.Stop('busy'))", "                            pass"),
    ('C34', 'an unconfirmed line of a restore keeps the app out, not failed', HC,
     "            entry['status'] = 'skipped'  # kept out before anything of it was touched (a line of the restore check)", "            pass"),
    ('C35', 'a job that was written for a restore keeps its converted backup\'s id in the result of an interrupted import', HC,
     "                     backup_id=params.get('backup_id'))\n        if started:", "                     backup_id=None)\n        if started:"),
    ('C36', 'a converted backup that is bad is not offered for another try', HC,
     "            tail = UNCHANGED_BAD_TAIL if error.get('code') in BAD_BACKUP_CODES else UNCHANGED_TAIL", "            tail = UNCHANGED_TAIL"),
    # ---------------------------------------------------------------- cli.py
    ('L01', 'only a converted backup with several apps is split', CL,
     "    if 1 < len(apps) <= hachain.MAX_APPS and _from_ha(svc, req['backup_id']):", "    if 1 < len(apps) <= hachain.MAX_APPS:"),
    ('L02', 'a converted backup of one app restores as a single job', CL,
     "    if 1 < len(apps) <= hachain.MAX_APPS and _from_ha(svc, req['backup_id']):", "    if _from_ha(svc, req['backup_id']):"),
    ('L11', 'a request of more apps than a chain can name is not cut to its first', CL,
     "    if 1 < len(apps) <= hachain.MAX_APPS and _from_ha(svc, req['backup_id']):", "    if 1 < len(apps) and _from_ha(svc, req['backup_id']):"),
    ('L03', 'the first job of a split restore restores the first app', CL, "        params['apps'] = apps[:1]\n", ""),
    ('L04', 'job-cancel passes after_this', CL, "after_this=req.get('after_this') is True)", "after_this=False)"),
    ('L05', 'an import chain remembers whether a key was typed', CL,
     "encrypt=encrypt, key_provided=key is not None, ha_backup_id=rec['id'],", "encrypt=encrypt, key_provided=False, ha_backup_id=rec['id'],"),
    ('L06', 'an import chain remembers its HA backup', CL,
     "encrypt=encrypt, key_provided=key is not None, ha_backup_id=rec['id'],", "encrypt=encrypt, key_provided=key is not None, ha_backup_id=None,"),
    ('L07', 'the options of a split restore go to every job', CL,
     "                                            allow_no_safety=bool(req.get('allow_no_safety')),\n", "                                            allow_no_safety=False,\n"),
    ('L08', 'a retry of a split restore returns the same group', CL,
     "        reply['group'] = known.get('id') if started.get('deduplicated') else group", "        reply['group'] = group"),
    ('L09', 'the first job of a split restore keeps only its app\'s lines', CL,
     "        acknowledged = {app_id: keys for app_id, keys in acknowledged.items() if app_id == apps[0]}\n", ""),
    ('L10', 'an unreadable registry never splits', CL,
     "    except Exception:  # noqa: BLE001 - the registry never changes whether a restore can start\n        traceback.print_exc(file=sys.stderr)\n        return False",
     "    except Exception:  # noqa: BLE001 - the registry never changes whether a restore can start\n        raise"),
]
CONTROLS = [
    ('K01', 'a comment of hachain.py', HC, "# What the customer reads about an app the import did not reach", "# What the customer reads about an app that the import did not reach"),
    ('K02', 'a comment of jobs.py', JB, "# Old private names, kept for callers and tests written against them.", "# Old private names, kept for callers and for tests written against them."),
]


def prepare(repo, root):
    work = Path(root) / 'repo'
    work.mkdir()
    shutil.copytree(repo / 'backup-engine', work / 'backup-engine', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(repo / 'tests' / 'backup', work / 'tests' / 'backup', ignore=shutil.ignore_patterns('__pycache__', 'evidence'))
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
    done = subprocess.run(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1500)
    ran = re.search(r'^Ran (\d+) test', done.stderr, re.M)
    return done.returncode, int(ran.group(1)) if ran else 0, done.stderr[-1500:]


def one(repo, item):
    mid, what, module, old, new = item
    with tempfile.TemporaryDirectory(prefix='f2mut-', dir=os.environ.get('F2MUT_TMP')) as root:
        work = prepare(repo, root)
        path = work / 'backup-engine' / module
        text = path.read_text(encoding='utf-8')
        if text.count(old) != 1:
            return {'id': mid, 'what': what, 'caught': None, 'note': f'text found {text.count(old)} times'}
        path.write_text(text.replace(old, new), encoding='utf-8')
        t0 = time.monotonic()
        rc, ran, tail = run(work, TESTS)
        return {'id': mid, 'what': what, 'module': module, 'caught': rc != 0, 'tests_run': ran, 'seconds': round(time.monotonic() - t0, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', required=True)
    ap.add_argument('--json')
    ap.add_argument('--only')
    ap.add_argument('--jobs', type=int, default=2)
    ap.add_argument('--check', action='store_true', help='only check that every mutation applies exactly once')
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    only = set(args.only.split(',')) if args.only else None
    todo = [m for m in MUTATIONS + CONTROLS if only is None or m[0] in only]
    if args.check:
        bad = 0
        for mid, what, module, old, new in todo:
            count = (repo / 'backup-engine' / module).read_text(encoding='utf-8').count(old)
            if count != 1 or old == new:
                bad += 1
                print(f'{mid} {what}: text found {count} times')
        print(f'{len(todo)} mutations, {bad} that do not apply once')
        return 1 if bad else 0
    with tempfile.TemporaryDirectory(prefix='f2mut-', dir=os.environ.get('F2MUT_TMP')) as root:
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
        sources = {m: hashlib.sha256((repo / 'backup-engine' / m).read_bytes()).hexdigest() for m in (HC, JB, CL)}
        Path(args.json).write_text(json.dumps({'lane': 'F2-chain', 'head': head, 'baseline': baseline, 'sources': sources, 'tests': TESTS,
                                               'caught': total - len(missed), 'total': total, 'missed': missed,
                                               'controls_noticed': noisy, 'rows': rows}, ensure_ascii=False, indent=1))
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({total - len(missed)}/{total} caught, missed {missed}, controls noticed {noisy})')
    return 0 if ok else 1


sys.exit(main())
