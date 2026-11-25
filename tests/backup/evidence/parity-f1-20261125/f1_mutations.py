#!/usr/bin/env python3
"""Mutation check of lane F1-foundation (HAOS parity, 2026-11-25): each protection or rule listed in MUTATIONS is removed,
one place at a time, in a throwaway copy of the repository, and the unit tests must FAIL for each (and pass on the
unmodified copy). CONTROLS change a comment only and must go unnoticed. Nothing here touches Podman, a device or a secret.

  python3 -I mutations.py --repo <worktree> [--json OUT] [--only ID,ID] [--jobs N]
"""
import argparse, concurrent.futures, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path

HI, IM, CL, HA, ER = ('woowbackup/haissues.py', 'woowbackup/haimport.py', 'woowbackup/cli.py', 'woowbackup/haapps.py',
                      'woowbackup/errors.py')
TESTS = ('tests.backup.test_ha_issues', 'tests.backup.test_ha_registry', 'tests.backup.test_ha_cli',
         'tests.backup.test_ha_import', 'tests.backup.test_ha_space')

# (id, protection, module, exact text, replacement)
MUTATIONS = [
    # ---------------------------------------------------------------- haissues.py
    ('S01', 'a conversion needs the confirmed key', HI,
     "        if self.converting and issue.level == 'confirm' and issue.key(self.app_id) not in self.acknowledged:\n",
     "        if False:\n"),
    ('S02', 'a confirm is a confirm, not a notice', HI,
     "        return self.add(Issue(issue_id, 'confirm', message, items, database=database))\n",
     "        return self.add(Issue(issue_id, 'notice', message, items, database=database))\n"),
    ('S03', 'a stop stops a conversion', HI,
     "        if self.converting and issue.level == 'stop':\n            raise stopped(issue)\n", ""),
    ('S04', 'the key covers the names', HI,
     "sorted(str(item) for item in items)]", "[]]"),
    ('S05', 'the key covers the app', HI, "    body = json.dumps([app_id, issue_id, database,", "    body = json.dumps(['', issue_id, database,"),
    ('S06', 'the key covers the database', HI, "    body = json.dumps([app_id, issue_id, database,",
     "    body = json.dumps([app_id, issue_id, None,"),
    ('S07', 'the key covers the issue', HI, "    body = json.dumps([app_id, issue_id, database,", "    body = json.dumps([app_id, '', database,"),
    ('S08', 'the key covers names that are not shown', HI,
     "        self._key_items = names.key_items() if names is not None else values\n",
     "        self._key_items = names.key_items() if names is not None else values[:MAX_ITEMS]\n"),
    ('S09', 'a long list of names counts completely', HI,
     "        self._sum = (self._sum + int.from_bytes(digest, 'big')) % (1 << 256)\n", "        self._sum = 0\n"),
    ('S10', 'invisible and reordering characters are not shown', HI,
     "' ' if unicodedata.category(ch) in HIDDEN_CATEGORIES else ch for ch", "ch for ch"),
    ('S11', 'messages are masked', HI, "'message': clean(_redact(self.message), MAX_MESSAGE)", "'message': clean(self.message, MAX_MESSAGE)"),
    ('S12', 'names are masked', HI, "return [clean(_redact(name), MAX_ITEM) for name in self.names]", "return [clean(name, MAX_ITEM) for name in self.names]"),
    ('S13', 'actions are masked', HI, "value['action'] = clean(_redact(self.action), MAX_ACTION)", "value['action'] = clean(self.action, MAX_ACTION)"),
    ('S14', 'at most 40 lines', HI, "    if len(rows) > MAX_ISSUES:\n", "    if False:\n"),
    ('S15', 'a stop or confirm is never dropped (lines)', HI, "        keep = max(must, MAX_ISSUES - 1)\n", "        keep = MAX_ISSUES - 1\n"),
    ('S16', 'at most 40 KiB', HI, "    while not fits and len(rows) > must:\n", "    while False:\n"),
    ('S17', 'a stop or confirm is never dropped (bytes)', HI, "    while not fits and len(rows) > must:\n", "    while not fits and len(rows) > 0:\n"),
    ('S18', 'dropped lines are counted', HI, "    return rows + ([_more(app_id, dropped)] if dropped else [])\n", "    return rows\n"),
    ('S19', 'names give way before lines, reminders first', HI,
     "        for levels in (('auto', 'notice'), ('stop', 'confirm')):\n", "        for levels in (('stop', 'confirm'), ('auto', 'notice')):\n"),
    ('S20', 'a stop makes the app not importable', HI,
     "    if any(issue.level == 'stop' and issue.database is None for issue in issues):\n        return False\n", ""),
    ('S21', 'no movable database: not importable', HI,
     "    return databases is None or any(row.get('ok') is True for row in databases)\n", "    return True\n"),
    ('S22', 'a stop of a database counts', HI, "row.get('ok', True) is True and row['value'] not in stops)", "row.get('ok', True) is True)"),
    ('S23', 'the only database that can move is the default', HI, "    if len(movable) == 1 and not any(", "    if False and not any("),
    ('S24', 'several movable databases have no default', HI, "    if len(movable) == 1 and not any(", "    if movable and not any("),
    ('S25', 'an older page does not import what needs confirming', HI, "'ok': can and not to_confirm,", "'ok': can,"),
    ('S26', 'what ends the job ends it', HI, "    return None if ends_job(error) else from_error(error)\n", "    return from_error(error)\n"),
    ('S27', 'job_wide errors end the job', HI,
     "    if is_job_wide(error) or out_of_space(error) is not None:\n", "    if out_of_space(error) is not None:\n"),
    ('S28', 'a full disk ends the job', HI,
     "    if is_job_wide(error) or out_of_space(error) is not None:\n", "    if is_job_wide(error):\n"),
    ('S29', 'a busy engine ends the job', HI, "    return isinstance(error, BackupError) and error.code == 'busy'\n", "    return False\n"),
    ('S30', 'an unexpected exception is only its app\'s', HI,
     "    if not isinstance(error, Exception) or isinstance(error, Cancelled):\n", "    if not isinstance(error, BackupError) or isinstance(error, Cancelled):\n"),
    ('S31', 'a cancel ends the job', HI,
     "    if not isinstance(error, Exception) or isinstance(error, Cancelled):\n", "    if not isinstance(error, Exception):\n"),
    ('S32', 'EDQUOT is a full disk too', HI, "error.errno in (errno.ENOSPC, errno.EDQUOT)", "error.errno in (errno.ENOSPC,)"),
    ('S33', 'an unexpected error\'s text stays in the journal', HI,
     "    return [Issue('failure.internal-error', 'stop', UNEXPECTED, action=ACTIONS['internal-error'])]\n",
     "    return [Issue('failure.internal-error', 'stop', str(error), action=ACTIONS['internal-error'])]\n"),
    ('S34', 'the journal text is masked', HI, "    sys.stderr.write(_redact(''.join(traceback.format_exception(error))))\n",
     "    sys.stderr.write(''.join(traceback.format_exception(error)))\n"),
    ('S35', 'an unknown add-on version is no gate (CM-01)', HI, "        found.append(Issue('version.addon-unknown', 'notice',\n",
     "        found.append(Issue('version.addon-unknown', 'stop',\n"),
    ('S36', 'an unreadable version is no gate (CM-02)', HI, "        found.append(Issue('version.target-unknown', 'notice',\n",
     "        found.append(Issue('version.target-unknown', 'stop',\n"),
    ('S37', 'known different versions still stop', HI, "    if upstream is not None and target is not None and semver(upstream) != semver(target):\n", "    if False:\n"),
    ('S38', 'another database does not matter to a conversion', HI,
     "        if self.converting and issue.database is not None and issue.database != self.database:\n            return None\n", ""),
    ('S39', 'only Issue objects get into a sink', HI, "        if not isinstance(issue, Issue):\n            raise TypeError('not an Issue')\n", ""),
    ('S40', 'a wrong level is a programming error', HI, "        if level not in LEVELS:\n", "        if False:\n"),
    ('S41', 'missing confirmations are found', HI,
     "    return [issue for issue in issues if issue.level == 'confirm' and issue.key(app_id) not in keys]\n", "    return []\n"),
    ('S42', 'old text lists are bounded', HI, "            if left < 0 and result:\n                break\n", ""),
    ('S43', 'an error\'s own issues are kept', HI, "    if issues:\n        return issues\n", ""),
    ('S44', 'every issue once', HI, "[issue for issue in extra if not any(issue is known for known in found)]", "list(extra)"),
    ('S45', 'confirmed keys are read strictly', HI, "KEY_RE = re.compile(r'[a-z0-9.-]{4,70}:[0-9a-f]{16}\\Z')", "KEY_RE = re.compile(r'.*')"),
    ('S46', 'a cut sentence says so', HI, "self.text[:MAX_MESSAGE - 1] + '…'", "self.text[:MAX_MESSAGE]"),
    ('S47', 'a long list keeps what can be chosen', HI, "        rows.sort(key=lambda row: row.get('ok') is False)  # stable\n", "        pass\n"),
    # ---------------------------------------------------------------- haimport.py
    ('I01', 'one app\'s failure never stops the others (HA-12)', IM, "            if stops is None:\n                raise\n", "            raise\n"),
    ('I02', 'nothing of an app is left for the next', IM, "    finally:\n        work.reset_app(app)\n    result.update(fields)\n", "    finally:\n        pass\n    result.update(fields)\n"),
    ('I03', 'reset removes the throwaway objects', IM, "                left = tmp.cleanup()\n", "                left = []\n"),
    ('I04', 'reset closes open members', IM, "            with contextlib.suppress(Exception):\n                stream.close()\n", "            pass\n"),
    ('I05', 'reset empties staging', IM, "            names = [name for name in os.listdir(self.staging) if name not in keep]\n", "            names = []\n"),
    ('I06', 'reset keeps what a conversion wrote', IM, "            names = [name for name in os.listdir(self.staging) if name not in keep]\n", "            names = os.listdir(self.staging)\n"),
    ('I07', 'objects that stay are kept for the end', IM, "            if left:\n                self._stale.append(tmp)\n", ""),
    ('I08', 'objects that stay are tried again and recorded', IM, "        for tmp in [*self._temps.values(), *self._stale]:\n            try:\n",
     "        for tmp in self._temps.values():\n            try:\n"),
    ('I72', 'the clean-up at the end never costs the result', IM, "                traceback.print_exc(file=sys.stderr)\n                left.append('?')\n", "                raise\n"),
    ('I73', 'a scope per app once tempctr knows it', IM, "            scope = {'scope': str(self._app[0])} if self._app and getattr(tempctr, 'SCOPES', False) else {}\n", "            scope = {}\n"),
    ('I74', 'every app its own throwaway objects', IM, "        tmp = self._temps.pop(getattr(app, 'owner', None), None)  # the next app gets its own\n", "        tmp = self._temps.get(getattr(app, 'owner', None))\n"),
    ('I75', 'the watchdog kills what an app left', IM, "            for tmp in [*self.work._temps.values(), *getattr(self.work, '_stale', ())]:\n", "            for tmp in list(self.work._temps.values()):\n"),
    ('I09', 'a job that ends hands over what it found', IM, "            ended.result = {'ha_check': _check_view(work, results, shared)}\n", ""),
    ('I10', 'a full disk is told as one', IM, "        ended = haissues.out_of_space(error) or error\n        if started:\n", "        ended = error\n        if started:\n"),
    ('I11', 'apps that were not reached say so', IM, "            for app_id in app_ids[done:]:\n", "            for app_id in []:\n"),
    ('I12', 'a key that opens nothing ends the job', IM, "            raise haissues.job_wide(wrong)\n", "            pass\n"),
    ('I13', 'that end is the whole job\'s', IM, "            raise haissues.job_wide(wrong)\n", "            raise wrong\n"),
    ('I14', 'a missing key ends the job', IM, "        raise haissues.job_wide(hasecuretar.key_required(member=encrypted[0][1].name))\n", "        return {}\n"),
    ('I15', 'one member that does not open stops only its app', IM, "    if all(error is not None for error in tried.values()):\n", "    if any(error is not None for error in tried.values()):\n"),
    ('I16', 'the share folder counts (KEY-16)', IM, "    wanted += [(app_id, share) for app_id in members if share is not None and haapps.get(app_id).needs_share]\n", ""),
    ('I17', '... only for the apps that read it', IM, " if share is not None and haapps.get(app_id).needs_share]\n", " if share is not None]\n"),
    ('I18', 'the chosen add-on is taken (HA-04)', IM, "        if wanted is not None:\n            member = next(", "        if False:\n            member = next("),
    ('I19', 'two add-ons need a choice', IM, "        if len(found) > 1:\n            raise haissues.stopped(Issue('ha.addon-choice', 'stop', ADDON_TWICE,", "        if False:\n            raise haissues.stopped(Issue('ha.addon-choice', 'stop', ADDON_TWICE,"),
    ('I20', 'a choice that is not there is refused', IM, "            if member is None:\n                raise haissues.stopped(Issue('ha.addon-choice', 'stop', ADDON_GONE,", "            if False:\n                raise haissues.stopped(Issue('ha.addon-choice', 'stop', ADDON_GONE,"),
    ('I21', 'an add-on that is not ours is refused (HA-05)', IM, "            if info is None or info.slug != suffix:\n", "            if info is None:\n"),
    ('I22', 'a missing add-on is told (HA-03)', IM, "            raise haissues.stopped(Issue('ha.addon-missing', 'stop', ADDON_MISSING, action=ADDON_MISSING_ACTION),\n                                   'not-found', slug=suffix)\n", "            return None\n"),
    ('I23', 'below the floor the whole job ends', IM, "            raise haissues.job_wide(error) if free < self.floor else error\n", "            raise error\n"),
    ('I24', 'an app\'s own estimate stops only it', IM, "            raise haissues.job_wide(error) if free < self.floor else error\n", "            raise haissues.job_wide(error)\n"),
    ('I25', 'the watchdog ends the whole job', IM, "            self.error = haissues.job_wide(BackupError(\n", "            self.error = (BackupError(\n"),
    ('I26', 'a conversion gets the confirmed keys', IM, "                acknowledged=params.get('acknowledged') or {})\n", "                acknowledged=None)\n"),
    ('I27', 'one app\'s failed conversion reports itself', IM, "        ended.result = {'results': [convert_result(app_ids[0], ended, haissues.combine(found, issues))]}\n", ""),
    ('I28', 'several apps in one job stay as they were', IM, "        if len(app_ids) != 1 or not isinstance(error, Exception) or isinstance(error, Cancelled):\n", "        if not isinstance(error, Exception) or isinstance(error, Cancelled):\n"),
    ('I29', 'a cancel stays a cancel', IM, "        if len(app_ids) != 1 or not isinstance(error, Exception) or isinstance(error, Cancelled):\n", "        if len(app_ids) != 1 or not isinstance(error, Exception):\n"),
    ('I30', 'what a conversion found before it failed is kept', IM, "haissues.combine(found, issues))]}\n", "issues)]}\n"),
    ('I31', 'skipped and failed differ', IM, "        status = 'skipped' if error.issues or error.code in SKIP_CODES else 'failed'\n", "        status = 'failed'\n"),
    ('I32', 'the device key is created (HA-13)', IM, "        device_key = device_key_for(ctx) if encrypt else None\n", "        device_key = ctx.keys.device_key() if encrypt else None\n        if encrypt and device_key is None:\n            raise BackupError('no-device-key', 'x')\n"),
    ('I33', '... only for an encrypted backup', IM, "        device_key = device_key_for(ctx) if encrypt else None\n", "        device_key = device_key_for(ctx)\n"),
    ('I34', '... and journaled', IM, "        ctx.audit(f'device-key-created key_id={key.key_id} reason=ha-import job={ctx.job_id}')\n", ""),
    ('I35', 'a key that cannot be created ends the import', IM, "        raise haissues.job_wide(BackupError('no-device-key', NO_KEY_CREATED)) from error\n", "        return None\n"),
    ('I36', 'database names are checked in the job', IM, "    if 'odoo' in app_ids and database is not None and not valid_database(database):\n", "    if False:\n"),
    ('I37', 'no control characters in a database name', IM, " <= MAX_DATABASE_BYTES and not re.search(r'[\\x00-\\x1f\\x7f-\\x9f]', name)\n", " <= MAX_DATABASE_BYTES\n"),
    ('I38', '63 bytes, not characters', IM, "    return len(data) <= MAX_DATABASE_BYTES and", "    return len(name) <= MAX_DATABASE_BYTES and"),
    ('I39', 'several movable databases: the customer chooses', IM, "    if len(movable) == 1:\n        work.log(", "    if movable:\n        work.log("),
    ('I40', 'the choice\'s reading is removed', IM, "        work.reset_app(app, keep=kept)\n", "        pass\n"),
    ('I41', 'the choice in the request is used', IM, "        database = (choices.get('odoo') or {}).get('database')\n    test_mode", "        database = None\n    test_mode"),
    ('I42', 'the conversion\'s sink knows its database', IM, "                work.database = database\n", ""),
    ('I43', 'registry schema 2 is written', IM, "REGISTRY_SCHEMA = 2 ", "REGISTRY_SCHEMA = 1 "),
    ('I44', 'schema 1 is still read', IM, "REGISTRY_READS = (1, 2) ", "REGISTRY_READS = (2,) "),
    ('I45', 'an unknown schema is not read', IM, "REGISTRY_READS = (1, 2) ", "REGISTRY_READS = (1, 2, 3) "),
    ('I46', 'the registry never outgrows what is read', IM, "        if sum(sizes.values()) <= REGISTRY_MAX_BYTES - 4096:\n", "        if True:\n"),
    ('I47', 'the newest row stays', IM, "        if bid != backup_id:\n            rows.pop(bid)\n", "        if True:\n            rows.pop(bid)\n"),
    ('I48', 'what was confirmed is recorded', IM, "                         'confirmed': [line for app in apps if app.id in sinks for line in sinks[app.id].confirmed()],\n", "                         'confirmed': [],\n"),
    ('I49', 'the import\'s group is recorded', IM, "'group': _group_id(params),\n", "'group': None,\n"),
    ('I50', 'databases that stay on HA are recorded', IM, "(converted.get('odoo') or {}).get('left_databases') or []})\n", "[]})\n"),
    ('I51', 'a row\'s results are checked', IM, "    if not isinstance(row['results'], list) or _clean_results(row['results']) != row['results']:\n        return False\n", ""),
    ('I52', 'a row\'s confirmed lines are checked', IM, "    if not isinstance(row['confirmed'], list) or _clean_confirmed(row['confirmed']) != row['confirmed']:\n        return False\n", ""),
    ('I76', 'only what comes later is changed in a row', IM, "    if not fields or not set(fields) <= set(ROW_LATER):\n", "    if False:\n"),
    ('I77', 'a row that is not there is not made', IM, "        if not rows or backup_id not in rows:\n            return False\n        row = clean_row(", "        rows = rows or {backup_id: {}}\n        row = clean_row("),
    ('I78', 'anything unexpected while opening stops only its app', IM, "            except Exception as error:  # noqa: BLE001 - whatever keeps a member shut", "            except BackupError as error:  # noqa: BLE001 - whatever keeps a member shut"),
    ('I79', 'what ends the job ends it while opening, too', IM, "                if haissues.ends_job(error):\n                    raise\n                tried", "                tried"),
    ('I80', 'a listed add-on without a usable member says why', IM, "                    self.ha.layout.addon(addon['slug'])\n", "                    pass\n"),
    ('I81', 'a backup without a readable date keeps its origin', IM, "            or not (row['date'] is None or util.is_iso_utc(row['date'])):\n", "            or not util.is_iso_utc(row['date']):\n"),
    ('I82', 'a date that is no date is not believed', IM, "            or not (row['date'] is None or util.is_iso_utc(row['date'])):\n", "            or False:\n"),
    ('I83', 'an import that names no date says so', IM, "        when = str(record.get('date') or '日期不明')[:20]", "        when = str(record.get('date') or '')[:20]"),
    ('I84', 'what is no single app\'s is told once', IM, "        if line not in seen:\n", "        if True:\n"),
    ('I85', 'what the apps found that is no single app\'s is told', IM, "    for issue in [*shared, *work.sink(haissues.SHARED).found]:\n", "    for issue in shared:\n"),
    ('S48', 'ten apps fit into one job record', HI, "MAX_TEXT_BYTES = 12 * 1024 ", "MAX_TEXT_BYTES = 64 * 1024 "),
    ('I53', 'confirmed names of a row are bounded', IM, "            if len(name) <= left:\n", "            if True:\n"),
    ('I54', 'the created key is announced in the check', IM, "        if ctx.encrypt_by_default() and ctx.keys.device_key() is None:\n            found.append(", "        if False:\n            found.append("),
    ('I55', '... only when something is encrypted', IM, "        if ctx.encrypt_by_default() and ctx.keys.device_key() is None:\n            found.append(", "        if ctx.keys.device_key() is None:\n            found.append("),
    ('I56', 'a key store that cannot be read does not fail the check', IM, "    with contextlib.suppress(Exception):  # a key store that cannot be read", "    with contextlib.nullcontext():  # a key store that cannot be read"),
    ('I57', 'no section of an unfinished check', IM, "            result.pop(app_id, None)  # no section: the check did not get to its end\n", ""),
    ('I58', 'a cancel between two apps', IM, "            work.checkpoint()\n        work.end_apps()\n        work.phase('check')\n", "        work.end_apps()\n        work.phase('check')\n"),
    ('I59', 'watching an owner never fails the check', IM, "            except Exception:  # noqa: BLE001 - the app's own check reports it", "            except BackupError:  # noqa: BLE001 - the app's own check reports it"),
    ('I60', 'the version is read from the settings (CM-06)', IM, "        if version is None and env:\n", "        if False:\n"),
    ('I61', 'the version is read from the program (CM-06)', IM, "        if version is None and command:\n", "        if False:\n"),
    ('I62', 'only the named settings count', IM, "            if sep and key in names and hacommon.semver(value):\n", "            if sep and hacommon.semver(value):\n"),
    ('I63', 'a program that failed tells nothing', IM, "        return hacommon.semver(match.group(1)) if result.returncode == 0 and match else None\n", "        return hacommon.semver(match.group(1)) if match else None\n"),
    ('I64', 'an image that is not here is not hidden', IM, "            if error.code != 'job-failed':  # an image that is not here", "            if False:  # an image that is not here"),
    ('I65', 'the job\'s end is not hidden by a version', IM, "            if haissues.is_job_wide(error):\n                raise\n            return None\n", "            return None\n"),
    ('I66', 'the program container is removed', IM, "                if tmp.name(role) in tmp.containers:\n                    tmp.remove(role)\n", "                pass\n"),
    ('I67', 'a check collects', IM, "    work = Work(ctx, None, key, staging, phases=CHECK_PHASES, choices=params.get('choices'))\n", "    work = Work(ctx, None, key, staging, phases=CHECK_PHASES)\n"),
    ('I68', 'not-deployed apps stop', IM, "    if issue is not None:\n        raise haissues.stopped(issue, 'not-deployed')\n", ""),
    ('I69', 'not-deployed apps stop in a conversion', IM, "            if issue is not None:\n                raise haissues.stopped(issue, 'not-deployed', app=app.id)\n", ""),
    ('I70', 'the throwaway owners stay in the record while something is left', IM, "        if self._owners and not left:\n", "        if self._owners:\n"),
    ('I71', 'a database in odd characters can be chosen only if valid', IM, "'ok': db.get('ok') is True and valid_database(db['name'])})\n", "'ok': db.get('ok') is True})\n"),
    # ---------------------------------------------------------------- cli.py
    ('C01', 'replacing data needs an explicit yes', CL, "        if data['then_restore'] and data.get('overwrite') is not True:\n", "        if False:\n"),
    ('C02', 'only selected apps are confirmed or chosen for', CL, "            if set(data.get(field) or {}) - set(data['apps']) - also:\n", "            if False:\n"),
    ('C03', 'at most 80 keys', CL, "len(keys) > haissues.MAX_ACKNOWLEDGED\n", "False\n"),
    ('C04', 'keys are well formed', CL, "or not all(haissues.valid_key(key) for key in keys) or", "or"),
    ('C05', 'no key twice', CL, " or len(set(keys)) != len(keys)):\n            raise _bad(field, f'的確認鍵", "):\n            raise _bad(field, f'的確認鍵"),
    ('C06', 'only choices the importer knows', CL, "            if kind not in haapps.get(app_id).choices:\n", "            if False:\n"),
    ('C07', 'a node name is checked', CL, "            elif not isinstance(item, str) or not HA_NODE_RE.fullmatch(item):\n", "            elif False:\n"),
    ('C08', 'an add-on slug is checked', CL, "                if not isinstance(item, str) or not hastore.ADDON_SLUG_RE.fullmatch(item):\n", "                if False:\n"),
    ('C09', 'a database name is checked', CL, "                v_ha_database(item, f'{field}.{app_id}.database')\n", "                pass\n"),
    ('C10', 'a missing add-on only leaves its app out (X-CLI-03)', CL, "    if not present:\n", "    if missing:\n"),
    ('C11', 'nothing of the selection is refused', CL, "    if not present:\n", "    if False:\n"),
    ('C12', 'the share folder is looked at (KEY-16)', CL, "    share = 'share' in rec['folders'] and any(haapps.get(app_id).needs_share for app_id in present)\n", "    share = False\n"),
    ('C13', 'the key is kept for the job (KEY-16)', CL, "        haimport.key_problems(backup, hasecuretar.Keys(key), wanted)\n    return rec, key, present, missing\n", "        haimport.key_problems(backup, hasecuretar.Keys(key), wanted)\n    return rec, None, present, missing\n"),
    ('C14', 'a wrong key is refused before a job starts', CL, "        haimport.key_problems(backup, hasecuretar.Keys(key), wanted)\n", "        pass\n"),
    ('C15', 'a missing key is refused before a job starts', CL, "            raise hasecuretar.key_required(ha_backup_id=rec['id'])\n        haimport", "            return rec, None, present, missing\n        haimport"),
    ('C16', 'an unneeded key is not kept', CL, "        if not any(member.encrypted for _app, member in wanted):\n            return rec, None, present, missing\n", "        if not any(member.encrypted for _app, member in wanted):\n            return rec, key, present, missing\n"),
    ('C17', 'left out apps are in the plan', CL, "'results': skipped}\n", "'results': []}\n"),
    ('C18', 'an app without settings is left out', CL, "        if catalog.get(app_id) is not None:\n            apps.append(app_id)\n            continue\n", "        apps.append(app_id)\n        continue\n"),
    ('C19', 'nothing left to import is refused', CL, "    if not apps:\n        raise refusal\n", ""),
    ('C20', 'the key is created for an import', CL, "    created = ensure_key(svc, 'ha-import') if encrypt else False\n", "    created = False\n"),
    ('C21', '... only when something is encrypted', CL, "    created = ensure_key(svc, 'ha-import') if encrypt else False\n", "    created = ensure_key(svc, 'ha-import')\n"),
    ('C22', 'the key is created for a conversion', CL, "    created = ensure_key(svc, 'ha-convert') if encrypt else False\n", "    created = False\n"),
    ('C23', 'the key is created for a restore (FL-07)', CL, "    created = ensure_key(svc, 'restore') if _needs_safety_key(svc, req['apps']) else False\n", "    created = False\n"),
    ('C24', '... only in place', CL, "            if svc.adapter(catalog.get(app_id)).detect_mode() == 'inplace':\n", "            if svc.adapter(catalog.get(app_id)).detect_mode():\n"),
    ('C25', '... only when encrypted', CL, "    if not svc.encrypt_by_default() or svc.keys.device_key() is not None:\n        return False\n    catalog", "    if svc.keys.device_key() is not None:\n        return False\n    catalog"),
    ('C26', 'a creation is journaled', CL, "        svc.audit(f'device-key-created key_id={info.key_id} reason={reason} loginuid={_login_uid()}')\n", "        pass\n"),
    ('C27', 'a creation that fails is told', CL, "        raise BackupError('no-device-key', '無法自動建立這台的加密金鑰，請到「加密金鑰」建立後再試一次。') from error\n", "        return False\n"),
    ('C28', 'confirmed lines are journaled', CL, "                svc.audit(f'ha-import-confirm", "                str(f'ha-import-confirm"),
    ('C29', 'a retry returns the same group', CL, "        group = known['id']\n", "        pass\n"),
    ('C30', 'a request id of another job is refused', CL, "        if not known.get('id'):\n            raise BackupError('invalid-request', '此請求識別碼已用於其他類型的作業。')\n        group", "        group"),
    ('C31', 'the restore check does not refuse for a missing key (X-PF-03)', CL, "            app_checks.append({'id': f'{app.id}/device-key', 'status': 'warn',", "            app_checks.append({'id': f'{app.id}/device-key', 'status': 'fail',"),
    ('C32', 'the restore check announces the key', CL, "            issues.append(haissues.Issue('restore.device-key', 'auto', RESTORE_KEY_CREATED))\n", ""),
    ('C33', 'a restore needs its confirmed lines', CL, "    confirm_restore(svc, req, header, key_text)\n", ""),
    ('C34', 'restore lines are listed', CL, "        if issues:\n            item['issues'] = haissues.views(app.id, issues)\n", ""),
    ('C35', 'confirmed restore lines are recorded', CL, "    if acknowledged:\n        params['acknowledged'] = acknowledged\n    return dict(svc.start('restore',", "    return dict(svc.start('restore',"),
    ('C36', 'one job of several apps stays strict', CL, "    if missing:\n        raise BackupError('invalid-request', f'這份 HA 備份沒有可以匯入「{missing[0]}」的附加元件。', field='apps',\n                          app=missing[0])\n    created", "    created"),
    ('C37', 'a job gets only its apps\' confirmations', CL, "                    if keys and app_id in (*apps, haissues.SHARED)}\n", "                    if keys}\n"),
    ('C38', 'a job gets only its apps\' choices', CL, "for app_id, values in (choices or {}).items() if values and app_id in apps}\n", "for app_id, values in (choices or {}).items() if values}\n"),
    ('C39', 'choices reach the check job', CL, "    if req.get('choices'):\n        params['choices'] = req['choices']\n    return svc.start('verify'", "    return svc.start('verify'"),
    ('C40', 'the chosen database reaches the first job', CL, "    database = (choices.get(first) or {}).get('database') if first == 'odoo' else None\n", "    database = None\n"),
    ('C42', 'an adapter that cannot be made never refuses a restore', CL, "        with contextlib.suppress(BackupError):\n            adapter = svc.adapter(app)\n", "        with contextlib.nullcontext():\n            adapter = svc.adapter(app)\n"),
    ('C43', 'a restore keeps only its apps\' confirmations', CL, "                    if keys and app_id in req['apps']}\n", "                    if keys}\n"),
    ('C41', 'the install hint is not the page that installs nothing', IM, "NOT_INSTALLED = '這台還沒有「{name}」的應用設定。'", "NOT_INSTALLED = '請先到「應用軟體」安裝「{name}」。'"),
    # ---------------------------------------------------------------- haapps.py, errors.py
    ('H01', 'Nextcloud reads the share folder', HA, "engine_mcp_lines=True, needs_share=True),", "engine_mcp_lines=True),"),
    ('H02', 'only Odoo has databases to choose from', HA, "             choices=('addon', 'database')),", "             choices=('addon',)),"),
    ('H03', 'EMQX nodes can be chosen', HA, "engine_mcp_lines=True, choices=('addon', 'node')),", "engine_mcp_lines=True),"),
    ('E01', 'errors are the app\'s unless they say otherwise', HI, "    return getattr(error, 'job_wide', False) is True\n", "    return True\n"),
    ('E02', 'the confirmation code is known', ER, "'internal-error', 'confirmation-required',\n", "'internal-error',\n"),
    # ---------------------------------------------------------------- second review (2026-11-25 09:5x)
    ('R00', 'a message is masked before it is cut', HI, "        self.text = clean(_redact(message), MAX_TEXT)", "        self.text = clean('' if message is None else message, MAX_TEXT)"),
    ('R01', 'an action is masked before it is cut', HI, "        self.action = clean(_redact(action), MAX_ACTION) if", "        self.action = clean(action, MAX_ACTION) if"),
    ('R02', 'nothing to say is nothing', HI, "    return redact('' if text is None else text)\n", "    return redact(text)\n"),
    ('R03', 'no database at all: not importable', HI,
     "    choices = {kind: list(rows or ()) for kind, rows in (choices or {}).items()}\n", "    choices = {kind: list(rows) for kind, rows in (choices or {}).items() if rows}\n"),
    ('R04', 'empty choices are not sent', HI, "    choices = {kind: rows for kind, rows in choices.items() if rows}\n", ""),
    ('R10', 'the whole result fits into the record', IM, "        if len(_json_bytes(view)) <= CHECK_BYTES:\n            break\n", "        break\n"),
    ('R11', 'what fits stays as it is', IM, "        if len(_json_bytes(view)) <= CHECK_BYTES:\n            break\n", ""),
    ('R12', 'the app with the most to say gives way', IM, "        row = max(view['apps'], key=lambda item: len(_json_bytes(item)))\n", "        row = min(view['apps'], key=lambda item: len(_json_bytes(item)))\n"),
    ('R13', 'the section goes before the result', IM, "        if row.pop(row['app_id'], None) is not None:\n", "        if row.pop(row['app_id'], None) is not None and False:\n"),
    ('R14', 'an app whose result was too large is a stop', IM,
     "        row.update(haissues.check_fields(row['app_id'], [Issue('failure.limit-exceeded', 'stop', TOO_LARGE,\n", "        row.update(haissues.check_fields(row['app_id'], [Issue('failure.limit-exceeded', 'notice', TOO_LARGE,\n"),
    ('R15', 'its choices go with it', IM, "        row.pop('choices', None)\n", ""),
    ('R16', 'one app of an import never ends it because its member does not open', IM,
     "        if grouped and error.code == 'wrong-key':\n            error.job_wide = False\n", ""),
    ('R17', 'a conversion of its own has nothing to go on with', IM, "        if grouped and error.code == 'wrong-key':\n", "        if error.code == 'wrong-key':\n"),
    ('R18', 'a missing key ends the import', IM, "        if grouped and error.code == 'wrong-key':\n", "        if grouped:\n"),
    ('R19', 'only a real group is an import', IM, "grouped=_group_id(params) is not None)", "grouped=params.get('group') is not None)"),
    ('R20', 'the choice collects the shared lines, too', IM, "        names = (app.id, haissues.SHARED)\n", "        names = (app.id,)\n"),
    ('R21', 'what the choice found is not the conversion', IM, "            for name in names:\n                self._sinks.pop(name, None)\n            self._sinks.update(kept)\n", "            pass\n"),
    ('R22', 'issues a module returns count for the choice', IM, "    sink.extend(found.get('issues') or ())\n", ""),
    ('R23', 'what keeps the whole app out counts before the choice', IM, "    if stop is not None:\n        raise haissues.stopped(stop)", "    if False:\n        raise haissues.stopped(stop)"),
    ('R24', 'a stop of one database does not keep the app out', IM, "if issue.level == 'stop' and issue.database is None), None)\n    finally:", "if issue.level == 'stop'), None)\n    finally:"),
    ('R25', 'settings that cannot be used are to be corrected', IM, "        action = SETTINGS_ACTION.format(name=name)\n", "        action = INSTALL_ACTION.format(name=name)\n"),
    ('R26', 'a missing owner is to be created', IM, "        if problem.get('code') == 'owner-missing':\n", "        if False:\n"),
    ('R27', 'a database name never changes how the log reads', IM, "（Odoo 資料庫 {haissues.clean(database, 63)}）", "（Odoo 資料庫 {database}）"),
    ('R28', 'an app that was not checked says what to do', IM, "NOT_CHECKED, action=NOT_CHECKED_ACTION)]", "NOT_CHECKED)]"),
]
CONTROLS = [
    ('K01', 'a changed comment in haissues.py', HI, "# The ids of the shared parts", "# Ids of the shared parts"),
    ('K02', 'a changed comment in haimport.py', IM, "# Keys added after the first rows were written", "# Keys which were added after the first rows were written"),
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
    done = subprocess.run(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=900)
    ran = re.search(r'^Ran (\d+) test', done.stderr, re.M)
    return done.returncode, int(ran.group(1)) if ran else 0, done.stderr[-1500:]


def one(repo, item):
    mid, what, module, old, new = item
    with tempfile.TemporaryDirectory(prefix='f1mut-', dir=os.environ.get('F1MUT_TMP')) as root:
        work = prepare(repo, root)
        path = work / 'backup-engine' / module
        text = path.read_text(encoding='utf-8')
        if text.count(old) != 1:
            return {'id': mid, 'what': what, 'caught': None, 'note': f'text found {text.count(old)} times'}
        path.write_text(text.replace(old, new), encoding='utf-8')
        t0 = time.monotonic()
        rc, ran, tail = run(work, TESTS)
        return {'id': mid, 'what': what, 'module': module, 'caught': rc != 0, 'tests_run': ran,
                'seconds': round(time.monotonic() - t0, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', required=True)
    ap.add_argument('--json')
    ap.add_argument('--only')
    ap.add_argument('--jobs', type=int, default=2)
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    only = set(args.only.split(',')) if args.only else None
    todo = [m for m in MUTATIONS + CONTROLS if only is None or m[0] in only]
    with tempfile.TemporaryDirectory(prefix='f1mut-', dir=os.environ.get('F1MUT_TMP')) as root:
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
        sources = {m: hashlib.sha256((repo / 'backup-engine' / m).read_bytes()).hexdigest() for m in (HI, IM, CL, HA, ER)}
        Path(args.json).write_text(json.dumps({'lane': 'F1-foundation', 'head': head, 'baseline': baseline, 'sources': sources,
                                               'tests': TESTS, 'caught': total - len(missed), 'total': total, 'missed': missed,
                                               'controls_noticed': noisy, 'rows': rows}, ensure_ascii=False, indent=1))
    print(f'mutation check: {"PASS" if ok else "FAIL"} ({total - len(missed)}/{total} caught, missed {missed}, controls noticed {noisy})')
    return 0 if ok else 1


sys.exit(main())
