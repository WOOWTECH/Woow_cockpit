"""Row-level explanation of Odoo differences between a source capture and a later capture (no table exemptions).

Input: two captures validated by odoo_capture.validate() (schema_version 2: every row carries cell hashes and a
small plaintext `safe` projection of non-secret columns). Every row event (added, removed, changed, schema) must match
one rule below or it stays unexplained; a caller passes only when nothing is unexplained.

Rules and their source (Odoo 18.0-20260926 in dev-c's image, /usr/lib/python3/dist-packages/odoo; the engine):
  import-settings  backup-engine/woowbackup/ha_odoo.py settings_sql(): web.base.url, web.base.url.freeze and
                   woow_paas_platform.upgrade_done set to the target device's live values, upgrade_attempt deleted.
  cron-schedule    addons/base/models/ir_cron.py:457-509 (_update_failure_count: raw UPDATE failure_count,
                   first_failure_date, active) and :511-540 (_reschedule_later: raw UPDATE nextcall, lastcall), called
                   from :329-389 (_process_job) for every due job; cron threads poll every 60 s (service/server.py:65).
  cron-progress    ir_cron.py:391-455 (_run_job) creates one ir_cron_progress row per batch through :714-732
                   (_add_progress) and fills it through :734-751 (_notify_progress).
  progress-gc      ir_cron.py:782-784 (_gc_cron_progress): rows older than one week, run by the autovacuum job.
  bus-gc           addons/bus/models/bus.py:95-104 (_gc_messages: DELETE rows older than bus.gc_retention_seconds,
                   default 24 h at bus.py:25), run by addons/base/models/ir_autovacuum.py:25-42 (_run_vacuum_cleaner,
                   the job base.autovacuum_job).
  bus-runtime      addons/bus/models/bus.py:106-140 (_sendone / precommit create): notifications written while Odoo runs.
  signup-reminder  addons/auth_signup/models/res_users.py:248-276 (send_unregistered_user_reminder: internal users
                   created exactly five days ago who never logged in -> template.send_mail(force_send=False)), run by
                   auth_signup/data/ir_cron_data.xml (auth_signup.ir_cron_auth_signup_send_pending_user_reminder);
                   addons/mail/models/mail_template.py:620-660 (send_mail -> mail.mail) and mail/models/mail_mail.py:30
                   (_inherits mail.message), :47 (message_type email_outgoing), :65-71 (state outgoing): one queued
                   mail.mail and its mail.message on res.users, written after the restore by that job.
  mail-queue-failed addons/mail/models/mail_mail.py:218-266 (process_email_queue: every 'outgoing' mail) and
                   :637-649 (ir.mail_server.connect fails -> write state 'exception' and failure_reason), run hourly by
                   mail/data/ir_cron_data.xml (mail.ir_cron_mail_scheduler_action): a mail already queued in the HA
                   backup that the lab cannot send (no network) after the restore. On a host that can reach its mail
                   server the same mail would be sent ('sent', or deleted when auto_delete); that stays unexplained.
A deactivated cron (active changed), a changed progress or bus row, a changed key, any other key, any schema change,
any other mail row and any row in another table stay unexplained. The mail tables are explained only when both
captures hold them row by row (otherwise they are compared as whole tables like every other table).
"""
from datetime import datetime, timedelta, timezone

TABLES = ('public.bus_bus', 'public.ir_config_parameter', 'public.ir_cron', 'public.ir_cron_progress')
MAIL_TABLES = ('public.mail_mail', 'public.mail_message')
SIGNUP_REMINDER = 'auth_signup.ir_cron_auth_signup_send_pending_user_reminder'
MAIL_QUEUE = 'mail.ir_cron_mail_scheduler_action'
MAIL_FAILED_COLUMNS = frozenset({'state', 'failure_reason', 'write_date', 'write_uid'})
SETTINGS_KEYS = ('web.base.url', 'web.base.url.freeze', 'woow_paas_platform.upgrade_done',
                 'woow_paas_platform.upgrade_attempt')
# Keys whose value the capture may show in plain text (none of them is a credential).
PLAIN_KEYS = SETTINGS_KEYS + ('bus.gc_retention_seconds',)
SCHEDULER_COLUMNS = frozenset({'nextcall', 'lastcall', 'failure_count', 'first_failure_date'})
AUTOVACUUM = 'base.autovacuum_job'
BUS_RETENTION = timedelta(hours=24)       # bus.py:25 DEFAULT_GC_RETENTION_SECONDS
PROGRESS_RETENTION = timedelta(weeks=1)   # ir_cron.py:784
RULES = ('import-settings', 'cron-schedule', 'cron-progress', 'progress-gc', 'bus-gc', 'bus-runtime',
         'signup-reminder', 'mail-queue-failed')


def row_tables(source, target):
    """Tables both captures hold row by row: the four core tables, plus the mail tables when both have them."""
    if not set(TABLES) <= set(source) & set(target):
        raise ValueError('core tables missing')
    if set(source) != set(target):
        raise ValueError('captures hold different tables')
    unknown = set(source) - set(TABLES) - set(MAIL_TABLES)
    if unknown or (set(source) & set(MAIL_TABLES) and not set(MAIL_TABLES) <= set(source)):
        raise ValueError('unexpected row tables')
    return tuple(sorted(source))


def ts(value):
    """Naive UTC datetime from a capture value (to_jsonb text of a timestamp without time zone) or None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError('timestamp expected')
    parsed = datetime.fromisoformat(value.replace(' ', 'T'))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _events(source, target):
    out = []
    for table in row_tables(source, target):
        a, b = source[table], target[table]
        if a['schema'] != b['schema']:
            out.append({'table': table, 'id': None, 'kind': 'schema', 'columns': [], 'before': None, 'after': None})
        for ident in sorted(set(a['rows']) | set(b['rows']), key=int):
            x, y = a['rows'].get(ident), b['rows'].get(ident)
            if x is None or y is None:
                out.append({'table': table, 'id': int(ident), 'kind': 'added' if x is None else 'removed',
                            'columns': [], 'before': x and x['safe'], 'after': y and y['safe']})
                continue
            columns = sorted(k for k in set(x['fields']) | set(y['fields'])
                             if x['fields'].get(k) != y['fields'].get(k))
            if columns or x['hash'] != y['hash']:
                out.append({'table': table, 'id': int(ident), 'kind': 'changed', 'columns': columns,
                            'before': x['safe'], 'after': y['safe']})
    return out


def _settings(event, live):
    """import-settings: the change settings_sql() makes for this key, given the device's live values."""
    before, after = event['before'] or {}, event['after'] or {}
    key = (after if event['kind'] == 'added' else before).get('key')
    if event['kind'] == 'changed' and after.get('key') != key:
        return None, 'key changed'
    if key not in SETTINGS_KEYS:
        return None, 'key outside the import settings'
    if key == 'woow_paas_platform.upgrade_attempt':
        return ('import-settings', key) if event['kind'] == 'removed' else (None, 'attempt marker must be removed')
    wanted = live.get(key)
    if wanted is None:
        return ('import-settings', key) if event['kind'] == 'removed' else (None, 'device has no value: row must go')
    if event['kind'] == 'removed':
        return None, 'device has a value: row must stay'
    if event['kind'] == 'changed' and not set(event['columns']) <= {'value', 'write_date'}:
        return None, 'columns beyond value and write_date'
    if after.get('value') != wanted:
        return None, 'value is not the device value'
    return 'import-settings', key


def explain(source, target, *, rules, restore_start=None, captured_at=None, live=None, cron_log_ids=None):
    """Classify every row event between two validated captures.

    rules: subset of {'import', 'runtime'} allowed for this pair of captures.
    restore_start / captured_at: naive UTC datetimes (runtime rules need both).
    live: the target device's own values {'web.base.url': str|None, 'web.base.url.freeze': str|None,
          'woow_paas_platform.upgrade_done': str} (import rules need it).
    cron_log_ids: ids of ir.cron jobs the Odoo log shows starting after restore_start, or None when unknown;
          a scheduler change is explained only when the log shows that job ran.
    """
    rules = set(rules)
    if not rules <= {'import', 'runtime'}:
        raise ValueError('unknown rule set')
    if 'runtime' in rules and (restore_start is None or captured_at is None):
        raise ValueError('runtime rules need restore_start and captured_at')
    if 'import' in rules and live is None:
        raise ValueError('import rules need the live values')
    events = _events(source, target)
    by_table = {t: [e for e in events if e['table'] == t] for t in TABLES + MAIL_TABLES}
    logged = set(cron_log_ids or ())
    ran = set()
    target_crons = target['public.ir_cron']['rows']
    autovacuum_ids = {int(i) for i, r in target_crons.items() if r['safe'].get('xmlid') == AUTOVACUUM}

    def mark(event, rule, why):
        event['rule'], event['why'], event['explained'] = rule, why, rule is not None

    for event in by_table['public.ir_cron']:
        if event['kind'] != 'changed' or 'runtime' not in rules:
            mark(event, None, 'only scheduler updates of existing jobs are explained')
            continue
        cols, before, after = set(event['columns']), event['before'] or {}, event['after'] or {}
        last = ts(after.get('lastcall'))
        if not cols <= SCHEDULER_COLUMNS:
            mark(event, None, 'columns beyond the scheduler columns: ' + ', '.join(sorted(cols - SCHEDULER_COLUMNS)))
        elif before.get('xmlid') != after.get('xmlid') or after.get('active') is not True:
            mark(event, None, 'job identity or active flag differs')
        elif 'lastcall' in cols and not (last and restore_start <= last <= captured_at):
            mark(event, None, 'lastcall not between the restore and the capture')
        elif 'nextcall' in cols and not (ts(after.get('nextcall')) and last and ts(after.get('nextcall')) > last):
            mark(event, None, 'nextcall not rescheduled after lastcall')
        elif event['id'] not in logged:
            mark(event, None, 'the Odoo log does not show this job running after the restore')
        else:
            mark(event, 'cron-schedule', 'job ran after the restore')
            ran.add(event['id'])
    ran |= logged & {int(i) for i in target_crons}
    autovacuum_ran = bool(autovacuum_ids & ran)
    retention = None
    for caps in (source, target):
        for row in caps['public.ir_config_parameter']['rows'].values():
            if row['safe'].get('key') == 'bus.gc_retention_seconds':
                retention = 'set'
    for event in by_table['public.ir_cron_progress']:
        before, after = event['before'] or {}, event['after'] or {}
        if 'runtime' not in rules:
            mark(event, None, 'no runtime between these captures')
        elif event['kind'] == 'added':
            created = ts(after.get('create_date'))
            ok = created and restore_start <= created <= captured_at and after.get('cron_id') in ran
            mark(event, 'cron-progress' if ok else None, 'progress of a job that ran after the restore' if ok
                 else 'progress row not created by a job run after the restore')
        elif event['kind'] == 'removed':
            created = ts(before.get('create_date'))
            ok = autovacuum_ran and created and created < captured_at - PROGRESS_RETENTION
            mark(event, 'progress-gc' if ok else None, 'older than one week, autovacuum ran' if ok
                 else 'removed without the one-week autovacuum condition')
        else:
            mark(event, None, 'existing progress rows must not change')
    for event in by_table['public.bus_bus']:
        before, after = event['before'] or {}, event['after'] or {}
        if 'runtime' not in rules:
            mark(event, None, 'no runtime between these captures')
        elif event['kind'] == 'removed':
            created = ts(before.get('create_date'))
            ok = retention is None and autovacuum_ran and created and created < captured_at - BUS_RETENTION
            mark(event, 'bus-gc' if ok else None, 'older than 24 h, autovacuum ran' if ok
                 else 'removed without the 24 h autovacuum condition')
        elif event['kind'] == 'added':
            created = ts(after.get('create_date'))
            ok = created and restore_start <= created <= captured_at
            mark(event, 'bus-runtime' if ok else None, 'notification written after the restore' if ok
                 else 'bus row not written after the restore')
        else:
            mark(event, None, 'bus rows must not change')
    if 'runtime' in rules and autovacuum_ran:
        # _gc_messages deletes every row older than the retention: none of those may survive the run.
        for ident, row in target['public.bus_bus']['rows'].items():
            created = ts(row['safe'].get('create_date'))
            if created and created < restore_start - BUS_RETENTION:
                events.append({'table': 'public.bus_bus', 'id': int(ident), 'kind': 'kept',
                               'columns': [], 'before': None, 'after': row['safe'], 'rule': None, 'explained': False,
                               'why': 'old notification survived an autovacuum run'})
    def job_ran(xmlid):
        return any(target_crons[str(i)]['safe'].get('xmlid') == xmlid for i in ran if str(i) in target_crons)
    reminder_ran, queue_ran = job_ran(SIGNUP_REMINDER), job_ran(MAIL_QUEUE)
    reminders = set()
    for event in by_table['public.mail_message']:
        after = event['after'] or {}
        created = ts(after.get('create_date')) if event['kind'] == 'added' else None
        ok = ('runtime' in rules and reminder_ran and created and restore_start <= created <= captured_at
              and after.get('model') == 'res.users' and after.get('message_type') == 'email_outgoing')
        if ok:
            reminders.add(event['id'])
        mark(event, 'signup-reminder' if ok else None, 'reminder message written by the signup reminder job' if ok
             else 'mail message not written by the signup reminder job after the restore')
    for event in by_table['public.mail_mail']:
        before, after = event['before'] or {}, event['after'] or {}
        if event['kind'] == 'changed':
            written = ts(after.get('write_date'))
            ok = ('runtime' in rules and queue_ran and set(event['columns']) <= MAIL_FAILED_COLUMNS
                  and 'state' in event['columns'] and before.get('state') == 'outgoing'
                  and after.get('state') == 'exception' and written and restore_start <= written <= captured_at
                  and before.get('mail_message_id') == after.get('mail_message_id'))
            mark(event, 'mail-queue-failed' if ok else None, 'queued mail the lab could not send' if ok
                 else 'mail changed other than a failed send of a queued mail after the restore')
            continue
        created = ts(after.get('create_date')) if event['kind'] == 'added' else None
        ok = ('runtime' in rules and created and restore_start <= created <= captured_at
              and after.get('mail_message_id') in reminders and after.get('state') == 'outgoing')
        mark(event, 'signup-reminder' if ok else None, 'queued reminder mail of that message' if ok
             else 'mail not a queued reminder of an explained message')
    for event in by_table['public.ir_config_parameter']:
        if 'import' not in rules:
            mark(event, None, 'no import between these captures')
            continue
        rule, why = _settings(event, live)
        mark(event, rule, why)
    for event in events:
        if event['kind'] == 'schema':
            mark(event, None, 'schema differs')
    return events


def public_event(event):
    """Evidence form: ids, columns, rule and non-secret projected values only (no cell hashes, no masked values)."""
    out = {k: event[k] for k in ('table', 'id', 'kind', 'columns', 'rule', 'explained', 'why')}
    keep = {'public.ir_config_parameter': ('key', 'value', 'write_date'),
            'public.ir_cron': ('xmlid', 'cron_name', 'nextcall', 'lastcall', 'failure_count', 'first_failure_date'),
            'public.ir_cron_progress': ('cron_id', 'create_date', 'done', 'remaining', 'timed_out_counter'),
            'public.bus_bus': ('create_date',),
            'public.mail_message': ('model', 'res_id', 'message_type', 'create_date'),
            'public.mail_mail': ('mail_message_id', 'state', 'create_date', 'write_date')}.get(event['table'], ())
    for side in ('before', 'after'):
        values = event.get(side) or {}
        shown = {k: values.get(k) for k in keep if k in values}
        if event['table'] == 'public.ir_config_parameter' and values.get('key') not in PLAIN_KEYS:
            shown.pop('value', None)
        out[side] = shown or None
    return out


def summary(events):
    tables = {}
    for event in events:
        row = tables.setdefault(event['table'], {'events': 0, 'explained': 0, 'by_rule': {}, 'by_kind': {}})
        row['events'] += 1
        row['explained'] += bool(event['explained'])
        row['by_kind'][event['kind']] = row['by_kind'].get(event['kind'], 0) + 1
        rule = event['rule'] or 'UNEXPLAINED'
        row['by_rule'][rule] = row['by_rule'].get(rule, 0) + 1
    return {'events': len(events), 'unexplained': sum(not e['explained'] for e in events), 'tables': tables}
