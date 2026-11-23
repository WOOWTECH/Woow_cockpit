"""odoo_explain: every row event needs a rule; synthetic captures only (no lab, no real values)."""
from datetime import datetime, timedelta
import copy
import hashlib
import json
import unittest

import odoo_explain as x

RESTORE = datetime(2026, 11, 23, 2, 0, 0)
CAPTURED = datetime(2026, 11, 23, 2, 5, 0)
LIVE = {'web.base.url': 'http://localhost:8069', 'web.base.url.freeze': None,
        'woow_paas_platform.upgrade_done': '{"digest":"sha256:feed"}'}
OLD = '2026-11-19T01:00:00'


def h(value):
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


def row(**cols):
    safe = dict(cols)
    return {'hash': h(cols), 'fields': {k: h(v) for k, v in cols.items()}, 'safe': safe}


def table(*rows):
    schema = {k: {'position': i + 1} for i, k in enumerate(rows[0]['fields'])} if rows else {'id': {'position': 1}}
    return {'schema': schema, 'rows': {str(r['safe']['id']): r for r in rows}, 'count': len(rows)}


def cfg(i, key, value, write=OLD):
    return row(id=i, key=key, value=value, create_date=OLD, write_date=write)


def cron(i, xmlid, nextcall, lastcall, active=True, failure_count=0, interval_number=1):
    return row(id=i, xmlid=xmlid, cron_name=xmlid, active=active, interval_number=interval_number,
               interval_type='days', nextcall=nextcall, lastcall=lastcall, failure_count=failure_count,
               first_failure_date=None, write_date=OLD)


def progress(i, cron_id, created):
    return row(id=i, cron_id=cron_id, done=0, remaining=0, deactivate=None, timed_out_counter=0,
               create_date=created, write_date=created)


def bus(i, created):
    return row(id=i, create_date=created)


def source():
    return {'public.ir_config_parameter': table(cfg(4, 'web.base.url', 'http://192.0.2.34:8069'),
                                                cfg(11, 'web.base.url.freeze', 'True'),
                                                cfg(12, 'database.secret', 'SYNTHETIC-NOT-A-SECRET'),
                                                cfg(13, 'woow_paas_platform.upgrade_attempt', '1')),
            'public.ir_cron': table(cron(1, 'base.autovacuum_job', '2026-11-20T01:00:00', '2026-11-19T01:00:00'),
                                    cron(2, 'base.ir_cron_portal_deletion', '2026-11-20T01:00:00', None),
                                    cron(3, 'mail.ir_cron_later', '2026-12-01T01:00:00', None)),
            'public.ir_cron_progress': table(progress(7, 1, '2026-11-19T01:00:00'),
                                             progress(8, 2, '2026-11-10T01:00:00')),
            'public.bus_bus': table(bus(20, '2026-11-19T00:00:00'), bus(21, '2026-11-19T00:30:00'))}


def ran(caps, cron_id, last='2026-11-23T02:01:05', nxt='2026-11-24T01:00:00'):
    current = caps['public.ir_cron']['rows'][str(cron_id)]['safe']
    caps['public.ir_cron']['rows'][str(cron_id)] = cron(cron_id, current['xmlid'], nxt, last)


def imported(caps):
    """What settings_sql() does with LIVE: base url set, freeze and attempt deleted, marker added."""
    rows = caps['public.ir_config_parameter']['rows']
    rows['4'] = cfg(4, 'web.base.url', LIVE['web.base.url'], write='2026-11-23T01:50:00')
    del rows['11'], rows['13']
    rows['50'] = cfg(50, 'woow_paas_platform.upgrade_done', LIVE['woow_paas_platform.upgrade_done'],
                     write='2026-11-23T01:50:00')


def runtime(caps):
    """Odoo started: autovacuum and the portal job ran, two progress rows, old bus rows collected."""
    ran(caps, 1)
    ran(caps, 2)
    caps['public.ir_cron_progress']['rows']['9'] = progress(9, 1, '2026-11-23T02:01:01')
    caps['public.ir_cron_progress']['rows']['10'] = progress(10, 2, '2026-11-23T02:01:02')
    caps['public.bus_bus']['rows'].clear()


def explain(src, dst, rules=('import', 'runtime'), log=(), live=LIVE):
    return x.explain(src, dst, rules=rules, restore_start=RESTORE, captured_at=CAPTURED, live=live,
                     cron_log_ids=list(log))


def unexplained(events):
    return [(e['table'], e['id'], e['kind'], e['why']) for e in events if not e['explained']]


class ExplainTests(unittest.TestCase):
    def test_identical_has_no_events(self):
        self.assertEqual(explain(source(), source()), [])

    def test_import_and_runtime_rows_all_explained(self):
        dst = source()
        imported(dst)
        runtime(dst)
        events = explain(source(), dst, log=(1, 2))
        self.assertEqual(unexplained(events), [])
        rules = sorted({e['rule'] for e in events})
        self.assertEqual(rules, ['bus-gc', 'cron-progress', 'cron-schedule', 'import-settings'])
        self.assertEqual(x.summary(events)['unexplained'], 0)

    def test_import_rows_need_import_rules(self):
        dst = source()
        imported(dst)
        events = explain(source(), dst, rules=('runtime',))
        self.assertEqual(len(unexplained(events)), 4)

    def test_runtime_rows_need_runtime_rules(self):
        dst = source()
        runtime(dst)
        self.assertTrue(unexplained(explain(source(), dst, rules=('import',), log=(1, 2))))
        self.assertTrue(unexplained(explain(source(), dst, rules=(), log=(1, 2))))

    def test_settings_value_must_be_the_device_value(self):
        dst = source()
        imported(dst)
        dst['public.ir_config_parameter']['rows']['4'] = cfg(4, 'web.base.url', 'http://198.51.100.7:8069')
        self.assertEqual([u[1] for u in unexplained(explain(source(), dst))], [4])
        dst = source()
        imported(dst)
        dst['public.ir_config_parameter']['rows']['50'] = cfg(50, 'woow_paas_platform.upgrade_done', '{}')
        self.assertEqual([u[1] for u in unexplained(explain(source(), dst))], [50])

    def test_freeze_removal_needs_a_device_without_freeze(self):
        dst = source()
        imported(dst)
        live = dict(LIVE, **{'web.base.url.freeze': 'True'})
        self.assertIn(11, [u[1] for u in unexplained(explain(source(), dst, live=live))])

    def test_other_keys_and_key_renames_stay_unexplained(self):
        dst = source()
        dst['public.ir_config_parameter']['rows']['12'] = cfg(12, 'database.secret', 'SYNTHETIC-OTHER')
        self.assertEqual([u[1] for u in unexplained(explain(source(), dst))], [12])
        dst = source()
        dst['public.ir_config_parameter']['rows']['4'] = cfg(4, 'web.base.url.other', LIVE['web.base.url'])
        self.assertEqual([u[1] for u in unexplained(explain(source(), dst))], [4])
        dst = source()
        dst['public.ir_config_parameter']['rows']['60'] = cfg(60, 'web.base.url', LIVE['web.base.url'])
        dst['public.ir_config_parameter']['rows']['61'] = cfg(61, 'mail.catchall.domain', 'example.invalid')
        self.assertEqual(sorted(u[1] for u in unexplained(explain(source(), dst))), [61])

    def test_cron_changes_need_log_time_and_scheduler_columns(self):
        dst = source()
        ran(dst, 2)
        self.assertEqual(unexplained(explain(source(), dst, log=(2,))), [])
        self.assertTrue(unexplained(explain(source(), dst, log=())))
        before = source()
        ran(before, 2, last='2026-11-23T01:59:59')
        self.assertTrue(unexplained(explain(source(), before, log=(2,))))
        late = source()
        ran(late, 2, nxt='2026-11-23T02:00:30')
        self.assertTrue(unexplained(explain(source(), late, log=(2,))))
        for change in ({'active': False}, {'interval_number': 7}):
            dst = source()
            current = dict(dst['public.ir_cron']['rows']['2']['safe'])
            current.update(change, nextcall='2026-11-24T01:00:00', lastcall='2026-11-23T02:01:05')
            dst['public.ir_cron']['rows']['2'] = row(**current)
            self.assertTrue(unexplained(explain(source(), dst, log=(2,))), change)

    def test_cron_rows_never_added_or_removed(self):
        dst = source()
        dst['public.ir_cron']['rows']['4'] = cron(4, 'x.new', '2026-11-24T01:00:00', None)
        self.assertTrue(unexplained(explain(source(), dst, log=(4,))))
        dst = source()
        del dst['public.ir_cron']['rows']['3']
        self.assertTrue(unexplained(explain(source(), dst, log=())))

    def test_progress_rows(self):
        dst = source()
        dst['public.ir_cron_progress']['rows']['9'] = progress(9, 3, '2026-11-23T02:01:01')
        self.assertTrue(unexplained(explain(source(), dst, log=())), 'job 3 did not run')
        self.assertEqual(unexplained(explain(source(), dst, log=(3,))), [])
        dst = source()
        dst['public.ir_cron_progress']['rows']['9'] = progress(9, 3, '2026-11-23T01:59:00')
        self.assertTrue(unexplained(explain(source(), dst, log=(3,))), 'created before the restore')
        dst = source()
        dst['public.ir_cron_progress']['rows']['7'] = progress(7, 1, '2026-11-19T01:00:01')
        self.assertTrue(unexplained(explain(source(), dst)), 'existing progress changed')

    def test_progress_gc_only_after_a_week_with_autovacuum(self):
        dst = source()
        ran(dst, 1)
        dst['public.bus_bus']['rows'].clear()             # the same autovacuum run collects the old bus rows
        del dst['public.ir_cron_progress']['rows']['8']   # created 2026-11-10: older than one week
        self.assertEqual(unexplained(explain(source(), dst, log=(1,))), [])
        dst = source()
        ran(dst, 1)
        dst['public.bus_bus']['rows'].clear()
        del dst['public.ir_cron_progress']['rows']['7']   # created 2026-11-19: younger than one week
        self.assertTrue(unexplained(explain(source(), dst, log=(1,))))
        dst = source()
        del dst['public.ir_cron_progress']['rows']['8']
        self.assertTrue(unexplained(explain(source(), dst, log=())), 'autovacuum did not run')

    def test_bus_rows(self):
        dst = source()
        ran(dst, 1)
        dst['public.bus_bus']['rows'].clear()
        self.assertEqual(unexplained(explain(source(), dst, log=(1,))), [])
        dst = source()
        dst['public.bus_bus']['rows'].clear()
        self.assertTrue(unexplained(explain(source(), dst, log=())), 'autovacuum did not run')
        dst = source()
        ran(dst, 1)
        del dst['public.bus_bus']['rows']['20']   # 21 is as old: _gc_messages would have deleted it too
        self.assertEqual([u[2] for u in unexplained(explain(source(), dst, log=(1,)))], ['kept'])
        dst = source()
        dst['public.bus_bus']['rows']['30'] = bus(30, '2026-11-23T02:02:00')
        self.assertEqual(unexplained(explain(source(), dst, log=())), [])
        dst['public.bus_bus']['rows']['31'] = bus(31, '2026-11-23T01:00:00')
        self.assertEqual([u[1] for u in unexplained(explain(source(), dst, log=()))], [31])
        dst = source()
        dst['public.bus_bus']['rows']['20'] = bus(20, '2026-11-19T00:00:01')
        self.assertTrue(unexplained(explain(source(), dst, log=())), 'bus rows never change')

    def test_custom_bus_retention_is_not_assumed(self):
        src = source()
        src['public.ir_config_parameter']['rows']['70'] = cfg(70, 'bus.gc_retention_seconds', '60')
        dst = copy.deepcopy(src)
        ran(dst, 1)
        dst['public.bus_bus']['rows'].clear()
        self.assertTrue(unexplained(explain(src, dst, log=(1,))))

    def with_mail(self, caps):
        caps = copy.deepcopy(caps)
        caps['public.mail_message'] = table(row(id=1, model='res.partner', res_id=3, message_type='comment',
                                                create_date=OLD, write_date=OLD))
        caps['public.mail_mail'] = table(row(id=1, mail_message_id=1, state='sent', create_date=OLD, write_date=OLD))
        caps['public.ir_cron']['rows']['12'] = cron(12, x.SIGNUP_REMINDER, '2026-11-20T01:00:00', None)
        return caps

    def reminder(self, caps, created='2026-11-23T02:01:10', model='res.users', state='outgoing', kind='email_outgoing'):
        caps['public.mail_message']['rows']['2'] = row(id=2, model=model, res_id=2, message_type=kind,
                                                       create_date=created, write_date=created)
        caps['public.mail_mail']['rows']['2'] = row(id=2, mail_message_id=2, state=state, create_date=created,
                                                    write_date=created)

    def test_signup_reminder_mail_explained(self):
        src = self.with_mail(source())
        dst = copy.deepcopy(src)
        ran(dst, 12)
        dst['public.ir_cron_progress']['rows']['9'] = progress(9, 12, '2026-11-23T02:01:09')
        self.reminder(dst)
        events = explain(src, dst, log=(12,))
        self.assertEqual(unexplained(events), [])
        self.assertEqual(sorted(e['rule'] for e in events if e['table'].startswith('public.mail')),
                         ['signup-reminder', 'signup-reminder'])

    def test_other_mail_rows_stay_unexplained(self):
        src = self.with_mail(source())
        for change in ({'model': 'res.partner'}, {'state': 'sent'}, {'kind': 'comment'},
                       {'created': '2026-11-23T01:00:00'}):
            with self.subTest(change=change):
                dst = copy.deepcopy(src)
                ran(dst, 12)
                self.reminder(dst, **change)
                self.assertTrue(unexplained(explain(src, dst, log=(12,))))
        dst = copy.deepcopy(src)
        self.reminder(dst)
        self.assertTrue(unexplained(explain(src, dst, log=())), 'the reminder job did not run')
        dst = copy.deepcopy(src)
        dst['public.mail_mail']['rows']['1'] = row(id=1, mail_message_id=1, state='exception', create_date=OLD,
                                                  write_date='2026-11-23T02:01:00')
        self.assertTrue(unexplained(explain(src, dst, log=(12,))), 'existing mail rows never change')
        dst = copy.deepcopy(src)
        del dst['public.mail_message']['rows']['1']
        self.assertTrue(unexplained(explain(src, dst, log=(12,))), 'mail rows never disappear')

    def queue(self, caps, before='outgoing', after='exception', written='2026-11-23T02:01:20', cols=None):
        caps['public.mail_mail']['rows']['1'] = row(id=1, mail_message_id=1, state=before, create_date=OLD,
                                                    write_date=OLD)
        changed = row(id=1, mail_message_id=1, state=after, create_date=OLD, write_date=written)
        for name in cols or ('failure_reason',):
            changed['fields'][name] = 'f' * 64
        return changed

    def test_failed_send_of_a_queued_mail_explained(self):
        src = self.with_mail(source())
        changed = self.queue(src)
        dst = copy.deepcopy(src)
        dst['public.ir_cron']['rows']['3'] = cron(3, x.MAIL_QUEUE, '2026-11-23T03:01:00', '2026-11-23T02:01:21')
        src['public.ir_cron']['rows']['3'] = cron(3, x.MAIL_QUEUE, '2026-11-19T01:59:22', '2026-11-19T01:00:51')
        dst['public.mail_mail']['rows']['1'] = changed
        self.assertEqual(unexplained(explain(src, dst, log=(3,))), [])
        self.assertTrue(unexplained(explain(src, dst, log=())), 'the queue job did not run')

    def test_other_mail_changes_stay_unexplained(self):
        cases = (dict(before='exception'), dict(after='sent'), dict(written='2026-11-23T01:00:00'),
                 dict(cols=('body_html',)))
        for case in cases:
            with self.subTest(case=case):
                src = self.with_mail(source())
                changed = self.queue(src, **case)
                src['public.ir_cron']['rows']['3'] = cron(3, x.MAIL_QUEUE, '2026-11-19T01:59:22', None)
                dst = copy.deepcopy(src)
                ran(dst, 3)
                dst['public.mail_mail']['rows']['1'] = changed
                self.assertTrue(unexplained(explain(src, dst, log=(3,))))

    def test_row_tables_must_match(self):
        src = self.with_mail(source())
        with self.assertRaises(ValueError):
            explain(src, source())
        half = copy.deepcopy(src)
        del half['public.mail_mail']
        with self.assertRaises(ValueError):
            explain(half, half)
        self.assertEqual(x.row_tables(src, src), tuple(sorted(src)))

    def test_schema_change_never_explained(self):
        dst = source()
        dst['public.bus_bus']['schema'] = dict(dst['public.bus_bus']['schema'], extra={'position': 9})
        self.assertEqual([u[2] for u in unexplained(explain(source(), dst))], ['schema'])

    def test_arguments_fail_closed(self):
        with self.assertRaises(ValueError):
            x.explain(source(), source(), rules=('runtime',), live=LIVE)
        with self.assertRaises(ValueError):
            x.explain(source(), source(), rules=('import',), restore_start=RESTORE, captured_at=CAPTURED)
        with self.assertRaises(ValueError):
            x.explain(source(), source(), rules=('everything',), live=LIVE)

    def test_public_event_masks_other_values_and_has_no_hashes(self):
        dst = source()
        dst['public.ir_config_parameter']['rows']['12'] = cfg(12, 'database.secret', 'SYNTHETIC-OTHER')
        imported(dst)
        text = json.dumps([x.public_event(e) for e in explain(source(), dst)])
        self.assertNotIn('SYNTHETIC', text)
        self.assertNotIn(h('SYNTHETIC-OTHER'), text)
        self.assertIn('database.secret', text)
        self.assertIn(LIVE['web.base.url'], text)

    def test_timestamps(self):
        self.assertEqual(x.ts('2026-11-23T02:00:00+08:00'), datetime(2026, 11, 22, 18, 0, 0))
        self.assertEqual(x.ts('2026-11-23 02:00:00.5'), RESTORE + timedelta(microseconds=500000))
        self.assertIsNone(x.ts(None))
        with self.assertRaises(ValueError):
            x.ts(5)


if __name__ == '__main__':
    unittest.main()
