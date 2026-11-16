"""排程備份 (scheduled backups, CONTRACT sections 3, 7, 8): settings and their validation, slots in Asia/Taipei and
America/New_York (DST gaps and overlaps), every tick decision (on time, late, catch-up, boot settling, busy,
superseded, dedup, disabled, bad file, clock back, time zone change, armed_at), the registry written before the backup,
partial runs, the two retention pools, the frozen 2026.11.15.2 format lists, the strict new commands and the status
shapes.

The tick runs through the helper (`cli.main(['schedule-tick'])`) with the fakes of test_flows and a fixed clock; jobs
are real JobStore records and the started job runs with `run-job` like on a device.
"""
import contextlib
import dataclasses
import datetime
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from zoneinfo import ZoneInfo

from woowbackup import archive, cli, flows, jobs, retention, schedule, settings, storage
from woowbackup.errors import BackupError
from woowbackup.paths import Paths

from .test_cli import ExplodingStdin
from .test_flows import FakeArchive, FakeKeys, FakeReporter, FakeStorage, HOST, World, make_catalog

UTC = datetime.timezone.utc
TAIPEI = ZoneInfo('Asia/Taipei')
NEW_YORK = ZoneInfo('America/New_York')
DAY = datetime.timedelta(days=1)


def at(text):
    return datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=UTC)


def env_at(text, zone=TAIPEI, uptime=86400.0, name=None):
    return schedule.Env(now=at(text), zone=zone, zone_name=name or str(zone), uptime=uptime)


def on(**fields):
    """Saved settings (as schedule.load returns them): on, every day at 03:00, armed long before."""
    base = schedule.defaults()
    base.update(enabled=True, armed_at='2026-11-01T00:00:00Z', updated='2026-11-01T00:00:00Z')
    base.update(fields)
    return base


def state(**fields):
    base = schedule.empty_state()
    base.update(fields)
    return base


# Slots of the default schedule in Taipei (UTC+8): 03:00 local is 19:00 UTC the day before.
SLOT = '2026-11-16T19:00:00Z'       # 2026-11-17 03:00 Taipei
PREVIOUS = '2026-11-15T19:00:00Z'   # 2026-11-16 03:00 Taipei
NEXT = '2026-11-17T19:00:00Z'       # 2026-11-18 03:00 Taipei


# ---------------------------------------------------------------- settings

class SettingsTests(unittest.TestCase):
    GOOD = {'enabled': True, 'days': ['sun', 'mon'], 'time': '03:05', 'apps': ['woowbk-demo'], 'include_images': False,
            'keep_last': 7}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(base=Path(self.tmp.name))
        os.makedirs(self.paths.config, mode=0o755)
        os.chmod(self.paths.config, 0o755)
        self.uid = os.getuid()
        self.file = Path(self.paths.config) / schedule.FILE

    def test_validation_normalizes_and_names_the_field(self):
        normalized = schedule.validate(self.GOOD)
        self.assertEqual(normalized['days'], ['mon', 'sun'], 'stored in week order')
        self.assertEqual(schedule.validate(dict(self.GOOD, apps='all', keep_last=None))['apps'], 'all')
        bad = {
            'schedule': [None, [], 'x', dict(self.GOOD, extra=1), dict(self.GOOD, updated='2026-11-01T00:00:00Z')],
            'schedule.enabled': [{k: v for k, v in self.GOOD.items() if k != 'enabled'}, dict(self.GOOD, enabled='yes'),
                                 dict(self.GOOD, enabled=1)],
            'schedule.days': [dict(self.GOOD, days=[]), dict(self.GOOD, days=['mon', 'mon']),
                              dict(self.GOOD, days=['monday']), dict(self.GOOD, days='mon'),
                              dict(self.GOOD, days=list(schedule.DAYS) + ['mon'])],
            'schedule.time': [dict(self.GOOD, time='3:00'), dict(self.GOOD, time='24:00'),
                              dict(self.GOOD, time='03:07'), dict(self.GOOD, time=300), dict(self.GOOD, time='03:00 ')],
            'schedule.apps': [dict(self.GOOD, apps=[]), dict(self.GOOD, apps='some'), dict(self.GOOD, apps=['Bad Id']),
                              dict(self.GOOD, apps=['woowbk-demo', 'woowbk-demo']),
                              dict(self.GOOD, apps=[f'app-{n}' for n in range(schedule.MAX_APPS + 1)])],
            'schedule.include_images': [dict(self.GOOD, include_images=None)],
            'schedule.keep_last': [dict(self.GOOD, keep_last=0), dict(self.GOOD, keep_last=1001),
                                   dict(self.GOOD, keep_last=True), dict(self.GOOD, keep_last='7')],
        }
        for field, values in bad.items():
            for value in values:
                with self.subTest(field=field, value=str(value)[:80]):
                    with self.assertRaises(BackupError) as caught:
                        schedule.validate(value)
                    self.assertEqual(caught.exception.code, 'invalid-request')
                    self.assertEqual(caught.exception.details['field'], field)

    def test_missing_file_is_off_with_the_defaults(self):
        settings_, problem, saved = schedule.load(self.paths, trusted_uid=self.uid)
        self.assertEqual((problem, saved), (None, False))
        self.assertEqual(settings_, {'enabled': False, 'days': list(schedule.DAYS), 'time': '03:00', 'apps': 'all',
                                     'include_images': False, 'keep_last': 7, 'updated': None, 'armed_at': None})
        missing = Paths(base=Path(self.tmp.name) / 'nowhere')
        self.assertEqual(schedule.load(missing)[1:], (None, False), 'no configuration directory yet')

    def test_save_arms_on_turning_on_and_on_time_or_day_changes_only(self):
        start = at('2026-11-17T01:00:00Z')
        record, previous = schedule.save(self.paths, schedule.validate(self.GOOD), trusted_uid=self.uid, now=start)
        self.assertFalse(previous['enabled'])
        self.assertEqual((record['armed_at'], record['updated']), ('2026-11-17T01:00:00Z', '2026-11-17T01:00:00Z'))
        self.assertEqual(oct(self.file.stat().st_mode & 0o7777), '0o644')
        self.assertEqual(json.loads(self.file.read_text()), record)
        self.assertEqual(set(record), set(schedule.FILE_KEYS))
        self.assertEqual(schedule.load(self.paths, trusted_uid=self.uid), (
            {k: v for k, v in record.items() if k != 'schema'}, None, True))
        later = start + DAY
        kept, _ = schedule.save(self.paths, schedule.validate(dict(self.GOOD, apps='all', keep_last=3,
                                                                   include_images=True)),
                                trusted_uid=self.uid, now=later)
        self.assertEqual(kept['armed_at'], '2026-11-17T01:00:00Z', 'apps, images and keep_last do not re-arm')
        moved, _ = schedule.save(self.paths, schedule.validate(dict(self.GOOD, time='04:00')), trusted_uid=self.uid,
                                 now=later)
        self.assertEqual(moved['armed_at'], '2026-11-18T01:00:00Z')
        days, _ = schedule.save(self.paths, schedule.validate(dict(self.GOOD, time='04:00', days=['mon'])),
                                trusted_uid=self.uid, now=later + DAY)
        self.assertEqual(days['armed_at'], '2026-11-19T01:00:00Z')
        off, _ = schedule.save(self.paths, schedule.validate(dict(self.GOOD, enabled=False)), trusted_uid=self.uid,
                               now=later + 2 * DAY)
        self.assertEqual(off['armed_at'], '2026-11-19T01:00:00Z', 'turning off keeps it')
        again, _ = schedule.save(self.paths, schedule.validate(self.GOOD), trusted_uid=self.uid, now=later + 3 * DAY)
        self.assertEqual(again['armed_at'], '2026-11-21T01:00:00Z', 'turning on again re-arms')

    def test_a_bad_or_unsafe_file_turns_the_schedule_off_and_never_raises(self):
        record, _ = schedule.save(self.paths, schedule.validate(self.GOOD), trusted_uid=self.uid)
        good = self.file.read_text()

        def problem():
            settings_, text, saved = schedule.load(self.paths, trusted_uid=self.uid)
            self.assertFalse(settings_['enabled'])
            self.assertTrue(saved)
            return text

        os.chmod(self.file, 0o666)
        self.assertIn('不可讓其他帳號寫入', problem())
        os.chmod(self.file, 0o644)
        for text in ('not json', json.dumps(dict(record, extra=1)), json.dumps(dict(record, time='03:01')),
                     json.dumps(dict(record, schema=2)), json.dumps(dict(record, armed_at=None)),
                     '{"schema": 1, "schema": 1}'):
            with self.subTest(text=text[:60]):
                self.file.write_text(text)
                self.assertIn('格式不正確', problem())
        self.file.write_text(' ' * (schedule.MAX_BYTES + 1))
        self.assertIn('過大', problem())
        self.file.unlink()
        os.symlink(Path(self.tmp.name) / 'elsewhere.json', self.file)
        self.assertIn('符號連結', problem())
        self.file.unlink()
        self.file.write_text(good)
        os.chmod(self.file, 0o644)
        self.assertIsNone(schedule.load(self.paths, trusted_uid=self.uid)[1])
        os.chmod(self.paths.config, 0o777)
        settings_, text, _saved = schedule.load(self.paths, trusted_uid=self.uid)
        self.assertFalse(settings_['enabled'])
        self.assertIn('資料夾', text)
        os.chmod(self.paths.config, 0o755)
        self.assertIsNotNone(schedule.load(self.paths, trusted_uid=self.uid + 1)[1], 'a file of another owner')


# ---------------------------------------------------------------- slots

class SlotTests(unittest.TestCase):
    def test_taipei_slots_are_local_time_on_the_scheduled_days(self):
        self.assertEqual(schedule.slot_instant(datetime.date(2026, 11, 17), '03:00', TAIPEI), at(SLOT))
        daily = on()
        self.assertEqual(schedule.latest_slot(daily, TAIPEI, at('2026-11-17T00:00:00Z')), at(SLOT))
        self.assertEqual(schedule.next_slots(daily, TAIPEI, at(SLOT), 3),
                         [at(NEXT), at('2026-11-18T19:00:00Z'), at('2026-11-19T19:00:00Z')])
        weekly = on(days=['mon', 'fri'], time='23:55')
        found = schedule.next_slots(weekly, TAIPEI, at('2026-11-17T00:00:00Z'), 3)  # Tuesday in Taipei
        self.assertEqual([slot.astimezone(TAIPEI).strftime('%a %H:%M') for slot in found],
                         ['Fri 23:55', 'Mon 23:55', 'Fri 23:55'])
        self.assertEqual(schedule.latest_slot(weekly, TAIPEI, at('2026-11-17T00:00:00Z')).astimezone(TAIPEI).date(),
                         datetime.date(2026, 11, 16), 'Monday 23:55')

    def test_a_time_the_dst_change_skips_runs_when_the_clock_jumps_past_it(self):
        # 2026-03-08 in New York: 02:00 EST -> 03:00 EDT; 02:00 and 02:30 do not exist that day.
        gap_day = datetime.date(2026, 3, 8)
        for hhmm in ('02:00', '02:30', '02:55'):
            with self.subTest(time=hhmm):
                slot = schedule.slot_instant(gap_day, hhmm, NEW_YORK)
                self.assertEqual(slot, at('2026-03-08T07:00:00Z'))
                self.assertEqual(slot.astimezone(NEW_YORK).strftime('%H:%M %Z'), '03:00 EDT')
        daily = on(time='02:30')
        slots = schedule.slots_between(daily, NEW_YORK, at('2026-03-06T12:00:00Z'), at('2026-03-10T00:00:00Z'))
        self.assertEqual([slot.astimezone(NEW_YORK).strftime('%m-%d %H:%M') for slot in slots],
                         ['03-07 02:30', '03-08 03:00', '03-09 02:30'], 'one run every day, none skipped')
        self.assertEqual(schedule.slot_instant(gap_day, '03:00', NEW_YORK), at('2026-03-08T07:00:00Z'))

    def test_a_time_the_dst_change_repeats_runs_once_at_its_first_occurrence(self):
        # 2026-11-01 in New York: 02:00 EDT -> 01:00 EST; 01:00-01:59 happen twice.
        slot = schedule.slot_instant(datetime.date(2026, 11, 1), '01:30', NEW_YORK)
        self.assertEqual(slot, at('2026-11-01T05:30:00Z'))
        self.assertEqual(slot.astimezone(NEW_YORK).strftime('%H:%M %Z'), '01:30 EDT')
        daily = on(time='01:30')
        slots = schedule.slots_between(daily, NEW_YORK, at('2026-10-31T00:00:00Z'), at('2026-11-02T12:00:00Z'))
        self.assertEqual(slots, [at('2026-10-31T05:30:00Z'), at('2026-11-01T05:30:00Z'), at('2026-11-02T06:30:00Z')])
        state_ = state(handled='2026-11-01T05:30:00Z')
        second = env_at('2026-11-01T06:31:00Z', zone=NEW_YORK)  # the second 01:31 of that night
        self.assertEqual(schedule.decide(daily, state_, second).action, 'idle')

    def test_offsets_and_views(self):
        self.assertEqual(schedule.offset_text(TAIPEI, at(SLOT)), '+08:00')
        self.assertEqual(schedule.offset_text(NEW_YORK, at('2026-01-10T12:00:00Z')), '-05:00')
        self.assertEqual(schedule.instant_view(at(SLOT), TAIPEI),
                         {'at': SLOT, 'local': '2026-11-17T03:00', 'utc_offset': '+08:00'})
        self.assertEqual(schedule.timezone_view(env_at(SLOT, name='Asia/Taipei')),
                         {'name': 'Asia/Taipei', 'utc_offset': '+08:00'})
        self.assertEqual(schedule.request_id(at(SLOT)), 'schedule-20261116T190000Z')
        self.assertRegex(schedule.request_id(at(SLOT)), jobs.REQUEST_ID_RE)

    def test_the_device_zone_comes_from_etc_localtime_not_from_tz(self):
        with mock.patch.dict(os.environ, {'TZ': 'America/New_York'}):
            zone, name = schedule.local_zone()
            self.assertNotIn('TZ', os.environ)
        self.assertIsNotNone(zone.utcoffset(datetime.datetime(2026, 11, 17)))
        self.assertTrue(name)
        env = schedule.system_env()
        self.assertEqual(env.now.tzinfo, UTC)
        self.assertGreater(env.uptime, 0)


# ---------------------------------------------------------------- the decision

class DecideTests(unittest.TestCase):
    def decide(self, now, settings_=None, uptime=86400.0, zone=TAIPEI, **fields):
        return schedule.decide(settings_ or on(), state(**fields), env_at(now, zone=zone, uptime=uptime))

    def test_on_time_starts_within_15_minutes(self):
        decision = self.decide('2026-11-16T19:02:00Z', handled=PREVIOUS)
        self.assertEqual((decision.action, decision.slot, decision.trigger), ('start', at(SLOT), 'on-time'))
        self.assertIsNone(decision.missed)
        self.assertEqual(self.decide('2026-11-16T19:14:59Z', handled=PREVIOUS).trigger, 'on-time')
        self.assertEqual(self.decide('2026-11-16T18:59:00Z', handled=PREVIOUS).action, 'idle', 'not yet')
        self.assertEqual(self.decide('2026-11-16T19:02:00Z', handled=SLOT).action, 'idle', 'handled already')

    def test_disabled_does_nothing_and_drops_a_waiting_slot(self):
        decision = self.decide('2026-11-16T19:02:00Z', on(enabled=False), pending={'slot': SLOT, 'since': SLOT})
        self.assertEqual((decision.action, decision.clear_pending), ('idle', True))

    def test_slots_before_armed_at_never_run(self):
        armed = on(armed_at='2026-11-16T19:02:00Z')  # turned on at 03:02 with the time 03:00
        self.assertEqual(self.decide('2026-11-16T19:05:00Z', armed).action, 'idle')
        self.assertEqual(self.decide('2026-11-17T19:01:00Z', armed).slot, at(NEXT), 'the next day runs')
        future = on(armed_at='2027-01-01T00:00:00Z')  # the clock went back below armed_at
        self.assertEqual(self.decide('2026-11-16T19:05:00Z', future).action, 'idle', 'past slots stay ignored')
        self.assertEqual(self.decide('2026-11-16T19:05:00Z', future, handled=None).action, 'idle')

    def test_boot_settling_waits_for_10_minutes_of_uptime(self):
        decision = self.decide('2026-11-16T19:03:00Z', uptime=299, handled=PREVIOUS)
        self.assertEqual((decision.action, decision.slot), ('settle', at(SLOT)))
        self.assertEqual(self.decide('2026-11-16T19:12:00Z', uptime=601, handled=PREVIOUS).trigger, 'on-time')
        # Up only after the window: the slot was missed; caught up once the device is settled.
        self.assertEqual(self.decide('2026-11-16T19:30:00Z', uptime=120, handled=PREVIOUS).action, 'settle')
        self.assertEqual(self.decide('2026-11-16T19:40:00Z', uptime=700, handled=PREVIOUS).trigger, 'catch-up')

    def test_a_missed_slot_is_caught_up_once_only_the_latest(self):
        decision = self.decide('2026-11-17T01:00:00Z', handled='2026-11-13T19:00:00Z')  # off for three nights
        self.assertEqual((decision.action, decision.slot, decision.trigger), ('start', at(SLOT), 'catch-up'))
        self.assertEqual(decision.missed, {'slot': at(PREVIOUS), 'first': at('2026-11-14T19:00:00Z'), 'count': 2})
        self.assertEqual(decision.handled, at(PREVIOUS))

    def test_a_missed_slot_is_not_caught_up_when_the_next_one_is_less_than_3_hours_away(self):
        decision = self.decide('2026-11-17T16:30:00Z', handled=PREVIOUS)  # 00:30 Taipei: the next run is at 03:00
        self.assertEqual((decision.action, decision.slot), ('missed', at(SLOT)))
        self.assertEqual(decision.missed, {'slot': at(SLOT), 'first': at(SLOT), 'count': 1})
        self.assertEqual(decision.handled, at(SLOT))
        self.assertEqual(self.decide('2026-11-17T15:59:00Z', handled=PREVIOUS).trigger, 'catch-up', '3 h 01 min away')

    def test_a_slot_that_waits_for_another_job_starts_late_and_is_skipped_when_the_next_one_comes(self):
        waiting = {'slot': SLOT, 'since': '2026-11-16T19:01:00Z'}
        decision = self.decide('2026-11-16T21:00:00Z', handled=PREVIOUS, pending=waiting)
        self.assertEqual((decision.action, decision.trigger), ('start', 'late'))
        self.assertEqual(self.decide('2026-11-16T21:00:00Z', uptime=30, handled=PREVIOUS, pending=waiting).action,
                         'settle')
        superseded = self.decide('2026-11-17T19:01:00Z', handled=PREVIOUS, pending=waiting)
        self.assertEqual(superseded.skipped, {'slot': at(SLOT), 'first': at(SLOT), 'count': 1})
        self.assertEqual((superseded.action, superseded.slot, superseded.trigger), ('start', at(NEXT), 'on-time'))
        self.assertEqual((superseded.handled, superseded.clear_pending), (at(SLOT), True))
        self.assertTrue(self.decide('2026-11-16T21:00:00Z', handled=SLOT, pending=waiting).clear_pending)

    def test_a_time_zone_change_applies_at_the_next_tick_without_a_second_run(self):
        # Handled at 03:00 in UTC (2026-11-17 03:00Z); the device moves east to Taipei. Taipei's 03:00 of that night was
        # 2026-11-16 19:00Z, before the handled slot: it does not run again; the next Taipei 03:00 does.
        taipei = self.decide('2026-11-17T12:00:00Z', handled='2026-11-17T03:00:00Z')
        self.assertEqual(taipei.action, 'idle')
        self.assertEqual(self.decide('2026-11-17T19:01:00Z', handled='2026-11-17T03:00:00Z').slot, at(NEXT))
        # Handled at 03:00 Taipei (2026-11-16 19:00Z); the device moves west to UTC. The next local 03:00 (03:00Z) is a
        # later slot of a new local day: it runs on time, once.
        utc = self.decide('2026-11-17T03:05:00Z', zone=UTC, handled=SLOT)
        self.assertEqual((utc.action, utc.slot, utc.trigger), ('start', at('2026-11-17T03:00:00Z'), 'on-time'))
        self.assertEqual(self.decide('2026-11-17T03:06:00Z', zone=UTC, handled='2026-11-17T03:00:00Z').action, 'idle')


# ---------------------------------------------------------------- the tick through the helper

class ScheduleCase(unittest.TestCase):
    """The helper with fakes (test_flows), a fixed clock in Taipei, the timer reported running."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = Paths(base=self.root / 'sys')
        self.storage = FakeStorage(self.root / 'data')
        self.storage.pending = Path(self.paths.pending)
        self.keys = FakeKeys(self.root)
        self.keys.device = dataclasses.replace(self.keys.device, kit_confirmed=True)
        self.archive = FakeArchive()
        self.world = World()
        self.catalog = make_catalog(self.paths)
        self.journal, self.audit = [], []
        self.deps = flows.Deps(storage=self.storage, keys=self.keys, archive=self.archive,
                               load_catalog=lambda: self.catalog, adapter_factory=self.world.factory,
                               host_info=lambda: dict(HOST), encrypt_by_default=lambda: self.encrypt)
        self.deps.audit = self.audit.append
        self.deps.journal = lambda line, warning=False: self.journal.append((line, warning))
        self.encrypt = True
        self.launched = []
        self.active_units = set()
        self.paths.config.mkdir(parents=True, exist_ok=True)
        os.chmod(self.paths.config, 0o755)
        self.env = env_at('2026-11-16T19:02:00Z', name='Asia/Taipei')
        self.timer = {'enabled': True, 'active': True}

    def services(self):
        return cli.Services(self.paths, deps=self.deps, launcher=self.launched.append,
                            unit_active=lambda unit: unit in self.active_units, trusted_uid=os.geteuid(),
                            clock=lambda: self.env, timer=lambda: dict(self.timer))

    def call(self, argv, request=None, raw=None):
        out = io.StringIO()
        if request is None and raw is None:
            stdin = ExplodingStdin()
        else:
            stdin = io.StringIO(raw if raw is not None else json.dumps(request))
        code = cli.main(argv, stdin=stdin, stdout=out, services=self.services(), require_root=False)
        response = json.loads(out.getvalue())
        self.assertEqual(code, 0 if response['ok'] else 1)
        return response

    def ok(self, argv, request=None):
        response = self.call(argv, request)
        self.assertTrue(response['ok'], response)
        return response

    def error(self, argv, request=None, raw=None):
        response = self.call(argv, request, raw)
        self.assertFalse(response['ok'], response)
        return response['error']

    def write_schedule(self, **fields):
        """schedule.json as root writes it (the test user is the trusted owner here), armed long before."""
        record = {'schema': 1, **on(**fields)}
        path = Path(self.paths.config) / schedule.FILE
        path.write_text(json.dumps(record))
        os.chmod(path, 0o644)
        return record

    def tick(self, now=None, uptime=86400.0):
        if now is not None:
            self.env = env_at(now, zone=self.env.zone, uptime=uptime, name=self.env.zone_name)
        return self.ok(['schedule-tick'])

    def state(self):
        value, problem = schedule.read_state(self.paths)
        self.assertIsNone(problem)
        return value

    def set_state(self, **fields):
        current = self.state()
        current.update(fields)
        schedule.write_state(self.paths, current)

    def lines(self, prefix):
        return [(line, warning) for line, warning in self.journal if line.startswith(prefix)]

    def store(self):
        return jobs.JobStore(self.paths)

    def busy_job(self):
        record = self.store().create('verify', {'backup_id': '20261113T020000Z-a1b2c3d4'}, request_id='busy-000001')
        record['state'] = 'running'
        self.store().save(record)
        self.active_units.add(record['unit'])
        return record

    def finish(self, record, state_='succeeded'):
        record = self.store().get(record['id'])
        record['state'] = state_
        self.store().save(record)
        self.active_units.discard(record['unit'])


class TickTests(ScheduleCase):
    def test_on_time_tick_starts_one_scheduled_job_and_records_it(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        out = self.tick()
        self.assertEqual((out['decision'], out['slot'], out['trigger']), ('started', SLOT, 'on-time'))
        self.assertEqual(self.launched, [out['job_id']])
        record = self.store().get(out['job_id'])
        self.assertEqual((record['type'], record['request_id']), ('backup', 'schedule-20261116T190000Z'))
        self.assertEqual(record['params'], {'apps': ['woowbk-demo', 'woowbk-two'], 'include_images': False,
                                            'note': '排程備份', 'encrypt': True,
                                            'schedule': {'slot': SLOT, 'trigger': 'on-time', 'keep_last': 7}})
        current = self.state()
        self.assertEqual(current['handled'], SLOT)
        self.assertEqual(current['last_run'], {'slot': SLOT, 'job': out['job_id'], 'trigger': 'on-time',
                                               'started': '2026-11-16T19:02:00Z', 'recorded': False, 'result': None,
                                               'finished': None, 'backup_id': None})
        self.assertEqual(self.lines('schedule-run'), [(f'schedule-run slot={SLOT} job={out["job_id"]} trigger=on-time '
                                                       'apps=woowbk-demo,woowbk-two encrypted=true', False)])
        self.assertTrue(schedule.tick_path(self.paths).exists())
        # The same slot never starts twice: a later tick, and a tick that read a stale state (request_id dedup).
        self.assertEqual(self.tick('2026-11-16T19:07:00Z')['decision'], 'idle')
        self.set_state(handled=PREVIOUS)
        again = self.tick('2026-11-16T19:08:00Z')
        self.assertEqual((again['job_id'], again['deduplicated']), (out['job_id'], True))
        self.assertEqual(self.launched, [out['job_id']])
        self.assertEqual(len(self.lines('schedule-run')), 1, 'logged once per slot')

    def test_the_started_job_makes_a_scheduled_backup_and_the_next_tick_records_the_result(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        job_id = self.tick()['job_id']
        self.assertEqual(self.ok(['run-job', job_id])['state'], 'succeeded')
        result = self.store().get(job_id)['result']
        backup_id = result['backup_id']
        self.assertEqual({key: result[key] for key in ('scheduled', 'slot', 'trigger', 'partial', 'skipped_apps',
                                                      'apps', 'encrypted', 'retention_deleted')},
                         {'scheduled': True, 'slot': SLOT, 'trigger': 'on-time', 'partial': False, 'skipped_apps': [],
                          'apps': ['woowbk-demo', 'woowbk-two'], 'encrypted': True, 'retention_deleted': []})
        self.assertEqual(self.state()['registry'], {backup_id: {'job': job_id, 'slot': SLOT, 'trigger': 'on-time'}})
        meta = self.storage.index[backup_id]
        self.assertEqual((meta['type'], meta['note']), ('manual', '排程備份'))
        listed = {item['id']: item for item in self.ok(['list'])['backups']}
        self.assertIs(listed[backup_id]['scheduled'], True)
        self.tick('2026-11-16T19:10:00Z')
        last = self.state()['last_run']
        self.assertEqual((last['recorded'], last['result'], last['backup_id']), (True, 'succeeded', backup_id))
        self.assertEqual(self.lines('schedule-result'),
                         [(f'schedule-result slot={SLOT} job={job_id} trigger=on-time result=succeeded '
                           f'backup={backup_id}', False)])
        self.tick('2026-11-16T19:15:00Z')
        self.assertEqual(len(self.lines('schedule-result')), 1, 'recorded once')
        # A deleted backup leaves the registry at the next tick (its job is not running).
        self.ok(['delete'], {'backup_id': backup_id})
        self.tick('2026-11-16T19:20:00Z')
        self.assertEqual(self.state()['registry'], {})

    def test_busy_waits_once_starts_late_when_free_and_is_skipped_when_the_next_slot_comes(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        busy = self.busy_job()
        self.assertEqual(self.tick()['decision'], 'busy')
        current = self.state()
        self.assertEqual(current['pending'], {'slot': SLOT, 'since': '2026-11-16T19:02:00Z', 'job_id': busy['id']})
        self.assertEqual([(e['kind'], e['slot']) for e in current['events']], [('waiting', SLOT)])
        self.assertIsNone(current['handled'])
        self.tick('2026-11-16T19:30:00Z')
        self.assertEqual(len(self.state()['events']), 1, 'one wait event per slot')
        self.assertEqual(len(self.lines('schedule-wait')), 1)
        self.finish(busy)
        out = self.tick('2026-11-16T21:00:00Z')
        self.assertEqual((out['decision'], out['trigger']), ('started', 'late'))
        self.assertIsNone(self.state()['pending'])
        # Busy again through the next slot: the waiting slot is recorded as skipped.
        self.finish(self.store().get(out['job_id']))
        busy = self.busy_job()
        self.tick('2026-11-17T19:01:00Z')
        self.assertEqual(self.state()['pending']['slot'], NEXT)
        self.tick('2026-11-18T19:01:00Z')
        current = self.state()
        self.assertEqual([(e['kind'], e['slot']) for e in current['events'][:3]],
                         [('waiting', '2026-11-18T19:00:00Z'), ('skipped', NEXT), ('waiting', NEXT)])
        self.assertEqual(current['handled'], NEXT)
        self.assertEqual(self.lines('schedule-skip'), [(f'schedule-skip slot={NEXT} reason=busy count=1', False)])
        self.assertIn('當時有其他作業一直在進行', current['events'][1]['message'])
        attention = self.ok(['status'])['schedule']['attention']
        self.assertEqual((attention['code'], attention['reason'], attention['slot']), ('skipped', 'busy', NEXT))

    def test_boot_settling_and_a_catch_up_after_the_device_was_off(self):
        self.write_schedule(armed_at='2026-11-10T00:00:00Z')
        self.set_state(handled='2026-11-13T19:00:00Z')
        self.assertEqual(self.tick('2026-11-17T01:00:00Z', uptime=200)['decision'], 'settle')
        self.assertEqual(self.launched, [])
        out = self.tick('2026-11-17T01:10:00Z', uptime=800)
        self.assertEqual((out['decision'], out['trigger']), ('started', 'catch-up'))
        current = self.state()
        self.assertEqual([(e['kind'], e['slot'], e['first'], e['count']) for e in current['events']],
                         [('missed', PREVIOUS, '2026-11-14T19:00:00Z', 2)])
        self.assertIn('2026-11-15 03:00 到 2026-11-16 03:00 共 2 次', current['events'][0]['message'])
        self.assertEqual(current['handled'], SLOT)
        self.assertEqual(len(self.lines('schedule-missed')), 1)

    def test_missed_without_a_catch_up_when_the_next_slot_is_near(self):
        self.write_schedule()
        self.set_state(handled=PREVIOUS)
        self.assertEqual(self.tick('2026-11-17T16:30:00Z')['decision'], 'missed')
        self.assertEqual(self.launched, [])
        current = self.state()
        self.assertEqual((current['handled'], current['events'][0]['kind']), (SLOT, 'missed'))
        self.assertIn('2026-11-17 03:00 的排程備份沒有執行：設備當時沒有開機', current['events'][0]['message'])
        self.assertEqual(self.tick('2026-11-17T19:02:00Z')['trigger'], 'on-time', 'the next slot runs as usual')

    def test_problems_before_a_job_are_events_without_a_job(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        self.keys.device = None
        self.assertEqual(self.tick()['decision'], 'no-key')
        self.assertEqual(self.launched, [])
        self.assertEqual(self.state()['events'][0]['kind'], 'no-key')
        self.assertEqual(self.lines('schedule-skip'), [(f'schedule-skip slot={SLOT} reason=no-key', True)])
        self.assertEqual(self.tick('2026-11-16T19:07:00Z')['decision'], 'idle', 'no automatic retry')
        self.encrypt = False  # unencrypted backups need no key
        self.write_schedule(armed_at='2026-11-17T18:00:00Z', apps=['woowbk-demo'])
        self.catalog.pop('woowbk-demo')
        self.assertEqual(self.tick('2026-11-17T19:02:00Z')['decision'], 'no-apps')
        self.assertIn('沒有可以備份的應用', self.state()['events'][0]['message'])

    def test_disabled_and_a_bad_file(self):
        self.write_schedule(enabled=False)
        self.assertEqual(self.tick()['decision'], 'idle')
        self.assertEqual(self.launched, [])
        path = Path(self.paths.config) / schedule.FILE
        self.write_schedule()
        os.chmod(path, 0o666)
        self.assertEqual(self.tick()['decision'], 'settings-problem')
        self.assertEqual(self.tick('2026-11-16T19:07:00Z')['decision'], 'settings-problem')
        self.assertEqual(self.launched, [])
        self.assertEqual([e['kind'] for e in self.state()['events']], ['settings-problem'], 'recorded once')
        self.assertEqual(self.lines('schedule-skip'), [('schedule-skip reason=settings-problem', True)])
        os.chmod(path, 0o644)
        self.tick('2026-11-16T19:09:00Z')
        self.assertNotIn('settings', self.state()['logged'])

    def test_an_unreadable_state_stops_the_schedule_and_is_never_overwritten(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        schedule.state_path(self.paths).parent.mkdir(parents=True, exist_ok=True)
        schedule.state_path(self.paths).write_text('{"schema": 1, "registry": {"bad": {}}}')
        self.assertEqual(self.tick()['decision'], 'state-problem')
        self.assertEqual(self.tick('2026-11-16T19:07:00Z')['decision'], 'state-problem')
        self.assertEqual(self.launched, [])
        self.assertEqual(self.lines('schedule-skip'), [('schedule-skip reason=state-unreadable', True)], 'once a boot')
        self.assertEqual(schedule.state_path(self.paths).read_text(), '{"schema": 1, "registry": {"bad": {}}}')

    def test_a_clock_that_went_back_starts_over_from_now(self):
        self.write_schedule()
        self.set_state(handled='2027-01-01T19:00:00Z')
        self.assertEqual(self.tick('2026-11-16T19:20:00Z')['decision'], 'idle')
        self.assertEqual(self.state()['handled'], SLOT, 'the latest slot up to now counts as handled')
        self.assertEqual(self.lines('schedule-clock'),
                         [('schedule-clock reset handled=2027-01-01T19:00:00Z now=2026-11-16T19:20:00Z', True)])
        self.assertEqual(self.tick('2026-11-17T19:02:00Z')['trigger'], 'on-time')
        self.assertEqual(len(self.lines('schedule-clock')), 1)

    def test_a_second_tick_while_one_runs_does_nothing(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        with schedule.tick_lock(self.paths) as held:
            self.assertTrue(held)
            self.assertEqual(self.tick()['decision'], 'tick-running')
        self.assertEqual(self.launched, [])

    def test_a_scheduled_job_that_died_is_settled_by_the_recovery_and_shown_interrupted(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        job_id = self.tick()['job_id']
        record = self.store().get(job_id)
        record['state'] = 'running'  # run-job took it, then the device lost power: no unit any more
        self.store().save(record)
        self.tick('2026-11-16T19:10:00Z')
        self.assertEqual(self.store().get(job_id)['state'], 'interrupted')
        current = self.state()
        self.assertEqual((current['last_run']['result'], current['events'][0]['kind']), ('interrupted', 'failed'))
        self.assertIn('備份作業意外中斷', current['events'][0]['message'])
        self.assertEqual(self.lines('schedule-result'),
                         [(f'schedule-result slot={SLOT} job={job_id} trigger=on-time result=interrupted '
                           'code=job-failed', True)])
        status = self.ok(['status'])['schedule']
        self.assertEqual((status['last_run']['result'], status['attention']['code']), ('interrupted', 'failed'))

    def test_partial_run_skips_apps_that_are_not_ready(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        self.world.deployed['woowbk-two'] = False
        job_id = self.tick()['job_id']
        self.assertEqual(self.ok(['run-job', job_id])['state'], 'succeeded')
        result = self.store().get(job_id)['result']
        self.assertEqual((result['partial'], result['apps']), (True, ['woowbk-demo']))
        self.assertEqual(result['skipped_apps'], [{'id': 'woowbk-two', 'name': '第二個應用',
                                                   'reason': '應用「第二個應用」尚未部署在此設備，無法備份。'}])
        self.tick('2026-11-16T19:10:00Z')
        self.assertEqual(self.state()['events'][0]['kind'], 'partial')
        self.assertEqual(self.lines('schedule-result')[0][1], True, 'a partial run is a warning')
        attention = self.ok(['status'])['schedule']['attention']
        self.assertEqual(attention['code'], 'partial')
        self.assertIn('「第二個應用」', attention['message'])


# ---------------------------------------------------------------- the scheduled job (flows)

class FlowTests(ScheduleCase):
    job_id = 'j20261116T190200Z-0123abcd'

    def run_scheduled(self, apps=('woowbk-demo', 'woowbk-two'), keep_last=7, trigger='on-time', **params):
        self.reporter = FakeReporter()
        ctx = flows.FlowContext(self.paths, self.job_id, self.deps, self.reporter)
        base = schedule.job_params(on(keep_last=keep_last), list(apps), True, slot=at(SLOT), trigger=trigger)
        base.update(params)
        return flows.run_backup(ctx, base)

    def test_the_registry_is_written_before_any_app_pauses(self):
        seen = []
        original = schedule.register_run

        def spy(paths, backup_id, job_id, slot, trigger):
            seen.append((list(self.world.events), list(self.reporter.phases()), backup_id))
            return original(paths, backup_id, job_id, slot, trigger)

        with mock.patch.object(schedule, 'register_run', spy):
            result = self.run_scheduled()
        events, phases, backup_id = seen[0]
        self.assertEqual((events, phases), ([], ['prepare']), 'nothing stopped, no app probed yet')
        self.assertEqual(result['backup_id'], backup_id, 'the id chosen ahead is the backup')
        self.assertEqual(self.state()['registry'][backup_id], {'job': self.job_id, 'slot': SLOT, 'trigger': 'on-time'})

    def test_a_registry_that_cannot_be_written_fails_the_job_before_anything_stops(self):
        with mock.patch.object(schedule, 'register_run', side_effect=OSError('read-only filesystem')):
            with self.assertRaises(BackupError) as caught:
                self.run_scheduled()
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('沒有暫停任何應用', caught.exception.message)
        self.assertEqual(self.world.events, [])
        self.assertNotIn('stop', self.reporter.phases())
        self.assertEqual(self.storage.index, {})

    def test_apps_missing_or_not_ready_are_skipped_and_none_left_fails(self):
        self.world.deployed['woowbk-two'] = False
        result = self.run_scheduled(apps=('woowbk-demo', 'woowbk-two', 'woowbk-gone'))
        self.assertEqual((result['partial'], result['apps']), (True, ['woowbk-demo']))
        self.assertEqual([item['id'] for item in result['skipped_apps']], ['woowbk-gone', 'woowbk-two'])
        self.assertIn('此設備沒有設定應用 woowbk-gone', result['skipped_apps'][0]['reason'])
        meta = self.storage.index[result['backup_id']]
        self.assertEqual(([a['id'] for a in meta['apps']], meta['type'], meta['note']),
                         (['woowbk-demo'], 'manual', '排程備份'))
        self.world.deployed['woowbk-demo'] = False
        self.world.events.clear()
        with self.assertRaises(BackupError) as caught:
            self.run_scheduled()
        self.assertEqual(caught.exception.code, 'job-failed')
        self.assertIn('沒有可以備份的應用', caught.exception.message)
        self.assertEqual(self.world.events, [], 'nothing stopped')
        with self.assertRaises(BackupError) as caught:
            self.run_scheduled(apps=('woowbk-gone',))
        self.assertEqual(caught.exception.code, 'job-failed')

    def test_space_is_checked_before_any_pause(self):
        self.storage.free = 1000
        with self.assertRaises(BackupError) as caught:
            self.run_scheduled()
        self.assertEqual(caught.exception.code, 'insufficient-space')
        self.assertEqual(self.world.events, [])

    def test_the_schedules_keep_last_removes_only_older_scheduled_backups(self):
        manual = flows.run_backup(flows.FlowContext(self.paths, 'j20261116T180000Z-00000001', self.deps,
                                                    FakeReporter()), {'apps': ['woowbk-demo'], 'note': '手動'})
        made = [self.run_scheduled(keep_last=2)['backup_id'] for _ in range(3)]
        self.assertEqual(set(self.storage.index), {manual['backup_id'], made[1], made[2]})
        self.assertEqual(self.storage.deleted, [made[0]])
        line = next(line for line in self.audit if line.startswith('retention-delete'))
        self.assertRegex(line, rf'^retention-delete backup={made[0]} type=manual size=[0-9]+ '
                               r'apps=woowbk-demo,woowbk-two reason=schedule$')
        self.assertTrue(any('已依排程備份的保留份數刪除較舊的排程備份' in entry for entry in self.reporter.logs))
        self.run_scheduled(keep_last=None)
        self.assertEqual(len(self.storage.deleted), 1, 'keep everything')

    def test_frozen_2026_11_15_2_formats_read_a_scheduled_backup(self):
        # The lists of the engine 2026.11.15.2 (c393dfb): an older engine reads, lists and restores what these allow.
        self.assertEqual(archive.TYPES, ('manual', 'safety'))
        self.assertEqual(archive.HEADER_KEYS, ('format', 'backup_id', 'created', 'key_id', 'encryption', 'compression'))
        self.assertEqual(archive.INNER_KEYS, ('format', 'backup_id', 'created', 'type', 'note', 'key_id', 'encryption',
                                              'tool', 'source', 'consistency', 'backup_apps', 'app', 'entries'))
        self.assertEqual(archive.DOC_KEYS, ('format', 'backup_id', 'created', 'type', 'note', 'tool', 'source',
                                            'encryption', 'compression', 'key_id', 'apps'))
        self.assertEqual(storage.TYPES, ('manual', 'safety', 'uploaded'))
        self.assertEqual(storage.META_REQUIRED, ('id', 'type', 'created', 'note', 'apps', 'size', 'sha256', 'key_id',
                                                 'include_images', 'filename', 'source', 'verified', 'inspected'))
        self.assertEqual(storage.META_OPTIONAL, ('uploaded_at', 'format', 'encrypted'))
        self.assertEqual(jobs.ACTIVE + jobs.TERMINAL, ('queued', 'running', 'succeeded', 'failed', 'rolled-back',
                                                       'interrupted', 'cancelled'))
        self.assertEqual(jobs.PUBLIC_KEYS, ('id', 'type', 'state', 'phase', 'phases', 'progress', 'created', 'started',
                                            'finished', 'params', 'result', 'error', 'cancellable'))
        # A scheduled backup uses only them: type manual, the note within its limit, the index keys of a manual one.
        manual = flows.run_backup(flows.FlowContext(self.paths, 'j20261116T180000Z-00000001', self.deps,
                                                    FakeReporter()), {'apps': ['woowbk-demo'], 'note': '手動'})
        result = self.run_scheduled()
        meta = self.storage.index[result['backup_id']]
        self.assertEqual(set(meta), set(self.storage.index[manual['backup_id']]))
        self.assertTrue(set(meta) <= set(storage.META_REQUIRED + storage.META_OPTIONAL))
        self.assertTrue(storage._valid_meta(dict(meta, sha256='0' * 64), result['backup_id']))
        written = self.archive.writes[-1]['manifest']
        self.assertEqual((written['type'], written['note']), ('manual', '排程備份'))
        self.assertEqual(set(written), set(self.archive.writes[0]['manifest']))
        # The job record: a backup job with one more param, which 2026.11.15.2 neither checks nor needs.
        self.assertTrue(set(json.loads(json.dumps(schedule.job_params(on(), ['woowbk-demo'], True, slot=None,
                                                                      trigger='run-now')))) >=
                        {'apps', 'include_images', 'note', 'encrypt'})
        self.assertEqual(set(settings.DEFAULTS), {'encrypt_by_default'}, 'settings.json keeps its keys')

    def test_a_real_format_2_archive_with_the_scheduled_note_passes_the_strict_readers(self):
        from .test_archive import demo_payloads, stage
        from .test_archive_v2 import v2_manifest
        out = Path(self.tmp.name) / 'real'
        out.mkdir(mode=0o700)
        payloads = demo_payloads(big=4096)
        entries = stage(out, payloads)
        manifest = v2_manifest(None, encryption='none')
        manifest['apps'] = manifest['apps'][:1]
        manifest.update(note=schedule.NOTE, type='manual')
        dest = out / 'scheduled.tar'
        archive.write_archive(dest, None, manifest, entries, None, tmp_dir=out)
        read = archive.read_manifest(dest, [])
        self.assertEqual((read['type'], read['note']), ('manual', '排程備份'))
        doc = archive.describe(dest)['doc']
        self.assertEqual((doc['type'], doc['note']), ('manual', '排程備份'))


# ---------------------------------------------------------------- retention: two pools

class PoolTests(ScheduleCase):
    def make(self, n, apps=('woowbk-demo',), scheduled=False, verified=None):
        backup_id = f'202611{n:02d}T020000Z-{n:08x}'
        self.storage.archive_path(backup_id).parent.mkdir(parents=True, exist_ok=True)
        self.storage.archive_path(backup_id).write_bytes(b'x' * 100)
        self.storage.index[backup_id] = {
            'id': backup_id, 'type': 'manual', 'created': f'2026-11-{n:02d}T02:00:00Z',
            'note': '排程備份' if scheduled else '手動', 'apps': [{'id': a, 'name': a} for a in apps], 'size': 100,
            'sha256': '0' * 64, 'key_id': 'AAAA-BBBB-CCCC-DDDD', 'include_images': False, 'filename': 'x.tar',
            'source': None, 'verified': verified, 'inspected': True}
        if scheduled:
            schedule.register_run(self.paths, backup_id, f'j202611{n:02d}T020000Z-0000000{n % 10}', None, 'run-now')
        return backup_id

    def test_the_manual_policy_ignores_scheduled_backups_and_the_scheduled_rule_ignores_manual_ones(self):
        manual = [self.make(n) for n in (1, 2, 3)]
        scheduled = [self.make(n, scheduled=True) for n in (4, 5, 6)]
        ids, _ = schedule.scheduled_ids(self.paths)
        backups = self.storage.list_backups()
        policy = retention.validate_policy({'default_keep_last': 1, 'apps': {}})
        plan = retention.plan(backups, policy, {}, scheduled=ids)
        self.assertEqual([c['id'] for c in plan['candidates']], [manual[1], manual[0]])
        self.assertFalse(any(c['scheduled'] for c in plan['candidates']))
        rule = retention.plan(backups, {'schema': 1, 'default_keep_last': 2, 'apps': {}}, {}, scheduled=ids,
                              pool='scheduled', label=retention.SCHEDULE_LABEL)
        self.assertEqual([c['id'] for c in rule['candidates']], [scheduled[0]])
        self.assertTrue(rule['candidates'][0]['scheduled'])
        self.assertIn('超出排程備份的保留份數', rule['candidates'][0]['reason'])
        # retention-plan keeps its candidates in the manual pool; usage counts the scheduled ones apart.
        retention.save_policy(self.paths, policy, trusted_uid=os.geteuid())
        command = retention.plan_command(self.paths, self.storage, None, trusted_uid=os.geteuid())
        self.assertEqual([c['id'] for c in command['candidates']], [manual[1], manual[0]])
        usage = {row['id']: row for row in command['usage']['apps']}
        self.assertEqual(usage['woowbk-demo']['types'], {'manual': 3, 'safety': 0, 'uploaded': 0, 'scheduled': 3})
        # A manual backup job applies its policy to its pool only.
        deleted = retention.enforce_after_backup(self.paths, self.storage, ['woowbk-demo'], exclude=[manual[2]],
                                                 log=lambda _m: None, audit=self.audit.append,
                                                 trusted_uid=os.geteuid())
        self.assertEqual(deleted, [manual[1], manual[0]])
        self.assertTrue(set(scheduled) <= {b['id'] for b in self.storage.list_backups()})

    def test_the_scheduled_rule_keeps_protections_and_does_not_count_failed_verifications(self):
        older = self.make(1, scheduled=True)
        bad = self.make(2, scheduled=True, verified={'at': '2026-11-03T00:00:00Z', 'ok': False, 'deep': True})
        pinned = self.make(3, scheduled=True)
        newest = self.make(4, scheduled=True)
        record = self.store().create('restore', {'backup_id': pinned, 'apps': ['woowbk-demo']})
        record['state'] = 'running'
        self.store().save(record)
        self.active_units.add(record['unit'])
        deleted = retention.enforce_schedule(self.paths, self.storage, ['woowbk-demo'], 2, exclude=[newest],
                                             log=lambda _m: None, audit=self.audit.append)
        self.assertEqual(deleted, [bad, older], 'the failed one does not count; the source of a running job stays')
        self.assertEqual(set(self.storage.index), {pinned, newest})
        self.assertTrue(all(line.endswith('reason=schedule') for line in self.audit))

    def test_an_unreadable_registry_protects_every_manual_backup(self):
        manual = self.make(1)
        scheduled = self.make(2, scheduled=True)
        schedule.state_path(self.paths).write_text('{"schema": 1, "registry": []}')
        protected = retention.protected_backups(self.paths, self.storage.list_backups())
        self.assertEqual(set(protected), {manual, scheduled})
        self.assertIn('無法分辨手動與排程備份', protected[manual])
        self.assertEqual(retention.enforce_schedule(self.paths, self.storage, ['woowbk-demo'], 1), [])
        retention.save_policy(self.paths, {'default_keep_last': 1, 'apps': {}}, trusted_uid=os.geteuid())
        logs = []
        self.assertEqual(retention.enforce_after_backup(self.paths, self.storage, ['woowbk-demo'], log=logs.append,
                                                        trusted_uid=os.geteuid()), [])
        self.assertIn('schedule-state.json', logs[-1])
        self.assertEqual(set(self.storage.index), {manual, scheduled})

    def test_the_preview_counts_the_next_run_as_the_newest(self):
        made = [self.make(n, scheduled=True) for n in (1, 2, 3)]
        plan = retention.schedule_plan(self.paths, self.storage, ['woowbk-demo'], 3)
        self.assertEqual([c['id'] for c in plan['candidates']], [made[0]])
        self.assertIn('第 4 新（保留最新 3 份）', plan['candidates'][0]['reason'])
        self.assertEqual(retention.schedule_plan(self.paths, self.storage, ['woowbk-demo'], None)['candidates'], [])
        self.assertEqual(retention.schedule_plan(self.paths, self.storage, ['woowbk-two'], 1)['candidates'], [],
                         'other apps keep theirs')


# ---------------------------------------------------------------- the commands

class CommandTests(ScheduleCase):
    REQUEST = {'enabled': True, 'days': list(schedule.DAYS), 'time': '03:00', 'apps': 'all', 'include_images': False,
               'keep_last': 7}

    def test_schedule_get_shape_and_defaults(self):
        response = self.ok(['schedule-get'])
        self.assertEqual(set(response), {'ok', 'schedule', 'next_runs', 'timer', 'last_run', 'waiting', 'attention',
                                         'events', 'timezone', 'gate'})
        self.assertEqual(response['schedule'], {'enabled': False, 'days': list(schedule.DAYS), 'time': '03:00',
                                                'apps': 'all', 'include_images': False, 'keep_last': 7, 'updated': None,
                                                'armed_at': None, 'saved': False, 'problem': None})
        self.assertEqual((response['next_runs'], response['last_run'], response['waiting'], response['attention'],
                          response['events']), ([], None, None, None, []))
        self.assertEqual(response['timer'], {'enabled': True, 'active': True, 'last_tick_age': None})
        self.assertEqual(response['timezone'], {'name': 'Asia/Taipei', 'utc_offset': '+08:00'})
        self.assertEqual(response['gate'], {'encrypt': True, 'device_key': True, 'kit_confirmed': True,
                                            'blocked': None})
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        self.tick()
        response = self.ok(['schedule-get'])
        self.assertEqual(response['next_runs'], [
            {'at': NEXT, 'local': '2026-11-18T03:00', 'utc_offset': '+08:00'},
            {'at': '2026-11-18T19:00:00Z', 'local': '2026-11-19T03:00', 'utc_offset': '+08:00'},
            {'at': '2026-11-19T19:00:00Z', 'local': '2026-11-20T03:00', 'utc_offset': '+08:00'}])
        self.assertEqual(response['timer']['last_tick_age'], 0)
        self.assertEqual(set(response['last_run']), {'slot', 'local', 'job_id', 'trigger', 'state', 'result',
                                                     'backup_id', 'started', 'finished', 'skipped_apps', 'error'})
        last = response['last_run']
        self.assertEqual((last['local'], last['result']), ('2026-11-17T03:00', 'queued'))

    def test_schedule_set_preview_saves_nothing_and_confirm_saves_and_audits(self):
        preview = self.ok(['schedule-set'], {'schedule': self.REQUEST})
        self.assertEqual(set(preview), {'ok', 'saved', 'schedule', 'next_runs', 'retention', 'timezone'})
        self.assertFalse(preview['saved'])
        self.assertFalse((Path(self.paths.config) / schedule.FILE).exists())
        self.assertEqual(preview['schedule']['armed_at'], '2026-11-16T19:02:00Z')
        self.assertEqual(preview['next_runs'][0]['at'], NEXT, 'today\'s 03:00 is before arming')
        self.assertEqual(preview['retention'], {'keep_last': 7, 'apps': ['woowbk-demo', 'woowbk-two'], 'delete': [],
                                                'blocked': [], 'freed_bytes': 0})
        self.assertEqual(self.audit, [])
        saved = self.ok(['schedule-set'], {'schedule': self.REQUEST, 'confirm': True})
        self.assertTrue(saved['saved'])
        self.assertTrue(saved['schedule']['saved'])
        path = Path(self.paths.config) / schedule.FILE
        self.assertEqual(oct(path.stat().st_mode & 0o777), '0o644')
        self.assertEqual(self.audit, ['schedule-set enabled=true days=mon,tue,wed,thu,fri,sat,sun time=03:00 apps=all '
                                      'include_images=false keep_last=7 previous_enabled=false loginuid='
                                      + self.audit[0].rsplit('loginuid=', 1)[1]])
        self.assertTrue(self.ok(['schedule-get'])['schedule']['enabled'])
        off = self.ok(['schedule-set'], {'schedule': dict(self.REQUEST, enabled=False), 'confirm': True})
        self.assertEqual((off['schedule']['enabled'], off['next_runs']), (False, []))

    def test_schedule_set_preview_lists_what_the_next_run_would_delete(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z', keep_last=7)
        for minute in ('02', '07'):
            self.write_schedule(armed_at='2026-11-16T18:00:00Z')
            self.set_state(handled=None)
            out = self.ok(['schedule-run-now'], {'request_id': f'run-now-000{minute}'})
            self.ok(['run-job', out['job_id']])
        made = sorted(self.storage.index)
        preview = self.ok(['schedule-set'], {'schedule': dict(self.REQUEST, keep_last=1)})
        self.assertEqual([item['id'] for item in preview['retention']['delete']], made[::-1])
        self.assertTrue(all(item['scheduled'] for item in preview['retention']['delete']))
        self.assertEqual(len(self.storage.index), 2, 'a preview deletes nothing')
        self.assertEqual(self.ok(['schedule-set'], {'schedule': dict(self.REQUEST, apps=['woowbk-two'], keep_last=1)}
                                 )['retention']['apps'], ['woowbk-two'])

    def test_turning_on_needs_a_device_key_and_a_saved_kit_while_encrypting(self):
        self.keys.device = dataclasses.replace(self.keys.device, kit_confirmed=False)
        error = self.error(['schedule-set'], {'schedule': self.REQUEST})
        self.assertEqual(error['code'], 'invalid-request')
        self.assertEqual(error['details'], {'reason': 'kit-unconfirmed', 'field': 'schedule.enabled'})
        self.assertEqual(error['message'], '開啟排程備份前，請先保存緊急金鑰。')
        self.assertEqual(self.error(['schedule-set'], {'schedule': self.REQUEST, 'confirm': True})['details']['reason'],
                         'kit-unconfirmed')
        self.assertEqual(self.ok(['schedule-get'])['gate']['blocked'], 'kit-unconfirmed')
        self.assertTrue(self.ok(['schedule-set'], {'schedule': dict(self.REQUEST, enabled=False), 'confirm': True})
                        ['saved'], 'turning off or saving it off is never blocked')
        self.keys.device = None
        self.assertEqual(self.error(['schedule-set'], {'schedule': self.REQUEST})['code'], 'no-device-key')
        self.encrypt = False  # 預設加密備份 off: no key and no kit needed
        self.assertTrue(self.ok(['schedule-set'], {'schedule': self.REQUEST, 'confirm': True})['saved'])
        self.assertEqual(self.ok(['schedule-get'])['gate'], {'encrypt': False, 'device_key': False,
                                                             'kit_confirmed': False, 'blocked': None})

    def test_the_new_commands_are_strict(self):
        cases = [
            ('schedule-set', {}), ('schedule-set', {'schedule': self.REQUEST, 'extra': 1}),
            ('schedule-set', {'schedule': 'on'}), ('schedule-set', {'schedule': self.REQUEST, 'confirm': 'yes'}),
            ('schedule-set', {'schedule': dict(self.REQUEST, time='03:02')}),
            ('schedule-set', {'schedule': dict(self.REQUEST, armed_at='2026-11-01T00:00:00Z')}),
            ('schedule-run-now', {}), ('schedule-run-now', {'request_id': 'short'}),
            ('schedule-run-now', {'request_id': 'run-now-0001', 'apps': ['woowbk-demo']}),
        ]
        for command, request in cases:
            with self.subTest(command=command, request=str(request)[:80]):
                self.assertEqual(self.error([command], request)['code'], 'invalid-request')
        self.assertEqual(self.error(['schedule-set'], {'schedule': dict(self.REQUEST, apps=['nope-app'])})['code'],
                         'app-not-in-catalog')
        self.assertEqual(self.error(['schedule-set'], raw='')['code'], 'invalid-request')
        self.assertEqual(self.error(['schedule-tick', 'now'])['code'], 'invalid-request', 'argv only, no arguments')
        self.assertEqual(self.error(['schedule-get', 'x'])['code'], 'invalid-request')
        self.assertTrue(self.ok(['schedule-get']))  # reads no stdin (ExplodingStdin)
        self.assertTrue(self.ok(['schedule-tick']))

    def test_run_now_uses_the_saved_settings_counts_as_scheduled_and_is_not_kit_gated(self):
        self.assertEqual(self.error(['schedule-run-now'], {'request_id': 'run-now-0001'})['details']['reason'],
                         'not-saved')
        self.write_schedule(enabled=False, apps=['woowbk-demo'], keep_last=3)
        self.keys.device = dataclasses.replace(self.keys.device, kit_confirmed=False)
        started = self.ok(['schedule-run-now'], {'request_id': 'run-now-0001'})
        self.assertFalse(started['deduplicated'])
        params = self.store().get(started['job_id'])['params']
        self.assertEqual(params['schedule'], {'slot': None, 'trigger': 'run-now', 'keep_last': 3})
        self.assertEqual((params['apps'], params['note']), (['woowbk-demo'], '排程備份'))
        self.assertEqual(self.ok(['schedule-run-now'], {'request_id': 'run-now-0001'})['deduplicated'], True)
        self.assertEqual(self.error(['schedule-run-now'], {'request_id': 'run-now-0002'})['code'], 'busy')
        self.assertEqual(self.state()['last_run']['trigger'], 'run-now')
        self.assertEqual(self.lines('schedule-run'), [(f'schedule-run slot=- job={started["job_id"]} trigger=run-now '
                                                       'apps=woowbk-demo encrypted=true', False)])
        self.ok(['run-job', started['job_id']])
        backup_id = self.store().get(started['job_id'])['result']['backup_id']
        self.assertIs(next(b for b in self.ok(['list'])['backups'] if b['id'] == backup_id)['scheduled'], True)
        self.keys.device = None
        self.assertEqual(self.error(['schedule-run-now'], {'request_id': 'run-now-0003'})['code'], 'no-device-key')
        os.chmod(Path(self.paths.config) / schedule.FILE, 0o666)
        self.assertEqual(self.error(['schedule-run-now'], {'request_id': 'run-now-0004'})['details']['reason'],
                         'settings-problem')

    def test_status_schedule_shape_and_every_attention_code(self):
        status = self.ok(['status'])['schedule']
        self.assertEqual(set(status), {'enabled', 'saved', 'problem', 'days', 'time', 'apps', 'include_images',
                                       'keep_last', 'next_run', 'last_run', 'waiting', 'attention', 'timezone',
                                       'timer'})
        self.assertEqual((status['enabled'], status['attention']), (False, None))
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        path = Path(self.paths.config) / schedule.FILE

        def attention():
            return self.ok(['status'])['schedule']['attention']

        os.chmod(path, 0o666)
        self.assertEqual(attention()['code'], 'settings-problem')
        os.chmod(path, 0o644)
        self.assertEqual(attention()['code'], 'timer-inactive', 'no tick yet and the device is up for a day')
        schedule.touch_tick(self.paths, at('2026-11-16T18:58:00Z'))
        self.assertIsNone(attention(), 'the slot is 2 minutes late: not overdue')
        self.timer['active'] = False
        self.assertEqual(attention(), {'code': 'timer-inactive', 'message': schedule.TIMER_MESSAGE})
        self.timer['active'] = True
        self.env = env_at('2026-11-16T19:40:00Z')
        schedule.touch_tick(self.paths, at('2026-11-16T19:39:00Z'))
        overdue = attention()
        self.assertEqual((overdue['code'], overdue['slot']), ('overdue', SLOT))
        self.assertIn('2026-11-17 03:00', overdue['message'])
        self.world.fail_backup.add('woowbk-demo')
        self.set_state(handled=PREVIOUS)
        job_id = self.tick('2026-11-16T19:41:00Z')['job_id']  # 41 minutes late: caught up
        self.assertEqual(self.ok(['run-job', job_id])['state'], 'failed')
        failed = attention()
        self.assertEqual((failed['code'], failed['job_id']), ('failed', job_id))
        self.assertTrue(failed['message'].startswith('上次排程備份失敗：pg_dump 執行失敗'))
        self.tick('2026-11-18T16:30:00Z')  # no tick saw 2026-11-18 03:00 and the next slot is near: missed
        missed = attention()
        self.assertEqual((missed['code'], missed['slot'], missed['reason']), ('missed', NEXT, 'missed'))
        self.assertIn('2026-11-18 03:00 的排程備份沒有執行', missed['message'])
        self.world.fail_backup.clear()
        self.keys.device = None
        self.tick('2026-11-18T19:02:00Z')
        skipped = attention()
        self.assertEqual((skipped['code'], skipped['reason']), ('skipped', 'no-key'))
        self.assertIn('沒有加密金鑰', skipped['message'])
        events = self.ok(['jobs'])['schedule_events']
        self.assertEqual([event['kind'] for event in events][:2], ['no-key', 'missed'])
        self.assertEqual(set(events[0]), {'at', 'kind', 'slot', 'first', 'count', 'job_id', 'message', 'not_run'})
        self.assertTrue(events[0]['not_run'])
        self.assertFalse(next(event for event in events if event['kind'] == 'failed')['not_run'])
        status = self.ok(['status'])['schedule']
        self.assertEqual(status['next_run'], {'at': '2026-11-19T19:00:00Z', 'local': '2026-11-20T03:00',
                                              'utc_offset': '+08:00'})

    def test_status_shows_the_slot_waiting_for_another_job(self):
        self.write_schedule(armed_at='2026-11-16T18:00:00Z')
        busy = self.busy_job()
        self.tick()
        schedule.touch_tick(self.paths, self.env.now)
        status = self.ok(['status'])['schedule']
        self.assertEqual(status['waiting'], {'slot': SLOT, 'local': '2026-11-17T03:00',
                                             'since': '2026-11-16T19:02:00Z', 'job_id': busy['id']})
        self.assertIsNone(status['attention'], 'waiting is not a problem')
        self.assertEqual(self.ok(['jobs'])['schedule_events'][0]['kind'], 'waiting')


if __name__ == '__main__':
    unittest.main()
