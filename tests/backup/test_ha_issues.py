"""The issue model of an HA import (haissues.py; CONTRACT section 7 "HaIssue", DESIGN "HAOS parity" B1-B3, C1): the shape,
the confirmation keys, the lists' limits, the sink of a check and of a conversion, what an exception becomes, versions
that are no gate (CM-01, CM-02) and that every id is declared once, with the level it is used with. Team E2."""
import ast
import contextlib
import errno
import hashlib
import io
import json
import unittest
from pathlib import Path

from woowbackup import cli, errors, flows, haapps, haimport, haissues, hacommon, jobs
from woowbackup.errors import BackupError
from woowbackup.haissues import Issue, Names, Sink

ENGINE = Path(haissues.__file__).resolve().parent
APP = 'emqx'


def confirm(items=('rule_a',), message='會被取代', database=None):
    return Issue('emqx.rules', 'confirm', message, items, database=database)


class ShapeTests(unittest.TestCase):
    def test_the_four_levels_and_their_fields(self):
        stop = Issue('odoo.no-database', 'stop', '沒有資料庫。', ['a'], action='請重新備份。', database='prod')
        self.assertEqual(stop.view('odoo'), {'id': 'odoo.no-database', 'level': 'stop', 'message': '沒有資料庫。',
                                             'items': ['a'], 'more': 0, 'action': '請重新備份。', 'database': 'prod'})
        line = confirm()
        self.assertEqual(line.view(APP), {'id': 'emqx.rules', 'level': 'confirm', 'message': '會被取代',
                                          'items': ['rule_a'], 'more': 0, 'key': line.key(APP)})
        for level in ('auto', 'notice'):
            self.assertEqual(Issue('emqx.version', level, '讀不到版本。', action='x').view(APP),
                             {'id': 'emqx.version', 'level': level, 'message': '讀不到版本。', 'items': [], 'more': 0})

    def test_a_wrong_id_or_level_is_a_programming_error(self):
        for issue_id in ('emqx', 'Emqx.rules', 'emqx.', '.rules', 'emqx.rules.more', 'e.rules', 'emqx rules', 7, None,
                         'emqx.' + 'x' * 41, 'e' * 25 + '.rules'):
            with self.subTest(issue_id=issue_id), self.assertRaises(ValueError):
                Issue(issue_id, 'stop', 'x')
        for level in ('warn', 'STOP', '', None):
            with self.subTest(level=level), self.assertRaises(ValueError):
                Issue('emqx.rules', level, 'x')

    def test_texts_are_cut_and_cannot_reorder_or_break_the_page(self):
        hostile = 'a\nb\x1b[31m‮⁦​﻿1\ud800c'
        view = Issue('emqx.rules', 'stop', '句' * 400, [hostile, 'n' * 200], action='做' * 300).view(APP)
        self.assertEqual((len(view['message']), len(view['action']), len(view['items'][1])),
                         (haissues.MAX_MESSAGE, haissues.MAX_ACTION, haissues.MAX_ITEM))
        for ch in '\n\x1b‮⁦​﻿\ud800':
            self.assertNotIn(ch, view['items'][0])
        self.assertTrue(view['items'][0].startswith('a b'))
        json.dumps(view, ensure_ascii=False).encode('utf-8')
        self.assertEqual(Issue('emqx.rules', 'stop', None).message, '')

    def test_only_the_first_names_are_listed_and_the_rest_counted(self):
        view = confirm([f'r{i}' for i in range(27)]).view(APP)
        self.assertEqual((view['items'], view['more']), ([f'r{i}' for i in range(haissues.MAX_ITEMS)], 7))
        self.assertEqual(Issue('emqx.rules', 'notice', 'x', 'single').view(APP)['items'], ['single'], 'a text is one name')

    def test_an_ha_key_never_reaches_a_record(self):
        key = 'Opaque Old Password'
        with jobs.masked(key):
            view = Issue('emqx.rules', 'stop', f'打不開 {key}', [f'x{key}'], action=f'用 {key}').view(APP)
            fields = haissues.check_fields(APP, [Issue('emqx.rules', 'stop', f'打不開 {key}')])
        self.assertNotIn(key, json.dumps([view, fields], ensure_ascii=False))
        self.assertNotIn(key, repr(Issue('emqx.rules', 'stop', key, [key])))

    def test_legacy_sentences_become_stops_and_notices(self):
        found = haissues.from_legacy(['不能搬。'], ['提醒。'], database='prod')
        self.assertEqual([(i.id, i.level, i.message, i.database) for i in found],
                         [('legacy.blocker', 'stop', '不能搬。', 'prod'), ('legacy.warning', 'notice', '提醒。', 'prod')])
        self.assertEqual(haissues.from_legacy(None, None), [])


class KeyTests(unittest.TestCase):
    def test_the_documented_form(self):
        body = json.dumps(['odoo', 'odoo.missing', 'prod', ['a', 'b']], ensure_ascii=False, separators=(',', ':'))
        expected = 'odoo.missing:' + hashlib.sha256(body.encode()).hexdigest()[:16]
        self.assertEqual(Issue('odoo.missing', 'confirm', 'x', ['b', 'a'], database='prod').key('odoo'), expected)
        self.assertTrue(haissues.valid_key(expected))

    def test_one_more_name_is_another_key_a_changed_number_is_not(self):
        key = confirm(['a', 'b']).key(APP)
        self.assertEqual(confirm(['b', 'a'], message='現在是 12 MiB').key(APP), key, 'order and message do not count')
        for other in (confirm(['a', 'b', 'c']), confirm(['a']), confirm(['a', 'a', 'b']), confirm(['a', 'b'], database='x'),
                      Issue('emqx.other', 'confirm', 'x', ['a', 'b'])):
            self.assertNotEqual(other.key(APP), key)
        self.assertNotEqual(confirm(['a', 'b']).key('odoo'), key, 'another app')

    def test_names_beyond_what_is_shown_still_count(self):
        many = [f'r{i}' for i in range(50)]
        self.assertNotEqual(confirm(many).key(APP), confirm([*many[:-1], 'other']).key(APP))
        self.assertNotEqual(confirm(['n' * 200 + 'a']).key(APP), confirm(['n' * 200 + 'b']).key(APP))
        self.assertNotEqual(confirm(['a​']).key(APP), confirm(['a ']).key(APP), 'names as they are, not as shown')
        self.assertTrue(haissues.valid_key(confirm(['\ud800']).key(APP)), 'an undecodable name')

    def test_names_collector_is_bounded_and_complete(self):
        small = Names(['b', 'a'])
        self.assertEqual(confirm(small).key(APP), confirm(['a', 'b']).key(APP), 'the same key as a plain list')
        names = [f'data/{i}' for i in range(3 * Names.MAX_EXACT)]
        big, again = Names(names), Names(reversed(names))
        self.assertEqual((len(big), len(big._exact), len(big.first)), (3000, Names.MAX_EXACT, haissues.MAX_ITEMS))
        self.assertEqual(confirm(big).key(APP), confirm(again).key(APP), 'the order of a large list does not count')
        self.assertNotEqual(confirm(big).key(APP), confirm(Names([*names, 'x'])).key(APP))
        self.assertNotEqual(confirm(big).key(APP), confirm(Names([*names[:-1], 'x'])).key(APP))
        self.assertEqual(confirm(big).view(APP)['more'], 3000 - haissues.MAX_ITEMS)

    def test_valid_keys(self):
        for good in ('emqx.no-authentication:1f0c52ab9d3e4f60', 'a.bc:0123456789abcdef'):
            self.assertTrue(haissues.valid_key(good), good)
        for bad in ('emqx.x:1f0c', 'EMQX.x:1f0c52ab9d3e4f60', 'emqx.x:1F0C52AB9D3E4F60', ':1f0c52ab9d3e4f60', None, 5,
                    'x' * 80 + ':1f0c52ab9d3e4f60', 'emqx.x:1f0c52ab9d3e4f60\n'):
            self.assertFalse(haissues.valid_key(bad), bad)

    def test_missing_confirmations(self):
        first, second = confirm(['a']), confirm(['b'])
        notice = Issue('emqx.version', 'notice', 'x')
        self.assertEqual(haissues.missing(APP, [first, notice, second], [first.key(APP)]), [second])
        self.assertEqual(haissues.missing(APP, [first, second], None), [first, second])
        error = haissues.confirmation_required({APP: [second], 'odoo': []}, '還有事情要確認。')
        self.assertEqual((error.code, error.issues), ('confirmation-required', [second]))
        self.assertEqual(error.as_dict()['details'], {'apps': {APP: [second.view(APP)]}})


class ListTests(unittest.TestCase):
    def test_order_and_count_limit(self):
        issues = ([Issue('emqx.version', 'notice', f'n{i}') for i in range(60)]
                  + [Issue('emqx.wait', 'auto', 'a')] + [confirm()] + [Issue('emqx.broken', 'stop', 's')])
        rows = haissues.views(APP, issues)
        self.assertEqual([row['level'] for row in rows[:3]], ['stop', 'confirm', 'auto'])
        self.assertEqual(len(rows), haissues.MAX_ISSUES)
        self.assertEqual((rows[-1]['id'], rows[-1]['message']),
                         ('shared.more-lines', haissues.MORE_LINES.format(count=len(issues) - len(rows) + 1)))

    def test_a_stop_or_a_confirm_is_never_dropped(self):
        issues = [Issue('emqx.rules', 'confirm', f'c{i}', [f'x{i}']) for i in range(50)] + [
            Issue('emqx.version', 'notice', 'n')]
        rows = haissues.views(APP, issues)
        self.assertEqual(sum(1 for row in rows if row['level'] == 'confirm'), 50)
        self.assertEqual({row['key'] for row in rows if row['level'] == 'confirm'}, {i.key(APP) for i in issues[:50]})
        self.assertEqual(rows[-1]['id'], 'shared.more-lines')

    def size(self, rows):
        return len(json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode())

    def test_the_bytes_limit_shrinks_names_first(self):
        long = ['字' * 120 for _ in range(20)]
        issues = [Issue('emqx.rules', 'confirm', f'c{i}', long) for i in range(20)] + [
            Issue('emqx.version', 'notice', '提' * 300, long) for _ in range(19)]
        rows = haissues.views(APP, issues)
        self.assertLessEqual(self.size(rows), haissues.MAX_BYTES)
        self.assertEqual(len(rows), len(issues), 'no line is dropped while fewer names are enough')
        self.assertTrue(all(len(row['items']) + row['more'] == 20 for row in rows), 'every name is still counted')
        lines = [row for row in rows if row['level'] == 'confirm']
        self.assertGreater(len(lines[0]['items']), len(rows[-1]['items']), 'the reminders give up their names first')
        self.assertEqual({row['key'] for row in lines}, {i.key(APP) for i in issues[:20]}, 'the key covers all names')

    def test_then_the_last_notices_are_dropped_and_counted(self):
        issues = [Issue('emqx.rules', 'confirm', '𠀀' * 300, [f'x{i}']) for i in range(26)] + [
            Issue('emqx.version', 'notice', '𠀀' * 300) for _ in range(14)]
        rows = haissues.views(APP, issues)
        self.assertLessEqual(self.size(rows), haissues.MAX_BYTES)
        self.assertEqual(sum(1 for row in rows if row['level'] == 'confirm'), 26)
        self.assertEqual(rows[-1]['id'], 'shared.more-lines')
        self.assertEqual(int(''.join(ch for ch in rows[-1]['message'] if ch.isdigit())) + len(rows) - 1, len(issues))
        only = [Issue('emqx.rules', 'confirm', '確' * 300, [f'x{i}']) for i in range(45)]
        self.assertEqual(len(haissues.views(APP, only)), 45, 'too many lines to confirm: all of them are sent anyway')

    def test_small_lists_are_untouched(self):
        issues = [confirm(), Issue('emqx.version', 'notice', 'n')]
        self.assertEqual(haissues.views(APP, issues), [issue.view(APP) for issue in issues])
        self.assertEqual(haissues.views(APP, []), [])


class CheckFieldTests(unittest.TestCase):
    def test_old_and_new_fields(self):
        issues = [Issue('emqx.version', 'notice', '提醒'), Issue('emqx.wait', 'auto', '自動')]
        fields = haissues.check_fields(APP, issues)
        self.assertEqual(set(fields), {'importable', 'issues', 'ok', 'blockers', 'warnings'})
        self.assertEqual((fields['importable'], fields['ok'], fields['blockers'], fields['warnings']),
                         (True, True, [], ['提醒', '自動']))
        fields = haissues.check_fields(APP, issues + [confirm()])
        self.assertEqual((fields['importable'], fields['ok'], fields['blockers']), (True, False, ['會被取代']),
                         'an older page cannot confirm, so it must not import')
        fields = haissues.check_fields(APP, [Issue('emqx.broken', 'stop', '不能。', action='請修。'), confirm()])
        self.assertEqual((fields['importable'], fields['ok'], fields['blockers']),
                         (False, False, ['不能。請修。', '會被取代']), 'it shows no action of its own')
        fields = haissues.check_fields(APP, [Issue('failure.job-failed', 'stop', '失敗了。', action='再試。')])
        self.assertEqual(fields['blockers'], ['失敗了。'])

    def test_databases(self):
        rows = [{'value': 'prod', 'label': 'prod'}, {'value': 'test', 'label': 'test'}, {'value': 'x', 'ok': False}]
        issues = [Issue('odoo.modules', 'stop', '缺模組', database='test')]
        fields = haissues.check_fields('odoo', issues, {'database': rows, 'addon': []})
        self.assertEqual(fields['choices'], {'database': [
            {'value': 'prod', 'label': 'prod', 'ok': True, 'default': True}, {'value': 'test', 'label': 'test', 'ok': False},
            {'value': 'x', 'label': 'x', 'ok': False}]}, 'the only one that can move is chosen already (HA-14)')
        self.assertEqual((fields['importable'], fields['ok'], fields['blockers']), (True, True, []),
                         'a stop of one database is in the section already')
        fields = haissues.check_fields('odoo', issues, {'database': [rows[1]]})
        self.assertFalse(fields['importable'], 'no database can move')
        two = haissues.check_fields('odoo', [], {'database': rows[:2]})['choices']['database']
        self.assertFalse(any('default' in row for row in two), 'two can move: the customer chooses')
        line = Issue('odoo.modules', 'confirm', '缺模組', ['m'], database='prod')
        fields = haissues.check_fields('odoo', [line], {'database': rows[:2]})
        self.assertEqual((fields['importable'], fields['ok'], fields['blockers']), (True, False, ['prod：缺模組']))
        self.assertTrue(all(row['ok'] for row in fields['choices']['database']), 'a line to confirm does not stop it')

    def test_old_text_lists_are_bounded(self):
        issues = haissues.from_legacy(['長' * 5000] * 60, ['提' * 5000] * 60)
        fields = haissues.check_fields(APP, issues)
        for name in ('blockers', 'warnings'):
            size = len(json.dumps(fields[name], ensure_ascii=False).encode())
            self.assertLessEqual(size, haissues.MAX_TEXT_BYTES + haissues.MAX_TEXT * 3)
            self.assertTrue(fields[name])


class SinkTests(unittest.TestCase):
    def test_a_check_collects_everything(self):
        sink = Sink(APP)
        sink.stop('emqx.broken', '不能')
        sink.confirm('emqx.rules', '會被取代', ['a'])
        sink.auto('emqx.wait', '自動')
        sink.notice('emqx.version', '提醒')
        self.assertEqual([i.level for i in sink.found], ['stop', 'confirm', 'auto', 'notice'])
        self.assertFalse(sink.converting)

    def test_a_conversion_stops_at_a_stop(self):
        sink = Sink(APP, [])
        with self.assertRaises(BackupError) as caught:
            sink.stop('emqx.broken', '不能。', action='請修。')
        self.assertEqual((caught.exception.code, caught.exception.message), ('incompatible', '不能。'))
        self.assertEqual([i.id for i in caught.exception.issues], ['emqx.broken'])
        self.assertIs(caught.exception.issues[0], sink.found[0])

    def test_a_conversion_needs_every_confirm_line(self):
        """G1: not confirmed -> only that app stops; confirmed -> it goes on; one more name -> confirm again."""
        line = confirm(['a', 'b'])
        sink = Sink(APP, [])
        with self.assertRaises(BackupError) as caught:
            sink.confirm('emqx.rules', '會被取代', ['a', 'b'])
        self.assertEqual(caught.exception.code, 'confirmation-required')
        self.assertEqual(caught.exception.message, '匯入前還有事情要確認：會被取代')
        self.assertEqual(caught.exception.details['apps'], {APP: [line.view(APP)]})
        sink = Sink(APP, [line.key(APP)])
        sink.confirm('emqx.rules', '會被取代（大小變了）', ['b', 'a'])
        self.assertEqual(sink.confirmed(), [{'app_id': APP, 'id': 'emqx.rules', 'items': ['b', 'a']}])
        with self.assertRaises(BackupError) as caught:
            Sink(APP, [line.key(APP)]).confirm('emqx.rules', '會被取代', ['a', 'b', 'c'])
        self.assertEqual(caught.exception.message, '這次匯入和檢查時看到的不同，請再確認一次：會被取代')
        with self.assertRaises(BackupError):
            Sink('odoo', [line.key(APP)]).confirm('emqx.rules', '會被取代', ['a', 'b'])

    def test_another_database_does_not_matter_to_a_conversion(self):
        sink = Sink('odoo', [], database='prod')
        self.assertIsNone(sink.stop('odoo.modules', '缺模組', database='test'))
        self.assertIsNone(sink.confirm('odoo.modules', '缺模組', ['x'], database='test'))
        self.assertEqual(sink.found, [])
        with self.assertRaises(BackupError):
            sink.stop('odoo.modules', '缺模組', database='prod')

    def test_refuse_stops_the_check_too(self):
        for acknowledged in (None, []):
            sink = Sink(APP, acknowledged)
            with self.assertRaises(BackupError) as caught:
                sink.refuse('emqx.broken', '讀不出來。', action='請重新備份。', code='corrupt-archive')
            self.assertEqual((caught.exception.code, sink.found), ('corrupt-archive', []))
            self.assertEqual(len(haissues.combine(sink.found, caught.exception.issues)), 1)

    def test_auto_lines_are_logged(self):
        lines = []
        sink = Sink(APP, log=lines.append)
        sink.auto('emqx.wait', '已先啟動資料庫')
        sink.extend([Issue('emqx.version', 'notice', '提醒')])
        self.assertEqual(lines, ['自動處理：已先啟動資料庫'])

    def test_combine_keeps_every_issue_once(self):
        sink = Sink(APP, [])
        sink.notice('emqx.version', '提醒')
        with self.assertRaises(BackupError) as caught:
            sink.stop('emqx.broken', '不能')
        found = haissues.combine(sink.found, haissues.from_error(caught.exception))
        self.assertEqual([i.id for i in found], ['emqx.version', 'emqx.broken'])


class FailureTests(unittest.TestCase):
    """DESIGN C1: what an app's exception becomes, and what ends the whole job."""

    def quiet(self, error):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            found = haissues.app_failure(error)
        return found, err.getvalue()

    def test_every_error_code_stops_only_its_app(self):
        for code in sorted(errors.CODES - {'busy'}):
            with self.subTest(code=code):
                found, _err = self.quiet(BackupError(code, '原因。'))
                self.assertEqual([(i.id, i.level, i.message) for i in found], [(f'failure.{code}', 'stop', '原因。')])

    def test_anything_unexpected_stops_only_its_app_and_is_told_in_the_journal_only(self):
        for error in (RuntimeError('boom secret detail'), KeyError('x'), MemoryError(), OSError(errno.EIO, 'bad disk'),
                      ValueError('x'), RecursionError(), AssertionError('x'), UnicodeDecodeError('utf-8', b'x', 0, 1, 'y')):
            with self.subTest(error=type(error).__name__):
                found, journal = self.quiet(error)
                self.assertEqual([(i.id, i.message) for i in found], [('failure.internal-error', haissues.UNEXPECTED)])
                self.assertNotIn('secret detail', json.dumps([i.view(APP) for i in found], ensure_ascii=False))
                self.assertIn(type(error).__name__, journal)

    def test_what_ends_the_whole_job(self):
        wide = haissues.job_wide(BackupError('wrong-key', '金鑰不正確。'))
        for error in (wide, BackupError('busy', '忙碌'), flows.Cancelled(), jobs.Terminated(15), KeyboardInterrupt(),
                      SystemExit(1), OSError(errno.ENOSPC, 'x'), OSError(errno.EDQUOT, 'x'),
                      haissues.job_wide(BackupError('insufficient-space', '看門狗'))):
            with self.subTest(error=repr(error)):
                self.assertIsNone(haissues.app_failure(error))
                self.assertTrue(haissues.ends_job(error))
        self.assertFalse(haissues.ends_job(BackupError('insufficient-space', '這個應用自己的估算')))
        self.assertFalse(BackupError('job-failed', 'x').job_wide)

    def test_a_full_disk_is_insufficient_space(self):
        full = haissues.out_of_space(OSError(errno.ENOSPC, 'No space left on device'))
        self.assertEqual((full.code, full.job_wide), ('insufficient-space', True))
        self.assertIsNone(haissues.out_of_space(OSError(errno.EIO, 'x')))
        self.assertIsNone(haissues.out_of_space(BackupError('insufficient-space', 'x')))

    def test_an_error_that_carries_issues_keeps_them(self):
        issue = Issue('emqx.broken', 'stop', '不能。')
        found, _err = self.quiet(haissues.stopped(issue, 'corrupt-archive', member='x'))
        self.assertEqual(found, [issue])
        self.assertEqual(haissues.stopped(issue).details, {})

    def test_actions_only_for_known_codes(self):
        self.assertLessEqual(set(haissues.ACTIONS), errors.CODES)
        self.assertTrue(all(len(text) <= haissues.MAX_ACTION for text in haissues.ACTIONS.values()))


class VersionTests(unittest.TestCase):
    """CM-01, CM-02: a version the table does not know, or one that cannot be read here, is told and never a gate."""

    def found(self, upstream, target, addon='0.2.0'):
        return [(i.id, i.level) for i in haissues.version_issues('Headscale', addon, upstream, target)]

    def test_an_unknown_add_on_version_is_a_notice(self):
        self.assertEqual(self.found(None, '0.29.4'), [('version.addon-unknown', 'notice')])
        issue = haissues.version_issues('Headscale', '9.9.9', None, '0.29.4')[0]
        self.assertIn('9.9.9', issue.message)
        self.assertIn('改看 Headscale 的資料本身', issue.message)
        self.assertEqual(self.found(None, '0.29.4', addon=''), [('version.addon-unknown', 'notice')])

    def test_an_unreadable_version_here_is_a_notice(self):
        self.assertEqual(self.found('0.29.4', None), [('version.target-unknown', 'notice')])
        self.assertEqual(self.found(None, None), [('version.addon-unknown', 'notice'),
                                                  ('version.target-unknown', 'notice')])

    def test_known_and_different_still_stops(self):
        self.assertEqual(self.found('0.29.4', '0.29.4'), [])
        self.assertEqual(self.found('0.29.4', 'v0.29.4'), [])
        self.assertEqual(self.found('0.29.3', '0.29.4'), [('version.different', 'stop')])

    def test_the_table_is_used_as_it_is(self):
        table = hacommon.VersionTable('Headscale', {'0.1.3': '0.29.4'})
        self.assertEqual(haissues.version_issues(table.product, '0.1.3', table.upstream('0.1.3'), '0.29.4'), [])
        self.assertEqual([i.id for i in haissues.version_issues(table.product, '0.9.0', table.upstream('0.9.0'), '0.29.4')],
                         ['version.addon-unknown'])


def tables():
    """{module name: {id: level}} of every module with an ISSUES table."""
    modules = {'haissues': haissues, 'haimport': haimport, 'cli': cli}
    modules.update({importer.module: importer.load() for importer in haapps.IMPORTERS})
    for path in sorted(ENGINE.rglob('*.py')):
        name = path.stem
        if name not in modules and 'ISSUES' in path.read_text(encoding='utf-8'):
            __import__(f'woowbackup.{path.relative_to(ENGINE).with_suffix("").as_posix().replace("/", ".")}')
            import sys
            modules[name] = sys.modules[f'woowbackup.{path.relative_to(ENGINE).with_suffix("").as_posix().replace("/", ".")}']
    return {name: dict(module.ISSUES) for name, module in modules.items() if hasattr(module, 'ISSUES')}


SINK_CALLS = {'stop': 'stop', 'confirm': 'confirm', 'auto': 'auto', 'notice': 'notice', 'refuse': 'stop'}


def used(path):
    """[(id, level, line)] of the issues a module makes with a literal id: `Issue('x.y', 'stop', ...)` and
    `sink.stop('x.y', ...)`."""
    found = []
    for node in ast.walk(ast.parse(path.read_bytes())):
        if not isinstance(node, ast.Call) or not node.args or not isinstance(node.args[0], ast.Constant) \
                or not isinstance(node.args[0].value, str) or not haissues.ID_RE.fullmatch(node.args[0].value):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', None)
        if name == 'Issue' and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            found.append((node.args[0].value, node.args[1].value, node.lineno))
        elif name in SINK_CALLS and isinstance(node.func, ast.Attribute):
            found.append((node.args[0].value, SINK_CALLS[name], node.lineno))
    return found


class RegistrationTests(unittest.TestCase):
    def test_every_id_is_declared_once_with_a_valid_level(self):
        seen = {}
        for module, table in tables().items():
            for issue_id, level in table.items():
                self.assertRegex(issue_id, haissues.ID_RE)
                self.assertIn(level, haissues.LEVELS, issue_id)
                self.assertNotIn(issue_id, seen, f'{issue_id} is declared in {module} and {seen.get(issue_id)}')
                seen[issue_id] = module

    def test_every_id_used_is_declared_with_its_level(self):
        levels = {issue_id: level for table in tables().values() for issue_id, level in table.items()}
        calls = 0
        for path in sorted(ENGINE.rglob('*.py')):
            for issue_id, level, line in used(path):
                calls += 1
                self.assertEqual(levels.get(issue_id), level, f'{path.name}:{line} {issue_id}')
        self.assertGreater(calls, 10, 'the scan finds the calls')

    def test_every_declared_id_is_used(self):
        texts = {path.stem: path.read_text(encoding='utf-8') for path in ENGINE.rglob('*.py')}
        for module, table in tables().items():
            for issue_id in table:
                if issue_id.startswith('failure.'):
                    continue  # made from the error's code (haissues.from_error)
                self.assertGreater(texts[module].count(f"'{issue_id}'"), 1, f'{issue_id} of {module} is never used')

    def test_the_failure_ids_follow_the_error_codes(self):
        self.assertEqual({i for i in haissues.ISSUES if i.startswith('failure.')},
                         {f'failure.{code}' for code in errors.CODES})

    def test_the_scan_sees_a_wrong_level(self):
        source = "sink.confirm('ha.addon-missing', 'x')\nIssue('ha.addon-choice', 'notice', 'x')\nx.stop('hapg')\n"
        path = Path(self.enterContext(__import__('tempfile').TemporaryDirectory())) / 'm.py'
        path.write_text(source)
        self.assertEqual(used(path), [('ha.addon-missing', 'confirm', 1), ('ha.addon-choice', 'notice', 2)])


if __name__ == '__main__':
    unittest.main()
