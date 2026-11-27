"""EMQX security re-review, 2026-11-24 (iteration 8, lane emqx-secreview): the owner's option C (「也不會留下明文密碼」)
for every stored row. PLAIN_EXPR now counts every row whose stored value is not in the form its authenticator's hashing
produces (md5 / sha / sha256 / sha512 hex of 32 / 40 / 64 / 128 characters in any case, pbkdf2 hex of twice the
derived length, bcrypt `$2<a|b|x|y>$<04..31>$` + 53 characters; emqx_passwd.erl:67-158,
emqx_authn_password_hashing.erl:220-253, minors and rounds proven in the EMQX 5.8.9 image) and every row of a user group
no built-in database of HA's configuration owns that has none of these forms; the answer names the first ten with their
user group. The Erlang behaviour is proven against real EMQX 5.8.9 brokers by the lab harness
(tests/e2e/lab/emqx_secreview/t16_forms.py, with behavioural mutants of the expression); these units pin the Python side:
the strict answer, the notice text with the user groups (HAOS parity, D1: named, no longer refused), O-2 (format characters
in shown names) and O-3 (HA's built-in database disabled or absent)."""
import re
import sys
import unicodedata
import unittest
from pathlib import Path

from woowbackup import ha_emqx, hacommon, haissues

from . import test_ha_emqx_sr5 as sr5
from .test_ha_emqx_plain_review import plain_answer
from .test_ha_emqx_sr5 import BCRYPT, users_answer

HIDDEN = ('Cc', 'Cf', 'Cs', 'Cn', 'Zl', 'Zp')


class FormsAnswerTests(unittest.TestCase):
    def test_every_item_carries_its_user_group(self):
        answer = plain_answer(names=('a', ('b', 'stomp:global'), ('c', 'zz:orphan')))
        self.assertEqual(ha_emqx.parse_plain(answer)['names'],
                         [('a', 'mqtt:global'), ('b', 'stomp:global'), ('c', 'zz:orphan')])
        for bad in ('WOOWPLAIN:0:1:YQ==:ENDok', 'WOOWPLAIN:0:1:YQ==.:ENDok', 'WOOWPLAIN:0:1:.YQ==:ENDok',
                    'WOOWPLAIN:0:1:YQ==..YQ==:ENDok', 'WOOWPLAIN:0:2:YQ==.YQ==:ENDok',
                    'WOOWPLAIN:0:1:YQ==.YQ==,:ENDok', 'WOOWPLAIN:0:1:YQ==.' + 'Q' * 1404 + ':ENDok'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ha_emqx.parse_plain(bad)

    def test_the_notice_names_users_with_the_chain_they_are_in(self):
        plain = ha_emqx.parse_plain(plain_answer(names=('a', ('b', 'stomp:global'), ('c', 'mqtt-sn:global'))))
        [(issue_id, message, names)] = ha_emqx.plain_notices({'hashing': sr5.hashing('sha256', 'suffix'), 'plain': plain})
        self.assertEqual((issue_id, names), ('emqx.clear-rows', ['a', 'b（stomp:global）', 'c（mqtt-sn:global）']))
        self.assertEqual(message, ha_emqx.CLEAR_ROWS.format(count=3))

    def test_long_ids_keep_their_chain_and_hidden_characters_never_reach_the_page(self):
        plain = {'elsewhere': 0, 'clear': 12, 'names': [('x' * 70, 'stomp:tcp:default'), ('a​b﻿', 'g⁠w'),
                                                         ('c­c\U000e0041', 'mqtt:global')]}
        [(_id, message, names)] = ha_emqx.plain_notices({'hashing': None, 'plain': plain})
        self.assertEqual(names[0], 'x' * 40 + '（stomp:tcp:default）')
        issue = haissues.Issue('emqx.clear-rows', 'notice', message, names)
        shown = issue.view('emqx')['items']
        self.assertEqual(len(shown), 3)
        self.assertFalse([ch for text in shown for ch in text if unicodedata.category(ch) in HIDDEN],
                         'nothing hidden reaches the page')
        self.assertIn('12 個', message)

    def test_the_text_says_what_the_rows_are_and_what_to_do(self):
        text = ha_emqx.CLEAR_ROWS.format(count=3)
        for words in ('沒有以所屬認證目前的雜湊方式保存', '可能是明文', '「plain」', '「hash」方式匯入', '監聽器或閘道',
                      '這些帳號在 HA 現在也無法用密碼登入', '會照 HA 原樣匯入', '明文密碼會留在這台', '之後每一份備份',
                      '重設這些帳號的密碼或刪除不用的帳號', '重新備份'):
            with self.subTest(words=words):
                self.assertIn(words, text)
        self.assertNotIn('不能匯入', text, 'HAOS parity: nothing is refused for it')


class FormsExpressionTests(unittest.TestCase):
    """The vendor forms the expression encodes (string pins; their behaviour, and that of mutants, runs in real
    EMQX 5.8.9 brokers in the lab: t16_forms.py)."""

    def test_each_algorithm_has_its_form(self):
        expr = ha_emqx.PLAIN_EXPR
        for part in ('md5 -> Hx(V, 32)', 'sha -> Hx(V, 40)', 'sha256 -> Hx(V, 64)', 'sha512 -> Hx(V, 128)',
                     'bcrypt -> Bc(V)', 'D when is_integer(D), D > 0 -> Hx(V, 2 * D)',
                     'Dk = #{sha => 20, sha224 => 28, sha256 => 32, sha384 => 48, sha512 => 64}',
                     'lists:member(Mi, "abxy")', '>= 4 andalso', '=< 31 andalso', 'when byte_size(Tb) =:= 53',
                     '(Ch >= $A andalso Ch =< $F)', 'Ch =:= $. orelse Ch =:= $/', '[32, 40, 56, 64, 96, 128]',
                     '[] -> Any(V)', '_ -> false end end'):
            with self.subTest(part=part):
                self.assertIn(part, expr)

    def test_the_salt_never_decides(self):
        fold = ha_emqx.PLAIN_EXPR[ha_emqx.PLAIN_EXPR.index('Fold = '):ha_emqx.PLAIN_EXPR.index('{Nc, Uc, Bad}')]
        self.assertNotIn('S =:=', fold)
        self.assertNotIn('Hex(H)', ha_emqx.PLAIN_EXPR, 'the iteration-7 any-length hex rule is gone')
        self.assertNotIn('<<"$2", _/binary>>', ha_emqx.PLAIN_EXPR, 'the iteration-7 $2-prefix rule is gone')


class HiddenCharacterTests(unittest.TestCase):
    """O-2: hacommon.names shows every control, format, surrogate, unassigned, line or paragraph separator as `?`."""

    def test_every_hidden_character_is_replaced_and_nothing_else(self):
        hidden, kept = [], []
        for code in range(sys.maxunicode + 1):
            (hidden if unicodedata.category(chr(code)) in HIDDEN else kept).append(chr(code))
        for start in range(0, len(hidden), 50):
            chunk = hidden[start:start + 50]
            self.assertEqual(hacommon.names([''.join(chunk)], 1), '?' * len(chunk))
        sample = ''.join(kept[i] for i in range(0, len(kept), 997))
        for start in range(0, len(sample), 60):
            self.assertEqual(hacommon.names([sample[start:start + 60]], 1), sample[start:start + 60])

    def test_a_superset_of_the_shared_control_class(self):
        for code in range(0x30000):
            if hacommon.CONTROL_RE.match(chr(code)):
                self.assertEqual(hacommon.names(['a' + chr(code)], 1), 'a?', hex(code))

    def test_the_ones_the_review_found(self):
        for ch in ('​', '‌', '‍', '⁠', '﻿', '­', '᠎', '\U000e0041', '\ud800'):
            with self.subTest(ch=hex(ord(ch))):
                self.assertEqual(hacommon.names(['x' + ch + 'y']), 'x?y')

    def test_limits_and_counts_are_unchanged(self):
        self.assertEqual(hacommon.names(['a' * 70]), 'a' * 60)
        self.assertEqual(hacommon.names([f'u{i}' for i in range(12)], 10),
                         '、'.join(f'u{i}' for i in range(10)) + ' 等 12 個')
        self.assertEqual(hacommon.names(iter(['a', 'b'])), 'a、b')
        self.assertEqual(hacommon.names(['中文名稱', 'é', '\U0001f600']), '中文名稱、é、\U0001f600')


class DatabaseOffTests(sr5.Sr5Case):
    """O-3: HA's built-in password database disabled or absent while this device has MQTT accounts in its own."""

    def off_warnings(self, result):
        return [w for w in result['warnings'] if w.startswith('HA 的 EMQX 沒有啟用內建資料庫的帳號密碼認證')]

    def test_a_disabled_database_is_named_before_the_conversion(self):
        for ha in ('[{false,sha256,suffix,none,none,none}]', '[{false,bcrypt,none,none,none,none}]', '[]'):
            with self.subTest(ha=ha):
                self.world.ha_hashing = ha
                self.world.live_users = users_answer('woow', 'sensor-01')
                result = self.run_check()
                self.assertTrue(result['ok'], result['blockers'])
                self.assertEqual(self.off_warnings(result), [ha_emqx.DB_OFF.format(names='woow、sensor-01')])
                self.assertEqual(self.sr5_warnings(result), [], 'one reason, one warning')
                self.assert_nothing_of_the_device_changed()

    def test_more_than_ten_accounts_are_counted(self):
        self.world.ha_hashing = '[]'
        self.world.live_users = users_answer(*[f'u{i:02d}' for i in range(10)], count=14)
        [warning] = self.off_warnings(self.run_check())
        self.assertIn('u09 等 14 個', warning)

    def test_no_warning_without_reason(self):
        cases = (('[{true,sha256,suffix,none,none,none}]', users_answer('woow'), None),
                 (BCRYPT, users_answer('woow'), None),
                 ('[{false,sha256,suffix,none,none,none}]', users_answer(), None),
                 ('[{false,sha256,suffix,none,none,none}]', users_answer('woow'), '[]'))
        for ha, users, live in cases:
            with self.subTest(ha=ha, users=users, live=live):
                self.world.ha_hashing, self.world.live_users = ha, users
                if live is not None:
                    self.world.live_hashing = live
                self.assertEqual(self.off_warnings(self.run_check()), [])

    def test_clear_text_and_a_disabled_database_are_both_said(self):
        """D1 + O-3: nothing is refused; each reason has its own notice."""
        self.world.ha_hashing = '[{false,plain,disable,none,none,none}]'
        result = self.run_check()
        self.assertTrue(result['importable'])
        self.assertIn(ha_emqx.PLAIN_PASSWORDS, result['warnings'])
        self.assertEqual(self.off_warnings(result), [ha_emqx.DB_OFF.format(names='woow')])
        self.world.ha_hashing = '[]'
        self.world.ha_plain = plain_answer(names=('old',))
        result = self.run_check()
        self.assertTrue(result['importable'])
        self.assertEqual(result['blockers'], [])
        self.assertIn(ha_emqx.CLEAR_ROWS.format(count=1), result['warnings'])
        self.assertEqual(len(self.off_warnings(result)), 1)

    def test_the_unit_function(self):
        device = {'hashing': sr5.hashing('sha256', 'suffix'), 'count': 1, 'names': ['woow']}
        none = {'elsewhere': 0, 'clear': 0, 'names': []}
        off = sr5.hashing('sha256', 'suffix', enable=False)
        self.assertEqual(ha_emqx.database_off({'hashing': off, 'plain': none}, device),
                         ha_emqx.DB_OFF.format(names='woow'))
        self.assertEqual(ha_emqx.database_off({'hashing': None, 'plain': none}, device),
                         ha_emqx.DB_OFF.format(names='woow'))
        self.assertIsNone(ha_emqx.database_off(None, device))
        self.assertIsNone(ha_emqx.database_off({'hashing': off, 'plain': none}, None))
        self.assertIsNone(ha_emqx.database_off({'hashing': off, 'plain': none}, dict(device, count=0)))
        self.assertIsNone(ha_emqx.database_off({'hashing': sr5.hashing('sha256', 'suffix'), 'plain': none}, device))


class FormsDocsTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]

    def test_the_docs_quote_the_engine(self):
        guide = (self.ROOT / 'docs' / 'backup.md').read_text(encoding='utf-8')
        if ha_emqx.DB_OFF.format(names='…') not in guide and '這台設有 bootstrap 帳號檔時轉換也會停止' in guide:
            self.skipTest('docs/backup.md still quotes the text before HAOS parity: the EMQX-A snippet is not merged yet')
        self.assertIn(ha_emqx.DB_OFF.format(names='…'), guide)
        self.assertIn('這台在 EMQX 管理頁自己建立的 MQTT 帳號，匯入後會被 HA 的帳號取代', guide, 'O-4: expected behaviour')

        def bare(text):
            return re.sub(r'\s+', '', text)
        contract = bare((self.ROOT / 'docs' / 'backup' / 'CONTRACT.md').read_text(encoding='utf-8'))
        if bare(ha_emqx.DB_OFF.format(names='<names>')) not in contract and bare('這台設有 bootstrap 帳號檔時轉換也會停止') in contract:
            self.skipTest('CONTRACT.md still quotes the text before HAOS parity: the EMQX-A snippet is not merged yet')
        self.assertIn(bare(ha_emqx.DB_OFF.format(names='<names>')), contract)


if __name__ == '__main__':
    unittest.main()
