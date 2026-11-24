"""EMQX security re-review, 2026-11-24 (iteration 8, lane emqx-secreview): the owner's option C (「也不會留下明文密碼」)
for every stored row. PLAIN_EXPR now counts every row whose stored value is not in the form its authenticator's hashing
produces (md5 / sha / sha256 / sha512 hex of 32 / 40 / 64 / 128 characters in any case, pbkdf2 hex of twice the
derived length, bcrypt `$2<a|b|x|y>$<04..31>$` + 53 characters; emqx_passwd.erl:67-158,
emqx_authn_password_hashing.erl:220-253, minors and rounds proven in the EMQX 5.8.9 image) and every row of a user group
no built-in database of HA's configuration owns that has none of these forms; the answer names the first ten with their
user group. The Erlang behaviour is proven against real EMQX 5.8.9 brokers by the lab harness
(tests/e2e/lab/emqx_secreview/t16_forms.py, with behavioural mutants of the expression); these units pin the Python side:
the strict answer, the refusal text with the user groups, O-2 (format characters in shown names) and O-3 (HA's built-in
database disabled or absent)."""
import re
import sys
import unicodedata
import unittest
from pathlib import Path

from woowbackup import ha_emqx, hacommon

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

    def test_the_refusal_names_users_with_the_chain_they_are_in(self):
        plain = ha_emqx.parse_plain(plain_answer(names=('a', ('b', 'stomp:global'), ('c', 'mqtt-sn:global'))))
        self.assertEqual(ha_emqx.plain_blocker({'hashing': sr5.hashing('sha256', 'suffix'), 'plain': plain}),
                         ha_emqx.CLEAR_ROWS.format(names='a、b（stomp:global）、c（mqtt-sn:global）'))

    def test_long_ids_keep_their_chain_and_hidden_characters_become_question_marks(self):
        plain = {'elsewhere': 0, 'clear': 12, 'names': [('x' * 70, 'stomp:tcp:default'), ('a​b﻿', 'g⁠w'),
                                                         ('c­c\U000e0041', 'mqtt:global')]}
        text = ha_emqx.plain_blocker({'hashing': None, 'plain': plain})
        self.assertIn('x' * 40 + '（stomp:tcp:default）、a?b?（g?w）、c?c? 等 12 個', text)
        self.assertFalse([ch for ch in text if unicodedata.category(ch) in HIDDEN], 'nothing hidden reaches the page')

    def test_the_text_says_what_the_rows_are_and_what_to_do(self):
        text = ha_emqx.CLEAR_ROWS.format(names='n')
        for words in ('沒有以所屬認證目前的雜湊方式保存', '可能是明文', '「plain」', '「hash」方式匯入', '監聽器或閘道',
                      '這些帳號現在也無法用密碼登入', '所以不能匯入', '存取控制 → 認證', '重新設定一次密碼',
                      '刪除不用的帳號', '先重新建立它的內建資料庫認證', '重新製作 HA 備份再匯入'):
            with self.subTest(words=words):
                self.assertIn(words, text)


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
                self.assert_nothing_built()

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

    def test_a_clear_text_refusal_says_it_all(self):
        self.world.ha_hashing = '[{false,plain,disable,none,none,none}]'
        result = self.run_check()
        self.assertEqual(result['blockers'], [ha_emqx.PLAIN_REFUSED])
        self.assertEqual(self.off_warnings(result), [])
        self.world.ha_hashing = '[]'
        self.world.ha_plain = plain_answer(names=('old',))
        result = self.run_check()
        self.assertEqual(result['blockers'], [ha_emqx.CLEAR_ROWS.format(names='old')])
        self.assertEqual(self.off_warnings(result), [])

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
        self.assertIn(ha_emqx.DB_OFF.format(names='…'), guide)
        self.assertIn('這台在 EMQX 管理頁自己建立的 MQTT 帳號，匯入後會被 HA 的帳號取代', guide, 'O-4: expected behaviour')

        def bare(text):
            return re.sub(r'\s+', '', text)
        contract = bare((self.ROOT / 'docs' / 'backup' / 'CONTRACT.md').read_text(encoding='utf-8'))
        self.assertIn(bare(ha_emqx.DB_OFF.format(names='<names>')), contract)


if __name__ == '__main__':
    unittest.main()
