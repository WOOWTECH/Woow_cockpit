"""SR-5 security re-review, 2026-11-24 (iteration 7): the owner's refusal of HA's `plain` hashing (option C: 「如果 HA 用的是
「不加密」的方式，就直接擋下……也不會留下明文密碼」) also covers what HASH_EXPR's global chain does not see: a `plain`
built-in password database of an MQTT listener or a gateway (all of them keep their rows in the one table the export
carries whole; the `gateway` root is imported), and rows HA's EMQX still keeps in clear text (written under `plain`
before HA changed the algorithm; EMQX never re-hashes a stored row). Both refuse at the check and stop the conversion
before HA's export; HA's broker answers counts and user ids only (PLAIN_EXPR). Vendor: emqx_authn_config.erl:371-374,
emqx_gateway_utils.erl:457-475, emqx_gateway_insta_sup.erl:295-307, emqx_authn_mnesia.erl:105 and :130,
emqx_authn_password_hashing.erl:206-207 and :221-224, emqx_passwd.erl:104-113 and :148-150."""
import base64
import re
import unittest
from pathlib import Path

from woowbackup import ha_emqx
from woowbackup.errors import BackupError

from . import test_ha_emqx_sr5 as sr5
from .test_ha_emqx_sr5 import BCRYPT, users_answer


def plain_answer(elsewhere=0, names=(), clear=None):
    """PLAIN_EXPR's answer; a name is a user id of the global chain or a (user id, user group) pair (iteration 8)."""
    def item(name):
        user, group = (name, 'mqtt:global') if isinstance(name, str) else name
        return base64.b64encode(user.encode()).decode() + '.' + base64.b64encode(group.encode()).decode()
    encoded = ','.join(item(name) for name in names[:10])
    return f'WOOWPLAIN:{elsewhere}:{len(names) if clear is None else clear}:{encoded}:ENDok\n'


class PlainElsewhereTests(sr5.Sr5Case):
    def test_a_plain_listener_or_gateway_database_is_refused_at_the_check(self):
        self.world.ha_plain = plain_answer(elsewhere=1)
        result = self.run_check()
        self.assertFalse(result['ok'])
        self.assertEqual(result['blockers'], [ha_emqx.PLAIN_ELSEWHERE])
        self.assertEqual(self.sr5_warnings(result), [], 'the refusal says it all; no account warning')
        self.assertEqual(result['emqx']['mqtt_users'], 3, 'HA\'s facts are still shown')
        self.assert_nothing_built()

    def test_rows_in_clear_text_are_refused_at_the_check_and_named(self):
        self.world.ha_plain = plain_answer(names=('old-sensor', 'old-gateway'))
        result = self.run_check()
        self.assertFalse(result['ok'])
        self.assertEqual(result['blockers'], [ha_emqx.CLEAR_ROWS.format(names='old-sensor、old-gateway')])
        self.assertEqual(self.sr5_warnings(result), [])
        self.assert_nothing_built()

    def test_more_than_ten_rows_are_counted_and_control_characters_shown_as_question_marks(self):
        names = ['bad\x1b[31m\nname‮'] + [f'u{i:02d}' for i in range(9)]
        self.world.ha_plain = plain_answer(names=names, clear=12)
        blockers = self.run_check()['blockers']
        self.assertEqual(blockers, [ha_emqx.CLEAR_ROWS.format(
            names='bad?[31m?name?、' + '、'.join(f'u{i:02d}' for i in range(9)) + ' 等 12 個')])
        self.assertFalse(re.search(r'[\x00-\x1f\x7f-\x9f‪-‮]', blockers[0]))

    def test_global_plain_keeps_its_own_text(self):
        self.world.ha_hashing = '[{true,plain,disable,none,none,none}]'
        self.world.ha_plain = plain_answer(elsewhere=2, names=('a',))
        self.assertEqual(self.run_check()['blockers'], [ha_emqx.PLAIN_REFUSED])

    def test_a_different_hashing_with_clear_rows_refuses_without_the_account_warning(self):
        self.world.ha_hashing = BCRYPT
        self.world.live_users = users_answer('woow')
        self.world.ha_plain = plain_answer(names=('old',))
        result = self.run_check()
        self.assertEqual(result['blockers'], [ha_emqx.CLEAR_ROWS.format(names='old')])
        self.assertEqual(self.sr5_warnings(result), [])

    def test_the_conversion_stops_before_has_export(self):
        for answer, text in ((plain_answer(elsewhere=1), ha_emqx.PLAIN_ELSEWHERE),
                             (plain_answer(names=('old',)), ha_emqx.CLEAR_ROWS.format(names='old'))):
            with self.subTest(answer=answer):
                self.world.ha_plain = answer
                with self.assertRaises(BackupError) as caught:
                    self.convert(self.upload_emqx(state='stopped'), ['emqx'])
                self.assertEqual(caught.exception.code, 'incompatible')
                self.assertEqual(caught.exception.message, 'EMQX 不能搬過來：' + text)
                self.assert_nothing_built()
                self.assertEqual(self.storage.list_backups(), [])

    def test_an_unreadable_answer_refuses_never_a_guess(self):
        for bad in ('ok\n', 'WOOWPLAIN:bad:ENDok\n', 'WOOWPLAIN:0:2:YQ==:ENDok\n', '{badrpc,nodedown}\n', ''):
            with self.subTest(bad=bad):
                self.world.ha_plain = bad
                result = self.run_check()
                self.assertFalse(result['ok'])
                self.assertTrue(any(b.startswith(ha_emqx.HASH_UNREADABLE.format(side='HA 的'))
                                    for b in result['blockers']), result['blockers'])
                self.assert_nothing_built()

    def test_no_plain_anywhere_changes_nothing(self):
        result = self.run_check()
        self.assertTrue(result['ok'], result['blockers'])
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])['ha_import']
        self.assertTrue(done)

    def test_only_has_broker_is_asked(self):
        self.run_check()
        self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertNotIn('plain', [kind for _role, kind in self.world.device_reads])
        asked = [role for role, command, _data in self.world.execs
                 if command[:2] == ['emqx', 'eval'] and command[2] == ha_emqx.PLAIN_EXPR]
        self.assertTrue(asked)
        self.assertEqual(set(asked), {'emqx-ha'})


class PlainExpressionTests(unittest.TestCase):
    """The fixed expression reads every place a built-in password database can live, and prints counts and base64 user
    ids only: a password hash or salt never leaves HA's broker."""

    def test_it_reads_the_global_chain_s_neighbours_and_the_table(self):
        expr = ha_emqx.PLAIN_EXPR
        for part in ('emqx:get_config([listeners], #{})', 'emqx:get_config([gateway], #{})',
                     'A2 <- Lw(maps:get(authentication, C2, []))', 'A3 <- Lw(maps:get(authentication, Gc3, []))',
                     'Ln(maps:get(listeners, Gc4, #{}))', 'A4 <- Lw(maps:get(authentication, C4, []))',
                     'emqx_gateway_utils:global_chain(G3)', 'emqx_gateway_utils:listener_chain(G4, T4, N4)',
                     'maps:get(backend, A, none) =:= built_in_database', "maps:get(name, H, none) =:= plain",
                     'ets:foldl(Fold, {0, [], 0}, emqx_authn_mnesia)', '[] -> Any(V)', 'Fits(Al, V)',
                     'case Bad of 0 -> io:format("WOOWPLAIN:~b:~b:~s:END"',
                     '(_, {N0, U0, B0}) -> {N0, U0, B0 + 1}', '_ -> io:format("WOOWPLAIN:bad:END")'):
            with self.subTest(part=part):
                self.assertIn(part, expr)

    def test_only_counts_and_user_ids_are_printed(self):
        expr = ha_emqx.PLAIN_EXPR
        self.assertEqual(expr.count('io:format('), 2)
        printed = expr[expr.index('io:format("WOOWPLAIN:~b'):]
        self.assertIn('[[base64:encode(Ux), ".", base64:encode(Kx)] || {Kx, Ux} <- lists:sublist(lists:sort(Uc), 10)]',
                      printed)
        self.assertIn('{N0 + 1, [{Kg, U} | U0], B0}', expr, 'only the user group and id are collected')
        for leak in ('[V |', '[S |', 'base64:encode(V)', 'base64:encode(S)', '~p', '~w', '{Kg, V}', '{Kg, S}'):
            with self.subTest(leak=leak):
                self.assertNotIn(leak, expr)


class ParsePlainTests(unittest.TestCase):
    def test_answers(self):
        parse = ha_emqx.parse_plain
        self.assertEqual(parse('WOOWPLAIN:0:0::ENDok\n'), {'elsewhere': 0, 'clear': 0, 'names': []})
        self.assertEqual(parse(plain_answer(elsewhere=3, names=('a', ('b', 'stomp:global')))), {
            'elsewhere': 3, 'clear': 2, 'names': [('a', 'mqtt:global'), ('b', 'stomp:global')]})
        self.assertEqual(parse(plain_answer(names=[f'u{i}' for i in range(10)], clear=11))['names'],
                         [(f'u{i}', 'mqtt:global') for i in range(10)])
        for bad in ('', 'ok', 'WOOWPLAIN:bad:ENDok', 'WOOWPLAIN:0:1::ENDok', 'WOOWPLAIN:0:1:YQ:ENDok',
                    'WOOWPLAIN:0:1:YQ===:ENDok', 'WOOWPLAIN:0:1:Y*==:ENDok', 'x WOOWPLAIN:0:0::ENDok',
                    'WOOWPLAIN:0:0::END ok x', 'WOOWPLAIN:-1:0::ENDok', 'WOOWPLAIN:0:0:YQ==:ENDok',
                    'WOOWPLAIN:0:0::EN', 'WOOWPLAIN:0:1:YQ==:ENDok', 'WOOWPLAIN:0:1:YQ==.:ENDok',
                    'WOOWPLAIN:0:1:.YQ==:ENDok', 'WOOWPLAIN:0:1:YQ==.YQ==.YQ==:ENDok', 'WOOWPLAIN:0:1:YQ==.Y*==:ENDok'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad)

    def test_plain_blocker(self):
        none = {'elsewhere': 0, 'clear': 0, 'names': []}
        sha = sr5.hashing('sha256', 'suffix')
        self.assertIsNone(ha_emqx.plain_blocker({'hashing': sha, 'plain': none}))
        self.assertEqual(ha_emqx.plain_blocker({'hashing': None, 'plain': dict(none, elsewhere=1)}),
                         ha_emqx.PLAIN_ELSEWHERE)
        self.assertEqual(ha_emqx.plain_blocker({'hashing': sha, 'plain': {'elsewhere': 0, 'clear': 1,
                                                                          'names': [('x', 'mqtt:global')]}}),
                         ha_emqx.CLEAR_ROWS.format(names='x'))
        self.assertEqual(ha_emqx.plain_blocker({'hashing': sr5.hashing('plain', 'disable'),
                                                'plain': dict(none, elsewhere=1)}), ha_emqx.PLAIN_REFUSED)


class PlainDocsTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]

    def test_the_docs_quote_the_engine(self):
        guide = (self.ROOT / 'docs' / 'backup.md').read_text(encoding='utf-8')
        self.assertIn(ha_emqx.PLAIN_ELSEWHERE, guide)
        self.assertIn(ha_emqx.CLEAR_ROWS.format(names='…'), guide)

        def bare(text):   # the CONTRACT wraps its lines
            return re.sub(r'\s+', '', text)
        contract = bare((self.ROOT / 'docs' / 'backup' / 'CONTRACT.md').read_text(encoding='utf-8'))
        self.assertIn(bare(ha_emqx.PLAIN_ELSEWHERE), contract)
        self.assertIn(bare(ha_emqx.CLEAR_ROWS.format(names='<names>')), contract)


if __name__ == '__main__':
    unittest.main()
