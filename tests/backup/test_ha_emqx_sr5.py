"""SR-5, OWNER DECISION 2026-11-24 (option C): HA's EMQX replaces this device's MQTT password hashing, so the CHECK warns
before any conversion and names this device's own MQTT accounts that stop working (names only, control characters
shown as `?`); HA's `plain` (unencrypted) hashing is refused by the check and by the conversion; equal hashing changes
nothing. Vendor: emqx_authn_password_hashing.erl:206-269, emqx_passwd.erl:67-104, emqx_authn_mnesia.erl:130-161."""
import base64
import copy
import re
import unittest
from pathlib import Path

from woowbackup import ha_emqx
from woowbackup.errors import BackupError
from woowbackup.podman import Result

from . import test_ha_emqx as base

SHA256_SUFFIX = '[{true,sha256,suffix,none,none,none}]'
BCRYPT = '[{true,bcrypt,none,none,none,none}]\n'


def users_answer(*names, count=None):
    encoded = ','.join(base64.b64encode(name.encode()).decode() for name in names[:10])
    return f'WOOWUSERS:{len(names) if count is None else count}:{encoded}:ENDok\n'


def hashing(name, salt=None, mac_fun=None, iterations=None, dk_length=None, enable=True):
    return {'enable': enable, 'name': name, 'salt': salt, 'mac_fun': mac_fun, 'iterations': iterations,
            'dk_length': dk_length}


class Sr5Case(base.EmqxCase):
    def setUp(self):
        super().setUp()
        # HA's backup has ACL rows: a target that also asks its built-in database (OWNER DECISION 2026-11-23 「C」), so
        # nothing but SR-5 decides these checks.
        self.world.target_config['authorization']['sources'] = copy.deepcopy(base.BUILTIN_TARGET)
        self.world.current_config = copy.deepcopy(self.world.target_config)

    def run_check(self):
        return self.check(self.upload_emqx(state='stopped'), ['emqx'])[0]

    def sr5_warnings(self, result):
        return [w for w in result['warnings'] if '保存 MQTT 密碼的方式' in w]

    def device_evals(self):
        return [command[2] for role, command, _data in self.world.execs
                if role == 'woow-emqx' and command[:2] == ['emqx', 'eval']]

    def assert_nothing_built(self):
        self.assertFalse(self.runs('emqx-new'), 'no candidate was built')
        self.assertFalse([c for c in self.world.ctl_calls if c[1][:2] in (['data', 'export'], ['data', 'import'])],
                         'nothing was exported or imported')
        self.assertFalse(self.world.imported_into or self.world.restored)


class WarningTests(Sr5Case):
    def test_a_different_hashing_names_this_devices_accounts_before_any_conversion(self):
        self.world.ha_hashing = BCRYPT
        self.world.live_users = users_answer('woow', 'sensor-01')
        result = self.run_check()
        self.assertTrue(result['ok'], result['blockers'])
        [warning] = self.sr5_warnings(result)
        self.assertEqual(warning, ha_emqx.ACCOUNTS_STOP.format(ha='bcrypt', mine='sha256，鹽在後', names='woow、sensor-01'))
        for words in ('woow、sensor-01', '匯入後無法再用原本的密碼登入', '要在匯入後重新設定', '存取控制 → 認證',
                      '刪除後重新啟動 EMQX 就會用原本的密碼建回'):
            self.assertIn(words, warning)
        self.assert_nothing_built()

    def test_equal_hashing_gives_no_warning_and_the_result_is_unchanged(self):
        result = self.run_check()
        self.assertTrue(result['ok'], result['blockers'])
        self.assertEqual(self.sr5_warnings(result), [])
        self.assertFalse([w for w in result['warnings'] if 'MQTT 帳號' in w and '密碼' in w], result['warnings'])

    def test_the_device_is_only_read_with_the_two_fixed_expressions(self):
        self.world.ha_hashing = BCRYPT
        self.run_check()
        evals = self.device_evals()
        self.assertEqual([e for e in evals if e in (ha_emqx.HASH_EXPR, ha_emqx.USERS_EXPR)],
                         [ha_emqx.HASH_EXPR, ha_emqx.USERS_EXPR], 'each read once, in the check')
        self.assertFalse([e for e in evals if 'password' in e and e != ha_emqx.HASH_EXPR],
                         'no other device read mentions a password')
        # The users read only lists the table's keys: never a password hash or salt (emqx_authn_mnesia.erl:65-70),
        # and only the global chain's (its user group is the chain name: emqx_authn_chains.erl:1000-1008).
        self.assertIn('mnesia:dirty_all_keys(emqx_authn_mnesia)', ha_emqx.USERS_EXPR)
        self.assertIn("G =:= 'mqtt:global'", ha_emqx.USERS_EXPR)
        self.assertIn('lists:sublist(L, 10)', ha_emqx.USERS_EXPR)
        # The hashing read is the built-in password database's only.
        for words in ('maps:get(mechanism, A, none) =:= password_based', 'maps:get(backend, A, none) =:= built_in_database',
                      'emqx:get_config([authentication], [])'):
            self.assertIn(words, ha_emqx.HASH_EXPR)
        for never in ('dirty_read', 'match_object', 'select', 'password', 'salt', 'user_info', 'ets:'):
            self.assertNotIn(never, ha_emqx.USERS_EXPR)

    def test_a_different_salt_position_or_algorithm_warns(self):
        for ha in ('[{true,sha256,prefix,none,none,none}]', '[{true,sha512,suffix,none,none,none}]',
                   '[{true,pbkdf2,none,sha256,4096,none}]', '[{true,sha256,disable,none,none,none}]'):
            with self.subTest(ha=ha):
                self.world.ha_hashing = ha
                self.assertEqual(len(self.sr5_warnings(self.run_check())), 1)

    def test_a_disabled_salt_on_this_device_is_still_accepted_with_any_position(self):
        self.world.live_hashing = '[{true,sha256,disable,none,none,none}]'
        for ha in ('[{true,sha256,prefix,none,none,none}]', '[{true,sha256,suffix,none,none,none}]'):
            with self.subTest(ha=ha):
                self.world.ha_hashing = ha
                self.assertEqual(self.sr5_warnings(self.run_check()), [])

    def test_more_than_ten_accounts_are_counted(self):
        self.world.ha_hashing = BCRYPT
        names = [f'user{i:02d}' for i in range(10)]
        self.world.live_users = users_answer(*names, count=25)
        [warning] = self.sr5_warnings(self.run_check())
        self.assertIn('user00、user01', warning)
        self.assertIn('user09 等 25 個', warning)

    def test_control_characters_in_a_user_name_are_shown_as_question_marks(self):
        self.world.ha_hashing = BCRYPT
        evil = 'woow\nEMQX 匯入完成\x1b[31m‮evil x\u0085'
        self.world.live_users = users_answer(evil)
        result = self.run_check()
        [warning] = self.sr5_warnings(result)
        self.assertIn('woow?EMQX 匯入完成?[31m?evil?x?', warning)
        for text in result['warnings'] + result['blockers'] + [str(line) for line in self.reporter.logs]:
            self.assertIsNone(ha_emqx.hacommon.CONTROL_RE.search(text), repr(text))

    def test_no_accounts_or_no_builtin_database_gives_no_warning(self):
        self.world.ha_hashing = BCRYPT
        self.world.live_users = users_answer()
        self.assertEqual(self.sr5_warnings(self.run_check()), [])
        self.world.live_hashing = '[]'
        self.world.execs.clear()
        self.assertEqual(self.sr5_warnings(self.run_check()), [])
        self.assertNotIn(ha_emqx.USERS_EXPR, self.device_evals(), 'no built-in database: its users are not read')

    def test_ha_without_a_builtin_database_gives_no_warning(self):
        self.world.ha_hashing = '[]'
        self.assertEqual(self.sr5_warnings(self.run_check()), [])

    def test_an_unreadable_device_answer_is_a_blocker_never_a_guess(self):
        cases = {'hashing': ('live_hashing', 'ok\n'), 'two authenticators': ('live_hashing', SHA256_SUFFIX[:-1] + ','
                 + SHA256_SUFFIX[1:]), 'users': ('live_users', 'WOOWUSERS:2:d29vdw==:ENDok\n'),
                 'users junk': ('live_users', 'ok\n')}
        self.world.ha_hashing = BCRYPT
        defaults = {'live_hashing': self.world.live_hashing, 'live_users': self.world.live_users}
        for label, (attribute, answer) in cases.items():
            with self.subTest(label):
                for name, value in defaults.items():
                    setattr(self.world, name, value)
                setattr(self.world, attribute, answer)
                result = self.run_check()
                self.assertFalse(result['ok'])
                self.assertIn(ha_emqx.HASH_UNREADABLE.format(side='這台'), result['blockers'])
                self.assertEqual(self.sr5_warnings(result), [])

    def test_a_failing_device_read_is_a_blocker(self):
        real = self.world.exec

        def exec_(role, command, data, stdout):
            if role == 'woow-emqx' and command[2:3] == [ha_emqx.USERS_EXPR]:
                return Result(1, b'WOOWUSERS:1:d29vdw==:ENDok\n', b'')
            return real(role, command, data, stdout)
        self.world.exec = exec_
        self.world.ha_hashing = BCRYPT
        result = self.run_check()
        self.assertIn(ha_emqx.HASH_UNREADABLE.format(side='這台'), result['blockers'])

    def test_a_target_outside_the_profile_is_not_read(self):
        self.world.target_config['authorization']['sources'] = [{'type': 'http', 'enable': True}]
        self.world.current_config = copy.deepcopy(self.world.target_config)
        result = self.run_check()
        self.assertFalse(result['ok'])
        self.assertNotIn(ha_emqx.HASH_EXPR, self.device_evals())


class PlainTests(Sr5Case):
    def test_the_refusal_names_the_change_in_ha_and_the_password_reset(self):
        text = ha_emqx.PLAIN_REFUSED
        for words in ('「plain」（不加密）', '明文密碼', '存取控制 → 認證', 'password_hash_algorithm', '改成 plain 以外的方式',
                      '替每個 MQTT 帳號重新設定一次密碼', 'EMQX 不會轉換已經存好的密碼', '重新製作 HA 備份再匯入'):
            self.assertIn(words, text)

    def test_plain_is_refused_at_the_check_with_or_without_salt_and_even_when_disabled(self):
        for answer in ('[{true,plain,disable,none,none,none}]', '[{true,plain,prefix,none,none,none}]',
                       '[{true,plain,suffix,none,none,none}]', '[{false,plain,disable,none,none,none}]'):
            with self.subTest(answer=answer):
                self.world.ha_hashing = answer
                result = self.run_check()
                self.assertFalse(result['ok'])
                self.assertEqual(result['blockers'], [ha_emqx.PLAIN_REFUSED])
                self.assertEqual(self.sr5_warnings(result), [], 'the refusal says it all; no account warning')
                self.assertEqual(result['emqx']['mqtt_users'], 3, 'HA\'s facts are still shown')
                self.assert_nothing_built()

    def test_plain_stops_the_conversion_before_anything_is_built(self):
        self.world.ha_hashing = '[{true,plain,disable,none,none,none}]'
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertEqual(caught.exception.code, 'incompatible')
        self.assertEqual(caught.exception.message, 'EMQX 不能搬過來：' + ha_emqx.PLAIN_REFUSED)
        self.assert_nothing_built()
        self.assertEqual(self.storage.list_backups(), [])

    def test_an_unreadable_ha_answer_refuses_the_check(self):
        self.world.ha_hashing = '{badrpc,nodedown}\n'
        result = self.run_check()
        self.assertFalse(result['ok'])
        self.assertTrue(any(b.startswith(ha_emqx.HASH_UNREADABLE.format(side='HA 的')) for b in result['blockers']),
                        result['blockers'])
        self.assert_nothing_built()


class ConversionTextTests(Sr5Case):
    def test_the_conversion_repeats_the_accounts_in_its_note_and_reminder(self):
        self.world.ha_hashing = BCRYPT
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])['ha_import']
        notes = [n for n in done['notes'] if '保存 MQTT 密碼的方式' in n]
        self.assertEqual(notes, ['HA 的 EMQX 保存 MQTT 密碼的方式（bcrypt）和這台（sha256，鹽在後）不同，匯入後以 HA 的為準：'
                                 '這台原本的 MQTT 帳號（woow）無法再用原本的密碼登入。'])
        reminders = [r for r in done['reminders_by_app']['emqx'] if r.startswith('請重新設定這台原本的 MQTT 帳號')]
        self.assertEqual(reminders, ['請重新設定這台原本的 MQTT 帳號（woow）：' + ha_emqx.RESET_HOW])

    def test_equal_hashing_adds_no_note(self):
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])['ha_import']
        self.assertFalse([n for n in done['notes'] + done['reminders_by_app']['emqx'] if 'MQTT 密碼' in n or '重新設定這台' in n])

    def test_an_unreadable_device_stops_the_conversion_before_anything_is_built(self):
        self.world.live_users = 'garbage'
        with self.assertRaises(BackupError) as caught:
            self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertEqual(caught.exception.message, ha_emqx.HASH_UNREADABLE.format(side='這台'))
        self.assert_nothing_built()
        self.assertFalse(self.runs('emqx-ha'), 'refused before HA\'s broker started')

    def test_import_texts(self):
        change = {'ha': 'bcrypt', 'mine': 'sha256，鹽在後', 'names': 'woow'}
        notes, reminders = ha_emqx.import_texts({'hash_change': change})
        self.assertEqual(sum('保存 MQTT 密碼的方式' in n for n in notes), 1)
        self.assertEqual(sum(r.startswith('請重新設定這台原本的 MQTT 帳號（woow）') for r in reminders), 1)
        notes, reminders = ha_emqx.import_texts({'hash_change': None})
        self.assertFalse([t for t in notes + reminders if 'MQTT 密碼的方式' in t or '重新設定這台' in t])


class RuleTests(unittest.TestCase):
    """rows_still_verify against the vendor's check_password (emqx_authn_password_hashing.erl:252-269)."""

    def test_simple_algorithms(self):
        verify = ha_emqx.rows_still_verify
        self.assertTrue(verify(hashing('sha256', 'suffix'), hashing('sha256', 'suffix')))
        self.assertFalse(verify(hashing('sha256', 'suffix'), hashing('sha256', 'prefix')))
        self.assertFalse(verify(hashing('sha256', 'prefix'), hashing('sha256', 'disable')))
        self.assertFalse(verify(hashing('sha256', 'suffix'), hashing('sha512', 'suffix')))
        self.assertFalse(verify(hashing('md5', 'suffix'), hashing('sha', 'suffix')))
        # a row written without salt has an empty salt: any position of HA's hashes the password alone
        for position in ('prefix', 'suffix', 'disable'):
            self.assertTrue(verify(hashing('sha256', 'disable'), hashing('sha256', position)))
        self.assertFalse(verify(hashing('sha256', 'disable'), hashing('sha512', 'disable')))
        self.assertFalse(verify(hashing('plain', 'disable'), hashing('sha256', 'disable')))

    def test_bcrypt_reads_its_rounds_from_the_stored_hash(self):
        verify = ha_emqx.rows_still_verify
        self.assertTrue(verify(hashing('bcrypt'), hashing('bcrypt')))
        self.assertFalse(verify(hashing('bcrypt'), hashing('sha256', 'suffix')))
        self.assertFalse(verify(hashing('sha256', 'suffix'), hashing('bcrypt')))
        self.assertFalse(verify(hashing('pbkdf2', mac_fun='sha256', iterations=4096), hashing('bcrypt')))

    def test_pbkdf2_compares_every_parameter(self):
        verify = ha_emqx.rows_still_verify
        mine = hashing('pbkdf2', mac_fun='sha256', iterations=4096)
        self.assertTrue(verify(mine, hashing('pbkdf2', mac_fun='sha256', iterations=4096)))
        self.assertTrue(verify(mine, hashing('pbkdf2', mac_fun='sha256', iterations=4096, dk_length=32)),
                        'no dk_length = the MAC\'s own length (emqx_passwd.erl:140-141,153-158)')
        self.assertFalse(verify(mine, hashing('pbkdf2', mac_fun='sha256', iterations=4096, dk_length=64)))
        self.assertFalse(verify(mine, hashing('pbkdf2', mac_fun='sha512', iterations=4096)))
        self.assertFalse(verify(mine, hashing('pbkdf2', mac_fun='sha256', iterations=10000)))
        self.assertFalse(verify(mine, hashing('sha256', 'suffix')))
        self.assertFalse(verify(hashing('sha256', 'suffix'), mine))

    def test_hash_change(self):
        device = {'hashing': hashing('sha256', 'suffix'), 'count': 1, 'names': ['woow']}
        self.assertIsNone(ha_emqx.hash_change(hashing('sha256', 'suffix'), device))
        self.assertIsNone(ha_emqx.hash_change(None, device))
        self.assertIsNone(ha_emqx.hash_change(hashing('bcrypt'), None))
        self.assertIsNone(ha_emqx.hash_change(hashing('bcrypt'), dict(device, count=0, names=[])))
        self.assertEqual(ha_emqx.hash_change(hashing('bcrypt'), device),
                         {'ha': 'bcrypt', 'mine': 'sha256，鹽在後', 'names': 'woow'})
        self.assertEqual(ha_emqx.hashing_text(hashing('pbkdf2', mac_fun='sha512', iterations=10000, dk_length=64)),
                         'pbkdf2（sha512，10000 次，64 位元組）')
        self.assertEqual(ha_emqx.hashing_text(hashing('md5', 'disable')), 'md5，不加鹽')

    def test_plain_blocker(self):
        self.assertEqual(ha_emqx.plain_blocker({'hashing': hashing('plain', 'suffix', enable=False)}), ha_emqx.PLAIN_REFUSED)
        self.assertIsNone(ha_emqx.plain_blocker({'hashing': hashing('sha256', 'suffix')}))
        self.assertIsNone(ha_emqx.plain_blocker({'hashing': None}))
        self.assertIsNone(ha_emqx.plain_blocker(None))


class DocsTests(unittest.TestCase):
    """docs/backup.md quotes the refusal verbatim; CONTRACT section 9 states both texts (wrapped)."""
    ROOT = Path(__file__).resolve().parents[2]

    def test_the_docs_quote_the_engine(self):
        guide = (self.ROOT / 'docs' / 'backup.md').read_text(encoding='utf-8')
        self.assertIn(ha_emqx.PLAIN_REFUSED, guide)
        self.assertIn(ha_emqx.HASH_UNREADABLE.format(side='這台'), guide)
        self.assertIn(ha_emqx.RESET_HOW.split('；')[0].replace('這些帳號', ''), guide.replace('這些帳號', ''))
        def bare(text):   # the CONTRACT wraps its lines
            return re.sub(r'\s+', '', text)
        contract = bare((self.ROOT / 'docs' / 'backup' / 'CONTRACT.md').read_text(encoding='utf-8'))
        self.assertIn(bare(ha_emqx.PLAIN_REFUSED), contract)
        self.assertIn(bare(ha_emqx.ACCOUNTS_STOP.format(ha='<HA\'s>', mine='<this device\'s>', names='<names>')), contract)


class ParseTests(unittest.TestCase):
    def test_hashing_answers(self):
        parse = ha_emqx.parse_hashing
        self.assertEqual(parse(SHA256_SUFFIX + '\n'), hashing('sha256', 'suffix'))
        self.assertEqual(parse('[{true,pbkdf2,none,sha256,4096,32}]'),
                         hashing('pbkdf2', mac_fun='sha256', iterations=4096, dk_length=32))
        self.assertEqual(parse('[{false,bcrypt,none,none,none,undefined}]'), hashing('bcrypt', enable=False))
        self.assertIsNone(parse('[]\n'))
        for bad in ('', 'ok\n', '{badrpc,nodedown}', '[{true,sha256,suffix}]', SHA256_SUFFIX + 'x',
                    SHA256_SUFFIX[:-1] + ',' + SHA256_SUFFIX[1:], '[{true,Sha256,suffix,none,none,none}]',
                    '[{true,sha256,suffix,none,-1,none}]', 'x' + SHA256_SUFFIX):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad)

    def test_user_answers(self):
        parse = ha_emqx.parse_users
        self.assertEqual(parse('WOOWUSERS:1:d29vdw==:ENDok\n'), (1, ['woow']))
        self.assertEqual(parse('WOOWUSERS:0::ENDok'), (0, []))
        self.assertEqual(parse(users_answer(*[f'u{i}' for i in range(10)], count=12)), (12, [f'u{i}' for i in range(10)]))
        for bad in ('', 'ok', 'WOOWUSERS:2:d29vdw==:ENDok', 'WOOWUSERS:1:d29vdw:ENDok', 'WOOWUSERS:1:d29vdw==:END ok x',
                    'WOOWUSERS:1:d2*vdw==:ENDok', 'x WOOWUSERS:1:d29vdw==:ENDok', 'WOOWUSERS:0:d29vdw==:ENDok'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad)


if __name__ == '__main__':
    unittest.main()
