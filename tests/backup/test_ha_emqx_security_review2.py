"""EMQX product import, security review iteration 2 (2026-11-24): regression tests for the product delta since the
21:52 review (28e9492 boot forms, 3761d18 EnvironmentFile=, fdb7cfe/0d260db root names, 92f2461/be2c92d scheduler
flags, be5bc6f image volume).

SR-8 (MEDIUM, real run T9 in the lab store): 3761d18 passed the values of the Quadlet's `EnvironmentFile=` files to
the candidate as `podman run --env KEY=VALUE`. Such a file may hold secrets (the product keeps it 0600, CONTRACT
"config_files"), and every local account can read a process's command line (/proc/<pid>/cmdline is 0444; this host
has no hidepid): a generated canary was in two command lines while the candidate started, in none with the device's
own `--env-file`. tempctr.run_argv's own rule says an `env` value must never be a secret. Now podman reads the files
for the candidate itself (`--env-file`), exactly as for the device's broker.

SR-9 (LOW, real run T10 against podman 4.9.3): candidate_env() split lines with str.splitlines() (also at \\v, \\f,
\\x1c-\\x1e, \\x85, \\u2028, \\u2029 and a lone \\r) and trimmed every Unicode blank, podman splits at \\n only (a final
\\r dropped) and trims blanks and tabs: 8 of 20 crafted files gave the candidate another environment than the device's
broker. podman now reads the values; the checks read the lines as podman does.
"""
import copy
import unittest
from types import SimpleNamespace

from woowbackup import tempctr
from woowbackup.errors import BackupError

from . import test_ha_emqx as base
from . import test_ha_emqx_product as product

CANARY = 'sr8-canary-not-a-credential'
ENV_FILE = '.config/emqx/emqx.env'
LINE = 'EnvironmentFile=%h/.config/emqx/emqx.env\n'


class EnvFileConversionTests(base.EmqxCase):
    def setUp(self):
        super().setUp()
        # HA's backup has ACL rows: the import target asks its built-in database too (OWNER DECISION 「C」).
        self.world.target_config['authorization']['sources'] = copy.deepcopy(base.BUILTIN_TARGET)
        self.world.current_config = copy.deepcopy(self.world.target_config)

    def test_env_file_values_never_reach_a_command_line(self):
        self.world.files[ENV_FILE] = (b'# woow emqx\nEMQX_LOG__CONSOLE__LEVEL=warning\n'
                                      b'EMQX_DASHBOARD__DEFAULT_PASSWORD=' + CANARY.encode() + b'\n')
        done = self.convert(self.upload_emqx(state='stopped'), ['emqx'])
        self.assertTrue(done['backup_id'])
        options = self.runs('emqx-new')[0][3]
        self.assertEqual(options.get('--env-file'), ['/home/appowner/' + ENV_FILE],
                         'podman reads the device\'s EnvironmentFile for the candidate itself')
        self.assertFalse([e for e in options.get('--env', []) if e.startswith(('EMQX_LOG__CONSOLE__LEVEL=',
                                                                             'EMQX_DASHBOARD__DEFAULT_PASSWORD='))])
        leaked = [call[0] for call in self.world.owner.calls if any(CANARY in str(arg) for arg in call)]
        self.assertEqual(leaked, [], 'no podman command line holds a value of the EnvironmentFile')
        self.assertIn('ERL_AFLAGS=+S 4:4', options.get('--env', []), 'the scheduler flag stays on --env (it wins)')


class EnvFileLinesTests(unittest.TestCase):
    """The checks read the lines as podman 4.9.3 does (T10, evidence/.../iteration2/t10-tip.json)."""

    def candidate(self, content):
        return product.EnvironmentFileTests.target(self, LINE, {ENV_FILE: content}).candidate_env()

    def test_one_podman_line_is_one_line(self):
        for sep in (b'\x0b', b'\x0c', b'\x1c', b'\x1d', b'\x1e', '\x85'.encode(), '\u2028'.encode(),
                    '\u2029'.encode(), b'\r'):
            with self.subTest(sep=sep):
                # podman: ONE variable EMQX_LOG__CONSOLE__LEVEL (the separator and the rest are its value); the old
                # splitlines() saw a second, conflicting EMQX_LOG__CONSOLE__LEVEL and refused
                env, files = self.candidate(b'EMQX_LOG__CONSOLE__LEVEL=warning' + sep + b'EMQX_LOG__CONSOLE__LEVEL=debug\n')
                self.assertEqual(files, ['/home/appowner/' + ENV_FILE])
                self.assertNotIn('EMQX_LOG__CONSOLE__LEVEL', env)
                # podman: one variable X (not EMQX configuration): nothing hidden after the separator is EMQX's
                self.assertEqual(self.candidate(b'X=1' + sep + b'EMQX_NODE__NAME="emqx@10.0.0.1"\n')[1],
                                 ['/home/appowner/' + ENV_FILE])

    def test_only_blanks_and_tabs_are_trimmed(self):
        # podman keeps U+3000/\x1c in the name: `\\u3000EMQX_NODE__NAME` is no EMQX setting (the old lstrip() made it
        # one, conflicting with the Quadlet's EMQX_NODE__NAME)
        for lead in ('\u3000'.encode(), b'\x1c'):
            with self.subTest(lead=lead):
                self.assertEqual(self.candidate(lead + b'EMQX_NODE__NAME=emqx@10.0.0.1\n')[1],
                                 ['/home/appowner/' + ENV_FILE])
        for lead in (b' ', b'\t', b' \t '):
            with self.subTest(lead=lead):
                with self.assertRaises(BackupError) as caught:   # a real EMQX line: conflicts with the Quadlet
                    self.candidate(lead + b'EMQX_NODE__NAME=emqx@10.0.0.1\n')
                self.assertIn('EnvironmentFile（~/.config/emqx/emqx.env）', caught.exception.message)

    def test_a_final_carriage_return_is_dropped_like_podman(self):
        env, files = self.candidate(b'EMQX_LOG__CONSOLE__LEVEL=warning\r\nEMQX_LOG__CONSOLE__LEVEL=warning\r\n')
        self.assertEqual(files, ['/home/appowner/' + ENV_FILE])
        with self.assertRaises(BackupError):
            self.candidate(b'EMQX_LOG__CONSOLE__LEVEL=warning\r\nEMQX_LOG__CONSOLE__LEVEL=debug\r\n')

    def test_what_podman_reads_literally_but_is_not_plain_still_refuses(self):
        for content in (b'EMQX_A=1\rEMQX_B="q"\n', b'EMQX_A="1"\r\n', b'EMQX_A=$B\n', b'EMQX_A=1 \n'):
            with self.subTest(content=content):
                with self.assertRaises(BackupError) as caught:
                    self.candidate(content)
                self.assertEqual(caught.exception.code, 'incompatible')


class EnvFilesArgvTests(unittest.TestCase):
    def tmp(self):
        return tempctr.TempObjects(SimpleNamespace(uid=None), 'j20261124T000000Z-0123abcd', cpus=None)

    def test_env_files_become_env_file_flags(self):
        argv = self.tmp().run_argv('x', 'docker.io/emqx/emqx:5.8.9', env={'A': '1'},
                                   env_files=['/home/o/.config/emqx/emqx.env'])
        self.assertEqual(argv[argv.index('--env-file') + 1], '/home/o/.config/emqx/emqx.env')
        self.assertEqual(argv[argv.index('--env') + 1], 'A=1')
        self.assertNotIn('--env-file', self.tmp().run_argv('x', 'docker.io/emqx/emqx:5.8.9'))

    def test_a_path_that_is_not_plain_and_absolute_refuses(self):
        for bad in ('relative.env', '/home/o/../etc/shadow', '/home/o/./x', '/home//x', '/home/o/', '/', '/home/o/x y',
                    '/a\nb', '', 7, None, b'/home/o/x'):
            with self.subTest(bad=bad):
                with self.assertRaises(BackupError) as caught:
                    self.tmp().run_argv('x', 'docker.io/emqx/emqx:5.8.9', env_files=[bad])
                self.assertEqual(caught.exception.code, 'internal-error')


if __name__ == '__main__':
    unittest.main()
