"""Hostile-value fuzz of the Odoo check and conversion flows (parity-odoo, OD-OWNER-1735, iteration 4).
Run from a worktree root:  PYTHONPATH=backup-engine:tests/e2e/lab python3 fuzz_flows.py N [seed0] [check|convert]
Each case randomises what the fake HA database / this device answer (names, versions, states, extensions, settings) and
what the backup's custom modules hold, with hostile CONTENT (and sometimes the wrong type), and flags every run that
ends in failure.internal-error (= an exception that is no BackupError). Nothing here is a product test."""
import io, json, random, re, string, sys, unittest, contextlib
sys.path.insert(0, '.')
from tests.backup import test_ha_flows as tf

SUP2, ARAB, RLO, EMOJI = '²', '١', '‮', '\U0001f600'
NASTY = ['', ' ', '0', '-1', 'a' * 70, 'a' * 300, '\x00', 'x\ny', SUP2, ARAB, '1.2.3.4.5.6', '18.0.1.0', '18.0.', '..', '/', "'", '"', ';', '$(id)',
         '`id`', RLO, EMOJI, 'ä', '9' * 40, '-d', '--help', 'x=y', 'postgresql://x', '\t', '\\', '%s', '{}', '${x}']

def nasty_text(rnd):
    if rnd.random() < 0.5:
        return rnd.choice(NASTY)
    return ''.join(rnd.choice(string.printable + SUP2 + ARAB + RLO) for _ in range(rnd.randint(0, 40)))

DENSITY = [1.0]

def apply(world, rnd, log):
    note = log.append
    base = rnd.random
    r = lambda: base() * DENSITY[0]   # a DENSITY of 3 makes every hostile dimension a third as likely
    if r() < 0.85:
        rows = []
        for name in ['base', 'woow_import_probe', 'live_mod'] + [rnd.choice(['sale', 'a1', 'x' * 129, 'bad name', '', 'ok_mod_2', 'custom_a', 'custom_b']) for _ in range(rnd.randint(0, 3))]:
            if r() < 0.1:
                continue
            good = {'base': '18.0.1.3'}.get(name, '18.0.1.0.0')
            ver = good if (DENSITY[0] > 1 and rnd.random() < 0.85) else rnd.choice(['18.0.1.3', '18.0.1.0.0', '1', '18.0.1.' + SUP2, nasty_text(rnd), '9' * 70, '18.0.1.3', '18.0.1.0.0'])
            state = 'installed' if (DENSITY[0] > 1 and rnd.random() < 0.85) else rnd.choice(['installed'] * 3 + ['to install', 'to upgrade', 'to remove', 'uninstalled', nasty_text(rnd)])
            rows.append([name, ver, state])
        world.ha_modules = rows; note(('ha_modules', rows))
    if r() < 0.5:
        ex = [['plpgsql', '1.0']] + [[rnd.choice(['pg_trgm', 'vector', 'unaccent', 'uuid-ossp', 'dblink', nasty_text(rnd), 'x' * 70]), nasty_text(rnd)] for _ in range(rnd.randint(0, 4))]
        world.ha_extensions = ex; note(('ha_extensions', ex))
    if r() < 0.4:
        dbs = [[rnd.choice(['woowtest', 'a b', "o'brien", nasty_text(rnd), 'db' * 40]), rnd.choice([0, 9000000, -5, 10 ** 15]), rnd.choice(['C', 'en_US.UTF-8', nasty_text(rnd)]),
                rnd.choice(['C', nasty_text(rnd)])] for _ in range(rnd.randint(1, 4))]
        if not any(d[0] == 'woowtest' for d in dbs):
            dbs.insert(rnd.randint(0, len(dbs)), ['woowtest', rnd.choice([0, 9000000, 10 ** 12]), 'C', 'C'])   # the database the conversion asks for
        world.ha_databases = dbs; note(('ha_databases', dbs))
    if r() < 0.4:
        sets = [[rnd.choice(['work_mem', 'search_path', 'shared_buffers', 'log_line_prefix', 'bad name', nasty_text(rnd)]), nasty_text(rnd),
                 rnd.choice(['configuration file', 'default', 'override']), rnd.choice(['user', 'internal', 'postmaster', nasty_text(rnd)])] for _ in range(rnd.randint(0, 6))]
        world.live_settings = sets; note(('live_settings', sets))
    if r() < 0.3:
        world.superuser_kinds = [rnd.choice(['EVENT TRIGGER', 'SERVER', nasty_text(rnd)]) for _ in range(rnd.randint(0, 4))]; note(('superuser_kinds', world.superuser_kinds))
    if r() < 0.3:
        world.live_base_url = rnd.choice([None, 5, [], nasty_text(rnd), 'https://x.example/' + 'a' * 3000, {'a': 1}]); note(('live_base_url', world.live_base_url))
    if r() < 0.3:
        world.live_marker = rnd.choice([None, 5, [], nasty_text(rnd), {'digest': 'x'}, '{"digest":1}']); note(('live_marker', world.live_marker))
    if r() < 0.3:
        world.dpkg_version = rnd.choice([None, '', nasty_text(rnd), '18.0.20260926', '18.0.2026', '18.0.99999999999', '1' * 40]); note(('dpkg_version', world.dpkg_version))
    if r() < 0.3:
        world.web_env = [rnd.choice(['ODOO_VERSION=18.0', 'ODOO_RELEASE=20260926', 'ODOO_RELEASE=' + nasty_text(rnd), 'x', '', nasty_text(rnd)]) for _ in range(rnd.randint(0, 4))]; note(('web_env', world.web_env))
    if r() < 0.3:
        world.conf = {'db_name': rnd.choice(['odoo', 'prod', re.sub(r'[\x00-\x1f\x7f]', '', nasty_text(rnd)) or 'x', None]), 'db_user': rnd.choice(['odoo', 'o2', nasty_text(rnd), None]),
                      'db_password': rnd.choice(['conf-secret-Pw-0123456789', '', None, nasty_text(rnd)])}
        note(('conf', {k: ('<pw>' if k == 'db_password' else v) for k, v in world.conf.items()}))
    if r() < 0.3:
        world.live_extensions = [[rnd.choice(['plpgsql', 'pg_trgm', 'vector', nasty_text(rnd)]), rnd.choice([True, False, None, 'yes', 5])] for _ in range(rnd.randint(0, 6))]; note(('live_extensions', world.live_extensions))
    if r() < 0.3:
        lines = rnd.choice(['9; 1 2 EVENT TRIGGER - evt owner', '10; 0 0 PUBLICATION - p x', '11; 0 0 SERVER - s x', nasty_text(rnd), '12; 3 4 COMMENT - SERVER s x'])
        world.toc_extra = lines.encode('utf-8', 'replace'); note(('toc_extra', world.toc_extra))
    if r() < 0.2:
        world.live_role = rnd.choice([{'password': nasty_text(rnd), 'super': True, 'login': False, 'createdb': True, 'createrole': True, 'replication': True, 'bypassrls': True, 'connlimit': 5},
                                      None, [], {'password': None}, {'super': 'x'}]); note(('live_role', world.live_role))
    if r() < 0.2:
        world.scan_broken = rnd.choice([[], ['a'], [nasty_text(rnd)], 'x', None, [1, 2]]); note(('scan_broken', world.scan_broken))
    if r() < 0.15:
        world.extensions_by_db = {'woowtest': rnd.choice([[], [['vector', '0.8']], [['pg_trgm']], [nasty_text(rnd)], 'x', [[None, None]]])}; note(('extensions_by_db', world.extensions_by_db))

MANIFEST = "{'name': 'M', 'version': '%s', 'depends': ['base'], 'installable': %s, 'external_dependencies': {'python': %s, 'bin': %s}}"
VALS = ['[]', "['lxml']", "['no_such_pkg']", '5', 'True', "'lxml'", '{}', "{'a': 1}", 'None', "['a b', 'x[y', '../x', 'a' * 120]", "['pkg>=1.0', 'pkg[extra]', 'My_Pkg.Name']", '3.5',
        "[None, 1, 'ok']", "['wkhtmltopdf']", "['nobin']", '[' + ', '.join("'p%d'" % i for i in range(70)) + ']']

def hostile_modules(rnd, note):
    extra, names = [], []
    for name in rnd.sample(['woow_import_probe', 'custom_a', 'custom_b', 'live_mod', 'sale', 'ok_mod_2'], rnd.randint(0, 4 if DENSITY[0] >= 1 else 1)):
        kind = rnd.random()
        if kind < 0.75:
            ver = rnd.choice(['18.0.1.0.0', '18.0.1.3', '1.0', '18.0.1.' + SUP2, '9' * 100, '9' * 5000, '1.2.3.4.5.6', '', '18.0'])
            data = (MANIFEST % (ver, rnd.choice(['True', 'False', 'None', '5']), rnd.choice(VALS), rnd.choice(VALS))).encode('utf-8')
        elif kind < 0.9:
            data = rnd.choice([b'', b'{', b'[]', b'\xff\xfe', b"__import__('os')", b"{'version': %s}" % rnd.choice([b'[]', b'{}', b'None', b'True', b'1j', b'b"x"']),
                               b'(' * 300 + b')' * 300, b'-' * 2000 + b'1', b'{' * 150 + b'}' * 150, b"{'a': " * 60 + b'1' + b'}' * 60])
        else:
            data = b'x' * (256 * 1024 + 1)
        names.append((name, data[:90]))
        extra += tf.module_entries(name, data)
    note(('custom modules', names))
    return extra

NOISE = [0]
DEEP = [0]
CLEAN = {}
from woowbackup.errors import BackupError

class FuzzBase(tf.OdooCase):
    SEED = 0
    MODE = 'check'
    def test_case(self):
        rnd = random.Random(self.SEED)
        log = []
        apply(self.world, rnd, log)
        extra = hostile_modules(rnd, log.append)
        err = io.StringIO()
        bad = []
        with contextlib.redirect_stderr(err):
            try:
                if self.MODE == 'check':
                    row = self.check(self.upload_odoo(extra))
                    bad = [i['message'][:80] for i in row['issues'] if i['id'] == 'failure.internal-error']
                else:
                    ha = self.upload_odoo(extra)
                    keys = self.confirm_keys(self.check(ha), 'woowtest')
                    result = self.convert(ha, ['odoo'], acknowledged={'odoo': keys})
                    DEEP[0] += 1 if 'ha_import' in result else 0
                    if 'failure.internal-error' in json.dumps(result, default=str):
                        bad = ['internal-error in result']
            except BackupError as error:   # a clean refusal of the whole job: not a finding (counted by its code)
                CLEAN[error.code] = CLEAN.get(error.code, 0) + 1
                if error.code == 'internal-error':
                    bad = [f'INTERNAL-CODE {error.message[:100]}']
            except Exception as error:   # the flow itself threw something that is no BackupError: a finding
                bad = [f'THROWN {type(error).__name__}: {str(error)[:150]}']
        trace = err.getvalue()
        import re as _re   # the unclosed tar stream of an aborted member pass is noise of the garbage collector (counted apart)
        noise = _re.compile(r'Exception ignored in: <function _Stream.__del__.*?ValueError: write to closed file\n', _re.S)
        NOISE[0] += len(noise.findall(trace))
        trace = noise.sub('', trace)
        if bad or 'Traceback' in trace:
            tail = [ln for ln in trace.splitlines() if ln.strip()][-5:]
            print(f'FINDING seed={self.SEED} mode={self.MODE}: {bad} || ' + ' | '.join(tail)[:700])
            for item in log:
                print('   ', str(item)[:260])
            self.fail('finding')

def main():
    n = int(sys.argv[1]); seed0 = int(sys.argv[2]) if len(sys.argv) > 2 else 0; mode = sys.argv[3] if len(sys.argv) > 3 else 'check'
    DENSITY[0] = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
    suite = unittest.TestSuite()
    for i in range(n):
        suite.addTest(type(f'Fuzz{i}', (FuzzBase,), {'SEED': seed0 + i, 'MODE': mode})('test_case'))
    res = unittest.TextTestRunner(stream=open('/dev/null', 'w'), verbosity=0).run(suite)
    print(f'cases={res.testsRun} findings={len(res.failures) + len(res.errors)} tar-gc-noise={NOISE[0]} conversions-done={DEEP[0]} clean-job-refusals={CLEAN}')
    for case, tb in res.errors[:3]:
        print('ERROR in', case, tb[-500:])

main()
