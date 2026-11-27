"""Long form of tests.backup.test_ha_backup.FuzzTests: many damaged copies of synthetic and fixture backups (the committed
securetar fixtures), seeds 0..N; every one must end in a BackupError of a known code or in exactly the content as written
(checksummed kinds) -- never another exception, never other content. Prints counts only.
usage: long_fuzz.py ROUNDS_PER_KIND   (cwd = the lane worktree; PYTHONPATH=backup-engine:tests/e2e/lab)"""
import json, os, random, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, os.getcwd())
from woowbackup import habackup, hasecuretar
from woowbackup.errors import BackupError
from tests.backup import hafixtures as hx
from tests.backup import test_ha_backup as t

ROUNDS = int(sys.argv[1])
CODES = ('corrupt-archive', 'limit-exceeded', 'unsupported-format', 'not-found', 'wrong-key', 'key-required')


class Run(t.FuzzTests):
    def runTest(self):
        pass


case = Run()
case.setUp()
kinds = [('gzip', hx.two_addons(doc=hx.ha_doc([hx.ODOO, hx.N8N])), None, True),
         ('plain', hx.outer_bytes([(f'{hx.ODOO}.tar', hx.addon_member(compress=False))], hx.ha_doc(compressed=False)), None, False)]
if hx.HAVE_NACL and hx.HAVE_CRYPTOGRAPHY:
    keys = hasecuretar.Keys(hx.PASSWORD)
    kinds += [('v3', hx.fixture('v3_gzip.tar').read_bytes(), keys, True), ('v2', hx.fixture('v2_gzip.tar').read_bytes(), keys, True)]
total, report = {}, {}
t0 = time.time()
for name, data, keys, checked in kinds:
    good = case.entries(case.write(data), keys)
    outcomes = {}
    path = case.dir / 'long.tar'
    for seed in range(ROUNDS):
        rng = random.Random(seed * 7919 + len(name))
        path.write_bytes(case.damage(rng, data))
        try:
            got = case.entries(path, keys)
        except BackupError as error:
            assert error.code in CODES, (name, seed, error.code)
            outcomes[error.code] = outcomes.get(error.code, 0) + 1
            continue
        outcomes['read'] = outcomes.get('read', 0) + 1
        if checked:
            for member, rows in got.items():
                assert rows == good.get(member), ('other content', name, seed, member)
    report[name] = outcomes
    for k, v in outcomes.items():
        total[k] = total.get(k, 0) + v
print(json.dumps({'rounds_per_kind': ROUNDS, 'kinds': [k[0] for k in kinds], 'outcomes': report, 'total': sum(total.values()),
                  'seconds': round(time.time() - t0)}))
case.doCleanups()
