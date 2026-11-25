"""READ + F1 merged (a throw-away merge tree): twelve ways an add-on member of an HA backup can be broken, at job level (flows.run_verify with FAKE
importer checks: the Odoo and n8n check functions are mocked, nothing is installed or imported). For each one: which issues the damaged app got, whether the
importer's own check was called for it, whether it is importable, and whether the other app stayed importable (the test helper asserts that).
usage: job_level.py TREE   (TREE = a checkout with tests/backup/test_ha_import.py and the lane's engine, e.g. BASE merged with parity/read-20261125)
Prints one line per case and a last line with the count. Only counts, ids and short texts of this repository; no value of any secret is involved.
What the count means: at CHECK time, with small fake members. A damage that lies behind the part of the member the check walks (the cut of a tiny gzip
whose end the fake check never reads) is not seen here; the reader itself stops it when it reads the member to its end (tested in the lane's unit tests)."""
import sys, gzip, struct
TREE = sys.argv[1]
sys.path.insert(0, TREE); sys.path.insert(0, TREE + '/backup-engine')
from tests.backup import test_ha_import as t, hafixtures as hx


class Case(t.AddonTests):
    def runTest(self):
        pass


good = hx.addon_member()
plain = hx.addon_member(compress=False)
head = b'SecureTar\x03' + bytes(6) + struct.pack('!Q8x', 100)


def two(odoo, **kw):
    return hx.two_addons(odoo=odoo, n8n=t.N8N_MEMBER, **kw)


cases = {
    'not an archive': two(b'\x01' * 4096), 'unsupported encryption': two(b'SecureTar\x08' + bytes(600)), 'size mismatch': two(head + bytes(10)),
    'empty': two(b''), 'cut gzip': two(good[:-20]), 'crc': two(good[:-8] + bytes(8)),
    'cut tar': two(gzip.compress(plain[:700])), 'hostile name in front': two(hx.tar_bytes([{'name': '../x', 'data': b'x'}], compress=True)),
    'bad addon.json': two(hx.tar_bytes([{'name': './addon.json', 'data': b'{'}], compress=True)),
    'duplicate': hx.two_addons(n8n=t.N8N_MEMBER, extra=[(f'{hx.ODOO}.tar.gz', b'other')]),
    'missing': hx.outer_bytes([(f'{hx.N8N}.tar.gz', t.N8N_MEMBER)], hx.ha_doc([hx.ODOO, hx.N8N])),
    'not listed': hx.outer_bytes([(f'{hx.N8N}.tar.gz', t.N8N_MEMBER)], hx.ha_doc([hx.N8N])),
}
stopped, not_stopped = [], []
for label, data in cases.items():
    case = Case()
    case.setUp()
    try:
        ha_id = case.upload(data)
        called, row = case.checked(ha_id)   # also asserts: the other app is importable
        ids = [i['id'] for i in row['issues']]
        only_the_app = (not row['importable']) and bool(ids)
        (stopped if only_the_app else not_stopped).append(label)
        print(f'{label:24} issues={ids} importer_check={"called" if called else "not called"} importable={row["importable"]} '
              f'other_app_importable=True -> {"stops only this app" if only_the_app else "NOT stopped at check time"}')
    finally:
        case.doCleanups()
print(f'RESULT {len(stopped)} of {len(cases)} damaged members stop only their own app at check time (fakes, not real); '
      f'not stopped at check time: {not_stopped}')
