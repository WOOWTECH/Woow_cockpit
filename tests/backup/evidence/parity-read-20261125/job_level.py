"""READ + F1 merged (scratch worktree): every way an add-on can be broken, at job level (run_verify with fakes): only it stops."""
import sys, gzip, struct, unittest
sys.path.insert(0, '/tmp/parity-read-merge-20261125'); sys.path.insert(0, '/tmp/parity-read-merge-20261125/backup-engine')
from tests.backup import test_ha_import as t, hafixtures as hx
from unittest import mock
class Case(t.AddonTests):
    def runTest(self): pass
good = hx.addon_member()
plain = hx.addon_member(compress=False)
head = b'SecureTar\x03' + bytes(6) + struct.pack('!Q8x', 100)
def two(odoo, **kw): return hx.two_addons(odoo=odoo, n8n=t.N8N_MEMBER, **kw)
cases = {
 'not an archive': two(b'\x01' * 4096), 'unsupported encryption': two(b'SecureTar\x08' + bytes(600)), 'size mismatch': two(head + bytes(10)),
 'empty': two(b''), 'cut gzip': two(good[:-20]), 'crc': two(good[:-8] + bytes(8)),
 'cut tar': two(gzip.compress(plain[:700])), 'hostile name in front': two(hx.tar_bytes([{'name': '../x', 'data': b'x'}], compress=True)),
 'bad addon.json': two(hx.tar_bytes([{'name': './addon.json', 'data': b'{'}], compress=True)),
 'duplicate': hx.two_addons(n8n=t.N8N_MEMBER, extra=[(f'{hx.ODOO}.tar.gz', b'other')]),
 'missing': hx.outer_bytes([(f'{hx.N8N}.tar.gz', t.N8N_MEMBER)], hx.ha_doc([hx.ODOO, hx.N8N])),
 'not listed': hx.outer_bytes([(f'{hx.N8N}.tar.gz', t.N8N_MEMBER)], hx.ha_doc([hx.N8N])),
}
for label, data in cases.items():
    case = Case(); case.setUp()
    try:
        ha_id = case.upload(data)
        called, row = case.checked(ha_id)
        print(f'{label:26}', [i['id'] for i in row['issues']], 'module called' if called else 'module not called', '| importable', row['importable'])
        msgs = {i['message'][:38] for i in row['issues']}
        print(' ' * 27, msgs)
    finally:
        case.doCleanups()
