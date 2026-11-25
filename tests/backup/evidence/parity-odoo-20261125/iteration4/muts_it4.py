import ast
_src = open('/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/parity-odoo/mutations.py', encoding='utf-8').read()
_tree = ast.parse(_src)
_node = next(n for n in _tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '') == 'MUTATIONS')
_all = {m[0]: m for m in ast.literal_eval(_node.value)}
V = ('tests.backup.test_ha_odoo.VersionTests',)
E = ('tests.backup.test_ha_odoo.EnvironmentFileTests', 'tests.backup.test_ha_odoo.MountTests', 'tests.backup.test_ha_odoo.LiveTests',
     'tests.backup.test_ha_flows.OdooTargetTests')
MUTS = [(i, V, _all[i][2], _all[i][3]) for i in ('M114', 'M115', 'M116', 'M117', 'M118', 'M119')]
MUTS += [(i, E, _all[i][2], _all[i][3]) for i in ('M88', 'M93', 'M120', 'M121', 'M122', 'M123', 'M124', 'M125', 'M126', 'M127', 'M128', 'M129', 'M130', 'M131', 'M132', 'M133')]

MUTS += [(i, ('tests.backup.test_ha_flows.OdooTargetTests', 'tests.backup.test_ha_odoo.VerdictTests', 'tests.backup.test_ha_odoo.TargetTests'), _all[i][2], _all[i][3]) for i in ('M134', 'M135', 'M136')]

MUTS += [('M137', ('tests.backup.test_ha_flows.OdooTargetTests',), _all['M137'][2], _all['M137'][3])]

MUTS = [m if m[0] != 'M136' else (m[0], ('tests.backup.test_ha_odoo.SqlTests',) + m[1], m[2], m[3]) for m in MUTS]
