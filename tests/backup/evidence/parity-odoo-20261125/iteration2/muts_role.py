T = ['tests.backup.test_ha_flows.OdooTargetTests']
MUTS = [
    ('R01', T, "STANDARD_ROLE = {'login': True, 'createdb': False,", "STANDARD_ROLE = {'login': True, 'createdb': True,"),
    ('R02', T, "STANDARD_ROLE = {'login': True, 'createdb': False, 'createrole': False,", "STANDARD_ROLE = {'login': True, 'createdb': False, 'createrole': True,"),
]
