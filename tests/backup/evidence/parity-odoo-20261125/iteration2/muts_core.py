T = ['tests.backup.test_ha_odoo.GateCoreTests', 'tests.backup.test_ha_flows.OdooTargetTests.test_the_release_of_the_marker_is_the_version_of_the_odoo_package_else_the_variables_of_the_image']
MUTS = [
    ('C01', T, "    core = version.split(':', 1)[1] if ':' in version else version\n", "    core = version\n"),
    ('C02', T, "    core = re.split(r'[-+~]', core, maxsplit=1)[0]\n", "    core = re.split(r'[-+]', core, maxsplit=1)[0]\n"),
    ('C03', T, "    core = '.'.join(core.split('.')[:3])\n", "    core = '.'.join(core.split('.')[:4])\n"),
    ('C04', T, "CORE_RE = re.compile(r'18\\.0\\.[0-9]{8}\\Z')", "CORE_RE = re.compile(r'18\\.0\\.[0-9]+\\Z')"),
    ('C05', T, "    core = gate_core(value)\n    if core is not None:\n        return core\n", "    core = value if value else None\n    if core is not None:\n        return core\n"),
    ('C06', T, "    return gate_core(composite)\n", "    return composite\n"),
    ('C07', T, "    core = re.split(r'[-+~]', core, maxsplit=1)[0]\n", "    core = re.split(r'[-+~]', core, maxsplit=1)[-1]\n"),
]
