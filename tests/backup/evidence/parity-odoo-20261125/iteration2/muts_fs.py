T = ['tests.backup.test_ha_odoo.RewriteTests', 'tests.backup.test_ha_odoo.ScanTests', 'tests.backup.test_ha_flows.OdooTargetTests.test_the_database_and_the_account_are_those_of_the_configuration']
MUTS = [
    ('F01', T, "                target = f'filestore/{filestore_name}' + (f'/{tail}' if tail else '')\n", "                target = 'filestore/odoo' + (f'/{tail}' if tail else '')\n"),
    ('F02', T, "            if _under(name, f'filestore/{database}') or _under(name, 'sessions'):\n", "            if _under(name, 'filestore/odoo') or _under(name, 'sessions'):\n"),
    ('F03', T, "    if not isinstance(filestore_name, str) or not DB_NAME_RE.fullmatch(filestore_name):\n        raise BackupError('internal-error', '附件資料夾名稱格式不正確。')\n", "    pass\n"),
    ('F04', T, "    if not isinstance(database, str) or not DB_NAME_RE.fullmatch(database):\n        raise BackupError('internal-error', '附件資料夾名稱格式不正確。')\n    try:\n        return _web_data_tar", "    pass\n    try:\n        return _web_data_tar"),
    ('F05', T, "web_data_tar(live_web, web, sessions_ids=odoo_ids, report=live_report, database=live.db_name)", "web_data_tar(live_web, web, sessions_ids=odoo_ids, report=live_report)"),
    ('F06', T, "modules=modules_tar, filestore_name=live.db_name)", "modules=modules_tar)"),
]
