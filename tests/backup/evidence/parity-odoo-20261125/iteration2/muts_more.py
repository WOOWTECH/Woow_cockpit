T = ['tests.backup.test_ha_odoo.MoreGapTests']
MUTS = [
    ('N01', T, "    try:\n        return int((src.pg_version or '').split('.')[0])\n    except ValueError:\n        return None\n", "    return int((src.pg_version or '').split('.')[0] or 0)\n"),
    ('N02', T, "            try:\n                return int(item.split('=', 1)[1].split('.')[0])\n            except ValueError:\n                return None\n", "            return int(item.split('=', 1)[1].split('.')[0])\n"),
    ('N03', T, "    except BackupError as error:\n        raise BackupError('job-failed', f'轉換後的資料卷內容無法匯入（{error.message}）。'", "    except ZeroDivisionError as error:\n        raise BackupError('job-failed', f'轉換後的資料卷內容無法匯入（{error.message}）。'"),
    ('N04', T, "            if ''.join(current).strip():\n                return None\n", "            if False:\n                return None\n"),
    ('N05', T, "    if not any(db['ok'] for db in databases):\n        return ['HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。']\n", "    if False:\n        return ['HA 的 Odoo 資料庫都不能搬過來（原因見各資料庫）。']\n"),
    ('N06', T, "    if 'choices' in found:\n        return []\n", "    if False:\n        return []\n"),
]
