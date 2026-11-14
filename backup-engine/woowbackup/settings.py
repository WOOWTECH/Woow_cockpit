"""Backup settings: whether new backups are encrypted by default (CONTRACT sections 3, 7, 10). Owner: E1 (format).

`/etc/woowtech-cockpit/backup/settings.json` (root 0644, next to `keys/`): `{"schema": 1, "encrypt_by_default": bool,
"updated": "<ISO UTC>"}`. Missing means the safe default: encrypted. A file that is not root-owned, is group/world
writable, is a symlink, is too large or is not valid is ignored (encrypted, with a zh-TW `problem` for the status page),
so a damaged or planted file can never turn encryption off. Changed only through `settings-set` (validated, audited in
the journal); turning encryption off needs the explicit acknowledgement of PLAINTEXT_WARNING.
"""
import json
import os
import stat

from . import util
from .catalog_admin import audit_log, login_uid, open_trusted_dir, read_trusted_file, write_trusted_file
from .errors import BackupError

FILE = 'settings.json'
SCHEMA = 1
MAX_BYTES = 16 * 1024
DEFAULTS = {'encrypt_by_default': True}
PLAINTEXT_WARNING = ('未加密的備份會以明文儲存與下載資料庫密碼、API 金鑰與存取權杖等應用機密；任何取得備份檔的人都能讀取，'
                     '也無法確認檔案在設備以外是否被修改過。')


def _problem(text):
    return f'備份設定檔 {FILE} {text}，已改用預設值（加密備份）。'


def load(paths, *, trusted_uid=0):
    """({'encrypt_by_default': bool}, problem zh-TW | None). Never raises for a bad file: encrypted then."""
    path = os.path.join(str(paths.config), FILE)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return dict(DEFAULTS), None
    except OSError:
        return dict(DEFAULTS), _problem('無法讀取')
    if not stat.S_ISREG(st.st_mode):
        return dict(DEFAULTS), _problem('不是一般檔案')
    if st.st_uid != trusted_uid or st.st_mode & 0o022:
        return dict(DEFAULTS), _problem('不是由 root 擁有或可被其他帳號修改')
    try:
        data = util.load_json_file(path, max_bytes=MAX_BYTES)
    except (OSError, ValueError):
        return dict(DEFAULTS), _problem('格式不正確')
    if (not isinstance(data, dict) or set(data) != {'schema', 'encrypt_by_default', 'updated'}
            or data['schema'] != SCHEMA or not isinstance(data['encrypt_by_default'], bool)
            or not util.is_iso_utc(data['updated'])):
        return dict(DEFAULTS), _problem('格式不正確')
    return {'encrypt_by_default': data['encrypt_by_default']}, None


def encrypt_by_default(paths):
    """The setting as a bool (encrypted when the file is missing or unusable)."""
    return load(paths)[0]['encrypt_by_default']


def view(paths, *, trusted_uid=0):
    """`settings` of `status` / `settings-get`: the values, the problem (or null) and the warning text."""
    settings, problem = load(paths, trusted_uid=trusted_uid)
    return {**settings, 'problem': problem, 'plaintext_warning': PLAINTEXT_WARNING}


def save(paths, *, encrypt_by_default, acknowledge_plaintext=False, trusted_uid=0, audit=None):
    """Write the setting (root 0644, atomic). Turning encryption off requires `acknowledge_plaintext` True."""
    if not isinstance(encrypt_by_default, bool):
        raise BackupError('invalid-request', '欄位 encrypt_by_default 必須是 true 或 false。', field='encrypt_by_default')
    if not encrypt_by_default and acknowledge_plaintext is not True:
        raise BackupError('invalid-request', f'關閉預設加密前必須確認風險：{PLAINTEXT_WARNING}', field='acknowledge_plaintext')
    previous, _problem_text = load(paths, trusted_uid=trusted_uid)
    data = json.dumps({'schema': SCHEMA, 'encrypt_by_default': encrypt_by_default, 'updated': util.iso_utc()},
                      ensure_ascii=False, indent=2).encode('utf-8') + b'\n'
    cfd = open_trusted_dir(paths.config, trusted_uid)
    try:
        current = read_trusted_file(cfd, FILE, max_bytes=MAX_BYTES)
        if current is not None and current['uid'] != trusted_uid:
            raise BackupError('permission-denied', f'{FILE} 不是由 root 擁有；請先以 root 手動處理後再試。', file=FILE)
        write_trusted_file(cfd, FILE, data)
    finally:
        os.close(cfd)
    uid = login_uid()
    (audit or audit_log)(f'settings encrypt_by_default={str(encrypt_by_default).lower()} '
                         f'previous={str(previous["encrypt_by_default"]).lower()} '
                         f'loginuid={"-" if uid is None else uid}')
    return view(paths, trusted_uid=trusted_uid)
