"""age X25519 key management and the emergency kit (CONTRACT sections 1, 5, 7). Owner: E1.

Layout (`paths.keys`, 0700): `device-<KEYID>.key` / `imported-<KEYID>.key` identity files (0600, age
identity format) plus `keys.json` (0600) holding metadata (created, kit confirmation). The key
files are the source of truth: a lost or damaged `keys.json` only loses metadata, never keys.

Secret keys never appear in argv, the environment, logs or error messages: `age-keygen` writes the
new identity to a pipe and `age-keygen -y` reads secrets from stdin.
"""
import contextlib
import datetime
import errno
import fcntl
import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import util
from .errors import BackupError

SECRET_RE = re.compile(r'^AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\Z')
RECIPIENT_RE = re.compile(r'^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}\Z')
KEY_ID_RE = re.compile(r'^[0-9A-F]{4}(?:-[0-9A-F]{4}){3}\Z')
KEY_FILE_RE = re.compile(r'^(device|imported)-([0-9A-F]{4}(?:-[0-9A-F]{4}){3})\.key\Z')
TEMP_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\Z')
MAX_SECRET_INPUT = 4096
MAX_KEY_FILE = 4096
MAX_KEYS_JSON = 256 * 1024
KEYGEN_TIMEOUT = 30

MSG_BAD_SECRET = '金鑰格式不正確，請貼上以 AGE-SECRET-KEY-1 開頭的完整緊急金鑰。'


@dataclass(frozen=True)
class KeyInfo:
    key_id: str
    recipient: str
    path: object  # pathlib.Path of the identity file (0600)
    kind: str  # 'device' | 'imported'
    created: str
    kit_confirmed: bool = False

    def as_dict(self):
        """Public, secret-free view (`status.key` / `imported_keys[]`)."""
        return {'key_id': self.key_id, 'kind': self.kind, 'created': self.created,
                'kit_confirmed': self.kit_confirmed}


def key_id_for(recipient):
    """sha256(recipient)[:16] upper-case grouped XXXX-XXXX-XXXX-XXXX."""
    digest = hashlib.sha256(recipient.encode('utf-8')).hexdigest()[:16].upper()
    return '-'.join(digest[i:i + 4] for i in range(0, 16, 4))


def normalize_secret(text):
    """Return the single canonical `AGE-SECRET-KEY-1…` line contained in user text.

    Accepted: the bare key line, or an age identity file (comment lines starting with '#',
    blank lines and exactly one key line). Bech32 is case-insensitive, so the key is upper-cased.
    Anything else raises BackupError('invalid-request') without echoing the input.
    """
    if not isinstance(text, str) or not text or len(text) > MAX_SECRET_INPUT or '\x00' in text:
        raise BackupError('invalid-request', MSG_BAD_SECRET)
    lines = [line.strip() for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n')]
    candidates = [line for line in lines if line and not line.startswith('#')]
    if len(candidates) != 1:
        raise BackupError('invalid-request', MSG_BAD_SECRET)
    key = candidates[0].upper()
    if not SECRET_RE.match(key):
        raise BackupError('invalid-request', MSG_BAD_SECRET)
    return key


def _keygen(args, stdin_data=None):
    tool = util.find_tool('age-keygen')
    if tool is None:
        raise BackupError('internal-error', '系統缺少 age-keygen 工具，無法管理加密金鑰。')
    try:
        return subprocess.run([tool, *args], input=stdin_data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=util.clean_env(), timeout=KEYGEN_TIMEOUT,
                              close_fds=True, check=False)
    except subprocess.TimeoutExpired as exc:
        raise BackupError('internal-error', '金鑰工具沒有回應。') from exc


def recipient_for_secret(secret):
    """Derive the public recipient with `age-keygen -y`; the secret travels on stdin only.

    Also validates the bech32 checksum; raises BackupError('invalid-request') on a bad key.
    """
    secret = normalize_secret(secret)
    proc = _keygen(['-y'], (secret + '\n').encode('ascii'))
    out = proc.stdout.decode('ascii', 'replace').strip()
    if proc.returncode != 0 or not RECIPIENT_RE.match(out):
        raise BackupError('invalid-request', MSG_BAD_SECRET)
    return out


def secret_info(secret_text):
    """{'key_id', 'recipient'} of a user-supplied secret (validated); never returns the secret."""
    recipient = recipient_for_secret(secret_text)
    return {'key_id': key_id_for(recipient), 'recipient': recipient}


def _identity_file_text(secret, recipient, created):
    return f'# created: {created}\n# public key: {recipient}\n{secret}\n'


def _write_new_file(path, data, mode=0o600):
    """Create `path` exclusively (no symlink following), write, fsync, fsync dir."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    os.close(fd)
    util.fsync_dir(Path(path).parent)


class KeyStore:
    def __init__(self, paths):
        self.paths = paths

    # ------------------------------------------------------------ storage helpers

    @property
    def dir(self):
        return Path(self.paths.keys)

    @property
    def meta_path(self):
        return self.dir / 'keys.json'

    def _ensure_dirs(self):
        config = Path(self.paths.config)
        if not os.path.lexists(config):
            util.ensure_dir(config, 0o755)
        util.ensure_dir(self.dir, 0o700)

    @contextlib.contextmanager
    def _locked(self):
        self._ensure_dirs()
        fd = os.open(self.dir / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _read_meta(self):
        """keys.json content; a missing or damaged file yields an empty skeleton (metadata only)."""
        try:
            data = util.load_json_file(self.meta_path, max_bytes=MAX_KEYS_JSON)
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('keys'), dict):
            return {'schema': 1, 'device': None, 'keys': {}}
        if not isinstance(data.get('device'), str) or not KEY_ID_RE.match(data['device']):
            data['device'] = None
        return data

    def _write_meta(self, meta):
        util.atomic_write_json(self.meta_path, meta, 0o600)

    def _read_secret(self, path):
        try:
            raw = util.read_file_limited(path, MAX_KEY_FILE)
            return normalize_secret(raw.decode('ascii', 'strict'))
        except (OSError, ValueError, BackupError) as exc:
            raise BackupError('internal-error', '讀取這台設備的加密金鑰失敗，金鑰檔可能已損毀。') from exc

    def _scan(self):
        """[(kind, key_id, path, stat)] of plausible key files: regular, not symlinks, ours, 0600."""
        try:
            names = sorted(os.listdir(self.dir))
        except (FileNotFoundError, NotADirectoryError):
            return []
        found = []
        for name in names:
            match = KEY_FILE_RE.match(name)
            if not match:
                continue
            path = self.dir / name
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                continue  # symlinks, devices and foreign files are never used as identities
            if st.st_mode & 0o077:
                # Tighten instead of ignoring: ignoring would make ensure_device_key() mint a new key.
                try:
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                    try:
                        os.fchmod(fd, 0o600)
                    finally:
                        os.close(fd)
                except OSError:
                    continue
            found.append((match.group(1), match.group(2), path, st))
        return found

    def _infos(self):
        meta = self._read_meta()
        entries = meta['keys']
        infos = []
        for kind, key_id, path, st in self._scan():
            record = entries.get(key_id) if isinstance(entries.get(key_id), dict) else {}
            recipient = record.get('recipient')
            if not (isinstance(recipient, str) and RECIPIENT_RE.match(recipient)
                    and key_id_for(recipient) == key_id):
                try:
                    recipient = recipient_for_secret(self._read_secret(path))
                except (BackupError, OSError, ValueError):
                    continue
                if key_id_for(recipient) != key_id:
                    continue
            created = record.get('created')
            if not util.is_iso_utc(created):
                created = util.iso_utc(datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc))
            confirmed = kind == 'device' and record.get('kit_confirmed') is True
            infos.append(KeyInfo(key_id, recipient, path, kind, created, confirmed))
        return infos, meta

    @staticmethod
    def _pick_device(infos, meta):
        devices = [info for info in infos if info.kind == 'device']
        if not devices:
            return None
        for info in devices:
            if info.key_id == meta.get('device'):
                return info
        return max(devices, key=lambda info: (info.created, info.key_id))

    # ------------------------------------------------------------ public API

    def device_key(self):
        """Current encryption KeyInfo or None."""
        infos, meta = self._infos()
        return self._pick_device(infos, meta)

    def ensure_device_key(self):
        """Return (KeyInfo, created_bool); generates with age-keygen when missing."""
        with self._locked():
            infos, meta = self._infos()
            current = self._pick_device(infos, meta)
            if current is not None:
                if meta.get('device') != current.key_id:
                    # Adopt an orphan device key (e.g. keys.json lost) instead of replacing it.
                    meta['device'] = current.key_id
                    meta['keys'].setdefault(current.key_id, {}).update(
                        {'kind': 'device', 'recipient': current.recipient, 'created': current.created})
                    self._write_meta(meta)
                return current, False
            proc = _keygen([])  # stdout is a pipe: the secret is never on argv/env/a world-readable file
            if proc.returncode != 0:
                raise BackupError('internal-error', '建立加密金鑰失敗。')
            secret = normalize_secret(proc.stdout.decode('ascii', 'replace'))
            recipient = recipient_for_secret(secret)
            key_id = key_id_for(recipient)
            created = util.iso_utc()
            path = self.dir / f'device-{key_id}.key'
            _write_new_file(path, _identity_file_text(secret, recipient, created).encode('ascii'))
            meta['device'] = key_id
            meta['keys'][key_id] = {'kind': 'device', 'recipient': recipient, 'created': created,
                                    'kit_confirmed': False, 'kit_confirmed_at': None}
            self._write_meta(meta)
            return KeyInfo(key_id, recipient, path, 'device', created, False), True

    def identities(self):
        """All KeyInfo usable for decryption (device first, then other device keys, then imported)."""
        infos, meta = self._infos()
        current = self._pick_device(infos, meta)
        rest = [info for info in infos if info is not current]
        rest.sort(key=lambda info: (info.kind != 'device', info.created, info.key_id))
        return ([current] if current else []) + rest

    def find(self, key_id):
        if not isinstance(key_id, str) or not KEY_ID_RE.match(key_id):
            return None
        for info in self.identities():
            if info.key_id == key_id:
                return info
        return None

    def import_key(self, secret_text):
        """Validate an AGE-SECRET-KEY-1… string, store as imported identity, return KeyInfo."""
        secret = normalize_secret(secret_text)
        recipient = recipient_for_secret(secret)
        key_id = key_id_for(recipient)
        with self._locked():
            infos, meta = self._infos()
            for info in infos:
                if info.key_id == key_id:
                    return info
            created = util.iso_utc()
            path = self.dir / f'imported-{key_id}.key'
            if os.path.lexists(path):
                # A damaged or foreign file squats the name: replace it atomically with the valid key.
                util.atomic_write(path, _identity_file_text(secret, recipient, created), 0o600)
            else:
                _write_new_file(path, _identity_file_text(secret, recipient, created).encode('ascii'))
            meta['keys'][key_id] = {'kind': 'imported', 'recipient': recipient, 'created': created}
            self._write_meta(meta)
            return KeyInfo(key_id, recipient, path, 'imported', created, False)

    def kit_filename(self):
        info = self.device_key()
        if info is None:
            raise BackupError('no-device-key', '這台設備尚未建立加密金鑰。')
        return f'woowtech-backup-key-{util.sanitize_hostname(util.hostname())}-{info.key_id}.txt'

    def kit_text(self):
        """zh-TW emergency kit text containing key id, secret key and restore instructions."""
        info = self.device_key()
        if info is None:
            raise BackupError('no-device-key', '這台設備尚未建立加密金鑰。')
        secret = self._read_secret(info.path)
        host = util.hostname()
        return '\n'.join([
            'woowtech Cockpit 備份緊急金鑰',
            '================================',
            '',
            '這是還原加密備份檔（.woowbackup）所需的金鑰。請立即把這個檔案保存到這台設備以外的安全位置，',
            '例如密碼管理器、加密隨身碟，或列印後上鎖保管。',
            '',
            f'金鑰 ID：{info.key_id}',
            f'建立時間：{info.created}（UTC）',
            f'建立設備：{host}',
            '',
            '緊急金鑰（請完整複製下一行，包含開頭的 AGE-SECRET-KEY-1）：',
            '',
            secret,
            '',
            '如何在另一台設備還原',
            '1. 在目標設備登入 Cockpit，以管理員身分開啟「備份與還原」頁面。',
            '2. 到「從檔案還原」，上傳你下載保存的 .woowbackup 備份檔。',
            '3. 頁面要求輸入金鑰時，貼上上方以 AGE-SECRET-KEY-1 開頭的整行金鑰。',
            '   若選擇在該設備保存金鑰，日後還原同一金鑰加密的備份時就不必再次輸入。',
            '4. 檢查預檢結果與受影響的應用，確認後開始還原。',
            '',
            '重要警告',
            '- 遺失這把金鑰後，以它加密的備份將永遠無法還原；任何人（包括 woowtech）都無法替你找回或重設。',
            '- 這台設備故障或重新安裝時，設備上保存的金鑰也會一起消失，屆時只能依靠這份緊急金鑰。',
            '- 任何同時取得這把金鑰與備份檔的人，都能讀取備份中的資料庫、檔案與應用機密。',
            '  請勿以電子郵件、聊天訊息或公開雲端分享傳送，也不要和備份檔存放在同一處。',
            '',
        ])

    def confirm_kit(self, key_id):
        if not isinstance(key_id, str) or not KEY_ID_RE.match(key_id):
            raise BackupError('invalid-request', '金鑰 ID 格式不正確。')
        with self._locked():
            infos, meta = self._infos()
            current = self._pick_device(infos, meta)
            if current is None:
                raise BackupError('no-device-key', '這台設備尚未建立加密金鑰。')
            if current.key_id != key_id:
                raise BackupError('invalid-request', '金鑰 ID 與這台設備目前的加密金鑰不符。', key_id=key_id)
            record = meta['keys'].setdefault(key_id, {})
            record.update({'kind': 'device', 'recipient': current.recipient, 'created': current.created,
                           'kit_confirmed': True, 'kit_confirmed_at': util.iso_utc()})
            meta['device'] = key_id
            self._write_meta(meta)
            return KeyInfo(current.key_id, current.recipient, current.path, 'device', current.created, True)

    @contextlib.contextmanager
    def temp_identity(self, secret_text, name):
        """Context manager: write a validated secret key to run/<name> (0600), yield its Path, always delete."""
        if not isinstance(name, str) or not TEMP_NAME_RE.match(name):
            raise BackupError('invalid-request', '暫存金鑰名稱不正確。')
        secret = normalize_secret(secret_text)
        recipient_for_secret(secret)  # checksum check: a typo must not look like a corrupt archive
        run = util.ensure_dir(Path(self.paths.run), 0o700)
        path = run / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            os.unlink(path)  # stale file from an interrupted run; unlink never follows a symlink
            fd = os.open(path, flags, 0o600)
        try:
            try:
                os.fchmod(fd, 0o600)
                data = memoryview((secret + '\n').encode('ascii'))
                while data:
                    data = data[os.write(fd, data):]
            finally:
                os.close(fd)
            yield path
        finally:
            try:
                os.unlink(path)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
