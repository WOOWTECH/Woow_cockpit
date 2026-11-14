"""Deep verification of a backup's content (CONTRACT sections 5 and 7, verify job). Owner: E1 (format).

Before 2026-11-13 the verify job only checked the archive itself (keys, sizes, sha256), so a backup whose volume, image or
host-directory tar a restore would refuse still showed 已驗證 until that restore. Now the verify job hands every entry
of every app to `DeepCheck` while it streams the archive (`archive.verify_archive(deep=…, scratch_dir=…)`: one entry at
a time in a private scratch directory, deleted right after its check), and each entry gets the check a restore runs on
it before it changes anything, with the same code:

* volume tars: `nested.check_volume` (members, links, names, counts; podman's import rules),
* host-directory tars: `nested.check_dir`,
* included images: `nested.check_oci` against the ref and image id the backup recorded,
* data digests (`verify_digests`): `digests.read_files_detail` / `read_pg_detail` -- strict listing, and its recomputed
  digest and summary equal the manifest's,
* instance-mode role scripts: `adapters.quadlet_postgres.globals_statements` (what psql would be given),
* database dumps: pg_dump's custom format (`PGDMP` header only; pg_restore read the whole dump when this device made
  the backup, and reads it again at restore -- the result says so: `header_only`, review L8),
* secrets: 1..511,999 bytes (what `podman secret create` accepts).

What stays with the restore preflight because it depends on the device: the owner's ID range ("capacity") for volume
and directory members, the image names this device's templates need, PostgreSQL versions and the local catalog.
"""
from . import digests, nested
from .errors import BackupError

SECRET_MAX = 511999
DUMP_MAGIC = b'PGDMP'
GLOBALS_MAX = 16 * 1024 * 1024
KINDS = ('volumes', 'dirs', 'images', 'digests', 'globals', 'dumps', 'secrets')
LABELS = {'volumes': '資料卷', 'dirs': '主機資料夾', 'images': '容器映像', 'digests': '資料摘要',
          'globals': '資料庫角色定義', 'dumps': '資料庫匯出', 'secrets': '應用機密'}
FILE_KINDS = ('volumes', 'dirs', 'images', 'digests', 'globals')  # checked on a scratch copy; the rest from the stream
LOCAL_ERRORS = ('internal-error', 'insufficient-space')
# What the check of a kind proves (review L8): a dump is only recognized by its pg_dump header here; its body was read
# in full by pg_restore when this device created the backup, and is read in full again by a restore.
HEADER_ONLY = ('dumps',)


class DeepCheck:
    """`start(apps)` with the manifest's app sections, then `wants(path)` / `entry(path, head, file, size)` per entry
    (archive.verify_archive calls them), then `report()`."""

    def __init__(self, log=None):
        self.log = log or (lambda _message: None)
        self.items = {}
        self.counts = {}
        self.names = {}
        self.notes = []

    def start(self, apps):
        for app in apps:
            app_id = app['id']
            self.names[app_id] = app.get('name') or app_id
            self.counts[app_id] = dict.fromkeys(KINDS, 0)

            def add(entry, kind, item, label, app_id=app_id):
                if isinstance(entry, str):
                    self.items[entry] = (kind, app_id, item, label)

            for item in app.get('volumes') or []:
                add(item.get('entry'), 'volumes', item, item.get('name'))
            for item in app.get('data_dirs') or []:
                add(item.get('entry'), 'dirs', item, f'~/{item.get("path")}')
            for item in app.get('images') or []:
                add(item.get('entry'), 'images', item, item.get('ref'))
            for item in app.get('verify_digests') or []:
                add(item.get('entry'), 'digests', item, item.get('id'))
            for item in app.get('postgres') or []:
                if item.get('scope') == 'instance':
                    add(item.get('entry'), 'globals', item, item.get('id'))
                    for db in item.get('databases') or []:
                        add(db.get('entry'), 'dumps', db, f'{item.get("id")}/{db.get("name")}')
                else:
                    add(item.get('entry'), 'dumps', item, f'{item.get("id")}/{item.get("database")}')
            for item in app.get('secrets') or []:
                add(item.get('entry'), 'secrets', item, item.get('name'))

    def wants(self, path):
        found = self.items.get(path)
        return found is not None and found[0] in FILE_KINDS

    def _fail(self, app_id, kind, label, error=None, reason=None):
        details = dict(getattr(error, 'details', None) or {})
        why = details.get('label') or reason or (error.message if error is not None else '')
        member = details.get('member')
        text = f'應用「{self.names.get(app_id, app_id)}」的{LABELS[kind]} {label} 未通過還原前的內容檢查'
        if why:
            text += f'（{str(why)[:200]}'
            text += f'：{str(member)[:200]}）' if member else '）'
        raise BackupError('corrupt-archive', text + '；這份備份無法還原。', app=app_id, check=kind,
                          item=str(label)[:200], reason=str(details.get('reason') or reason or '')[:200])

    def entry(self, path, head, file, size):
        found = self.items.get(path)
        if found is None:
            return
        kind, app_id, item, label = found
        try:
            if kind == 'volumes':
                report = nested.check_volume(file)
                self.notes.extend(report.warnings(label))
            elif kind == 'dirs':
                report = nested.check_dir(file)
                self.notes.extend(report.warnings(label))
            elif kind == 'images':
                nested.check_oci(file, ref=item.get('ref'), image_id=item.get('id'))
            elif kind == 'digests':
                read = digests.read_files_detail if item.get('type') == 'files-digest' else digests.read_pg_detail
                summary, digest = read(file, what=f'資料摘要 {label}')
                if digest != item.get('digest'):
                    self._fail(app_id, kind, label, reason='摘要與記錄不符')
                if summary != item.get('summary'):
                    self._fail(app_id, kind, label, reason='摘要的統計與記錄不符')
            elif kind == 'globals':
                if size > GLOBALS_MAX:
                    self._fail(app_id, kind, label, reason='檔案過大')
                from .adapters.quadlet_postgres import globals_statements
                with open(file, 'rb') as handle:
                    globals_statements(handle.read(GLOBALS_MAX + 1))
            elif kind == 'dumps':
                if not head.startswith(DUMP_MAGIC):
                    self._fail(app_id, kind, label, reason='不是 pg_dump 自訂格式的匯出檔')
            elif kind == 'secrets':
                if not 0 < size <= SECRET_MAX:
                    self._fail(app_id, kind, label, reason='大小不在 Podman 接受的範圍（1 到 511,999 位元組）')
        except BackupError as error:
            if error.code == 'corrupt-archive' and error.details.get('check') == kind:
                raise
            if error.code in LOCAL_ERRORS:
                raise  # this device could not read its scratch copy: says nothing about the backup (review F10)
            self._fail(app_id, kind, label, error)
        except OSError as error:
            if error.errno is not None:
                # EIO, EMFILE, ENOSPC... while reading the local scratch copy: not a defect of the backup, so the job
                # fails without recording `verified` (review F10). tarfile's own "unexpected end of data" has no errno.
                raise BackupError('internal-error', f'讀取暫存檔時發生錯誤（{error.strerror or type(error).__name__}），'
                                                    '無法完成驗證；備份的驗證狀態沒有變更。', app=app_id) from None
            self._fail(app_id, kind, label, reason=type(error).__name__)
        except ValueError as error:
            self._fail(app_id, kind, label, reason=type(error).__name__)
        self.counts[app_id][kind] += 1

    def report(self):
        """[{id, name, checked{kind: count}, header_only[kinds]}] in manifest order (`header_only`: kinds checked only by
        their format header, review L8)."""
        return [{'id': app_id, 'name': self.names[app_id], 'checked': dict(counts),
                 'header_only': [kind for kind in HEADER_ONLY if counts.get(kind)]}
                for app_id, counts in self.counts.items()]

    def summary_text(self):
        total = dict.fromkeys(KINDS, 0)
        for counts in self.counts.values():
            for kind, count in counts.items():
                total[kind] += count
        parts = [f'{LABELS[kind]} {count}' for kind, count in total.items() if count]
        return '、'.join(parts) if parts else '沒有需要額外檢查的項目'
