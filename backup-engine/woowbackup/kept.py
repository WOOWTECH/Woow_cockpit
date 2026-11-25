"""Kept copies of a database service (S4: owner decisions D7 and H4, 2026-11-25; RESTORE lane, HAOS parity).

The restore of a converted Home Assistant backup rebuilds the app's PostgreSQL service: its data volume is removed and
created again, and the app's own database comes back from the dump. Everything else in that service -- other databases,
their roles -- would be gone for good (HAOS replaces the target's data the same way, but it has no other databases of a
neighbour in that folder). So, before anything is touched and only when the check found such data or could not tell:

* `keep` stops the database and exports its whole data volume (a cold copy that a rollback puts back as it was) and reads
  every database and the roles into dumps (what puts them back afterwards); both are packaged as ONE ordinary, verified
  backup of type `safety` (encrypted with the device key while the setting 預設加密備份 is on) whose note starts with
  NOTE_PREFIX. Nothing deletes it by itself: `flows.prune_safety` skips every backup `is_kept` names, retention only
  counts manual backups, and the converted backup's row in ha-imports.json says where it is (`from_ha.kept`). The
  administrator deletes it (`delete`) or downloads it (`export-start`) like any backup.
* a failed restore rolls back FROM that copy (`rollback_volumes`): the service is put back whole, every database and role.
* after a successful restore `put_back` puts the other databases and roles back into the new cluster (the app's own
  database and what the HA data brought are never touched); one that cannot go back is named and stays in the copy.

The page's list needs nothing new: the copy is a backup of type `safety` with `from_ha.kept` on its converted backup.

API for other lanes (LITELLM, L-38 "other schemas in the same database"): the pre-restore backup of an app already holds
the whole database, every schema of it. A converted backup whose app section has `keep_safety: true`
(`adapter.import_manifest(..., keep_safety=True)`) makes the restore write that pre-restore backup with NOTE_PREFIX, so it
is pinned like a kept copy (`flows._take_safety_copy`, `wants_pin`); the importer lists its own line to confirm.
"""
import contextlib
import traceback
import sys
from pathlib import Path

from .errors import BackupError

NOTE_PREFIX = '保留的複本：'
SPACE_FACTOR = 2.2
MAX_NAMES = 20


def note_for(app, *, source_note=None):
    """The note of a kept copy (`source_note`: the pre-restore backup's own note, pinned by L-38)."""
    if source_note is not None:
        return NOTE_PREFIX + source_note
    return f'{NOTE_PREFIX}{app.name}（匯入前整個資料庫服務，含其他資料庫）'


def is_kept(record):
    """True for a backup record (storage index entry) that is a kept copy or a pinned pre-restore backup."""
    return isinstance(record, dict) and record.get('type') == 'safety' and str(record.get('note') or '').startswith(NOTE_PREFIX)


def kept_ids(backups):
    """The ids of the kept copies among `backups` (storage.list_backups()): nothing prunes them."""
    return {record['id'] for record in backups if is_kept(record) and isinstance(record.get('id'), str)}


def wants_pin(plans):
    """True when an app of the restore asks for its pre-restore backup to be kept (`keep_safety`, see the module text)."""
    return any(isinstance(getattr(plan, 'manifest', None), dict) and plan.manifest.get('keep_safety') is True
               for plan in plans)


class Kept:
    """What the job knows about one app's kept copy: the backup's id, the plain files in staging (the cold copy a rollback
    uses and the dumps put-back uses; gone when the job ends) and what was read."""

    def __init__(self, backup_id, info):
        self.backup_id = backup_id
        self.volumes = dict(info['volumes'])      # {data volume: the cold copy's tar}
        self.logical = dict(info['logical'])      # {pg id: dump of the whole cluster}
        self.databases = list(info['databases'])  # names of the databases besides the app's own and postgres
        self.notes = list(info['notes'])

    def view(self):
        """What the job's result says about it (no path, no content)."""
        return {'backup_id': self.backup_id, 'databases': [name[:63] for name in self.databases[:MAX_NAMES]],
                'more': max(0, len(self.databases) - MAX_NAMES), 'put_back': [], 'not_put_back': [], 'notes': list(self.notes)}


def check_space(ctx, plans):
    """Before anything stops: the kept copies need the export of every database volume twice (the plain copy a rollback
    reads and the archive) and the device reserve. Refused with `insufficient-space` for this app only; nothing changed."""
    need = sum(int(getattr(plan.adapter, 'kept_estimate', 0) or 0) for plan in plans if getattr(plan.adapter, 'kept_wanted', None))
    if not need:
        return
    free = int(ctx.storage.free_bytes())
    required = int(need * SPACE_FACTOR) + int(ctx.paths.reserve_bytes)
    from .flows import human
    if free < required:
        raise BackupError('insufficient-space', f'這台的磁碟空間不夠保留資料庫服務的完整複本：需要約 {human(required, up=True)}，'
                                                f'目前可用 {human(free)}。沒有做任何變更，請先清出空間再匯入。',
                          required=required, free=free)
    ctx.log(f'保留資料庫服務的完整複本，預估需要 {human(required, up=True)}，目前可用 {human(free)}')


def keep(ctx, plans, handover, *, staging, key, source_backup_id, result):
    """Make the kept copies (see the module text). Called after the pre-restore copy, before the restore's first
    destructive step: a failure here is a refusal (the caller starts the stopped units again). Returns {app id: Kept}."""
    from . import flows
    kept = {}
    for plan in plans:
        adapter = plan.adapter
        if plan.mode != 'inplace' or not getattr(adapter, 'kept_wanted', None):
            continue
        ctx.log(f'保留「{plan.app.name}」資料庫服務的完整複本…')
        work = Path(staging) / 'kept' / plan.app.id
        section, entries, info = adapter.keep_cluster(work)
        stopped = handover.setdefault(plan.app.id, {'units': [], 'first_stop': None})
        stopped['units'] = list(dict.fromkeys([*stopped.get('units', []), *getattr(adapter, 'kept_stopped', [])]))
        if stopped.get('first_stop') is None:
            stopped['first_stop'] = adapter.timing.get('first_stop')
        packaged = flows._package(ctx, [plan.app], staging, include_images=False, note=note_for(plan.app), backup_type='safety',
                                  key=key, phases=False, manifest_apps=[section], entries=entries, downtime=0.0)
        copy = Kept(packaged['backup_id'], info)
        kept[plan.app.id] = copy
        result.setdefault('kept', {})[plan.app.id] = copy.view()
        ctx.log(f'完整複本已保留為 {copy.backup_id}（不會自動刪除；可在備份列表下載或刪除）')
        _register(ctx, source_backup_id, copy.backup_id)
    return kept


def _register(ctx, source_backup_id, kept_backup_id):
    """The converted backup's row says where its kept copy is (`from_ha.kept`); the copy is pinned by its note either way."""
    from . import haimport
    try:
        haimport.update_row(ctx.paths, source_backup_id, kept=kept_backup_id)
    except Exception:  # noqa: BLE001 - only a pointer for the page; details go to the journal, never the job
        traceback.print_exc(file=sys.stderr)


def rollback_volumes(kept, app_id):
    """{data volume: tar} a rollback of this app puts back whole ({} when no copy was kept)."""
    copy = (kept or {}).get(app_id)
    return dict(copy.volumes) if copy is not None else {}


def put_back(ctx, plans, kept, result):
    """After a successful restore: the other databases and roles go back into the new cluster (adapter.put_back_databases).
    Never fails the restore: what cannot go back is named in the result (`kept[app].not_put_back`, a warning) and stays in the
    copy."""
    from . import flows
    for plan in plans:
        copy = (kept or {}).get(plan.app.id)
        if copy is None or not copy.logical:
            if copy is not None and copy.databases:
                flows._add_warning(result, f'「{plan.app.name}」資料庫服務裡的其他資料庫沒有自動放回（無法逐一匯出）；'
                                           f'它們仍在保留的完整複本 {copy.backup_id} 裡。')
            continue
        view = result['kept'][plan.app.id]
        for pg in plan.app.postgres:
            dump = copy.logical.get(pg['id'])
            if dump is None:
                continue
            ctx.log(f'把「{plan.app.name}」資料庫服務裡原有的其他資料庫放回去…')
            try:
                done, failed = plan.adapter.put_back_databases(pg, dump)
            except BaseException as exc:  # noqa: BLE001 - a signal ends the job; anything else is only a warning here
                if not isinstance(exc, Exception):
                    raise
                done, failed = [], [(name, '放回時發生未預期的錯誤') for name in copy.databases]
                if isinstance(exc, BackupError):
                    failed = [(name, exc.message.rstrip('。')[:200]) for name in copy.databases]
                else:
                    traceback.print_exc(file=sys.stderr)
            view['put_back'] += [name[:63] for name in done]
            view['not_put_back'] += [{'name': name[:63], 'reason': reason} for name, reason in failed]
            if failed:
                flows._add_warning(result, f'「{plan.app.name}」的其他資料庫沒有全部放回：{"、".join(name for name, _ in failed[:6])}；'
                                           f'它們仍在保留的完整複本 {copy.backup_id} 裡。')
            if done:
                ctx.log(f'已放回資料庫：{"、".join(done)}')
