# Backup & Restore — Engineering Contract (v1)

Status: binding interface for the implementation teams on branch `feat/backup-restore`.
Revised 2026-11-13 after the security/correctness review and lab hardening (H1–H8): nested-tar checks (§5),
second-resolution file names (§5), restore result fields and inspect/restore-start key rules (§7), job unit limits,
signal handling and recovery duties (§8), the backup/restore algorithm details (§9), config-path allowlist (§4).
Revised again after the delta review (HD-01–HD-10): image names and volume members podman really writes (§5),
restore `warnings` (§7), the fresh-deployment marker and its recovery, upload-finish completion (§8), backup-time
volume checks, snapshot confirmation, database enumeration and bounded health requests (§9), upload frames (§11).
Revised 2026-11-13 (branch `feat/backup-host-dirs`) for **host directories** (`data_dirs`, 主機資料夾): catalog
schema (§4), manifest, entries and nested-tar rules (§5), the owner-side directory helper (§6), summary, preflight
and result fields (§7), the `dir_apps` marker and its recovery (§8), the backup/restore/rollback algorithms (§9),
security rules (§10); the emergency kit is an age identity file (§5). After the host-directory review (M1–M5,
L1–L7): helper answers are untrusted and checked, mount points and other containers that use a directory are refused,
the rollback moves the previous content back instead of extracting a third copy, old copies are renamed to `-del-`
before they are deleted, and the forbidden trees grew (§4–§10).
Revised 2026-11-13 (branch `feat/backup-strengthen`, engine core) after the production run of 20 apps: built-in data
verification (`postgres-digest`, `files-digest`; §4, §5, §7, §9), fewer and shorter stops (one `systemctl stop`, start
groups from the units' `After=`, the safety backup hands its stopped writers to the restore, host directories written
before anything stops; §8, §9), unavailability measured for backups and restores (§7), and PostgreSQL **instance
mode** (`scope: "instance"`: roles with password hashes and every database; §4, §5, §9, §10). Manifest additions that
the archive format must accept are marked **[format]** (§5).
Revised 2026-11-13 (branch `feat/backup-strengthen`, format) for the Home Assistant-like **format 2** and the
**encryption choice** (user decisions 2026-11-13: like Home Assistant backups; encrypted by default; the administrator
can choose whether to encrypt): new backups are a plain POSIX `.tar` (`backup.json`, `README.txt`, one archive per app,
age-encrypted or not; §5), the setting 預設加密備份 and the per-backup choice 加密此備份 (§3, §7), unencrypted
download copies with a TTL and an audit trail (§7, §8), uploads of format 1, encrypted and unencrypted format 2 with
an extra acknowledgement for unauthenticated ones (§7), per-app partial restores (§9) and the **deep verify** job that
checks every nested tar the way a restore does (§5, §7). Format 1 stays readable forever.
Revised 2026-11-14 (branch `feat/backup-strengthen`, UI): the page implements every feature of this phase (§11): the
encryption choice and badges, the download menu with 下載未加密版本, the per-item data check table and downtime figures,
PostgreSQL mode labels, the deep verify result, storage per app and 清理備份 (`retention-plan`/`retention-apply`), and
應用設定 (`catalog-suggest`/`catalog-install`/`catalog-remove`).
Revised 2026-11-14 (branch `feat/backup-strengthen`, integration): the catalog-draft, catalog-administration and
retention contract written by the catalog + retention engineer is merged here (§2, §3, §4 "Catalog drafts" and
"Installing and removing entries", §7 commands and shapes, §8 retention, §10 rules 15–16) and wired into the helper;
`status.storage.apps` and the backup job's `retention_deleted` are filled by the engine; the lab record of the
integrated build is §13.
Revised 2026-11-14 (branch `feat/backup-strengthen`, review fixes) after the security and correctness review of the
integrated build (H1, H2, M1–M4, L1–L8, F1–F8, F10, F11, F14, F16, F17): the SQL digest hashes `record_out(t.*)`
(no table owner's cast runs as the digest's superuser, a column named `t` no longer hides the row; §4, §10), every
digest is read twice around the copy it vouches for and kept only when both reads agree, a restore reads a differing
digest again and reports data that is still moving as not compared, and a running container that the backup does not
stop may not mount an app volume read-write (§4, §9); instance mode requires the bootstrap
superuser, keeps template databases, refuses databases that accept no connections, recognizes a new cluster by its
initdb time and recreates every database of the backup (§4, §5, §9); the roles script is checked without regard to
case and the restore's role is re-checked after it (§9, §10); retention ignores backups that failed verification when it
counts and protects everything while a job record cannot be read (§8); exports and plaintext downloads are audited on
every path (§8, §10); an installed entry cannot change its owner (§4); config files may not lie in shell or git
configuration trees (§4).
Revised 2026-11-17 (branch `feat/backup-schedule`, 2026.11.17.1) for **排程備份 (scheduled backups)**, like Home
Assistant's automatic backups (owner decisions: off by default; daily at 03:00 when turned on; all apps; no images;
encrypted like manual backups; keep the newest 7 scheduled backups; manual, pre-restore and uploaded backups are never
deleted by the schedule; the emergency kit must be saved before turning it on; a missed slot is caught up once; apps that
are not ready are skipped and the run is 部分完成): the settings and state files and the units (§3), the commands and
shapes (§7), the timer, the tick decision, the registry and the two retention pools (§8), security rule 17 (§10), the
page (§11) and the lab scenarios (§13). The archive and index formats are unchanged: a scheduled backup is a `manual`
backup with the note 排程備份 that the schedule's registry lists, readable by 2026.11.15.2.
Revised 2026-11-19 (branch `feat/ha-import-arm`): HA backups made on **ARM (aarch64)** are imported like x86 ones, after tests with
a real Raspberry Pi 5; an Odoo custom module that would be copied and holds an ELF file for another processor is a blocker (§7, §9).
Revised 2026-11-23 (branch `feat/ha-import-litellm-product-20261123`, owner decision 「決定1 做」): the WOOWTECH LiteLLM add-on
(`woow-litellm` → `litellm`) is imported as a product (§9 "LiteLLM"): HA's PostgreSQL 18 rows move into this device's
PostgreSQL 17 schema (never HA's DDL), HA's salt key replaces this device's secret `litellm-salt-key` through the new
`adapter.import_manifest(secrets={name: file})` item (only a declared secret), and the check and the notes name this
device's apps that use LiteLLM keys (`HaCheck.litellm.key_users`); every other shape is unchanged except the app id
enumerations gaining `litellm`.
Revised 2026-11-19 (branch `feat/ha-import-batch1`, engine): the HA import is **registry-driven** (`haapps.IMPORTERS`: add-on slug
suffix → catalog app id, default name, module, convert params, MCP admin app) and imports four more WOOWTECH add-ons: Omnigent
(`woow-omnigent` → `omnigent`), Hermes (`woow-hermes` → `hermes`), EMQX (`woow-emqx` → `emqx`) and Headscale (`woow-headscale` →
`headscale`) (§5 "Apps", §7 shapes, §9 "Home Assistant import"); the HA reader hands out clean absolute symlinks below the areas a
caller allows (`Select.absolute_symlinks`) and new HA-side secrets are never read (§5, §6); throwaway containers take validated
`--add-host` lines (§6, §8); SQLite files of the new add-ons are read, and Headscale's API keys replaced, only by a sandboxed child
(`hasqlite`, §9, §10 rule 18). Odoo and n8n behave exactly as before; every existing shape is unchanged except that the app id
enumerations (`apps`, `importable_apps[].app_id`, `HaCheck.apps[].app_id`, `HaImport.apps`) gain the four ids, and `HaCheck` /
`reminders_by_app` gain the new apps' sections and lines.
Revised 2026-11-23 (branch `feat/ha-import-opendesign-20261123`, engine and page; owner decision 「決定2 A」): the HA
import takes the WOOWTECH **OpenDesign** add-on (`woow_ha_opendesign` → `open-design`, §9 "Batch 2: OpenDesign"): the
registry gains its importer (MCP admin `opendesign-mcp-admin`; the MCP server is built into the add-on), the SQLite
child two fixed reads (`opendesign.project_folders`, `opendesign.routines_active`), the app id enumerations
`open-design`, `HaCheck` the `open-design` section and the page its facts. Every other shape is unchanged.
Revised 2026-11-23 (branch `feat/ha-import-code-server-20261123`, engine and page; owner decision 「決定2 A」): the HA import
takes the WOOWTECH **code-server** add-on (`woow_ha_code_server` → `woow-code-server`, §9 "Batch 2: code-server"): the
registry gains its importer (no MCP admin app, no HA MCP add-on), `habackup.NEVER_READ` the agents' login files of that
add-on, the app id enumerations `woow-code-server`, `HaCheck` the `woow-code-server` section and the page its facts. The
page also names the add-ons an HA backup may hold that are **never moved** — the Cloudflare Tunnel and the WOOWTECH MCP
admin add-ons — with what to do on this device (§9 "Batch 2: add-ons that are not moved"). Every other shape is
unchanged.
Revised 2026-11-23 (branch `feat/ha-import-nextcloud-20261123`, engine + page; owner decision 2026-11-23 「決定2 A」): imports
the WOOWTECH **Nextcloud Office** add-on (`woow-nextcloud-office` → `nextcloud`, `ha_nextcloud.py`; §9 "Batch 2: Nextcloud"):
HA's PostgreSQL 16 database (restored as the live Nextcloud role), config.php's identity, the custom apps and the users'
files, which live in HA's **share folder** (a backup without it, or without the data directory, is refused); the target keeps
its URLs, database credentials, mail, caches, secrets and Office (Collabora) settings. The app id enumerations gain
`nextcloud`; `HaCheck` gains the `nextcloud` section (§7); no other shape changes.
Revised 2026-11-18 (branch `feat/ha-import`, part A: engine) for **importing Home Assistant backups** (owner decisions
2026-11-18: Cockpit reads a Home Assistant OS backup file itself; only the WOOWTECH Odoo and n8n add-ons; x86 only; the
HA key is pasted for each import and never stored): an uploaded HA backup is recognised by `upload-finish` and kept in
its own store `ha-backups/` (§2, §3), read only by strict HA readers -- securetar v1/v2/v3 decryption, the outer tar,
member streams, inner tars and addon.json -- that never hand out the add-on's options or HA passwords (§5 "Home
Assistant backups", §6); `upload-finish` answers `{ha_backup}` for it, `list` adds `ha_backups[HaBackupMeta]` and
`ha-delete` removes one (§7); job logs mask HA keys (§8); security rule 18 (§10). The Cockpit formats, the index and
every existing shape are unchanged, and an older engine simply does not list HA uploads. Part B (same branch, same
day) adds the **check and convert jobs**: `ha-check-start` (job type `verify`, `params.source` `ha`) and
`ha-convert-start` (job type `backup`, `params.source` `ha`), their results and `BackupMeta.from_ha` (§7), the HA key kind
of a job, the phase labels of the HA jobs, throwaway containers of a job with their clean-up and recovery (§8,
`tempctr.py`), the side registry `ha-imports.json` (§3, §8) and the conversion itself (§9 "Home Assistant import"): the
converted backup is an ordinary format 2 `manual` backup that every reader since 2026.11.15.2 restores, so the import
itself is the existing restore.
Product docs for customers are written separately in Traditional Chinese (`docs/backup.md`).
All UI text is **Traditional Chinese (zh-TW)**. Code comments in English.

If a detail below proves infeasible, implement the closest *safe* alternative inside your own
files and report it as a deviation in your final output. Do not silently change shared shapes.

## 1. Scope of this phase

Customers manage **Podman application packages** (rootless Quadlet apps owned by a Linux user)
from a Cockpit page "備份與還原", modelled on Home Assistant backups:

1. Create a backup of selected apps → stored **locally by default** → listed. Encrypted unless the administrator
   chose otherwise (setting 預設加密備份, per backup 加密此備份).
2. **Download** any backup as **one self-contained file** (`.tar`, format 2, §5; backups made before 2026-11-13:
   `.woowbackup`, format 1), exactly as stored; an encrypted one can also be downloaded as an unencrypted copy
   (explicit confirmation, deleted after a short TTL).
3. **Upload** a `.tar` (encrypted or not) or `.woowbackup` on the same or **another compatible device**, enter the
   emergency key if this device does not hold it (encrypted only), run preflight, confirm, restore.
4. In-place restore always keeps a **pre-restore copy** first (on disk before anything changes), **rolls back
   automatically** from it if the restore fails, and packages it into a verified **pre-restore safety backup** once the
   apps run again (2026.11.14.2: one outage, the packaging outside it; §9).
5. Jobs run in the background (systemd), survive browser close, show phases/progress/log.
6. Encryption key management with an HA-style **emergency kit** (download once, confirm saved).
7. Built-in data checks compared before the app starts, downtime figures per app, PostgreSQL instance mode and a deep
   verify (2026-11-13, §4, §5, §7, §9).
8. **應用設定**: catalog drafts from an owner's Quadlet files, reviewed, edited and installed or removed from the page;
   **清理備份**: storage per app and a keep-last-N policy for manual backups
   (§4 "Catalog drafts", "Installing and removing entries", §7, §8, §11).
9. **排程備份** (2026.11.17.1): backups of the chosen apps on chosen weekdays at a chosen time of the device, started by
   a static systemd timer that ticks every 5 minutes; the newest N scheduled backups per app are kept (§3, §7, §8, §11).

Non-goals this phase: retention beyond keep-last-N (manual policy, schedule rule), NAS/cloud targets, rootful
(system) Quadlet apps, multi-node apps, OS/bare-metal restore, shipping catalog entries with application packages (an
entry is generated or written per device and reviewed). Owner `root` is rejected.

## 2. Repository layout and ownership

| Path | Owner team | Notes |
| --- | --- | --- |
| `backup-engine/woowbackup/{archive,keys,storage,util}.py` | E1 engine-core | format, crypto, local storage |
| `backup-engine/woowbackup/{hasecuretar,habackup,hastore}.py` | E1 engine-core (format) | Home Assistant backups (read only): securetar decryption, outer/inner tars, the `ha-backups/` store (branch feat/ha-import) |
| `backup-engine/woowbackup/{haimport,haapps,hacommon,hasqlite,ha_odoo,ha_n8n,ha_omnigent,ha_hermes,ha_emqx,ha_headscale,tempctr}.py` | E2 engine-ops | Home Assistant import: jobs, the registry of importers, shared helpers, the sandboxed SQLite child, one module per app, throwaway containers (branches feat/ha-import, feat/ha-import-batch1) |
| `backup-engine/woowbackup/{settings,deepcheck}.py` | E1 engine-core (format) | 預設加密備份 setting; deep verify checks |
| `backup-engine/woowbackup/{errors,paths,__init__}.py` | coordinator (frozen) | shared; change only via coordinator |
| `backup-engine/woowbackup/{catalog,podman,flows,jobs,cli,digests}.py`, `adapters/*` | E2 engine-ops | apps, podman, orchestration, CLI, data digests |
| `backup-engine/woowbackup/{suggest,catalog_admin,retention}.py` | catalog + retention | catalog drafts, catalog install/remove, retention |
| `backup-engine/woowtech-cockpit-backup` | E2 | root entrypoint |
| `backup/` (Cockpit package `woowtechbackup`) | U ui | `manifest.json index.html backup.css backup.js` |
| `catalog-examples/woowbk-demo/**` | L lab | demo app fixture + trusted catalog entry |
| `tests/e2e/**` | L lab (E2E runners later: integrator) | lab device tooling, E2E scripts |
| `tests/backup/test_{archive,keys,storage,archive_security}*.py`, `tests/backup/test_format_choice.py` | E1 | (`test_archive_v2.py`: format 2) |
| `tests/backup/test_ha_*.py`, `tests/backup/hafixtures.py`, `tests/backup/fixtures/ha/**` | E1 | Home Assistant backups; the fixtures are written by the real securetar library (`fixtures/ha/README.md`) |
| `tests/backup/test_{catalog,podman,flows,jobs,cli,adapter}*.py` | E2 | |
| `tests/backup/test_{suggest,catalog_admin,retention}.py`, `tests/backup/fixtures/reference-host/**` | catalog + retention | the fixture mirrors the reference host's Quadlet shapes (names only, no secret values) |
| `tests/backup-ui.mjs` | U | fixture browser tests (pattern of `tests/services-ui.mjs`) |
| `scripts/manage.py`, `scripts/check_source.py`, `scripts/bootstrap-ubuntu.sh`, `tests/test_manage.py`, `package.json`, `.github/workflows/validate.yml` | I installer | |

Rules for every agent: edit only files you own. **Never run** `git commit/checkout/stash/reset/clean`
(the coordinator commits). Never touch production containers, volumes, images, Quadlets or
services on this host. Container work uses only `~/.woowbk-lab/bin/labpodman` (separate storage
root). No `sudo`. Do not write user-supplied credentials anywhere.

## 3. Runtime layout on a device

| Path | Mode | Content |
| --- | --- | --- |
| `/usr/local/share/cockpit/woowtechbackup/` | root 0755/0644 | UI package |
| `/usr/local/lib/woowtech-cockpit-backup/woowbackup/` | root 0755/0644 | engine library |
| `/usr/local/lib/woowtech-cockpit-backup/VERSION` | root 0644 | repo VERSION at install |
| `/usr/local/libexec/woowtech-cockpit-backup` | root 0755 | entrypoint `#!/usr/bin/python3 -I` |
| `/etc/woowtech-cockpit/backup/apps/<id>.json` | root 0644, dir 0755 | **trusted catalog** (created by `catalog-install` when missing) |
| `/etc/woowtech-cockpit/backup/apps-history/` | root 0755 | previous catalog entries `<id>.<YYYYMMDDTHHMMSSZ>.<sha256[:8]>[-<n>].json` (root 0644), the newest 10 per app id, written by `catalog-install` (the replaced entry) and `catalog-remove` (the removed entry); the loader never reads it |
| `/etc/woowtech-cockpit/backup/retention.json` | root 0644 | keep-last-N policy of manual backups (§8); missing = keep everything |
| `/etc/woowtech-cockpit/backup/schedule.json` | root 0644 | 排程備份 settings (§7 `Schedule`, §8): `{"schema": 1, "enabled", "days", "time", "apps", "include_images", "keep_last", "updated", "armed_at"}`, ≤ 16 KiB, exactly these keys; written only by `schedule-set`; missing = off (every day 03:00, all apps, no images, keep 7); not root-owned, group/world-writable, a symlink, too large or invalid → the schedule is off with a `problem`, nothing is deleted |
| `/usr/local/lib/systemd/system/woowtech-cockpit-backup-schedule.timer`, `….service` | root 0644 | the static timer (`OnCalendar=*:0/5`) and its oneshot tick service (§8), installed by `scripts/manage.py` with the engine; the helper never writes unit files |
| `/usr/local/share/woowtech-cockpit-backup/catalog/<id>/` | root 0755/0644 | trusted templates (quadlet files, app assets) |
| `/etc/woowtech-cockpit/backup/keys/` | root 0700 | `device-<KEYID>.key`, `imported-<KEYID>.key` (0600), `keys.json` |
| `/etc/woowtech-cockpit/backup/settings.json` | root 0644 | `{"schema": 1, "encrypt_by_default": bool, "updated": "…Z"}` (預設加密備份); missing, not root-owned, group/world-writable, a symlink or invalid → ignored: **encrypted** (with a `problem` in `status.settings`) |
| `/var/lib/woowtech-backup/` | root 0700 | `archives/<id>.tar` (format 2, every new backup) or `archives/<id>.woowbackup` (format 1) + `archives/<id>.json` (index), `uploads/<upload_id>.{part,json,done}` (`.done` names the backup of a finished upload for 24 h), `staging/<job>/`, `pending/<job>/` (an in-place restore's pre-restore copy: `pending.json` + `data/apps/<id>/…`, plaintext like staging, kept until it is packaged into the safety backup and removed only by that packaging or before the restore changed anything; §8, §9), `exports/<export_id>.tar` + `.json` (unencrypted download copies, 0600, deleted after `EXPORT_TTL` = 15 min; §8), `jobs/<job>.json` + `.log` + `.lock` (record lock, empty, 0600) + `.cancel` (pending cancel request), `requests.json`, `schedule-state.json` (0600, ≤ 4 MiB: the schedule's registry `{backup id: {job, slot, trigger}}`, last handled slot, the handled slot a clock reset put aside (`handled_before_reset`), the floor kept while the clock is below `armed_at` (`armed_floor{armed_at, floor}`), waiting slot, last run, events ≤ 50; §8) |
| `/var/lib/woowtech-backup/ha-backups/` | root 0700 | uploaded Home Assistant backups (branch feat/ha-import, §5 "Home Assistant backups"): `<id>.tar` (the file exactly as uploaded, 0600) + `<id>.json` (sidecar, 0600, exactly the stored HaBackupMeta keys of §7, strictly validated; unknown keys make it unreadable and it is then never replaced), id `ha-` + sha256[:20] of the file (the same file uploaded twice is one record); written only by `upload-finish` (sidecar first, then the rename, under `index.lock`) and removed only by `ha-delete`; retention, orphan adoption, the schedule and `delete` never look here |
| `/var/lib/woowtech-backup/ha-imports.json` | root 0600 | which backups were converted from an HA backup (branch feat/ha-import part B, §8 "Home Assistant import jobs"): `{"schema": 1, "imports": {<backup id>: {ha_backup_id, name, date, apps, odoo_database, test_mode, workflows_to_fix, reminders, reminders_by_app, notes, addons, job_id, created}}}` (rows written before `reminders_by_app` and `notes` existed read as empty ones), strict when read (an unreadable file is never replaced and `from_ha` is then omitted), every text cleaned and cut when a row is written (whatever a conversion found is accepted), written under `index.lock`; a row is dropped when its backup is deleted, when its job failed before the backup was in the index, and a day after its backup no longer exists; `ha-delete` never touches it |
| `/run/woowtech-backup/` | root 0700 (tmpfs) | `engine.lock`, `jobs.lock` (start lock), `index.lock` (index sidecar and HA store writes), transient key files `key-<random>` (0600, deleted in `finally`), `schedule-tick` (empty, 0600; its mtime is the last tick), `schedule-tick.lock` (one tick at a time), `schedule.lock` (state file writes), `schedule-state.reported` (an unreadable state file was journaled this boot) |

`woowbackup.paths.Paths` holds these. Tests construct `Paths(base=tmpdir)`; real paths are used
when `base` is None. The entrypoint never honours environment overrides when running as root.

## 4. Trusted catalog entry (schema 1)

```json
{
  "schema": 1,
  "id": "woowbk-demo",
  "name": "示範筆記應用",
  "description": "PostgreSQL、檔案與密鑰的備份還原示範應用",
  "owner": "appowner",
  "adapter": "quadlet-postgres",
  "quadlet": {
    "files": ["woowbk-demo.network", "woowbk-demo-db.container", "woowbk-demo-app.container"],
    "template_dir": "/usr/local/share/woowtech-cockpit-backup/catalog/woowbk-demo/quadlet"
  },
  "units": ["woowbk-demo-db.service", "woowbk-demo-app.service"],
  "writer_units": ["woowbk-demo-app.service"],
  "postgres": [{"id": "main", "container": "woowbk-demo-db", "unit": "woowbk-demo-db.service",
                "database": "notes", "user": "notes", "data_volume": "woowbk-demo-pgdata"}],
  "volumes": [{"name": "woowbk-demo-files", "label": "上傳檔案"}],
  "secrets": [{"name": "woowbk-demo-db-password"}, {"name": "woowbk-demo-app-key"}],
  "config_files": [{"path": ".config/woowbk-demo/app.env", "mode": "0600"}],
  "health": [{"type": "http", "url": "http://127.0.0.1:18090/healthz", "expect_status": 200, "timeout_seconds": 90}],
  "verify": [{"id": "summary", "type": "http-json", "url": "http://127.0.0.1:18090/api/summary",
              "compare": ["notes", "files", "digest", "title", "signatures_valid"]}]
}
```

Validation (strict; unknown keys rejected): `id` `^[a-z0-9][a-z0-9-]{1,40}$`; `owner` a
non-root existing user matching `^[a-z_][a-z0-9_-]{0,31}$`; units `^[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}\.service$`;
container/volume names `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`; secret names `^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}$`;
quadlet file names `^[A-Za-z0-9][A-Za-z0-9_.@-]*\.(container|network|volume|pod)$`; config paths are
relative, no `..`, no empty/`.` segments, and lie in the app's own directory `.config/<id>/` or
`.local/share/<id>/` (an allowlist; `.config/{systemd,containers,environment.d,autostart,dbus-1,user-tmpfiles.d}/`
and `.local/share/{systemd,containers,dbus-1,applications}/` stay forbidden even for a colliding id, and so does every
tree a host directory may not touch, e.g. `.config/fish/` and `.config/git/`, compared without regard to case: an id
`fish` or `git` must not let archive bytes write the owner's shell or git start-up files; review L3); modes are
octal strings ≤ `0644`; `template_dir` must be inside the templates root above; URLs must be
`http://127.0.0.1:<port>/…` or `http://localhost:<port>/…` (loopback only). Catalog files and
directories must be root-owned, not group/world-writable, and not symlinks. `units` is the start
order (stop = reverse); `writer_units` ⊆ `units` are stopped during a backup while databases stay up.

**Host directories** (optional `data_dirs`, schema stays 1): directories in the owner's home that Quadlet files
bind-mount (`Volume=%h/<dir>:<path>`), backed up and restored **as a whole**:

```json
"data_dirs": [{"path": ".local/share/nextcloud-office/html", "label": "網站程式"},
              {"path": "homeassistant/config-preinstalled"}]
```

At most 16 items `{"path", "label"?}` (unknown keys rejected; `label` 0–80 characters, no control characters).
`path` is relative to the owner's home and normalized: no leading or trailing `/`, segments
`^[A-Za-z0-9._@+-]{1,255}$` and not `.`/`..` (so never the home itself), no segment containing `.woowbk-` (any case:
the restore's own sibling names), last segment ≤ 200 characters (room for the sibling names). Compared without
regard to case, it may neither equal, lie inside nor contain `.ssh`, `.gnupg`, `.config/systemd`,
`.config/containers`, `.local/share/containers`, `.config/environment.d`, `.config/autostart`, `.config/dbus-1`,
`.config/user-tmpfiles.d`, `.local/share/systemd`, `.local/share/dbus-1`, `.local/share/applications`,
`.local/share/user-tmpfiles.d`, `.local/bin`, `.local/lib`, `bin`, `.bashrc.d`, `.config/fish` or `.config/git` (login keys, unit
definitions, the user manager's environment, user tmpfiles that write any file at the next login, programs, Python
user site-packages and shell start-up files his logins run, and the Podman storage never come from archive bytes);
the restore preflight also refuses an overlap with the owner's actual Podman `GraphRoot` and `VolumePath` (a
`storage.conf` may move them). Items must not overlap each other (equal, or one inside the other) or any
`config_files` path; two loaded apps of the same owner must not declare overlapping directories, nor a directory
that holds the other's config file (the later entry, in file name order, is reported in `status.warnings` and not
loaded). A directory must be on its parent's mount and hold no mount point (another filesystem or a bind mount):
the backup and the restore preflight refuse it. Every unit whose container can write into a directory belongs in
`writer_units`: a backup fails, before any writer stops, while a running container that is not a writer it stops
bind-mounts a directory (or a directory above it) read-write, whatever started it (Quadlet `Volume=`/`Mount=`, a pod,
`PodmanArgs`, by hand). The same holds for `volumes` (2026-11-14, review H2/F3): a running container that the backup
does not stop and that mounts one of the app's volumes read-write fails the backup before any writer stops (add its
unit to `writer_units`, or mount the volume `:ro` when it only reads). **Cold databases:** a PostgreSQL whose
data lives in a volume or host directory may be declared without a `postgres` entry: list the data volume in
`volumes` or the data directory in `data_dirs` and put the database unit in `writer_units`; everything stops during
the backup and roles, passwords, owners and grants are kept at file level (the major version must then be the same
on restore).

**PostgreSQL modes.** A `postgres[]` item takes an optional `"scope"`: `"database"` (default, single-database mode, as
above) or `"instance"`; with `"instance"` the item has no `database` key (the engine connects to `postgres`, or `template1`
where that database was dropped) and `user` must be the instance's **bootstrap superuser** (the role initdb created,
oid 10: the image's `POSTGRES_USER`) -- a restore runs in a cluster the image has just created, where no other role
exists yet; any other user fails the backup and the preflight (review F5). Which mode to use:

| Mode | Catalog | Database during backup | Kept | Restore needs |
| --- | --- | --- | --- | --- |
| single-database | `postgres[]` item, scope `database` | keeps running (writers stop) | one database, its data; restored with `--no-owner --no-privileges` | target major ≥ source; refuses instances holding other databases (in place) |
| instance | `postgres[]` item, `"scope": "instance"` | keeps running (writers stop) | every database besides template0/template1 (template databases too; one that accepts no connections fails the backup), every role with its password hash, memberships, per-role and per-database settings, owners, grants, encoding/locale, comments | target major ≥ source; the image must have every extension the databases use (checked before any data is restored) |
| cold | no `postgres[]` item; data volume in `volumes` or data directory in `data_dirs`; database unit in `writer_units` | stops with the writers | the data files as they are (everything) | the **same** PostgreSQL major |

Use single-database mode for an app that owns exactly one database and needs no extra roles; instance mode when the app
creates roles or databases itself (Nextcloud's `oc_<admin>`, Odoo's `odoo` role and its company databases) or when other
majors must be restorable; cold mode when the database cannot be dumped (no superuser, unsupported major, a non-PostgreSQL
store) and the downtime of a stopped database is acceptable.

**Data verification** (`verify[]`, at most 16 items, ids unique, `[a-z0-9][a-z0-9_-]{0,31}`). Three types:

```json
{"id": "summary", "type": "http-json", "url": "http://127.0.0.1:18090/api/summary", "compare": ["notes"]}
{"id": "db", "type": "postgres-digest", "postgres": "main", "databases": "all", "exclude_tables": ["public.cron_*"], "label": "資料表"}
{"id": "db", "type": "postgres-digest", "container": "x-db", "unit": "x-db.service", "user": "x", "databases": ["x"]}
{"id": "files", "type": "files-digest", "volume": "woowbk-demo-files", "exclude": ["*.log", "cache"], "label": "上傳檔案"}
{"id": "config", "type": "files-digest", "data_dir": "homeassistant/config", "exclude": [".storage/core.restore_state"]}
```

* `http-json` (unchanged): the app's own JSON summary, read before the writers stop and confirmed after they restart.
* `postgres-digest`: per table and sequence a row count and an order-independent content digest, computed by the engine
  with psql (no application API). Exactly one of `postgres` (a `postgres[]` id; `databases` defaults to that item's
  database in single-database mode, where no other value is accepted, and to `"all"` in instance mode) or `container` (a
  **cold** database: `unit` must be in `writer_units` and is not a `postgres[]` container, `user` required, `databases`
  defaults to `"all"`). `databases`: `"all"` (every database that accepts connections, templates excluded) or 1–64 names
  `^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,62}$`. `exclude_tables`: up to 64 fnmatch globs on `schema.table` (e.g. tables a
  database job writes as soon as it runs). Roles and memberships are compared too where a restore brings them back
  (instance mode; a cold database read by a superuser). A row's text is `pg_catalog.record_out(t.*)` -- the row
  type's own output function: `t::text` ran a cast a table owner can define, as the digest's superuser, and named a
  column called `t` instead of the row (review H1, F2; both forms give the same text for every other table, so digests
  of earlier backups stay comparable).
* `files-digest`: every entry of a declared volume (`volume`, a `volumes[]` name — not a database data volume) or host
  directory (`data_dir`, a `data_dirs[]` path) as type, mode, numeric owner, size, link target and sha256. `exclude`: up
  to 64 fnmatch globs; a glob without `/` matches any name (file or directory, a directory with everything below it), a
  glob with `/` the path from the top. Sockets are not listed (tar never keeps them); a volume's top directory is not
  listed (`podman volume import` creates it anew, 0755 owner 0 — lab 2026-11-13); setuid/setgid of a volume's files are
  not compared (a volume restore drops them, §5). A listing is at most 1 GiB whatever the free space (about 2,000,000
  entries; review M4).
* Every digest is read **twice** during a backup, around the copy it vouches for (§9): a check whose two reads differ --
  something the catalog does not stop wrote meanwhile -- is left out of that backup (logged with the reason) instead of
  being kept and failing every restore of it (review H2, F3).
* `label` (0–80 characters) only for the digest types. One digest check per target (`postgres:<id>`, `container:<name>`,
  `volume:<name>`, `dir:<path>`).

**Authority rule:** during restore, *what* gets written (secret names, config paths, volume names, host directory
paths, databases, units, templates) always comes from the **local** catalog. The archive only supplies
bytes for items the local catalog declares. Items present in the archive but not in the local
catalog are ignored and reported; items declared locally but missing in the archive make the app
incompatible (an archive without `data_dirs` is incompatible with a catalog entry that declares some).

### Catalog drafts (`catalog-suggest`)

Read-only. Everything about the owner's home is done **as the owner**: `OwnerRunner.run([python3, -I, -c, SCAN_HELPER,
.config/containers/systemd])` lists the Quadlet directory (every component from `$HOME` opened with `O_NOFOLLOW`, not
recursive, at most 512 entries, only `*.container|network|volume|pod|kube|image|build` files read, each ≤ 1 MiB and ≤ 8 MiB
in all, as UTF-8 text), `OwnerRunner.stat_files` (FILE_HELPER `stat`) checks bind-mount sources and environment files,
and `podman secret ls`, `podman volume ls` and `systemctl --user show --property=Id,LoadState,ActiveState` run as the owner.
The helper's answer is untrusted: shape, types, names, sizes and totals are checked (`job-failed` otherwise). Environment
files are never read; `Environment=` values are never returned (only `POSTGRES_USER`/`POSTGRES_DB`, when they are
PostgreSQL identifiers); `HealthCmd=` text is never returned (only the loopback URL derived from it, checked with the
catalog's URL rule). Owner-controlled text in messages is filtered to printable characters and truncated.

**Grouping.** `.container` files are linked by: systemd dependencies on each other's services (`Requires`, `BindsTo`,
`PartOf`, `Requisite`, `Wants`, `After`, `Upholds`, `Before`), a shared network namespace (`Network=container:<name>` or
`Network=<x>.container`), a shared pod, a shared named volume or overlapping bind-mounted directory, the label `app=<v>`, and
a Quadlet network whose name (file stem or `NetworkName=`) is a `-`-prefix of the container's file stem (`n8n.network`
links `n8n-worker`; a shared `proxy.network` does not merge every app on it). `io.woowtech.app=<id>` is authoritative:
containers with different values are never merged (a link between them is reported, `cross-app-link`). `.network`,
`.volume` and `.pod` files go to the app whose containers use them (a file used by two apps goes to the one whose id
prefixes its name, the other gets `shared-file`); an unused one joins the app whose id is the longest `-`-prefix of its
name (`aux-by-name`), else it is listed in `unassigned`. `.kube`, `.image`, `.build` and template units (`@`) are listed in
`unsupported`; symlinks, sub-directories and drop-in folders (`*.d`) are reported and not analysed.

**App id.** The `io.woowtech.app` label, else the longest common `-`-prefix of the container file stems, else the stem of
the one linked network file, else a single `app` label value, else the first container stem; normalized to
`^[a-z0-9][a-z0-9-]{1,40}$`, unique. When the app's files belong to exactly one installed entry of this owner, that entry's
id is used (`installed-id`); an id another owner's entry uses is reported (`id-taken`, level `error`) and makes every
variant invalid (`field: "id"`): installing it would move that entry and its backups to this owner (review M3).

**Entry fields.**
* `units`: the containers' services in start order: `After=`/`Before=` and network namespaces order them; other
  dependencies count as "start that one first" unless that makes a cycle; ties: databases, then caches (Redis/Valkey/
  KeyDB/Dragonfly), then the rest, by file name. A real `After=` cycle is reported (`dependency-cycle`).
* `writer_units`: a container that mounts a backed-up volume, host directory or config file read-write; every client of
  a database (it depends on the database's unit); every database in cold mode; and, as a closure, every container that
  systemd stops together with a writer (`Requires`/`BindsTo`/`PartOf`/`Requisite` on it) or that lives in a writer's
  network namespace (the engine only restarts the writers it stopped). In export modes the PostgreSQL unit is never a
  writer.
* Databases: PostgreSQL by image name (`postgres`, `postgresql`, `postgis`, `pgvector`, `timescaledb`, …) or `POSTGRES_*`
  environment with a data mount at `PGDATA` or `/var/lib/postgresql[/data]`, `/bitnami/postgresql`; database and user from
  `POSTGRES_DB`/`POSTGRES_USER` (or `pg_isready -U/-d` in `HealthCmd`; else `postgres`, reported `db-guessed`); major from
  the image tag (`16-alpine`, `pg17`; else `db-tag`). Other databases (MariaDB, MySQL, MongoDB, …) are cold only.
* Variants (only when a PostgreSQL database was found): `cold` (default: no `postgres` item, the data volume in `volumes`
  or data directory in `data_dirs` labelled `PostgreSQL 資料（冷備份）`, the database unit a writer), and — when every
  database keeps its data in a named volume — `instance` (`{"id","container","unit","user","data_volume","scope":
  "instance"}`) and `database` (`{"id","container","unit","database","user","data_volume"}`). The selected variant is
  `cold`, except for an installed entry that exports its database: then its mode is kept (`installed-mode`), because
  changing the mode makes the existing backups unrestorable under the new entry.
* `volumes`: named volumes the containers mount (`Volume=x.volume:` resolved through `VolumeName=`, default
  `systemd-<stem>`), except volumes mounted only below `/run`, `/var/run`, `/tmp`, `/var/tmp`, `/dev/shm` (skipped: sockets,
  PID files) and, in export modes, the database's data volume.
* `data_dirs`: bind-mounted directories in the owner's home (`%h/…`, absolute paths below the home, `./` relative to the
  Quadlet directory, `Mount=type=bind`, `PodmanArgs -v`), outermost directory only (`dir-nested`); a directory every
  container mounts read-only (configuration, program code) is still proposed and noted (`dir-read-only`). Refused with a reason:
  the catalog's forbidden trees (`bind-forbidden`: `.ssh`, `.local/bin`, `.config` as a whole, …), personal folders and whole
  configuration trees (`bind-sensitive`: `Desktop`, `Documents`, `Downloads`, `.cache`, `.local/state`, `.kube`, `.aws`, …),
  the home itself, paths with characters the catalog does not allow, symlinks, missing paths. System paths (`/etc/localtime`,
  `/run/dbus`) are skipped; a Podman/Docker socket is reported (`podman-socket`).
* `config_files`: `EnvironmentFile=` files (mode `0600`) and bound files (`0644`, or `0600` when not readable by group and
  others) that lie in `.config/<id>/` or `.local/share/<id>/`; a current mode above 0644 is reported (`config-mode`); files
  elsewhere are listed in `skipped`; files inside a proposed host directory are covered by it.
* `secrets`: every `Secret=` name (also `PodmanArgs --secret`); names that do not exist are reported (`secret-missing`).
* `health`: every `http://localhost|127.0.0.1|0.0.0.0[:port]/path` in a `HealthCmd=`, mapped to the host port of a
  `PublishPort=` bound to 127.0.0.1 or all addresses (of the container, its network-namespace owner or its pod; with
  `Network=host` the port itself); `expect_status` 200 and `timeout_seconds` 300 (180 for a single service without a
  database; 600 for the id `litellm`, `suggest.HEALTH_TIMEOUTS`) are proposals (`hints`). LiteLLM's 600 s (owner
  decision 2026-11-23, the catalog maximum) follows its package's own 10-minute start budget (40 readiness probes 15 s
  apart, `TimeoutStartSec=600`): real restores on a loaded test device took 251-345 s until `/health/readiness`
  answered, so 300 s could declare a restore that worked failed. A longer limit only waits longer; no check is relaxed.
  LAN-only ports, HTTPS and unpublished ports give hints instead of URLs. A query
  string (`?…`, possibly a token) is never copied: the URL keeps only its path and a hint says so (review L5). A path
  that answers only inside the container (`suggest.HEALTH_PATHS`: `emqx` `/readyz`, 403 through the published port) is
  replaced by the path of the same port that answers the host (`/`, the Dashboard the broker serves), with a hint.
* `verify`: built-in digests (feature 1): one `postgres-digest` per PostgreSQL database (`{"postgres": "main"}` in export
  modes, `{"container","unit","user"}` in cold mode) and one `files-digest` per proposed volume and host directory, except
  a PostgreSQL data volume or directory (the table digest covers it); at most 16. If the validator rejects them (an engine
  without digests) the draft keeps `verify: []` (`no-digests`).
* `name` is the id and `description` an automatic zh-TW summary; no `template_dir` (fresh deployment templates are
  installed separately). Every variant is checked with `catalog.validate_entry`: `valid`, `problem`, `field`.

**Installed entries.** For an id that is installed for this owner, every variant keeps the installed entry's name,
description, `template_dir`, volume and directory labels, `health` and `verify` items (built-in digests of targets the
installed checks do not cover are appended), its list order (new items last; the start order only when no unit was
added), and leaves out empty lists the installed entry leaves out. One exception: a `health` item of an id in
`suggest.HEALTH_TIMEOUTS` (`litellm`) with a shorter `timeout_seconds` (or none, the catalog's 60 s) gets that limit in
the draft, with an info note `health-timeout` naming the old limits; it takes effect when the draft is installed (the
engine never edits an installed entry by itself). The same way a `health` item that expects 200 on a path in
`suggest.HEALTH_PATHS` gets the path that answers the host, with an info note `health-path` (a check adapted to another
status is left alone). `installed.changes` is the structured diff
installed → draft, `installed.drift` the zh-TW notes on structural differences (a volume, directory, secret, config file,
unit, writer or Quadlet file on one side only), `installed.same` true when nothing differs.

Which mode a draft proposes (the general guidance is the "PostgreSQL modes" table above):

| | cold (default) | instance (`scope: instance`) | single database (`postgres` item) |
| --- | --- | --- | --- |
| Use when | any PostgreSQL, also with the data in a host directory, several databases and extra roles (Odoo, Nextcloud); a short stop of the database is acceptable | the database must keep running during the backup and the instance holds several databases or roles; restoring to a newer major is wanted | the instance holds exactly the app's database and the app needs no other role (LiteLLM, n8n, Hermes as installed today) |
| Not available | — | data in a host directory | data in a host directory; instances with other databases cannot be restored in place |
| Restore needs | the same PostgreSQL major | the same or a newer major | the same or a newer major |

The draft for an app that is already installed in an export mode keeps that mode, because switching modes makes its
existing backups unrestorable under the new entry (`compat` says so before installing).

### Installing and removing entries (`catalog-install`, `catalog-remove`)

* Without `confirm` both commands only preview and write nothing. `catalog-install` returns the validation result
  (`valid`, `error` with `details.field` for the editor), the installed entry, `expected_sha256` (sha256 of the installed
  file, null when none), the new file's sha256, `changes` (structured diff), `diff` (unified text diff of the pretty JSON,
  ≤ 400 lines), `compat` (zh-TW notes: added volumes, directories, secrets or config files make older backups of the app
  unrestorable under the new entry; removed ones are skipped when an older backup is restored; switching between cold and
  export modes; owner change; template removed), `warnings` (shared secrets or Quadlet files, missing template directory,
  unchanged entry), the number of listed backups of this app and the kept `history`.
* Validation = the loader's own `catalog.validate_entry` (strict, owner must exist) on the exact bytes that will be written
  (pretty UTF-8 JSON + newline, ≤ 256 KiB), plus conflicts with the other loaded entries of the same owner: a unit, volume
  (including database data volumes), database container or config file in two entries, or a host directory overlapping the
  other's directory or config file, is refused (`invalid-request`, `details.conflicts`); a shared secret or Quadlet file is
  a warning. An entry whose id is installed for **another owner** is refused (`invalid-request`, `details.field: "owner"`,
  `details.reason: "owner-change"`): its backups would restore into the new owner's account and count toward its
  retention; remove the entry first (`catalog-remove`), then install it for the new owner (review M3).
* With `confirm: true` the request must carry `expected_sha256` (the preview's value; null = "no entry installed"). Under the
  start lock: refused with `busy` (`details.job_id`) while any job is queued or running, or while a finished job still lists
  this app in `stopped_writers`, `fresh_apps` or `dir_apps` (the recovery settles them from this entry); refused with
  `invalid-request` (`details.reason: "entry-changed"`, `details.current_sha256`) when the installed file changed since the
  preview. The catalog directory and `/etc/woowtech-cockpit/backup` must be root-owned, not group/world-writable and not
  symlinks; a symlink or non-regular file at `<id>.json` is refused (`permission-denied`), never followed.
* Install: the previous file (if any) is copied to `apps-history/`, the new file is written as a hidden temp file
  (`O_EXCL|O_NOFOLLOW`), `fchmod 0644`, fsync, renamed to `<id>.json`, directory fsync. The catalog is then reloaded: the
  new entry must load with exactly these bytes and every app that loaded before must still load, else the previous file
  is put back (or the new one removed) and the call fails. Remove: the file is copied to `apps-history/` and unlinked;
  the app's backups stay (restorable again after the entry is re-installed).
* Each install and remove writes one line to the system journal (syslog ident `woowtech-cockpit-backup`, facility
  `authpriv`, priority notice): `catalog-install id=… owner=… sha256=… previous=…|- loginuid=…` /
  `catalog-remove id=… sha256=… loginuid=…` (`loginuid` from `/proc/self/loginuid`, the Cockpit session's login uid).
* Only the entry JSON is installed; deployment templates (`quadlet.template_dir`) are not created by these commands.

## 5. Backup file formats

Every new backup is **format 2** (`.tar`); format 1 (`.woowbackup`) files stay readable forever (`archive.format_of`
tells them apart by their first bytes). The app section of a manifest (`apps[]` in format 1, `app` in format 2) has one
schema (format 1 below and the shared rules after it), and entries are named `apps/<id>/<category>/<name>` in both
formats, so an extraction looks the same and the adapters do not care which format they restore.

### Format 2 (`.tar`, native since 2026-11-13)

A plain, uncompressed POSIX tar (ustar headers, a PAX `size` record only for a member over 8 GiB, mode 0600, uid/gid 0,
mtime = `created`) that any archive tool opens, like a Home Assistant backup. Members, in this order and nothing else:

| Member | Content |
| --- | --- |
| `backup.json` | readable metadata without secrets (below), ≤ 1 MiB UTF-8 JSON, padded with spaces up to the size reserved for it before the data was written |
| `README.txt` | ≤ 64 KiB UTF-8, zh-TW then English: what the file is, how to restore it in Cockpit, how to unpack it by hand (the exact age/zstd/tar or tar/gzip commands for each app) |
| `apps/<id>.tar.zst.age` | encryption `age-x25519`: age X25519 ciphertext (device recipient, `age -e -R <file>`) of zstd (`-3 -T2`) of the app's inner tar |
| `apps/<id>.tar.gz` | encryption `none`: gzip (exactly one RFC 1952 member; deflate level 1 in parallel 1 MiB blocks primed with the 32 KiB before them, like pigz) of the app's inner tar |

One application member per app of `backup.json`, in its order; then the end-of-archive marker and only zeros (≤ 1 MiB).

`backup.json` is **not authenticated**: it is shown before a key is entered and otherwise only compared with the
authenticated per-app manifests; any difference is `corrupt-archive`.

```json
{"format": 2, "backup_id": "20261113T020000Z-a1b2c3d4", "created": "2026-11-13T02:00:00Z", "type": "manual", "note": "",
 "tool": {"name": "woowtech-cockpit-backup", "version": "2026.11.13.3"},
 "source": {"hostname": "dev-a", "arch": "x86_64", "os": "Ubuntu 24.04.3 LTS", "podman": "4.9.3"},
 "encryption": "age-x25519", "compression": "zstd", "key_id": "ABCD-EF01-2345-6789",
 "apps": [{"id": "woowbk-demo", "name": "示範筆記應用", "adapter": "quadlet-postgres", "owner": "appowner",
           "images": [{"ref": "docker.io/library/postgres:16-alpine", "included": true}], "databases": ["notes"],
           "volumes": ["woowbk-demo-files"], "data_dirs": [], "secrets": ["woowbk-demo-db-password"],
           "config_files": [".config/woowbk-demo/app.env"],
           "file": "apps/woowbk-demo.tar.zst.age", "size": 1234567, "sha256": "…"}]}
```

Strict (unknown keys rejected; a schema violation is `corrupt-archive`, another `format` number or algorithm
`unsupported-format`): `encryption` `age-x25519` with `compression` `zstd` and a `key_id`, or `none` with `gzip` and
`key_id` null; `source` without a machine id; 1–100 apps, unique ids; per app `owner` (name), `images[{ref, included}]`,
`databases` (single-database: its database; instance: every database), `volumes`, `data_dirs` (paths), `secrets`
(names), `config_files` (paths) — **names only**, with the manifest's rules — `file` = `apps/<id>` + the suffix of the
encryption, `size` (> 0, the member's size) and `sha256` (of the member's bytes).

The inner tar of an app follows the strict tar rules of format 1: `manifest.json` first, then exactly the entries it
lists, in order. The **per-app manifest** (≤ 1 MiB; authenticated by age when encrypted):

```json
{"format": 2, "backup_id": "…", "created": "…Z", "type": "manual", "note": "", "key_id": "ABCD-EF01-2345-6789",
 "encryption": "age-x25519", "tool": {"name": "…", "version": "…"},
 "source": {"hostname": "…", "machine_id_sha256": "…", "arch": "…", "os": "…", "podman": "…"},
 "consistency": {"method": "writers-stopped", "downtime_seconds": 7}, "backup_apps": ["woowbk-demo", "n8n"],
 "app": {"id": "woowbk-demo", "…": "the format 1 app section"},
 "entries": [{"path": "apps/woowbk-demo/postgres/main.dump", "size": 12345, "sha256": "…"}]}
```

Validation (`archive.validate_app_manifest`): the head fields as format 1 (`key_id` null without encryption),
`backup_apps` the 1–100 unique app ids of the backup (including `app.id`), `app` the shared app-section schema
(`data_dirs`, `verify_digests`, instance-mode `postgres[]` items included), `entries` ≤ 3,999, all below
`apps/<app id>/`, each referenced exactly once. Readers also require: every head field, `backup_apps` and the app's
names equal `backup.json`; all manifests of one file share the same head; the member's sha256 equals `backup.json`'s
once the member was read whole.

Readers (`archive.read_header|read_manifest|verify_archive|extract_archive`, both formats): the outer tar is parsed
strictly first (headers only: names, sizes, order, padding, end marker, nothing after it); truncated, extra, duplicate,
missing or reordered members, links, directories, devices, GNU or global headers, PAX records other than `path`/`size`,
non-zero padding and trailing data are `corrupt-archive`; a tar whose first member is not `backup.json` is
`not-a-backup`. Then each **selected** app's member is fed (pread by offset) to `age -d | zstd -d`, or to zlib, its
manifest is read and checked, and (verify, extract) every entry by name, size and sha256; the tools must exit 0, the
gzip stream end exactly at the member's end and the member's sha256 match. Only the selected apps' members are read: a
restore of one app never decrypts another. Their manifests are read first, so the totals and limits are known before
anything is written. The combined manifest the flows get has the format 1 shape plus `format: 2`, `encryption` and
`backup_apps`, holding the selected apps only (`incompatible` when a selected app is not in the backup). Limits: ≤ 100
apps, ≤ 3,999 entries in all, manifest and `backup.json` ≤ 1 MiB, README ≤ 64 KiB, declared total ≤ 2 TiB and ≤ free
space − 512 MiB (extract). Errors as format 1 (`wrong-key` when age matches no identity and `backup.json` names a key
this device does not hold, else `corrupt-archive`; `key-required` without usable identities; an unencrypted backup needs
none).

Writer (`archive.write_archive` with `manifest.format` 2, or `archive.ArchiveWriter` app by app): a temp file next to
the destination; `backup.json` gets a fixed-size slot (its largest possible length) and is written last; each app's inner
archive streams (tarfile → zstd → age, or → the parallel deflate) straight into the file behind a header slot (512
bytes, or 1,536 with a PAX `size` record when an upper bound of the member exceeds 8 GiB) that is filled once the size is
known; then the end marker, fsync, a full read for the file's sha256 and an atomic rename. Every per-app manifest is
validated like a reader would. Returns `{size, sha256, apps[{id, file, size, sha256}]}`.

**Unencrypted backups and copies** hold everything (database dumps, secrets, password hashes) in clear text and nothing
in them is authenticated: anyone who had the file could have changed `backup.json`, the manifests and the data. A backup
made here and kept in the root-only `archives/` is trusted like an encrypted one; an **uploaded** (or adopted)
unencrypted file is `unauthenticated` (§7): its preflight warns and a restore needs `accept_unauthenticated`.

Download names: format 2 `woowtech-backup-<hostname>-<YYYYMMDD-HHMMSS>.tar`; an unencrypted copy (§8)
`woowtech-backup-<hostname>-<YYYYMMDD-HHMMSS>-unencrypted.tar` (the backup's source hostname and created time). An uploaded
file keeps its name when it matches one of these patterns (or the format 1 ones below) **with the extension of its
format**, else it is named `woowtech-backup-uploaded-<YYYYMMDD-HHMMSS>.tar` (`.woowbackup` for format 1).

**Deep verification** (the verify job; `deepcheck.DeepCheck`): `verify_archive(deep=…, scratch_dir=…)` hands every entry
of every app to the deep check while it streams. Entries with a nested format are copied one at a time into a private
scratch directory (free space ≥ the entry + 512 MiB, deleted right after the check) and checked with the restore's own
code: volume tars `nested.check_volume`, host-directory tars `nested.check_dir`, included images `nested.check_oci`
(against the ref and image id the backup recorded), digest listings `digests.read_files_detail|read_pg_detail` (digest
and summary equal the manifest's), instance role scripts `adapters.quadlet_postgres.globals_statements`; database dumps
must start with `PGDMP` and secrets be 1–511,999 bytes. A failure is `corrupt-archive` with `details.check`
(`volumes|dirs|images|digests|globals|dumps|secrets`), and the index records `verified {at, ok: false, deep: true}`. The
checks that depend on the device stay with the restore preflight: the owner's ID range for volume and directory
members, the image refs this device's templates need, PostgreSQL versions, the local catalog. Both formats are checked.

Lab (2026-11-14, dev-a/dev-b, `tests/e2e/lab/format_e2e.py`; woowbk-demo without images): an encrypted backup 450,560 bytes
(job 7.8 s), the same app unencrypted 890,880 bytes (8.9 s; deflate level 1 against zstd -3); GNU tar lists the members, the
README commands decrypt it with the emergency kit (and unpack the unencrypted one with tar alone), a format 1 backup still
verifies deeply and restores, a re-sealed backup with an escaping volume symlink fails the verify job, and restoring one app
of a two-app backup whose other application archive was damaged succeeds. `dirs_e2e.py` D1–D7 pass on format 2 (D5 crafts
its hostile cases with `ArchiveWriter`).

### Format 1 (`.woowbackup`, read forever)

```
WOOWTECH-BACKUP/1\n
{"format":1,"backup_id":"…","created":"…Z","key_id":"…","encryption":"age-x25519","compression":"zstd"}\n
<age v1 binary ciphertext of: zstd( POSIX/PAX tar )>
```

* Line 1 exactly `WOOWTECH-BACKUP/1`. Another `WOOWTECH-BACKUP/<n>` → `unsupported-format`;
  anything else → `not-a-backup`. Header line ≤ 4096 bytes, strict keys above.
* Encryption: `age` CLI with X25519 recipients from a 0600 recipients file in staging (`age -e -R <file>`, so the
  device recipient never shows in `/proc/<pid>/cmdline`), identities via `-i <file>`.
  Never pass key material in argv/env; identity files live in `/run/woowtech-backup` (0600).
* Tar members, in order: `manifest.json` first, then each entry listed in `manifest.entries` in
  that order. Regular files only, mode 0600, uid/gid 0, names exactly as listed.
* `manifest.json` (≤ 1 MiB):

```json
{
  "format": 1, "backup_id": "20261113T020000Z-a1b2c3d4", "created": "2026-11-13T02:00:00Z",
  "type": "manual", "note": "", "key_id": "ABCD-EF01-2345-6789",
  "tool": {"name": "woowtech-cockpit-backup", "version": "2026.11.13.1"},
  "source": {"hostname": "dev-a", "machine_id_sha256": "…", "arch": "x86_64",
             "os": "Ubuntu 24.04.3 LTS", "podman": "4.9.3"},
  "consistency": {"method": "writers-stopped", "downtime_seconds": 7},
  "apps": [{
    "id": "woowbk-demo", "name": "示範筆記應用", "adapter": "quadlet-postgres", "adapter_version": 1,
    "catalog_sha256": "…", "owner": {"name": "appowner", "uid": 1001},
    "images": [{"ref": "docker.io/library/postgres:16-alpine", "id": "sha256:…", "digest": "sha256:…",
                "arch": "amd64", "entry": "apps/woowbk-demo/images/0.oci.tar"}],
    "postgres": [{"id": "main", "database": "notes", "server_version": "16.4", "major": 16,
                  "entry": "apps/woowbk-demo/postgres/main.dump"}],
    "volumes": [{"name": "woowbk-demo-files", "entry": "apps/woowbk-demo/volumes/woowbk-demo-files.tar"}],
    "secrets": [{"name": "woowbk-demo-db-password", "entry": "apps/woowbk-demo/secrets/woowbk-demo-db-password"}],
    "config_files": [{"path": ".config/woowbk-demo/app.env", "mode": "0600", "entry": "apps/woowbk-demo/config/0"}],
    "quadlet_files": [{"name": "woowbk-demo-app.container", "entry": "apps/woowbk-demo/quadlet/woowbk-demo-app.container"}],
    "verify_snapshot": {"summary": {"notes": 12, "files": 4, "digest": "…", "title": "…", "signatures_valid": true}}
  }],
  "entries": [{"path": "apps/woowbk-demo/postgres/main.dump", "size": 12345, "sha256": "…"}]
}
```

`images[].entry` is present only when images were included. Entry paths match
`^apps/[a-z0-9][a-z0-9-]{1,40}/(images|postgres|volumes|dirs|secrets|config|quadlet|verify)/[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}$`.

Readers must: verify header, decrypt with the given identities (`wrong-key` when age reports no
matching identity), stream-decompress, parse+validate the manifest, then for every member check
name == next expected entry, type regular, size == declared, sha256 == declared, total ≤ limits;
reject links, devices, absolute or `..` names, duplicates, extra or missing members, and require
age and zstd to exit 0 before anything is considered valid. Extraction only into an empty
root-owned 0700 directory, with `O_NOFOLLOW|O_EXCL` file creation. Limits: ≤ 4000 members,
manifest ≤ 1 MiB, declared total ≤ free space − 512 MiB reserve, per-member size enforced while
streaming.

Key id: `sha256(recipient_utf8).hexdigest()[:16].upper()` grouped as `XXXX-XXXX-XXXX-XXXX`.
Backup id: `YYYYMMDDTHHMMSSZ-<8 lowercase hex>`. Job id: `j` + same pattern.
Download filename (format 1): `woowtech-backup-<hostname>-<YYYYMMDD-HHMMSS>.woowbackup` (hostname sanitized; seconds since
2026-11 so two backups of the same minute differ). An uploaded file keeps its name when it matches this pattern or the
older `…-<YYYYMMDD-HHMM>.woowbackup`; any other name is replaced by `woowtech-backup-uploaded-<YYYYMMDD-HHMMSS>.woowbackup`.

### Shared rules (both formats)

Nested tars (image entries `apps/<id>/images/<n>.oci.tar`, volume entries `apps/<id>/volumes/<name>.tar`) are untrusted
too. Before any change on the device the restore checks each completely (`woowbackup.nested`; the restore job's preflight
already does, before the safety backup, and the restore reuses the result):

* A volume tar may hold only regular files, directories, FIFOs, symlinks and hard links to an earlier non-directory
  member (a second name of a file, symlink or FIFO, as `podman volume export` writes it), with no absolute or `..`
  names, no duplicates, no member below a symlink or other non-directory, at most 2,000,000 members, no symlink whose
  target leaves the volume when resolved from the link's own directory (podman's own import rule, which otherwise
  aborts half-way after the volume was emptied), and only member owners (uid and gid) that the owner's user
  namespace maps (`podman unshare cat /proc/self/uid_map`, `gid_map`; else `incompatible`). Devices and sparse or
  unknown types are refused. Member names are kept as keyed 128-bit digests while checking.
* An image entry must be exactly a podman OCI archive (`oci-layout`, `index.json`, `blobs/`, `blobs/sha256/<hex>`) with
  one manifest whose config digest is the image `id` recorded in the manifest and whose
  `org.opencontainers.image.ref.name` names the image the local templates need: the ref itself or its normalized form;
  for a short ref (no registry) the same repository path and tag under any registry (podman saves `postgres:16` as
  `docker.io/library/postgres:16`, `app:1` built locally as `localhost/app:1`).

Podman is then fed a canonical tar rebuilt from the validated members only, never the archive's bytes: for volumes
setuid/setgid are dropped from non-directories, owner names dropped and only `SCHILY.xattr.user.*` kept (what was
dropped is reported, §7 `warnings`); for images the index names the image `local_name(ref)`, the name
`podman tag <id> <ref>` gives it (`localhost/<short ref>`, Docker Hub `library/`, `:latest` added), which `<ref>`
resolves to first, so the archive never chooses which image name of the owner moves. Exception: a short name with an
alias (`/etc/containers/registries.conf.d/shortnames.conf`: `ubuntu`, `python`, `node`, `alpine`, …) resolves to an
existing image under the alias target before `localhost/<ref>` (podman 4.9.3, checked in the lab). When `<ref>` then
still resolves to another image, that image's names which mean the image `<ref>` names (the rule above, e.g.
`docker.io/library/node:20` for `node:20`) are moved to the loaded or recorded image as well — names this device
already uses for `<ref>`, never one from the archive — and are put back after a failure. The load (or retag) must
leave `<ref>` resolving to the recorded image id. Every volume export is checked the same way when a backup is made
(§9).

**The app's settings in the archive (2026.11.15.2).** Every app section a backup writes carries `catalog_entry`: the
app's catalog entry as installed when the backup was made (the parsed JSON of `/etc/woowtech-cockpit/backup/apps/<id>.json`,
not its bytes). Readers check only its shape (a JSON object for the same app id, ≤ 256 KiB, depth ≤ 8, finite numbers,
text without NUL; otherwise `invalid-manifest`); it is never installed by a restore. `inspect` offers it for review where
the device has no settings for the app or other ones (`Preflight.apps[].settings`, §7), and the page installs it only
through `catalog-install` (the same validation, owner and conflict checks, apps-history, journal line and acknowledged
confirmation as any entry, §4). A drill on a new device found that settings drafted there by `catalog-suggest` can
differ from the source's (a database copied as a cold volume instead of dumped), which leaves the backup unrestorable:
the backup now brings the settings its items match. The preflight compares a carried entry with the local one as JSON
(an entry installed from a backup is formatted otherwise than a hand-written file); backups without it compare
`catalog_sha256` as before. The size is measured as compact JSON, so every file the catalog loads (≤ 256 KiB however
written) fits; an installed entry a backup cannot hold all the same (a lone surrogate escape in a hand-written file) is
left out of that backup with a job-log line, never fatal. Engines before 2026.11.15.2 refuse new backups
(`invalid-manifest`: the app section is strict), and the README in every backup and the emergency kit say so; every
backup made before stays readable. Rolling the engine back past 2026.11.15.2 (operations.md 回退) makes the backups made
since unreadable to it: verifying one there records a failed verification, which retention treats as a deletion
candidate, so they are left alone until the device is updated again and verified again then.

**Host directories in the archive.** An app with `data_dirs` carries `data_dirs: [{path, entry}]` in its manifest
(apps without them keep the old shape) and one entry `apps/<id>/dirs/<n>.tar` per directory, `<n>` its position in
the catalog. The tar is GNU tar's POSIX format of the directory read as the owner inside his user namespace (§6):
numeric owners as the namespace sees them, modes, nanosecond mtimes, hard links, symlinks verbatim, `user.*` xattrs;
no ACLs, no SELinux labels, one filesystem (`--one-file-system`). `nested.check_dir` checks it like a volume tar plus
the target owner's ID map: every owner must be mappable on the restoring device ("capacity"), members ≤ the volume
limit, no absolute names, `..`, links leaving the tree, devices or setuid bits; a restore only ever extracts the
canonical copy `nested.stream_dir` re-emits. A backup checks each of its own directory exports this way after the
writers run again, and fails rather than storing a directory a restore would refuse. Files owned by ids outside the
owner's range appear (and are restored) as the namespace's overflow id 65534; entries with POSIX ACLs are counted and
reported in the backup log, the ACLs are not kept.

**Data digests in the archive [format]** (accepted by both formats since 2026-11-13). An app with digest checks carries `verify_digests` (apps without them keep the
old shape, like `data_dirs`), one item per check whose digest was taken, and one entry per item in the new category
`verify` (`ENTRY_RE`: `(images|postgres|volumes|dirs|secrets|config|quadlet|verify)`, path `apps/<id>/verify/<check id>.txt`):

```json
"verify_digests": [
  {"id": "files", "type": "files-digest", "target": "volume:woowbk-demo-files", "exclude": [],
   "summary": {"entries": 40, "files": 30, "dirs": 8, "symlinks": 2, "other": 0, "bytes": 123456},
   "digest": "<sha256 hex of the entry>", "entry": "apps/woowbk-demo/verify/files.txt"},
  {"id": "db", "type": "postgres-digest", "target": "postgres:main", "exclude": [], "databases": ["notes"], "roles": false,
   "summary": {"databases": 1, "tables": 3, "sequences": 2, "rows": 345, "roles": 0},
   "digest": "<sha256 hex>", "entry": "apps/woowbk-demo/verify/db.txt"}
]
```

Validation (strict, unknown keys rejected): ≤ 16 items, `id` `^[a-z0-9][a-z0-9_-]{0,31}$` unique, `type` one of the two,
`target` ≤ 1100 characters of printable text, `exclude` ≤ 64 strings of 1–200 printable characters, `summary` an object
whose keys are exactly those of its type (files: `entries files dirs symlinks other bytes`; postgres: `databases tables
sequences rows roles`), each an integer 0…2^53, `digest` 64 lowercase hex, `entry` a `verify` entry of this app (listed
in `entries`, referenced once; its sha256 equals `digest`); postgres only, both required: `databases` 1–64 names
`^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,62}$`, `roles` boolean; optional (2026-11-14, review L4/F7) `server_major` 1…999, the
PostgreSQL major the digest was read on (a restore does not compare a digest read on 11 or older with one read on 12 or
newer: float text differs; the check then reports `match: null` with a `note`). The entry is canonical text, one line per item, ≤ 2,000,000
lines of ≤ 20,000 bytes, strictly increasing: files `<kind f|d|l|p|c|b> <mode 4 octal> <uid> <gid> <size> <sha256|-> <link
target hex|-> <path hex>` sorted by path bytes; postgres `D <db hex>` (each database read), `T <db hex> <schema hex> <table hex> <r|S> <rows> <a> <b>` (`a`, `b` signed: sums of signed 64-bit halves),
`R <role hex> <7 t/f flags> <connection limit> <valid until hex|-> <md5 of the password hash|->`, `M <role hex> <member
hex> <t|f>` sorted by line bytes (`woowbackup.digests` parses both and is what the engine uses; a reader that only
displays may ignore the entry). The verify job's deep check may recompute the entry's sha256 against `digest`.

**Import readback in the archive [format]** (2026-11-23). The app section of a converted Home Assistant backup may
carry `import_check` (older archives have none; an engine that does not know the key refuses the archive as before):

```json
"import_check": {"kind": "emqx-readback", "version": 1,
  "config_roots": {"authorization": "<sha256 hex>", "listeners": "<sha256 hex>", "node": "<sha256 hex>"},
  "tables": {"emqx_authn_mnesia": [4, "<sha256 hex>"], "emqx_authn_scram_mnesia": [0, "<sha256 hex>"],
             "emqx_acl": [4, "<sha256 hex>"], "emqx_admin": [2, "<sha256 hex>"], "emqx_app": [1, "<sha256 hex>"],
             "emqx_psk": [0, "<sha256 hex>"], "emqx_banned_rules": [-1, null]}}
```

Validation (strict, unknown keys rejected): `kind` one of the known kinds and belonging to the section's app
(`emqx-readback` → `emqx`), `version` 1, `config_roots` 1–128 roots `^[a-z][a-z0-9_]{0,63}$` (a real broker has all of its about 44) each a 64
lowercase hex digest, `tables` exactly the kind's tables, each `[rows, digest]` with `rows` −1…2^31 (−1: no such table, digest
`null`) and a 64 lowercase hex digest otherwise. CONTRACT section 9 (EMQX, step 6) says how a restore uses it.

**Instance-mode PostgreSQL items [format]** (accepted by both formats since 2026-11-13). A `postgres[]` item may carry `"scope": "instance"`; then (all keys required,
unknown keys rejected):

```json
{"id": "main", "scope": "instance", "database": "postgres", "server_version": "16.16", "major": 16,
 "entry": "apps/nextcloud/postgres/main.globals.sql",
 "databases": [{"name": "nextcloud", "owner": "oc_admin", "encoding": "UTF8", "collate": "en_US.utf8",
                "ctype": "en_US.utf8", "locale_provider": "libc", "icu_locale": null,
                "extensions": [{"name": "pg_trgm", "version": "1.6"}],
                "entry": "apps/nextcloud/postgres/main.db0.dump"}],
 "roles": [{"name": "oc_admin", "superuser": false, "login": true}]}
```

`database` is the database the backup connected to (`postgres` or `template1`), `entry` the `pg_dumpall --globals-only
--no-tablespaces` output (role definitions with password hashes: it is as sensitive as the secrets), `databases` 1–64
items with `name` as above (unique), `owner` 1–63 printable characters, `encoding` `^[A-Za-z0-9_]{1,32}$`, `collate`,
`ctype` `^[A-Za-z0-9_.@-]{0,100}$`, `locale_provider` `libc|icu|builtin`, `icu_locale` null or like `collate`,
`extensions` ≤ 100 items `{name, version}` of 1–63 printable characters, `entry` a `postgres` entry of this app (the
database's `pg_dump -Fc`); `roles` ≤ 1000 items `{name (1–63 printable), superuser (bool), login (bool)}`. Every entry is
referenced once. Optional since 2026-11-14 (archives written before have neither): `bootstrap_user` (1–63 printable,
the instance's bootstrap superuser at backup time; review F5) and per database `template` (boolean: a template database,
kept since 2026-11-14 and marked a template again by `pg_restore --create`; review F1); `template0`/`template1` are
never items. Items without `scope` (or `"scope": "database"`) keep the single-database shape above. The UI only
displays names and counts; passwords never appear outside the globals entry.

### Home Assistant backups (read only; branch `feat/ha-import`)

Home Assistant OS backups (Supervisor) are uploaded like any backup and **read**, never written. Facts and sources:
`tests/backup/fixtures/ha/README.md` and the design notes of the branch.

* **Outer file**: a plain, never compressed POSIX tar written by Python's tarfile -- per member a PAX header (float
  `mtime`; `path`/`size` when needed) and a regular file, `./backup.json` written last, flat names (`./` stripped
  before comparing). Accepted: ustar POSIX headers with valid checksums, PAX records `path size mtime atime ctime uid
  gid uname gname hdrcharset` (any other key, `GNU.sparse.*` and global headers are refused), regular files only, no
  duplicates, zero padding, the end-of-archive marker and only zeros (≤ 1 MiB) after it, ≤ 512 members.
* **Recognition** (`habackup.looks_like_ha`, run by `upload-finish` before the Cockpit formats): a member named
  `backup.json` (any `./` prefix) whose strict JSON has `supervisor_version`. A Cockpit file answers no at once.
* **backup.json** (≤ 1 MiB, strict JSON; a subset of Supervisor's SCHEMA_BACKUP, unknown keys ignored): `version` 2
  (1 → `unsupported-format`), `slug` `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, `name` ≤ 200 characters without control
  characters, `date` ISO 8601 (kept as UTC `…Z`), `type` `full|partial`, `supervisor_version`, `protected` and
  `compressed` booleans, `addons[{slug, name, version, size?}]` (≤ 100, unique slugs), `folders[]` (`homeassistant`
  dropped, `addons/local` read as `apps/local`), `homeassistant` object|null, `repositories[]`, `extra` object. Display
  data only: never trusted for a security decision.
* **Members**: exactly `<add-on slug>.tar[.gz]` per add-on, `homeassistant.tar[.gz]` when `homeassistant` is set,
  `<folder with / as _>.tar[.gz]` per folder (`apps_local` or the legacy `addons_local`) and optionally
  `supervisor.tar[.gz]`; `.tar.gz` when `compressed`, else `.tar`. Encryption is decided **per member from its first
  bytes**, never from `protected` (Home Assistant's download button gives a decrypted copy that says `protected: false`
  while `supervisor.tar.gz` stays encrypted): `SecureTar` + version 2|3 → v2|v3 (another version:
  `unsupported-format`), gzip or tar magic → plain, anything else → v1 when `protected`, else `corrupt-archive`. The
  member size must fit the header: v1 whole cipher blocks, v2 the plaintext size rounded up to the next 16 bytes, v3
  the plaintext size + 17 bytes per 1 MiB chunk.
* **securetar** (`hasecuretar`): v1 (Supervisor ≤ 2024.12: 16 B salt + AES-128-CBC), v2 (2025.01–2026.03: 48 B header +
  AES-128-CBC, PKCS7 over the whole stream), v3 (2026.04+ with Core 2026.3+: 136 B header + XChaCha20-Poly1305
  secretstream in 1 MiB chunks). Keys come from the HA key text exactly as pasted (UTF-8, never trimmed or upper-cased):
  v1/v2 100 rounds of SHA-256; v3 Argon2id (opslimit 8, memlimit 16 MiB, once per backup) and BLAKE2b-256 subkeys. A
  wrong key is `wrong-key` before any plaintext (v3 exact through the validation key; v1/v2 the first 512 decrypted
  bytes must look like gzip or tar, a heuristic). Truncation and tampering are `corrupt-archive`: v3 authenticates every
  chunk and requires exactly the writer's tags and chunk sizes, v2 its padding and plaintext size; v1 has no integrity of
  its own (the gzip CRC/ISIZE or the tar structure catches it). PyNaCl (`python3-nacl`, v3) and cryptography
  (`python3-cryptography`, v1/v2) are imported only when needed; a missing package is `internal-error` naming it.
* **Member streams**: decrypted, then gunzipped by the engine's own reader (RFC 1952 header parse, raw inflate with
  bounded output, CRC32 and ISIZE checked; a v1 member may end `pad | CRC | 0x0c × 12 | ISIZE`, the trailer securetar
  ≤ 2024.11 wrote because it padded every write, also checked).
* **Inner tars** (`habackup.iter_entries`): ustar POSIX or GNU headers with PAX and GNU long-name records; names
  without `./`, never absolute, with `..`, `.` or empty components or control characters, ≤ 4096 bytes; no
  duplicates, nothing below a non-directory, no non-directory where a directory was implied; regular files,
  directories, symlinks (handed out only below the caller's areas when relative and staying inside them -- or, since
  batch 1, absolute with a clean target below a prefix the caller allows (`Select.absolute_symlinks`: no empty, `.` or
  `..` component, so joined below the link's folder it stays in the volume) -- else skipped and counted; a symlink is
  only ever a link entry and nothing may lie below it), hard links (only to an earlier selected regular file and only
  when the caller allows them, else refused) and FIFOs (skipped); devices, sparse and contiguous files, global headers
  and unknown types are refused;
  member and byte budgets; the end-of-archive marker, only zeros after it, then the stream's final checks.
  `addon.json` of an add-on is parsed (`system.slug`, `version`, `user.image` → arch `amd64|aarch64|unknown`,
  `system.name`) and never handed out (it holds the options with passwords and the tokens); `data/options.json`,
  `data/odoo.conf`, `data/n8n-runners-auth-token` and (batch 1) Hermes's `data/secrets/{dashboard_password,
  api_server_key,webhook_secret,basic_auth_secret}` and `data/applied/{minimax_api_key,openrouter_api_key,github_token}`,
  EMQX's `data/emqx/node.cookie` and Headscale's `data/.headplane_api_key` / `data/.headplane_cookie_secret` are never
  read.
* **Apps**: an add-on maps to this device's catalog id by its slug after the first `_` (any repository prefix), from
  the one registry `haapps.IMPORTERS` (in this order): `odoo18ce` → `odoo`, `woow-n8n` → `n8n`, `woow-omnigent` →
  `omnigent`, `woow-hermes` → `hermes`, `woow-emqx` → `emqx`, `woow-headscale` → `headscale`; the jobs identify the app
  by addon.json `system.slug`.

## 6. Python module contract (signatures are in the scaffold files; keep them)

* `errors.BackupError(code, message, **details)` — every expected failure. `message` is zh-TW.
* `archive`: `read_header(path)` (format 1 header, or format 2 `{format, backup_id, created, key_id|null, encryption,
  compression}` from `backup.json` after the strict outer parse), `format_of(path)`, `describe(path)` /
  `describe_fd(fd, check_members, hasher)` (`{format, header, doc, readme}`; uploads read every byte once),
  `write_archive(dest, header, manifest, entries, recipient|None, *, tmp_dir, progress)` (format by `manifest.format`),
  `ArchiveWriter(dest, head, apps, recipient|None, *, tmp_dir)` with `add_app(app, entries, *, meter|progress)` and
  `finish()` / `abort()`, `head_of(manifest)`, `read_manifest(path, ids, *, limits, apps)`,
  `verify_archive(path, ids, *, progress, limits, apps, deep, scratch_dir)` → `{manifest, entries, bytes, format,
  encryption}`, `extract_archive(path, ids, dest, *, progress, limits, apps)`, `validate_manifest` (format 1),
  `validate_app_manifest` / `validate_doc` (format 2), `Entry`, `inner_name(app_id, encryption)`.
* `keys`: `KeyStore(paths)` with `device_key()`, `ensure_device_key()`, `identities()`,
  `import_key(text)`, `kit_text()`, `confirm_kit(key_id)`, `temp_identity(text)` (context manager).
* `storage`: `Storage(paths)` with layout, ids, index CRUD, uploads, staging, free space;
  `archive_path(id, fmt=None)` (the file that exists, `.tar` first, else the name a new format `fmt` backup gets —
  format 2 by default), `exports` (dir), `new_export_id()`, `publish_export(export_id, staged, *, backup_id, filename,
  sha256, ttl, evicted=None)` (`evicted`: a list that receives the ids of copies it removed), `list_exports()`,
  `export_info(export_id, removed=None)` (`removed`: ids of expired copies it deleted on the way), `delete_export(export_id)`,
  `cleanup_exports()`; `storage.unauthenticated(meta)`.
* `settings`: `load(paths) -> ({encrypt_by_default}, problem|None)`, `encrypt_by_default(paths)`, `view(paths)`,
  `save(paths, *, encrypt_by_default, acknowledge_plaintext)`, `PLAINTEXT_WARNING` (zh-TW).
* `deepcheck`: `DeepCheck(log)` with `start(apps)`, `wants(path)`, `entry(path, head, file, size)`, `report()`,
  `summary_text()`, `notes`.
* `catalog`: `load_catalog(paths) -> dict[str, App]`.
* `podman`: `OwnerRunner(owner)` — runs as the owner via `runuser`, user systemd, safe file I/O.
* `adapters.quadlet_postgres.QuadletPostgresAdapter` — implements `adapters.base.Adapter`; `unavailable(info)`
  (2026.11.17.1) gives the zh-TW reason why `backup()` cannot run in the app's current state (`info` from `probe()`:
  a database it dumps is not running — 「應用「<name>」已停止，無法備份：備份時它的資料庫必須在執行中。」, or 「應用「<name>」的資料庫沒有在
  執行，…」 while other units run), None when it can (an app with nothing to dump is backed up while stopped).
* `flows`: `run_backup`, `run_restore`, `run_verify` (deep), `run_export` (used by jobs); `Deps` gains optional
  `encrypt_by_default() -> bool`, `schedule_cleanup(seconds, export_id)`, `audit(line)` and
  `enforce_retention(app_ids, *, exclude, log) -> [backup ids]` (default `retention.enforce_after_backup`);
  `running_reserve(ctx)` (space a verify or export job leaves free), `pinned_safety(paths)` (None while a job record
  cannot be read).
* `suggest`: `suggest(owner, *, paths, catalog)` (`catalog-suggest`); `catalog_admin`: `preview_install`, `install`,
  `preview_remove`, `remove`, `audit_log`, `login_uid`; `retention`: `load_policy`, `validate_policy`, `app_usage`,
  `plan_command`, `apply_command`, `enforce_after_backup` (all take `trusted_uid`, root in production).
* `jobs`: `JobStore` (`list(limit, *, unreadable=None)`: `unreadable` receives the ids of record files that could not be
  read), `start_job`, `run_job`, `recover_interrupted`, `pinned_safety_records(records)` (`{record id: safety id|None}`).
* `digests`: `ROW_TEXT` (`pg_catalog.record_out(t.*)::text`), `PG_OPTIONS`, `FLOAT_TEXT_MAJOR`, `tables_sql(oids)`,
  `pg_lines`, `read_files_detail`, `read_pg_detail`, `diff`.
* `hasecuretar` (branch feat/ha-import; §5 "Home Assistant backups"): `Keys(password)` (one per HA backup and job;
  `invalid-request` for text that is not a key; no repr of the key), `sniff(head)` (`v2|v3|unsupported|gzip|tar|
  unknown`), `ciphertext_ok(kind, member_size, head)`, `DecryptReader(src, member_size, keys, *, name)` (io.RawIOBase
  over any `read(n)` source positioned at the member: `read`/`readinto` bounded to one ~1 MiB chunk, `finish()` reads
  the rest and runs the final checks, `kind`, `plaintext_size`; `wrong-key`/`key-required`/`unsupported-format` come
  from the constructor, before any plaintext), `open_decrypted(...)`, the zh-TW `WRONG_KEY_MESSAGE`, `CORRUPT_MESSAGE`,
  `KEY_REQUIRED_MESSAGE`.
* `habackup`: `looks_like_ha(fd) -> bool`; `describe(fd) -> Layout` (`doc` (validate_doc), `members` of `Member(name,
  offset, size, role addon|homeassistant|folder|supervisor, slug, encryption none|v1|v2|v3, compressed)` (`.encrypted`),
  `size`, `member(name)`, `addon(slug)`, `summary()`); `open_backup(path) -> HaBackup` (context manager; `layout`,
  `open_member(name, keys=None)`, `open_addon(slug, keys=None)`); `open_member(path, name, *, keys=None,
  password=None) -> MemberStream` (owns its descriptor); `MemberStream` (io.RawIOBase of the member's tar stream:
  `member`, `finish()`, `close()`); `iter_entries(stream, select=None, report=None, *, addon=None)` yields `Entry`
  (`name, kind file|dir|symlink|hardlink, mode, uid, gid, size, mtime, linkname, fileobj`, `read(n)`,
  `read_all(max_bytes)`, `copy_to(out)`; a file's data is readable until the walk moves on) and sets `report.complete`
  only after every final check; `Select(include=None|(), exclude=(), symlinks=(), hardlinks=False, max_members,
  max_bytes, absolute_symlinks=())`; `Report` (`entries, files, dirs, symlinks, hardlinks, bytes, skipped_symlinks,
  skipped_symlink_samples, absolute_symlinks, skipped_other, secret_files, addon, complete`, `warnings()` zh-TW); `read_addon_info(stream) -> AddonInfo|None`,
  `parse_addon_json(data) -> AddonInfo(slug, version, image, arch, name, state)` (`state`: addon.json `state`, the
  add-on's state when the backup began, '' when absent; batch 1), `image_arch(image)`, `normalize(name)`,
  `NEVER_READ`.
* `hastore`: `HaStore(paths)` (`root`, `ensure()`, `file_path(id)`, `list()`, `get(id)`, `exists(id)`, `delete(id)`,
  `publish(fd, st, part, summary, sha256, filename) -> (record, created)`), `view(record, catalog) -> HaBackupMeta`,
  `valid_id`, `is_record`, `addon_suffix(slug)`, `importable_app(slug) -> (app_id, name)|None`, `IMPORTABLE`,
  `SIDECAR_KEYS`; `storage.Storage.ha_store`, and `Storage.finish_upload` returns the HA record (id `ha-…`) for an HA
  file.
* `jobs` (branch feat/ha-import): `redact(text)` also masks `HA_KEY_PATTERN` and every exact text registered with
  `mask_secret(text)` / `unmask_secret(text)` / `masked(text)` (context manager, reference counted, process-wide: the job
  process that holds an HA key registers it before it logs anything). Part B: `start_job(..., key_text, key_kind='age'
  |'ha', ..., sweep_temp=None)` (`ha`: validated by `hasecuretar.Keys`, written as the raw UTF-8 text, never trimmed),
  `HA_PHASES`, `is_ha_job(type, params)`, records may carry `temp_owners` (owners whose throwaway objects the job may
  have left; `has_leftovers`), `recover_interrupted(..., sweep_temp=None)` (`sweep_temp(job_id, owners) -> [problems]`,
  default `haimport.sweep_job`); `run_job` reads an HA job's key file, masks it and sets `ctx.ha_key`, and calls
  `deps.sweep_temp(job_id, log)` when the deps have one.
* `tempctr` (part B): `TempObjects(runner, job_id, *, log, memory='2g', pids=1024)` (context manager) with `name(role)`,
  `volume(role)`, `network(role)` (internal), `run(role, image, args, *, detach, network, volumes, secrets, env,
  entrypoint, user, workdir, input, stdout, timeout, max_output, check, remove)`, `run_argv(...)`, `exec(role, argv, *,
  user, env, input, stdout, timeout, max_output, check)`, `stop(role)` (exit code), `running(role)`, `remove(role)`,
  `remove_volume(role)`, `user_ids(role, image, user)` (`run`/`run_argv` also take `read_only_root` and, batch 1,
  `add_hosts=[(name, IPv4)]` -> `--add-host`), `volume_import(role, produce)` (a producer writes the tar into a
  pipe), `volume_export(role, handle)`, `kill_all()`, `cleanup() -> [names left]`, attributes `cpus`, `abort` (the
  job's watchdog, handed to every long podman call); `sweep(runner, alive, *, log, only_job) -> (removed, left)`,
  `default_cpus(uid)`,
  `quadlet_secrets(text)`, `quadlet_image(text)`, `quadlet_environment(text, allowed)`, `parse_unit(text)`, `LABEL`.
* `ha_odoo` / `ha_n8n` (part B): `check(work, app)` and `convert(work, app, …, out_dir)` (the app steps of the jobs,
  driven by `haimport.Work`), the pure parts the tests use (`database_verdict`, `parse_manifest`, `same_version`,
  `filter_toc`, `superuser_kinds`, `settings_to_carry`, `split_list_setting`, `alter_system_sql`, `carry_settings`,
  `restore_dump`, `verify_converted`, `marker_ok`, `role_sql`, `scan_member`, `PgSink`, `ha_server_args`, `web_data_tar`,
  `addons_dir_tar`, `Live`; `inspect_sqlite(path, *, checkpoint)` -> workflows `[(name, active, reasons)]`,
  `workflow_reasons`, `workflows_to_fix`, `fixed_key_settings`, `packages_of`, `elf_fits`, `scan_member`, `count_rows`).
* `haapps` (batch 1): `Importer(app_id, slug, name, module, convert_args, mcp_admin, mcp_addon, engine_mcp_lines)`
  (`load()` imports the module), `IMPORTERS` (ordered), `BY_APP`, `BY_SLUG`, `APP_IDS`, `get(app_id)`,
  `for_slug(suffix)`; every importer module has `check(work, app)` -> `{target_version, blockers?, warnings?, <app id>:
  section}`, optionally `check_blockers(found)`, `convert(work, app, *convert_args, out_dir)` -> `{volumes?, postgres?,
  dirs?, ...}` and `import_texts(data)` -> `(notes, reminders)`. `hastore.IMPORTABLE`, `haimport.APPS` and
  `cli.HA_APP_IDS` are derived from it.
* `hacommon` (batch 1): `VersionTable(product, table)` (`upstream(addon_version)`, `blocker(addon_version, target)`),
  `semver`, `image_labels(work, app, ref)`, `container_file`, `mounted`, `environment`, `live_json`, `live_export`,
  `copy_live`, `top_only`, `TreeTar(path, uid, gid, guard)` (`root`, `dir`, `file`, `data`, `symlink`, `hardlink`,
  `close`, `files`, `counts`), `ha_hosts(text)`, `scalars(yaml_text)`, `network`, `host_elf_machine`, `foreign_elf`.
* `hasqlite` (batch 1): `run(specs, files, work_dir, *, outputs, out_dir, checkpoint, timeout, what)` -> `{db name:
  answer, None: {output name: path}}`, `problem(answer)`, `QUERIES`, `CHILD`; a spec is `{db, check: 'quick'|
  'integrity'|None, schema, counts[table], queries[QUERIES key], replace_api_keys_from: db|None}`.
* `ha_omnigent` / `ha_hermes` / `ha_emqx` / `ha_headscale` (batch 1): `check`, `convert`, `import_texts`, `VERSIONS`,
  `scan_member`, `Target`, and the pure parts the tests use (`toc_kinds`, `key_ok`, `strip_env`, `parse_counts`,
  `parse_authn`, `parse_strict`, `check_counts`, `valid_records`, `records_rel`, `nodes_outside`).
* `haimport` (part B): `run_ha_check(ctx, params)`, `run_ha_convert(ctx, params)` (reached through `flows.run_verify` /
  `flows.run_backup` when `params.source` is `ha`), `Work`, `SpaceGuard`, `Watchdog`, `job_key(ctx)`,
  `read_key_file(path)`, `import_texts(converted, catalog=None)`, `mcp_lines(importer, catalog)`, `clean_row(row)`,
  `register(paths, backup_id, row)`,
  `forget(paths, backup_id)`, `load_registry(paths)`, `from_ha_views(paths)`, `view_row(row)`, `note_for(record)`,
  `sweep_job(job_id, owners)`, `sweep_finished(paths, *, log, current)`,
  `interrupted_message(job_type)`, `APPS` (from `haapps`), `ITEM_KEYS`.
* Adapter (part B): `read_quadlets()` and `import_manifest(staging_dir, *, postgres, volumes, dirs)` -> `(app section,
  [Entry])`: images, secrets, config files and Quadlet files read live exactly like `backup()`, the data items given
  (one per declared item), `verify_snapshot` empty, `catalog_entry` carried. `flows.Deps.sweep_temp`,
  `FlowContext.ha_key`, `FlowContext.phase(phase_id, *, percent, message)` / `JobReporter.phase(...)` (a progress that
  replaces the phase position's), `podman.default_runner(..., abort)` / `OwnerRunner.run|relay|dir_pack(..., abort)`,
  `habackup.iter_entries(..., checkpoint)`, `retention.converted_ids(paths)`, `retention.plan(..., converted)`,
  `retention.app_usage(..., converted)`.
* `cli.main(argv) -> int`.

**Directory helper** (`podman.DIR_HELPER`, host directories only). `OwnerRunner` runs
`podman unshare /usr/bin/python3 -I -c DIR_HELPER <op> …` as the owner, i.e. as root of his rootless user namespace:
files of his subordinate ids can be read, written with their owners and removed, never more than his own rights.
Every component from `$HOME` down is opened with `O_NOFOLLOW` (a directory that is a symlink, or lies below one, is
refused) and renames use `renameat2(RENAME_NOREPLACE)`. Siblings are named `<dir>.woowbk-new-<token>` (being
written), `<dir>.woowbk-old-<token>` (the replaced copy) and `<dir>.woowbk-del-<token>` (an old copy being deleted);
`<token>` is the job id, `<job id>-rollback` for its rollback. Operations: `pack` (tar to stdout through the owner-side
relay), `measure` and `mounts` (size, entries, entries with ACLs; whether the directory is a mount point and the mount
points below it, compared by device and statx mount id), `unpack` (stdin tar into the new sibling, missing parents
created 0700), `swap` (directory → old sibling, new sibling → directory; fresh mode only replaces an empty directory),
`revert` (rollback without a copy: directory → old sibling of the rollback token, the restore's old sibling →
directory), `drop new|old|del|target` (an old copy is renamed to `del` first; every directory's device and mount id
are checked before anything is deleted), `back` (old sibling → a missing directory) and `state` (type, empty, mount
point, device and free space of the parent, siblings: those of the requested tokens always, others up to 50 plus a
count). The owner controls that namespace (he can bind-mount over `python3` in it), so every answer is untrusted:
`OwnerRunner` checks each field (types, enums, token format, the requested paths exactly once) and turns undecodable,
deeply nested or differently shaped answers into `BackupError(job-failed)`; exit status 12 means a mount point.
Two more operations list a tree for `files-digest`, through the owner-side relay into a staging file: `digest <rel> <flags>
[glob…]` (a host directory, reached like the others) and `digestvol <mount point> <flags> [glob…]` (a volume's mount
point as `podman volume inspect` printed it, opened with the owner's rights). `flags`: `root` (list the top directory),
`nosetid` (mask setuid/setgid of non-directories), or `-`. Symlinks are never followed, another mount below the top
fails (exit 12), more than 2,000,000 entries fail (13), a regular file that changes while it is hashed fails (14).
The listing is untrusted: `woowbackup.digests` parses it line by line, requires strict order, bounds it and recomputes
its digest; psql's JSON answers for `postgres-digest` are checked field by field the same way.

Adapter additions (E2, used by flows): `stage_dirs(app_manifest, extracted_dir, mode)` (host directories written to their
new siblings before anything stops), `take_over(units, first_stop)` (units a safety backup left stopped),
`backup(..., keep_stopped=True)` with `kept_stopped`, `start_groups(units)`, `timing_report()`
(`{writer_pause_seconds, unavailable_seconds}`), `digest_results` (the checks of the last restore). `flows.create_backup(...,
keep_stopped=True)` returns `handover {app_id: {units, first_stop}}` besides `timing` and `unavailable_seconds`.

## 7. Helper CLI contract (UI ↔ engine)

Invocation from the UI: `cockpit.spawn(["/usr/local/libexec/woowtech-cockpit-backup", <command>],
{superuser: "require", err: "message"})`, request JSON written to **stdin** (`proc.input(json)`),
response is exactly one JSON object on **stdout**. Exit 0 → `{"ok": true, …}`. Exit 1 →
`{"ok": false, "error": {"code": "…", "message": "zh-TW text", "details": {}}}`. stdin ≤ 1 MiB.
Key material only ever travels in stdin JSON field `key`.

| Command | stdin | stdout (ok) |
| --- | --- | --- |
| `status` | – | `version, host{hostname,arch,os,podman}, storage{path,free_bytes,total_bytes,backups_bytes,backup_count,apps[AppUsage],ha_backups_bytes,ha_backup_count}, key{key_id,created,kit_confirmed}\|null, imported_keys[], apps[App], active_job Job\|null, warnings[], settings Settings, schedule ScheduleSummary\|null` (deletes expired unencrypted copies first, §8; `storage.apps` is the per-app usage of the overview, no I/O beyond the index listing and the policy file, `[]` when it cannot be computed; `schedule` null when it cannot be computed, 2026.11.17.1) |
| `list` | – | `backups[BackupMeta]` (newest first), `exports[{export_id,backup_id,filename,size,expires}]` (unencrypted copies that can still be downloaded; `expires` epoch seconds), `ha_backups[HaBackupMeta]` (uploaded Home Assistant backups, newest HA backup date first; `[]` when the HA store cannot be read; branch feat/ha-import) |
| `inspect` | `backup_id, key?, save_key?` | `backup BackupMeta, manifest ManifestSummary, preflight Preflight` (`backup` carries `from_ha` exactly like `list`; with `key`, only that key is used; `save_key` imports it only after it decrypted the manifest, else `wrong-key`; an unencrypted backup needs no key and refuses one with `invalid-request`). Fast: a format 2 backup decrypts only each app's manifest |
| `key-init` | – | `key, created(bool)` |
| `key-kit` | – | `key_id, filename, content` (kit text) |
| `key-confirm` | `key_id` | – |
| `key-import` | `key` | `key{key_id,created}` |
| `backup-start` | `apps[], include_images, note, request_id, encrypt?, acknowledge_plaintext?` | `job_id, deduplicated` (`encrypt` = 加密此備份, default the setting 預設加密備份; `encrypt: false` needs no device key, and while the setting is on it needs `acknowledge_plaintext: true`, else `invalid-request` with `details.field`; `encrypt: true` without a device key is `no-device-key`; params record `encrypt`) |
| `verify-start` | `backup_id, request_id, key?` | `job_id, deduplicated` (the job verifies deeply, §5; `key` is refused for an unencrypted backup) |
| `restore-start` | `backup_id, apps[], request_id, confirm:true, key?, save_key?, allow_no_safety?, accept_unauthenticated?` | `job_id, deduplicated` (`save_key` imports only a key that opens this backup; `allow_no_safety: true` is the explicit, separately confirmed "restore even if no safety backup can be made"; `accept_unauthenticated: true` is required — `invalid-request` with `details.field` otherwise — for an `unauthenticated` backup: the separately confirmed "I trust where this unencrypted file came from"; only the selected apps are read) |
| `settings-get` | – | `settings Settings` |
| `settings-set` | `encrypt_by_default, acknowledge_plaintext?` | `settings Settings` (turning it off needs `acknowledge_plaintext: true`, the acknowledgement of `plaintext_warning`; audited) |
| `export-start` | `backup_id, request_id, confirm:true, key?` | `job_id, deduplicated` (an **unencrypted copy** of an encrypted backup for one download; `invalid-request` for a backup that is not encrypted — download it as it is; `key-required` when the key is not on this device and none is given; audited) |
| `export-info` | `export_id` | `path, filename, size, expires, backup_id` (`path` only inside `exports/`; `not-found` once expired; audited) |
| `export-delete` | `export_id` | `deleted(bool)` (audited) |
| `export-cleanup` (internal) | argv only | `removed[]` (run by the transient timer an export schedules) |
| `catalog-suggest` | `{}` or `{owner}` | without owner: `owners[Owner]`; with owner: `owner, uid, quadlet_dir, state("ok"\|"missing"\|"blocked"), owners[Owner], apps[Draft], unassigned[{file,reason}], unsupported[{file,reason}], warnings[Warning]` (read-only, §4 "Catalog drafts") |
| `catalog-install` | `entry, confirm?, expected_sha256?` | preview: `preview:true, valid, error\|null, id, file, current{sha256,entry\|null,owner}\|null, expected_sha256, new_sha256, changes[Change], diff[str], compat[str], warnings[str], backups, history[str]`; confirmed: `installed:true, id, file, sha256, previous{sha256,backup}\|null, changes, compat, warnings, backups` (§4 "Installing and removing entries") |
| `catalog-remove` | `id, confirm?, expected_sha256?` | preview: `preview:true, id, file, current, expected_sha256, backups, warnings[str], history[str], diff[str]` (`not-found` when not installed); confirmed: `removed:true, id, sha256, backup, backups` |
| `retention-plan` | `{}` or `{policy}` | `policy, saved_policy, proposed(bool), policy_problem\|null, usage{apps[AppUsage],unassigned{backups,bytes},total{backups,bytes}}, candidates[BackupBrief], blocked[BackupBrief], protected[BackupBrief], freed_bytes` (read-only, §8) |
| `retention-apply` | `confirm:true, backup_ids[], policy?` | `policy, policy_problem\|null, deleted[BackupBrief], skipped[{id,reason}], freed_bytes` (§8) |
| `schedule-get` | – | `schedule Schedule, next_runs[Instant]` (the next 3 slots; `[]` while off or stopped by a problem), `timer Timer, last_run LastRun\|null, waiting Waiting\|null, attention Attention\|null, events[ScheduleEvent]` (≤ 50, newest first), `timezone{name,utc_offset}, gate Gate` (2026.11.17.1, §8) |
| `schedule-set` | `schedule{enabled,days,time,apps,include_images,keep_last}, confirm?` | `saved(bool), schedule Schedule` (as saved, or as it would be saved), `next_runs[Instant], retention{keep_last, apps[], delete[BackupBrief], blocked[BackupBrief], freed_bytes}, timezone{name,utc_offset}` — without `confirm` (or `false`) a preview that writes nothing: `retention.delete` lists the scheduled backups the **next successful run** of `retention.apps` would delete (its new backup counted as the newest), `blocked` those that are protected; with `confirm: true` the settings are saved (root 0644) and journaled (`schedule-set …`, §8). Saving never deletes anything |
| `schedule-run-now` | `request_id` | `job_id, deduplicated` — one scheduled run now with the saved settings, enabled or not (like Home Assistant's "create automatic backup"); not kit-gated (like `backup-start`); it counts as a scheduled backup and the schedule's keep-last rule runs after it |
| `schedule-tick` (internal) | argv only | `decision` (`idle`, `settle`, `missed`, `started`, `busy`, `no-key`, `no-apps`, `start-failed`, `settings-problem`, `state-problem`, `tick-running`), `slot?`, `trigger?`, `job_id?`, `deduplicated?` (run by `woowtech-cockpit-backup-schedule.service`; never reads stdin; any argument is `invalid-request`) |
| `job-status` | `job_id` | `job Job, log[str]` (≤ 200 lines, secrets never logged; each entry is one written line of ≤ 500 characters: every C0/C1 control character, U+2028/U+2029 and every Unicode bidirectional control (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) becomes a space when it is written, and the log is split on `\n` only, so text a backup chose, such as its name or an HA `PG_VERSION`, can neither start a line of its own nor reorder how its line reads — SR-6) |
| `jobs` | – | `jobs[Job]` (≤ 50, newest first, no log), `schedule_events[ScheduleEvent]` (≤ 50, newest first, `[]` when the schedule's state cannot be read; 2026.11.17.1) |
| `job-cancel` | `job_id` | `state` |
| `delete` | `backup_id` | – (`busy` with `details.job_id` while a queued/running job uses it as source or as its `safety_backup_id`, or for any `safety` backup while a restore runs; checked under the start lock; journaled `backup-delete backup=… type=… encrypted=true\|false loginuid=…`, review L6) |
| `ha-delete` | `ha_backup_id, confirm:true` | – (deletes an uploaded HA backup; `busy` with `details.job_id` while a queued/running job's `params.ha_backup_id` names it, checked under the start lock; `not-found`; journaled `ha-backup-delete ha_backup=… loginuid=…`; branch feat/ha-import) |
| `ha-check-start` | `ha_backup_id, apps["odoo"\|"n8n"\|"omnigent"\|"hermes"\|"emqx"\|"headscale"], request_id, key?` | `job_id, deduplicated` — job type `verify`, `params {source:"ha", ha_backup_id, apps, key_provided}`; `key` is the HA key exactly as typed (never trimmed); refused before a job starts with `key-required` (a selected add-on member is encrypted and no key came) or `wrong-key` (it does not open it; v3 exact, v1/v2 heuristic), `invalid-request` (the backup has no such add-on), `not-found`; a key is kept only when something is encrypted; result `{ha_check: HaCheck}`; the job can also fail with `key-required`/`wrong-key`/`corrupt-archive` (branch feat/ha-import part B) |
| `ha-convert-start` | `ha_backup_id, apps, test_mode(bool), request_id, confirm:true, odoo_database?, key?` | `job_id, deduplicated` — job type `backup`, `params {source:"ha", ha_backup_id, apps, odoo_database (null without odoo), test_mode, encrypt (預設加密備份 when it started), key_provided}`; `odoo_database` required when `apps` has `odoo`; refused like `ha-check-start` and with `app-not-in-catalog` 「請先到「應用軟體」安裝同版本的 <app>，再匯入。」 or `no-device-key`; result `{backup_id, size, apps, encrypted, ha_import: HaImport}`; nothing on the device changes (part B) |
| `upload-begin` | `filename, size` | `upload_id, path, max_size` |
| `upload-finish` | `upload_id` | `backup BackupMeta` (idempotent: a retry after success returns the same backup; a failure after the move puts the file back) — or, for a Home Assistant backup (recognised before the Cockpit formats, §5 "Home Assistant backups"), `ha_backup HaBackupMeta`: checked strictly without a key, hashed and stored in `ha-backups/`, idempotent the same way, the same file uploaded again returns its record; a broken HA file is `corrupt-archive`/`unsupported-format`/`limit-exceeded` and stays in uploads/ for `upload-abort` (branch feat/ha-import) |
| `upload-abort` | `upload_id` | – |
| `download-info` | `backup_id` | `path, filename, size` (the stored file as created: `archives/<id>.tar` or `.woowbackup`; for an unencrypted backup journaled `download-unencrypted backup=… loginuid=…`, review L6) |
| `run-job` (internal) | argv: `run-job <job_id>` | – |

Shapes:

* `App`: `id, name, description, owner, adapter, deployed(bool), state("running"|"stopped"|"partial"|"not-deployed"|"error"), units[{name,active}], last_backup{id,created}|null, problems[str]` — `error` also when every unit is active but a quick health request fails, and while units are masked by an unfinished restore (both explained in `problems`). `last_backup`: the newest manual or pre-restore backup holding the app, never one converted from an HA backup (it holds HA's data, not this device's).
* `BackupMeta`: `id, type("manual"|"safety"|"uploaded"), created|null, note, apps[{id,name,size?}], size, sha256, key_id|null, key_available(bool), include_images(bool), filename, source{hostname}|null, verified{at,ok,deep?}|null, inspected(bool), uploaded_at?, format(1|2), encrypted(bool), unauthenticated(bool), scheduled(bool)` — `key_id` null and `key_available` true when not encrypted; `apps[].size` the bytes of the app's archive in a format 2 file (backups made here; uploads after `inspect`); `verified.deep` true when the verify job checked the content like a restore; `unauthenticated` = not encrypted and `type` `uploaded` (also adopted files); `scheduled` (2026.11.17.1) = `type` `manual` and listed in the schedule's registry (排程備份; derived, never stored in the index; false while the registry cannot be read). Sidecars written before format 2 have no `format`/`encrypted` (format 1, encrypted). `from_ha` (HaImport; branch feat/ha-import part B): only on a `manual` backup that `ha-imports.json` lists as converted from an HA backup (absent otherwise, and while that file cannot be read); it keeps the HA backup's name and date after the HA file was deleted.
* `HaBackupMeta` (branch feat/ha-import): the stored record `id` (`ha-` + sha256[:20]), `ha_slug, name, date` (UTC
  `…Z`), `type("full"|"partial"), supervisor_version, protected(bool)` (what backup.json says), `compressed(bool),
  addons[{slug, name, version, encrypted(bool)}]` (`encrypted`: from the member's first bytes), `folders[str], size,
  sha256, uploaded_at, filename` (display only: the uploaded name when it is a plain file name, else
  `ha-backup-<YYYYMMDD-HHMMSS>.tar`), plus the derived `importable_apps[{slug, app_id("odoo"|"n8n"|"omnigent"|"hermes"|"emqx"|"headscale"|"open-design"|"woow-code-server"|"litellm"), app_name,
  installed(bool)}]` (WOOWTECH add-ons this engine can import, §5; `installed`: this device's catalog has `app_id`;
  `app_name` from the catalog, else 「Odoo 18」/「n8n 工作流程」/「Omnigent 協作平台」/「Hermes 代理」/「EMQX MQTT 代理」/
  「Headscale VPN 控制伺服器」/「OpenDesign 設計工具」/「code-server 開發環境」/「LiteLLM 閘道」) and `other_addons[{slug, name, version}]` (add-ons without
  an app here: 「這台沒有對應的應用」; the page adds a to-do for the Cloudflare Tunnel and the MCP admin add-ons, §9
  "Batch 2: add-ons that are not moved").
* `HaCheck` (part B): `ha_backup_id, apps[{app_id, slug, name (the add-on's name), arch("amd64"|"aarch64"|"unknown"),
  version (the add-on's), target_version (Odoo: the target image's `18.0-YYYYMMDD`; n8n: its `n8n --version`), ok(bool),
  blockers[zh-TW], warnings[zh-TW], odoo?{databases[{name, ok, blockers[], warnings[], partners, users (internal,
  active), attachments, attachment_bytes, modules (installed), custom_modules[{name, version, from ("data/addons",
  "data/odoo/addons/18.0" or "share/odoo_addons")}], crons_active, mail_servers_active, size (bytes), filestore_files,
  filestore_bytes}]}, n8n?{owner_email|null, workflows, workflows_active, credentials, executions, users, projects,
  variables, data_tables, community_packages[{name, version}], workflows_to_fix[{name, active, reasons[]}]},
  omnigent?{omnigent_version (HA's, from the add-on version), alembic, users, admins, conversations, scheduled_tasks,
  scheduled_tasks_active, hosts, agents, files, public_sessions, artifact_files, artifact_bytes, override_files[],
  account_conflicts[]}, hermes?{hermes_version, target_release, files, bytes, dirs, symlinks, absolute_symlinks,
  hardlinks, databases, sessions, messages, schema_version|null, config_version|null, skills, cron_jobs, plugins[],
  env_keys (a count; names and values are never sent), ha_urls[("config.yaml：<host>"|".env：<host>")], media_refs,
  skipped[]}, emqx?{emqx_version, target_version, node_name, files, bytes, mqtt_users, acl_rules, dashboard_users,
  api_keys, banned, psk, retained_messages, default_dashboard_password(bool), anonymous(bool), hot_backup(bool: the
  backup was made while EMQX ran, or its state is unknown), plugins[], ha_hosts[]},
  headscale?{headscale_version, target_version, db_version, users, nodes, pre_auth_keys, api_keys (HA's, not moved),
  policies, prefixes{v4, v6} (HA's), server_url (HA's), target_server_url, dns_records},
  open-design?{open-design_version (HA's, from the add-on version), source_revision, target_version, target_revision
  (8 hex each), files, bytes, dirs, symlinks, hardlinks, skipped_symlinks, projects, conversations, messages,
  routines, routines_active, project_folders, mcp_servers (HA's that move), mcp_integration_entries (HA's `woow-paseo`,
  not moved), shared, ha_urls[("<file>：<host>")], left_out{<top-level
  name>: entries}},
  woow-code-server?{woow-code-server_version (HA's code-server, from the add-on version), pins{code-server, pi, claude,
  codex} (HA's, '' when the add-on ships none), target_pins{same keys} (what the live image prints), files, bytes,
  sessions, claude_projects, codex_sessions, skills, snippets, settings(bool), extensions (HA's own, without the
  connector VSIX), mcp_servers, workspace(bool: `projects/` found in HA's share folder), share(bool), workspace_files,
  workspace_bytes, skipped_symlinks, ha_urls[("<file>：<host>")], left_out{<area>:<label>: entries}, unknown[]},
  nextcloud?{nextcloud_version (HA's config.php `version`), addon_nextcloud_version|null, users, files (file cache rows),
  shares, tokens, calendar_objects, contacts, datadir (HA's `datadirectory`), datadir_in_backup(bool), datadir_files,
  datadir_bytes, custom_apps[], pg_version, office(bool: richdocuments enabled on HA), ha_url, target_url},
  litellm?{litellm_version (HA's, from the add-on version), migrations (finished Prisma migrations), pg_major (HA's,
  18), target_pg_major, users, teams, keys (virtual keys without the UI's session keys), models, credentials,
  organizations, spend_logs, chatgpt_accounts, salt_moves(true), key_users[names of this device's other catalog apps
  whose configuration uses LiteLLM today]}}]`
  (batch 2: `target_version` of OpenDesign is the live image's `OD_APP_VERSION`; batch 2: `target_version` of code-server is the live image's `code-server --version`; batch 2: `target_version` of Nextcloud is the live config.php `version`; batch 1: `target_version` is
  the live server's `/v1/info` version for Omnigent, the live image's Hermes base tag, the live image's version label
  for EMQX and Headscale) — an app
  is `ok` only without blockers (Odoo: and at least one database `ok`); a blocker is a plain sentence (unknown processor, app
  not installed or not deployed here, no owner account in HA's n8n, different versions, missing modules with the
  share-folder hint, missing Python packages or programs of custom modules, a custom module to copy with an ELF file for
  another processor, newer PostgreSQL, unsupported extensions,
  pending module operations, not enough space; batch 1: an add-on version the engine's table does not know, a different
  alembic revision, unexpected database objects, a missing Omnigent cookie key or artifact, a damaged SQLite file, a hard
  link to a file that does not move, programs for another processor in Hermes's data, EMQX's admin/public Dashboard
  account, an ambiguous EMQX node, different Headscale prefixes or a node outside them, Headscale migrations this release
  does not know, a missing Noise key).
* `HaImport` (part B; `result.ha_import` and `BackupMeta.from_ha`): `ha_backup_id, name, date, apps[app_id],
  odoo_database|null, test_mode(bool), workflows_to_fix[{name, active, reasons[]}], reminders[zh-TW],
  reminders_by_app{app_id: [zh-TW]}, notes[zh-TW], addons[{app_id, slug, name}]` (every text at most 500 characters,
  at most 20 lines per list). `notes`: ONE list describing the whole converted backup, what the import moves or changes,
  for the page to show BEFORE the restore (the users and passwords become HA's, the custom modules added, the website
  domains that change, n8n's login account, the community nodes; each line names its app). `reminders_by_app`: what to
  do AFTERWARDS, per app (log in
  with HA's Odoo / n8n account, check the community nodes); `reminders`: what to do afterwards that belongs to no app
  (none today). The page writes the rest itself: stop the HA add-on, log the MCP admin apps of Odoo and n8n in again,
  the test-import line, delete the HA backup file (it holds HA's passwords and tokens; the engine never sends that
  line). For the batch 1 apps (`haapps.Importer.engine_mcp_lines`) the engine adds the MCP lines to
  `reminders_by_app` itself: 「請到「<this device's MCP admin app>」確認或重新設定 <app> 的連線資料…」 when the catalog has
  `hermes-mcp-admin` / `emqx-mcp-admin` / `headscale-mcp-admin` (Omnigent has none), and 「如果 HA 上有「Woow <X> MCP
  Server」，請把它停掉，並把指向它的 MCP 連接器（例如 claude.ai）刪掉，改用這台的 MCP 網址重新建立。」; the MCP admin apps'
  state is never imported. Test mode pauses Omnigent's active scheduled tasks; it changes nothing of Hermes, EMQX or
  Headscale.
* `Settings`: `encrypt_by_default(bool), problem(zh-TW)|null, plaintext_warning(zh-TW)` — the text the page shows for every acknowledgement of an unencrypted backup or copy: database passwords, API keys and tokens are stored and downloaded in plain text.
* `ManifestSummary`: `backup_id, created, type, note, tool, source, consistency, total_size, format(1|2), encryption("age-x25519"|"none"), apps[{id,name,adapter,owner{name,uid},images[{ref,included}],postgres[{id,database,major,scope("database"|"instance"),databases?[{name,owner}],roles_count?}],volumes[{name}],data_dirs[{path,size,label}],secrets_count,config_files_count,settings_included(bool),verify_snapshot,verify_digests[{id,type,target,summary}],archive_size?}]` (`databases`/`roles_count` only for scope `instance`; `archive_size` the app's member in a format 2 file)
* `Preflight`: `ok(bool), checks[Check], apps[{id,name,restorable(bool),mode("inplace"|"fresh"),checks[Check],settings?{state("missing"|"unloadable"|"different"|"same"),entry}}]` (`settings`: only when the backup carries the app's settings, §5: `missing` where this device has none for the app and `unloadable` where its settings file could not be loaded (the app is not restorable until settings are installed; the check says what else is needed, e.g. the owner account, and never promises the restore), `different` where its settings differ, `entry` the carried settings for `catalog-install`; `settings_included` in `ManifestSummary` says the same for the backup's contents)
* `Check`: `id, status("ok"|"warn"|"fail"), message(zh-TW)`
* `Owner`: `name, uid, linger(bool), catalog_apps[str]` (lingering accounts and owners of loaded entries; never root).
* `Draft`: `id, containers[{file,unit,container,image,state}], databases[DatabaseView], entry, valid, problem|null,
  field|null, variant("cold"|"instance"|"database"), variants[{id,label,entry,valid,problem,field}] (only with PostgreSQL),
  installed{id,sha256,entry,changes[Change],drift[str],same}|null, warnings[Warning], notes[Warning], skipped[{kind,
  name|path,reason}], hints[str]`.
* `DatabaseView`: `unit, container, kind("postgres"|"cache"|"other"), image`, and for PostgreSQL `major|null, database,
  user, guessed, data{volume}|{dir}|null`.
* `Warning`: `code, level("warn"|"info"), message(zh-TW), file?, path?`. Codes: `dir-missing, dir-blocked, too-many-files,
  podman-list, installed-problem, dropin, subdir, file-name, symlink, file-unread, cross-app-link, stat-failed,
  netns-unknown, missing-file, shared-file, aux-by-name, installed-id, installed-split, id-taken, environment-secret,
  image-ref, image-missing, not-running, service-name, env-file-unresolved, too-many, volume-missing, secret-missing,
  podman-socket, bind-home, bind-missing, bind-symlink, bind-blocked, bind-forbidden, bind-sensitive,
  bind-path-unsupported, config-mode, env-file-missing, config-in-dir, dir-nested, dir-read-only, db-data-unknown, db-dir,
  db-tag, db-guessed, db-depends-on-writer, db-other, cache, installed-mode, no-digests, dependency-cycle`.
* `Change`: `path` (`volumes[name=x].label`, `units`, `secrets[name=y]`, `a[]` for scalar list items), `op("add"|"remove"|
  "change"|"order")`, `old?`, `new?`.
* `AppUsage`: `id, name, in_catalog, backups, types{manual,safety,uploaded,scheduled,converted}, bytes, estimated, shared,
  newest|null, oldest|null, keep_last|null` (a backup of several apps is split by the per-app archive sizes the index
  records, else evenly: `estimated`; catalog apps without backups are included; `types.manual` counts the manual backups
  that are neither scheduled nor converted from an HA backup, `types.scheduled` the scheduled ones, `types.converted`
  those `ha-imports.json` lists; `keep_last` is the manual policy's and never counts scheduled or converted ones).
* `BackupBrief`: `id, type, created, size, note, apps[{id,name}], scheduled?(bool), reason?` (`scheduled` in the
  retention and schedule commands' lists).
* `Schedule` (2026.11.17.1): `enabled(bool), days[str]` (unique of `mon tue wed thu fri sat sun`, 1–7, week order; all 7
  = every day), `time` (`HH:MM`, 00:00–23:55 in 5-minute steps, device time), `apps("all"|[id])` (`"all"`: every app of the
  catalog at run time, later ones included; a list: 1–100 ids, each in the catalog when saved), `include_images(bool),
  keep_last(1..1000|null)` (null keeps every scheduled backup), `updated|null, armed_at|null` (when it was turned on or
  its time or days changed: earlier slots never run), `saved(bool)` (a file exists), `problem(zh-TW)|null` (a settings
  file the engine does not use, or a state file it cannot read; worded for the device's owner without file names, e.g.
  「排程備份的設定檔內容不正確，排程備份已暫停。請重新儲存排程設定。」, 「排程備份的紀錄檔無法讀取，排程備份已暫停；…請通知工程人員
  檢查。」), `defaults(bool)` (`schedule-get` only, false in `schedule-set` replies: the fields are the defaults, not a
  saved file's — nothing was saved, or the saved file cannot be used; the page then says so and asks to save again).
* `Instant`: `at` (UTC `…Z`), `local` (`YYYY-MM-DDTHH:MM` in the device's zone), `utc_offset` (`+08:00`).
* `Timer`: `enabled(bool|null), active(bool|null)` (of `woowtech-cockpit-backup-schedule.timer`, `systemctl show`; null
  when systemd cannot be asked), `active_age(int seconds|null)` (since the timer last became active, from its
  `ActiveEnterTimestampMonotonic`; null while it is not active or systemd cannot be asked), `last_tick_age(int
  seconds|null)` (age of `/run/woowtech-backup/schedule-tick`; null before the first tick of this boot).
* `LastRun`: `slot|null` (null: `schedule-run-now`), `local|null, job_id, trigger("on-time"|"late"|"catch-up"|"run-now"),
  state` (the job's state, null when its record is gone), `result("queued"|"running"|"succeeded"|"partial"|"failed"|
  "interrupted"|"cancelled"|"unknown")` (live from the job record; `unknown`: its record is gone or cannot be read),
  `backup_id|null, started, started_local, finished|null, finished_local|null, skipped_apps[{id,name,reason}],
  error{code,message}|null`. Every `local`/`*_local` here and in `Waiting` and `ScheduleEvent` is that instant in the
  device's zone as `YYYY-MM-DDTHH:MM` (like `Instant.local`): the page shows the schedule's times in device time, whatever
  the browser's zone.
* `Waiting`: `slot, local, since, job_id|null` (a due slot waiting for another job, `job_id` the job it waits for).
* `ScheduleEvent`: `at, kind, slot|null, local|null, first|null, first_local|null, count, job_id|null, message(zh-TW),
  not_run(bool)` (`local`/`first_local`: `slot`/`first` in device time, null without them); kinds: `waiting`
  (a slot waits for another job), `missed` (no tick saw the slot in time and it was not caught up; `first`/`count` cover
  several), `skipped` (the slot waited for another job until the next slot came), `no-key` (預設加密備份 on, no device
  key), `no-apps` (nothing to back up), `settings-problem` (slot null; once per problem), `failed` (the run failed or was
  interrupted, with `job_id`; without `job_id` the job could not be launched), `partial` (with `job_id`), `cancelled`.
  `not_run` (shown as 未執行): `missed`, `skipped`, `no-key`, `no-apps` and `failed` without a job.
* `Gate`: `encrypt(bool)` (預設加密備份 now), `device_key(bool), kit_confirmed(bool), blocked(null|"no-device-key"|
  "kit-unconfirmed")` — what turning the schedule on needs.
* `Attention`: `code, message(zh-TW)`, plus `slot?`, `job_id?`, `reason?` (`skipped`: `busy`|`no-key`|`no-apps`;
  `missed`: `missed`). One item, the first that applies: `settings-problem` (the settings or state file is bad: the
  problem text, which says the schedule is paused) → `timer-inactive` (enabled, and systemd says the timer is not active,
  or for 15 minutes neither a tick nor the timer becoming active (`min(last_tick_age, active_age)` > 15 minutes: a
  timer just enabled or restarted waits for its first tick; PID 1's age stands in when systemd cannot say and there was
  no tick): 「排程檢查沒有在執行，排程備份不會自動開始。請重新執行備份元件的安裝程式來啟用它。」) → `overdue` (enabled, a slot ≥ 30 minutes old is neither handled nor waiting: 「排程備份已逾期：
  <local> 的排程備份還沒有開始。」) → the newest outcome: a slot that did not run (`missed`: 「<local> 的排程備份沒有執行：
  設備當時沒有開機，或排程檢查沒有在執行。」, several: 「<first> 到 <last> 共 N 次的排程備份沒有執行：…」; `skipped` busy:
  「<local> 的排程備份沒有執行：當時有其他作業一直在進行。」, no-key: 「…沒有執行：預設加密備份已開啟，但這台設備還沒有加密金鑰。」,
  no-apps: 「…沒有執行：沒有可以備份的應用。」; a job that could not be launched: `failed`, 「上次排程備份失敗：<local> 的排程備份
  沒有開始：…」) or the last run (`failed` for failed/interrupted: 「上次排程備份失敗：<job error message>」, and for `unknown`,
  its job record gone (or unreadable): 「上次排程備份失敗：作業紀錄已不存在。」; `partial`: 「部分完成：上次排程備份沒有包含「A」、
  「B」。請查看作業結果了解原因。」; a success or a cancelled run: none). Only `settings-problem` is reported while the
  schedule is off.
* `ScheduleSummary` (`status.schedule`): `enabled` (false also while a problem stops it), `saved, problem|null, days, time,
  apps, include_images, keep_last, next_run Instant|null, last_run LastRun|null, waiting Waiting|null, attention
  Attention|null, timezone{name,utc_offset}, timer Timer`.
* `Job`: `id, type("backup"|"restore"|"verify"|"export"), state("queued"|"running"|"succeeded"|"failed"|"rolled-back"|"interrupted"|"cancelled"), phase, phases[{id,label,state("pending"|"active"|"done"|"failed"|"skipped")}], progress{percent,message}, created, started|null, finished|null, params, result|null, error{code,message}|null, cancellable(bool)`
* Job `params` of a scheduled backup (2026.11.17.1): a manual backup's `apps[], include_images, note` (`排程備份`),
  `encrypt` (預設加密備份 when it started), plus `schedule{slot|null, trigger, keep_last|null}`; 2026.11.15.2 reads such
  records (it checks no params) and lists them as backup jobs.
* Job `result`: backup → `backup_id, size, apps[], downtime_seconds, unavailable_seconds|null, timing[Timing], encrypted(bool), retention_deleted[str]` (`retention_deleted`: older manual backups the saved keep-last policy deleted after this manual backup, §8); a scheduled backup adds `scheduled(true), slot|null, trigger, partial(bool), skipped_apps[{id,name,reason}]` (apps left out: not in the catalog, not deployed, reporting problems, or not backed up in their current state, e.g. stopped with a database to dump: `Adapter.unavailable`) and its `retention_deleted` are older scheduled backups the schedule's keep-last deleted (a partial run is `succeeded` with `partial: true`; no new job state); export → `export_id, backup_id, filename, size, expires`; restore → `apps[], safety_backup_id|null, health[Check], verification[{app,match,before,after,checks?[DigestCheck]}], rolled_back(bool), changed(bool), fresh_apps[str], safety_skipped(bool), safety_failed(bool), safety_pending(bool), safety_in_downtime(bool), safety_pending_failed{path,message}?, warnings[str], timing[Timing]` (`safety_pending`: the pre-restore copy is kept in `pending/<job>/` and not packaged (yet); `safety_in_downtime`: it was packaged while the apps were stopped, the free space being too short for packaging next to the running apps (§9); `safety_pending_failed`: the recovery could not package it either, it stays at `path` for manual work); verify → `ok, entries, bytes, deep(true), format, encrypted, apps[{id,name,checked{volumes,dirs,images,digests,globals,dumps,secrets},header_only[str]}], notes[str]` (`checked`: entries that passed a restore's content check; `header_only` (2026-11-14, review L8): the kinds checked only by their format header -- `dumps`: a dump is recognized by its pg_dump header, its body was read in full by `pg_restore` when this device made the backup and is read again by a restore, so an uploaded backup's dump bodies are first read at restore; `notes`: what a restore would drop, e.g. setuid bits). A local read error while checking (EIO, EMFILE, ENOSPC on the scratch copy) fails the job with `internal-error` and records no `verified`; only defects of the content record `verified.ok: false` (review F10).
  `Timing`: `{app, writer_pause_seconds|null, unavailable_seconds|null}` (one decimal): writers (restore: units) stopped →
  every unit running again, and first stop → every health check of the app passed; null when not measured (nothing was
  stopped, a health check failed). The first stop of an in-place restore is the pre-restore copy's writer stop (§9); its
  packaging into the safety backup runs after the health checks and is not part of these figures.
  `downtime_seconds` stays the backup's total writer pause (whole seconds), `unavailable_seconds` the sum of the apps'.
  `DigestCheck`: `{id, type("postgres-digest"|"files-digest"), target, label, match(true|false|null), before{summary}|null,
  after{summary}|null, differences{missing,extra,changed,samples[{item,change("missing"|"extra"|"changed"),detail}]}|null,
  note|null}` — `summary` as in §5, at most 20 `samples` (item and detail ≤ 300 characters, zh-TW detail), `note` says why
  a check was not compared (`match` null: no digest in the backup -- also when the backup left an unstable one out, §9 --,
  the check's definition changed, a digest read on PostgreSQL ≤ 11 meets one read on ≥ 12, or the restored data was still
  changing while it was read twice). For a digest check
  `before`/`after` of the verification entry also hold `{<check id>: summary}`, so a table of compared values shows the
  counts; `match` of the entry is false when any check differs, true when one matched and none differs. A restore whose
  digests differ stops **before the app's units start** and rolls back; its result still lists the checks.
  `changed`: a destructive step started (false → nothing on the device changed); `fresh_apps`: apps deployed from templates
  (of an `interrupted` restore: the deployments that had not finished their data import); `warnings`: zh-TW notes about
  what the restore could not keep (setuid/setgid bits and non-`user.*` extended attributes such as file capabilities
  dropped from a volume, an instance whose databases could not be listed), ≤ 50, also in the job log;
  `safety_skipped`: in-place apps were restored without a new safety backup (the source is a safety backup, or
  `allow_no_safety`); `safety_failed`: refused because no safety backup could be made. A failed restore always carries
  its result. `verification[].before/after` hold only the catalog's `compare` keys, each value ≤ 2 KiB of JSON.

Host-directory preflight checks (ids under `<app>/`): `dir-target` (a symlink on the path, a mount point, an overlap
with the Podman storage, or the state in place/fresh), `dir-conflict` (fresh: a non-empty directory exists),
`dir-mounts` (mount points below it), `dir-in-use` (a running container of another unit, or one started by hand,
bind-mounts it, read-only included: after the swap it would keep using the replaced copy), `dir-leftover` (siblings
of earlier restores, warn), `dir-archive`/`dir-ids`/`dir-attributes` (the archived tar and the owner's ID range), and
`space`: twice what the archive holds for the app on the home's filesystem (the extracted archive and the restored
data; the replaced copy stays until the job succeeded and moves back after a failure, so no third copy is counted),
a directory on another filesystem counting there with the free space the helper read.

Instance-mode and digest preflight checks (ids under `<app>/`): `postgres-scope` (fail: the archive's scope differs from
the catalog's), `instance` (ok: databases and roles that come back), `roles` (fail: the archive's version of the catalog
user is not a superuser that can log in), `bootstrap` (fail: the archive's `bootstrap_user` is not the catalog user),
`bootstrap-current` (fail, in place: the running instance's bootstrap superuser is not the catalog user; review F5),
`extensions` (fail: the image lacks an extension the databases use — in place read from the running instance; fresh:
warn, checked once the new cluster runs), `databases-closed` (fail, in place: databases that accept no connections are in
neither this backup nor the safety backup and would be lost for good; review F1), `databases` (warn: databases that
exist now but not in the backup are removed; the safety backup keeps them), `template1` (warn: user objects in the
running instance's template1, which a restore does not keep), `instance-current` (warn: the running instance could not
be read), `digests` (ok: checks the restore compares), `digests-missing` (warn: checks without a digest in the backup or
with a changed definition).

App check `owner-changed` (warn, 2026-11-14, review M3): the archive's app came from another account (`owner.name` of the
backup is not the catalog owner); its data, secrets and config files will belong to this device's account. App check
`rollback-unverified` (warn, in place, review F16): the app has http-json checks but no digest, so a rollback after a failed
restore is checked by the health checks only (§9 "Hand-over from the safety backup").

Preflight check `unauthenticated` (warn, top level): an unencrypted upload whose origin and integrity cannot be verified.
The app check `device-key` (fail: an in-place restore needs the device key for its safety backup) applies only while the
setting 預設加密備份 is on: safety backups follow it.

Phases — backup: `prepare 準備`, `check 檢查空間與應用`, `stop 暫停應用寫入`, `dump 匯出資料庫`,
`export 匯出資料卷與設定`, `start 恢復應用`, `package 加密封裝` (`封裝（未加密）` for a backup made with `encrypt`
false), `verify 驗證備份`.
Restore: `prepare 準備`, `decrypt 解密並驗證檔案`, `preflight 相容性檢查`, `stage 預先寫入主機資料夾` (skipped without
host directories), `safety 保存還原前資料`, `stop 停止應用`, `restore 還原資料`, `start 啟動應用`, `check 健康與資料核對`,
`safety-package 封裝還原前備份` (skipped without a pre-restore copy; `done` already during `safety` when the copy was
packaged in the downtime, and kept `done` while the restore's phases and a rollback run; `failed` while the job still
succeeds when the copy could not be packaged, `done` again once a recovery pass packaged it; never counted as a
destructive phase for `changed`), and `rollback 自動回復` appended on failure (the
copy is packaged inside it). Verify: `prepare`, `decrypt` (decrypt and check every entry, deep), `check`.
Export: `prepare 準備`, `decrypt 解密並驗證檔案`, `package 封裝未加密副本`, `verify 驗證副本`. Digests are taken inside `dump`
(PostgreSQL) and `export` (files) and compared inside `restore` (files) and `start` (PostgreSQL, before other units).

Error codes: `invalid-request, not-found, busy, key-required, wrong-key, no-device-key,
not-a-backup, unsupported-format, corrupt-archive, invalid-manifest, limit-exceeded,
insufficient-space, incompatible, app-not-in-catalog, owner-missing, not-deployed,
permission-denied, not-cancellable, job-failed, internal-error`.

Requests of the catalog and retention commands (strict like every command, unknown keys rejected): `owner`
`^[a-z_][a-z0-9_-]{0,31}$` and not `root`; `entry` a JSON object (deep validation is the catalog validator's); `id`
`^[a-z0-9][a-z0-9-]{1,40}$`; `confirm` boolean (`retention-apply`: must be `true`); `expected_sha256` `^[0-9a-f]{64}$` or
null, required (may be null) when `confirm` is true (`invalid-request` with `details.field`); `policy` a JSON object (deep
validation `retention.validate_policy`); `backup_ids` an array of at most 500 unique backup ids. Errors: `invalid-request`
(with `details.field`, `details.conflicts`, `details.reason`), `owner-missing`, `limit-exceeded`, `busy`, `not-found`,
`permission-denied`, `internal-error`, `job-failed` (the owner-side scan answer). A confirmed `catalog-install`/
`catalog-remove` and both retention commands run the recovery first (dead jobs are marked interrupted and their
leftovers settled), like `delete`.

Requests and errors of the schedule commands (2026.11.17.1, strict like every command): `schedule` a JSON object with
exactly `enabled` (bool), `days`, `time`, `apps`, `include_images` (bool), `keep_last` (rules in `Schedule`; `updated`
and `armed_at` are the engine's and refused); `confirm` boolean; `request_id` as for `backup-start`. `schedule-set`:
`invalid-request` with `details.field` (`schedule` or `schedule.<field>`), or with `details.reason: "kit-unconfirmed"`
and `field: "schedule.enabled"` (「開啟排程備份前，請先保存緊急金鑰。」) when it would be on while 預設加密備份 is on and the
emergency kit is not confirmed; `no-device-key` when it would be on while 預設加密備份 is on and the device has no key;
`app-not-in-catalog` / `owner-missing` (`details.app`) for a listed app the catalog does not load; `permission-denied` /
`limit-exceeded` when the existing `schedule.json` is not root's, a symlink or too large (saving); turning it off is never
gated. `schedule-run-now`: `invalid-request` with `details.reason` `not-saved` (no settings saved yet),
`settings-problem` (the message is the file's problem), `state-problem` or `no-apps`; `no-device-key` (預設加密備份 on,
no key); `busy` (`details.job_id`). `schedule-get` and `schedule-tick` take no input.

## 8. Job execution

* `*-start` validates, deduplicates by `request_id` (24 h), refuses with `busy` while another job is
  queued/running, writes the job record, then launches
  `systemd-run --unit=woowtech-backup-<job_id>.service --collect --quiet --property=KillMode=mixed
  --property=MemoryMax=50% --property=TasksMax=512 /usr/local/libexec/woowtech-cockpit-backup run-job <job_id>`
  and returns immediately.
* Every helper command turns SIGTERM/SIGHUP/SIGINT into an exception, so `finally` blocks run (a pasted key in
  `/run/woowtech-backup` is always deleted when cockpit-bridge closes the channel). Captured output of owner commands
  is capped (default 16 MiB + 64 KiB, 1 MiB for psql/pg_isready/systemctl, secrets 512 000 + 1 bytes, stderr keeps
  its last 64 KiB); file outputs (pg_dump, volume export, podman save) are copied through the helper with a budget of
  free space − 512 MiB, and the child is killed when it is exceeded.
* Job logs, progress messages and error messages pass `jobs.redact`: age secret keys, anything shaped like a Home
  Assistant backup key (`[A-Z0-9]{4}(-[A-Z0-9]{4}){6}`) and the exact key a running job registered with
  `jobs.mask_secret` (an older HA backup may use any password) are masked as 「[已遮蔽]」; `job-status` masks the patterns
  again when it reads a log (branch feat/ha-import).
* `run-job` takes an exclusive `flock` on `/run/woowtech-backup/engine.lock` for its lifetime and
  updates the record atomically (write temp + rename) at every phase/progress change; it writes its final
  state before it releases the lock.
* Locks, always in this order: start lock (`jobs.lock`; held by the commands that decide: `*-start`, recovery,
  `job-cancel`, `delete`) → engine lock → record lock (`jobs/<job>.lock`). Every write of an existing record
  happens under its record lock, and every decision that depends on a record (queued → running, a failed launch,
  `job-cancel`, leaving the cancellable window, recovery, retention) re-reads it under that lock. Readers
  (`status`, `jobs`, `job-status`) take no lock.
* A record in `queued|running` whose unit is not active and whose lock is free is marked
  `interrupted` by `recover_interrupted()` (called by `status`, `jobs`, `job-status`, `delete` and `*-start`).
  Recovery decides only while it holds the start lock and, taken without waiting, the engine lock (no job can be
  running or finishing meanwhile; while a job holds it nothing is decided and no unit is probed), and from a fresh
  read of the record under its record lock taken after the unit probe — never from the listing that picked the
  candidate, so a job that finished meanwhile keeps its own final record. Recovery also, for dead and for finished
  records, restarts writers still listed in `stopped_writers` and removes an unfinished fresh deployment listed in
  `fresh_apps` (recorded before the first fresh step; each app leaves it right after its data import finished, before
  its units are unmasked, and a rollback lists it again before it removes it), each once and taken from that fresh read.
  Recovery never removes a deployment whose non-database units are unmasked or running (for an app without such units:
  any running unit), or whose unit state cannot be read: it may already hold new data, so it is kept and reported as
  `需人工確認`. What it removes is the deployment (units, Quadlet files, volumes, secrets, config files); images the dead
  job loaded keep their names (the record does not list them; only an in-process rollback puts image names back), and a
  later fresh restore of the same backup loads them again. It deletes
  `key-<job>` files of jobs that are not running and `key-*` files older than 15 minutes. `run-job` indexes
  archives that a hard kill left in `archives/` without a sidecar (older than one hour) as type `uploaded`.
* Pre-restore copies (2026.11.14.2): a restore record with `safety_pending` (its own packaging failed, or the job died
  or was stopped by a shutdown after the copy was saved) has recovery work left: the recovery packages `pending/<job>/`
  into its safety backup once (`package_safety` → `flows.package_pending_safety`, from `pending.json`; entries outside
  the copy, symlinks or other files than regular ones are refused; an encrypted copy needs the device key). The id the
  copy's record chose is adopted when it is registered already (a packaging cut short before the record said so), and an
  archive of that id published but never registered is this job's own output and packaged again: never a second safety
  backup. The record gets `safety_backup_id` (also in the result, the phase `safety-package` back to `done`) and the
  guidance, and is saved, before the copy is deleted; a failure records `safety_pending_failed {path, message}` and keeps
  the copy for manual work. Either way `safety_pending` is then false, so it is tried once. Too little free space (the
  §9 need) is not a failure: nothing is written, the flag stays, `safety_pending_deferred` and one note say why (said
  once: later passes only update the field with the latest figures, so the record never grows; review 2026-11-14), and
  each later pass checks again; the dead job's staging is removed before the space is checked. A copy of an
  interrupted, failed or cancelled restore that never reached a destructive phase (and is not `finishing`) is not
  packaged but deleted, flag first: its data is unchanged where it came from, as after a failure there; such a record's
  message says so (`UNCHANGED_MESSAGE`, naming a safety backup made in the downtime, if any). The other leftovers of
  the record are saved before the packaging starts. It runs inside the helper call that holds the recovery's locks
  (status/jobs/job-status wait for it): about a minute for a large copy, acceptable for this rare path; termination
  signals are ignored meanwhile (a page timeout makes cockpit-bridge send SIGTERM) and its outcome is saved before they
  apply again. A restore whose copy is not packaged yet or could not be pins like a failed restore (its source backup
  is protected) until a later restore of its apps succeeded, and its record is kept as long as the copy exists. Each pass
  also sweeps `pending/`: the copy of a finished record that lists neither `safety_pending` nor `safety_pending_failed`
  is removed (a job that died while copying -- the flag is on disk before the first destructive step, so that data never
  changed -- or a copy already packaged); copies of running, flagged or unreadable/missing records are kept. An
  interrupted restore's result says `finishing` when the restore itself had finished and passed its checks (only its
  clean-up or packaging was cut short): the page does not offer to revert it.
* Retention (each recovery pass): records of queued/running jobs, records with `stopped_writers`/`fresh_apps`
  left or a pre-restore copy not packaged yet, and failed/interrupted (not rolled back) restores whose safety backup is still pinned (at least one of
  their apps has had no successful restore since) are always kept; of the other records only the newest 200 are kept, with their `.log`, `.lock`
  and `.cancel`. A `.log`/`.lock`/`.cancel` whose record is gone and temp files of interrupted writes are removed
  after one hour. A request id whose job was pruned starts a new job.
* If the launcher reports an error after `run-job` already took the job (e.g. `systemd-run` timed out after
  starting the unit), the job keeps running and `*-start` returns its `job_id`; otherwise it is marked `failed`
  and a late `run-job` refuses it.
* User-provided keys for a job are stored as `/run/woowtech-backup/key-<job_id>` (0600) and
  removed by `run-job` in `finally`; `save_key: true` imports the key permanently instead.
* Cancel is honoured only before any destructive step (backup: until `stop`; also during `package`
  and `verify` the partial archive is discarded and writers are already restarted;
  verify and export: always; restore: only before `safety`). `job-cancel` accepts a request only while the record says
  `cancellable` (else `not-cancellable`), and leaving the cancellable window is itself a checkpoint under the
  same record lock, so an accepted cancel is never followed by a destructive step.
* Index sidecars are written (register, update, delete) under `/run/woowtech-backup/index.lock`, and an update
  reads the sidecar under it: `inspect` and a verify job's result never overwrite each other. A sidecar that exists but
  cannot be read or validated is never replaced: orphan adoption and a re-upload of the same file leave it as it is.
* `stopped_writers {app: [units]}` lists every unit this job stopped that must run again should it die: the writers a
  backup stopped (until they run again); the writers a safety backup left stopped for the restore (until that restore
  masked the app's units, or started them again after a failure before its first destructive step); and every unit an
  in-place restore stops, from just before its stop until the non-database units are masked (nothing changed yet). The
  recovery (and `run-job` after a termination signal) starts the listed units of the app's catalog entry in groups as in
  §9; units that do not start stay listed. A rollback never lists units (they are stopped and masked already).
* Host directories: before the first copy is written the restore records `dir_apps`; a job that dies leaves siblings
  named after it, which the recovery settles once (`settle_dirs` → `recover_dirs` per app): deletions cut short
  (`-del-`) are finished; a missing directory gets a moved-aside copy back, the content before the restore
  (`-old-<job>`) before the failed restore's data (`-old-<job>-rollback`); new copies are removed; old copies of a
  directory that exists are kept and reported by what they hold, never deleted. Right before it deletes the replaced
  copies after success the job records `finishing`; a job that dies then is reported as a finished restore whose
  clean-up the recovery completes (no "restore the safety backup" guidance).
* `upload-finish` holds an exclusive `flock` on the upload's `.json` and, once it holds it, ignores SIGTERM/SIGHUP/SIGINT
  until its result is recorded (`.done`): a page timeout makes cockpit-bridge send SIGTERM, and the check must still
  finish. A second `upload-finish` of the same upload (the page's 「重新確認」) waits for that lock, then returns the
  recorded backup instead of hashing again. A format 2 upload is read once whole: the strict outer parse, each app
  member's sha256 against `backup.json` (`corrupt-archive` otherwise, nothing listed) and the file's sha256; the index
  records `format`, `encrypted` and `key_id` (null without encryption) from it, `apps` stay empty until `inspect` read the
  authenticated manifests.
* **Unencrypted download copies** (`export-start` → job type `export`, §5): the job reads the backup's authenticated
  manifests, then decrypts and fully verifies one app at a time into its staging (that app's plaintext is there only
  meanwhile), writes a format 2 copy with encryption `none` (`apps/<id>.tar.gz`), verifies the whole copy and moves it
  into `exports/<export_id>.tar` (root 0600, `exports/` 0700) with its record `<export_id>.json` (`export_id, backup_id,
  filename, size, sha256, created, expires`). At most two copies exist (the oldest goes first). A copy expires
  `EXPORT_TTL` = 15 minutes after it was made: `status`, `list`, every `export-*` command, every recovery pass (`jobs`,
  `job-status`, `delete`, `*-start`, …) and every `run-job` delete expired copies (and a copy without a record after an
  hour), and the job schedules a transient timer (`systemd-run --on-active=<TTL+5>s --collect
  --unit=woowtech-backup-export-clean-<export_id> … export-cleanup`) **before** it publishes the copy, so it also goes
  when no page asks and when the job dies right after publishing (review L1). A transient timer does not survive a
  reboot: a copy that expired meanwhile is deleted by the next helper command (opening the page, any job); no persistent
  timer is installed for it (the only system units the installer manages are the schedule's timer and service below). A download that already started keeps reading its open
  file. Space needed: the largest app's plaintext + the backup's plaintext (+1 %) + the larger reserve of a job that runs
  while the apps keep running: 5 % of the filesystem, at least 2 GiB and at most 10 GiB (never less than 512 MiB; review
  M4; the deep verify's scratch copies keep the same reserve). The job may be cancelled at any time (nothing on the
  device changes); a key given to `export-start` is a job key file like a restore's. Journal lines (syslog ident
  `woowtech-cockpit-backup`, authpriv, notice): `export-unencrypted-request backup=… job=… loginuid=…` (export-start),
  `export-unencrypted-created backup=… export=… size=… sha256=… job=…` (the job), `export-unencrypted-download export=…
  backup=… loginuid=…` (export-info), `export-unencrypted-deleted export=… reason=expired|request|evicted[ loginuid=…|
  job=…]` (every deletion: expiry wherever it is noticed, also inside `export-info`; a request; the oldest copy evicted
  by a new one; review F17), and `settings encrypt_by_default=… previous=… loginuid=…` (settings-set).

* **Retention of manual backups (清理備份) and storage per app** (`retention.py`, `retention-plan`/`retention-apply`, the
  backup job):
  * Policy (`retention.json`, schema 1): `{"schema": 1, "default_keep_last": null|N, "apps": {"<app id>": {"keep_last":
    null|N}}}`, N in 1..1000, at most 500 apps, unknown keys rejected. An app without its own value uses the default; null
    keeps every manual backup. A file that is not root-owned, is group/world-writable, a symlink or invalid is ignored
    (`policy_problem`, zh-TW) and nothing is deleted automatically.
  * Only `manual` backups are counted and deleted by the policy. `safety` backups keep their rule (§9: 3 newest per app after
    a successful restore); `uploaded` backups are only deleted when the administrator selects them.
  * A manual backup is a candidate only when it is outside the newest N manual backups of **every** app it holds (a backup of
    two apps stays while either app still needs it). A backup whose verification failed (`verified.ok: false`) does not
    count toward N and is a candidate itself (reason 驗證未通過…): the N kept are the newest backups that did not fail, so
    unrestorable backups never push out restorable ones (review M1).
  * Protected (never deleted by retention, reason in zh-TW): the source and the safety backup of a queued/running job; every
    safety backup while a restore is queued/running; the safety backup a failed or interrupted (not rolled back) restore
    still pins (`jobs.pinned_safety_records`) and that restore's source backup, until a later restore of its apps succeeded
    -- the source also when the restore had no safety backup but changed the apps (`allow_no_safety`, restoring a safety
    backup; such records are kept like other pinning records; review M2); everything while any job record cannot be read
    (a damaged record may be such a restore; review F11). Pruning of safety backups after a successful restore waits the
    same way.
  * `retention-plan` previews (with the saved or a proposed policy): usage per app, `candidates` (newest first, with the reason
    `超出保留份數：「n8n」第 7 新（保留最新 5 份）…`), `blocked` (candidates that are protected), all `protected` backups and
    `freed_bytes`. Read-only.
  * `retention-apply` (`confirm: true`): under the start lock, saves the policy when one is given, then deletes exactly the
    confirmed `backup_ids` that exist and are not protected at that moment (others are returned in `skipped` with the reason).
    Each deletion and the policy change are written to the journal: `retention-policy default=… apps=… loginuid=…`,
    `retention-delete backup=… type=… size=… apps=… loginuid=…`.
  * After a successful **manual** backup the job applies the saved policy to the backup's apps
    (`retention.enforce_after_backup`): candidates holding one of them are deleted (the new backup is excluded), each logged
    in the job log (`已依保留原則刪除較舊的手動備份 …`) and the journal (`… reason=policy`); a deletion problem is logged,
    never fails the backup; an unreadable policy deletes nothing (`警告：…`). Result field `retention_deleted[]`.
  * Usage per app (`retention.app_usage`): bytes of the backups of each app; a backup of several apps is split by the per-app
    sizes when the index records them (`apps[].size`, e.g. from the v2 `backup.json`), else evenly (`estimated: true`);
    catalog apps without backups are included; uploaded backups not inspected yet (`apps: []`) are `unassigned`.

* **Scheduled backups (排程備份, 2026.11.17.1; `schedule.py`, the timer, the backup job's scheduled mode):**
  * Trigger: the static `woowtech-cockpit-backup-schedule.timer` (`OnCalendar=*:0/5`, `AccuracySec=15s`, no `Persistent=`,
    `WantedBy=timers.target`) starts `woowtech-cockpit-backup-schedule.service` (`Type=oneshot`,
    `ExecStart=/usr/local/libexec/woowtech-cockpit-backup schedule-tick`, `ConditionPathExists=` that helper,
    `StandardInput=null`, `StandardOutput=null` (the JSON reply), `StandardError=journal` with `SyslogLevel=warning` (a
    traceback or a job that could not be launched is a warning; unset, stderr would follow stdout to /dev/null),
    `LogLevelMax=notice`, `TimeoutStartSec=15min`). Both live in `/usr/local/lib/systemd/system/`, outside the
    `woowtech-backup-*` job units; the timer only ticks: no unit config is generated, the helper never writes units or runs
    `daemon-reload`. Never run `systemd-analyze verify` against a live system or a lab device's runtime directories (a
    `--user` verify once replaced a running manager's private socket): the unit files are checked by parsing
    (`scripts/check_source.py`, unit tests) and with `systemctl show` in the lab.
  * Time: the engine unsets `TZ` and calls `tzset()`; slots are in the device's zone (`/etc/localtime`, read per tick, so a
    change applies at the next tick). A slot is a local date and `time` on a scheduled weekday as a UTC instant; a time a
    DST change skips is the moment the clock jumps past it (02:30 on a 02:00→03:00 day runs at 03:00), a repeated time
    runs at its first occurrence. Slots before `armed_at` never run. While `armed_at` lies above the clock (it went back
    after the schedule was armed) the slots start at a floor instead: the time of the first tick that saw it, kept in the
    state (`armed_floor`, lowered when the clock goes back further, never moved forward by later ticks, dropped once the
    clock is past `armed_at` or unused once the schedule is armed again); so the slots after it run and an unhandled
    one becomes `overdue`. A slot is handled once: run, recorded as missed/skipped/no-key/no-apps, or a launch failure.
  * Each tick: touches `/run/woowtech-backup/schedule-tick`; holds `schedule-tick.lock` (a second tick returns
    `tick-running`); when the last scheduled job is still recorded queued/running, runs the recovery first (it never judges
    a job that runs; a dead one becomes `interrupted`); records the last run's outcome once its job ended
    (`schedule-result`, events `failed`/`partial`/`cancelled`; ended as for the registry: a record that exists but cannot
    be read is unknown, so nothing is recorded and the next tick looks again — a newer run replaces it without an event —
    while a record that is gone is recorded `unknown`, a `failed` event 「…的作業紀錄已不存在。」); drops registry entries
    whose job ended (its record is readable and finished, or gone; an unreadable record keeps the entry) and whose backup
    is then gone (neither its index nor its archive exists; the job is read first, so a job that publishes and ends
    between the two reads keeps its entry); resets the handled slot when it lies more than a day ahead (the clock went
    back: everything up to now counts as handled, `schedule-clock` once) and puts the old one aside
    (`handled_before_reset`): once the clock is past it again (it came back, e.g. NTP after a lost RTC) it counts as
    handled, so the slots that ran are not reported missed; then decides (`schedule.decide`, pure: settings, state,
    clock, zone, uptime):
    * off → nothing (a waiting slot is dropped); a bad settings file → nothing, one `settings-problem` event per problem;
    * the latest due slot that is not handled: less than 15 minutes late → start (`on-time`); a slot that waits for
      another job → start as soon as no job is queued/running (`late`, any delay), and recorded `skipped` (busy) when the
      next slot arrives first; otherwise no tick saw it in time: when the next slot is less than 3 hours away it is
      recorded `missed`, else it is caught up once (`catch-up`); several missed slots → one run of the latest, the others
      one collapsed `missed` event (`first`, `count`);
    * no run starts before 10 minutes of uptime (`settle`: nothing recorded; the slot is judged again by the next tick).
      Uptime is the time since PID 1 started (`CLOCK_BOOTTIME` minus PID 1's start time, field 22 of `/proc/1/stat`):
      a restarted container without a time namespace counts from its own start, not from the host's boot; when the
      stat cannot be read or compared, `CLOCK_BOOTTIME`.
  * Starting: apps = the catalog's apps for `"all"`, else the saved list; none of them in the catalog → `no-apps` event;
    預設加密備份 on and no device key → `no-key` event (no job, no retry). Otherwise `start_job('backup', params,
    "schedule-<slot as YYYYMMDDTHHMMSSZ>")` — the request id makes two ticks of one slot start one job (dedup 24 h, and the
    handled slot after that); `busy` → the slot waits (`pending`, one `waiting` event and `schedule-wait`); another error
    → a `failed` event without job (no retry). The state is written outside the start (the state lock is a leaf lock: it is
    never held while another lock is taken).
  * The job (`flows.run_scheduled_backup`): resolves the apps (missing ones are skipped with the catalog's problem or
    「此設備沒有設定應用 <id>。」), checks the device key when encrypting, chooses the backup id and writes its registry entry
    `{job, slot, trigger}` **before any app is probed or paused** (if that write fails the job fails with 「無法寫入排程備份
    紀錄，沒有暫停任何應用。」), checks the space before any pause (as every backup), skips apps that are not deployed,
    report problems or cannot be backed up as they are (`Adapter.unavailable`: a stopped app whose database must be
    dumped; a manual backup of it still fails) (`partial`; none left → `job-failed`), packages with the note 排程備份 and
    type `manual`, then applies the schedule's keep-last rule. Encryption follows 預設加密備份 when the run started.
    Cancelling and interruption work as for a manual backup; an interrupted run is shown as 已中斷 and is not retried (the
    next slot runs as usual).
  * Registry and pools: a backup is scheduled only when its index type is `manual` and its id is in the registry. The
    manual keep-last policy (`retention.json`) never counts or deletes a scheduled backup; the schedule's rule keeps the
    newest `keep_last` scheduled backups per app (`retention.plan` on the scheduled pool: a backup goes only when it is
    outside the newest N of every app it holds, a backup that failed verification does not count, every protection of the
    manual policy applies, the new backup is excluded) and runs only after a successful or partial scheduled run, for the
    apps it holds; `keep_last` null keeps all. Journal: `retention-delete backup=<id> type=manual size=<n> apps=<a,b>
    reason=schedule`. Safety and uploaded backups are untouched; an explicit `retention-apply`/`delete` may delete a
    scheduled backup. While `schedule-state.json` cannot be read the schedule stops (`state-problem`, journaled once a
    boot), every manual backup is protected (`retention-plan` lists them as blocked, both rules delete nothing) and the file
    is never overwritten.
  * Compatibility: the archive and index formats are unchanged (frozen lists in `tests/backup/test_schedule.py`), so
    2026.11.15.2 lists, inspects and restores a scheduled backup as a manual one (note 排程備份). Downloaded and uploaded
    elsewhere it is `uploaded` and never deleted automatically; uploading the same file again on the same device returns
    the existing record. Downgrading on the same host: scheduled backups appear as 手動 and an older manual policy counts
    them; the install transaction's rollback removes the timer (docs/operations.md).
  * Journal (ident `woowtech-cockpit-backup`, authpriv; notice unless marked *warning*), once per slot or change:
    `schedule-set enabled=<bool> days=<mon,…> time=<HH:MM> apps=<all|a,b> include_images=<bool> keep_last=<n|null>
    previous_enabled=<bool> loginuid=<uid|->`; `schedule-run slot=<ISO|-> job=<id> trigger=<t> apps=<a,b>
    encrypted=<bool>`; `schedule-wait slot=<ISO> busy_job=<id|->`; `schedule-skip slot=<ISO> reason=busy count=<n>`;
    *warning* `schedule-skip slot=<ISO> reason=no-key|no-apps`; *warning* `schedule-skip reason=settings-problem`;
    *warning* `schedule-skip reason=state-unreadable`; `schedule-missed slot=<ISO> first=<ISO> count=<n>`;
    `schedule-result slot=<ISO|-> job=<id> trigger=<t> result=succeeded backup=<id>`; *warning* `… result=partial
    backup=<id> skipped=<a,b>`; *warning* `… result=failed|interrupted|unknown code=<code|->`; `… result=cancelled`;
    *warning* `schedule-result slot=<ISO> job=- trigger=<t> result=failed code=<code>` (not launched); *warning*
    `schedule-clock reset handled=<ISO> now=<ISO>`.
  * Installer (`scripts/manage.py`, live root `/` only, fixed argv `/usr/bin/systemctl …` with the timer's name): it
    records the timer's state (`systemctl show`: load, unit file and active state) in the transaction journal
    (`systemd{timer, before, stopped}`), stops the timer before it writes backup files when it is active, runs
    `daemon-reload` when a unit file changed and `enable --now` the timer when it is not enabled and active (also on an
    install with nothing to change). A masked timer (`systemctl mask`) is the administrator's decision: never enabled or
    started, reported in the output's `notices`, and the install completes; any other systemctl failure fails the install.
    A failed install restores the files and the earlier timer state. Rollback concerns the timer only when the transaction
    changed backup files (the units are some): it stops a running timer while the files go back, disables it while its
    unit file still exists when the units are rolled back, restores or removes the files and runs `daemon-reload` when a
    unit file changed; it enables/starts the timer again when it was enabled/active before the install if the install
    stopped it or changed a unit file, else it starts it again when this rollback stopped it. A transaction that changed
    no backup file (e.g. `--no-backup`) is rolled back without any systemctl. `verify` reports `timer` (or
    `not-checked`), never as drift. `--no-backup` leaves the units and the timer alone; `--root`, and a live root where
    systemd is not PID 1 (no `/run/systemd/system`: a chroot, an image build), write the files, print what to run once
    systemd runs there and run no systemctl.

### Home Assistant import jobs (branch feat/ha-import, part B)

* **Types and phases**: the check is a `verify` job and the conversion a `backup` job with `params.source == "ha"`
  (known types keep older pages' job validation working); their phase labels live in the records like every job's:
  check 準備, 解開 HA 備份, 檢查內容與版本; convert 準備, 解開 HA 備份, 轉換資料, 封裝備份 (封裝（未加密） when
  `params.encrypt` is false), 驗證備份. `decrypt` and `check`/`convert` are entered once per app; the overall
  `progress.percent` still never goes back (two apps: 20, 30, 40, 50 %, packaging 60 %) and `progress.message` names
  the app and its place (「Odoo：解開 HA 備份（1/2）」). Both jobs are cancellable until they end and a cancel takes
  effect within seconds, also in the middle of a long container step (`pg_restore`, n8n's import): the job's watchdog
  stops the step, the throwaway objects are removed, the job ends `cancelled`. Nothing of the apps changes; they keep
  running.
* **The key**: `start_job(key_kind='ha')` checks it with `hasecuretar.Keys` and writes the raw UTF-8 text to
  `/run/woowtech-backup/key-<job>` (0600, removed in `finally` and by the recovery like every job key). `run-job`
  reads it before the job's first log line, registers it with `jobs.masked` and hands it to the flow as `ctx.ha_key`;
  the start commands already refused a missing or wrong key, and the job fails with `key-required`/`wrong-key` again
  when the file is gone or the key no longer opens a member.
* **Throwaway containers** (`tempctr.py`): run as the app owner; names `woowbk-<job>-<role>`; label
  `io.woowtech.backup.job=<job>`; `--network none`, or an internal network of the job when two containers must talk
  (Odoo's `odoo neutralize` with its database; n8n's import with its database); no published ports;
  `--security-opt no-new-privileges`, `--pids-limit 1024`, `--memory 2g`, half the CPUs (`--cpus`, when the owner's user
  manager has the cpu controller), `--pull=never` (the only download is the pinned PostgreSQL 16 image when the device
  has none), `--log-driver none`; secrets mounted exactly as the live Quadlet file's `Secret=` lines say; environment
  only for the keys the job names. HA's PostgreSQL 16 runs with a read-only root file system, its data volume mounted
  `noexec,nosuid,nodev`, HA's configuration files replaced and every library/command setting overridden (§9); batch 1:
  Omnigent's HA cluster the same way (the live PostgreSQL 16 image), HA's EMQX broker with a read-only root, a
  `noexec,nosuid,nodev` data volume, user 0 and `--add-host <its node's host>:127.0.0.1` (no network is opened by it),
  this device's EMQX broker and `headscale configtest` with a read-only root. Before
  the first object exists the record lists its owner in `temp_owners`; every object is removed in `finally` and the
  list is cleared once none is left. A killed job keeps `temp_owners`: the recovery (`recover_interrupted` →
  `_finish_leftovers`, any later helper call) removes that job's labelled objects and clears the list; an object it
  could not remove (podman answered, but the object is still there) or a listing that failed keeps the list and the
  next try waits 10 minutes (`temp_retry_at`). At its start an HA job (only an HA job: other jobs never wait for podman
  listings) also removes the labelled objects of jobs that are not queued or running, for the owners of every importable app (`haimport.APPS`)
  and every owner a job record still lists; each listing has a 30-second limit.
* **Space**: the floor is the running reserve (`flows.running_reserve`) plus 512 MiB. Up front the free space must
  exceed three times the selected members plus the floor; after streaming, each app asks again with what it measured
  (Odoo: twice HA's cluster plus 1 GiB, before the dump; n8n: four times the SQLite files; Omnigent: twice HA's cluster
  plus 1 GiB; Hermes, EMQX and Headscale are counted every 64 MiB while they write); before packaging, the
  archive (the data plus 1 %). Throughout, the job's watchdog reads the free space of the staging disk and of each
  owner's home and Podman storage every 2 seconds and the engine re-checks every 64 MiB it writes itself
  (`haimport.SpaceGuard`, `Watchdog`): below the floor the job's containers are killed at once and the job fails with
  `insufficient-space`; nothing of the apps changed by then.
* **Results** (§7 `HaCheck`, `HaImport`): an app that cannot move is a blocker in the check's result, never a failed job:
  also an add-on that is there twice or whose addon.json is not WOOWTECH's, an owner that is gone, an app not
  deployed, the live upgrade marker or the `odoo` role the conversion would refuse (failed jobs: key, corrupt file,
  space, cancel). The conversion fails with the first blocker of the chosen database or app instead.
* **The converted backup**: one format 2 `manual` backup of the selected apps, written by `flows._package` (the normal
  packaging, encrypted with the device key when `params.encrypt`, verified, registered), note
  「由 HA 備份轉換：<HA name>（<HA date as local time>）」; its row in `ha-imports.json` is written under the index lock
  with the backup id chosen first, every text cleaned and cut on the way in (whatever the conversion found is
  accepted), dropped when the job fails before the backup is in the index (a failure after that keeps it), by `delete`
  of the backup, and a day after its backup no longer exists (rows of other jobs are never touched). The conversion runs
  no retention. Converted backups are a pool of their own: no keep-last rule counts or deletes them and they are no
  app's `last_backup` (they hold HA's data; §7, rule 18). `ha-delete` of the HA file leaves converted backups and their
  rows alone.
* **Interrupted**: an HA job cut short says so in its own words (「檢查 HA 備份的作業意外中斷…」 /
  「轉換 HA 備份的作業意外中斷…」) and that nothing on the device changed; its staging (plaintext) goes like every job's.

## 9. Backup and restore algorithms (adapter `quadlet-postgres`)

**Stops, starts and downtime (2026-11-13 strengthening).** Units stop with **one** `systemctl --user stop -- <units>`
(listed dependents first): systemd stops them side by side and orders only what `After=` orders (n8n's task runners took
~50 s each one after another). Units start in **groups**: a unit whose `After=`, `Requires=` or `BindsTo=` names other
units of the app waits only for those of them that are started too (Quadlet adds no `After=` for `Requires=`, so a
required unit counts as a prerequisite as well; review L7); a unit that names none waits for every unit before it in the
catalog order (the catalog order stays the fallback); each group is one `systemctl --user start`, and a catalog order
that contradicts them, or dependencies that cannot be read (`systemctl show --property=Id,After,Requires,BindsTo`), start
one unit at a time. A writer
that does not start is tried once more on its own (backup, recovery); a unit of a restore that does not start fails the
restore. Writer pause and unavailability are measured per app (§7 `Timing`). Exceptions to the single stop: a cold
database with a `postgres-digest` stops in a second call, right after its digest was read while the apps using it were
already stopped. Measured in the lab (2026-11-14, integrated build, dev-a; `tests/e2e/lab/strengthen_e2e.py e4`: woowbk-dirs
plus a 300 MB host directory and two writer units that each take 15 s to stop, like n8n's task runners; previous engine
2026.11.13.2 against this one, same device and data, one run each):

| Helpers' Quadlet | Engine | Backup writer pause | App's own outage during the backup | Restore job | App's own outages during the restore |
| --- | --- | --- | --- | --- | --- |
| `After=` the app (production's n8n-runners) | previous | 39 s | 6.8 s | 120.6 s | 3, 30.3 s in all over 71.7 s |
| `After=` the app | this one | 22.6 s | 6.5 s | 75.5 s | 1, 26.6 s (`unavailable_seconds` 42.6) |
| none | previous | 38 s | 6.6 s | 114.8 s | 2, 29.0 s in all over 70.1 s |
| none | this one | 24.2 s | 22.9 s | 70.0 s | 1, 37.6 s (`unavailable_seconds` 39.8) |

With `After=` systemd stops the helpers first and the app last, so the single stop shortens every figure. Without it the
units stop together and the app goes down at the start of the window: the total pause and the job are shorter, the app's
own outage is longer (the previous engine's reverse-catalog serial stop kept the app up while the helpers stopped).
Declaring `After=<main>.service` in a slow helper's Quadlet file is the remedy; runs vary by a few seconds on the shared
lab host (an earlier run of this build: restore job 103 s, one outage of 54 s without `After=`).

**Data digests.** Backup: every digest is read **twice**, around the copy it vouches for, while the writers are stopped:
SQL digests of `postgres[]` databases before and after the `pg_dump`s (database running), a cold database twice right
before it stops, files digests before and after the exports. A check whose two reads differ -- something the catalog
does not stop wrote meanwhile: a client of the database, a job inside it (pg_cron, TimescaleDB), a host process -- is
left out of this backup with a warning in the job log naming the check and the reason, and the backup is still made
(review H2, F3: a digest read at another moment than the dump used to be stored, the backup passed its checks, and every
restore of it -- and the rollback of a failed restore that took it as its safety backup -- failed the comparison, the
latter leaving the app stopped and masked). Equal reads prove the copy in between holds the same data, except a change
undone before the second read; for a cold database a write between the second read and the stop is not seen. A volume
that a running container the backup does not stop mounts read-write refuses the backup (§4). Each kept listing becomes a
`verify` entry (§5). psql runs with `PGOPTIONS` fixing TimeZone (UTC), DateStyle, IntervalStyle, extra_float_digits,
bytea_output, search_path (pg_catalog), standard_conforming_strings and lc_monetary (C), and with
`PGCLIENTENCODING=UTF8`, so a row's text does not depend on the server's or the client's defaults; a row's text is
`pg_catalog.record_out(t.*)` (no user-defined cast runs, a column named `t` is just a column; review H1, F2), its digest the
md5 of that text as UTF-8 (a SQL_ASCII database: its bytes as stored; review F6), a table's digest the two sums of the
64-bit halves (order independent, duplicates count), all tables of a database read in one read-only REPEATABLE READ
transaction; sequences contribute `last_value:is_called`; temporary tables, extension members, views, materialized views,
foreign tables and large objects are not covered. The digest records the PostgreSQL major it was read on
(`server_major`): float text differs between 11 and 12, so such a pair is reported as not compared (review L4/F7). Restore: after the data is in place and before
anything that uses it starts — files digests right after the swaps and volume imports; then the database units start
alone (single-database/instance: `pg_restore`; a cold database: unmasked and started by itself) and the SQL digests are
read (exactly the databases the backup recorded, also for `"all"`: a missing one fails, one the image created at its first start is not compared); only then are the remaining units unmasked and started. A digest that differs is read once more:
when the second read differs from the first, the data is still changing (a writer the catalog does not stop, e.g. a
client of the running database between `pg_restore` and the read) and the check is reported as not compared (`match`
null, a `note`, and the note in the result's `warnings`) instead of failing -- the rollback would meet the same writer
and end with the app stopped and masked (seen in the lab, 2026-11-14). Equal reads that differ from the backup fail the
restore before the app runs, with the differing items (first 20) in the result, and the automatic rollback follows (its
own digests are compared the same way). Probed in the lab (2026-11-13, postgres:16-alpine 16.16): identical digests on the source and on a cluster restored
by instance mode, including timestamptz, float8, real, numeric, bytea and jsonb columns.

**Pre-restore copy (2026.11.14.2).** Phase `safety` copies the in-place apps' data exactly as a safety backup did
(`create_backup(..., keep_stopped=True, defer_package=True)`: same consistency, digests and hand-over) into
`pending/<job>/data/` (laid out like an extracted archive), checks that every entry's file is `data/<entry path>`, fsyncs
every file and directory of the copy, writes its record `pending.json` atomically (entries with size and sha256, the
apps' manifest sections, note, downtime, the encryption choice made at the job's start, and the id the safety backup
will get) and records `safety_pending` before the restore's first destructive step: from then on a power loss leaves a
complete copy. A failure to save or record the copy counts as no safety backup (`safety_failed`, or the
`allow_no_safety`/safety-source fallback). **Where the copy is packaged is decided before any writer stops**, from the
estimate E (review 2026-11-14, three rounds). After the restore when the free space holds the copy counted with a
tenth more (E', for what the estimate leaves out and the other apps' writes meanwhile), its archive (E' + 1 %) and the
running reserve (the apps run while it is written: 5 % of the filesystem, at least 2 GiB and at most 10 GiB, review
M4), less what the restore gives back first: the in-place apps' extracted data except images (deleted before that
packaging, review CR-01), at most E, because where the apps' storage shares the filesystem the restored data takes the
place of what it replaces. Otherwise -- and also when the job deploys an app from templates, whose data on disk is not
known before it runs -- in the downtime when the free space holds what 2026.11.14.1 needed for its safety backup
(E × 2.2 + the device reserve): exactly as then, the copy is packaged, verified and registered before the first
destructive step and then deleted, so the restore keeps the room it had then, and a rollback extracts the safety
backup into the job's staging (the failed restore's extracted archive deleted first); only when that extraction would
not fit (the free space once the copy is deleted, with the extracted archive, less than the copy + the device reserve)
the copy stays and the rollback reads it. A deletion that fails half-way still counts as deleted: the rollback extracts
the safety backup, and what is left of the unflagged copy is the recovery sweep's.
No restore that 2026.11.14.1 accepted is refused. With too little space for either, the restore is refused before any
writer stops (`safety_failed`, `應用未被暫停`), the error naming the smaller need (rounded up) and the log both; with
`allow_no_safety` or a safety-backup source it goes on without a copy, as before. Once the copy is on disk, its real
size and the databases the backup brings are checked again: a copy that will not fit after the restore (larger than
estimated, or an in-place database dump in the backup larger than the one just copied: the database grows with the
restore) is packaged in the downtime instead when that fits (the copy + 1 % + the device reserve). **Space is then no
reason to refuse any more**: a downtime packaging that does not fit (or fails with ENOSPC, also while registering)
leaves the copy for the packaging after the restore (flagged as `safety_pending`; the rollback reads it), which checks
the space again and waits for space if it must. The one exception: with less free space than the device reserve
after the copy, neither the restore nor a rollback could be trusted to finish (the job's own records may fail to
save), so the restore is refused there, the copy deleted (its data is unchanged), also with `allow_no_safety`. A
restore is otherwise refused after the stop only when the copy itself cannot be written or recorded, or when the
downtime packaging fails for another reason than space and restoring without a safety backup is not accepted (as
before 2026.11.14.2; production 2026-11-14: Hermes was paused 2 min 16 s and then refused, 11.8 GiB needed after the
restore, 11.6 GiB free, because only the check after the copy knew the running reserve). Packaging in the downtime
sets `safety_in_downtime` and marks phase `safety-package` `done` during `safety`, kept so through the restore's
phases and a rollback; that phase never counts as a destructive step (`changed`, §7). A termination signal while the
copy is deleted right after that packaging stops the job (nothing has changed yet); once the restore or a rollback is
over, one while the copy is deleted leaves the rest to the recovery sweep and the outcome stands. For packaging after the restore, the same need is checked again right before it starts (images pulled or WAL
written meanwhile). A successful restore deletes
the replaced host-directory copies, the extracted archive, and then packages the copy in phase `safety-package` (written
and fully verified like any backup, then registered; `safety_backup_id` set) and deletes it -- outside the outage
(production 2026-11-14: Hermes 66 s and Nextcloud 35 s of the outage were this packaging). A failed restore rolls back
**from the copy** (no extraction) after checking every entry again (regular file, no symlink, recorded size and sha256;
a damaged copy means no rollback: `需人工處理`), then packages it inside `rollback` (the message names the new safety
backup); a copy deleted after its packaging in the downtime is replaced by the safety backup, extracted. A termination
signal after the packaging registered the safety backup (while that is being recorded) reports it packaged, not kept. Registration is the commit point: the record names the backup (`safety_backup_id`, flag cleared) before the
copy is deleted. Packaging that fails, finds too little space or is cut by a termination signal keeps the copy and the
flag, and the job's outcome stands (a finished restore still ends `succeeded`, a rollback `rolled-back`, with their
full result; `warnings` say where the copy is); a shutdown during the restore itself leaves both for the recovery after
boot. Nothing deletes a copy except its successful packaging, a failure before the first destructive step (its data is
unchanged where it came from; the flag is cleared first), or the recovery's sweep of copies nothing needs (§8).

**Hand-over from the pre-restore copy.** The pre-restore copy of an in-place restore leaves its writers stopped
(`keep_stopped`): no restart, no health wait, no second stop. Its http-json snapshot is then not stored (it cannot be
confirmed while the app is down); digests are exact anyway and are what the rollback compares. An app with http-json
checks but no digest (the hand-written production entries) therefore has a rollback that is checked by the health checks
only: the preflight says so before the restore (`rollback-unverified`, warn), the safety backup's log says so, and a
rollback that compared no data adds a note to the result's `warnings` instead of implying a data check (review F16; a
second stop and health wait to confirm the snapshot -- the behaviour before 2026-11-13 -- is not traded for it; adding
digest checks makes rollbacks compare data). Any failure before the
restore's first destructive step (saving the pre-restore copy, the packaging-space check, a refusal inside `restore()`)
starts those writers again and deletes the copy; apps a multi-app restore had not reached when it failed are started again by the rollback.

**Host directories before the stop.** After the preflight (the cancellable window closed, `dir_apps` recorded) phase
`stage` writes each archived host directory to `<dir>.woowbk-new-<job>` while the apps still run (HA's 30 s and
Nextcloud's 75 s of extraction no longer count as downtime); nothing that exists changes. The restore then only swaps
them in. Any failure before the restore's first destructive step removes them again (`discard_dirs`) and clears
`dir_apps` (kept for the recovery when a copy cannot be removed); a killed job leaves them to the recovery (§8).

**Instance mode.** Backup (database running, writers stopped): the catalog user must be a superuser and the instance's
bootstrap superuser (oid 10, the image's `POSTGRES_USER`: a restore runs in a cluster where only that role exists; review
F5), recorded as `bootstrap_user`; `pg_dumpall -l <postgres|template1> --globals-only --no-tablespaces` (checked right
away by the restore's validator, §10) and `pg_dump -Fc` of every database except template0/template1 -- template
databases too, flagged `template` (e.g. an image's `template_postgis`) -- each fully read back; a database that accepts no
connections fails the backup (pg_dump cannot read it, and an in-place restore would lose it for good; review F1);
database names must match the §4 rule, owner/encoding/locales the §5 rules; user objects in template1 are named in the
log (a restore keeps the image's own template1). Restore into the fresh cluster the image initializes at its first
start (the data volume was removed): before the removal, in place, the engine refuses (as for single-database mode) an
instance that holds databases accepting no connections (they are in no backup; review F1); the new cluster must be
newer than that removal (the high 32 bits of `pg_control_system().system_identifier` are its initdb time; an older one
means the volume was not rebuilt, and the restore stops before writing; review F4); the target major must be ≥ the
source; every extension of every database must be in `pg_available_extensions` (else `incompatible` before any data,
naming the extensions); the globals script runs with `ON_ERROR_STOP=1` after §10's checks, with the bootstrap superuser
**reconciled**: its `CREATE ROLE` is dropped (the image created it), its `ALTER ROLE` applies the backed-up attributes and
password hash (the restored secret holds the matching password), and an archive that would make it `NOSUPERUSER` or
`NOLOGIN` is refused; afterwards a new session of that role must still be a superuser that can log in and not be
read-only, else the restore stops (review L2, F8). Every database of the backup -- the connection database `postgres`
included -- is then created by `pg_restore --create --exit-on-error --no-tablespaces -d template1` (original owner,
encoding, locale provider and locales, ACL, `ALTER DATABASE … SET`, `ALTER ROLE … IN DATABASE … SET`, comment, template
flag; checked in the lab); a database of the backup that the new cluster already has (`postgres`, `POSTGRES_DB`, a
template an init script made) is dropped first whatever the image's init scripts put into it (postgis and timescaledb
images load extensions there; review F4; a template is unmarked first). Owners and privileges are restored (no
`--no-owner`/`--no-privileges`). In place, databases that exist now but not in the backup are removed (preflight warns;
the safety backup keeps them, templates included). Probed in the lab (2026-11-13): Nextcloud-like (`oc_admin` owning
`nextcloud`, membership in a NOLOGIN role, per-database role setting) and Odoo-like (`odoo` with CREATEDB and a
connection limit owning `odoo_prod`, LC_COLLATE C, REVOKE CONNECT FROM PUBLIC, database setting and comment) setups, an
ICU database, and pgvector (`vector` 0.8.7) onto postgres:16-alpine (refused, `vector` unavailable); the 2026-11-14 build
again end to end in §13.


Backup (per app): probe (owner, linger runtime dir, quadlet files, units active) → estimate size (volumes:
apparent size + 1 KiB per member for tar headers and padding) → space check (free ≥ 2.2 × estimate + 512 MiB) →
log databases/roles of the instance that the catalog does not declare and user objects in its `postgres` database (they
are not backed up) → snapshot business verify → stop `writer_units` → `podman exec <db> pg_dump -U <user> -d <db> -Fc` (stream to staging file) and check
it with a full read `pg_restore -f /dev/null` (`--list` only reads the table of contents) → `podman volume export
<vol>` (stdout to staging) → read secrets with `podman secret inspect --showsecret` → read config + quadlet files as
the owner → **always restart writers in `finally`** (a writer is listed before its stop, so a signal during the stop
still restarts it; after an ordinary failure a database that stopped during the backup is started again and the
writers restarted once more) → check every volume export like a restore would (§5, with the owner's ID map; content
podman cannot import or more than 2,000,000 members fails the backup with a message naming the volume and the
member) → health check (only when every unit was active before the backup; an app that was
already down is not waited for, and `downtime_seconds` is 0 when no writer had to be stopped) → a second verify
snapshot, also for an app that was only partly running (then retried up to the catalog's health timeout while the
restarted writers come up): the snapshot is stored only when it equals the one taken before the stop, otherwise none
is stored (writes or settings applied at restart would make every restore of that backup fail its data check) →
optionally `podman save --format oci-archive` per image. Then the engine writes the format 2 archive in staging (§5:
encrypted to the device key, or unencrypted when the job's `encrypt` is false; a safety backup follows the setting
預設加密備份) (temp file, fsync, rename), verifies it fully (with the device key when encrypted), moves it into
`archives/<id>.tar` (rename without overwrite), writes the index (`format: 2`, `encrypted`, per-app archive sizes), and
deletes staging.

Restore (per app, after full verification and extraction of the **selected apps' archives only** to staging; an
`unauthenticated` backup only with `accept_unauthenticated`):
* Before any change: check every nested tar (section 5); `inplace` (single-database mode) refuses (`incompatible`) when the database
  instance holds databases the catalog does not declare (the data volume is rebuilt from one `pg_dump -d`) — listed
  through the catalog's own database (`pg_database`/`pg_roles` are shared catalogs), every database except the
  catalog's, `postgres`, `template0` and `template1` (by name; other template databases count) — and also when the
  instance cannot be listed at all, unless the restore runs without a safety backup (`allow_no_safety`, or restoring a
  `safety` backup, and no new one could be made): then it proceeds and says so in the log and `warnings`. Preflight
  fails in the same case and warns about tables, functions or extensions in the instance's `postgres` database (not
  kept). A rollback skips this check: it rebuilds what the failed restore itself created. Remember which image each
  needed ref and `local_name(ref)` point to.
* `fresh` (quadlet files absent): preflight fails when a catalog volume, template-declared volume, secret or config
  file already exists (a failed fresh restore removes what it created, so a leftover would be destroyed); install
  catalog templates as the owner into `~/.config/containers/systemd/`, `systemctl --user daemon-reload`.
* `inplace`: first create and fully verify a `safety` backup of the app (its plaintext staging is deleted as soon
  as it is published; encrypted with the device key while 預設加密備份 is on — `no-device-key` without one — else
  unencrypted, and then no device key is needed; a rollback extracts it with the device key or none); abort without
  changes if that fails, unless the backup being restored is itself a `safety`
  backup or the request has `allow_no_safety: true` — then the restore proceeds without one (`safety` phase skipped,
  `result.safety_skipped`). With a safety backup, abort without changes (`insufficient-space`) unless free space plus
  the extracted archive covers the safety backup's plaintext + 512 MiB (what a rollback needs). Then stop units
  (reverse order).
* `systemctl --user mask` the app's non-database units until the restore finished (an interrupted restore must not
  start on half-restored data at boot); recreate secrets (`podman secret rm` + `podman secret create <name> -` from
  stdin), write config files (as owner, `O_NOFOLLOW`, declared mode), load included images (`podman load` of the
  canonical OCI stream; afterwards `<ref>` must resolve to the manifest's id, §5), recreate volumes (`podman volume rm -f`, `create`,
  `import <vol> -` of the canonical stream), remove the database data volume, start the DB unit, wait for
  `pg_isready`, `pg_restore --exit-on-error --single-transaction --no-owner --no-privileges`, `unmask`, start
  remaining units in order, run health checks, then compare verify output with `verify_snapshot` on the `compare` keys.
* A failure before the first destructive step puts back the image names it loaded, retagged or pulled
  (`result.changed` false). Any failure after the first destructive step → automatic rollback, each app on its own:
  the extracted archive is deleted first, then the safety backup is extracted and restored (`inplace`; a rollback
  never pulls an image: the exact pre-restore image id must still exist) or what was created is removed (`fresh`:
  `systemctl stop` exit 5 counts as stopped, networks and pods are removed without force, image names are put back),
  then state `rolled-back` (or `failed` with `需人工處理` guidance when rollback also fails). Exception: a termination
  signal while systemd reports the machine is shutting down starts no rollback; the job ends `interrupted` naming the
  safety backup, and a partial fresh deployment is removed by the recovery after boot.
* Only after a successful restore: keep the 3 newest `safety` backups per app, never deleting the backup being
  restored, the safety backup this restore took, or a safety backup that a failed/interrupted restore (not rolled back
  and not followed by a successful restore of that app) still names.

Health and verify requests (`loopback_get`) are bounded in total, not per socket operation: connect, headers and body
together take at most the request's timeout. The status page's quick health request reads only the status line (3 s),
and `status` probes the apps side by side (up to 8 at a time).

Images: if not included, the local image for the ref must exist or be pullable; otherwise the app
preflight fails (`podman image exists` exit 1 is "absent", any other non-zero exit is an error). PostgreSQL major
in the archive must be ≤ the target image major; PostgreSQL before 10 is not supported (preflight and backup say so).

**Host directories.** Backup: each directory is measured inside the owner's namespace before any writer stops; a
directory that is a mount point or holds one fails the backup (a restore could not rename it, and tar stays on one
filesystem), POSIX ACLs are reported. A running container that is not a stopped writer and bind-mounts a directory
read-write fails it too. The writers stop, each directory is packed through the relay, the writers restart, and each
export is checked as a restore would check it. Restore (in place and fresh): after the units stop (fresh: the
templates are installed) every directory is written to its new sibling first, while nothing that exists has changed;
then secrets, config files, volumes and the database volume; then, right before the swaps, the owner's running
containers are listed again and any that bind-mounts a directory fails the restore; then each directory is swapped.
The replaced copies are deleted (renamed to `-del-` first) only after the whole job succeeded. Rollback: a directory
the failed restore swapped moves back from its `-old-<job>` copy (`revert`, no extraction, no space); one it replaced
without such a copy (removed meanwhile, or created by the restore) is extracted from the safety backup; one it never
changed is left alone. The failed restore's data (`-old-<job>-rollback`) is deleted once the rollback was verified,
and reported otherwise. Any error of a directory step (also an unexpected exception) is recorded as a problem and never
stops the rollback of the other apps.

### Home Assistant import (branch feat/ha-import, part B; `ha_odoo.py`, `ha_n8n.py`, `haimport.py`)

**Odoo** (add-on `odoo18ce` → app `odoo`, cold PostgreSQL mode: volumes `odoo18-db-data-isolated` (a whole cluster)
and `odoo18-web-data`, host directory `.local/share/odoo18/addons`). The live Quadlet files describe the target (the
database container's image, environment, secret mount and data volume; the web container's image, configuration
secret and mounts); an entry of another shape is `incompatible`.
1. One strict pass over the add-on's member: `data/postgres/**` streams into a throwaway volume as a tar owned by the
   helper image's postgres user (dirs 0700, files 0600). HA's cluster is untrusted: `postgresql.conf`,
   `postgresql.auto.conf`, `pg_hba.conf` (`local all all trust`) and `pg_ident.conf` are replaced by known files,
   `recovery.signal`, `standby.signal`, `recovery.conf`, `recovery.done` and the pid files dropped; a tablespace link is
   refused. The walk calls the job's checkpoint every 1024 headers and 64 MiB read and a member may inflate to at most
   100 times its stored size (at least 32 GiB, else `limit-exceeded`); filestore files and bytes are counted per database; custom
   module candidates are read from `data/addons/<m>` (before `data/odoo/addons/18.0/<m>` and `share.tar[.gz]`
   `odoo_addons/<m>`, HA's addons_path order; `__pycache__` skipped) with their manifests parsed by
   `ast.literal_eval`. A conversion also writes the chosen database's filestore and every candidate to staging.
2. The live upgrade marker and role `odoo` are checked first, as the conversion checks them (step 4). A throwaway
   PostgreSQL 16 (`pgvector:0.8.6-pg16`, else `postgres:16.15-alpine`, else the pinned official image, pulled) serves
   the cluster on its socket only, started with every library, archive, restore, recovery and listen setting overridden
   on the command line (`shared_preload_libraries=` … `restore_command=`, `dynamic_library_path=$libdir`, `ssl=off`,
   `jit=off`), its data volume mounted `rw,noexec,nosuid,nodev` and a read-only root; per connectable, non-template
   database other than `postgres`: installed modules (and pending ones), partners, internal active users, attachments
   and their bytes, active crons and mail servers, size, extensions, objects only a superuser can create (event
   triggers, FDWs, servers, subscriptions, languages, C functions, access methods, casts, operator classes, text search
   parsers/templates that no extension owns) and the website domains (when `website` exists). Odoo itself in the live image (network none, the configuration secret and the live
   module folders mounted read-only, `python3 -I` fed a scanner on stdin) lists the target's modules with their adapted
   versions in addons_path order and checks the candidates' `external_dependencies` (`check_python_external_dependency`,
   `find_in_path`).
3. Verdict per database (`database_verdict`): every installed module present on the target with the identical version
   (verify-modules.py's comparison), or a candidate with that version that the target lacks or holds in another
   version only in the custom modules folder (it is copied); nothing pending; extensions ⊆ plpgsql, pg_trgm, unaccent,
   vector (vector only with the pgvector image); no object only a superuser can create; HA's major ≤ the target's;
   the copied modules installable and their Python packages and programs present. Warnings: active mail servers and
   crons, and the website domains that will change to this device's address.
4. Conversion of the chosen database: `pg_dump -Fc` in the PostgreSQL 16 container; a new cluster in a throwaway
   volume from the live database image with the live environment and secret mount (initdb sets the live superuser
   password); role `odoo` with the attributes and the password verifier of the live role (read from the live cluster
   as its superuser, checked against a strict pattern, masked, sent on stdin); `createdb -O odoo --template=template0
   --encoding=UTF8 --lc-collate=C odoo`; pg_trgm, vector (+ unaccent when HA has it), `ALTER EXTENSION vector UPDATE`;
   the dump's list without its EXTENSION and `COMMENT - EXTENSION` entries (matched on the entry type field), refused
   (`incompatible`, naming the kind) when it lists an object only a superuser can create; the dump streamed on stdin into
   `pg_restore -U odoo --no-owner --no-acl --exit-on-error --single-transaction -L <list> -d odoo` (as the role
   itself: what HA's server wrote never runs with superuser rights);
   `web.base.url` and `web.base.url.freeze` as the live database has them, `website.domain` cleared on every website
   row (the target keeps its own address); the live `woow_paas_platform.upgrade_done`
   (it must name the live Odoo image ID) copied and `…upgrade_attempt` deleted (HA's core date never reaches the
   marker); test mode: `odoo neutralize -c /etc/odoo/odoo.conf -d odoo --db_host <cluster>` in a throwaway container of
   the live Odoo image on an internal network with the cluster and the custom modules folder as it will be after the
   import (step 5, in a throwaway volume: a module copied from HA runs its own `neutralize.sql`), and a new
   `database.uuid`; the modules (installed, versions equal), partner and attachment counts, marker, address, cleared
   website domains and uuid verified; settings the live cluster sets in its configuration that differ (not locations,
   ports, commands or build constants) carried with `ALTER SYSTEM`, one statement per `psql` call outside any
   transaction block (list settings such as `search_path` one literal per element), then `pg_reload_conf()` and every
   carried setting read back from `pg_file_settings` without an error; `CHECKPOINT`, stop, exit 0 and `pg_controldata
   <PGDATA>` "shut down" (PGDATA when the Quadlet sets it, a folder of the volume); `podman volume export`.
5. `odoo18-web-data`: the live export (read while Odoo runs) without `filestore/odoo/**` and `sessions/**`, an empty
   `sessions/` owned like the live one, HA's filestore of the database as `filestore/odoo/**` (the image's odoo
   uid/gid, dirs 0700, files 0600). The custom modules folder: the live folder (DIR_HELPER pack) without the modules
   being replaced, plus the copied modules owned by the app owner, dirs 0755, files 0644 (0755 when executable). Every
   tar passes `nested.check_volume`/`check_dir` with the owner's ids.

**n8n** (add-on `woow-n8n` → app `n8n`: database `main`, volumes `n8n_n8n_data` and `n8n_valkey_data`).
1. The pass stages `config/.n8n/database.sqlite` (+ `-wal`; never HA's `-shm` wal-index: SQLite rebuilds it from the
   WAL) and reads `config/.n8n/config`'s `encryptionKey`
   (masked); `nodes/package.json` names the community packages; every native `.node` file must be x86-64 ELF without
   glibc (the image is musl) or the package is named in a warning; a conversion stages `nodes/**` (relative links that
   stay inside `nodes/` and whose `..` components all come before their names, so no chain of links can climb out)
   and `storage/**`. Caches, Redis, runner files, logs and `data/` never move.
2. The SQLite file is never opened by the job process: a child (`python3 -I -S`) reads a copy of its own after it
   dropped to the account nobody (no supplementary groups, its own network namespace, memory/CPU/file-size/process
   limits), with `SQLITE_DBCONFIG_DEFENSIVE`, `PRAGMA trusted_schema=OFF`, `cell_size_check=ON`, ordinary tables only
   (no virtual table or its shadow tables), explicit columns: the `global:owner` user must have an email and a password;
   counts; the workflows one JSON line each (a workflow over 16 MiB, or past 256 MiB in all, comes as "too large to
   analyse"), whose nodes the job scans one at a time for things that need changes here (`workflow_reasons`). The
   add-on version must equal `n8n --version` of the live image, and the live n8n must not set its own
   `N8N_ENCRYPTION_KEY`/`_FILE` (Quadlet `Environment=`, `Secret=…,type=env`, an `EnvironmentFile=` in the owner's home:
   names only; it would refuse HA's key).
3. Conversion: a throwaway volume with the copy, HA's key (0600, the image's node uid/gid), an empty `out/` and a
   random temporary database password (`pgpass`, masked); `n8n export:entities --outputDir=/work/out
   --includeExecutionHistoryDataTables=true` (network none, SQLite); a throwaway PostgreSQL from the live n8n-postgres
   image (user and database as the catalog's) and `n8n import:entities --inputDir=/work/out --truncateTables=true` on
   an internal network; every table with rows in the copy (but `migrations`, `sqlite_sequence`, `sqlite_stat1`,
   `sqlite_stat4`) must hold exactly as many rows after the import (it exits 0 when it skipped; counted 40 tables per
   query); test mode `n8n unpublish:workflow --all` and no active workflow left;
   `pg_dump -Fc` (read in full once) becomes database `main` with the temporary server's version.
4. `n8n_n8n_data` from scratch: the top directory owned like the live one, `config` `{"encryptionKey": <HA key>}`
   (0600), HA's `nodes/**` and `storage/` (node uid/gid); `n8n_valkey_data` only its top directory (owned like the live
   one): HA's queued jobs never run here.

**Batch 1** (branch `feat/ha-import-batch1`; `ha_omnigent.py`, `ha_hermes.py`, `ha_emqx.py`, `ha_headscale.py`,
`hasqlite.py`, `hacommon.py`). Binding rules for every app: the data, the data's own keys and the accounts move; the
target keeps its URL, ports, database passwords, secrets, settings and units; the versions must be identical (each
module keeps a table add-on version → upstream version; an add-on version it does not know is refused) or the job is
refused before anything changes; amd64 and aarch64 backups are both accepted. Facts: `phase3/facts/{omnigent,hermes,
emqx,headscale,mcp-admin}.md` of the design notes.

**Omnigent** (`woow-omnigent` → `omnigent`, cold PostgreSQL mode: volumes `omnigent-postgres-data` (a whole PostgreSQL
16 cluster whose bootstrap superuser is the app role), `omnigent-server-data`, `omnigent-pi-data`).
1. Versions: add-on 0.1.20–0.1.23 → Omnigent 0.21.0 (0.1.19 → 0.20.0, ≤ 0.1.18 → 0.12.0) must equal the live server's
   `GET http://127.0.0.1:<port>/v1/info` `server_version` (the port of the catalog's health URL); HA's `alembic_version`
   must equal the live database's (read as the app owner, `podman exec <db> psql`); HA's PostgreSQL major ≤ the live one.
2. One pass: `data/postgres/**` into a throwaway volume exactly like Odoo's (PgSink: HA's configuration files replaced,
   recovery/pid files dropped; a hard link or a tablespace link there is refused); the artifact store
   `data/omnigent-home/.omnigent/artifacts/**` (where omnigent 0.21.0 keeps it: HOME is /data/omnigent-home and the
   add-on's ARTIFACT_DIR is never read) staged, `.cache/` never; HA's runtime setting files in /data (sharing, admins,
   allowed domains, config.yaml) only named. The cluster is opened by a throwaway of the LIVE PostgreSQL 16 image,
   hardened exactly like Odoo's (`ha_odoo.start_ha_cluster`). Blockers: tables other than Omnigent's, any function,
   trigger, view, rule, policy or other schema, an object only a superuser can create, extensions beyond plpgsql and
   pg_trgm, not UTF8, a missing `accounts-cookie-secret`, an agent bundle or file blob the database names that is not
   in the staged store, a malformed artifact key.
3. **Trusted schema (B1-01; owner decision 2026-11-23 replaced the security hold).** HA's backup provides DATA only:
   no DDL, default, check, domain, index or function written by HA ever runs. The check reads this device's live
   schema (as the owner, read only) and names every table whose columns differ (a blocker). Conversion: HA's cluster
   is dumped (`pg_dump -Fc omnigent`, the hardened throwaway); a new cluster from the live image, environment and
   secret mount (read-only root, data volume `noexec,nosuid,nodev`) gets THIS device's schema: `pg_dump
   --schema-only` of the live database inside one exported snapshot (`REPEATABLE READ READ ONLY`, revision checked in
   the snapshot), its pre-data and post-data sections restored by the app role. The product itself proves what the
   lab proved (`ha_omnigent.trusted_schema`; no caller flag): the live schema signature (`SCHEMA_SIGNATURE_SQL`:
   relations, columns with types/defaults/collations, constraints, indexes, sequences, types and enum labels,
   functions, triggers, rules, views, policies, extensions, schemas, other user objects), its columns and its alembic
   revision are read before and after the capture and must be equal, and the snapshot's columns must be the live
   ones -- else `incompatible` 「這台 Omnigent 的資料庫結構在轉換期間改變了…」, nothing changed. HA's columns (in order),
   sequences (type, owning column) and types must equal the trusted ones (else `incompatible`, naming them); HA's
   defaults, checks and indexes are not compared because they are never used. From HA's dump only TABLE DATA and
   SEQUENCE SET entries are restored (`pg_restore -L`), and each selected entry must name a table or sequence of the
   trusted schema exactly once (pg_restore reads only a line's dump id: a name with a line break cannot add an entry);
   they are loaded by `woowbk_restore` (`LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, only
   `USAGE` on public, `INSERT` on its tables, `SELECT` on users/scheduled_tasks, `UPDATE` on scheduled_tasks,
   sequence values; `--no-owner --no-acl --exit-on-error --single-transaction`). The new cluster's signature must
   equal the trusted one after the post-data section and again after the last write; `woowbk_restore` is dropped
   (`DROP OWNED`, `DROP ROLE`); the cluster may then hold only its bootstrap role, no role or database setting, no
   `postgresql.auto.conf` setting and no large object (else `job-failed`). This device's own accounts -- the
   Quadlet's `OMNIGENT_ACCOUNTS_INIT_ADMIN_USERNAME` and `OMNIGENT_RUNNER_USERNAME` (default admin, operator) -- are
   read from the live database as the owner (password hashes masked in every log line) and added back by
   `woowbk_restore` (`json_populate_recordset` on its stdin, never an argv; `ON CONFLICT DO NOTHING`: a same-named HA
   user wins, with a note); test mode pauses every active scheduled task (`state` 1 → 2) as `woowbk_restore`; every
   table's rows equal HA's (users plus the accounts added), alembic unchanged; `CHECKPOINT`, stop, `pg_controldata`
   "shut down", export. Every Quadlet `Secret=` of the app must be declared in its catalog entry before anything runs.
   HA's cluster is hostile code, not only hostile data (security review 2026-11-23, `tests/backup/evidence/
   omnigent-product-security-review-20261123/`): its catalog and its own per-role/per-database settings (which win over
   the command line) can make every answer lie and can run commands inside the throwaway container, whose boundary
   (no network, read-only root, limits) is what holds. So nothing it answers is believed: right after HA's data is
   loaded, the new cluster (HA's data on this device's schema and server) must give the check's answers again --
   `DETAIL_SQL`, `KEYS_SQL` and every table count (lists compared as sets) -- else `incompatible`
   「這份 HA 備份的 Omnigent 資料庫回報的內容和它實際的資料不一致…」 before anything is exported (SR-1); and the selected
   SEQUENCE SET entries, whose statement pg_dump writes from the value the server sent (unquoted), are printed by
   pg_restore itself (`-f - -L`) before anything is restored and must be exactly one
   `SELECT pg_catalog.setval('public.<trusted sequence>', <integer>, true|false);` each (SR-3).
   HA's `pg_dump` runs as an OS user that is not the HA server's (`dump_user`: the first of `DUMP_IDS` 65534, 32767,
   9999, 999 that the owner's uid AND gid maps hold, never root and never the image's postgres ids; none ->
   `job-failed` before anything is exported), over the socket directory as the database user postgres: code HA's
   catalog runs inside its server can then neither open pg_dump's stdout through `/proc/<pid>/fd` nor signal it, so it
   cannot write the archive the conversion restores (SR-2b). A fixed 65534 failed in the real product flow on dev-d,
   whose owner maps only uids 1..55000 (`podman exec` exit 255); dev-d gets 32767. Names taken from HA's database (tables, schemas, extensions, alembic) reach the job log and the page
   with control characters and Unicode bidirectional controls shown as `?` (`hacommon.names`, SR-4).
   HA's rows that this device's schema refuses (its CHECK/NOT NULL constraints at the data load, its primary keys,
   unique indexes and foreign keys at post-data, values its column types reject; the schema comparison covers
   columns, sequences and types, not constraints) end the job `incompatible` with `DATA_REFUSED`
   「HA 的 Omnigent 資料不符合這台 Omnigent 的資料庫結構…」 (`load_into_new_cluster`): pg_restore's stderr only
   classifies the failure and is never shown or logged (it holds HA's row values); other failures stay as they were.
4. `omnigent-server-data`: the live export without `artifacts/**` plus HA's artifacts owned like the live artifacts
   folder (dirs 0755, files 0644, `accounts-cookie-secret` 0600: HA's session key replaces this device's, so HA's grants
   and tokens keep working and this device's browser sessions end); `omnigent-pi-data`: the live export as it is (the
   runner's identity, provider logins and pairings never move; the server's telemetry id never moves either).
   These live exports run while writers are active, even for a cold-mode catalog: they are not a consistent cold backup.
   Concurrent writes can produce torn or mutually inconsistent files; Headscale similarly exports headplane-data live
   and does not integrity-check hp_persist.db. B1-11 remains open: use a coordinated cold snapshot or pause all writers
   and verify the SQLite copy before claiming consistency; do not treat the converted archive as a cold backup.

**Hermes** (`woow-hermes` → `hermes`: volumes `hermes-data`, `hermes-redis-data`, database `main` of an unused
PostgreSQL 15).
1. Versions: add-on 0.1.10–0.1.14 → Hermes 0.22.5 (≤ 0.1.9 → 2026.8.31) must equal the tag of the live image's label
   `io.woowtech.hermes.base` (a different upstream digest is a warning); `config/.woow-image-version` must name the
   add-on version (missing: a warning); `state.db` `schema_version` ≤ 32 and `config.yaml` `_config_version` ≤ 51.
2. One pass over `config/**` (HERMES_HOME; `data/**` never) into the new `hermes-data` tar: every member owned by the
   Quadlet's `HERMES_UID`/`HERMES_GID` (10000 when unset), permission bits without setuid/setgid, the top folder as the
   live one; symlinks as link entries (relative ones staying in the tree; absolute ones only into `/opt/data`,
   `/opt/hermes`, `/usr`, clean); hard links as hard links to an earlier file of the tree written to the tar -- one to a
   file that does not move stops the job (`incompatible`); left out: `gateway.pid`, `gateway.lock`,
   `gateway_state.json`, `processes.json`, `cron.pid`, `.backup.lock`, `.woow-image-version`, `.woow-dotenv`, every
   `-shm`, `browser-profile(s)/`, `browser_profiles/`. HA's `.env` loses the lines of `API_SERVER_KEY`,
   `WEBHOOK_SECRET`, `HERMES_DASHBOARD_BASIC_AUTH_*`, `HERMES_DASHBOARD_PUBLIC_URL`, `HERMES_BASE_URL`, `HERMES_PASEO_*`
   (its other values are masked in the job's logs); the first start applies this device's hermes.env (no
   `.woow-dotenv`), whose keys win. Special configuration files and known SQLite files and sidecars must be regular
   files; cron must be a directory. An unknown state.db schema version is a blocker. Programs for another processor than this device's, a
   damaged known SQLite file are blockers. The known databases (`state.db`, `kanban.db`, `response_store.db`,
   `runs_idempotency.db`, `shared-state.db`, `projects.db`, `cron/{executions,notepad}.db`) move unchanged with their WAL
   and are checked by the sandboxed child (`quick_check`; `state.db`: sessions, messages, schema version).
   Warnings: HA-only hosts in `config.yaml`/`.env` (hosts only), `/media/` references, plugins (they replace this
   device's and need re-pairing). HA's /media is never moved.
3. `hermes-redis-data`: its top folder only, owned like the live one; database `main`: the live database's dump
   (`adapter._dump_database`, read while it runs: nothing uses it).

**EMQX** (`woow-emqx` → `emqx`: volumes `woow_emqx_data`, `woow_emqx_log`).
1. Versions: add-on 5.8.9, 5.9.0, 5.9.1 → EMQX 5.8.9 (pinned by the add-on's Dockerfile) must equal the live image's
   `org.opencontainers.image.version`.
2. One pass stages `data/emqx/data/{mnesia/**, configs/cluster.hocon, certs/**, authz/**}` root-owned (certs 0600) into
   a throwaway volume and reads `data/emqx/node.name`; never the cookie, generated `app.*.config`/`vm.*.args`, plugins,
   patches, backups, traces or logs. The node is `node.name`, else the single `mnesia/*@*` folder (several without
   `node.name`, none at all, or a name without its folder: a blocker).
3. HA's broker: the live image, `--network none`, a read-only root, user 0 (as on HA), HA's node name (`--add-host
   <host>:127.0.0.1` when its host is not an IPv4 literal), the staged volume at `/data/emqx/data` mounted
   `rw,noexec,nosuid,nodev` (`EMQX_NODE__DATA_DIR`), the image's `VOLUME` paths `/opt/emqx/data` and `/opt/emqx/log`
   on this job's own volumes, also `rw,noexec,nosuid,nodev` (a path no mount covers would get an anonymous volume that
   `podman rm` keeps on the device), an empty `EMQX_DASHBOARD__DEFAULT_PASSWORD` (nothing is created at
   boot); ready when `emqx ctl status` says "is started" (300 s). `emqx eval` of fixed expressions answers
   whether admin/public still logs in (a blocker), the table counts (a table every 5.8.9 broker has missing: HA's
   database did not load completely, refused), root names, authenticators and authorization
   policy; then `emqx ctl data export --root-keys <DATA_ROOTS present> --table-sets builtin_authn,builtin_authz,banned,
   dashboard_users,api_keys,psk,builtin_retainer --dir /work/out` (settings such as listeners, dashboard, node, log,
   mqtt, zones are never exported).
4. This device's broker (the candidate). Read first from the running broker as the owner, with fixed `emqx eval`
   expressions: its effective RAW configuration (`emqx:get_raw_config([])`, never cooked defaults), `EMQX_ETC_DIR`
   (must be `/opt/emqx/etc`; vendor rel/emqx_vars, bin/emqx) and the no-follow state of `data/configs/cluster.hocon`.
   Supported, else `incompatible` with a message naming what (the check reports the same message as the app's
   blocker; a stopped broker is named too): authorization sources exactly `[file]` or `[file, built_in_database]`, both
   enabled, in that order (EMQX 5.8.9 allows one source per type, emqx_authz.erl check_dup_types); a file ACL at
   `${EMQX_ETC_DIR}/acl.conf` (resolved with the verified directory, as the vendor's `naive_env_interpolation` does),
   an absolute path or a data-volume path under `authz/`, `configs/` or `certs/`, on exactly one read-only mount or in
   the data volume; the built-in password database's bootstrap file on a read-only mount or a `type=mount` secret (mode
   0400/0440); the image's own TLS files (fingerprinted); only configuration roots whose file dependencies were
   reviewed for 5.8.9. The data volume's `configs/cluster.hocon` and the data-volume files the configuration names are
   snapshotted (an override that is absent stays absent, proven by a complete volume traversal); configuration and
   override state are read again afterwards and must be unchanged. The candidate is the live image with the Quadlet's
   `EMQX_*` environment, its `EnvironmentFile=` files (in the owner's home, plain `EMQX_*` lines only, read by podman
   itself with `--env-file` as for the running broker: their values never appear in a command line, which every local
   account can read), its `Secret=` mounts and its read-only host files, the snapshot in an otherwise empty data
   volume and the export (owned by the image's emqx user) at `/work/in`. It starts with this device's scheduler
   counts (fixed `emqx eval` of `erlang:system_info(schedulers)` and `schedulers_online` on the running broker,
   passed as `ERL_AFLAGS="+S total:online"` at the start of the command line; `ERL_FLAGS` would land after the
   `-emqx_data_dir` that bin/emqx reads back from `ps`, bin/emqx:570,1321-1324): a boot stores schema defaults derived from them in
   the raw configuration (Dashboard listeners' `num_acceptors` = online schedulers, emqx_dashboard_schema.erl:125-131;
   node pool sizes, emqx_conf_schema.erl:688-706) and the candidate runs under `--cpus`. Before anything is imported
   its scheduler counts, `EMQX_ETC_DIR`, effective configuration and image TLS fingerprints must equal this device's. `emqx ctl data import`
   must say "imported successfully". Then this device's settings come back: every root that is not HA data
   (`DATA_ROOTS`), and `authorization`, is loaded back exactly as it was (`emqx ctl conf load --replace`, no merge of
   stale fields); the bootstrap file of this device's built-in authenticator is re-attached to HA's matching
   authenticator. When this device authorizes with the file ACL only and HA's import enabled the built-in database
   source, that source is first disabled (EMQX 5.8.9 destroys an enabled source's table when it is removed) and the
   ACL table is proven unchanged by a native receipt (rows, bytes, sorted row hashes) before and after. HA's ACL rows
   only take effect through an enabled built-in database source and the import never adds or changes this device's
   sources (owner decision 2026-11-23 「C」): on a target that authorizes with the file ACL only, a backup with ACL
   rows (`emqx_acl` > 0 in HA's broker) is refused, `incompatible` with the owner's text 「Podman 上的 EMQX 沒有開啟
   『內建資料庫』權限，HA 的裝置權限搬過去不會生效，裝置會被拒絕。請先在 Podman EMQX 的管理頁「存取控制 → 授權」新增
   「內建資料庫」（排在檔案規則之後），再匯入。」: by the check as the app's blocker (nothing changed) and by the
   conversion, which reads this device's profile before anything runs and stops as soon as HA's rows are counted,
   before any candidate; the finished candidate must hold the profile read before the build. Security review
   2026-11-23: HA's broker runs with `EMQX_PLUGINS__STATES=[]` and the image's plugin folder pinned through the
   environment (it wins over cluster.hocon; EMQX 5.8.9 starts every enabled plugin at boot) and all its volumes
   `noexec,nosuid,nodev` (SR-1); after this device's settings came back the candidate is refused (`incompatible`,
   with a message naming what) when a data-volume file of this device's snapshot other than `configs/cluster.hocon`
   is not byte-identical (SR-2: HA's export inlines HA's file ACL and the import would rewrite this device's), when a
   value in the roots HA's import brought uses EMQX's `file://` secret loader (SR-3), when a migrated rule calls `jq`
   (SR-6: jq reads the broker's environment), or when an enabled authenticator other than the built-in database
   (`password_based`/`scram`) or an enabled ExHook server remains (SR-7: they receive every client's credentials).
   The final effective configuration must equal this device's in every preserved root; node, rpc and cluster never change; an enabled authenticator must remain (no
   anonymous login); every table holds at least HA's rows and at most HA's plus what the empty broker seeded. HA's
   API keys replace this device's. The candidate's fixed `emqx eval` reads are bounded at 120 s each (the vendor CLI
   itself waits without a limit, bin/nodetool); their output bounds are unchanged.
   Hot backups (addon.json `state` `started`: the add-on has no cold backup mode) are tried; when HA's broker does not
   start, a table is missing, EMQX's own export fails or the import reports errors, the job refuses (`incompatible`) with
   the advice to make a new backup with the add-on stopped -- never a silently incomplete result.
5. `woow_emqx_data`: that broker's volume export without `configs/app.*.config`, `configs/vm.*.args` (the cookie),
   `configs/*.bak`, `backup/**`, `trace/**`; `woow_emqx_log`: its top folder only, owned like the live one.
6. Readback (2026-11-23). Before the candidate stops, its readback goes into the converted backup's app section as
   `import_check` (section 5): a SHA-256 per root of its effective raw configuration (canonical JSON per root; first
   every value under a key containing password, passwd, secret, cookie, token or key, every value below `headers` and
   the user part of a `scheme://user@host` URL become one fixed marker, so the digests never carry this device's
   Dashboard password or Erlang cookie, which the raw configuration holds; security review SR-4) and,
   per table only an administrator changes (`emqx_authn_mnesia`, `emqx_authn_scram_mnesia`, `emqx_acl`, `emqx_admin`,
   `emqx_app`, `emqx_psk`, `emqx_banned_rules`), the row count and the SHA-256 of the sorted SHA-256s of the rows'
   external terms (one read-locked transaction per table; -1 for a table the broker does not have). Retained
   messages and the banned list move with clients and expiry and are only counted by the conversion. After a restore
   of that backup started the units and its health checks passed, the engine waits until `emqx ctl status` says "is
   started" (300 s) and reads the same values from the restored broker; any difference fails the restore with the
   names of the differing roots or tables (「EMQX 還原後的設定（…）和轉換時核對的不同…」), and the restore rolls back
   by itself; an equal readback logs 「EMQX 還原後核對一致…」. A section whose `import_check` this engine does not know
   (another kind or app) refuses the restore in its preflight, before anything changes. The digests are derived from
   data the same archive holds and never appear in a log or job record.

**Headscale** (`woow-headscale` → `headscale`: volumes `headscale-data`, `headplane-data`).
1. Versions: add-on 0.1.1–0.1.3 → Headscale 0.29.4 (0.1.0 → 0.29.3) must equal the live image's
   `org.opencontainers.image.version`; HA's `database_versions` row must name it and every applied migration must be one
   0.29.4 knows (gormigrate's `SCHEMA_INIT` mark included). HA's prefixes (`config/config.yaml`) must equal this
   device's and every node address must lie inside
   them.
2. One pass: `data/db.sqlite` (+ `-wal`, never `-shm`: an add-on killed before it checkpointed leaves all data in the
   WAL, seen on the RPi5, and the child applies it) staged, `data/noise_private.key` (`privkey:<64 hex>`, masked),
   `config/dns_records.json` (a JSON array of `{name, type, value}` strings, else a blocker), `config/config.yaml`
   (plain keys only, for the checks); never Headplane's data, API key, cookie secret, options or the image.
3. The sandboxed child reads HA's database (integrity, only Headscale's tables, no trigger or view, counts, version,
   migrations, node addresses) and, for the conversion, replaces HA's `api_keys` rows by the rows of an
   integrity-checked copy of the live database (taken from the live volume's export while it runs), in one transaction,
   then requires a completed WAL checkpoint and independently reopens the output, original and live copies to verify integrity, table counts and API key prefixes: the live Headplane and MCP admin keys keep working, HA's keys do not exist
   here.
   A live database-mode ACL policy blocks import, because HA's database policies replace it; file-mode policy remains configured.
4. `headscale-data` from scratch, owned like the live top folder: the converted database 0644 and HA's
   Noise key 0600 at the live config's paths (which must be within `/var/lib/headscale/`), HA's records at the live config's `dns.extra_records_path` when it lies in the volume
   (`[]` when HA has none; a warning when it lies elsewhere). Before packaging, `headscale configtest` of the live image
   (network none, read-only root, the live configuration read-only) opens a throwaway copy of that volume: version path,
   migrations and schema as the server will check them; failing it fails the job. `headplane-data`: the live export
   (this device's Headplane logins and roles stay).

**Batch 2: code-server** (branch `feat/ha-import-code-server-20261123`; `ha_codeserver.py`; owner decision 2026-11-23
「決定2 A」 = the facts' recommended answers D1 b, D2 a, D3, D4 a, D6; facts `phase3/facts/code-server.md`). Add-on
`woow_ha_code_server` → app `woow-code-server`: the container `code-server` (`keep-id:uid=1000`) with the volumes
`woow-code-server-pi-data` (at `/data/pi-agent`), `woow-code-server-ide` (at `/home/coder/.local/share/code-server/User`)
and `woow-code-server-extensions` (at `…/code-server/extensions`), and, when the catalog lists it (D1 b), the workspace
folder bound at `/workspace` (one data dir, the bind's path below the owner's home); another set of volumes or data
dirs is `incompatible`. No database server.
1. Versions (D6): the add-on version maps to the four programs that write the data (code-server, Pi, Claude Code,
   Codex; 0.1.6–0.1.15 all code-server 4.139.1, Pi 0.99.1, Claude Code 2.1.285, Codex 0.167.0 from 0.1.8, none before),
   and each must equal what the live image prints: `--version` of each in one throwaway container of the live image
   (entrypoint `/bin/sh`, network none, nothing pulled). An unknown add-on version, a program that differs or cannot be
   read is a blocker; a program the add-on did not ship is not compared.
2. One pass over `data/pi-agent/**`, `data/vscode/User/**` and `data/vscode/extensions/**`; never handed out (NEVER_READ or
   excluded from the walk): `options.json`, `pi-agent/{auth.json, mcp-auth.json, claude/.credentials.json,
   codex/auth.json}`, `.ssh/`, `git/`, `.zsh_history`, the legacy `claude/`, `woow-connectors-primary/`,
   `pi-agent/{connectors, connectors-primary, omnigent}/`. `share.tar.gz` is read only for `projects/**` and only when
   the catalog lists the workspace.
3. Moved, HA's entry wins (the IDE volume): `keybindings.json`, `tasks.json`, `mcp.json`, `chatLanguageModels.json`,
   `snippets/`, `globalStorage/` (without `globalStorage/woowtech.{paseo,omnigent}`, the connector extensions' state, D3),
   `History/`, `profiles/`, `prompts/`; `settings.json` merged (JSON with comments and trailing commas accepted, written
   back as plain JSON): this device's settings, HA's keys over them without the HA-only values that break here
   (`terminal.integrated.defaultProfile.linux` `zsh`, zsh terminal profiles, the Prettier default formatter,
   `[home-assistant]`/`[esphome]` blocks and `files.associations` to those languages), this device's
   `security.workspace.trust.*` and `extensions.autoUpdate`, and `acp.agents` = this device's agents plus HA's other
   ones. Left: `workspaceStorage/`, `caches/`, `machineid`, `*ExtensionsCache.json`, `sync/`, `logs/`.
4. Moved, this device's entry wins (the agents' volume): `sessions/`, `skills/` (a folder `skills/<name>` that this device
   has stays whole, HA's is skipped and named), `claude/projects/`, `claude/file-history/`, `codex/sessions/`,
   `codex/archived_sessions/`, `settings.json`, `models.json`, `codex/session_index.jsonl`,
   `home/.pi/pi-acp/session-map.json`; `claude/history.jsonl` merged by `timestamp` (each line once; this device's file
   stays when either side is not JSON lines or both exceed 32 MiB); `shared/mcp.json` merged (D4 a: HA's servers added, the
   same name stays this device's; servers with `headers`/`env` and HA-only hosts in their URLs are named for review,
   never their values). Left: the logins (D2 a) and `claude/.claude.json`, `codex/config.toml`, `mcp.json`, `trust.json`,
   `.woow-pi-store`, `*.before-*`, `bin/`, `npm-global/` (programs), every other file below `claude/`, `codex/`, `home/`,
   `shared/` (caches, locks, state databases); another top-level name with files in it is left with a warning naming it.
5. Extensions: HA's extension folders listed in its `extensions.json`, except the connector VSIX (`woowtech.*`), the ids
   this device has, `targetPlatform` for another processor and folders with a program for another processor; this
   device's `extensions.json` gains them with `location.path` below this device's folder (an unreadable list moves none).
6. Moved SQLite files (header `SQLite format 3`) are staged with their `-wal`/`-journal` (never `-shm`) and quick-checked by
   the sandboxed child (`hasqlite`); a damaged one stays in HA (a warning).
7. Every moved member is owned like the live volume's top folder, permission bits without setuid/setgid; symlinks as link
   entries when relative and inside their own tree (others skipped and counted); hard links only to an earlier moved
   file (one to a file that does not move: `incompatible`). Each volume is then completed from a live export (read while
   the app runs; not a cold snapshot) with its owners and modes; a folder both sides have keeps the live owner and mode;
   a kept hard link to a replaced file stops the job (`job-failed`). The workspace dir tar is the live folder pack plus
   HA's `projects/**` in a new folder `ha-projects-<HA backup date>` (a suffix when the name exists), owned like the live
   folder's root. Secrets (`code-server-config`), `woow-code-server.env` and units are the live ones (packaging below).
   Test mode changes nothing of code-server (it runs no scheduled work).

**Batch 2: add-ons that are not moved** (page only). The Cloudflare Tunnel (`*_cloudflared`; facts `cf-tunnel.md` D1 a:
its token, certificate and PaaS link belong to the tunnel it serves, and its routes are in options this engine never
reads or in Cloudflare) and the WOOWTECH MCP admin add-ons (`*_woow_mcp_<product>`; facts `mcp-admin.md` verdict: their
state is HA's credentials and URLs) stay `other_addons`. The HA backup page and the wizard's first step say for each
what to do here: re-add every route on this device's tunnel with this device's services and re-link WOOW PaaS, then
remove the routes from HA and stop HA's add-on; re-configure the product's MCP admin app here (this device's catalog
name, or install it), stop HA's add-on and re-create the MCP connectors with this device's MCP address.

**Batch 2: Nextcloud** (`woow-nextcloud-office` → `nextcloud`: data dirs `.local/share/nextcloud-office/{postgres,redis,
html,data}`; facts `phase3/facts/nextcloud.md`, owner decisions D1-D5 applied with their recommended answers).
1. Where the data is: the add-on member holds the PostgreSQL 16 cluster (`data/postgres`), `data/nextcloud/config/config.php`
   and the app-store apps (`data/nextcloud/custom_apps/<id>`); the users' files are Nextcloud's `datadirectory` (default
   `/share/nextcloud`): `/share/<p>` is read from the share folder member (`share.tar[.gz]`, only `<p>/**`), `/data/<p>` and
   `/config/<p>` from the add-on member (never overlapping the add-on's own items); anything else (a network mount, /media)
   is a blocker. No share folder in the backup → blocker 「這份 HA 備份沒有包含 share 資料夾，Nextcloud 的使用者檔案（…）不在
   備份裡…」; a data directory missing from it or without its `.ncdata` → blocker. Never read: `data/options.json`, HA's
   `apps.config.php`, Redis and Collabora data, `config/**`, everything of the share folder outside the data directory.
2. config.php is PHP code and is never run by the engine: a strict parser accepts only what Nextcloud's var_export writes
   (one `$CONFIG = array (...)`; arrays, single-quoted strings, numbers, booleans, null; comments skipped); anything else is
   a blocker. Versions: HA's `version` (4 parts) must equal the live config.php's and its first three parts the live
   image's `NEXTCLOUD_VERSION`; both `installed`; HA not in maintenance; `dbtype` pgsql; table prefix `oc_` on both sides;
   no object storage; server-side encryption (an `oc_appconfig` flag or `files_encryption` folders: decision D4),
   symlinks in the data directory and a `.htaccess` anywhere below its top (「HA 的 Nextcloud 使用者檔案裡有 … 個網站伺服器
   設定檔 .htaccess…」: here the data dir is inside Apache's web root with `AllowOverride All`, so one could publish a folder
   or run files as programs; Nextcloud never creates nor accepts one) are blockers. The add-on version (0.2.3/0.2.4 →
   35.0.1) is shown only.
3. check: the cluster is streamed into a throwaway volume and opened by a throwaway PostgreSQL 16 exactly like Odoo's
   (§9 Odoo 1; the files of an online backup, `backup_label` and `tablespace_map`, are never streamed: blocker 「HA 的
   Nextcloud 資料庫不是在停止狀態下備份的…」, the cluster is not started); the database named by HA's `dbname` must hold Nextcloud's
   tables, only the plpgsql extension, no other schema, and the root storage `local::<HA datadirectory>/`
   (lib/private/Files/Storage/Local.php `getId`; longer than 64 bytes → its md5), and no row may already have an id this
   device's data directory needs (blocker 「HA 的 Nextcloud 資料庫裡已經有這台使用者檔案資料夾（…）的儲存空間記錄…」). Every session in
   HA's cluster carries
   PGOPTIONS `-c search_path=pg_catalog` (a client setting: above HA's per-database and per-role settings; no function,
   operator or table of HA's can stand in for a built-in). HA's catalogs are read first (`SHAPE_SQL`, extension members
   not counted): any function, procedure, aggregate, operator, type or domain, trigger, rule, policy or row security,
   event trigger, view or other relation kind than table/sequence/index, CHECK or exclusion constraint, generated
   column, inheritance, collation, conversion, text search object, operator class/family, cast, foreign server, user
   mapping, publication, large object, default privilege, transform, extended statistics or tablespace, or a column
   default that is neither a constant nor `nextval()` → blocker 「HA 的 Nextcloud 資料庫含有 Nextcloud 不會建立的資料庫物件（…），無法安全地搬過來。」
   and HA's tables are not read at all (an unreadable shape → blocker too); a genuine Nextcloud 35.0.1 database has none
   of them (dev-e, 2026-11-24). Known app that creates some: Memories (pulsejet/memories lib/Db/FilecacheTriggers.php:
   function `memories_fcu_fun`, trigger `memories_fcu_trg` on `oc_filecache`): an HA Nextcloud that had it is refused. Counts (users, file cache, shares, tokens, calendar objects, contacts, storages, mounts,
   external mounts) are read; per user the database's file list (home storages, `files/**`: number, bytes and an
   order-free md5 digest of size and path, `FILES_SQL`) is compared with the files in the backup (HA archives the share
   folder after the add-on runs again): a difference is a warning and a reminder with the command `podman exec -u
   www-data <app container> php occ files:scan --all`, not a blocker (not compared when the data directory holds hard
   links). This device's own database is read as its superuser with `search_path = pg_catalog` (nothing the Nextcloud
   role could create in `public` stands in for a built-in). Warnings besides: apps HA enables that exist nowhere here,
   HA custom apps whose info.xml excludes this Nextcloud or PHP version or that hold programs for another processor,
   local external storages (outside the data directory), HA config keys that do not move (names).
4. convert: `pg_dump -Fc`; a NEW cluster from the live database image, environment and secret; the live config.php's
   `dbuser` role (e.g. `oc_admin`) with the LIVE attributes and password verifier (stdin, masked) and the grants
   Nextcloud's installer gives it (lib/private/Setup/PostgreSQL.php: `GRANT CONNECT`, `REVOKE ALL … FROM PUBLIC`, `GRANT
   CREATE ON SCHEMA public`), the live extensions (`vector`); the dump restored as that role (`--no-owner --no-acl
   --exit-on-error --single-transaction`, no EXTENSION entries, superuser-only objects refused, and refused before
   anything is restored when its `pg_restore -l` list holds a kind outside TABLE, TABLE DATA, SEQUENCE, SEQUENCE SET,
   SEQUENCE OWNED BY, DEFAULT, CONSTRAINT, FK CONSTRAINT, INDEX, COMMENT, ACL, EXTENSION, unknown kinds included: 「HA 的
   Nextcloud 資料庫匯出檔含有 Nextcloud 不會建立的物件（…）」). From the restore on every session in the new cluster is pinned the same
   way; its superuser reads catalogs only (the `SHAPE_SQL` refusal again, now also any per-role or per-database setting)
   and every statement on HA's tables (the fix-ups, the counts, the kept settings) runs as the Nextcloud role itself, so
   nothing of HA's ever runs with more rights than Nextcloud has. Fix-ups in one transaction: the root storage id →
   `local::<target datadirectory>/`, and the id of every local storage below HA's data directory the same way (the Team
   folders app keeps one per folder, `local::<datadirectory>/__groupfolders/<id>/`, and names it by its number:
   groupfolders 23.0.2 lib/Mount/FolderStorageManager.php; ids over 64 bytes are stored as their md5); `richdocuments` `wopi_url`, `public_wopi_url`, `wopi_callback_url`,
   `wopi_allowlist`, `disable_certificate_verification` and `core.backgroundjobs_mode` exactly as the live database has
   them (Office uses this device's Collabora); HA's cached Collabora answers
   (`appdata_<instanceid>/richdocuments/remoteData`, `discovery` and `capabilities`) are replaced by this device's own
   cached files (their file cache rows deleted; Nextcloud adds files it finds), because the Office app never fetches
   them on demand (12.0.1 lib/Service/CachedRequestService.php `get`; without them every document is an HTTP 500), and
   the hourly job that refreshes them (`OCA\Richdocuments\Backgroundjobs\ObtainCapabilities`) is made due at once in
   `oc_jobs`; this device without those files → a reminder with `occ richdocuments:activate-config`. Verified: every
   count (file cache minus those rows), table owners = the role, the role's attributes (never superuser) and password
   verifier, the root storage id and every moved storage id, roles, extensions, database and public-schema grants and
   the kept settings equal the live ones, no database besides `postgres`, `template0`, `template1` and Nextcloud's, no per-role or per-database setting,
   no table or column grant (the dump is restored with --no-acl, so one can only come from SQL hidden in it). Live
   PostgreSQL settings are carried (§9 Odoo); clean stop, `pg_controldata` "shut down"; the PostgreSQL dir is the volume
   export with its top folder owned like the live one.
5. config.php = the live one (base: URLs, trusted domains, proxies, database credentials, data directory, caches, mail,
   maintenance window) + HA's `instanceid`, `passwordsalt`, `secret` + HA's `twofactor_enforced*` and
   `app_install_overwrite` (D1; the three two-factor keys are one policy, MandatoryTwoFactor.php: all of HA's, or all of
   the live ones when the live enforcement is stricter: HA enforces nothing, or leaves someone out where the live one is
   for everybody) + a new `data-fingerprint` (md5 of the time, as `occ maintenance:data-fingerprint` writes it; the
   package's own restore runs that command, scripts/restore.sh:76: sync clients then treat the server as restored and
   keep local files it lacks), written in Nextcloud's format with the live file's owner and mode; before packaging the
   live image's PHP (throwaway container, network none, read-only root, the file on stdin) must lint it and return
   exactly the merged values. html dir = the live pack without `config/config.php` and without the custom apps HA
   brings, plus the merged file and HA's custom apps (D2; owner www-data of the live image); data dir = HA's data
   directory (owner www-data, HA's modes, top folder like the live one; the web updater's own `updater-<instanceid>`
   skipped, previews kept: D5) with
   Nextcloud's own `.htaccess` (Setup.php `protectDataDirectory`, deny all) written at its top instead of HA's, whether
   HA had one or not (HA's data directory is outside its web root, here it is inside); Redis dir = its top folder only,
   owned like the live one. Every dir tar is checked like a restore reads it.
6. Notes and reminders: the users, files, shares, calendars, contacts and app passwords become HA's; the URL, database
   password, mail and Office settings stay; HA's custom apps; stop the HA add-on for good (same instance identity); log in
   with HA's accounts and point sync, CalDAV and CardDAV clients to this device's URL; the new data fingerprint (sync
   clients keep their local files); public links and federated IDs
   still name HA; mail settings did not move; a file scan when HA's file lists and files differ; Office not enabled on HA;
   the MCP lines for `nextcloud-mcp-admin` and
   「Woow Nextcloud MCP Server」 (`engine_mcp_lines`). Test mode changes nothing else for Nextcloud.

**LiteLLM** (`woow-litellm` → `litellm`: one `postgres` item `main`, container `litellm-postgres`, database and user
`litellm`; the proxy container `litellm` reads secret `litellm-salt-key` as `LITELLM_SALT_KEY`; owner decision 2026-11-23).
1. Versions: add-on 0.1.15 → LiteLLM 1.104.0 must equal the running proxy's `importlib.metadata.version("litellm")`
   (`podman exec litellm`, read only); HA's `data/woow/state.json` `litellm_version`, when present, must say the same;
   HA's finished Prisma migrations must be exactly the live database's. HA's PostgreSQL is 18 (`PG_VERSION`), this
   device's 17: the only importer that moves data to an older major, and only as rows (3).
2. One pass: `data/postgres/**` through `ha_odoo.PgSink` (configuration replaced, recovery/pid files dropped; a symlink
   such as a tablespace refuses), `data/secrets/salt_key` (one small regular file, `^[A-Za-z0-9_-]{16,256}$` after
   strip, masked at once), `data/woow/state.json`; never `options.json`, the master key, the UI or database password
   files, the pre-upgrade dumps. HA's cluster runs in the official PostgreSQL 18.7 image pinned by content
   (`PG18_IDS`; else `PG18_PINNED` is pulled by digest and must give one of them), hardened like Odoo's (read-only root,
   network none, noexec data volume at the image's VOLUME path, every library/command setting overridden, event
   triggers off). HA's per-database and per-role settings beat the command line, so every session the engine opens
   there sends its own client options, which beat them (`HA_SESSION_OPTIONS`; the superuser's also
   `HA_SUPERUSER_OPTIONS`): names resolve in `pg_catalog` only, the rows are exported in fixed formats like pg_dump's,
   no preload library, no event trigger (review SR-1..SR-3); `public._prisma_migrations` is read only as an ordinary
   table; `backup_label` and `tablespace_map` never reach the volume and refuse (a cold backup has neither; SR-4). The salt
   must be the one HA's database is bound to (`woow_platform.settings` and the `woow.meta` fingerprint, read by a role
   without privileges): else `incompatible` -- nothing stored could be decrypted. HA's database: only `public`,
   `woow_platform` and `woow` (with `meta` only), no object only a superuser creates, no large object, UTF8; its data
   shape (columns, sequences, types of `public` and `woow_platform`) must equal the live database's. Every session
   that reads the columns or the schema signature -- HA's cluster, the live database, the schema snapshot and the new
   cluster -- pins `search_path = pg_catalog` in the query itself (`PIN_SEARCH_PATH`), so type names and expressions
   render alike on every side (an enum column is `public."JobStatus"` everywhere; without the pin HA's pg_catalog-only
   sessions and this device's default ones differed, real attempt 7).
3. Convert: this device's schema is captured like Omnigent's (one exported snapshot of the live database: migrations,
   columns line, `pg_dump --schema-only`; the live signature before == after == the snapshot's columns, else
   `incompatible` and nothing changed); a NEW cluster from the live `litellm-postgres` image, environment and secret
   mount gets its pre-data section; every trusted table's rows are copied as `COPY "<schema>"."<table>" (<trusted
   columns>) TO STDOUT` in HA's cluster and `... FROM STDIN` in the new one by `woowbk_restore` (INSERT and sequence
   values only), each trusted sequence value is set by it, then the post-data section (HA's rows must satisfy this
   device's constraints). The new cluster's signature equals the live one after the post-data section and after the
   last write, it holds only its bootstrap superuser (no role or database setting, ALTER SYSTEM value or large object),
   every table's count and the migrations equal HA's, and the salt row it got equals the salt that moves. Its
   `pg_dump -Fc` (read in full once) is `postgres/main.dump` (PostgreSQL 17); HA's salt is the item's
   `secrets{litellm-salt-key}`. `test_mode` changes nothing for LiteLLM.
4. What stays: the master key, UI password, database password and URL (the other four secrets, read live),
   `config.yaml`, `litellm.env`, the Quadlet files. The restore's safety backup holds the old salt and database, so an
   automatic rollback or a later restore of it puts both back. This device's virtual keys are replaced by HA's: the
   check's `key_users` and a note/reminder name the other catalog apps whose declared config files or Quadlet files set
   a LiteLLM key or address, whose networks LiteLLM's drop-in `local-agent-networks.conf` joins, or whose Pi agent
   provider list (`models.json` in the volume a `.container` mounts at its `PI_CODING_AGENT_DIR`, default
   `/data/pi-agent`: pi-web, Omnigent's runner; read as the owner, inside the owner's home only, only the verdict kept)
   has a provider whose base URL is this device's LiteLLM (nothing else changes).
   HA's stored proxy settings (`LiteLLM_Config`) move with the rows and take effect here (`store_model_in_db: true`:
   stored environment variables are decrypted with the moved salt into the proxy's environment, callbacks are loaded):
   the check warns and a note names the stored environment variable names and callback names (never a value; review
   SR-5). Stored settings LiteLLM imports and calls as code refuse (SR-6; LiteLLM's `get_instance_fn` imports any
   dotted path): `post_call_rules`, the `general_settings` `custom_*` hooks, a callback whose name has a dot, a string
   `callbacks` value, `custom_provider_map[].custom_handler`, a dotted guardrail callback or type (`guardrails` v1 and
   v2 shapes), a dotted `pass_through_endpoints[].target` that is not `scheme://…`, `litellm_jwtauth.custom_validate`,
   `router_settings.plugins` and a `key_management_settings.custom_secret_manager` (the vendor's own DB-overlay list
   plus the router plugins and the custom secret manager file it misses); a dotted callback is found by the query
   itself, however many plain names come before it. The check's blocker names them (labels only) and the conversion
   stops before reading HA's rows or capturing this device's schema. An answer that cannot be read completely (over the output limit, a timeout, not an object) refuses too
   (fail closed). Because HA's data directory controls its throwaway cluster's catalog, the conversion asks the same
   question again in the new cluster after HA's rows are loaded (this device's image and schema, HA's data only as
   rows) and refuses there before the converted dump is written; the import note names what that answer found (SR-8).

**Packaging**: per app `adapter.import_manifest` adds the live non-data items exactly as a backup reads them (images
list, secrets, config files, Quadlet files, `catalog_entry`, `catalog_sha256`), so `match_items` finds every item and
the restore's settings check says `same`; then `flows._package` (§8 "Home Assistant import jobs"). A conversion's
`secrets{name: file}` (LiteLLM's salt) replaces that one live secret; it must be declared by the catalog and be one
regular file of 1..511999 bytes.

**Batch 2: OpenDesign** (branch `feat/ha-import-opendesign-20261123`; `ha_opendesign.py`; owner decision 2026-11-23
「決定2 A」; facts `phase3/facts/opendesign.md`). Add-on `woow_ha_opendesign` (its slug holds `_`: the member is found by
the slug after the repository prefix and must carry `system.slug` `woow_ha_opendesign`) → app `open-design`: volumes
`open-design_open_design_data` (at `/app/.od` of the `open-design` container, `keep-id`) and `open-design_mcp_data`
(at `/data/mcp`); no database server (the daemon keeps `app.sqlite`, WAL mode, and plain files).
1. Versions: the data has no version stamp and the daemon migrates `app.sqlite` forward silently, so the add-on version
   maps to the WoowTech fork revision of the OpenDesign core it ships (0.2.15 → OpenDesign 0.24.1, fork
   `05b23f5a5259d4f2c22e5c6e3eb92ce9103ed34a`) and that revision must equal the live image's label
   `io.woow.opendesign.source-revision` (a shorter label must be a prefix of it); `OD_APP_VERSION` of the image is
   shown. An add-on version the table does not know, a missing label or another revision is a blocker.
2. One pass over `data/opendesign/**` (never `data/mcp/**` nor `data/options.json`). Moved (owner decisions O4, O5 =
   the facts' recommended answers): `app.sqlite` with `-wal`/`-journal` (never `-shm`), `projects/ runs/ artifacts/
   chat-artifact-blobs/ critique-artifacts/ design-systems/ design-templates/ brands/ library/ memory/ skills/ plugins/
   connectors/`, `mcp-config.json` (every `/data/opendesign` path in its strings remapped to `/app/.od`; the entries
   this device's integrations write themselves, `woow-paseo` of the Paseo runtime, are never taken from HA: this
   device's entry stays, O2),
   `mcp-tokens.json`, `mcp-oauth-clients.json`, `media-config.json`, `app-config.json` (HA's preferences with this
   device's `installationId`, `agentCliEnv`, `agentCliEnvIntent`; project locations and recent folders below
   `/data/opendesign` remapped, others dropped with a warning), and HA's `shared/workspaces/**`, `shared/skills/**`
   copied inert. Left out: `home/` (agent logins, O1), `paseo/`, `integrations/` (Paseo pairing and Omnigent host
   identity, O2), `installation.json`, `diagnostics/`, `od-next-run-inputs/`, `od-next-task-inputs/`, `agent-runtime/`,
   `export-render/`, `export-pdf/`, `credentials`, `.backup/`, `shared/mcp`, `shared/plugins`. Another top-level entry
   with anything but directories in it is a blocker. Special files must be regular files (folders directories).
   Every moved member is owned like the live volume's top folder, permission bits without setuid/setgid; symlinks as
   link entries when relative and inside the tree (others skipped and counted); hard links only to an earlier moved
   file (one to a file that does not move stops the job, `incompatible`). Warnings: programs for another processor in
   the moved trees, skipped symlinks, HA-only hosts in the moved settings, projects imported from a folder
   (`metadata_json.baseDir`; they will not open here), dropped preferences, active routines (they run here).
3. The sandboxed child (`hasqlite`) opens `app.sqlite` with its WAL: `quick_check`, the counts of `projects`,
   `conversations`, `messages`, `routines`, the folder projects and the active routines (fixed queries
   `opendesign.project_folders`, `opendesign.routines_active`); a damaged database or one without `projects` is a
   blocker.
4. `open-design_open_design_data` from scratch: HA's moved tree, plus from a live export of the volume (read while the
   daemon runs, like Odoo's web data; not a cold snapshot) this device's `home/`, `paseo/`, `integrations/`,
   `installation.json`, `export-render/`, `export-pdf/` (and its `app-config.json` when HA has none that can be used)
   with their live owners; a kept hard link to a replaced file stops the job. `open-design_mcp_data`: the live export,
   unchanged (O3: this device's MCP token and tool grants stay). Secrets (`open-design-api-token`, the htpasswd),
   `open-design.env`, nginx files and units are the live ones (packaging below).
   Test mode changes nothing of OpenDesign (its routines are not paused; the reminder says so).

## 10. Security rules (reviewers will check each)

1. Helper refuses to run unless `euid == 0`; entrypoint checks its library dir is root-owned and
   not group/world-writable before importing.
2. No `shell=True`; fixed argv; validated names; sanitized env (`PATH`, `LANG=C.UTF-8`).
3. Owner operations via `runuser -u <owner> --` with `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS`;
   root never opens paths inside an owner's home.
4. Secrets/keys never in argv, environment, logs, job records or error messages.
5. Untrusted archives handled per §5; local catalog is the authority per §4.
6. `download-info` only returns paths inside `archives/`; uploads only into helper-generated
   `uploads/<upload_id>.part`; `upload-finish` rejects symlinks/non-regular files/size mismatch.
7. Staging contains plaintext; it is 0700 root and removed in `finally`; residual risk documented.
8. All JSON inputs strictly validated (types, lengths, enums, regexes); unknown keys rejected. This includes what
   the owner-side helpers print: the directory helper runs in a namespace the owner controls (§6).
9. Host directories: root never opens a path in an owner's home (it only reads `statvfs`/`stat` of the home itself);
   all directory work runs as the owner in his namespace, without following symlinks, without crossing into another
   mount, and never deleting the only copy of a directory's earlier content.
10. Instance mode: the archive's `pg_dumpall` script never reaches psql unchecked (`adapters.quadlet_postgres.
   globals_statements`): it is scanned the way psql scans it — standard string literals only (a quote must follow
   whitespace, `(`, `,` or `=`, so `E''`/`U&''` are refused), double-quoted identifiers without newlines, `--` comments;
   a backslash outside them (a psql meta-command such as `\!`), `/* */`, `$` dollar quoting and NUL are refused; the
   `\restrict`/`\unrestrict` lines PostgreSQL ≥ 16.10 writes are dropped (older psql does not know them); every statement
   must be one of the three `SET`s pg_dumpall writes, `CREATE ROLE`, `ALTER ROLE`, `GRANT`, `REVOKE` or `COMMENT ON
   ROLE`. Keywords compare without regard to case; `&` outside quotes (`U&"…"` identifiers), the role names
   `CURRENT_USER`, `SESSION_USER`, `CURRENT_ROLE`, `ALL` and `PUBLIC` as the target of `CREATE`/`ALTER ROLE`,
   `ALTER ROLE … RENAME` and role settings that load server code (`session_preload_libraries`, `local_preload_libraries`,
   `shared_preload_libraries`, `dynamic_library_path`, `jit_provider`) are refused -- pg_dumpall writes none of them --,
   and after the script a new session of the restore's role must still be a login superuser that is not read-only
   (review L2, F8). The same check runs on the backup's own output, so a backup a restore would refuse is not made. Database
   names are checked before they reach argv (`-d`), and `DROP DATABASE` only ever names a checked name. The globals entry
   holds password hashes: it gets the treatment of the secrets (encrypted archive, never logged or shown).
11. Digest listings and psql's JSON come from places the owner controls: parsed strictly and bounded (§6; a files
   listing at most 1 GiB whatever the free space, review M4); they can only make the owner's own restore pass or fail its
   comparison. The SQL digest runs as the catalog's database user -- a superuser in instance mode, usually the bootstrap
   superuser otherwise -- over tables other roles own: it may run nothing they can define. It hashes
   `pg_catalog.record_out(t.*)` (a cast from a table's row type to `text`, which any table owner can create, ran as that
   superuser with `t::text`: `COPY … TO PROGRAM` from inside the read-only transaction, reproduced in the lab; review
   H1), all functions and operators resolve in `pg_catalog` (`search_path`), and only ordinary tables and sequences are
   read (no views, foreign tables or partitioned parents).
12. Format 2: `backup.json` and `README.txt` are untrusted display data. Nothing a restore writes comes from them: the
   authenticated per-app manifests decide, and any difference between them and `backup.json` is `corrupt-archive`.
   `backup.json` never holds secrets, the device recipient or a machine id (names only). A file that claims to be
   unencrypted is treated as unauthenticated wherever it did not come from this device's own jobs: its preflight warns
   and a restore needs `accept_unauthenticated`.
13. Unencrypted data at rest and in transit is always an explicit administrator decision with the zh-TW warning
   `settings.PLAINTEXT_WARNING` acknowledged in the request (`settings-set`, `backup-start` while the setting is on,
   `export-start` with `confirm`); a settings file that is missing, damaged, not root-owned, writable by others or a
   symlink means **encrypted**. Unencrypted copies are root 0600 in a root 0700 directory, served only through
   `export-info` paths inside `exports/`, deleted after 15 minutes, and every request, creation, download and deletion is
   in the journal (eviction and expiry noticed by `export-info` included; review F17). Unencrypted backups made here live
   in `archives/` like encrypted ones (root 0700); downloading one (`download-info`) and deleting any backup (`delete`) are
   journaled too (review L6).
14. Deep verify: nested content is checked one entry at a time in a root 0700 scratch directory inside the job's
   staging, each copy deleted right after its check (staging is removed in `finally` and by the recovery); the copies
   leave the larger reserve of a job that runs while the apps keep running free (§8, review M4).
15. `catalog-suggest` never opens a path in an owner's home as root and never reads environment files; it returns no
   `Environment=` values (except PostgreSQL user/database identifiers) and no `HealthCmd=` text; the owner-side answer is
   validated like the directory helper's (§6).
16. Catalog entries change only through `catalog-install`/`catalog-remove` with the checks of §4 ("Installing and
   removing entries"); every change keeps the previous entry and is audited in the journal. Retention deletes only
   unprotected backups, only after an explicit confirmation (`retention-apply`) or a policy the administrator saved,
   and audits every deletion.
17. 排程備份: the timer's service runs the helper with the fixed argv `schedule-tick`, no input and `python3 -I`; the
   tick decides only from root-owned files (`schedule.json` trusted like `retention.json`: root-owned, not group/world
   writable, no symlink, ≤ 16 KiB, strictly validated, unknown keys rejected; `schedule-state.json` root 0600 in the 0700
   data directory) and starts jobs only through `start_job` (dedup, busy, recovery), like the page. A bad settings file
   only stops the schedule; a bad state file stops it and every automatic deletion and is never overwritten. The
   schedule's rule deletes only scheduled backups beyond `keep_last`, with every protection of the manual policy, after a
   successful or partial scheduled run. Turning the schedule on while 預設加密備份 is on needs the device key and a
   confirmed emergency kit. Every settings change, run, wait, skip, missed slot, result and deletion is journaled. The
   installer names only `woowtech-cockpit-backup-schedule.timer` in systemctl argv, only on the live root, never runs
   `systemd-analyze verify`, and the unit names stay outside `woowtech-backup-*`.
18. Home Assistant backups (branch feat/ha-import) are hostile input read only by the strict readers of §5: nothing of
   them is ever extracted with tarfile or GNU tar, every name and type is checked before use, memory stays bounded
   (one ~1 MiB chunk, budgets on members and bytes, bounded decompression). The HA key travels only in the stdin field
   `key` and the job key file, is masked in every job log line, progress and error message, and never appears in argv,
   the environment, records or replies. addon.json, `data/options.json`, `data/odoo.conf` and
   `data/n8n-runners-auth-token` (HA passwords and tokens) are never handed out, extracted or kept. Uploaded HA files
   live only in the root 0700 `ha-backups/` store and leave it only through `ha-delete`. Part B: the HA key is written
   only to the job key file (raw, 0600) and never to a container; the live Odoo role's password verifier and n8n's
   encryption key are masked as soon as they are read, travel on stdin or inside the throwaway volume only, and the
   throwaway containers log nothing (`--log-driver none`); throwaway containers never publish a port, never join an
   app's network, never pull other than the pinned PostgreSQL 16 image and always carry the job label, so a killed job's
   objects are removed by the recovery; nothing of the target app changes before the existing restore of the
   converted backup (its pre-restore backup and rollback apply). Review 2026-11-18: HA's PostgreSQL cluster is treated
   as attacker-controlled (its configuration and recovery files replaced or dropped, every library/command setting
   overridden on the command line, its data volume `noexec,nosuid,nodev`, a read-only root, and its dump restored as
   the role `odoo`, never as a superuser, an entry only a superuser can create refused); HA's n8n SQLite is read only by
   a child that dropped to the account nobody on a copy of its own, never by the job process; symlinks below `nodes/`
   may climb (`..`) only before their names; a disk running full or a cancel stops a container step within seconds.
   Batch 1: every SQLite file of an HA backup (and the copy of the live Headscale database) is opened only by
   `hasqlite`'s child (nobody, chroot, no network, limits, defensive, ordinary tables, fixed statements; databases containing virtual tables are refused before integrity checks), whose only
   write is Headscale's `api_keys` on a database without triggers or views, and what it wrote is copied out with
   O_NOFOLLOW as a regular file with one link; Omnigent's HA data is loaded into this device's own schema (B1-01: HA's
   DDL, defaults, checks and domains never run; only its table data and sequence values, by a role without
   privileges, each entry naming a trusted table once; the new cluster's schema and contents audited); HA's EMQX data is opened by the live image without a
   network, with a read-only root and a `noexec` data volume, its cookie, generated configs, plugins and patches never
   staged; an absolute symlink is handed out only below an allowed prefix with a clean target and stays a link entry;
   a hard link only to an earlier file of the same tree that moves; the HA-side secrets of the new add-ons are never
   read, and Omnigent's account hashes, Headscale's Noise key and Hermes's `.env` values are masked as soon as they are
   read.

## 11. UI (`backup/`) requirements

* Cockpit package: `manifest.json` menu entry `備份與還原` (order 46), `index.html` loads
  `../base1/cockpit.js`, `../../static/branding.css`, `backup.css`, `backup.js`; default CSP
  (no inline script/style, no remote assets). Brand: white canvas, `#6183FC` spot colour,
  20 px cards, Poppins/Outfit/Noto Sans TC via branding.css. Match `services/` look and the
  prototype `design/backup-prototype/` information architecture (overview, list, detail, create,
  restore wizard, key/emergency kit, activity). Routing with `cockpit.location`.
* Never use `innerHTML` with data; build DOM with `textContent`.
* Upload: `upload-begin` → `cockpit.channel({payload:"fsreplace1", path, binary:true,
  superuser:"require", size, "send-acks":"bytes"})`, send 512 KiB chunks from `File.slice`,
  keep ≤ 4 MiB unacknowledged, progress from `ack` control messages, `channel.control({command:"done"})`,
  wait for `close`; cancel → `channel.close()` + `upload-abort`; then `upload-finish` (timeout ≥ 15 min, 2 min +
  size at 20 MB/s; on a timeout the upload is kept (`unconfirmed`), the device finishes the check anyway (§8) and
  「重新確認」 returns the same backup — `upload-finish` is idempotent). Measured through the real Cockpit 362 on the
  lab (H8, 2026-11-13, ~142 MB backup to dev-b, sha256 of every stored file checked, 6 runs per setting in two
  batches under a busy host: load1 ≈ 13–15 on 4 CPUs, ≈ 91–96 % CPU busy): median 2 MiB/64 KiB 6.7, 2 MiB/256 KiB
  11.2, 2 MiB/512 KiB 11.4, 4 MiB/64 KiB 7.1, 4 MiB/256 KiB 11.2, 4 MiB/512 KiB 12.8 MB/s, no errors. 4 MiB/512 KiB is
  the default since it was ≥ 30 % faster than 2 MiB/64 KiB (+91 %; its slowest run, 9.8 MB/s, beat the old default's
  fastest, 8.6 MB/s); the frame size was the bottleneck, not the window. While an upload runs or is `unconfirmed` it
  is never replaced by another restore, a banner links back to it and leaving the page asks first.
* **Format 2 and the encryption choice (2026-11-13), as implemented:**
  * Create view: checkbox 加密此備份 (default `status.settings.encrypt_by_default`). Unticking it shows
    `settings.plaintext_warning` verbatim; while the setting is on, the checkbox 「我了解這份備份不加密…」 is required and
    sent as `acknowledge_plaintext: true`; the submit button then reads 「開始備份（不加密）」. The request carries `encrypt`
    whenever `status.settings` exists (an engine without it gets neither key). An unencrypted backup needs no device key:
    the key banner stays informational and the missing-key notice appears only when encrypting.
  * Keys page, card 加密設定: checkbox 預設加密備份. Turning it off opens a dialog with `plaintext_warning` whose
    confirm button stays disabled until 「我了解未加密的備份會以明文保存與下載…」 is ticked →
    `settings-set {encrypt_by_default: false, acknowledge_plaintext: true}`; turning it on sends
    `{encrypt_by_default: true}` without a dialog. `settings.problem` is shown as a warning.
  * Every backup carries a chip 已加密 or 未加密 (list, recent backups, detail), 金鑰可用／需要緊急金鑰 only for encrypted
    ones, and 來源未驗證 for `unauthenticated`; format 1 files show 「舊格式（.woowbackup）」. Verification text:
    `verified.deep` → 「已驗證（內容已逐項檢查）」, other successful checks 「已驗證（檔案完整）」. The verify job's result lists per
    app what was checked; a kind in `header_only` gets 「（只檢查格式）」 after its count, and when dumps are among them a note
    says where a dump body is read in full (when this device made the backup, and at restore; an upload's only at
    restore; review L8).
  * Download: 「下載」 serves the stored file (`download-info`). Next to it, for an encrypted backup, a menu button
    (`aria-haspopup="menu"`, arrow keys, Escape and Tab close it, kept inside the viewport) offers 「下載加密的備份檔（.tar）」
    (the default again) and 「下載未加密版本…」: a dialog with `plaintext_warning`, the 15-minute lifetime and the audit, and a
    required acknowledgement → (`keyDialog` first when `key_available` is false) `export-start {backup_id, request_id,
    confirm: true, key?}` → the job view (title 建立未加密副本, phases from the record) → on success the copy downloads
    once by itself (`export-info` → fsread1) when this page started the job; the result and the backup detail (from
    `list.exports`) offer 「下載副本」 and 「立即刪除」 (`export-delete`) until `expires`.
  * Upload: `accept=".tar,.woowbackup"`, drop-zone text and the name warning name both. No key step for an unencrypted
    backup. For an `unauthenticated` backup the preflight shows a warning (and the engine's `unauthenticated` check), and
    確認 requires the extra checkbox 「我確認信任這個未加密備份檔的來源」, sent as `accept_unauthenticated: true`.
  * The confirm step of an in-place restore says whether safety backups follow 預設加密備份 encrypted or not.
* **Data checks, downtime and PostgreSQL modes (2026-11-13):**
  * Restore result: a line 「共 N 項：a 項一致、b 項不一致、c 項未比對。」, then one table: http-json fields as before
    (a field without a backup value is 未比對), and one row per `DigestCheck` (label or id, type and `target`, the
    `before`/`after` summaries as counts, 一致／不一致／未比對 with `differences` counts or `note`); the digest summaries are
    not repeated as raw `<check>.<key>` rows. Each mismatching check has a disclosure listing its `samples` (change, item,
    detail). Backup and restore results show `timing` as a table (寫入暫停 or 服務停止, and 無法使用 to the health checks;
    null → 未測量, one decimal); a backup result also shows `encrypted`, `unavailable_seconds` and `retention_deleted`.
  * Backup contents: `postgres[]` items as 「單一資料庫」 or 「整個執行個體」 (database names with owners, `roles_count`), a
    cold database as 「沒有以 pg_dump 匯出的資料庫」; 資料核對 lists `verify_snapshot` ids and `verify_digests` (type, target,
    summary counts); `archive_size` and the manifest's format and encryption are shown.
  * Verify result: `deep`, the `apps[].checked` counts per app (資料卷、主機資料夾、容器映像、資料摘要、資料庫角色定義、
    資料庫匯出、應用機密) and `notes` as warnings.
* **Storage per app and 清理備份 (`#/cleanup`):** the overview lists each app's backup bytes, counts by type, newest backup
  and keep-last policy from `status.storage.apps`, or, when the engine does not send it, computed from `list` with the
  same split as `retention.app_usage`. 清理備份 loads `retention-plan {}`; the keep-last controls (預設 and per app:
  依預設／全部保留／保留最新幾份, 1–1000) change a draft policy that must be previewed (`retention-plan {policy}`)
  before anything can be deleted. Candidates start checked, `blocked` and `protected` are shown with their reasons and
  cannot be selected, other backups can be added from a disclosure. The confirm dialog requires
  「我了解這些備份刪除後無法復原」 → `retention-apply {confirm: true, backup_ids, policy?}` (`policy` only when it differs
  from the saved one; a policy alone is saved with `backup_ids: []`); `deleted`, `skipped` and `freed_bytes` are shown.
  Deleting is disabled while a job runs.
* **應用設定 (`#/catalog`, `#/catalog/<id>`):** installed entries (from `status.apps`) with 移除…; owners from
  `catalog-suggest {}`; 掃描 → `catalog-suggest {owner}`: drafts with installed state, warnings, unassigned and unsupported
  files. A draft page shows the containers, the PostgreSQL variants (radio; switching replaces the editor text, after a
  confirmation when it was edited), a structured summary of the editor's entry, warnings/notes/skipped/hints and the
  installed drift, and a JSON editor: JSON errors are reported in the browser (line and column) and never sent; ~0.8 s
  after typing stops `catalog-install {entry}` previews (validity, `details.field`, `conflicts`, compat notes, warnings,
  backups, history, structured changes and the unified diff). Typing never rebuilds the editor. 安裝 is enabled only for
  a valid preview of the current text that differs from the installed file; the dialog requires
  「我已審查上面的內容、差異與影響」 → `catalog-install {entry, confirm: true, expected_sha256}` (an `entry-changed` refusal
  asks for a new preview). 移除 previews with `catalog-remove {id}`, then `{id, confirm: true, expected_sha256}` after
  「我了解移除後無法再備份或還原這個應用…」.
* An engine older than the page answers the new commands with `invalid-request` 「不支援的指令。」: 應用設定 and 清理備份
  then say that this device does not support them yet instead of failing.
* **排程備份 (`#/schedule`, 2026.11.17.1):** a route titled 「排程備份」 under 總覽 (no seventh tab), reached from an overview
  card (from `status.schedule`: on/off, next run, last run), a button in 備份列表 and the banners. It loads
  `schedule-get`; an engine without it (`invalid-request` 「不支援的指令。」, or `status.schedule` missing) shows
  「這台設備的備份元件不支援排程」. Controls: switch 「自動建立排程備份」; 「每天」／「每週指定的日子」 + 週一–週日 (`days`, week
  order); the time in 5-minute steps (`time`) with the hint 「以這台設備的時間（<timezone.name>，UTC±hh:mm）為準，會在這個時間後 5
  分鐘內開始。備份時每個應用會暫停寫入約 10–90 秒。」 (and a hint when the browser's zone differs from `timezone`);
  「全部應用（之後新增的也會包含）」 (`apps: "all"`)／「只備份選擇的應用」 (a list); 「包含容器映像」 (`include_images`, off, with a
  size warning); a read-only line on the encryption (`gate.encrypt`: 預設加密備份); 「保留最新幾份排程備份」 (`keep_last`,
  default 7, or keep all) with 「手動備份、還原前自動備份與上傳的備份不會被刪除。」. 「儲存排程…」 first previews
  (`schedule-set {schedule}`) and shows a dialog with the next runs (`next_runs[].local`) and what the next successful run
  would delete (`retention.delete`, `blocked`; acknowledged), then saves with `schedule-set {schedule, confirm: true}`.
  Saved off (turned off, or saved again while off) nothing runs or is deleted by itself: the dialog lists no deletions
  and asks for no acknowledgement, and only says that 「立即執行一次」 would apply the keep-last afterwards. 「立即執行一次」
  sends `schedule-run-now {request_id}` (a saved schedule; enabled or not; this device's key while 預設加密備份 is on; a
  retry after an error sends the same `request_id`, a new run a new one) and opens the job view. Every time of the
  schedule is the device's: the engine's `local` texts (`next_runs`, `LastRun.local`/`started_local`, events'
  `local`/`first_local`), else the instant in `timezone.name` when the browser knows that IANA zone and it keeps
  `utc_offset` now (the job view's `params.schedule.slot`); otherwise the time is this computer's and says so
  (「你電腦上的時間」). In 活動紀錄 and the job view, beside the jobs' times of this computer, the device's are marked
  「設備時間」 when the two differ. 「排程檢查」 says 「沒有在執行」 whenever `attention.code` is `timer-inactive` and 正常 only
  after a recorded tick. `schedule.defaults` with a `problem`: the form says that it shows the defaults and needs saving
  again (「需要重新儲存」). Turning 預設加密備份 off while the schedule is on names it in the confirmation (「排程備份（每天
  03:00）也會不加密。」). Turning it on while
  `gate.blocked` is `kit-unconfirmed` (or the save answers `invalid-request` with `details.reason: "kit-unconfirmed"`)
  shows the kit step 「開啟排程備份前，請先保存緊急金鑰。」 with a link to 加密金鑰, which offers 「回到排程備份」; `no-device-key`
  leads to creating the key. Banners from `status.schedule.attention` (`message` as sent): 「上次排程備份失敗：…」,
  「…的排程備份沒有執行：…」, 「排程備份已逾期…」, 「排程檢查沒有在執行…」, 「部分完成：…」, and the settings problem; `waiting`
  is shown as information, not a problem. Backup list: a chip 「排程」 and a filter from `BackupMeta.scheduled`, the title
  「排程備份 · <date>」; 清理備份 counts per type with `types.scheduled`; 活動紀錄 rows for `jobs.schedule_events` with
  `not_run` (「未執行」) next to the jobs (a scheduled job is recognized by `params.schedule`). Plain zh-TW, no jargon;
  widths 1440–320, dark/light, keyboard, as every view.
* Download: `download-info` then navigate a hidden iframe to
  `<channel prefix>?<base64(JSON{payload:"fsread1", binary:"raw", path, superuser:"require",
  max_read_size:-1, external:{"content-disposition": attachment; filename*=UTF-8''…,
  "content-type":"application/octet-stream"}})>` where the prefix is
  `new URL(cockpit.transport.uri("channel/" + cockpit.transport.csrf_token)).pathname`.
* Restore wizard: 選擇檔案 → 上傳 → 金鑰（only if `key-required`） → 預檢 → 確認（explicit checkbox,
  lists affected apps, downtime, safety backup; a second checkbox for an unauthenticated upload） → 進度 → 結果（health,
  downtime, data verification table).
* 預檢, the settings a backup carries (`settings` state `missing`, `unloadable` or `different`): 「審查備份中的應用設定」
  runs `catalog-install {entry}` (the preview) and shows its result (announced once; the notice is not a live alert),
  the file metadata, the impact on existing backups, warnings, the structured changes and text diff against installed
  settings (never cut silently), a summary of what the entry declares (owner, units, writer units, PostgreSQL, volumes,
  host directories, secrets, config files, health, digests, template) and its complete text, scrollable and
  selectable. Install / 改用 is offered only for a valid preview that differs from the installed file; its dialog
  repeats owner, units, host directories and template and needs an acknowledgement (worded for an unauthenticated
  upload: the administrator trusts the file's source). The install sends `confirm` with the preview's
  `expected_sha256`; `entry-changed` discards the review, reviews again and says so in the dialog. After an install the
  preflight runs again with the key already entered: the administrator's selection stays and only apps that were not
  restorable before are added. 重新檢查 ends a review. Focus lands on the review's heading when it ends, on the review
  button after 收合, on the app's checkbox after an install. 複製完整內容 falls back to selecting the text when the
  clipboard is unavailable (Cockpit over plain HTTP).
* Jobs: poll `job-status` every 1.5 s while active; resume the progress view after reload from
  `status.active_job`. Show `interrupted` guidance and offer restoring the safety backup. Results derive what
  happened from `result.changed` (or the phases of older records): "manual work" and the primary "restore the safety
  backup" only after a destructive step with an incomplete rollback or interruption; after a successful rollback the
  primary action is the overview. Background refreshes never rebuild the view under a focused text field or an IME
  composition.
* Emergency kit: when `status.key` is null show setup; after `key-init` show key id + the secret
  key text once with a download button (Blob from `key-kit`) and a confirm checkbox; keep a banner
  until `kit_confirmed`. Leaving the keys page drops the kit; it is fetched again only on request. After
  confirmation the kit can be downloaded again behind a dialog that explains its sensitivity; the secret is never
  put into the page then.
* States: loading, empty catalog (`尚未設定可備份的應用`), admin access required (pattern of
  `services/service.js`), disconnected, helper missing, busy.
* RWD: 1440/1024/768/390/360/320 px without horizontal page scroll (open menus and dialogs included); keyboard
  reachable; visible focus inside containers; WCAG AA text contrast in the light and the dark theme
  (`tests/backup-ui.mjs`).

## 12. Lab and fixture (team L)

* Only `~/.woowbk-lab/bin/labpodman` (storage root `~/.woowbk-lab/storage`). Nested rootless
  Podman inside a rootless `--privileged --device /dev/fuse` container is verified to work here.
* Device image `localhost/woowbk-device:noble`: Ubuntu 24.04 + systemd + cockpit (ws, bridge,
  system; noble-backports, record version) + podman + uidmap + age + zstd + python3.
  Devices `woowbk-dev-a` (127.0.0.1:19091→9090, appowner uid 1001) and `woowbk-dev-b`
  (127.0.0.1:19092→9090, appowner uid 1007, different hostname/machine-id). `--memory 768m`,
  `--cpus 1.5`. Users: `devadmin` (sudo; Cockpit login; generated password in
  `~/.woowbk-lab/secrets/devadmin.pass`, 0600), `appowner` (linger, subuid/subgid).
* Demo app `woowbk-demo`: `docker.io/library/postgres:16-alpine` + `localhost/woowbk-demo-app:1`
  (python:3.12-alpine + pg8000, stdlib HTTP). Endpoints: `GET /healthz`, `GET /api/summary`
  (`notes, files, digest, title, signatures_valid`), `GET/POST /api/notes`, `POST /api/files?name=`,
  `GET /api/files/<name>`. Notes carry an HMAC with the app-key secret; `title` comes from the env
  file; files live in volume `woowbk-demo-files`; DB password from secret. Published on
  `127.0.0.1:18090` inside the device.

## 13. Acceptance scenarios (E2E, run in the lab)

S1 same device via UI: seed → backup (images included) → mutate → in-place restore → summary equals
backup-time snapshot; safety backup listed. S2 cross device via UI: download on A, upload on B
(app not deployed, different appowner UID), enter kit key, preflight, fresh restore → healthy,
summary equal, app can write new data. S3 missing image (backup without images, local-only app
image) → preflight fails, no changes. F1 wrong key, F2 truncated, F3 flipped byte, F4 unknown
format, F5 crafted malicious archives (traversal, symlink, extra/missing/duplicate member, size
lie, manifest path outside catalog, unknown app) → rejected, nothing written outside staging.
F6 insufficient space → backup fails before stopping writers. F7 pg_dump failure → backup fails,
writers restarted, nothing listed. F8 restore failure after destructive step → automatic rollback,
data equals pre-restore. F9 killed job → `interrupted`, guidance, safety backup restorable.
F10 concurrent/duplicate requests → `busy` / same job. F11 browser closed mid-job → job finishes,
page resumes. F12 non-admin → admin required, nothing executed.
Format 2 (2026-11-13): S4 an encrypted format 2 backup downloaded from A opens with `tar`, its README commands decrypt
it with the emergency kit, and it restores fresh on B. S5 an unencrypted backup made without a device key restores in
place on A and, uploaded to B, warns as unauthenticated and restores only with the extra acknowledgement. S6 an
unencrypted copy of an encrypted backup is 0600, downloadable until its TTL and then deleted (timer or next status),
with its journal lines. F13 a backup whose nested volume tar a restore would refuse (re-encrypted to the device key)
fails the verify job (deep). F14 restoring one app of a two-app backup whose other application archive is damaged
succeeds and reads only that app's archive. F15 a backup made by the previous engine (format 1) still verifies and
restores.

**Scheduled backups (2026.11.17.1; unit level in `tests/backup/test_schedule.py`, additions to `test_cli`, `test_flows`,
`test_retention`, `tests/test_manage.py`; lab in `tests/e2e/lab/schedule_e2e.py`, run by the main session).** S7 install
shows the timer enabled and active (`verify` → `timer`), rolling back the install transaction disables and removes it,
reinstalling enables it again (extends H7). S8 a real timer run at the next 5-minute boundary after saving a slot
(`time` = that boundary) starts one job with `trigger: on-time`. S9 fast ticks: `schedule.json` written as root (0644)
with `time` = the latest 5-minute boundary up to now and `armed_at` before it, then `systemctl start
woowtech-cockpit-backup-schedule.service` twice → one job (`schedule-run` once). S10 busy: a verify job first → the slot
waits (`waiting`, `schedule-wait`), starts `late` when the verify ended. S11 retention: three scheduled runs with
`keep_last: 2` plus manual backups under a manual keep-last policy → the oldest scheduled one goes (`reason=schedule`),
manual backups follow only their own policy. S12 a stopped demo app → `partial` with its id in `skipped_apps`. S13 a time
zone relink (`/etc/localtime`) moves the next run at the next tick. S14 compatibility: a scheduled backup uploaded to
dev-b running the c393dfb engine (2026.11.15.2) is listed, inspected and restored. S15 (optional) reboot across a slot:
caught up once after 10 minutes of uptime, or `missed` when the next slot is near. S16 journal noise: one line per slot
decision, nothing per quiet tick; whether systemd 255 also hides PID 1's Starting/Finished lines with `LogLevelMax=notice`
is recorded.

**Catalog drafts, catalog administration and retention (2026-11-13, module level, catalog + retention engineer).**
* Unit tests: `python3 -m unittest tests.backup.test_suggest tests.backup.test_catalog_admin tests.backup.test_retention`
  (69 tests; the owner-side helpers run for real against a temporary home). The reference-host fixture (90 Quadlet
  files: LiteLLM, n8n queue mode, Hermes, EMQX with the entrance in the broker's network namespace, OpenDesign, Headscale,
  Odoo, Nextcloud with host directories, Home Assistant, 10 MCP admin containers, code-server) groups into the 19
  production apps plus code-server; for each, the draft of the matching mode equals the hand-written production entry in
  Quadlet files, units, writers, PostgreSQL item, volumes, host directories, secrets, config files (path and mode) and
  health URLs — the only representation difference is Headscale's read-only configuration directory, proposed as one host
  directory where the hand-written entry lists its three files. With those entries installed, `drift` is empty for all of
  them except that Headscale difference. Full `tests/backup` suite: 606 tests OK with the other engineers' edits of that moment; `scripts/check_source.py` OK.
* Lab device dev-a (real root, engine package copied to `/root/woowbk-catret`, installed engine untouched): drafts from
  appowner's real Quadlet directory equal `catalog-examples/woowbk-demo` and `woowbk-dirs` structurally, no drift against
  the installed entries (0.49 s). Install/replace/remove in a sandbox `Paths` base: files root:root 0644, history 0644 in a
  0755 directory, stale digest / unit conflict / group-writable directory refused, the remove's audit line in the journal.
  Read-only retention preview of dev-a's 49 real backups (2.26 GB; 32 manual + 3 safety of woowbk-demo) and a sandbox
  `retention-apply` (2 of 3 deleted, policy file root 0644). Evidence: `~/.woowbk-lab/evidence/catalog-retention/`.

**Integration (2026-11-14, branch `feat/backup-strengthen`; both devices deployed from the working tree with
`deploy-src.sh`; evidence `~/.woowbk-lab/evidence/strengthen/`, `format/`, `dirs/`, `integration/`, `hardening/`).**
The catalog and retention commands are wired into the helper (`status.storage.apps`, the backup job's
`retention_deleted`); everything below ran through the installed helper or the real Cockpit 362 page.

* Page (`tests/e2e/lab/strengthen_ui.mjs`, real Cockpit, devadmin with administrative access): 應用設定 on dev-a scans
  appowner, reports a JSON syntax error with line and column, shows the engine refusing `owner: root` with its field,
  previews the two generated digest checks of woowbk-demo and woowbk-dirs as the only changes and installs both after the
  acknowledgement (previous entries in `apps-history`, journal lines) — 16/16; 清理備份 previews keep-last 5 for woowbk-demo
  exactly as `retention-plan` does (35 candidates), keeps one the administrator unticked, deletes 34 and saves the policy,
  then a policy-only save restores "keep everything"; 預設加密備份 off (acknowledged) and on; an unencrypted and an
  encrypted backup from the create view; the encrypted `.tar` downloaded through the page lists `backup.json`,
  `README.txt`, `apps/woowbk-demo.tar.zst.age` with plain tar, `backup.json` holds no key material, the README's own
  `age -d -i <kit> | zstd -d | tar -x` command decrypts the app and every entry matches its sha256; the unencrypted copy
  (root 0600 in 0700, ~15 min) opens with tar and gzip and is deleted from the page; deep verify; an in-place restore whose
  result table lists both digest checks as 一致 — 36/36 (清理備份 10, the rest 26); dev-b without a device key creates an unencrypted backup from the
  create view, and (setting off) an unencrypted dev-a backup uploaded through the page shows the unauthenticated warning,
  needs the extra checkbox and restores with both digests 一致 — 10/10.
* `tests/e2e/lab/strengthen_e2e.py`: `catalog-apply` 28/28 (both devices end with identical entries); `digests` 40/40
  (woowbk-demo single database and woowbk-dirs cold database in a host directory: both digests equal, before == after,
  in place on dev-a and fresh on dev-b with uid 1007 and other subordinate ids; every comparison before the app unit
  started); `mismatch` 14/14 (a backup re-sealed with one byte of an uploaded file changed passes the deep verify — all
  checksums are consistent — but its restore names `files/check-…bin` as changed, never starts the app and rolls back; a
  database written by an undeclared container during the backup: `public.woowbk_mm` 152 → 146 rows, rolled back -- the
  integrated build's behaviour; since the review fixes such a backup keeps no database digest, see the record below);
  `deep` 19/19 (escaping volume symlink, absolute symlink with a member below it in a host-directory tar, a digest
  listing that disagrees with its summary and a non-PGDMP dump each fail the verify job with `corrupt-archive` and
  `verified {ok: false, deep: true}`; an untouched re-seal passes; inspect, which reads only the manifests, still answers in 2.1–3.3 s); `instance` 53/53
  (`catalog-examples/woowbk-inst`: pgvector 0.8.7 image, Nextcloud-like `oc_admin` used by the app with its password only
  in the app's volume, HNSW and GIN indexes, Odoo-like `odoo` owning two databases with C collation, revoked CONNECT,
  settings and comment; drafted with `catalog-suggest`'s instance variant and installed with `catalog-install`; backed
  up with the database running; after damage, in place on dev-a and fresh on dev-b: roles with md5 of their password
  hashes, memberships, role and database settings, owners, encodings, collations, ACLs, comments, contents, exact nearest
  neighbours, extension versions and valid indexes the planner uses all equal the backup; `odoo` logs in with its old
  password; the app (oc_admin) is healthy; the instance digest — 5 databases, 3 roles besides the bootstrap superuser —
  matches); `keyless` 19/19 and `retention` 16/16 on dev-b (no device key: no-device-key for encrypted backups,
  acknowledgement for `encrypt: false`, setting off → unencrypted backups and safety backups, setting on again; keep-last
  2 deletes older manual backups after each manual backup; a SIGKILLed restore's safety backup and source are protected
  until the app was restored); `tampered-json` 10/10 (a changed member checksum is refused at upload; a changed note is
  stored but refused by inspect, verify and restore as `corrupt-archive`). Downtime: §9 table.
* `format_e2e.py all` 105/105 (S4–S6, F13–F15, cleanup; the format 1 backup verifies deeply and restores), `dirs_e2e.py
  all` 256/256 (prep 20, D1 29, D3 18, D4 29, D5 107, D6 10, D7 16, D2 22, leaks 5), both with the generated digest
  checks installed. (Correction 2026-11-14: `dirs_e2e.py prep` reinstalls the fixture entry of woowbk-dirs, which has no
  digest checks, so D1–D7 ran without them; the digest paths of woowbk-dirs are covered by `strengthen_e2e.py digests`.) `cli_e2e.py all` 122/122 (S1 29, S2 22, faults 11, S3 8, S2 again 22, F8 10, F9 9, cancel 6,
  leaks 5; its expectations now allow the skipped `stage` phase of an app without host directories, and a damaged
  format 2 upload refused already at `upload-finish`). `hardening.py`: H1 325/325 with format 2 crafted cases
  (`backup.json` built from the app section before the defect, so the authenticated manifest is what is judged;
  `unknown-app` is refused while decrypting, the selected app not being in the backup; `undeclared-items` now fails the
  deep verify for its junk image entry while a restore here ignores the undeclared items and succeeds) and 50/50 for
  control, unknown-app, undeclared-items and traversal-entry with the generated digest checks installed; H2 13/13, H3
  28/28, H4 49/49, H5 15/15, H6 12/12; H7 13/13 with `H7_FULL=0` on a clean pair of install transactions (the full
  rollback chain on dev-a stops where manage.py must: a transaction whose `archive.py` the lab-only shim of 2026-11-13 had
  patched, "Changed since installation"); SEC-1 26/26 (format 2 re-sealed with `ArchiveWriter`; the deep verify job now
  refuses it with `verified {ok: false, deep: true}`); fidelity 21/21; fresh 43/43; leaks 7/7.
* Unit tests: host 823 OK; the Ubuntu 24.04 runner 823 OK as root (4 skipped: three tests that only apply to a non-root
  user, and the reference-host directory test: that directory is absent in the container) and as uid 1000 (1 skipped: that directory); `check_source.py`
  passed; `npm test` (managed-owners 4, preview, services-ui 10, backup-ui 52) with chromium-1248 and `backup-ui.mjs`
  52/52 with chromium_headless_shell-1208.

**Review fixes and final regression (2026-11-14, fixer).** The security and correctness review of the integrated build
confirmed H1, H2, M1–M4, L1–L8 and F1–F8, F10, F11, F14, F16, F17 (F3 repeats H2, F7 L4, F8 L2). Each is fixed with a
regression test: unit tests in `test_strengthen.py` (`ReviewFixTests`, `InstanceModeTests`, `GlobalsScriptTests`,
`DigestRestoreTests`, `StartGroupTests`), `test_retention.py`, `test_flows.py`, `test_format_choice.py`, `test_catalog.py`,
`test_catalog_admin.py`, `test_suggest.py`, `test_archive.py` (`ReviewFixManifestTests`), `test_archive_v2.py`,
`test_adapter.py`, and `backup-ui.mjs`; in the lab `tests/e2e/lab/digest_sql_probe.py` and the reworked
`strengthen_e2e.py mismatch`. Lab record (evidence `~/.woowbk-lab/evidence/strengthen-final/`, index `runs.json`):
* `digest_sql_probe.py` on postgres:16-alpine 16.16, 9/9: a role without superuser rights owns a table and defines
  `CREATE CAST (victim AS text) WITH FUNCTION evil(victim)`, whose function runs `COPY … TO PROGRAM`; the pre-fix
  expression `t::text`, run as the digest's superuser, wrote `postgres super=true` into the marker file; the engine's SQL
  wrote nothing; tables without a cast or a `t` column give the same digests as before; a column named `t` no longer hides
  the rest of the row; a SQL_ASCII database with a byte ≥ 0x80 and a LATIN1 database with a non-ASCII table name (equal
  to the same content in UTF-8) are digested.
* Builds: build 3 (every fix but one) ran the long suites; build 4 adds only the restore-side re-read of a differing
  digest (§9) and is the final working tree, installed on both devices (28 engine, helper and page files equal the tree
  by sha256 after its deploy and after the final reset). Build 4 ran the unit tests, `cli_e2e.py all` and
  `strengthen_e2e.py mismatch digests instance`; `hardening.py`, `format_e2e.py`, `dirs_e2e.py`, the rest of
  `strengthen_e2e.py` and the page parts ran on build 3 -- with the fixture catalogs (no digest checks) or with digests
  that match, so they never reach the re-read (of the build 3 runs only `mismatch` met a differing digest, and it ran
  again on build 4).
* Unit tests (build 4): host 856 OK; the Ubuntu 24.04 runner 856 OK as root (4 skipped: three tests that only apply to a non-root user, and the reference-host directory test) and as uid 1000 (1 skipped: that directory); `check_source.py` passed; `node --check`;
  `backup-ui.mjs` 52/52 (chromium-1248; new: the 「（只檢查格式）」 label and note of the verify result).
* `cli_e2e.py all` 122/122 on build 3 and 122/122 on build 4 (S1 29, S2 22, faults 11, S3 8, S2 again 22, F8 10,
  F9 9, cancel 6, leaks 5). `hardening.py all` (`H7_FULL=0`) 551/551: H1 325, H2 13, H3 28, H4 48 (one check fewer than
  the integration run: this time the kill in phase `stop` landed before the writer had stopped, so the conditional
  "writer was down, recovery restarted it" check did not apply and is logged instead), H5 15, H6 12, H7 13, SEC-1 26,
  fidelity 21, fresh 43, leaks 7. `format_e2e.py all` 105/105. `dirs_e2e.py all` 255/255 (prep 18, D1 29, D3 18, D4 29,
  D5 107, D6 11, D7 16, D2 22, leaks 5; also 255/255 on build 1, the first deploy).
* `strengthen_e2e.py` on build 3: `catalog-apply` 28/28, `digests` 38/38 (the two preview checks of the integration run
  did not apply: the entries were installed already), `instance` 53/53 -- the rewritten instance restore (every database
  of the backup, `postgres` and `POSTGRES_DB` included, dropped and recreated from `template1` with `pg_restore
  --create`; the new cluster recognised by its initdb time; the restore's role re-checked after the roles script) keeps
  roles with md5 of their password hashes, memberships, settings, owners, encodings, collations, ACLs, comments,
  contents, exact nearest neighbours and valid indexes equal to the backup in place and fresh on dev-b --, `keyless`
  19/19, `retention` 16/16, `deep` 19/19, `tampered-json` 10/10, `mismatch` 18/18. The first `mismatch` run (11/15,
  `deep` and `tampered-json` then aborted because dev-a's app was left masked) failed in its new case (c): its separate
  writer container lost its connection to the database for a few seconds after the app container stopped (a network
  change on the shared Podman network), wrote nothing between the safety backup's two reads (they matched, the digest
  was kept), reconnected during the rollback and inserted 2 rows into the restored database before the rollback's digest
  read: 250 → 252 rows, the rollback failed (需人工處理, app masked). Restoring that safety backup afterwards succeeded
  with its digest equal (evidence `…/strengthen/*-repair-dev-a`). The driver now adds a writer inside the database
  container (like pg_cron), and build 4 reads a differing digest again at restore (§9): build 4 `mismatch` 24/24 (new case (d): a stable backup restored while the writer container keeps inserting -- the differing digest was read again, the data was moving, the check is reported as not compared and the restore completed),
  `digests` 38/38, `instance` 53/53; `cleanup` 55/55 afterwards.
* `strengthen_ui.mjs` on build 3 (real Cockpit 362): `catalog` 16/16, `cleanup` 10, `backups` 26, `devb` 9, `cleanup-lab` 7 (52/52).
* Writer pause with digest checks (double read; lab data is small): woowbk-demo 3.9 s (4.5 s in the integration run, one
  read), woowbk-dirs 7.6 s (5.8 s; its data had grown from 201 to 259 entries and 92 to 122 rows). The pause grows with
  the data a digest reads; apps without digest checks are unchanged (the §9 table was measured without them).
* Leak scan of the evidence: every driver's leaks scenario passed; a host-side scan of the 622 evidence files of this round found no lab password, no dev-a kit key and no `AGE-SECRET-KEY-1` pattern. Lab state afterwards: both devices run build 4 (28 files equal to the tree), woowbk-demo and woowbk-dirs running with their fixture entries (http-json only), woowbk-inst removed, 預設加密備份 on, retention keeps everything, no job queued or running, staging and exports empty; dev-a keeps 34 backups the lab drivers reference, dev-b 1 (check `20261114T085933-final-state`, 6/6).
