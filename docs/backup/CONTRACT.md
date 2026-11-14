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
4. In-place restore always takes a verified **pre-restore safety backup** first and
   **rolls back automatically** if the restore fails.
5. Jobs run in the background (systemd), survive browser close, show phases/progress/log.
6. Encryption key management with an HA-style **emergency kit** (download once, confirm saved).
7. Built-in data checks compared before the app starts, downtime figures per app, PostgreSQL instance mode and a deep
   verify (2026-11-13, §4, §5, §7, §9).
8. **應用設定**: catalog drafts from an owner's Quadlet files, reviewed, edited and installed or removed from the page;
   **清理備份**: storage per app and a keep-last-N policy for manual backups
   (§4 "Catalog drafts", "Installing and removing entries", §7, §8, §11).

Non-goals this phase: scheduled backups, retention beyond keep-last-N of manual backups, NAS/cloud targets, rootful
(system) Quadlet apps, multi-node apps, OS/bare-metal restore, shipping catalog entries with application packages (an
entry is generated or written per device and reviewed). Owner `root` is rejected.

## 2. Repository layout and ownership

| Path | Owner team | Notes |
| --- | --- | --- |
| `backup-engine/woowbackup/{archive,keys,storage,util}.py` | E1 engine-core | format, crypto, local storage |
| `backup-engine/woowbackup/{settings,deepcheck}.py` | E1 engine-core (format) | 預設加密備份 setting; deep verify checks |
| `backup-engine/woowbackup/{errors,paths,__init__}.py` | coordinator (frozen) | shared; change only via coordinator |
| `backup-engine/woowbackup/{catalog,podman,flows,jobs,cli,digests}.py`, `adapters/*` | E2 engine-ops | apps, podman, orchestration, CLI, data digests |
| `backup-engine/woowbackup/{suggest,catalog_admin,retention}.py` | catalog + retention | catalog drafts, catalog install/remove, retention |
| `backup-engine/woowtech-cockpit-backup` | E2 | root entrypoint |
| `backup/` (Cockpit package `woowtechbackup`) | U ui | `manifest.json index.html backup.css backup.js` |
| `catalog-examples/woowbk-demo/**` | L lab | demo app fixture + trusted catalog entry |
| `tests/e2e/**` | L lab (E2E runners later: integrator) | lab device tooling, E2E scripts |
| `tests/backup/test_{archive,keys,storage,archive_security}*.py`, `tests/backup/test_format_choice.py` | E1 | (`test_archive_v2.py`: format 2) |
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
| `/usr/local/share/woowtech-cockpit-backup/catalog/<id>/` | root 0755/0644 | trusted templates (quadlet files, app assets) |
| `/etc/woowtech-cockpit/backup/keys/` | root 0700 | `device-<KEYID>.key`, `imported-<KEYID>.key` (0600), `keys.json` |
| `/etc/woowtech-cockpit/backup/settings.json` | root 0644 | `{"schema": 1, "encrypt_by_default": bool, "updated": "…Z"}` (預設加密備份); missing, not root-owned, group/world-writable, a symlink or invalid → ignored: **encrypted** (with a `problem` in `status.settings`) |
| `/var/lib/woowtech-backup/` | root 0700 | `archives/<id>.tar` (format 2, every new backup) or `archives/<id>.woowbackup` (format 1) + `archives/<id>.json` (index), `uploads/<upload_id>.{part,json,done}` (`.done` names the backup of a finished upload for 24 h), `staging/<job>/`, `exports/<export_id>.tar` + `.json` (unencrypted download copies, 0600, deleted after `EXPORT_TTL` = 15 min; §8), `jobs/<job>.json` + `.log` + `.lock` (record lock, empty, 0600) + `.cancel` (pending cancel request), `requests.json` |
| `/run/woowtech-backup/` | root 0700 (tmpfs) | `engine.lock`, `jobs.lock` (start lock), `index.lock` (index sidecar writes), transient key files `key-<random>` (0600, deleted in `finally`) |

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
  database) are proposals (`hints`). LAN-only ports, HTTPS and unpublished ports give hints instead of URLs. A query
  string (`?…`, possibly a token) is never copied: the URL keeps only its path and a hint says so (review L5).
* `verify`: built-in digests (feature 1): one `postgres-digest` per PostgreSQL database (`{"postgres": "main"}` in export
  modes, `{"container","unit","user"}` in cold mode) and one `files-digest` per proposed volume and host directory, except
  a PostgreSQL data volume or directory (the table digest covers it); at most 16. If the validator rejects them (an engine
  without digests) the draft keeps `verify: []` (`no-digests`).
* `name` is the id and `description` an automatic zh-TW summary; no `template_dir` (fresh deployment templates are
  installed separately). Every variant is checked with `catalog.validate_entry`: `valid`, `problem`, `field`.

**Installed entries.** For an id that is installed for this owner, every variant keeps the installed entry's name,
description, `template_dir`, volume and directory labels, `health` and `verify` items (built-in digests of targets the
installed checks do not cover are appended), its list order (new items last; the start order only when no unit was
added), and leaves out empty lists the installed entry leaves out. `installed.changes` is the structured diff
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
* `adapters.quadlet_postgres.QuadletPostgresAdapter` — implements `adapters.base.Adapter`.
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
| `status` | – | `version, host{hostname,arch,os,podman}, storage{path,free_bytes,total_bytes,backups_bytes,backup_count,apps[AppUsage]}, key{key_id,created,kit_confirmed}\|null, imported_keys[], apps[App], active_job Job\|null, warnings[], settings Settings` (deletes expired unencrypted copies first, §8; `storage.apps` is the per-app usage of the overview, no I/O beyond the index listing and the policy file, `[]` when it cannot be computed) |
| `list` | – | `backups[BackupMeta]` (newest first), `exports[{export_id,backup_id,filename,size,expires}]` (unencrypted copies that can still be downloaded; `expires` epoch seconds) |
| `inspect` | `backup_id, key?, save_key?` | `backup BackupMeta, manifest ManifestSummary, preflight Preflight` (with `key`, only that key is used; `save_key` imports it only after it decrypted the manifest, else `wrong-key`; an unencrypted backup needs no key and refuses one with `invalid-request`). Fast: a format 2 backup decrypts only each app's manifest |
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
| `job-status` | `job_id` | `job Job, log[str]` (≤ 200 lines, secrets never logged) |
| `jobs` | – | `jobs[Job]` (≤ 50, newest first, no log) |
| `job-cancel` | `job_id` | `state` |
| `delete` | `backup_id` | – (`busy` with `details.job_id` while a queued/running job uses it as source or as its `safety_backup_id`, or for any `safety` backup while a restore runs; checked under the start lock; journaled `backup-delete backup=… type=… encrypted=true\|false loginuid=…`, review L6) |
| `upload-begin` | `filename, size` | `upload_id, path, max_size` |
| `upload-finish` | `upload_id` | `backup BackupMeta` (idempotent: a retry after success returns the same backup; a failure after the move puts the file back) |
| `upload-abort` | `upload_id` | – |
| `download-info` | `backup_id` | `path, filename, size` (the stored file as created: `archives/<id>.tar` or `.woowbackup`; for an unencrypted backup journaled `download-unencrypted backup=… loginuid=…`, review L6) |
| `run-job` (internal) | argv: `run-job <job_id>` | – |

Shapes:

* `App`: `id, name, description, owner, adapter, deployed(bool), state("running"|"stopped"|"partial"|"not-deployed"|"error"), units[{name,active}], last_backup{id,created}|null, problems[str]` — `error` also when every unit is active but a quick health request fails, and while units are masked by an unfinished restore (both explained in `problems`).
* `BackupMeta`: `id, type("manual"|"safety"|"uploaded"), created|null, note, apps[{id,name,size?}], size, sha256, key_id|null, key_available(bool), include_images(bool), filename, source{hostname}|null, verified{at,ok,deep?}|null, inspected(bool), uploaded_at?, format(1|2), encrypted(bool), unauthenticated(bool)` — `key_id` null and `key_available` true when not encrypted; `apps[].size` the bytes of the app's archive in a format 2 file (backups made here; uploads after `inspect`); `verified.deep` true when the verify job checked the content like a restore; `unauthenticated` = not encrypted and `type` `uploaded` (also adopted files). Sidecars written before format 2 have no `format`/`encrypted` (format 1, encrypted).
* `Settings`: `encrypt_by_default(bool), problem(zh-TW)|null, plaintext_warning(zh-TW)` — the text the page shows for every acknowledgement of an unencrypted backup or copy: database passwords, API keys and tokens are stored and downloaded in plain text.
* `ManifestSummary`: `backup_id, created, type, note, tool, source, consistency, total_size, format(1|2), encryption("age-x25519"|"none"), apps[{id,name,adapter,owner{name,uid},images[{ref,included}],postgres[{id,database,major,scope("database"|"instance"),databases?[{name,owner}],roles_count?}],volumes[{name}],data_dirs[{path,size,label}],secrets_count,config_files_count,verify_snapshot,verify_digests[{id,type,target,summary}],archive_size?}]` (`databases`/`roles_count` only for scope `instance`; `archive_size` the app's member in a format 2 file)
* `Preflight`: `ok(bool), checks[Check], apps[{id,name,restorable(bool),mode("inplace"|"fresh"),checks[Check]}]`
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
* `AppUsage`: `id, name, in_catalog, backups, types{manual,safety,uploaded}, bytes, estimated, shared, newest|null,
  oldest|null, keep_last|null` (a backup of several apps is split by the per-app archive sizes the index records, else
  evenly: `estimated`; catalog apps without backups are included).
* `BackupBrief`: `id, type, created, size, note, apps[{id,name}], reason?`.
* `Job`: `id, type("backup"|"restore"|"verify"|"export"), state("queued"|"running"|"succeeded"|"failed"|"rolled-back"|"interrupted"|"cancelled"), phase, phases[{id,label,state("pending"|"active"|"done"|"failed"|"skipped")}], progress{percent,message}, created, started|null, finished|null, params, result|null, error{code,message}|null, cancellable(bool)`
* Job `result`: backup → `backup_id, size, apps[], downtime_seconds, unavailable_seconds|null, timing[Timing], encrypted(bool), retention_deleted[str]` (`retention_deleted`: older manual backups the saved keep-last policy deleted after this manual backup, §8); export → `export_id, backup_id, filename, size, expires`; restore → `apps[], safety_backup_id|null, health[Check], verification[{app,match,before,after,checks?[DigestCheck]}], rolled_back(bool), changed(bool), fresh_apps[str], safety_skipped(bool), safety_failed(bool), warnings[str], timing[Timing]`; verify → `ok, entries, bytes, deep(true), format, encrypted, apps[{id,name,checked{volumes,dirs,images,digests,globals,dumps,secrets},header_only[str]}], notes[str]` (`checked`: entries that passed a restore's content check; `header_only` (2026-11-14, review L8): the kinds checked only by their format header -- `dumps`: a dump is recognized by its pg_dump header, its body was read in full by `pg_restore` when this device made the backup and is read again by a restore, so an uploaded backup's dump bodies are first read at restore; `notes`: what a restore would drop, e.g. setuid bits). A local read error while checking (EIO, EMFILE, ENOSPC on the scratch copy) fails the job with `internal-error` and records no `verified`; only defects of the content record `verified.ok: false` (review F10).
  `Timing`: `{app, writer_pause_seconds|null, unavailable_seconds|null}` (one decimal): writers (restore: units) stopped →
  every unit running again, and first stop → every health check of the app passed; null when not measured (nothing was
  stopped, a health check failed). The first stop of an in-place restore is the safety backup's writer stop (§9).
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
host directories), `safety 建立還原前備份`, `stop 停止應用`, `restore 還原資料`, `start 啟動應用`, `check 健康與資料核對`,
and `rollback 自動回復` appended on failure. Verify: `prepare`, `decrypt` (decrypt and check every entry, deep), `check`.
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
* Retention (each recovery pass): records of queued/running jobs, records with `stopped_writers`/`fresh_apps`
  left, and failed/interrupted (not rolled back) restores whose safety backup is still pinned (at least one of
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
  timer is installed (the installer manages no system units). A download that already started keeps reading its open
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

**Hand-over from the safety backup.** The safety backup of an in-place restore leaves its writers stopped
(`keep_stopped`): no restart, no health wait, no second stop. Its http-json snapshot is then not stored (it cannot be
confirmed while the app is down); digests are exact anyway and are what the rollback compares. An app with http-json
checks but no digest (the hand-written production entries) therefore has a rollback that is checked by the health checks
only: the preflight says so before the restore (`rollback-unverified`, warn), the safety backup's log says so, and a
rollback that compared no data adds a note to the result's `warnings` instead of implying a data check (review F16; a
second stop and health wait to confirm the snapshot -- the behaviour before 2026-11-13 -- is not traded for it; adding
digest checks makes rollbacks compare data). Any failure before the
restore's first destructive step (the safety backup's packaging, the rollback-space check, a refusal inside `restore()`)
starts those writers again; apps a multi-app restore had not reached when it failed are started again by the rollback.

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
* Download: `download-info` then navigate a hidden iframe to
  `<channel prefix>?<base64(JSON{payload:"fsread1", binary:"raw", path, superuser:"require",
  max_read_size:-1, external:{"content-disposition": attachment; filename*=UTF-8''…,
  "content-type":"application/octet-stream"}})>` where the prefix is
  `new URL(cockpit.transport.uri("channel/" + cockpit.transport.csrf_token)).pathname`.
* Restore wizard: 選擇檔案 → 上傳 → 金鑰（only if `key-required`） → 預檢 → 確認（explicit checkbox,
  lists affected apps, downtime, safety backup; a second checkbox for an unauthenticated upload） → 進度 → 結果（health,
  downtime, data verification table).
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
