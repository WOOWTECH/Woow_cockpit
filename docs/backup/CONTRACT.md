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
security rules (§10); the emergency kit is an age identity file (§5).
Product docs for customers are written separately in Traditional Chinese (`docs/backup.md`).
All UI text is **Traditional Chinese (zh-TW)**. Code comments in English.

If a detail below proves infeasible, implement the closest *safe* alternative inside your own
files and report it as a deviation in your final output. Do not silently change shared shapes.

## 1. Scope of this phase

Customers manage **Podman application packages** (rootless Quadlet apps owned by a Linux user)
from a Cockpit page "備份與還原", modelled on Home Assistant backups:

1. Create a backup of selected apps → stored **locally by default** → listed.
2. **Download** any backup as **one self-contained encrypted file** (`.woowbackup`).
3. **Upload** a `.woowbackup` on the same or **another compatible device**, enter the emergency
   key if this device does not hold it, run preflight, confirm, restore.
4. In-place restore always takes a verified **pre-restore safety backup** first and
   **rolls back automatically** if the restore fails.
5. Jobs run in the background (systemd), survive browser close, show phases/progress/log.
6. Encryption key management with an HA-style **emergency kit** (download once, confirm saved).

Non-goals this phase: schedules/retention policies, NAS/cloud targets, rootful (system) Quadlet
apps, multi-node apps, OS/bare-metal restore, registering production apps (they need their own
reviewed catalog entries later). Owner `root` is rejected.

## 2. Repository layout and ownership

| Path | Owner team | Notes |
| --- | --- | --- |
| `backup-engine/woowbackup/{archive,keys,storage,util}.py` | E1 engine-core | format, crypto, local storage |
| `backup-engine/woowbackup/{errors,paths,__init__}.py` | coordinator (frozen) | shared; change only via coordinator |
| `backup-engine/woowbackup/{catalog,podman,flows,jobs,cli}.py`, `adapters/*` | E2 engine-ops | apps, podman, orchestration, CLI |
| `backup-engine/woowtech-cockpit-backup` | E2 | root entrypoint |
| `backup/` (Cockpit package `woowtechbackup`) | U ui | `manifest.json index.html backup.css backup.js` |
| `catalog-examples/woowbk-demo/**` | L lab | demo app fixture + trusted catalog entry |
| `tests/e2e/**` | L lab (E2E runners later: integrator) | lab device tooling, E2E scripts |
| `tests/backup/test_{archive,keys,storage,archive_security}*.py` | E1 | |
| `tests/backup/test_{catalog,podman,flows,jobs,cli,adapter}*.py` | E2 | |
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
| `/etc/woowtech-cockpit/backup/apps/<id>.json` | root 0644, dir 0755 | **trusted catalog** |
| `/usr/local/share/woowtech-cockpit-backup/catalog/<id>/` | root 0755/0644 | trusted templates (quadlet files, app assets) |
| `/etc/woowtech-cockpit/backup/keys/` | root 0700 | `device-<KEYID>.key`, `imported-<KEYID>.key` (0600), `keys.json` |
| `/var/lib/woowtech-backup/` | root 0700 | `archives/<id>.woowbackup` + `archives/<id>.json` (index), `uploads/<upload_id>.{part,json,done}` (`.done` names the backup of a finished upload for 24 h), `staging/<job>/`, `jobs/<job>.json` + `.log` + `.lock` (record lock, empty, 0600) + `.cancel` (pending cancel request), `requests.json` |
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
and `.local/share/{systemd,containers,dbus-1,applications}/` stay forbidden even for a colliding id); modes are
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
`^[A-Za-z0-9._@+-]{1,255}$` and not `.`/`..` (so never the home itself), last segment ≤ 200 characters (room for
the restore's sibling names). It may neither equal, lie inside nor contain `.ssh`, `.gnupg`, `.config/systemd`,
`.config/containers`, `.local/share/containers`, `.config/environment.d`, `.config/autostart`, `.config/dbus-1`,
`.config/user-tmpfiles.d`, `.local/share/systemd`, `.local/share/dbus-1` or `.local/share/applications` (login
keys, unit definitions, the user manager's environment and the Podman storage never come from archive bytes).
Items must not overlap each other (equal, or one inside the other) or any `config_files` path; two loaded apps of
the same owner must not declare overlapping directories (the later entry, in file name order, is reported in
`status.warnings` and not loaded). Every unit that mounts a directory belongs in `writer_units` (the backup logs a
warning for a running non-writer unit whose `.container` file mounts it). **Cold databases:** a PostgreSQL whose
data lives in a volume or host directory may be declared without a `postgres` entry: list the data volume in
`volumes` or the data directory in `data_dirs` and put the database unit in `writer_units`; everything stops during
the backup and roles, passwords, owners and grants are kept at file level (the major version must then be the same
on restore).

**Authority rule:** during restore, *what* gets written (secret names, config paths, volume names, host directory
paths, databases, units, templates) always comes from the **local** catalog. The archive only supplies
bytes for items the local catalog declares. Items present in the archive but not in the local
catalog are ignored and reported; items declared locally but missing in the archive make the app
incompatible (an archive without `data_dirs` is incompatible with a catalog entry that declares some).

## 5. Archive format `.woowbackup` v1

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
`^apps/[a-z0-9][a-z0-9-]{1,40}/(images|postgres|volumes|secrets|config|quadlet)/[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}$`.

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
Download filename: `woowtech-backup-<hostname>-<YYYYMMDD-HHMMSS>.woowbackup` (hostname sanitized; seconds since
2026-11 so two backups of the same minute differ). An uploaded file keeps its name when it matches this pattern or the
older `…-<YYYYMMDD-HHMM>.woowbackup`; any other name is replaced by `woowtech-backup-uploaded-<YYYYMMDD-HHMMSS>.woowbackup`.

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

## 6. Python module contract (signatures are in the scaffold files; keep them)

* `errors.BackupError(code, message, **details)` — every expected failure. `message` is zh-TW.
* `archive`: `read_header`, `write_archive`, `read_manifest`, `verify_archive`, `extract_archive`.
* `keys`: `KeyStore(paths)` with `device_key()`, `ensure_device_key()`, `identities()`,
  `import_key(text)`, `kit_text()`, `confirm_kit(key_id)`, `temp_identity(text)` (context manager).
* `storage`: `Storage(paths)` with layout, ids, index CRUD, uploads, staging, free space.
* `catalog`: `load_catalog(paths) -> dict[str, App]`.
* `podman`: `OwnerRunner(owner)` — runs as the owner via `runuser`, user systemd, safe file I/O.
* `adapters.quadlet_postgres.QuadletPostgresAdapter` — implements `adapters.base.Adapter`.
* `flows`: `run_backup`, `run_restore`, `run_verify` (used by jobs).
* `jobs`: `JobStore`, `start_job`, `run_job`, `recover_interrupted`.
* `cli.main(argv) -> int`.

## 7. Helper CLI contract (UI ↔ engine)

Invocation from the UI: `cockpit.spawn(["/usr/local/libexec/woowtech-cockpit-backup", <command>],
{superuser: "require", err: "message"})`, request JSON written to **stdin** (`proc.input(json)`),
response is exactly one JSON object on **stdout**. Exit 0 → `{"ok": true, …}`. Exit 1 →
`{"ok": false, "error": {"code": "…", "message": "zh-TW text", "details": {}}}`. stdin ≤ 1 MiB.
Key material only ever travels in stdin JSON field `key`.

| Command | stdin | stdout (ok) |
| --- | --- | --- |
| `status` | – | `version, host{hostname,arch,os,podman}, storage{path,free_bytes,total_bytes,backups_bytes,backup_count}, key{key_id,created,kit_confirmed}\|null, imported_keys[], apps[App], active_job Job\|null, warnings[]` |
| `list` | – | `backups[BackupMeta]` (newest first) |
| `inspect` | `backup_id, key?, save_key?` | `backup BackupMeta, manifest ManifestSummary, preflight Preflight` (with `key`, only that key is used; `save_key` imports it only after it decrypted the manifest, else `wrong-key`) |
| `key-init` | – | `key, created(bool)` |
| `key-kit` | – | `key_id, filename, content` (kit text) |
| `key-confirm` | `key_id` | – |
| `key-import` | `key` | `key{key_id,created}` |
| `backup-start` | `apps[], include_images, note, request_id` | `job_id, deduplicated` |
| `verify-start` | `backup_id, request_id, key?` | `job_id, deduplicated` |
| `restore-start` | `backup_id, apps[], request_id, confirm:true, key?, save_key?, allow_no_safety?` | `job_id, deduplicated` (`save_key` imports only a key that opens this backup; `allow_no_safety: true` is the explicit, separately confirmed "restore even if no safety backup can be made") |
| `job-status` | `job_id` | `job Job, log[str]` (≤ 200 lines, secrets never logged) |
| `jobs` | – | `jobs[Job]` (≤ 50, newest first, no log) |
| `job-cancel` | `job_id` | `state` |
| `delete` | `backup_id` | – (`busy` with `details.job_id` while a queued/running job uses it as source or as its `safety_backup_id`, or for any `safety` backup while a restore runs; checked under the start lock) |
| `upload-begin` | `filename, size` | `upload_id, path, max_size` |
| `upload-finish` | `upload_id` | `backup BackupMeta` (idempotent: a retry after success returns the same backup; a failure after the move puts the file back) |
| `upload-abort` | `upload_id` | – |
| `download-info` | `backup_id` | `path, filename, size` |
| `run-job` (internal) | argv: `run-job <job_id>` | – |

Shapes:

* `App`: `id, name, description, owner, adapter, deployed(bool), state("running"|"stopped"|"partial"|"not-deployed"|"error"), units[{name,active}], last_backup{id,created}|null, problems[str]` — `error` also when every unit is active but a quick health request fails, and while units are masked by an unfinished restore (both explained in `problems`).
* `BackupMeta`: `id, type("manual"|"safety"|"uploaded"), created|null, note, apps[{id,name}], size, sha256, key_id, key_available(bool), include_images(bool), filename, source{hostname}|null, verified{at,ok}|null, inspected(bool), uploaded_at?`
* `ManifestSummary`: `backup_id, created, type, note, tool, source, consistency, total_size, apps[{id,name,adapter,owner{name,uid},images[{ref,included}],postgres[{id,database,major}],volumes[{name}],secrets_count,config_files_count,verify_snapshot}]`
* `Preflight`: `ok(bool), checks[Check], apps[{id,name,restorable(bool),mode("inplace"|"fresh"),checks[Check]}]`
* `Check`: `id, status("ok"|"warn"|"fail"), message(zh-TW)`
* `Job`: `id, type("backup"|"restore"|"verify"), state("queued"|"running"|"succeeded"|"failed"|"rolled-back"|"interrupted"|"cancelled"), phase, phases[{id,label,state("pending"|"active"|"done"|"failed"|"skipped")}], progress{percent,message}, created, started|null, finished|null, params, result|null, error{code,message}|null, cancellable(bool)`
* Job `result`: backup → `backup_id, size, apps[], downtime_seconds`; restore → `apps[], safety_backup_id|null, health[Check], verification[{app,match,before,after}], rolled_back(bool), changed(bool), fresh_apps[str], safety_skipped(bool), safety_failed(bool), warnings[str]`; verify → `ok, entries, bytes`.
  `changed`: a destructive step started (false → nothing on the device changed); `fresh_apps`: apps deployed from templates
  (of an `interrupted` restore: the deployments that had not finished their data import); `warnings`: zh-TW notes about
  what the restore could not keep (setuid/setgid bits and non-`user.*` extended attributes such as file capabilities
  dropped from a volume, an instance whose databases could not be listed), ≤ 50, also in the job log;
  `safety_skipped`: in-place apps were restored without a new safety backup (the source is a safety backup, or
  `allow_no_safety`); `safety_failed`: refused because no safety backup could be made. A failed restore always carries
  its result. `verification[].before/after` hold only the catalog's `compare` keys, each value ≤ 2 KiB of JSON.

Phases — backup: `prepare 準備`, `check 檢查空間與應用`, `stop 暫停應用寫入`, `dump 匯出資料庫`,
`export 匯出資料卷與設定`, `start 恢復應用`, `package 加密封裝`, `verify 驗證備份`.
Restore: `prepare 準備`, `decrypt 解密並驗證檔案`, `preflight 相容性檢查`, `safety 建立還原前備份`,
`stop 停止應用`, `restore 還原資料`, `start 啟動應用`, `check 健康與資料核對`, and `rollback 自動回復`
appended on failure. Verify: `prepare`, `decrypt`, `check`.

Error codes: `invalid-request, not-found, busy, key-required, wrong-key, no-device-key,
not-a-backup, unsupported-format, corrupt-archive, invalid-manifest, limit-exceeded,
insufficient-space, incompatible, app-not-in-catalog, owner-missing, not-deployed,
permission-denied, not-cancellable, job-failed, internal-error`.

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
  verify: always; restore: only before `safety`). `job-cancel` accepts a request only while the record says
  `cancellable` (else `not-cancellable`), and leaving the cancellable window is itself a checkpoint under the
  same record lock, so an accepted cancel is never followed by a destructive step.
* Index sidecars are written (register, update, delete) under `/run/woowtech-backup/index.lock`, and an update
  reads the sidecar under it: `inspect` and a verify job's result never overwrite each other. A sidecar that exists but
  cannot be read or validated is never replaced: orphan adoption and a re-upload of the same file leave it as it is.
* `upload-finish` holds an exclusive `flock` on the upload's `.json` and, once it holds it, ignores SIGTERM/SIGHUP/SIGINT
  until its result is recorded (`.done`): a page timeout makes cockpit-bridge send SIGTERM, and the check must still
  finish. A second `upload-finish` of the same upload (the page's 「重新確認」) waits for that lock, then returns the
  recorded backup instead of hashing again.

## 9. Backup and restore algorithms (adapter `quadlet-postgres`)

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
optionally `podman save --format oci-archive` per image. Then the engine writes the archive in staging (temp file, fsync, rename),
verifies it fully with the device key, moves it into `archives/` (rename without overwrite), writes the index, and
deletes staging.

Restore (per app, after full archive verification + extraction to staging):
* Before any change: check every nested tar (section 5); `inplace` refuses (`incompatible`) when the database
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
  as it is published); abort without changes if that fails, unless the backup being restored is itself a `safety`
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
8. All JSON inputs strictly validated (types, lengths, enums, regexes); unknown keys rejected.

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
* Download: `download-info` then navigate a hidden iframe to
  `<channel prefix>?<base64(JSON{payload:"fsread1", binary:"raw", path, superuser:"require",
  max_read_size:-1, external:{"content-disposition": attachment; filename*=UTF-8''…,
  "content-type":"application/octet-stream"}})>` where the prefix is
  `new URL(cockpit.transport.uri("channel/" + cockpit.transport.csrf_token)).pathname`.
* Restore wizard: 選擇檔案 → 上傳 → 金鑰（only if `key-required`） → 預檢 → 確認（explicit checkbox,
  lists affected apps, downtime, safety backup） → 進度 → 結果（health + data verification table).
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
* RWD: 1440/1024/768/390/360/320 px without horizontal page scroll; keyboard reachable; visible
  focus inside containers.

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
