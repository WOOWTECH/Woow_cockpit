# Backup & Restore — Engineering Contract (v1)

Status: binding interface for the implementation teams on branch `feat/backup-restore`.
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
| `/var/lib/woowtech-backup/` | root 0700 | `archives/<id>.woowbackup` + `archives/<id>.json` (index), `uploads/`, `staging/<job>/`, `jobs/<job>.json` + `.log`, `requests.json` |
| `/run/woowtech-backup/` | root 0700 (tmpfs) | `engine.lock`, transient key files `key-<random>` (0600, deleted in `finally`) |

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
relative, no `..`, no empty/`.` segments, and start with `.config/` or `.local/share/`; modes are
octal strings ≤ `0644`; `template_dir` must be inside the templates root above; URLs must be
`http://127.0.0.1:<port>/…` or `http://localhost:<port>/…` (loopback only). Catalog files and
directories must be root-owned, not group/world-writable, and not symlinks. `units` is the start
order (stop = reverse); `writer_units` ⊆ `units` are stopped during a backup while databases stay up.

**Authority rule:** during restore, *what* gets written (secret names, config paths, volume names,
databases, units, templates) always comes from the **local** catalog. The archive only supplies
bytes for items the local catalog declares. Items present in the archive but not in the local
catalog are ignored and reported; items declared locally but missing in the archive make the app
incompatible.

## 5. Archive format `.woowbackup` v1

```
WOOWTECH-BACKUP/1\n
{"format":1,"backup_id":"…","created":"…Z","key_id":"…","encryption":"age-x25519","compression":"zstd"}\n
<age v1 binary ciphertext of: zstd( POSIX/PAX tar )>
```

* Line 1 exactly `WOOWTECH-BACKUP/1`. Another `WOOWTECH-BACKUP/<n>` → `unsupported-format`;
  anything else → `not-a-backup`. Header line ≤ 4096 bytes, strict keys above.
* Encryption: `age` CLI with X25519 recipients (`age -r age1…`), identities via `-i <file>`.
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
Download filename: `woowtech-backup-<hostname>-<YYYYMMDD-HHMM>.woowbackup` (hostname sanitized).

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
| `inspect` | `backup_id, key?, save_key?` | `backup BackupMeta, manifest ManifestSummary, preflight Preflight` |
| `key-init` | – | `key, created(bool)` |
| `key-kit` | – | `key_id, filename, content` (kit text) |
| `key-confirm` | `key_id` | – |
| `key-import` | `key` | `key{key_id,created}` |
| `backup-start` | `apps[], include_images, note, request_id` | `job_id, deduplicated` |
| `verify-start` | `backup_id, request_id, key?` | `job_id, deduplicated` |
| `restore-start` | `backup_id, apps[], request_id, confirm:true, key?, save_key?` | `job_id, deduplicated` |
| `job-status` | `job_id` | `job Job, log[str]` (≤ 200 lines, secrets never logged) |
| `jobs` | – | `jobs[Job]` (≤ 50, newest first, no log) |
| `job-cancel` | `job_id` | `state` |
| `delete` | `backup_id` | – |
| `upload-begin` | `filename, size` | `upload_id, path, max_size` |
| `upload-finish` | `upload_id` | `backup BackupMeta` |
| `upload-abort` | `upload_id` | – |
| `download-info` | `backup_id` | `path, filename, size` |
| `run-job` (internal) | argv: `run-job <job_id>` | – |

Shapes:

* `App`: `id, name, description, owner, adapter, deployed(bool), state("running"|"stopped"|"partial"|"not-deployed"|"error"), units[{name,active}], last_backup{id,created}|null, problems[str]`
* `BackupMeta`: `id, type("manual"|"safety"|"uploaded"), created|null, note, apps[{id,name}], size, sha256, key_id, key_available(bool), include_images(bool), filename, source{hostname}|null, verified{at,ok}|null, inspected(bool), uploaded_at?`
* `ManifestSummary`: `backup_id, created, type, note, tool, source, consistency, total_size, apps[{id,name,adapter,owner{name,uid},images[{ref,included}],postgres[{id,database,major}],volumes[{name}],secrets_count,config_files_count,verify_snapshot}]`
* `Preflight`: `ok(bool), checks[Check], apps[{id,name,restorable(bool),mode("inplace"|"fresh"),checks[Check]}]`
* `Check`: `id, status("ok"|"warn"|"fail"), message(zh-TW)`
* `Job`: `id, type("backup"|"restore"|"verify"), state("queued"|"running"|"succeeded"|"failed"|"rolled-back"|"interrupted"|"cancelled"), phase, phases[{id,label,state("pending"|"active"|"done"|"failed"|"skipped")}], progress{percent,message}, created, started|null, finished|null, params, result|null, error{code,message}|null, cancellable(bool)`
* Job `result`: backup → `backup_id, size, apps[], downtime_seconds`; restore → `apps[], safety_backup_id|null, health[Check], verification[{app,match,before,after}], rolled_back(bool)`; verify → `ok, entries, bytes`.

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
  /usr/local/libexec/woowtech-cockpit-backup run-job <job_id>` and returns immediately.
* `run-job` takes an exclusive `flock` on `/run/woowtech-backup/engine.lock` for its lifetime and
  updates the record atomically (write temp + rename) at every phase/progress change.
* A record in `queued|running` whose unit is not active and whose lock is free is marked
  `interrupted` by `recover_interrupted()` (called by `status`, `jobs`, `job-status`).
* User-provided keys for a job are stored as `/run/woowtech-backup/key-<job_id>` (0600) and
  removed by `run-job` in `finally`; `save_key: true` imports the key permanently instead.
* Cancel is honoured only before any destructive step (backup: until `stop`; also during `package`
  and `verify` the partial archive is discarded and writers are already restarted;
  verify: always; restore: only before `safety`).

## 9. Backup and restore algorithms (adapter `quadlet-postgres`)

Backup (per app): probe (owner, linger runtime dir, quadlet files, units active) → estimate size →
space check (free ≥ 2.2 × estimate + 512 MiB) → snapshot business verify → stop `writer_units`
→ `podman exec <db> pg_dump -U <user> -d <db> -Fc` (stream to staging file) and check with
`pg_restore --list` → `podman volume export <vol>` (stdout to staging) → read secrets with
`podman secret inspect --showsecret` → read config + quadlet files as the owner → optionally
`podman save --format oci-archive` per image → **always restart writers in `finally`** → health
check (only when every unit was active before the backup; an app that was already down is not
waited for, and `downtime_seconds` is 0 when no writer had to be stopped). Then the engine writes
the archive (temp file, fsync, atomic rename), verifies it fully with the device key, writes the
index, and deletes staging.

Restore (per app, after full archive verification + extraction to staging):
* `fresh` (quadlet files absent): install catalog templates as the owner into
  `~/.config/containers/systemd/`, `systemctl --user daemon-reload`.
* `inplace`: first create and fully verify a `safety` backup of the app; abort without changes if
  that fails. Then stop units (reverse order).
* Recreate secrets (`podman secret rm` + `podman secret create <name> -` from stdin), write config
  files (as owner, `O_NOFOLLOW`, declared mode), load included images (`podman load`), recreate
  volumes (`podman volume rm -f`, `create`, `import <vol> -`), remove the database data volume,
  start the DB unit, wait for `pg_isready`, `pg_restore --exit-on-error --single-transaction
  --no-owner --no-privileges`, start remaining units in order, run health checks, then compare
  verify output with `verify_snapshot` on the `compare` keys.
* Any failure after the first destructive step → automatic rollback from the safety backup
  (`inplace`) or full removal of what was created (`fresh`), then state `rolled-back` (or `failed`
  with `需人工處理` guidance when rollback also fails). Keep the 3 newest `safety` backups per app.

Images: if not included, the local image for the ref must exist or be pullable; otherwise the app
preflight fails. PostgreSQL major in the archive must be ≤ the target image major.

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
  superuser:"require", size, "send-acks":"bytes"})`, send 64 KiB chunks from `File.slice`,
  keep ≤ 2 MiB unacknowledged, progress from `ack` control messages, `channel.control({command:"done"})`,
  wait for `close`; cancel → `channel.close()` + `upload-abort`; then `upload-finish`.
* Download: `download-info` then navigate a hidden iframe to
  `<channel prefix>?<base64(JSON{payload:"fsread1", binary:"raw", path, superuser:"require",
  max_read_size:-1, external:{"content-disposition": attachment; filename*=UTF-8''…,
  "content-type":"application/octet-stream"}})>` where the prefix is
  `new URL(cockpit.transport.uri("channel/" + cockpit.transport.csrf_token)).pathname`.
* Restore wizard: 選擇檔案 → 上傳 → 金鑰（only if `key-required`） → 預檢 → 確認（explicit checkbox,
  lists affected apps, downtime, safety backup） → 進度 → 結果（health + data verification table).
* Jobs: poll `job-status` every 1.5 s while active; resume the progress view after reload from
  `status.active_job`. Show `interrupted` guidance and offer restoring the safety backup.
* Emergency kit: when `status.key` is null show setup; after `key-init` show key id + the secret
  key text once with a download button (Blob from `key-kit`) and a confirm checkbox; keep a banner
  until `kit_confirmed`.
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
  (127.0.0.1:19092→9090, appowner uid 1007, different hostname/machine-id). `--memory 1g`,
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
