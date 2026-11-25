# NEXTCLOUD lane (NC-OWNER-1905), 2026-11-25: evidence and self review

What is REAL here: the strict config.php parser (with the NC-12 extension) and `scan_member` read the real encrypted HA backup
`woow-b2-nextcloud-x86-enc-noshare` (2026-11-23, 248 MB) in-process; `real_smoke-noshare.json` holds only names, ids and booleans (the key is read from
the lab creds file in-process, never printed): config found and parsed, data folder `('share', 'nextcloud')`, ONE issue `nextcloud.no-share` (confirm) against a
live config of the same version, no stop. Everything else is simulated: every container, psql, pg_restore, pg_dump and systemd step is a test double
(tests/backup/test_ha_nextcloud.py, hab1fakes World). No device was used. The new SQL has never run against a real PostgreSQL (FOR-REAL.txt 1).
Results: see the lane file (team/parity-nextcloud.md) and runs/m1.* for the heavy runs (full tests/backup --b1, the 74-mutant sweep, backup-ui).

## Self review of what was relaxed (DESIGN H-c "安全複查"): nothing of the hostile-archive protections was weakened
- NC-12 (parser): still never run; a `$` is never accepted unescaped, so no interpolation; only fixed escapes, texts joined by a dot, 12 named constants; the size limit
  (1 MiB) bounds a chain of dots. Tests: refusals (variables, `{$x}`, `${x}`, `{\$x}`, `\x41`, `\u{41}`, octal, heredoc, calls, class constants, unknown constants,
  text . number) and acceptances; mutants M01-M05.
- NC-26/NC-27/files.skipped: left OUT, never moved (a link may point outside this device's data folder, an `.htaccess` could publish the folder); Nextcloud's own
  `.htaccess` is always written; every name is in the confirmation key (a new one asks again).
- NC-29 (hard link copy): the reader copies the content of a file of the SAME member, never a NEVER_READ file, an addon.json or an excluded name; here only for the
  files this module leaves out on purpose (the updater's folder, HA's cached Collabora answers, an `.htaccess`: no secret); the copy has the link's own name and is
  counted in the file lists. A link whose file is not a file of the member is listed, not made up.
- NC-38/NC-45: programs (functions, triggers) of HA's database are NOT moved (they would run as Nextcloud's database role); only their names are read, from the catalogs
  (OBJECTS_SQL); the list of the dump leaves out exactly the confirmed kinds and their comments, any other kind that Nextcloud never creates still stops, and the NEW
  cluster is read again after the restore: ANY foreign object there stops the conversion before a fix-up. A kind outside functions/triggers (type, view, rule, policy,
  event trigger, CHECK, generated column, inheritance, default that calls a function ...) still stops. Not built: the allow-list of known apps.
- NC-39: `CREATE EXTENSION` only of names that are in this device's own `pg_available_extensions` (and EXT_RE); HA decides nothing but which of them to enable.
- NC-40: `pg_dump -n public`: less is moved, nothing else is added.
- NC-07: the plain password of config.php (this device's own) is in no statement, argument or log; the SCRAM verifier made from it is masked (jobs.mask_secret) and
  equals the RFC 7677 example. A role is made only when this device's has none / no usable password; a name starting with `pg_` is refused.
- NC-08: HA's data is loaded and its fix-ups run only as a NOSUPERUSER role (never as a superuser); the hand-over is `REASSIGN OWNED / DROP OWNED / DROP ROLE` by the
  cluster's superuser in a pinned session (ownership changes, no code of HA's runs); the verification compares the role's attributes (superuser included) with this
  device's and requires the role to own every table. The plain path is untouched (a test shows no `woowbk_load` there).
- NC-05: only THIS device's config.php is evaluated, by its own PHP in its own container (`php -d display_errors=0 -r`, read only); HA's is never run.
- NC-04: services are started through the unit of their own Quadlet file (hatarget.ensure_running) and put back; one that cannot be started stops only Nextcloud.
- NC-32 removed a pre-check (HA's PostgreSQL newer than this device's): the restore decides, in one transaction (`--single-transaction --exit-on-error`), so a refusal
  leaves nothing half done; the safety backup and the automatic rollback of the restore are not touched by this lane.
- Every relaxed block has a unit test that shows the new behaviour, and one that shows the app is still stopped when it must be (StopsHoldTests: a conversion stops at a
  stop even with a sink that only collects; the not-confirmed tests: only Nextcloud stops, before any cluster of the new database is built).
