# LiteLLM HA member preflight candidate

This is an internal parser, not a registered importer or UI feature. It never permits
conversion. `scan_member` walks a complete HA add-on member using the strict existing tar
reader and returns only a source version, PostgreSQL major, and booleans for the control
file and valid salt-file format. It does not open the database, validate its integrity,
or prove the salt matches the database. It reads the salt in memory only and does not
return, log, or write the value. `assess` takes target versions as inputs; the caller must
establish their provenance. Unknown versions block. `convert` always refuses.

Evidence used: the local HA source `phase3/ref/Woow_ha_litellm` at `cf009e3`,
`litellm/Dockerfile`, `rootfs/usr/share/woow-litellm/build-info.json`,
`rootfs/usr/local/lib/woow-litellm/{init-postgres,init-db,woow_init.py}`; the local
Podman package `Woow_podman_litellm` at `dd690ae`, `quadlet/litellm-postgres.container`,
`image/db_prepare.py`, and `scripts/restore.sh`. HA 0.1.15 records LiteLLM 1.104.0 and
uses PG18; the Podman package specifies PG17. A PG18 to PG17 logical downgrade is not
proven compatible and this candidate rejects a newer source major. Both packages bind
stored credentials to the salt, and the target refuses a differing database salt.

Only HA 0.1.15 is mapped: the checked-in build metadata establishes it, not every older
release's deployed image. A present, syntactically valid salt is merely a source-file
check. Missing or non-regular required files, unknown source or target versions, and
incompatible versions fail closed. Archive bytes and source fields are untrusted.

Before public registry/UI integration: define how to verify the running target product
version and database major without assuming mutable tags; establish the actual HA backup
layout with an isolated non-production fixture; safely inspect the untrusted PG18 database
and compare its salt without exposing it; decide and implement encrypted secret transfer,
trusted-schema handling, downgrade policy, rollback, and target credential preservation;
then demonstrate the complete chain and negative cases with isolated real services. The
format check and synthetic tests do not establish any of these properties.

## Offline target and preservation contract (follow-up)

`target_evidence` is a pure helper, not a collector: a future trusted caller must obtain
both the running PostgreSQL container image ID and the image inspection for that ID.
Only matching full SHA-256 IDs and exactly one well-formed `PG_MAJOR` entry yield a
candidate major. The helper does not verify the caller's provenance, prove the server's
actual version, or derive LiteLLM's runtime version. An image tag is not proof of either.
`assess_target` connects these non-secret fields to the existing fail-closed assessment;
the product version is unknown and conversion stays blocked.

`preservation_contract` declares that existing target credentials, configuration and
salt remain untouched while the source data and salt/database binding are unverified.
It implements no transfer or rollback. In particular, the present adapter's
`import_manifest` copies live secrets and cannot transfer the source salt; using it for
LiteLLM would not preserve decryptability if the keys differ.

On 2026-11-20, read-only inspection of the running isolated dev-d image store found
PostgreSQL 15 and 16, but no PG18, PG17, or LiteLLM image. The lab's outer image store
also had no PG18, PG17, or LiteLLM image; dev-a/b/c were stopped, so their nested image
stores were not inspected. No image was downloaded, no other device was started, and no
production secret was used. A genuine PG18 database, valid and mismatched source salt,
and safe inspection through the real restricted parser remain external test prerequisites.
Synthetic tests of this contract are not PostgreSQL or end-to-end acceptance.

## Target image version probe candidate

`probe_target_images` accepts full immutable image IDs from a caller that has separately
established their relationship to the intended running services. Using `TempObjects`, it
runs `postgres --version` and Python's installed LiteLLM package metadata probe in
short-lived containers with no network, read-only root, no supplied environment, secrets
or volumes, and no image pull. Unparseable output or failed execution produces unknown;
`assess_target` feeds those facts to the existing blocked assessment. The caller has not
been wired to production or the public UI, and image identity alone does not establish
schema, migrations, credentials, or deployment provenance.

In dev-d only, the candidate caller was executed through the real `TempObjects` against
an already loaded PG17 image: major 17, LiteLLM version unknown, and no probe objects
remained. See `tests/e2e/lab/evidence/litellm-candidate/pg17-probe.json`. This is a
version-probe test, not a LiteLLM restore or migration acceptance.

## Synthetic salt binding model

`fixture_salt_binding` is a bounded in-memory comparison for synthetic values only.
It models the HA source contract: exactly one `woow_platform.settings` value must
match the stripped source salt, and one `woow.meta` fingerprint must match the first
16 lowercase hex digits of SHA-256 over `woow-litellm-salt-v1:` plus the salt.
Optional synthetic target input reports only same/different, not a key or digest.
`fixture_target_binding` models the target `db_prepare.py` equality check. It uses
the HA salt character and length limits as a conservative candidate restriction;
the target source itself checks nonempty equality, not that format.

Both functions require caller-provided fixture values. They do not run SQL, validate
source row provenance or integrity, perform a target-secret read, move a salt, verify
encrypted credentials, or authorize conversion. Results are explicitly labelled
`synthetic_only`. Missing, duplicate, oversized, malformed and mismatched fixture
values are covered by negative tests. The existing conversion guard remains mandatory;
never treat an in-memory match as a trusted database observation.

## Internal SQL reader awaiting isolated PG validation

`read_source_salt_binding` sends a fixed SQL script through psql stdin to a separately
provisioned `woowbk_litellm_reader` role in an isolated throwaway cluster. The script
checks for ordinary `woow_platform.settings` and `woow.meta` tables with text key/value
columns, rejects RLS and inheritance and a superuser or superuser member, sets read-only
transaction and timeouts, and limits each fixed key to two bounded rows. Only `match`,
`mismatch`, `invalid_source`, `invalid_rows`, or `unknown` is returned. SQL, argv and
return values do not contain the input salt; source DB values appear in captured,
bounded stdout only and must not be logged. It is not connected to scan, conversion,
registry, UI, or target-secret reads. The caller must ensure cluster isolation, reader
privileges and no concurrent DDL; these are not established by the reader itself.

An isolated dev-d PostgreSQL 17 synthetic run exercised matching and mismatched rows,
missing, duplicate and oversized rows, and rejection of a view, RLS, and a superuser
reader; see `tests/e2e/lab/evidence/litellm-candidate/pg17-salt-sql.json`. It used no
real source or target secrets and demonstrates this query contract only. It cannot
prove PG18 compatibility, arbitrary untrusted-schema safety, actual HA backup integrity,
encrypted credential usability, or a safe salt transfer and rollback.


The earlier PG17 9/9 run used a lab subprocess wrapper that did not enforce
`max_output`; those results establish only the synthetic SQL cases and cleanup, not
a bounded capture. The harness now delegates to `default_runner`, forwards input,
stdout, timeout, max_output and abort, and discards the bounded stderr tail. Local
real-child tests exercise the 4096-byte capture boundary, overflow, timeout, file
output, abort, and stderr sanitization. The PG17 synthetic SQL test was subsequently rerun with this wrapper at source
commit `7e63c6c`: 9/9 passed, with independent container and volume cleanup checks.
See `tests/e2e/lab/evidence/litellm-candidate/pg17-bounded-runner.json`; this is not
PG18, HA-backup, or migration acceptance.

## PG18 lab experiments

The salt SQL test now requires `--expected-pg-major 17` or `18` and checks the
running server major before creating fixture tables. Its separate PG18 run is not
part of the earlier PG17 9/9 evidence. The PostgreSQL 18 image digest reported by
the coordinating agent is an external observation, not independently verified by
this worktree; the lab requires the full image ID after its offline load.

`tests/e2e/lab/litellm_pg18_pg17_candidate.py` prepares an independent, entirely
synthetic experiment. It starts two isolated temporary clusters at 128 MiB each,
checks the actual PG18 and PG17 majors, creates a fixed source sample and a separate
fixed target schema, and uses PG18's `pg_dump --data-only --inserts --column-inserts`
for one synthetic table. An unprivileged target role loads the dump; the script
compares the fixture rows and target column schema. It uses no HA backup or real
credentials. The small dump shape check is only an experiment assertion, **not** an
untrusted SQL sanitizer, and this script is not connected to the import engine.

The isolated runs passed: PG18 salt SQL 9/9 and the fixed single-table PG18-to-PG17
plain SQL data-only fixture 4/4. Independent checks found no test containers or
volumes; see `tests/e2e/lab/evidence/litellm-candidate/pg18-synthetic-compat.json`.
The lab source image is PostgreSQL 18.7 as reported by the coordinator; the HA package
uses 18.6. The fixed fixture found no incompatibility; it does not test general
PG18-to-PG17 compatibility, LiteLLM Prisma schemas, arbitrary DDL safety, sequences,
encrypted credential transfer, or rollback. Conversion remains disabled.

## Real HA backup through the internal cluster reader (2026-11-23)

`cluster_member` is an internal candidate, not an importer: `convert` still refuses with
`GUARD` and `litellm` is not in `haimport.APPS`. It makes one strict pass over the add-on
member, hands every `data/postgres` entry (name relative to the cluster) to the product
`ha_odoo.PgSink` (HA's `pg_hba.conf`, `postgresql.conf`, `postgresql.auto.conf` and
`pg_ident.conf` replaced, recovery/standby/pid files dropped) and returns the four
`data/secrets` files (`master_key`, `salt_key`, `pg_password`, `ui_password`; vendor
`woow_init.py` `SECRET_FILES`) in a private holder without repr. Each must be one small
regular file and the salt must have HA's format; a symlink or a missing file refuses.
It proves nothing about the database binding by itself.

`tests/e2e/lab/litellm_real_ha.py` drives one isolated dev-d run from the owner-made real
backup (`ha-fixtures/20261123-litellm/x86`, add-on 0.1.15, LiteLLM 1.104.0, PG 18.6,
encrypted): product decrypt and `scan_member`, the cluster into a throwaway PostgreSQL 18
(read-only root, `noexec` data volume, every library/command setting overridden on the
command line as in `ha_odoo.HA_SERVER_SETTINGS`), the product salt/database binding
reader (`match` for HA's salt and `mismatch` for another), a plain `pg_dump` restored into
the package's PostgreSQL 17.11 image in the order of the package's `scripts/restore.sh`
(drop, create, load in one transaction), HA's salt moved while the target keeps its own
master key, UI password and database password (a Podman secret created from stdin), the
package entrypoint `/opt/woow/start.sh` (db_prepare salt gate, Prisma, UI session
revocation) and the real app API. Row digests (count and MD5 of every row, every table,
sequence state) are compared between HA's cluster and the restored target, and between
the target's own data before the import and after the rollback.

Lab limits that stay open: the app runs as 1000:0 because dev-d maps only IDs 0..55000
(image USER 65534); throwaway containers stand in for the package's Quadlet units;
`WOOW_CHATGPT_ENABLED=false` (no ChatGPT subscription restore); no provider call (no
network); the restore runs as the package's database owner, which is a superuser in the
package as in `restore.sh` (a product importer must decide how far to trust HA's dump).
