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

As of this commit it has only mock-based interface tests, not a real database run. In
particular its SQL, privilege/schema checks and PostgreSQL behavior remain unverified.
The planned dev-d PG17 synthetic test needs coordination with the EMQX agent first,
uses no real source or target secrets, and demonstrates the query contract only. It
cannot prove PG18 compatibility, arbitrary untrusted-schema safety, actual HA backup
integrity, encrypted credential usability, or a safe salt transfer and rollback.
