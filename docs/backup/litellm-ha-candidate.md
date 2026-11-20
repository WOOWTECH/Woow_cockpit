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
