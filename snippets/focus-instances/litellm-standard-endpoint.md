# LiteLLM standard connection companions

Bounded product follow-up for original-service acceptance preparation. Trusted
package `dd690ae` declares a secret-backed `DATABASE_URL`, plus
`DATABASE_HOST=litellm-postgres`, `DATABASE_NAME=litellm`, and
`DATABASE_USERNAME=litellm`. Its `image/start.sh` first invokes `db_prepare.py`
(which consumes those companions), then Prisma migrations, then `exec litellm`;
the installed `config/config.yaml` declares no alternate database URL.

The actual running proxy URL remains authoritative. Selected companion values
must agree exactly with its parsed host/database/user; USER and USERNAME must
both agree when present. PORT must be bounded ASCII decimal and agree. Explicit
URL port 0 refuses; only an absent URL port defaults to 5432. The outer reader
still requires the marked local database, declared PostgreSQL alias, shared
non-host network and port 5432. Direct/file/config/CLI alternatives still refuse.
Only the redacted endpoint is output; URL credentials never leave the probe.

New compiled production-probe tests: four methods in
`tests.backup.test_ha_instance_access.LiteLlmStandardEndpointTests` (4/4 guarded,
zero blocked/shim/native calls). They exercise standard companion inputs,
each mismatch, alternative inputs, port 0 and same-network binding. Existing
YAML/CLI override refusal has its own narrowly scoped gate.

No controller runtime or original-service acceptance claim. Generated PG87
remains independent load/rollback evidence; source freeze d09's full gate ran
before this product delta.
