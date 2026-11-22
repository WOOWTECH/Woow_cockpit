# Restricted target capture handoff to Turing (dev-d sole runtime owner)

Base: e968b3980edd22ea38aee197c8da9fc9754f905c.
Independent branch: codex/emqx-target-capture-20261122.
No dev-d/production access, broker operations, real secret reads, or real caller
execution occurred. Existing broker registry's reported 12 actual checks are
unchanged; source and target remain **not assessed**. This delivery does not
establish commercial readiness or complete five-category target capture.

## Delivered integration

`emqx_target_capture.exact_target_readers(raw, exporter=trusted_native_exporter,
username_group=owner_verified_native_group_bytes)` returns the exact five-key
callable mapping accepted by `register_target_snapshots` and `login_preflight`.
Each unsupported category raises fixed `target-capture-unsupported`; the existing
full-workflow wrapper preserves its fixed `runtime-private-refused` diagnostic.
No schema, registry, unknown-reference rule or publication guard was changed.
Current full-workflow registration deliberately FAILS until remaining producers
exist. There is no caller-supplied empty/completeness shortcut.

Only mqtt-auth has a producer, using a trusted native export of the entire
`emqx_authn_mnesia` table under the EXISTING
`emqx-mnesia-checkpoint-json-v1` semantic reader contract for EMQX 5.8.9.
The trusted exporter is invoked once; digest/input length/version/table/record
name/attributes/schema validation/complete traversal/typed values are checked
before projection. No native checkpoint exporter is supplied or selected by data.
`mqtt_table_reader` exposes this one category for owner integration in isolation;
that is not permission to publish full-workflow evidence.

| Exact target field | Required native source |
| --- | --- |
| username | user_info.user_id tuple's second binary, UTF-8, nonempty |
| password_hash | user_info.password_hash binary, UTF-8, nonempty |
| salt | user_info.salt binary, UTF-8; explicitly empty binary permitted |

The first user_id tuple binary must equal the owner-verified username auth group;
all rows must match, without filtering. Duplicate usernames, missing values,
unknown schema, wrong group, unsupported typed terms, references, masked values,
non-UTF8 hashes, malformed superuser atom, and late malformed records refuse.
Missing salt never becomes empty. A complete native export with zero rows can
produce zero records; no table export means unsupported. Non-UTF8 native binary
values are deliberately gated rather than transformed into misleading text.
A caller must separately prove that this is the whole target's only username
password authenticator; this module does not discover listeners/auth chains.
SCRAM and client-id authentication are unsupported.

## Remaining gates (no completeness claims)

* api-keys: `emqx_app.api_secret_hash` NEVER maps to plaintext `api_secret`.
  Existing hashed inventory alone is unsupported. A future producer needs
  actual creation responses containing api_key/api_secret, reliable binding to
  the complete target inventory, coverage of every live key and every issued
  secret (including rotation/revocation/failure paths), and runtime observation
  before any credential or diagnostic reaches evidence. Merely combining an
  arbitrary response with a hash export is not proof and is not implemented.
* connectors: no native structured config producer installed. Missing passwords,
  file/env/vault/unknown references and masked API listings remain unsupported.
* tls: no complete raw PEM/key/password dependency capture installed. Config file
  paths/fingerprints cannot substitute for material; this code opens no files.
* target-bootstrap: no complete native bootstrap inventory producer installed.
  Login input observation by itself does not establish bootstrap completeness.

## Owner-only next steps

1. Review/project the pinned native exporter output in the private owner process.
   Feed original checkpoint bytes and trusted exporter to mqtt_table_reader;
   confirm actual native user_id structure and group meaning. No actual native
   exporter, native checkpoint, table row, or caller was exercised here.
2. Establish whole-target inventory of authentication chains/listeners and every
   category. If unsupported rows or categories exist, retain the gate. Do not
   replace them with hand-written empty snapshots to reach login_preflight.
3. Implement/review missing producers independently, preserving exact target
   schema and atomic registry commit. API credential issuance also needs runtime
   registration beyond the current login-only runtime categories; do not loosen
   those categories as a workaround.
4. Only after private owner integration, run caller capture/restore/login/MQTT/
   restart checks and classify source/target separately. Synthetic test success
   cannot upgrade not-assessed or be counted as runtime commercial acceptance.

This target-only projector does not change or replace Mencius's native Mnesia
exporter work, semantic contract, source consumer gate, or EMQX_NATIVE_HOCON.md.
In particular raw HA DAT/DCD/DCL are still unsupported; no ETF decoder, native
exporter implementation, or HOCON interpretation is introduced here. Coordinate
native export availability with Mencius rather than documenting a competing
export format.

## Validation

Only generated synthetic contract fixtures, no broker or secrets:

```sh
PYTHONPATH=backup-engine:tests/e2e/lab:. python3 -m unittest \
  test_emqx_target_capture test_emqx_semantic_readers \
  test_emqx_runtime_credentials test_emqx_private_boundary \
  test_emqx_private_evidence test_emqx_real_candidate \
  test_emqx_source_consumer -q
```

65 tests passed. Includes explicit-empty vs missing source, wrong group,
SCRAM/emqx_app refusal, binary/reference rejection, duplicate rows, exporter
single invocation, stream compatibility, fixed diagnostics, unsupported category
callbacks and refusal to seal incomplete target registration. `git diff --check`
passed. Native target capture, native Mnesia exporter execution, issuance
observation, whole-target inventory and actual caller are all untested here.
