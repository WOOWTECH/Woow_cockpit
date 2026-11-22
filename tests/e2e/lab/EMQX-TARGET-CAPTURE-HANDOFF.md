# Persisted-value companion handoff to Turing and Mencius

Independent worktree: /tmp/ha-emqx-target-capture-20261122
Branch: codex/emqx-target-capture-20261122; original base e968b39.
The exact-two-table restriction introduced in 13b9312 is REMOVED. Normal broker
persistent inventory may include admin, JWT, ACL, retainer and other tables;
there is no business table-name whitelist in the companion reader.
No dev-d/production operations, real source rows or secrets were accessed.

## Delivered implementation

`emqx_persisted_values.capture_persisted_values` validates full owner-provided
native inventory, then reads every listed checkpoint stream through EOF and
optional finish, invokes trusted native exporter(table, raw), and checks the
UNCHANGED `emqx-mnesia-checkpoint-json-v1` output. It matches input digest/size,
version, table, record name, complete, native schema_validated and attributes;
all rows must have the native-declared arity/tag. No schema is invented for JWT.
A reviewed native producer must actually support that table/container; the
five-table exporter cannot simply assert support for all other tables.

Every binary, atom, nested map key/value and charlist is registered as a private
superset. Unknown/executable term kinds, malformed rows, unsupported native
producer, late failure, partial traversal and input mismatches refuse atomically.
Empty JWT still requires native validated schema and complete traversal. Nonempty
JWT succeeds only with an actual supported native typed-value producer and full
capture. New login-token registration never substitutes for persisted JWT data.

`PersistedValues.scan` checks raw, base64, hex, URL and JSON escaped forms, with
existing aggregate private-value limits. It carries generation/scope and table
checkpoint bindings. Main secret registry/schema/unknown-ref rules are unchanged.

`bind_target_persisted(owner_exact_readers, persisted_values=companion,
generation=owner_generation)` attaches the companion to the original five-key
reader mapping. This path does NOT require the restricted effective-config
absence profile. Existing reviewed owner business producers retain responsibility
for five-category provenance. It does not convert API hashes into plaintext.

`login_preflight` automatically includes that mapping's target companion in
`CombinedRegistry.scan`, together with source/runtime. It accepts an optional
`source_persisted_values` companion as well. The actual publisher and the returned
session both scan through all attached registries; persisted values colliding
with actual preflight JSON bytes prevent evidence file creation. Pass the bound
mapping intact, rather than copying it to a plain dict and losing its companion.

## Native inventory callback boundary

Trusted owner `private_inventory()` returns a bounded JSON stream with exact keys:

* contract: emqx-persistent-inventory-v1; version: 5.8.9
* generation: owner-quiesced generation; scope: source or target
* complete: true; eof: true
* tables: descriptors with exact table, input_sha256, input_bytes, record_name,
  attributes fields from actual native inventory/schema

`private_table(table)` returns the matching checkpoint byte stream. Native
`exporter(table, raw)` emits the existing checkpoint JSON contract, not a new
Mnesia format. Inventory must enumerate ALL persistent tables/files accounted
for by owner policy, including empty JWT and state outside supported projections;
never start from the exporter's whitelist. Unknown/unaccounted physical files
must fail inventory creation. Inventory completeness/EOF declarations are trust
boundaries for reviewed owner code, not authentication of user-written JSON.
Owner must hold mutation/issuance exclusion across inventory, all reads and
registration. Limits: <=256 tables, 8MiB per checkpoint, <=2GiB total sequential
checkpoint input; existing 1MiB/4096 values and typed-node bounds remain in force.

The old `observed_target_readers` absence-profile helper now requires the full
companion, same generation and complete matching table set; its MQTT/app
projection bytes must match companion bindings. Its effective-config subset
remains deliberately narrow and is NOT advertised as a normal broker config
parser. The new standalone binder/companion is the normal-inventory integration
path. Existing API rows still cannot satisfy plaintext api_secret in that helper.

## Mencius cold-history integration (source, not final-state recovery)

Read-only code inspection located Mencius's current `emqx_cold_history.py`,
`HistoryInventory`, native DETS/disk_log decoder and matching semantic-reader
historical-term revision in /tmp/emqx-native-adapter-20261122. These were still
uncommitted there when inspected; no files were copied or modified. Coordinate
that dependency's actual delivery commit before integrating the bridge.

`capture_cold_persisted_values(expected=owner_complete_receipts,
private_file=private_file_stream, finish_inventory=owner_archive_eof_finish,
generation=owner_generation, decoder=trusted_native_decoder)` directly uses
Mencius `HistoryInventory` (no competing cold format/decoder). Expected receipts
are his exact canonical path -> {kind, bytes, sha256} mapping. It consumes every
file with bounded EOF/finish, calls overall archive EOF+finish, then history.finish
before returning a source companion. Historical dump/log/deleted values remain
registered; history is never interpreted as final live rows. Unknown files/terms
or missing dependency refuse. The source consumer's cold-format/restore gate is
unchanged; this bridge does not authorize recovery/startup or commercial claims.

## Owner coordination and remaining verification

The user reports ARM 22 DCD files including admin/admin_jwt/ACL/retainer. This
branch did not inspect those rows or assert a fabricated complete table list.
Turing's tracked runtime worktree did not contain a complete shareable real table
inventory at inspection time; no dev-d query or private evidence read was made.
Turing must supply actual complete target table/schema inventory and canonical
source cold-file receipts, reconcile them with Mencius native coverage, and bind
one stable generation. Test actual native JWT empty/nonempty/EOF, every table,
issuance/rotation and caller evidence before upgrading source/target status.

No schema loosening, false empty acknowledgement, hash-to-secret substitution,
or source gate bypass was introduced. Source/target remain not assessed until
actual owner integration. Synthetic 22-table fixtures verify cardinality only;
they are explicitly NOT a real broker inventory or commercial validation.

## Validation

```sh
PYTHONPATH=backup-engine:tests/e2e/lab:. python3 -m unittest \
  test_emqx_persisted_values test_emqx_target_capture \
  test_emqx_runtime_credentials test_emqx_semantic_readers \
  test_emqx_private_boundary test_emqx_private_evidence \
  test_emqx_real_candidate test_emqx_source_consumer -q
```

Synthetic regressions cover multi-table/nonempty JWT capture, 22-table acceptance,
unknown native terms, native schema/digest/EOF failure, private stream closure,
source/target fullscan and actual evidence collision, owner reader binding,
Mencius history bridge ordering and late archive finish failure. The optional
`test_emqx_persisted_native_bridge` requires Mencius's matching cold-history and
semantic-reader revision; it uses only his generated synthetic native fixtures.
It must be reported separately from these synthetic contract tests.

Current validation results after Turing integration: 86 contract regressions passed; diff check
passed. Actual optional native bridge against Mencius's then-uncommitted working
tree: DETS/schema history -> companion scan PASSED; disk_log/DCD bridge FAILED
closed with persisted-values-unsupported at the dependency decoder boundary.
A separate synthetic native format diagnostic passed schema.DAT but refused
DCD/DCL/transaction/decision logs. This is an unresolved dependency issue, not
native full-source success; no native implementation files were changed here.

Turing update supplied by user: actual broker checkpoint attempt5 passed 14
checks including typed schema semantics and MQTT single-category projection.
Commit 7a283a9 supplies native atom/binary auth-group matching with independently
verified provider group binding. Cherry-picked 7a283a9 as 29753b8 with full inventory/companion support retained. Those 14 checks are Turing's actual evidence, not
this branch's runtime execution. Full target registry still refuses, source/
target full acceptance remains unestablished. Main candidate d97e078 contains
e38 base collector; rejected 13b9312 is not a recommended integration dependency.


Integration packaging: a standalone net-change delivery branch is based directly
on e38f996, with the final tree including Turing atom-group changes. Review/apply
that single delivery commit to a mainline containing e38; do not cherry-pick the
rejected 13b9312 as a prerequisite. Native checkpoint/coldreader dependency files
are not part of this delivery. Reader binding captures each producer exactly once
and freezes its validated bytes, avoiding credential re-issuance during preflight.
