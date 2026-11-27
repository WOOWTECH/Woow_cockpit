# EMQX semantic reader handoff

Independent baseline 1b8f338. Parent owns `emqx_source_consumer.py`; it and
product/public guards are unchanged. New module: `emqx_semantic_readers.py`.
No production/lab/container/SSH activity, credentials or real secret payloads.

## Verified source facts

Local upstream checkout is EMQX v5.8.9 at
`a8319fe2390169e1f2483e3ec80dd01a6cdb233d`; exact read source hashes are in
`source-facts.json`. rebar.config and mix.exs pin emqx/hocon 0.44.0.
`emqx_mgmt_data_backup.erl` uses hocon:files for config, emits META.hocon and
cluster.hocon, exports tables using activate_checkpoint/backup_checkpoint, and
validates Mnesia exports with read-only traverse_backup. Native backup files
must not be treated as JSON, Erlang source, ETF or Python objects.

## Parent interface

`read_hocon(raw_bytes, trusted_parser)` returns a private `Values` object;
`read_mnesia(raw_checkpoint_bytes, table_name, trusted_exporter)` does likewise.
`.values` exposes a tuple of bytes for the PRIVATE registry only. Do not print,
serialize or include it in diagnostics. repr is fixed and all errors are fixed
`emqx-semantic-source-unsupported`, with suppressed exception context.

Adapters take the exact source bytes and return UTF-8 JSON bytes. Common exact
keys: contract, version (`5.8.9`), input_sha256, input_bytes, complete (`true`).
HOCON contract `emqx-hocon-json-v1` additionally requires resolution (`disabled`),
references (empty list), document (entire parsed config object). Include and
substitution detection MUST happen before any resolution, including optional
substitutions. No field projection or redaction is permitted. A parsed tree
alone cannot prove that includes/references were absent. Any declared reference
or file dependency refuses; no regex parser or JSON-as-HOCON fallback exists.

Mnesia contract `emqx-mnesia-checkpoint-json-v1` additionally requires table,
record_name, exact attributes list, rows and schema_validated (`true`). Trusted
exporter must validate checkpoint headers/schema and traverse to EOF read-only.
Rows are tagged tuples including the record atom. Every term is exactly
`{"type": kind, "value": value}`. Supported kinds: binary (canonical base64),
atom (UTF-8 string), integer (signed 64 bit), tuple/list (array of terms), map
(array of key/value term pairs). Raw binary values, atom strings, map keys and
values, and byte/Unicode charlists are collected. No fun/pid/ref/ETF or arbitrary
deserialization is supported. These are complete typed term readers for private
value coverage, not business-row validity or restore authorization.

Pinned layouts: emqx_authn_mnesia/user_info, emqx_authn_scram_mnesia/user_info,
emqx_acl/emqx_acl, emqx_admin/emqx_admin, emqx_app/emqx_app. Exact fields live in
TABLES and are verified against the upstream records. Old api-key `desc`
layouts and all other tables refuse, including banned/retainer/PSK. Parent must
account for EVERY source file/table and register combined categories once;
per-table success is never a full source coverage seal. Unknown table/file
coverage must keep the consumer fail-closed.

## Bounds and limits

Input 8 MiB, output JSON 1 MiB, each private value 64 KiB, aggregate private
values 1 MiB, 4096 unique values, traversal 8192 nodes and depth 16. JSON rejects
duplicate keys, trailing content, nonfinite numbers and invalid UTF-8. Typed
map duplicate keys, malformed/noncanonical base64 and unknown fields refuse.
Partial traversal or late failure returns no private result.

Adapters are trusted injected CODE, never supplied by an archive. Their own
execution/memory bounds and absence of filesystem/environment/network resolution
remain adapter obligations. This module has no subprocess or IO and cannot
sandbox an arbitrary Python callback. No native adapter is installed here;
there is NO claim that a real HOCON or HA Mnesia source was parsed. Without a
trusted adapter both interfaces refuse. Raw cold DAT/DCD/DCL files are NOT
native checkpoint exports; obtaining a safe export is separate parent work.

Validation command:

```sh
PYTHONPATH=backup-engine:tests/e2e/lab:. python3 -m unittest test_emqx_semantic_readers test_emqx_source_consumer test_emqx_private_boundary -q
```

Tests exercise structured contracts with generated fixtures, not an EMQX runtime.
