# Private owner source registration

Code-only handoff, based on immutable main `8aa5929`. No lab or production
credentials were used to develop or test it. Main's actual ARM historical-value
results remain separate evidence; these tests do not attest actual configuration
parsing, target coverage, candidate restore or commercial HA acceptance.

`emqx_owner_source_capture.capture_owner_source` is the owner callable. Invoke it
inside the authorized owner workflow, with the existing private encrypted staging
archive and password already in RAM. It loads no credentials, starts no broker,
creates no target documents and emits no stdout/stderr evidence. It uses actual
`Capture.source_only`, `native_hocon`, `native_cold_history`,
`product_selection=True`, and the bounded256MiB private spool with its existing
reserve/0700/0600/EOF/finish/cleanup policy. Existing `NEVER_READ` selection means
source node.cookie is not extracted, registered as consumed or copied to a target.
Its explicit unused source-cookie acknowledgement remains empty.

```python
from emqx_owner_source_capture import capture_owner_source

with capture_owner_source(
    encrypted_staging_archive,
    password=ram_password,
    expected_sha256=immutable_source_sha256,
    spool_directory=private_owner_directory,
    required_encryption='v3',  # use the actual authorized archive format
) as (captured, private_binding):
    # Source binding's final consistency check has already completed.
    # Source historical values are registered, but the registry is UNSEALED.
    # scan(), summary(), seal() and private replay refuse without target data.
    # No evidence publication or candidate invocation belongs at this stage.
    pass
```

Do not manufacture JSON `[]` target documents. The normal source-only call does
not register any of mqtt-auth, api-keys, tls, target-bootstrap or connectors.
Inside the same live context, only when authoritative observed target documents
are available, the owner may call:

```python
captured.supply_target_documents(observed_target_documents)
```

The mapping must contain exactly those five categories as bounded self-contained
JSON bytes, using the existing target-document parser. All documents are parsed
before their categories are registered. A failed target completion is one-shot
and cannot be retried; missing, unknown or invalid snapshots keep the registry
unsealed. Completion must follow successful source capture and precede context
exit. It registers owner-supplied values, then applies the existing Registry seal
checks. Acceptance of snapshots is an owner acknowledgement, not independent
proof that the target inventory is complete; it does not replace the full target
producer or its generation binding, persisted JWT, TLS and reference coverage.

After completion the existing scan and private replay gates can operate within
the context. Replay refuses after context exit. Cold receipt semantics remain
historical-values-only with final_state=False. Unknown selected files, unsupported
metadata/HOCON/native contracts and late source failures refuse; no fallback
converts an unresolved configuration into empty source values. In particular,
main's currently failing real configuration diagnosis is not bypassed here.

The callable yields no source binding until source_binding's final consistency
check passes. Cancellation/failure cleans the private spool and crosses this
callable boundary only as fixed `private-owner-source-cancelled` or
`private-owner-source-refused`. Existing public preservation guards and native
runtime implementations are unchanged. The main owner/transfer/controller files
are intentionally unchanged to avoid competing with the active owner diagnosis;
when main wires this callable into its transfer, its immutable git-archive list
must include this module, emqx_source_consumer.py, emqx_native_hocon.py,
emqx_hocon_native.escript, and their existing semantic/native/boundary dependencies.

Generated integration verification (no Podman/native processes):

```sh
PYTHONPATH=backup-engine:tests/e2e/lab python3 -m unittest \
  test_emqx_owner_source_capture test_emqx_source_consumer \
  test_emqx_source_cold_capture test_emqx_private_spool -v
```

29/29 passed, including nine new tests. The owner tests use real generated
SecureTar v3 decryption, source_binding and actual private disk spool; the native
adapter boundary supplies generated contracts. Tests cover unsealed source-only
operation, explicit nonempty target registration and secret scanning after seal,
invalid/missing target refusal, lifecycle/retry gates, unknown selected files,
wrong archive SHA, late native failure and mutation detected by source_binding's
final check. No real ARM configuration or source values were accessed.

Additional adjacent verification: 12/12 passed with
`PYTHONPATH=backup-engine:.:tests/e2e/lab python3 -m unittest test_emqx_private_boundary tests.backup.test_ha_emqx_preservation_guard -v`.
`git diff --check` passed; product public guard and the integrated actual
owner/transfer/controller files are byte-for-byte unchanged from `8aa5929`.
