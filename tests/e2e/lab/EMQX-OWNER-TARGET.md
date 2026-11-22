# Executable owner-side target observation increment

Code: emqx_owner_target.py and the fixed emqx_owner_target.expr. No lab/dev-d
operations or real secret reads were performed in this delivery. Main remains
sole lab owner. Candidate code read for integration: 8aa5929, including existing
emqx_broker_export.py. No independent review workflow is involved.

## Invocation by owner (not executed here)

```python
from emqx_owner_target import broker_target_readers

with broker_target_readers(
    broker=invocation_owned_broker,
    checked=checked,  # same private transport as emqx_broker_export
    quiesce=owner_exclusive_quiescence_context,
) as target_readers:
    session = login_preflight(
        # existing source/private login inputs and evidence arguments
        target_readers=target_readers,
        **owner_preflight_arguments,
    )
```

Creating the context is lazy. Entering it executes ONE fixed native expression
via checked('exec', broker, 'emqx', 'eval', expression). No discovery, new broker,
volume mutation, checkpoint conversion or default transport is installed.
The owner must exclude client writes, configuration mutations and issuance while
the context remains open; a Python lock by itself does not quiesce external MQTT
clients. The transport must bound execution/output and never log private reply or
stderr. The existing checked transport is used as supplied, not bypassed.

## Actual producer path

The expression reads emqx:get_config([]) (cooked effective config, not a HOCON
file or REST listing), native global authenticator provider state, and
mnesia:system_info(tables). Built-in nonfragmented table types only. A native read
transaction locks all data tables and folds every current row; schema metadata
is collected as table_info(...,all) for EVERY table, including schema. Schema is
metadata coverage, not a fabricated zero-row data table. The table set/config/
provider state are checked again before returning the complete structured reply.
Only producer-generated nonce interpolation is used; no input table/path/schema
is turned into Erlang code. Native table/record/attribute identifiers are checked
against the existing safe lowercase atom-name profile on receipt.

The private consumer validates pinned EMQX/OTP/ERTS, generation, exact inventory,
row counts/tags/arity and bounded typed data. Every config/provider/schema/table
private value enters the companion, including numeric strings, true/false atoms,
binary/charlist values, hashes, existing JWT and retained payloads. No short-value
exclusion. Full exact scanner and public guards are unchanged. The producer
builds MQTT fields from the actual auth table and derives its expected group from
provider state (atom or binary), never from that table's rows.

Empty API records require an actually observed empty emqx_app with the existing
exact native schema. Any existing row refuses; API hashes are never plaintext.
Connector/TLS absence is derived from required cooked roots, not caller-supplied
empty snapshot dictionaries. Bootstrap username/password come directly from
native dashboard defaults, are validated and registered privately. Both five-key
readers and the companion are frozen/bound to the same nonce and register through
the unchanged exact snapshot contract.

## Restricted supported config and limits

Required cooked roots include connectors, bridges, actions, sources, gateway,
exhook, authentication, listeners, dashboard, api_key, cluster, rpc and node.
Connector/bridge/action/source/gateway maps and exhook servers must be observed
empty. Supported auth is one enabled global built-in username/password provider,
TCP-only enabled listeners, no local auth chains, disabled SSL/WS/WSS listeners,
dashboard HTTPS bind integer zero, empty API bootstrap_file, manual cluster,
TCP RPC and inet_tcp distribution. Nonempty file/env/vault/substitution refs,
TLS materials, missing roots/default credentials, masked values, configured
connectors, SCRAM/client-id auth, wrapped-function secrets, executable native
terms, fragmented/custom backend tables and unsupported config refuse explicitly.
Other cooked roots are retained in the private superset, never silently dropped.

Bounds: 1MiB native JSON, depth16, 64 inventory tables, <=4096 total data rows,
existing aggregate private value/node limits; all unknown terms refuse. The
native expression was subsequently tested in a fresh synthetic dev-d fixture:
native parser and single-line CLI eval passed, but native_tables returned a fixed
badmatch failure. No complete native observation/registry success is claimed.
See EMQX-OWNER-TARGET-NATIVE-HANDOFF.md for preserved attempts and ownership
return. Deeper table_info/fold/schema and cooked secret compatibility is pending.
This is current live-state coverage, not historical DCD/DCL EOF traversal,
checkpoint export or source recovery. Existing cold historical companion support
remains separate and is not marked successful by this live producer.

## Local validation (no lab)

Transport-response fixtures exercise the executable callable through all five
readers and the original registry, matching native typed config and row layouts;
extra config values, schema metadata and nonempty JWT/ACL/retainer values are
scanned. Tests include actual checked argument dispatch, lock lifetime, wrong
nonce/provider group, missing roots/table coverage, native function terms,
nonempty API hashes, TLS/bootstrap refs and fixed failure diagnostics.

The fixture uses generated config/rows and illustrative generic table schemas;
it is NOT a real broker observation. A separate integration test exercises the
main candidate's names-only preflight publisher and private session counts when
that main-owned dependency is present. No workflow/publisher files are changed.
All actual broker execution and full-target acceptance remain with Turing/main.
