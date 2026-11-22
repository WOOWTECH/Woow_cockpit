# Private EMQX runtime credential adapters

Base: `1b8f338`. Parent evidence commit `b134d5f` is integrated here as
`7f74bd7` (same files). No changes to `emqx_source_consumer.py`,
`emqx_private_boundary.py`, or product/public guard code.

## Callable workflow

`emqx_runtime_workflow.login_preflight` takes keyword arguments:

- `source_registry`: existing sealed `emqx_private_boundary.Registry`, populated
  by the source owner. Its scan runs before any owner callback and again on the
  exact evidence bytes. This adapter cannot establish the source reader's
  semantic completeness or supply the outstanding HOCON/Mnesia readers.
- `source_counts`: exact `backup-key`, `source-options`, `source-cookie` integer
  registration counts (0..4096, backup key nonzero), from that source owner.
  Counts must equal the sealed source registry actual unique-value registrations;
  mismatch refuses before target readers/login or evidence publication. Counts
  attest registration only, not semantic completeness of source discovery.
- `target_readers`: exact five-category callable mapping described below.
- `private_transport`: private callable `(username_bytes, password_bytes)`
  returning `(200, 'application/json', response_stream)`. No transport defaults,
  network access, logging hooks, argv/environment credentials, or HTTP client
  are added. The owner must disable request/response logging at its transport.
- `username`, `password`: private bytes; registered before the transport runs.
- `evidence_directory`, optional `evidence_name`: passed to the parent's existing
  `emqx_private_evidence.publish`; no duplicate evidence writer is implemented.

The workflow captures/registers target snapshots atomically, consumes a bounded
login response through EOF, closes it, registers the token and its Bearer form,
then invokes the parent publisher with a CombinedRegistry that scans through
both source and runtime registries. Token commit failure cannot reach publication
or return a usable credential. Invalid/failed login and incomplete snapshots
produce no evidence. The returned PrivateSession exposes `registry.scan(bytes)`,
`credential.with_bearer(private_consumer)`, `coverage`, and fixed `evidence` status.
The private consumer must be a reviewed transport, never a log/evidence callback.
Representations contain no credential values.

Only `preflight/passed` is emitted, meaning registration and login succeeded.
The workflow does not declare restore, startup, MQTT, restart or cleanup success.
It does not invoke the candidate builder, installer, Podman or a broker.

## Structured target captures

Each reader returns a private closable byte stream containing exactly:

```json
{"schema":1,"complete":true,"records":[]}
```

The owner must capture actual complete, unmasked material, including all pages,
and normalize it into this explicit version-1 contract. An empty array explicitly
acknowledges no records. Missing categories, extra fields/cursors, unsupported
records, duplicate JSON keys, masked credentials and external references refuse.
No adapter converts a masked REST listing into a completeness assertion.

| Category | Exact per-record fields |
| --- | --- |
| `mqtt-auth` | `username`, `password_hash`, `salt` |
| `api-keys` | `api_key`, `api_secret` |
| `connectors` | `type`, `username`, `password`; only inline MQTT is supported |
| `tls` | `cert_pem`, `key_pem`, `password` |
| `target-bootstrap` | `username`, `password` |

All fields are strings. Empty salt, connector username and unencrypted TLS
password are allowed; bootstrap username/password must be nonempty. API secret
and password hash must be nonempty. Connector type is validated metadata, not
registered as a secret. Unsupported connector backends, referenced credentials,
TLS chains or legacy PEM forms refuse. TLS reader registers PEM bytes, base64
body/lines and decoded DER bytes. It validates bounded PEM framing/base64 only,
not ASN.1, cryptographic validity, certificate trust or broker compatibility.
These normalized snapshots do not implement discovery of files, secrets,
Mnesia, target APIs, or container state. Actual owner capture integration and
its completeness review remain required before a real workload run.

Limits: 64 KiB per document/value/login response, 4096 distinct registered values,
1 MiB total registered bytes, and 1 MiB scanned evidence bytes. Runtime tokens
remain registerable after snapshots; use the same registry for later private
logins. Snapshot commit is atomic across all five categories. Registration,
scan and evidence publication require the parent's exclusive serial owner;
there is no concurrency/lock or secure-memory-zeroization claim. Exact-byte
scans cover raw, base64, hex, percent-encoded and UTF-8 JSON-escaped forms.
Short values may conservatively block a fixed category/status field; they are
never silently excluded. Parent publication also bounds category counts.
Failures/cancellation cross the adapter only as fixed PrivateFailure text with
suppressed exception chaining. Never publish traceback locals or private transport
output. A future caller must register additional issued credentials before use
or evidence; there is no automatic interception of arbitrary owner transport.

## Verification and acceptance limits

Final targeted run: **67 tests passed in 4.894 s**, no skips/failures:

```sh
TMPDIR="$PWD/.cli-test-tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:.:tests/e2e/lab python3 -m unittest test_emqx_runtime_credentials test_emqx_private_evidence test_emqx_source_consumer test_emqx_private_boundary test_emqx_real_candidate tests.backup.test_ha_emqx_preservation_guard tests.backup.test_ha_emqx_candidate_flow tests.backup.test_ha_emqx_package
git diff --check
git diff --exit-code 1b8f338 -- tests/e2e/lab/emqx_source_consumer.py tests/e2e/lab/emqx_private_boundary.py backup-engine/woowbackup/ha_emqx.py
```

Thirteen new adapter/workflow tests plus the parent's five evidence tests cover
registration order, failed token commit, bounded/duplicate/malformed/late-error
responses, closure, fixed cancellation/errors, atomic snapshot refusal, TLS
representations, exact evidence scan/write identity, actual 0600 files, and
source/runtime collision refusal before file creation. These use generated
credentials, synthetic transports and PEM payloads; actual temporary filesystem
publication is real. Existing generated encrypted-v3 and fake-broker tests are
regressions, not actual cold-v3 broker acceptance.

No live login, real snapshot source, network, Podman or dev-d use occurred.
No integrity fallback, Hermes retry, askpass read, original-data mutation,
production/.54/Pi access, runner/model changes or omnigent stop occurred.
Real broker acceptance remains pending source semantic readers, authoritative
owner capture/transport integration, confirmed lab gate and actual workload
validation. Public preservation blockers remain unchanged.

## Integration follow-up

`a8cbf5b` binds source counts to actual registry registrations. The affected runtime credential and private boundary regressions passed 24/24, with mismatched counts for each of the three source categories preventing login/publication. `f5099c4` integrates bounded semantic readers; 44 cross-module fixture tests passed, while native parser/exporter wiring and real cold-backup broker acceptance remain outstanding. These local tests do not establish commercial acceptance.
