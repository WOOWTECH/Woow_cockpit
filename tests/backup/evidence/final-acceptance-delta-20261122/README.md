# Final acceptance delta — 2026-11-22

Audited main **c8471ed8bf1582ccea8d626da102cdd4b045da8f**, after integrations
0168078→36d13a9, 25d5cf2→7566d44, cd849408→fe30094. c8471ed changes only
progress metadata. No backup-engine file changed from 3fe2ff3 to this snapshot.
This is an independent **local artifact audit**, not commercial acceptance or a
service rerun. No remote access, .54 mutation, labs, Hermes review, or passed
suite replay occurred in this lane.

| Requested gap | Accepted evidence delta | Exact boundary / next minimal uncovered test | Blocker |
| --- | --- | --- | --- |
| Large backups / single member >8GiB | Real x86 age-X25519/zstd 8193MiB nonsparse member: generated, verified, extracted; source/extracted SHA equal. Missing/wrong keys rejected. Existing plain/gzip result retained. | Ciphertext is only **34,519,040 bytes**, not >8GiB. Next: bounded large encrypted **late corruption** and **mid-stream cancellation**, asserting refusal, child termination and payload/key cleanup. Incompressible >8GiB outer archive and ARM large service restore remain separate unproved claims. | Positive-run artifacts/ephemeral keys were deleted, so no independent payload rehash now. Negatives assigned to large-archive owner; outer-archive test needs sufficient storage/reserve. |
| Native ARM service / cleanup | Real native rootful Headscale: synthetic HA converter → private import → startup → gRPC CLI source-user assertion. Real containers/volumes underpin six TempObjects checks across **two** attempts. | RootfulRunner allows direct namespace reads/stat because rootful unshare failed; **not production OwnerRunner/rootless**. One removal return125 is injected before transport, followed by real residue detection/retry. Next: production OwnerRunner lifecycle with real internal-network cleanup and actual transport-error residue/retry if claiming those guarantees. | Production namespace/deployment coverage absent. VPN registration still fails; zero nodes in passed chain. No installer/rollback, Headplane UI/nonempty API-key behavior or real-original acceptance. Banach owns remaining ARM cleanup work; no repetition of six passed scenarios requested. |
| Cross-physical-device restore | Earlier x86→ARM→x86 synthetic archive roundtrip (8,396,860 payload bytes) remains recorded. New converter/service source and target are **on the same ARM host**. | Next: one authorized physical HA-source→independent ARM-target private service restore, verifying source identity/config semantics; after registration is fixed, verify VPN node identity/IP and reconnect. | Same-host synthetic service evidence does not close physical service migration. Registration root cause unresolved; public install/rollback untested. No remote work performed/authorized by this audit. |
| Final integrated version | 32/32 explicit local R2 methods, no skips/xfails; final log and 50 before/after source hashes verified. ARM 42 engine files match main. All three original evidence sets survive integration byte-for-byte. | R2 executes real Python/archive/crypto but service/PG/owner transports are simulated. Next real R2 gap: one reviewed cold-v3 EMQX source through private build/package with real broker/runtime, complete-stream checks at each consumer, and independent cleanup evidence. Retain public refusal guards. | No real-source/broker proof in R2. Final source equality is not remote-execution attestation or commercial acceptance; rootless/public deployment remains open. |

## Integrity and provenance corrections

`python3 tests/backup/audit_final_evidence.py` passes **33 offline consistency
checks** across **80 changed/new committed evidence files**, with **165 manifest
bindings: 164 match main; one explained historical mismatch**. Detailed paths,
SHA-256 values, exit statuses and original/integrated commit IDs are in
[integrity.json](integrity.json) and [source-bindings.json](source-bindings.json).

* Initial `arm54_build_native.py` SHA `e11d25537ef3063a7c1882ef9ac4bb99965bf52e7926fe9b2c916bfd14b4d40e`
  matches `native-package-build.source.txt` (failed attempt). Final source SHA
  `2fe64604bdddd1e76b0555c6fb649d356064eda9716940628b9cb3ff69ccee54`
  matches main. The original manifest must retain the initial hash. Final harness
  inventory is not proof that every final script ran. Successful service-converter
  snapshot **does** match final `arm54_service_native.py`; neither lifecycle
  snapshot equals the final combined six-case harness.
* Initial lifecycle exited1 after three successful checks with a fixture
  `ValueError`. Completion exited0, **copied those three checks** and executed
  cancellation, sweep, and injected removal-refusal/retry. Six checks passed
  across attempts; no clean six-case final-harness execution is asserted.
* Official package recipe was locally rebuilt on ARM; binary equals pinned
  upstream. This is **not a shipped image**. Rootful adapter reads actual namespace
  IDs; it does not simulate IDs, but bypasses production OwnerRunner transport.
* Encrypted manifest's four recorded source hashes all match main. Five omitted
  direct dependencies (`util`, `errors`, `paths`, two archive test helpers) now have
  a [retrospective sidecar](encrypted-dependency-sidecar.json): identical at recorded
  base, producer commit and main. These are repository hashes, not fabricated
  runtime measurements or a complete transitive/environment manifest.
* [Secret scan](secret-scan.json): **zero matches** for private-key, age secret,
  Tailscale/GitHub/Slack/AWS token, JWT, bearer, credential-URL and quoted credential
  patterns in the 80 committed evidence files. This does not prove absence of
  arbitrary encoded/unknown-format secrets. No private runtime key store was read.

Raw failed attempts are retained. Deleted archives/images/upload bundle cannot
be independently rehashed from these committed artifacts; recorded payload/image
hashes, disk samples and remote cleanup assertions are internally checked or
classified, not replayed. Historical `.34`/`.54` metadata is evidence only.

The adjacent progress-status diff fixes the stale ARM `next` task, separates
same-host converter success from physical service migration, and links this audit.
No product/public-guard changes are needed for these provenance corrections.
