## 2026-11-21 bounded CLI negative-test increment

Incremental tests on candidate `6b34dba`; no implementation or public-guard
changes. The coordinator reports the earlier two commits integrated on main as
`6ab87c2` / `79dfbc0`; those objects are not present in this checkout. This
increment does not replay either earlier patch.

Three new subprocess tests use locally generated SecureTar v3 ciphertext and
test-only passwords, with the real CLI and streaming decryptor (no decrypt
mock). Six negative cases cover missing `--key-stdin`, empty stdin, wrong key,
oversize key, non-ASCII input and multiline input. Each requires exit 2, exact
fixed-field refusal JSON, empty stderr, no key/payload/private-path markers,
no prepared directory and unchanged source bytes. A valid-key subprocess
control requires exit 0 and the expected v3 metadata with restore disallowed.
The third test leaves stdin open after 1025 bytes and requires refusal within
10 seconds, proving the CLI does not wait for EOF or read beyond the bound.
Every subprocess has a 10-second timeout; the open-pipe child is killed and
reaped on failure. Output checks avoid echoing unexpected secrets in assertion
failures. These fixtures prove encryption and metadata boundaries, not valid
broker data or service acceptance.

Exact local results (no skips or failures):

- Fixture suite: **27 tests passed in 3.478 s** (24 existing + 3 new).
- Existing EMQX preservation guard / candidate / Headscale suites:
  **25 tests passed in 3.942 s**.
- `git diff --check`: passed.

Commands used the existing interpreter and dependencies, with
`PYTHONDONTWRITEBYTECODE=1`, `PYTHONPATH=backup-engine:.` and `TMPDIR` set to
`.cli-test-tmp` inside this checkout. Test temporary files were cleaned up.
Only generated archives were opened in this increment. No real restore, lab
command, production credential access, Hermes review, runner/model/workspace
change or omnigent stop was performed. Public preservation guards remain intact.

## 2026-11-21 encrypted cold-source increment

The older unsupported-encryption note below is superseded for the private key path.
`--key-stdin` reads at most 1025 bytes, refuses input over 1024 bytes, and passes
an in-memory `hasecuretar.Keys` into the existing product streaming decryptor.
Keys are never argv values or written to the report. Missing keys still refuse
before opening encrypted members. `source_binding(..., keys=...)` uses the same
validated context. Private preparation copies the original encrypted archive,
not a plaintext export. `restore_allowed` remains false.

24 local tests passed, including real generated SecureTar v3 decryption and
binding, wrong-key refusal, hot-source refusal and bounded invalid stdin. The
first run had two fixture construction errors (`./backup.json` spelling), fixed
before the passing run. These tests are not service acceptance.

Using only existing lab fixture credentials in memory, both actual stopped-enc
archives were fully streamed and their selected member headers checked. x86 is
amd64, ARM is aarch64; both inner states are stopped, addon 5.9.1 and upstream
5.8.9. Sanitized evidence is `evidence/emqx-cold-encrypted-preflight-20261121.json`.
No plaintext files were created, no containers started and no restore ran.
This does not validate Mnesia contents, workload canaries, ACL behavior or grant
permission to restore original data. All existing restore/guard restrictions remain.

# EMQX / Headscale real HA fixture preparation — 2026-11-21

Base: `d06e1668006a351f14339335e08b4781892c8214`. Candidate only. No lab,
network, production credentials, original service or conversation-runner changes.
No Hermes independent review attempted. dev-d remains LiteLLM-exclusive.

## Located fixtures and actual result

Root: `/home/woowtechopenclaw/.woowbk-lab/ha-fixtures/20261119-b1`.
See `evidence/real-fixture-metadata-20261121.json` for all eight archives / sixteen
app selections. Only outer/addon metadata and member headers were interpreted;
payload was drained by the strict reader, never extracted or printed. No keys
were supplied. Full-archive SHA256 binds bytes, not authenticity or provenance.

| App | Existing real fixture | Offline result | Next source gate |
|---|---|---|---|
| EMQX | x86 and ARM `*-plain` | `cold-backup-required` | Existing plaintext is hot; cannot use it for this acceptance |
| EMQX | x86 and ARM `*-emqx-stopped-enc` | outer member is securetar v3 | Encrypted preparation deliberately unsupported; need an authorized cold plaintext test export or separately reviewed private key/decryption path |
| Headscale | x86 and ARM `*-plain` | metadata contract passes: stopped, add-on 0.1.3 → upstream 0.29.4 | Content, target compatibility and service acceptance remain pending |
| Headscale | EMQX-only stopped archives | `missing-or-ambiguous-addon` | Not a Headscale fixture |

The stopped filename alone does not prove stopped inner state for encrypted
archives. No decryption, private copy, candidate build or restore was performed
on real backups in this task. No real fixture has been accepted end to end.

## Runnable offline preparation

Run from this checkout, using the existing Python dependencies. No Podman or
owner transport is called, so these commands can run inside the original lab
when its owner schedules the work, without changing its network or runner.

```sh
export PYTHONPATH=backup-engine:tests/e2e/lab
python3 tests/e2e/lab/ha_real_fixture.py /private/path/to/backup.tar \
  --app headscale --target-version 0.29.4 --metadata-only
python3 tests/e2e/lab/ha_real_fixture.py /private/path/to/backup.tar \
  --app headscale --target-version 0.29.4 --prepare /private/new-fixture-dir
```

`--prepare` only follows a successful full member-header pass, including gzip
CRC/trailer and strict archive checks. It copies the exact original archive to
`source.tar` (0600) in a newly created directory (0700) and records fixed-field
`preflight.json` (0600). Existing destinations are rejected; failed partial
copies are removed. File stamps and SHA256 detect replacement/modification
between validation and copy. This is not a defense against a malicious local
owner mutating bytes during runtime; only the scheduled lab owner may write
staged fixtures. Full archives can contain other apps and secrets: keep the
entire directory private, never attach it as evidence.

Both apps require exact outer/inner version agreement, known architecture,
known product version matching the requested target, `state=stopped`, required
nonempty regular members, and a completely checked archive. EMQX additionally
requires exactly one Mnesia node directory with data. Unsupported encryption,
missing/ambiguous app, unknown version/architecture, links in selected paths,
special entries, hot/unknown state, corruption, oversize and source changes
fail closed. JSON never includes raw exception text, config values, image
names, node names, key bytes or archive-controlled paths.

The caller-supplied target version is an assertion for offline preparation,
not evidence from the installed image. The later product target check must
read the pinned local image label and verify it again. The tool deliberately
does NOT parse SQLite, HOCON, Noise key bodies, TLS keys or policies. Nonempty
files can be semantically invalid; `semantic_validation=pending` and
`restore_allowed=false` remain true even on a successful metadata contract.

## Concrete source wiring and differences

`ha_real_fixture.source_binding(path, app, target_version, expected_sha256)`
is a context manager supplying exactly `work.open`, `work.addon_member` and
`work.addon_info`. It hashes and rechecks the original archive, uses the actual
repository-prefixed slug and actual inner AddonInfo, retains the open fd, and
rejects requests for another app/member. Use these bindings only within its
context and close every member stream before leaving it. No function here
calls a converter, installer or public import API.

```python
with source_binding(private_source, app.id, verified_image_version, approved_sha256) as source:
    # work is the separately reviewed disposable-target work object.
    for name, function in source.items():
        setattr(work, name, function)
    # Future scheduled harness calls the existing product checks here.
    # This preparation patch intentionally performs no conversion/restore.
```

| Existing synthetic seam | Required real-source wiring / contract |
|---|---|
| `emqx_ha_candidate.backup_from_volume` manufactures HA metadata | Use the verified original `source.tar`; never relabel a hot source as stopped |
| `emqx_ha_candidate.build_candidate` hardcodes slug and 5.9.1 | Replace its three work bindings with `source_binding`; actual add-on version maps through product VERSIONS; obtain target 5.8.9 from the pinned image |
| EMQX `_build_candidate` / `_package_candidate` | Remain internal only; full effective ACL/settings/bootstrap/reference/TLS checks still required. Public `analyse` and `convert` retain PRESERVATION_BLOCKER |
| EMQX synthetic user/retained-message markers | Need authorized real-source expected counts and functional canaries; target business Mnesia is replaced, target configuration preserved; source API keys replace target keys |
| `headscale-product-convert.py` builds tar from synthetic volume | Separate its synthetic tar creation from work construction, bind original archive; retain real `ha_headscale.convert`, target parsing and sandboxed SQLite checks |
| Headscale synthetic CA, clients, grants and log-scanner sources | Real-source client identity/canary fixture and complete private-source registration are still absent; do not reuse synthetic two-node assumptions |
| Headscale credential behavior | Preserve source Noise/node IDs/public keys/IPs; remove source API keys, preserve target API keys and Headplane data; prefixes/migrations/schema/policy must pass product checks |

The binding is executable and boundary-tested; the service drivers are NOT
switched to real mode by this patch. They still create synthetic fixtures.
This avoids implicitly treating their synthetic secret scanner and known
canaries as coverage for arbitrary real backup contents.

## Exact remaining gates, in order

1. **Source**: resolve EMQX cold plaintext input without touching production
   credentials. Headscale already has two metadata-compatible originals; choose
   x86/ARM case and bind its inventory hash. Establish authorized test provenance.
2. **Exclusive slot**: coordinator releases LiteLLM's dev-d slot, grants the next
   owner the slot, then existing owner.sh isolation and headroom checks pass.
   Do not run any lab command now. No new network configuration is authorized.
3. **Private data / target**: register real fixture private sources with bounded
   evidence handling; select disposable targets, pinned images and reviewed
   effective configuration. Reject unsupported secret encodings/references.
   Product runtime checks must validate EMQX node name/Mnesia/default admin,
   ACL and cluster preservation; Headscale SQLite integrity/schema/version/
   migrations/node prefixes/Noise key/DNS/policy and target API-key preservation.
4. **Real workload assertions**: supply source and target baselines without
   credential output; EMQX actual MQTT auth, ACL denial, retained data, bootstrap,
   target setting persistence; Headscale existing client identities and private
   client state, automatic reconnection before manual intervention, relay and
   source/target API authorization. Metadata success cannot satisfy this gate.
5. **Candidate + installer + rollback**: explicitly schedule the real-source
   disposable candidate chain and failure injection. EMQX synthetic joined
   chain passed, but real fixture has not. Headscale synthetic conversion,
   55-second auto-reconnect and 10/10 relay passed, but installer rollback,
   Headplane UI and real-source identity recovery remain unproved.
6. **Evidence / cleanup / release**: compare independent before/after objects,
   original service preservation, private-source scan coverage and all attempted
   runs. Public guard removal or original-HA restore is a separate decision;
   this task grants neither and no preparation output is an approval token.

## Local verification

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 -m unittest discover -s tests/e2e/lab -p test_ha_real_fixture.py -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backup-engine:. python3 -m unittest tests.backup.test_ha_emqx_preservation_guard tests.backup.test_ha_emqx_candidate_flow tests.backup.test_ha_headscale
git diff --check
```

New tests cover both apps/architectures, hot/unknown state, version mismatch,
missing members/Mnesia, ambiguous Mnesia, links, traversal/redaction, unknown
architecture, encryption refusal before opening, copy modes/no overwrite,
failed-copy cleanup, actual non-default slug binding, wrong-app binding, hash
mismatch, source changes, duplicate/truncated archive and size limit. Payload
contents in these unit fixtures are intentionally fake: they prove the metadata
boundary and do not claim database or broker validity.

Recorded results: **21 new tests passed** (0.443 s); **25 existing EMQX guard /
candidate / Headscale tests passed** (15.746 s). `git diff --check` passed.
Only these local tests and read-only real-backup metadata passes ran. Private
copy cleanup was tested using generated unit fixtures; no lab cleanup is
claimed because no lab objects were created or inspected.
