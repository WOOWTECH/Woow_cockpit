# Native HOCON minimum delivery (2026-11-22)

Actual offline native parsing verified using the already cached image:
`sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b`.
Image labels identify EMQX 5.8.9, source a8319fe2390169e1f2483e3ec80dd01a6cdb233d,
OTP 26.2.5.14-1. Native hocon 0.44.0 BEAM abstract source was inspected locally
(hocon and hocon_token); no upstream network fetch or host Erlang required.
The original loose upstream checkout was not located in this turn. The shipped
native BEAM is executable, not a simulated contract or regex HOCON substitute.

`emqx_native_hocon.native_hocon(bytes)` is owner-selected trusted code. It runs
only escript, never a broker, in a rootless networkless read-only container with
no host data mounts beyond a private temporary directory containing this script
and one synthetic/source HOCON input. Cached image only, no pulls. Bounds: 8MiB
input per file, 32768 scanner tokens, AST depth 32, 1MiB JSON output, 256MiB
container RAM, 64 tasks, CPU 10s, container timeout 15s, client timeout 20s.
Private input file is 0600 in a 0700 temporary directory; diagnostics discarded.
Container expiration is independent of the client timeout. No ETF decoding.

Native scanner rejects include/variable tokens before parsing. AST rejects them
again. Pipeline calls parse, expand, concat, transform; include and resolve are
never called. Native map and all AST string components are returned together
under document.parsed/document.syntax_strings so duplicate overrides and
concatenation do not drop private strings. External-file keys are conservatively
refused even if overwritten. Semantic reader still applies all original limits,
reference checks and key registration. Generic keys such as password can thus
reject harmless evidence containing the same word; this is deliberate conservative
coverage, not evidence that every original source format is supported.

Consumer opt-in: `Capture(password, target_documents, hocon_parser=native_hocon)`
or `build_consumed_candidate(..., hocon_parser=native_hocon)`. Exact accepted
paths: data/emqx/data/configs/cluster.hocon, data/emqx/etc/emqx.conf,
data/emqx/etc/base.hocon. Unknown files refuse. Default remains unsupported.
All HOCON and addon values combine into the private source-options registration.
No whole-source success is claimed from per-file HOCON parsing.

Spool integration: parent e46915d is included as a dependency. Opt in with
`spool_directory=caller_owned_0700_directory`. Use Capture as a context manager;
build_consumed_candidate holds that context for the whole candidate build.
Spool consumes full EOF and finish before archive validation or native parsing.
Validation and tar iteration seek over the private file; each recognized HOCON
member alone is read into bytes (maximum 8MiB). Replay seeks the same open file,
and context exit cleans it up on success or failure. No entire spool read into
bytes. Legacy callers without spool_directory retain the original 8MiB memory
path. Spool retains parent's 256MiB maximum and 12GiB free-space reserve.
Preflight encrypted layout members (x86 137936119B, arm 117195765B) are NOT
measurements of the expanded open_addon tar stream. Parent subsequently reports
ARM fullEOF+tarcomplete+finish at 117760000 expanded bytes / 43 files, fitting
256MiB. Parent also reports x86 full tarEOF+finish under an explicitly bounded
512MiB / 30-second read-only probe: 290785280 expanded bytes / 43 files. Its
256MiB rejection is a capacity refusal, not wrong-key evidence. Both inventories
contain Mnesia DCD22, DCL3, LOG2, DAT1. Parent reports original archive SHA binding;
this branch did not replay those sources or independently verify their counts/SHA.
Candidate still uses 256MiB and therefore continues to reject that x86 stream.
Future x86 consumption requires an explicit per-source byte/time budget bound to
the expected archive SHA; no global limit increase, automatic retry at a larger
limit, or weakening of per-file/schema/EOF/finish/private-value checks follows
from this capacity evidence. Cold Mnesia, unknown files and commercial acceptance
remain separately gated; successful stream counting is not checkpoint support.

Mnesia gate: any file below data/emqx/data/mnesia/ raises the fixed
private-source-native-mnesia-unsupported before reading or decoding it, sealing
or candidate runtime. Other unknown Mnesia paths still refuse as unknown files.
DAT/DCD/DCL are not native checkpoint exports. No safe offline checkpoint
exporter is installed; read_mnesia remains unsupported without a separate trusted
exporter. Only lab owner Turing01a2025f-4294-7301-a4b9-4d624f51ab0e may provide
future lab exports. No dev-d, production data/secrets or Hermes review activity.

Run actual native and boundary regressions:
`PYTHONPATH=backup-engine:tests/e2e/lab:. python3 -m unittest test_emqx_native_hocon test_emqx_semantic_readers test_emqx_source_consumer test_emqx_private_boundary test_emqx_private_evidence test_emqx_real_candidate test_emqx_private_spool -q`

Final validation: 53 tests passed in 24.253s, including actual native parser,
spool-to-native consumer/replay lifecycle, late finish failure before parser,
Mnesia refusal before seal, private evidence and candidate regressions.
`git diff --check` passed. This worktree includes semantic readers as 9f96d9f
(equivalent to 458031e/f5099c4) and parent spool as 114c422 (e46915d).
Integrators already containing those dependencies should cherry-pick only the
native adapter delivery commit.

Runtime hardening follow-up: all native runs require targeted `podman info`
metadata to report `true crun`, explicitly select `--runtime=crun`, disable image
VOLUME creation with `--image-volume=ignore`, use the immutable image ID, and
clean/check only their invocation-random container name. No container/volume
inventory or production mount is consulted. Native VM atom cap is 65536 and
default process max heap 8388608 words (64MiB on this amd64 image).
