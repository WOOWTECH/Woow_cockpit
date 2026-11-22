# Offline cold historical-value superset (selected files only)

This adds SECRET VALUE COVERAGE without calculating final business rows. An old
DCD value, its replacement in DCL, a deleted object's value, and un-replayed LOG
values must all remain private. Proving replay/final-state semantics is not a
prerequisite for this superset capture. Subsequent authorized isolated COPY
recovery and checkpoint validation remain separate work.

No sourceconsumer edits are included. Parent owns product_selection, exact STAGED
selection, safe full-tar EOF/finish, excluded-file discard receipts and cookie
absence. This reader receives ONLY explicitly selected Mnesia file bytes. It
never opens a true archive, source directory, production volume or live broker.
No true HA service is started here; tests generate data containers without even
starting synthetic Mnesia. Turing remains sole lab/dev-d owner.

## Parent interface

```
from emqx_cold_history import HistoryInventory, native_cold_history

# receipts from trusted COMPLETE validated tar/product selection, not a claimed
# list inside the archive: every selected Mnesia file must be accounted for.
receipts = {
    'data/emqx/data/mnesia/<node>/schema.DAT': {
        'kind': 'schema-dat', 'bytes': exact_size, 'sha256': exact_sha256},
    # every other selected Mnesia member, including tables outside TABLES
}
inventory = HistoryInventory(receipts, native_cold_history)
# For each selected file, read only this bounded member (<=8MiB) from the already
# EOF+finish-validated, archive-SHA-bound spool. Do not read the whole tar to bytes.
for path, raw in bounded_selected_members:
    inventory.consume(path, raw)
private_values = inventory.finish().values
# Merge these into the parent's private registration exactly once, before seal.
# Do not print, serialize as evidence, or expose private_values/native JSON.
```

Expected paths are canonical relative paths. Every expected file is consumed once
with exact size and SHA256; unexpected/missing/duplicate/mismatched files poison
finish. A late decode/value-limit failure yields no Values result. At most64
files / 8MiB per file / 32MiB total selected native bytes. Existing private value
limits remain 4096 unique / 64KiB each / 1MiB aggregate. Expected inventory cannot
prove its own completeness: parent must bind it to exact product-selected tar
members and original archive SHA before accepting the result. Unknown selected
files cannot be omitted, silently classified, or acknowledged by an empty list.
Default decoder is absent; owners explicitly inject native_cold_history.

Supported kind values and exact native container versions:

| kind | native format |
| --- | --- |
| schema-dat | DETS9, set, keypos2, read-only, repair=false |
| dcd | internal halt disk_log, dcd_log 1.0 |
| dcl | internal halt disk_log, dcl_log 1.0 |
| transaction-log | internal halt disk_log, trans_log 4.3 |
| decision-log | internal halt disk_log, decision_log 3.0 |
| decision-tab | internal halt disk_log, decision_tab 1.0 |

Kinds must be assigned by reviewed parent path policy, never archive-provided
code. Unknown container kinds, magic/header/version mismatches and every bad-byte
chunk are refused. No extension heuristic, fallback to ETF/JSON or repair.
All log terms including headers are traversed to native EOF. DETS must cleanly
open as v9; its native header validator checks proper-close, header checksum and
logical trailer/physical EOF. Its complete fold count must equal no_objects.
Both formats have a full raw-byte SHA/size pass before and after traversal and
stable file metadata checks. DETS covers all live data objects read by native
consumers, not unallocated/deleted forensic slack bytes. Log capture retains all
historical terms; it does not collapse overwrites/deletes or recover transactions.

Schema records are structurally {schema, atom_table, property_pairs}. Schema is
DATA: no mnesia_schema:list2cs, backend resolution, apply/eval, recovery/dumper,
restore, repair or Mnesia startup. Unknown table names (JWT, retainer, PSK, etc.)
are traversed as data instead of being filtered by the checkpoint five-table
layout whitelist. This does not attest those tables' business schema/rows.
Custom backend/index-plugin registrations, external copies, fragmentation and
SNMP dependencies currently refuse rather than authorize their later execution.
Native fun/pid/ref/port/improper list/bitstring, oversize or deep terms refuse
anywhere, including schema property values and the last record of a log.

Supported typed JSON is tuple/list/map (both keys and values), binary canonical
base64, atom UTF-8 strings, int64 and finite floats. Full terms are preserved;
Python only reads bounded strict JSON, NEVER ETF. Private collection includes
all binary/atom values, byte/Unicode charlists and canonical numeric strings.
Generic keys/atoms and small numbers can conservatively reject otherwise harmless
evidence containing the same bytes. This does not justify weakening leak checks.
The existing checkpoint typed reader retains its stricter default (no floats,
no numeric scalar collection); historical mode is explicit.

Native contract emqx-cold-history-json-v1 binds kind, container, traversal,
input SHA256/bytes, pinned OTP/ERTS, exact term_count and all terms, complete=true,
semantics=historical-value-superset, final_state=false. complete refers to ONE
supported container's traversal, not whole-source coverage or restore approval.

## Execution and evidence

Uses the existing immutable EMQX5.8.9/OTP26/ERTS14.2.5.11 image and rootless crun
runner, network disabled, input-only read-only mount, no image VOLUME creation,
RAM256MiB, atom65536, process heap8388608 words, pids64, CPU10s, container15s,
client20s, exact invocation-name cleanup verification. Each file receives a new
VM so untrusted terms do not accumulate atoms across files. Per-file term cap4096,
term nodes8192, depth16 and JSON1MiB. Native disk_log/DETS decode untrusted data
ONLY inside this resource-limited sandbox; type validation is not a host ETF
sandbox. Diagnostic stdout/stderr are not published. Success JSON is private.

Pinned source actually inspected: mnesia_log DCD/DCL add_recs and log versions,
mnesia_dumper transaction handling, mnesia_schema raw DETS settings, dets and
dets_v9 clean-close/trailer/header validation. No regex format guessing or
arbitrary schema/backend module loading.

Parent reports real ARM expanded117760000B and x86 expanded290785280B with complete
tarEOF+finish and bound original archive SHA. Candidate256MiB remains unchanged;
x86 requires explicit source budget configuration. Parent reports selected ARM
Mnesia28 files total57502B / max33593B; those bytes have NOT been decoded by this
branch. Large excluded archive files are not inputs to this reader. Real-source
support still requires parent integration and full selected-file receipts;
unknown selected formats remain gates. Synthetic fixtures are not commercial
acceptance or proof that all true files decode.

Run actual native cold tests:
`PYTHONPATH=backup-engine:tests/e2e/lab:. python3 -m unittest test_emqx_cold_history -v`

Validation delivered: initial5 cold methods passed in98.422s (27 actual native
runs: one fixture generator +26 decodes). Added late-typed-failure poisoning
regression passed separately in20.354s (fresh synthetic containers). Existing49
semantic/source/private-evidence/candidate/spool regressions passed in9.128s.
git diff --check passed. No sourceconsumer changes. These results are generated
fixtures only; true ARM/x86 selected cold bytes have not been decoded here.
