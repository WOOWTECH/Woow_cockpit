# Fullflow02: proven snapshot JSON scalar defect

Actual retained private diagnostic SHA256
`965f013787585e7ff3eb3a7871a013ca82f02aa2786db2a52edfce1d36043c5b`
records JSONDecodeError: Extra data, line1 column4/char3. Frozen f396 combined
root payload frames map dispatch -> snapshot/schema MD5 query -> sql/json.loads.
The query emitted bare hex rather than a JSON string. This is actual failure
evidence, independent of the earlier lost baseline sample (still unproved).

Wrap both schema and roles MD5 aggregates in to_json. Keep all covered columns,
role/password facts, digest coverage and equality assertions. roles=True is
correct for the installed adapter's boolean inclusion parameter; generatedPG87
also used it. No adapter/product change is needed.

One offline full-snapshot regression runs real snapshot(), sql()/JSON decoding,
Services boundary, access normalization and the actual adapter digest writer
over both databases. Only external psql responses are simulated, including the
bare-text versus quoted-JSON scalar wire semantics. The old queries reproduce
the exact schema JSONDecodeError; both corrected hashes and two real digest
files (including roles) pass. This is a wire-contract test, not a native SQL
execution claim. No PG87/original80/broad test rerun or new device call.

Fullflow02 remains FAIL. Its complete cleanup/zero jobs/no safety/backups/leak
and original8 strict-return evidence is retained; old case/credentials/results
must stay immutable. Separate bounded operation-diagnostic preservation and a
new-case image-adoption proposal follow before another runtime lease.

Operation diagnostics now persist before cleanup: host receipt records the
operation before dispatch; on failure the device writes a case-private bounded
record before replying, and the host writes its own immutable record before
unwinding. Both retain fixed exception class/errno/returncode and up to16KiB
stderr (base64/private), never argv, SQL results, request values or exception
messages. Host command captures are capped too. Root diagnostic files survive
package cleanup and a lost reply. A one-method offline regression covers real
nonzero-command stderr and PermissionError errno13, checks durable root/host
records before cleanup, and confirms they remain afterward. It is separate
from the accepted snapshot test, which was not repeated for this delta.
