# Image-only export01: failed safely; read-only finding

Source `17e76e61d6637c863f4d6b2031e5daf79d5ec4cd`. Original result SHA256 `8be003308e19384b04be75d447fc772cc138ba0dc65e633eb9e171117b1990e0` records only `ValueError`; the original inner phase/message were discarded. No historical cause is recovered from that envelope.

After parent confirmed tiny LL image verification terminal PASS/D release, bounded D-mutex read-only inspection found:

- The exact retained payload is UID1019/mode0700; all51 reviewed Python files match17e and all11 immutable public package files match the intended package commit. Context/profile/source match. No private error file or original pre-export image-catalog snapshot exists in the retained payload. The old code kept its before inventory only in memory.
- The one retained broker OCI archive is115,731,968bytes, SHA256 `c56871cae03b42356408db6d4ab31c85f808590d385f2ab5914f15e703fe9a63`. Its config descriptor is `sha256:1b8bcb217955926f6a50af4d1dc3f2aa8ea2370fa864579942eecc68a607b80f`; the required cached broker config is `sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b`. Running only the unchanged17e read-only validator against these retained bytes reproduces `ValueError: pinned_config_mismatch`. The archive hash is equal before/after that read. This localizes a reproducible archive-validation failure without inventing the missing original trace or asserting why the config changed.
- All3 current fixed cache-reference metadata reads pass the actual17e guards. Actual rootless owner1019 uses `/home/appowner/.local/share/containers/storage`. Whole current image catalog is18lines and equal before/after the metadata diagnostic; af291 is present. No original pre-export catalog snapshot was retained by this exporter, so historical full-catalog equality is not claimed. Parent's independent LL verification remains separate evidence.
- No save/export/build/load/tag/delete/container/service/secret/source mutation or cleanup occurred during diagnosis. D released after each bounded read. Original result/archive/payload remain. The first diagnostic packet had a SyntaxError before its read operations; its capture is retained, and the corrected packet was parsed locally before its D call.

Fixed hashes/counts and private-capture hashes are in [cache-export-failure.json](cache-export-failure.json). Raw private metadata/error captures stay outside the repository. Source59 and the retained17e payload were not changed.

## Minimal future diagnostic change

The cache exporter now assigns fixed phases/role before guards, narrow inspect, save, archive validation and final catalog/provenance checks. On future failure it retains `cache-error.json` inside that run's owned payload using0600/exclusive/no-follow creation. This contains a bounded exception message and at most2KiB of failed narrow Podman stderr; no command line, full inspect, stdout or secret reads. Existing diagnostics are never overwritten. Public output contains only class, phase, role and whether the private file was saved. Private-write failure preserves the original failure.

Two targeted guarded offline checks pass: actual owner-guard failure with no subprocess, and bounded private details/non-overwrite/public-output separation. No broad suite or future native run. The source pin, config/layer/archive/resource guards and metadata/catalog comparison are retained. The future change needs its own reviewed clean SHA/lease; it does not authorize replaying the failed export.

## Remaining decision

The retained OCI artifact cannot satisfy the current exact-config gate and cannot be passed to provisioning. Any alternative transport must preserve the reviewed original config identity and receive separate source/provenance review and a fresh lease; no alternate format is executed here. No digest alias, weaker pin, semantic-equivalence waiver, arbitrary backup code or silent fixture change is implemented. Cleanup still requires its separate lease bound to the original result SHA. Package producer, fresh device, H2 actual package/service evidence and remaining R4 acceptance stay pending.
