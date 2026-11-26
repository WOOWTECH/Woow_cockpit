# Odoo opt-in offline PostgreSQL 16 release proof

Real isolated dev-d proof at source `516e02a2`; product input adapters `360829c7` and `0123142e`. The existing Linux/amd64 image config was independently bound to the pinned official platform manifest and all 11 ordered layer diff IDs before loading. Actual Docker-directory packaging and root-protected install passed; production Odoo selection loaded through the app owner once, reused the image without a second load, and ran PostgreSQL 16.15 with no network or pulls. Source image fields remained unchanged, zero containers/anonymous volumes remained, and both new stores were removed.

The 297,140,736-byte release is retained outside Git at `/tmp/parity-focus-20261127/odoo-pg16-release-amd64`. Manifest SHA256: `f563a9bf4123af20f65247ab752169e4664c7e0d179806711c7957d70687f9aa`. The coordinator independently rehashed the retained manifest and archive. These local hashes are a review receipt; authenticated release publication is a separate action. No image artifact is committed.

Failed attempts are preserved in `snippets/focus-odoo-image/`: legacy Docker links were refused, OCI config rewriting was refused, and isolated runtime path failures were corrected in the proof harness. No pin, path, layer or reserve check was waived.

This closes OD-23 implementation and amd64 offline artifact proof. It does not prove ARM loading, the original Odoo tenant image, or all ten services. `commercial_acceptance`: `not-complete`.
