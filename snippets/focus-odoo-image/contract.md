# OD-23 opt-in PostgreSQL 16 release sidecar

This adds optional image provisioning. It does not add application installation, change VERSION, pull/build images, or require a sidecar for ordinary Cockpit installs/updates. Keep current local-first and pinned online retry behavior when no sidecar is installed. Do not describe this as commercial/hardware acceptance until the leased-store proof is recorded.

Release input is a pre-exported, single-image, uncompressed `docker-archive` from a trusted isolated source. The exact source must match:

`docker.io/library/postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139`

RepoTags must be exactly `["docker.io/library/postgres:16.15-alpine"]`; use the canonical tagged ref for export after independently verifying its config ID and RepoDigests against this pin. The CLI never retags or exports images. One bundle is built per architecture (`amd64` or `arm64`, Linux). The release builder must independently obtain the expected `sha256:<config-id>` from trusted pinned platform metadata; deriving this argument from an unreviewed input archive does not establish provenance.

```
python3 scripts/package_odoo_pg16.py \
  --archive /release-input/postgres16.docker.tar \
  --architecture arm64 \
  --image-id sha256:<trusted-platform-config-id> \
  --output /release-output/odoo-pg16-arm64
```

The new output directory contains `manifest.json` and `postgres16.docker.tar`. The small manifest has exactly these keys:

```
{
  "schema": 1,
  "kind": "odoo-pg16",
  "architecture": "arm64",
  "ref": "docker.io/library/postgres:16.15-alpine@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139",
  "image_id": "sha256:<64 lowercase hex characters>",
  "archive": "postgres16.docker.tar",
  "archive_sha256": "<64 lowercase hex characters>",
  "archive_size": 123456789
}
```

Publish the printed `manifest_sha256` in authenticated release metadata separately from the artifact. A checksum shipped alongside a mutable manifest is insufficient. No giant image files belong in Git. Packaging and installation copy/hash at most 1 MiB per read. Artifact ceiling: 2 GiB; JSON ceiling: 1 MiB each; outer archive entries: 4096. Outer archives cannot contain multiple images, unrelated image files/tags, duplicate or unsafe paths, links, devices, sparse members, GNU long names, or PAX extensions. Layer contents are bound by the complete trusted artifact SHA, not extracted by the helper.

```
sudo python3 scripts/manage.py plan \
  --odoo-pg16-bundle /release-output/odoo-pg16-arm64 \
  --odoo-pg16-manifest-sha256 <SHA-from-authenticated-release-metadata>
sudo python3 scripts/manage.py install \
  --odoo-pg16-bundle /release-output/odoo-pg16-arm64 \
  --odoo-pg16-manifest-sha256 <SHA-from-authenticated-release-metadata>
```

Both flags are required together; `--no-backup` is incompatible with explicit bundle staging. The live-root CLI rejects a different architecture. `--root` stages a target image without running Podman, systemctl, or package installation there. Planning verifies the artifact without staging it. Installation verifies before any Cockpit/package changes and again during streaming copy.

Installed layout:

```
/usr/local/share/woowtech-cockpit-backup/images/odoo-pg16/<architecture>/
  active.sha256
  <manifest_sha256>/
    manifest.json
    postgres16.docker.tar
```

Only root can write the selected pin, manifest, archive, or ancestors. Symlinks in paths and hardlinked payloads are refused. A new generation is fully staged/fsynced, then renamed into place; `active.sha256` is atomically replaced last. Failed staging leaves the previous generation active. Archive bytes never enter the Cockpit desired-file dictionary, installed.json, or rollback journals. Image provisioning persists independently of Cockpit UI rollback; ordinary updates/`--no-backup` preserve sidecars without opening/hashing them. Superseded generations remain for explicit release maintenance (no automatic deletion).

Odoo import keeps existing local image priority. Otherwise it chooses this machine's architecture, verifies the complete installed root trust chain, pin/manifest/artifact SHA, config ID, ref, OS and architecture, and passes the already-open verified file descriptor as stdin to the existing app-owner runner's `podman load`. It inspects loaded ID/OS/architecture, returns the config ID for subsequent `--pull=never` temporary containers, and does not rely on Docker save/load retaining RepoDigests. No root/global-store load or owner-writable archive path is used. A configured but invalid sidecar fails closed for Odoo; no sidecar retains existing pinned pull + retry. Job cancellation/storage failure propagates.

Suggested coordinator docs/registry update: OD-23 now has opt-in installer/release packaging and owner-load implementation, focused synthetic proofs, and a pending real isolated-store artifact/load proof. Link focused test names from `tests/backup/test_pg16_bundle.py` and `tests/test_manage.py::OdooPg16BundleContract`. Do not mark actual artifact delivery proven by unit tests.
