# Exact ARM proof request — no lease execution yet

Product validation passed: guarded final neighbor run304 tests,0failures,0errors,3real-fixture skips,0blocked,0shim hits. Scope: tests.backup.test_pg16_bundle, tests.test_manage, tests.backup.test_ha_odoo, tests.backup.test_ha_flows. Log /tmp/parity-focus-20261127/odoo-image-final-neighbors.log. No further broad rerun is needed for this change.

Current controller state names `/var/tmp/woow-arm54-final-20261123-wcjdtakj`. This is a LOCAL state read, not a fresh remote existence/disk proof. Current worker lacks the controller's existing ARM54_ASKPASS/ARMHA_PW context. `arm_inventory.py` exited before invoking SSH and recorded `arm-inventory-20261127.json`. No new authentication override/helper was created. Coordinator must invoke the same script through the existing authenticated private controller context (or identify the already-configured private controller module):

```
python3 snippets/focus-odoo-image/arm_inventory.py \
  --controller <existing-authenticated-private-arm54-controller.py> \
  --output snippets/focus-odoo-image/arm-inventory-20261127.json
```

Only fixed metadata is queried in the explicitly selected private source store. No global/default-store command, image export, pull, load, retag, service/account action, or remote staging occurs in this inventory script. Fresh free bytes and exact source-match verdict must pass before leasing the mutation step. Expected source: ARM64/Linux, canonical tag `docker.io/library/postgres:16.15-alpine`, current PG16_PINNED RepoDigest `aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139`, config ID `sha256:35726244c51a57338a5a5a5ad8a7e2b18f4ecb8dccd51224cab33ac2ea6a5df0`.

The lease-only script is `snippets/focus-odoo-image/arm_offline_proof.py`. After fresh inventory and explicit coordinator lease, coordinator stages this committed tree into a separate lease code directory and supplies an existing leased non-root owner with uidmap and /run/user/<uid>. It is not necessary to overwrite the source lab workspace's code, install packages, create users, restart services, or change authentication.

Exact remote invocation (through the same private ARM controller):

```
python3 <leased-code-root>/snippets/focus-odoo-image/arm_offline_proof.py \
  --source-workspace /var/tmp/woow-arm54-final-20261123-wcjdtakj \
  --code-root <leased-code-root> \
  --proof-root /var/lib/woowbk-odoo-pg16-proof-<lease-id> \
  --owner <existing-leased-test-owner>
```

The script requires root on device54 and refuses a pre-existing proof directory. Source must be the existing canonical exact image in the private store; absent/mismatching source fails before export and no substitute/pull is attempted. It enters a private network namespace (only lo), exports the canonical image into its NEW proof directory, packages it using the independently recorded config ID, and stages the sidecar into `<proof-root>/install-root` using the real bundle installer. This root lives under trusted /var/lib ancestors, so runtime root trust checks remain fully enabled (no fixture trust-anchor bypass).

The existing production OwnerRunner executes the new Odoo bundle selection/load path with explicit NEW graphroot/runroot/tmpdir in the leased owner's disposable VFS store. It then runs `postgres --version` with `--pull=never --network=none` and repeats selection to prove one load and reuse. Only allowlisted source inspect/save and target inspect/load/run operations are dispatched; pull is rejected. Free space must begin at12GiB+128MiB reserve+2GiB and is watched during commands/hashes; reserve failure aborts. The script does not clear baseline/source stores or clean up files automatically. Review its result.json, then coordinator removes ONLY the newly leased proof directory/store after artifact retention is decided.

Expected public proof fields: source_workspace, proof_root, architecture/ref/image_id, archive size/SHA256, independently trusted manifest SHA256, loads1, pulls0, network interfaces[lo], PostgreSQL16.15, free bytes after/reserve. This is a specific offline image delivery/load proof; it does not imply all-service or commercial acceptance. Actual uncompressed artifact can exceed the approximate200MB planning figure (historical ARM image size290943896 bytes).

Potential real-export incompatibility remains explicitly observable: archive headers/ref/config validation can refuse a format not covered by synthetic fixtures. Keep that failure; do not weaken path/link/multiimage/ref checks to claim a pass.
