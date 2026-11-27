# Exact dev-d disposable proof — completed

Executable driver: `snippets/focus-emqx-plugins/probe.py`; its reviewed child is `runtime_probe.py`, and its known fixture OTP application source is `woow_e44_fixture.erl`. Default invocation prints only the plan. Native attempt 3 passed **33/33 checks** at committed source `a82a086f382ea08be46e857e41004165527da680`, run `j20261126T215925Z-ba807121`, under the coordinator's bounded dev-d lease. See `runtime-attempt3-pass.json` and `runtime-cleanup.json`. The lease work is finished and the existing mutation lock released; any future replay needs a current coordinator lease.

Read-only inspection through the existing isolated `owner.sh d` wrapper found:

- Config/image ID: `sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b`.
- Tag: `docker.io/emqx/emqx:5.8.9`; linux/amd64; size 244,323,182 bytes.
- Manifest: `sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937`.
- Outer dev-d: running, network none, published ports `{}`. Memory used 1,733,378,048 / 4,294,967,296 bytes at inspection; host available RAM 4,709,084 KiB; host disk free 32,200,183,808 bytes. These are observations, not reservations; the driver rechecks resource floors.

Exact executed command (from the clean committed worker checkout):

```sh
HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock \
  /tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 -B -I snippets/focus-emqx-plugins/probe.py --run \
  > /tmp/parity-focus-20261127/emqx-plugin-runtime-03.json
```

The driver uses the existing `/tmp/woowbk-dev-d-mutation.lock` via `dev_d_guard.acquire`, waits up to 180 seconds for NC, and holds it for the whole fixture. Runtime budget 15 minutes (device child alarm 840 seconds, child supervisor 870 seconds, host command 900 seconds). No shared application container, volume, catalog, source installation, service unit, original HA fixture or baseline backup is selected for mutation.

Bounded resources: at most two brokers concurrently, each 768 MiB memory, memory+swap 768 MiB, 0.5 CPU, 256 pids, scheduler `+S 1:1`; the short compiler runs separately at 256 MiB. File/staging output limit 256 MiB; host disk reserve 13 GiB plus staging allowance; host available RAM >=1200 MiB and dev-d headroom >=1900 MiB before creation. Every run has `--pull=never`, `--image-volume=ignore`, no network/ports, read-only root, no-new-privileges and cap-drop ALL. All named resources are owned by one random product TempObjects job; anonymous image volumes are disabled for compiler, id helper and brokers alike. Cleanup and before/after non-fixture inventory/source hashes are mandatory checks.

The compiled fixture is actual OTP application code supplied by this reviewed source file, never backup code. The compiler resolves exactly one image `/opt/emqx/erts-*/bin/escript`, checks OTP release 26, adds the image's `/opt/emqx/lib/*/ebin`, then compiles only `woow_e44_fixture.erl`. It registers a process and answers a real `ping` call, with its plugin manifest, BEAM and `.app` mounted read-only into both disposable brokers. Its configuration is a separate device-owned read-only mount at the vendor path. Its real record and one enabled missing-plugin record are both persisted in `cluster.hocon` **before first boot**, and the proof requires current/boot state equality.

Native proof gates:

1. Compile fixture with the exact existing image, start disposable source/device, prove actual plugin ping plus binary/config/running presence, and prove a nonempty Dashboard administrator table.
2. Produce a real filtered vendor export. Use product `candidate_from_target`, actual volume snapshot, export allowlist and vendor import/count checks; gather the exact enabled-missing confirmation.
3. Refuse an empty acknowledgement list at the product issue boundary. Prove disposable device records unchanged, remove only the first candidate, then rebuild a fresh candidate with the exact acknowledged key.
4. Prove only the missing record was removed and the available plugin's full settings/order and ping survive.
5. Restart that candidate; require the clean state list, working plugin and exact configuration-root/table receipts. Call the unmocked product `verify_restored`; deliberately alter the expected admin receipt in memory and require its normal refusal. No broker data is altered by the negative receipt test.
6. Product TempObjects cleanup, no owned resources left, all non-fixture durable volumes, images and installed importer source hashes unchanged. Container churn is recorded as an observation because Headscale independently recreates containers; every mutating target must belong to the invocation job.

This is a generated native E-44 delta fixture. Existing actual EMQX full-flow evidence remains untouched and remains the separate proof for original HA MQTT/Dashboard/ACL/rules/action/import/restart/safety rollback. Do not relabel this fixture as that original full flow. E-44 implementation can close after the coordinator integrates the startup-override guard and this evidence. This does not complete all R4 or ten-service acceptance.

Product followup committed at `d787b6a1`: high-priority `emqx.conf`/environment plugin-state overrides can reintroduce a cleaned record after restart. The fixture uses stable persisted cluster states and no plugin-state environment override. The inventory checks high-priority startup files plus the two plugin-state environment variables and refuses cleanup if either could resurrect a record. The actual native expression and stable-state restart passed; positive override refusal cases remain targeted offline coverage.

Attempt 1 failed its disk floor before creating resources because the payload used device `/tmp`; `8c23d8c8` moved staging to the nested home filesystem. Attempt 2 failed before broker startup at the direct ELF compiler launcher; `a82a086f` uses the image's escript runtime. Both fixed failure records are retained. All three attempts' labeled containers/volumes/networks and both diagnostic containers were absent at final cleanup; all private payloads were removed. Durable volume/image inventory and installed importer hashes matched before/after attempt 3; unrelated container churn was false. Catalogs, installed application units and baseline data were never selected: the postcheck adapter/Quadlet exists only in memory. No catalog before/after digest was collected, so the catalog claim is mutation-scope isolation, not an extra measured gate.
