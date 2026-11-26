# Exact dev-d disposable proof to queue after NC

Prepared executable driver: `snippets/focus-emqx-plugins/probe.py`; its reviewed child is `runtime_probe.py`, and its known fixture OTP application source is `woow_e44_fixture.erl`. Default invocation prints only the plan. **No runtime fixture has been executed.** Coordinator is leasing dev-d after NC; no owner confirmation is needed.

Read-only inspection through the existing isolated `owner.sh d` wrapper found:

- Config/image ID: `sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b`.
- Tag: `docker.io/emqx/emqx:5.8.9`; linux/amd64; size 244,323,182 bytes.
- Manifest: `sha256:d4ec63c4065c745507e7652d9c0213134697dc1317d8a431b167ae7651c4e937`.
- Outer dev-d: running, network none, published ports `{}`. Memory used 1,733,378,048 / 4,294,967,296 bytes at inspection; host available RAM 4,709,084 KiB; host disk free 32,200,183,808 bytes. These are observations, not reservations; the driver rechecks resource floors.

Exact command after coordinator lease (from this committed worker checkout):

```sh
/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad/team/heavy.sh \
  python3 snippets/focus-emqx-plugins/probe.py --run \
  > /tmp/parity-focus-20261127/emqx-plugin-runtime-01.json
```

The driver uses the existing `/tmp/woowbk-dev-d-mutation.lock` via `dev_d_guard.acquire`, waits up to 180 seconds for NC, and holds it for the whole fixture. Runtime budget 15 minutes (device child alarm 840 seconds, child supervisor 870 seconds, host command 900 seconds). No shared application container, volume, catalog, source installation, service unit, original HA fixture or baseline backup is selected for mutation.

Bounded resources: at most two brokers concurrently, each 768 MiB memory, memory+swap 768 MiB, 0.5 CPU, 256 pids, scheduler `+S 1:1`; the short compiler runs separately at 256 MiB. File/staging output limit 256 MiB; host disk reserve 13 GiB plus staging allowance; host available RAM >=1200 MiB and dev-d headroom >=1900 MiB before creation. Every run has `--pull=never`, `--image-volume=ignore`, no network/ports, read-only root, no-new-privileges and cap-drop ALL. All named resources are owned by one random product TempObjects job; anonymous image volumes are disabled for compiler, id helper and brokers alike. Cleanup and before/after non-fixture inventory/source hashes are mandatory checks.

The compiled fixture is actual OTP application code supplied by this reviewed source file, never backup code. It registers a process and answers a real `ping` call, with its plugin manifest, BEAM and `.app` mounted read-only into both disposable brokers. Its configuration is a separate device-owned read-only mount at the vendor path. Its real record and one enabled missing-plugin record are both persisted in `cluster.hocon` **before first boot**, and the proof requires current/boot state equality.

Native proof gates:

1. Compile fixture with the exact existing image, start disposable source/device, prove actual plugin ping plus binary/config/running presence, and prove a nonempty Dashboard administrator table.
2. Produce a real filtered vendor export. Use product `candidate_from_target`, actual volume snapshot, export allowlist and vendor import/count checks; gather the exact enabled-missing confirmation.
3. Refuse an empty acknowledgement list at the product issue boundary. Prove disposable device records unchanged, remove only the first candidate, then rebuild a fresh candidate with the exact acknowledged key.
4. Prove only the missing record was removed and the available plugin's full settings/order and ping survive.
5. Restart that candidate; require the clean state list, working plugin and exact configuration-root/table receipts. Call the unmocked product `verify_restored`; deliberately alter the expected admin receipt in memory and require its normal refusal. No broker data is altered by the negative receipt test.
6. Product TempObjects cleanup, no owned resources left, all non-fixture container states, volumes, images and installed importer source hashes unchanged.

This is a generated native E-44 delta fixture. Existing actual EMQX full-flow evidence remains untouched and remains the separate proof for original HA MQTT/Dashboard/ACL/rules/action/import/restart/safety rollback. Do not relabel this fixture as that original full flow. Shared E-44 row remains part until appropriate native evidence completes.

Remaining product concern noted in review: high-priority `emqx.conf`/environment plugin-state overrides can reintroduce a cleaned record after restart. The fixture explicitly uses stable persisted cluster states and no plugin-state environment override. A conservative refusal for those override-driven cleanup cases is being prepared separately; this concern is not resolved by an empty inventory or by the fixture plan alone.
