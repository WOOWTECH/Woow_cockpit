# Isolated real-Omnigent cold chain — interim evidence

`attempt-before-independent-target.jsonl` records the earlier run using the actual Omnigent 0.21.0 image and synthetic credentials. The application created the schema, its cold PostgreSQL volume and real artifact tree were wrapped in a synthetic HA add-on tar, the private candidate ran, and the output volumes were installed into new containers. The restored application was healthy; both synthetic accounts logged in and a source token issued before conversion still worked.

This attempt **did not pass as a whole**: cleanup reported false because the synthetic source password secret was not removed by the harness. The secret was subsequently removed by exact name and verified absent; its containers and volumes were separately checked absent. In addition, this earlier attempt cloned the source database to seed the target schema and used an unbounded `subprocess.run` wrapper. Therefore it does not prove independent target-schema trust or bounded execution. It uses controlled synthetic data only. Public guards stayed enabled.

The harness was subsequently changed to use the product `default_runner`, bound output/deadline/abort, initialize the target independently with the application image and a separate newly generated synthetic credential, wait for PostgreSQL TCP readiness, and track and remove both synthetic secrets. Those changes **have not yet been run in dev-d**; EMQX has scheduling priority. The fixture and bounded-runner unit tests run without lab resources:

```sh
PYTHONPATH=backup-engine:. python3 -m unittest tests.backup.test_ha_omnigent_real_app_fixture tests.backup.test_ha_omnigent_trusted tests.backup.test_ha_omnigent_server_volume
```

Do not use the earlier attempt as evidence of full acceptance. After coordinating resources, run `python3 tests/e2e/lab/omnigent_real_app_chain.py --run` and record its actual masked output, cleanup, and product/harness hashes. The outer HA envelope and production target discovery remain fixture boundaries; it does not use the production installer, existing runner, or any real credentials.
