# Synthetic EMQX adapter rollback: previous run transcript

This is copied from the tool transcript of the preceding session, not a new run.
The successful run executed the working tree subsequently committed as `73ae93e`
(base `c93d57e`; the wrapper was invoked with `bash` before executable bits were
committed). No complete timestamped raw log was captured; the text below is the
available output, with failure tracebacks identified as excerpts.

Image IDs: EMQX `3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b`, label version `5.8.9`;
MQTT client `93a0bdfcbd9b7a86b36127cb81f54e1afd2019f12f39033458df405a027c03e3`.
Outer dev-d inspection printed `none {} running`. The successful wrapper checked
dev-d cgroup headroom and used the isolated labpodman wrapper.

## Successful wrapper run

Command, from the worktree:

```text
bash tests/e2e/lab/run_emqx_adapter_lab.sh
```

Copied complete stdout:

```json
{"stage": "adapter_automatic_rollback", "result": "pass", "cleanup": "pass"}
```

The tool reported normal completion, exit 0. Independent subsequent queries for
`woowbk-emqxlab-*` containers, volumes and user units and for secrets with that
prefix all returned empty stdout. These queries do not prove anything about other
names. The driver's candidate volumes came from a synthetic adapter backup, not
from `_build_candidate` or `_package_candidate`; this is not a full HA join.

## Earlier failed attempts (copied traceback excerpts)

1. Direct driver invocation, exit nonzero, before broker start: Podman secret
   list output did not parse as a single JSON document:
   `json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)`.
   The subsequent synthetic volume query returned empty stdout.
2. Direct driver invocation, exit nonzero, after adapter backup: the following
   synthetic MQTT publish failed before broker readiness:
   `woowbackup.podman.CommandError: podman run 93a0bdfcbd9b 127.0.0.1 執行失敗（結束碼 1）。`
   Subsequent synthetic container and volume queries returned empty stdout.
3. Direct driver invocation, exit nonzero: product flow raised `RolledBack`, but
   the immediate configuration read failed before broker readiness:
   `woowbackup.podman.CommandError: podman exec woowbk-emqxlab-cf555653 emqx 執行失敗（結束碼 1）。`
   The synthetic container, volume and secret queries were empty; two failed
   synthetic unit states were subsequently reset explicitly.
4. Direct driver invocation: functional assertions printed
   `{"stage": "adapter_automatic_rollback", "result": "pass"}` but process
   exited nonzero with `RuntimeError: cleanup incomplete: resources`. Independent
   synthetic container, volume and unit queries were empty. This was not a pass.
   Cleanup handling was revised before the successful wrapper run.

No full stdout/stderr captures exist for those attempts; these are excerpts from
the tool transcript, not complete logs. No production service or volume was used.
