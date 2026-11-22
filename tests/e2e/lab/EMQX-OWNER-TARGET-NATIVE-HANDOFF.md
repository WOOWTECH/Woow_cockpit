# Dev-d ownership returned after fresh synthetic target attempt4

Base: 3086765. Worktree: /tmp/ha-emqx-owner-target-native-20261122.
Branch: codex/emqx-owner-target-native-20261122.
Explicit ownership was returned to main after attempt4 wrapper EXIT/postflight.
No dev-d commands will be run by this branch after that handoff. Both lock file
FDs were held by the wrapper and closed when it exited. No active tool session
remains. Last postflight: network none, published ports empty, owned workload
containers/volumes zero. Main may proceed with its ARM config retest.

## Actual fresh synthetic result

This was new --mode owner-target in emqx_broker_workload, not the old export14
suite. Each broker used cached pinned EMQX 5.8.9 image
3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b,
network none, no implicit image volumes, raw log driver disabled, private
invocation-only files. No real HA startup, production input or credentials.
Only owner.sh transported commands into dev-d; both required mutation locks were
held by run_emqx_owner_target.sh. No broad prune or nonowned cleanup occurred.

No MQTT client or ticker was started. Before and after each expression attempt,
the actual broker asserted emqx_cm:all_channels() == []; there was no external
network and no published port. This excludes this harness's writers rather than
claiming an arbitrary Python context manager alone quiesced a live workload.

Attempt1: fresh broker ready and no-client assertions passed; native CLI eval
transport failed. Attempt2 refined fixed diagnostic to expression_syntax.
Attempt3: native erl_scan/erl_parse accepted the fixed public expression before
broker startup, but multiline CLI eval still failed syntax. All failures and
cleanup/postflight evidence are preserved in attempt1..3.jsonl.

Minimal fix 977b252: remove comment-only/blank lines and fold ONLY the fixed
public expression into one CLI argument line. No config, schema or user input
is transformed into code. Generation interpolation remains fixed generated hex.
The source still gets a native parser preflight before startup.

Attempt4 executed 977b252: fixed source native parse PASSED; broker ready PASSED;
zero clients before/after PASSED; actual native eval transport PASSED. Native
expression returned a fixed failure at stage native_tables, reason badmatch.
The expression reached native table transaction setup after pinned version,
effective-config lookup, provider lookup and table-list acquisition. It did NOT
return a completed typed observation or complete target registry. The precise
inner aborted transaction/schema condition is not established by that fixed
diagnostic; do not infer that schema semantics or row projection passed.
No additional mutation/debug attempt was made after main requested handback.

Cleanup of parser container, broker, clients and private files passed. Final
postflight after attempt4 passed. Full target remains NOT ACCEPTED; source is
not assessed by this synthetic mode and commercial HA acceptance is not claimed.

## Delivered implementation and evidence

* emqx_broker_workload.py: separate owner-target fresh synthetic mode, no old
  MQTT/restart/export workload execution and no bootstrap/ACL file references.
* emqx_broker_owner_target.py: actual no-client quiescence, fixed diagnostic
  collection, native expression/registry path and exact target-only names
  evidence if all producers pass. No fake source registry/counts.
* run_emqx_owner_target.sh: both locks, owner.sh-only transport, cgroup headroom,
  pre/post owned-only assertions and cleanup. Tracked code required before run.
* emqx_owner_target_parse.escript: syntax-only native preflight on fixed PUBLIC
  source, never config/checkpoint input. No native term execution in that step.
* emqx_owner_target.expr: fixed private stage/reason enums, no raw broker error
  terms/config/rows printed by diagnostic catch.
* emqx_owner_target.py: minimal CLI one-line transport fix; existing exact
  fullscan/public guards, registry schema and unknown-reference rules unchanged.

Evidence: tests/e2e/lab/evidence/emqx-owner-target-20261122/attempt1..4.jsonl.
Actual attempt4 source commit is 977b252; final evidence commit does not rerun it.
Local owner-target unit regression: 6 passed. Wrapper bash syntax and Python
compile checks passed before execution. Actual native preflight is independently
recorded in attempts3/4. No test here establishes full target success.
