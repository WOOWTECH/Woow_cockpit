Candidate-only two-phase builtin ACL removal

Primary source: pinned EMQX checkout a8319fe, emqx_authz.erl overwrite_entire_sources
and ensure_deleted; emqx_authz_mnesia.erl update identity/destroy clear_table.
Main actual 365e651 attempt7 confirmed EMQX_ACL_UNDERFLOW after settings restore.

restore_target_settings now enters this path only for a nonempty FILE-only
original target and an imported raw enabled builtin source to remove. Exact raw
builtin type/enable is required; no max_rules/default expansion, custom providers,
duplicate source types or unknown source fields. All original/intermediate source
objects, root cache settings and other roots are preserved except the one boolean.
The existing nontransition paths, public preservation blocker and check_counts
are unchanged.

1. Observe bounded private complete emqx_acl row+schema receipt and stable raw cfg.
2. Load only authorization with builtin enable=false, preserving source ordering,
   file source and every other field; compare full raw config, receipt, raw config.
3. Execute the existing changed target roots/settings replace; compare full expected
   resulting raw config, original receipt and raw config again. Disabled removal
   skips native destroy. Any failure abandons the throwaway candidate; do not attempt
   live-target repair, table recreation, row injection or count-gate exemptions.

Receipt expression is fixed, version=5.8.9, one transaction (zero retries), table
read locks, known ACL record/attrs/type/storage/fragments only; full persistent
schema record plus all folded rows are hashed privately. Count==foldN==post-size;
rows<=65536, total encoded row bytes<=8MiB, row/schema<=64KiB, depth<=16,
containers<=4096; unknown function/PID/ref/port/non-byte-bitstring refuses.
Sorted per-row SHA256 hashes make the digest independent of fold traversal order.
Native null storage only accepts an actually observed size/fold count zero.
Receipt command timeout=10s, output<=256 bytes, fixed refusal with no abort terms.
These receipts must never be logged or published.

Host entry tests model native enabled-removal destruction, demonstrate direct
removal loses rows, then verify disable->remove retains data. Negative tests cover
same-count content mutation, schema changes, row loss, stage config mutation,
load/receipt failure and unknown raw source shapes. They are transport models,
NOT native proof. No native/container/lab runtime was run for this increment;
main's actual pinned candidate attempt must verify expression/backend/schema
compatibility and end-to-end preservation. No host Erlang executable was present.
