# Fixed private owner preflight

This entry joins authenticated source Capture to an invocation-fresh empty target,
observed native target inventory, fixed vendor files, generated bootstrap login,
and the existing registration/login evidence scanner. It does not build a source
broker/candidate, install, restore, or establish commercial HA acceptance.
Historical cold receipts remain `final_state: false`.

Authorized lab owner only, after explicit runtime ownership handoff:

```
tests/e2e/lab/run_emqx_arm_cold.sh --preflight
tests/e2e/lab/run_emqx_arm_cold.sh --x86-preflight
```

These fixed modes use the existing ARM/x86 SQL alias profiles, archive identities,
256 MiB ARM / fixed expanded x86 spool profiles, and key/ciphertext stdin frame.
No path, digest, key, parser or target override is accepted. Source-only modes
retain their previous behavior. Both mutation locks, owner.sh realm/isolation,
and an extra 1 GiB available-memory check apply before a preflight run. Cleanup
and postflight run on refusal too. No production owner/Podman operation is added.

`staged_owner_frame` is shared with the existing fresh build workflow: bounded
ASCII key in RAM, bounded ciphertext-only private staging, full ciphertext SHA,
EOF/optional finish before creating any target. Actual Capture then authenticates
v3 through full EOF/finish and binds product selection, native HOCON and historical
cold inventory. ARM's exact 28/57502 receipt assertion is retained; x86 uses the
existing bounded historical receipt shape and actual source architecture.

The common driver join retains source lifetime and actual target quiescence
through native readers, lazy private inspect CID binding, fixed vendor observer,
login, and exact evidence scan. Vendor policy/provenance/class/capability checks
remain authoritative. Unsupported source or target data refuses; no invented
empty category documents or absence acknowledgements are supplied by this entry.
Preflight never invokes the candidate bridge. The separate build callsite keeps
its existing bridge gates.

Only after all held contexts, fresh resources, private spool/evidence staging and
bootstrap code have cleaned up does the host accept a bounded private pipe frame.
It contains the **unchanged, rescanned publication bytes** and their SHA-256;
length/hash/EOF/child exit and the fixed evidence schema are checked. The host
stores these exact bytes as a mode-0600 `owner-preflight.json` under an invocation
mode-0700 `/home/woowtechopenclaw/.woowbk-lab/emqx-preflight-evidence-*` directory.
The host private parent must already be owner-owned mode 0700 without symlinks.
No source replay, source values, target docs, key, token, capability or raw errors
are returned. The payload, hash and private path are never printed publicly.

Success stdout is fixed `PREFLIGHT REGISTRATION LOGIN PASSED`, followed by the
wrapper's fixed postflight result. Exit zero requires both consumer completion
and postflight success. Any framed/preflight refusal returns nonzero; postflight
failure overrides child success. A retained preflight artifact proves only this
registration/login evidence scan, even if subsequent postflight fails.

Validation in this change uses generated encrypted archives, typed native reply
fixtures and generated vendor file contracts. The real Capture, readers, vendor
observer/policy, registry and publication consumers execute; process/native image
IO is substituted. Pipe bound/EOF/exit tests use local generated subprocesses.
No lab or real source workflow was run for this implementation.
