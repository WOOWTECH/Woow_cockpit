# Hermes FTS5 allowance — independent security review (2026-11-23)

Reviewed: `backup-engine/woowbackup/hasqlite.py` and its use by `ha_hermes.py` on `feat/ha-import-batch1`
(b2f63ce, FTS allowance 7f1cd1a). This review was refused by an automatic reviewer on 2026-11-20 and stayed a manual
item. The owner explicitly authorized it on 2026-11-23 and approved each command in manual mode.

## How it was tested

- The real code ran in throwaway rootless containers with `--network=none`: `hasqlite.run`, and `hasqlite.CHILD`
  started exactly as `run()` starts it. Image `localhost/woowbk-testrunner:noble`, SQLite 3.45.1, Python 3.12.
  The production host's python3 also has SQLite 3.45.1.
- The container's root ran the privileged path (unshare, chroot, setuid nobody). Every run was done twice: with
  `CAP_SYS_ADMIN`, like the host's real root, and without it, like a restricted environment.
- Real input: the Hermes add-on (`9c1a67eb_woow-hermes`, Hermes v0.22.5, schema 32) of the unencrypted x86
  batch-1 HA backup. It holds 6 SQLite databases. Its `state.db` has 2 FTS5 tables whose external content is
  supplied by 2 **views**.
- Script: `tests/e2e/lab/hasqlite_sandbox_review.py`. It prints structure only (versions, outcome classes,
  timings, FTS declarations) and never database contents.

## Results

| Check | Result | Evidence |
|---|---|---|
| Child identity and filesystem (root path) | nobody/nobody, no groups, empty chroot; `/etc`, `/proc`, engine and input not visible | original-sysadmin-full.json `sandbox_probe` |
| fork / setuid(0) / chroot again | all blocked (EAGAIN, EPERM, EPERM); rlimits applied | same |
| Network with CAP_SYS_ADMIN | new netns, loopback listener unreachable (ENETUNREACH) | same |
| **Network without CAP_SYS_ADMIN (before the fix)** | **failed open: unshare failure was ignored and the child connected to a 127.0.0.1 listener** | original-nosysadmin-probe.json |
| Network without CAP_SYS_ADMIN (after the fix) | child exits 3 before opening anything; `run()` raises job-failed 「…切斷網路（隔離失敗），已停止，沒有讀取任何資料。」 | fixed-nosysadmin-real-backup.json |
| Real backup through `run()` (before and after the fix, with CAP_SYS_ADMIN) | all 6 databases `ok`; sessions 5, messages 15, schema 32 | original-sysadmin-full.json, fixed-sysadmin-real-backup.json |
| Whitelist bypass (14 forged `sqlite_master` declarations) | 13 refused: fts4, rtree, extra option, porter, other content table, quoted name, IF NOT EXISTS, schema-qualified, comment between keywords, NBSP in args, vertical tab, extra FTS table, rtree hidden by comments. 1 accepted: lowercase keywords with identical arguments (same meaning) | original-sysadmin-full.json `bypass` |
| Targeted index damage (6 cases) | garbage structure → refused; random leaves → refused (「malformed inverted index」); config version 999 → refused; empty structure, dropped docsize, stale index → accepted | `damaged_index` |
| 150 random byte flips in the FTS index | 0 crashes, 0 hangs; 114 refused by the check, 22 refused with an error, 14 accepted | `fuzz` |
| Content view replaced by an infinite recursive CTE | accepted in 0.1 s: quick_check does not run the content views | original-sysadmin-view-and-large.json |
| 60,000 extra messages (274 MB state.db) | check passed in 6.8 s (timeout 1800 s) | same |
| Unit and real-backup regression | 42/42 OK, 0 skipped: test_ha_sqlite, test_ha_hermes, test_ha_headscale and test_ha_b1_real over the 8 real batch-1 backups (key read in-process, never printed) | run log in the commit message |

## Findings

1. **Fixed (medium): network isolation failed open.** `CHILD` ignored a failed `unshare(CLONE_NEWNET)`. A child
   that runs code from a malicious archive (through an SQLite bug) would then keep the host's network, including
   local services. Now, as root, a failed unshare exits `NO_NETNS` (3) before any database is opened, and `run()`
   stops the job with its own message instead of blaming the archive. dev-c, dev-d and the production backup service
   can all create a network namespace, so no working import is affected.
2. **Fixed (documentation): quick_check does parse the FTS5 indexes.** The docstrings said the index contents were
   not validated or queried. SQLite's quick_check runs FTS5's own index check (structure and segment pages), inside
   the sandbox. It does not compare an index with its content and never runs the content views.
3. **Accepted residual risk.** The FTS5 index parser (SQLite C code) handles archive-controlled blobs inside the
   sandbox: nobody, empty chroot, no network (now enforced), no fork, memory/CPU/file limits. A stale or empty index
   passes the check, so Hermes search over restored data may need Hermes's own rebuild. That is a correctness note,
   not a security issue: the content is the archive's own.
4. **Coverage gap closed.** The unit tests only check the source order of the privilege drop and run unprivileged.
   This script runs the real root path. Rerun it after any change to `CHILD`.

## Not covered

Kernel-level escapes. SQLite builds other than 3.45.1. The Hermes end-to-end restore (service start, client,
rollback) is a separate lab item.
