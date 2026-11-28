# code-server through dev-e's real Cockpit page (2026-11-28)

`codeserver_full_flow.py --via-page` (driver `687cc9b7`, cherry-picked here as `18f60897`) took the actual encrypted
x86 Home Assistant showcase backup through the real Cockpit backup page on woowbk-dev-e (headless Chromium, through the
per-connection relay into the network-isolated device): upload through the page, only woow-code-server selected, the
check calling it importable and stopping nothing (it listed zero confirmation keys, a valid case the page handled),
the one acknowledgement enabling the import, one import click whose request carried every listed key exactly once,
then one conversion and its restore as two linked jobs in the first job's systemd unit. The other checks of the
code-server flow ran unchanged (workspace content, settings, authentication, identity, ownership, restart, injected
automatic rollback, safety-backup restore, leak scans incl. every issued Cockpit session value, cleanup, isolation).
**105/105** in 406 s (the 18 helper upload/check/import checks replaced by 36 page checks).

Before it `deploy-batch2.sh e wake:code-server` loaded the host's exact image (ID 7999790230ec, 763 s); after it a
separate read-only `batch2_baseline.py --verify code-server` passed 8/8 and `rotate:code-server` stopped the unit and
dropped the image from dev-e.

`page-full-flow.json` is the capture's fixed-status record (108 lines) and stdout hash. Private run:
`~/.woowbk-lab/evidence/codeserver-csff/20261128T083845/`, full stdout in
`/tmp/parity-focus-20261127/codeserver-page-pilot-01.private.log`, step logs `codeserver-page-pilot-01.*.log`.
`commercial_acceptance`: `not-complete`.
