# n8n through dev-c's real Cockpit page (2026-11-28)

`focus_acceptance_n8n.py --run --via-page --source <clean bfe7b914 checkout>` (driver `d500e379`; the n8n commit
`c84e9e9a`, cherry-picked here as `1cccf984`) ran the saved original n8n application flow (historically 34/34) on
woowbk-dev-c with the upload, the check and the one-action import going through dev-c's real Cockpit page: the
encrypted HA backup uploaded through the page, only n8n selected, the HA key taken, the check (n8n importable, nothing
stopped) and its one confirmation acknowledged once, one import click whose conversion and restore ran as two linked
jobs in the first job's unit, nothing to choose, every issued Cockpit cookie absent from records and journal. Everything
after the import ran unchanged: owner login, credential decryption, workflows, executions, both health endpoints, the
baseline restored, cleanup and leak scans. **61/61** in 435 s (page gates all true; `import_path: page`,
`baseline_restored: true`; product on dev-c `bfe7b914`).

Around it (coordinator, `launch_n8n_page.sh`): dev-c's seven n8n service units were started under the dev-c lock and
both health endpoints (15678 readiness, 15679) answered 200 before the run; after it the seven units were stopped again
(N8-01's original state). The images were already present (nothing loaded or pulled).

Files: the driver's own record `../focus-acceptance-20261127/n8n-x86-20261128T091424-3862de6b.json` (61 fixed status
lines and the page gates) and `page-capture.json` (the capture wrapper keeps only the exit code and the stdout hash for
this driver). Private run: `~/.woowbk-lab/evidence/focus-acceptance-n8n/20261128T091424`, full stdout in
`/tmp/parity-focus-20261127/n8n-page-20261128-01.private.log`. `commercial_acceptance`: `not-complete`.
