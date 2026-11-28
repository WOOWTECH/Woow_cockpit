# Headscale through dev-d's real Cockpit page (2026-11-28)

`headscale_full_flow.py --run --arch x86 --via-page` (driver `d500e379`; the page machinery of `0bec8206` and the
Headscale commits `97c97286`/`fed064e6`, cherry-picked here as `71ad3a38`, `6793f941`, `d8af48b0`) took the plain
(UNENCRYPTED) b1 Home Assistant backup through the real Cockpit backup page on woowbk-dev-d. It is the first page run of
an unencrypted HA backup: the wizard asked for no key, the check ran without a key step, neither the check nor the import
request carried a key and the engine was given none; the check offered nothing to choose and neither request nor the
chain carried a choice; the check called Headscale importable, stopped nothing and listed its confirmation lines, which
the one acknowledgement and the import carried exactly once. The temporary DERP simulation stayed (Headscale 0.29.4
refuses to start offline without a DERP map; only the derp block of dev-d's config.yaml changed, the original kept next
to it and put back), and the rest of the Headscale flow ran unchanged: real Tailscale clients (x86) registering and
pinging through the embedded DERP region, identity and settings, restart, automatic rollback, the restore of dev-d's own
Headscale, owned-only cleanup (converted and safety backups deleted, dev-d's baseline kept, the catalog entry this run
installed removed again), leak scans of every registered value and isolation. **125/125** in 405 s (the lock held
404 s).

`page-full-flow.json` is the capture's fixed-status record (131 lines) and stdout hash. Private run:
`~/.woowbk-lab/evidence/services-a-2-hsff/20261128T090623/`, full stdout in
`/tmp/parity-focus-20261127/hs-page-20261128-01.private.log`. The run installed its checkout's engine and page on dev-d
(product code equal to `b058df27`). `commercial_acceptance`: `not-complete`.
