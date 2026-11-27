# CM-06 and O-31 integration follow-up (2026-11-26)

CM-06 now wires Hermes, EMQX, Headscale and OpenDesign into the shared image-version reader. It uses image settings after missing/unusable labels, then an in-image version command; an unknown version remains a notice. The existing target-image failures still stop the affected app.

O-31 now serializes the target's Alembic revision list as JSON UTF-8 and base64 before inserting it into the read-only PostgreSQL snapshot query. The database still compares the exact sorted revision list. Empty lists and punctuation/Unicode are representable without interpolating the original values into shell or SQL source.

Evidence: 32 focused guarded tests passed (0 failures/errors/skips/blocked/shim hits); the registry suite passed 9 tests; `scripts/check_source.py` passed. A real PostgreSQL probe in the isolated dev-d container passed normal, punctuation/Unicode and empty-list cases and removed the temporary container. The test harness output contains only fixed stage names and image ID.

The source repository's full final acceptance across ten services is still pending. This evidence is not device acceptance for the four caller integrations; `commercial_acceptance` remains `not-complete`.

The complete x86 real-HA-backup Omnigent flow was rerun after the O-31 product change, starting at `a2069c20`. It passed conversion, encrypted packaging, installation, restart, deliberately failed second installation and automatic rollback; HA data, logins, the kept target account, 19 table counts, cookie and runner identity were checked. Three journals and engine logs contained zero registered secret values; temporary resources were removed and the dev-d container/volume/secret inventory returned to its baseline. See `full-flow-current-x86.json`. This is the normal real-backup run; the subsequently completed O-15 extra-object derivative is recorded separately in `../parity-omnigent-r7-20261126/README.md`.
