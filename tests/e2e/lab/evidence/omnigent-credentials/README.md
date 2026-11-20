# Real synthetic Omnigent credential producer — 2026-11-20

Command: `python3 tests/e2e/lab/omnigent_synthetic_credentials.py --run`.
Actual stdout: `run.jsonl`; exit 0. Exact image IDs are in that output.

A NEW PostgreSQL database and NEW Omnigent server initialized their real schema
and a new synthetic administrator from a newly generated Podman secret. No
original identity/grant, production data, or existing runner workspace was used.
Server shares only the new PostgreSQL network-none namespace, publishes no ports,
and returned errno101 on an actual external TCP probe. Original services untouched.

The existing CREDENTIAL_HTTP producer contacted the real /auth/login and
/oauth/token endpoints. Existing acknowledged event transport registered and
validated login.token, login.refresh_token, refresh.access_token and
refresh.refresh_token before permitting the summary. Actual observed credentials
were passed through Evidence.save redaction, with zero hits in resulting evidence
and application stdout/stderr logs. A further scan including coverage.json also
returned zero. Evidence prints only fixed stages, source names, counts and images.
Cleanup verified absence of both new containers, both volumes and the test secret.

Limits: direct API producer/consumer coverage with fresh synthetic identity,
not the autonomous runner ensure/refresh path, not all services' issued secrets,
not existing dev-d account repair or a restored HA account's acceptance. The old
refresh400/login401 credentials were not retried. Public import/scenario guards
remain. This does not grant permission to use host production Podman or bypass
Hermes independent-review restriction.
