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

## Actual runner login/ensure cycle

Command: `python3 tests/e2e/lab/omnigent_synthetic_credentials.py --run --runner-ensure`.
`run-ensure.jsonl`: exit 0, cleanup verified. A NEW disposable runner image,
`68794c7302df51c24539009635483e9300ff00e353192d7b7bb656ddf1eef373`,
ran the actual installed omnigent-runner-login and omnigent.cli_auth functions.
The production functions were not replaced: observers forwarded real HTTP
responses unchanged, registering issued credentials before normal persistence.
Helper console messages were suppressed to retain the framed event protocol.
The container used log-driver=none so credential frames could not enter container
logs. No existing HOME, runner/model/workspace or Pi process was touched.

Actual observations: login succeeded; ensure on a valid token made no request;
only the new container's cached expiration was forced into the past through
CLI store_token; ensure then called the real refresh endpoint and persisted its
returned access/refresh pair. There was no fallback login. A further ensure made
no request. This does NOT claim an eight-hour JWT expiry was waited out.
Four HTTP credential events (direct API plus runner cycle) passed registration.
Evidence and application logs had zero registered-secret matches. Exact helper
and cli_auth source hashes appear in run-ensure.jsonl.

Autonomous daemon refresh/host-registration events over long-lived operation,
all other service credential sources and complete restoration acceptance remain
unverified; full_runner_coverage deliberately remains false.
