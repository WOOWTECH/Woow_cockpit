"""Native ARM images for the Omnigent restore on .54, in the private store: the exact references the Woow Omnigent
package pins (commit 6e4f0c0, quadlet/omnigent-postgres.container and omnigent-server.container; multi-arch index
digests, arm64 selected). Image fetches happen here only; every runtime container later runs in a pod with network
none and no published port. The runner image of the package is a local build (Containerfile.runner) and is NOT
built here: the restore keeps the runner's pi volume with a placeholder container (the Pi agent is out of scope)."""
import json
import sys
import time

from arm54_final_runtime import DRIVER, ROOT, Runner, report

PG = ('docker.io/library/postgres:16.15-alpine3.24'
      '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
SERVER = ('ghcr.io/omnigent-ai/omnigent-server:v0.21.0'
          '@sha256:9bba2964f015ddbb61da0924267effd1801c0db8f44ecec95f401f24d9a3f90c')
# arm64 manifests of those indexes (registry listing 2026-11-23): what `--arch arm64` must select.
ARM64 = {PG: 'sha256:9f5be6795d4e', SERVER: 'sha256:38ed1996713c'}

r = Runner()
out = {'status': 'failed', 'phase': 'start', 'store_driver': DRIVER, 'package_commit': '6e4f0c0',
       'commercial_acceptance': 'not-complete'}
started = time.monotonic()
try:
    out['phase'] = 'pull'
    for ref in (PG, SERVER):
        r.podman('pull', '--arch', 'arm64', '--authfile', str(ROOT / 'empty-auth.json'), ref, timeout=900)
    out['phase'] = 'verify'
    images = {}
    for ref in (PG, SERVER):
        info = json.loads(r.podman('image', 'inspect', ref).stdout)[0]
        assert info['Architecture'] == 'arm64', 'arch-' + ref.split('/')[-1][:20]
        assert any(d.split('@')[1].startswith(ARM64[ref]) for d in info.get('RepoDigests') or []), 'arm64-manifest'
        assert r.podman('image', 'exists', ref, check=False).returncode == 0, 'reference-resolves-locally'
        images[ref.split('@')[0]] = {'id': info['Id'], 'arch': info['Architecture'], 'bytes': info['Size'],
                                     'repo_digests': sorted(info.get('RepoDigests') or [])}
    pg_version = r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '128m', PG,
                          'postgres', '--version', timeout=120).stdout.decode().strip()
    assert pg_version.startswith('postgres (PostgreSQL) 16.'), 'pg-version'
    probe = ('import importlib.metadata as m, json, platform\n'
             'found = sorted({(d.metadata["Name"] or "").lower(): d.version for d in m.distributions()\n'
             '                if (d.metadata["Name"] or "").lower().startswith("omnigent")}.items())\n'
             'print(json.dumps({"dists": found, "machine": platform.machine()}))\n')
    py = json.loads(r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '256m',
                             '--entrypoint', 'python3', SERVER, '-I', '-c', probe, timeout=180).stdout)
    versions = dict(py['dists'])
    out.update(omnigent_dists_seen=py['dists'], machine_seen=py['machine'])
    assert py['machine'] == 'aarch64' and versions.get('omnigent') == '0.21.0', 'omnigent-version'
    secret_ls = r.podman('secret', 'ls', '--format', '{{.Name}}', check=False)
    out.update(status='passed', phase='done', images=images, pg_version=pg_version, omnigent_dists=py['dists'],
               machine=py['machine'], secret_listing_format_ok=secret_ls.returncode == 0)
except Exception as error:  # noqa: BLE001 - recorded as a fixed code; messages may carry source values
    out['error_code'] = type(error).__name__
    out['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
    if hasattr(error, 'code'):
        out['product_error_code'] = error.code
finally:
    out.update(elapsed_seconds=round(time.monotonic() - started, 1), commands=r.commands,
               free_bytes_min=min(r.free) if r.free else None)
    report(ROOT / 'omni-build-result.json', out)
    print(json.dumps(out, sort_keys=True))
    sys.exit(0 if out['status'] == 'passed' else 1)
