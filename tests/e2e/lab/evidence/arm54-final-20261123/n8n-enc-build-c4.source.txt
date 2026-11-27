"""Native ARM images for the n8n restore on .54 (lane arm54-2, item B), in the private store: the exact images the
Woow n8n package pins (commit 2ac1ae2 = the host's package: quadlet/n8n.container docker.io/n8nio/n8n:2.43.6,
quadlet/n8n-postgres.container docker.io/library/postgres:16.15-alpine, quadlet/queue/n8n-valkey.container
docker.io/valkey/valkey:8.1.11-alpine), each pinned here by its multi-arch index digest (registry listing
2026-11-23; the PostgreSQL digest is the product's own PG16_PINNED) with the arm64 manifest selected. Image fetches
happen here only; every runtime container later runs in a pod with network none and no published port."""
import json
import sys
import time

from arm54_final_runtime import DRIVER, ROOT, Runner, report

N8N = 'docker.io/n8nio/n8n:2.43.6@sha256:dd580fe1ab6e99e85bc66f2acf8bc8c5e9409fbe61b2e2803c5024403ef52833'
PG = ('docker.io/library/postgres:16.15-alpine'
      '@sha256:aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139')
VALKEY = ('docker.io/valkey/valkey:8.1.11-alpine'
          '@sha256:2602ace2be6569bc2bbb06f873776516ab9089821525be34f4305c67eb9db02a')
# arm64 manifests of those indexes (registry listing 2026-11-23): what `--arch arm64` must select.
ARM64 = {N8N: 'sha256:4648e0196554', PG: 'sha256:9f5be6795d4e', VALKEY: 'sha256:880f09f3e1ba'}

r = Runner()
out = {'status': 'failed', 'phase': 'start', 'store_driver': DRIVER, 'package_commit': '2ac1ae2',
       'commercial_acceptance': 'not-complete'}
started = time.monotonic()
try:
    out['phase'] = 'pull'
    for ref in (PG, VALKEY, N8N):
        r.podman('pull', '--arch', 'arm64', '--authfile', str(ROOT / 'empty-auth.json'), ref, timeout=900)
    out['phase'] = 'verify'
    images = {}
    for ref in (PG, VALKEY, N8N):
        info = json.loads(r.podman('image', 'inspect', ref).stdout)[0]
        assert info['Architecture'] == 'arm64', 'arch-' + ref.split('/')[-1][:20]
        assert any(d.split('@')[1].startswith(ARM64[ref]) for d in info.get('RepoDigests') or []), 'arm64-manifest'
        assert r.podman('image', 'exists', ref, check=False).returncode == 0, 'reference-resolves-locally'
        images[ref.split('@')[0]] = {'id': info['Id'], 'arch': info['Architecture'], 'bytes': info['Size'],
                                     'repo_digests': sorted(info.get('RepoDigests') or [])}
    # The package's quadlets name the images by tag only (Image=docker.io/n8nio/n8n:2.43.6, ...): the digest-pinned
    # pull above is given that exact tag so `--pull=never` and the product's throwaway runs resolve it locally.
    out['phase'] = 'tag'
    tags = {}
    for ref in (PG, VALKEY, N8N):
        name = ref.split('@')[0]
        r.podman('tag', ref, name, timeout=60)
        assert r.podman('image', 'exists', name, check=False).returncode == 0, 'tag-resolves'
        same = json.loads(r.podman('image', 'inspect', name).stdout)[0]['Id'] == images[name]['id']
        assert same, 'tag-points-at-the-pinned-image'
        tags[name] = images[name]['id']
    out['tags'] = tags
    pg_version = r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '128m', PG,
                          'postgres', '--version', timeout=120).stdout.decode().strip()
    assert pg_version.startswith('postgres (PostgreSQL) 16.'), 'pg-version'
    n8n_version = r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '512m', N8N,
                           '--version', timeout=300).stdout.decode().strip().splitlines()[-1]
    assert n8n_version == '2.43.6', 'n8n-version'
    machine = r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '64m', '--entrypoint',
                       'uname', VALKEY, '-m', timeout=120).stdout.decode().strip()
    assert machine == 'aarch64', 'machine'
    # Informational (attempt n8n-build, dc653c8: --add-host entries were NOT in /etc/hosts of a network-none pod):
    # the restore therefore points the main container at the pod's loopback by environment (stated deviation).
    out['phase'] = 'pod-hosts'
    r.podman('pod', 'create', '--name', 'a54n-hostcheck', '--label', 'io.woowtech.test=arm54-final-20261123',
             '--network', 'none', '--add-host', 'n8n-postgres:127.0.0.1', '--add-host', 'n8n-valkey:127.0.0.1',
             timeout=120)
    try:
        hosts = r.podman('run', '--rm', '--pod', 'a54n-hostcheck', '--pull=never', '--memory', '64m', '--entrypoint',
                         'cat', VALKEY, '/etc/hosts', timeout=120, check=False).stdout.decode()
    finally:
        r.podman('pod', 'rm', '--force', 'a54n-hostcheck', check=False, timeout=120)
    names = sorted({part for line in hosts.splitlines() if line.strip() and not line.startswith('#')
                    for part in line.split()[1:]})
    out['pod_hosts_names_informational'] = names
    out.update(status='passed', phase='done', images=images, pg_version=pg_version, n8n_version=n8n_version,
               machine=machine)
except Exception as error:  # noqa: BLE001 - recorded as a fixed code; messages may carry source values
    out['error_code'] = type(error).__name__
    out['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
    if hasattr(error, 'code'):
        out['product_error_code'] = error.code
finally:
    out.update(elapsed_seconds=round(time.monotonic() - started, 1), commands=r.commands,
               free_bytes_min=min(r.free) if r.free else None)
    report(ROOT / 'n8n-build-result.json', out)
    print(json.dumps(out, sort_keys=True))
    sys.exit(0 if out['status'] == 'passed' else 1)
