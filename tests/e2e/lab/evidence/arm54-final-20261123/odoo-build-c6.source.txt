"""SUBSTITUTE images, not the product service (owner decision 3A, 2026-11-23 「決定3 A」): native ARM images for the
HA ARM Odoo restore on .54 (lane arm54-2, item B Odoo), in the private store. The product's Odoo target images have no
arm64 build (tenant image localhost/woow-odoo-tenant-ha:20261101.1152-51856b0 = a local amd64 build; paas-postgres
17.11 from the private registry), so the owner accepted:
- web: the official odoo:18.0 image, dated tag 18.0-20260926 = the Odoo release of the product's tenant image (dev-c's
  check reported target_version 18.0-20260926 for it; HA's add-on 0.4.13 installs the 18.0.20260930 package);
- database: the official PostgreSQL 17 with pgvector (pgvector/pgvector:0.8.6-pg17; the product's tenant install
  creates pg_trgm + vector);
- the product's own first PostgreSQL 16 choice for opening HA's cluster (ha_odoo.PG16_IMAGES[0], pgvector 0.8.6-pg16).
Each is pinned by its multi-arch index digest (registry listing 2026-11-23) with the arm64 manifest selected and then
given the plain tag the rendered quadlets and the product name. Image fetches happen here only; every runtime
container later runs in a pod with network none (or on the product's internal throwaway network) and no published
port."""
import json
import sys
import time

from arm54_final_runtime import DRIVER, ROOT, Runner, report

ODOO = ('docker.io/library/odoo:18.0-20260926'
        '@sha256:60eb1b5006df85f900e300b6cc120d51ebd979379ee9588340adc2a84ffcd718')
PG17 = ('docker.io/pgvector/pgvector:0.8.6-pg17'
        '@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f')
PG16 = ('docker.io/pgvector/pgvector:0.8.6-pg16'
        '@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b')
# arm64 manifests of those indexes (registry listing 2026-11-23): what `--arch arm64` must select.
ARM64 = {ODOO: 'sha256:7cda9ea19a04', PG17: 'sha256:de5bb95ded56', PG16: 'sha256:3f0a88823465'}

r = Runner()
out = {'status': 'failed', 'phase': 'start', 'store_driver': DRIVER, 'commercial_acceptance': 'not-complete',
       'label': 'substitute images, not the product service (owner decision 3A)'}
started = time.monotonic()
try:
    out['phase'] = 'pull'
    for ref in (PG16, PG17, ODOO):
        r.podman('pull', '--arch', 'arm64', '--authfile', str(ROOT / 'empty-auth.json'), ref, timeout=1800,
                 max_output=1024 * 1024)
    out['phase'] = 'verify'
    images = {}
    for ref in (PG16, PG17, ODOO):
        info = json.loads(r.podman('image', 'inspect', ref).stdout)[0]
        assert info['Architecture'] == 'arm64', 'arch-' + ref.split('/')[-1][:20]
        assert any(d.split('@')[1].startswith(ARM64[ref]) for d in info.get('RepoDigests') or []), 'arm64-manifest'
        name = ref.split('@')[0]
        r.podman('tag', ref, name, timeout=60)
        same = json.loads(r.podman('image', 'inspect', name).stdout)[0]['Id'] == info['Id']
        assert same, 'tag-points-at-the-pinned-image'
        env = dict(item.split('=', 1) for item in (info.get('Config') or {}).get('Env') or [] if '=' in item)
        images[name] = {'id': info['Id'], 'arch': info['Architecture'], 'bytes': info['Size'],
                        'index_digest': ref.split('@')[1],
                        'arm64_manifest': next(d.split('@')[1] for d in info['RepoDigests']
                                               if d.split('@')[1].startswith(ARM64[ref])),
                        'env': {k: env[k] for k in ('ODOO_VERSION', 'ODOO_RELEASE', 'PG_MAJOR', 'PG_VERSION')
                                if k in env}}
    out['images'] = images
    out.update(status='passed', phase='done')
except Exception as error:  # noqa: BLE001
    out['error_code'] = type(error).__name__
    out['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
finally:
    out['elapsed_seconds'] = round(time.monotonic() - started, 1)
    out['free_bytes_min'] = min(r.free) if r.free else None
    report(ROOT / 'odoo-build-result.json', out)
    print(json.dumps(out, sort_keys=True))
sys.exit(0 if out['status'] == 'passed' else 1)
