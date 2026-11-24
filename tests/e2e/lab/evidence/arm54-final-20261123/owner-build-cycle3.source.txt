"""Native ARM images in the private store: the unmodified Woow Headscale package recipe (commit 0afdfa4, the
same localhost/woow-headscale:0.29.4-r1 tag scripts/install.sh builds) and the pinned public Tailscale client
1.104.7 (arm64 manifest of the index the real B1 client ran). Image fetches happen here only; every runtime
container later runs with network none and no published ports."""
import hashlib
import json
import sys
import time
from pathlib import Path

from arm54_final_runtime import ROOT, Runner, private_dir, report

HEADSCALE_SRC = 'ghcr.io/juanfont/headscale:v0.29.4@sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f'
DEBIAN_SRC = 'docker.io/library/debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef'
TAILSCALE = 'docker.io/tailscale/tailscale@sha256:8934bed5f68e80c5f9c881f62c65909223ee660432946c10ad212d958fc2c2bb'
TAG = 'localhost/woow-headscale:0.29.4-r1'
RECIPE = ROOT / 'source/tests/e2e/lab/evidence/arm54-service-20261122/package.Containerfile'
RECIPE_SHA256 = '02f850bfe625cec627d8da94c3b61bd802990b75b0fd55d6ef164c8c2b7f403d'

r = Runner()
out = {'status': 'failed', 'phase': 'start', 'package_commit': '0afdfa464a5ae55c85145c242f5b38ac88eea969',
       'shipped_image': False, 'commercial_acceptance': 'not-complete'}
started = time.monotonic()
try:
    from woowbackup import ha_headscale, hacommon
    from types import SimpleNamespace
    assert hashlib.sha256(RECIPE.read_bytes()).hexdigest() == RECIPE_SHA256, 'recipe-hash-mismatch'
    out['phase'] = 'pull'
    for ref in (HEADSCALE_SRC, DEBIAN_SRC, TAILSCALE):
        r.podman('pull', '--arch', 'arm64', '--authfile', str(ROOT / 'empty-auth.json'), ref, timeout=900)
    out['phase'] = 'build'
    context = private_dir('build-context')
    r.podman('build', '--network=none', '--pull=never', '--layers=false', '--no-cache', '--memory=512m',
             '--tag', TAG, '--file', str(RECIPE), str(context), timeout=900)
    out['phase'] = 'verify'
    info = json.loads(r.podman('image', 'inspect', TAG).stdout)[0]
    assert info['Architecture'] == 'arm64', 'headscale-arch'
    labels = hacommon.image_labels(SimpleNamespace(runner=lambda app: r), SimpleNamespace(id='headscale'), TAG)
    version = hacommon.semver(labels.get('org.opencontainers.image.version'))
    blocker = ha_headscale.VERSIONS.blocker('0.1.3', version)
    assert blocker is None, 'product-version-gate'
    banner = r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '256m', TAG, 'version',
                      timeout=120).stdout.decode().strip().splitlines()
    assert banner and banner[0] == 'headscale version v0.29.4', 'headscale-banner'
    ts = json.loads(r.podman('image', 'inspect', TAILSCALE).stdout)[0]
    assert ts['Architecture'] == 'arm64', 'tailscale-arch'
    ts_version = r.podman('run', '--rm', '--network', 'none', '--pull=never', '--memory', '256m',
                          '--entrypoint', 'tailscale', TAILSCALE, 'version', timeout=120).stdout.decode().split()
    assert ts_version and ts_version[0] == '1.104.7', 'tailscale-version'
    out.update(status='passed', phase='done', headscale_image_id=info['Id'], headscale_arch=info['Architecture'],
               headscale_bytes=info['Size'], headscale_labels=labels, product_version=version,
               recipe_sha256=RECIPE_SHA256, headscale_banner=banner[0], tailscale_image_id=ts['Id'],
               tailscale_digest=TAILSCALE.split('@')[1], tailscale_version=ts_version[0],
               tailscale_arch=ts['Architecture'])
except Exception as error:  # noqa: BLE001 - recorded as a fixed code; messages may carry source values
    out['error_code'] = type(error).__name__
    out['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
    if hasattr(error, 'code'):
        out['product_error_code'] = error.code
finally:
    out.update(elapsed_seconds=round(time.monotonic() - started, 1), commands=r.commands,
               free_bytes_min=min(r.free) if r.free else None)
    report(ROOT / 'build-result.json', out)
    print(json.dumps(out, sort_keys=True))
    sys.exit(0 if out['status'] == 'passed' else 1)
