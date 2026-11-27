"""Lane arm54-2 item D (EMQX on .54): the product's own EMQX image for this ARM64 device, in the private store.

The Woow_podman_emqx quadlet (package ea5886c, evidence emqx-package-ea5886c) names
docker.io/emqx/emqx:5.8.9@sha256:35b46f7a... -- a multi-arch index (registry listing 2026-11-23, evidence
emqx-image-index-35b46f7a.json): amd64 sha256:8b92a101..., arm64 sha256:c455c60f.... This pulls exactly that index with
`--arch arm64`, proves the arm64 manifest was selected, gives it the plain tag, and proves that the quadlet's own full
reference (tag + index digest), the one the product's Target and its throwaway containers use, resolves to the same
local image. The image is the product image itself (not a substitute). Image fetches happen here only; every runtime
container later runs with network none in the run's own network namespace and no published port."""
import json
import sys
import time

from arm54_final_runtime import DRIVER, ROOT, Runner, report

QUADLET_IMAGE = ('docker.io/emqx/emqx:5.8.9'
                 '@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b')
INDEX = 'docker.io/emqx/emqx@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b'
ARM64 = 'sha256:c455c60feced3452a5fa81a761f840983039118b1c126fdad6c86f93467a3be5'
TAG = 'docker.io/emqx/emqx:5.8.9'


def main():
    r = Runner()
    out = {'status': 'failed', 'phase': 'start', 'store_driver': DRIVER, 'commercial_acceptance': 'not-complete',
           'image': 'product image (Woow_podman_emqx ea5886c quadlet), not a substitute'}
    started = time.monotonic()
    try:
        out['phase'] = 'pull'
        r.podman('pull', '--arch', 'arm64', '--authfile', str(ROOT / 'empty-auth.json'), INDEX, timeout=1800,
                 max_output=1024 * 1024)
        out['phase'] = 'verify'
        info = json.loads(r.podman('image', 'inspect', INDEX).stdout)[0]
        assert info['Architecture'] == 'arm64', 'arch'
        digests = [d.split('@')[1] for d in info.get('RepoDigests') or []]
        assert ARM64 in digests, 'arm64-manifest'
        r.podman('tag', INDEX, TAG, timeout=60)
        tagged = json.loads(r.podman('image', 'inspect', TAG).stdout)[0]['Id']
        quadlet = json.loads(r.podman('image', 'inspect', QUADLET_IMAGE).stdout)[0]['Id']
        assert tagged == info['Id'] == quadlet, 'quadlet-reference-resolves-to-the-pinned-image'
        config = info.get('Config') or {}
        labels = config.get('Labels') or {}
        out['image'] = {'id': info['Id'], 'arch': info['Architecture'], 'bytes': info['Size'],
                        'index_digest': INDEX.split('@')[1], 'arm64_manifest': ARM64,
                        'repo_digests': sorted(digests),
                        'version_label': labels.get('org.opencontainers.image.version'),
                        'declared_volumes': sorted((config.get('Volumes') or {}).keys()),
                        'user': config.get('User'), 'quadlet_reference_resolves': True,
                        'label': 'product image, not a substitute'}
        assert out['image']['version_label'] == '5.8.9', 'version-label'
        out.update(status='passed', phase='done')
    except Exception as error:  # noqa: BLE001
        out['error_code'] = type(error).__name__
        out['failed_check'] = str(error)[:80] if isinstance(error, AssertionError) else None
    finally:
        out['elapsed_seconds'] = round(time.monotonic() - started, 1)
        out['free_bytes_min'] = min(r.free) if r.free else None
        report(ROOT / 'emqx-build-result.json', out)
        print(json.dumps(out, sort_keys=True))
    return 0 if out['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
