#!/usr/bin/env python3
"""Read-only fixed PG16 image evidence inside dev-d's isolated nested owner store. No export/load/retag/pull."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

LAB = Path.home() / '.woowbk-lab/bin/labpodman'
HERE = Path(__file__).resolve().parent
IMAGE = '4278d7b1e3deb3193ddc803158f6532963f059fc25a2eefaee4b5a9e71741873'
INDEX = 'aa6cb33cf4c19c765cefcf48d96176258800870a9a1e930ad126200f9d825139'
CODE = r'''
import hashlib, json, os, pathlib, stat, subprocess
image_id = IMAGE_ID
pinned = PINNED_MANIFEST
fmt = ('{"id":"{{.Id}}","architecture":"{{.Architecture}}","os":"{{.Os}}","size":{{.Size}},'
       '"repo_digests":{{json .RepoDigests}},"repo_tags":{{json .RepoTags}}}')
result = subprocess.run(['podman', 'image', 'inspect', '--format', fmt, image_id],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
assert result.returncode == 0 and len(result.stdout) <= 65536
image = json.loads(result.stdout)
graph = subprocess.run(['podman', 'info', '--format', '{{.Store.GraphRoot}}'],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
assert graph.returncode == 0 and len(graph.stdout) <= 4096
root = pathlib.Path(graph.stdout.decode().strip())
assert root.is_absolute()
found = None
for driver in ('overlay-images', 'vfs-images'):
    path = root / driver / image_id / 'manifest'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        continue
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        assert stat.S_ISREG(st.st_mode) and 0 < st.st_size <= 1024**2
        raw = stream.read(1024**2 + 1)
    assert len(raw) <= 1024**2
    found = json.loads(raw)
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    break
assert found is not None
same_config = found['config']['digest'] == pinned['config']['digest'] == 'sha256:' + image_id
same_layers = [(x['digest'], x['size']) for x in found['layers']] == [(x['digest'], x['size']) for x in pinned['layers']]
config = None
total = 0
for candidate in sorted(path.parent.iterdir())[:32]:
    if not candidate.is_file() or candidate.is_symlink() or candidate.stat().st_size > 1024**2:
        continue
    fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(1024**2 + 1)
    total += len(raw)
    assert total <= 4 * 1024**2
    if hashlib.sha256(raw).hexdigest() == image_id:
        config = json.loads(raw)
        break
same_uncompressed = (config is not None and config.get('rootfs', {}).get('type') == 'layers'
                     and [x['digest'] for x in found['layers']] == config['rootfs']['diff_ids']
                     and all(x.get('mediaType', '').endswith('.tar') for x in found['layers']))
digest_observed = 'docker.io/library/postgres@' + digest in image['repo_digests']
print(json.dumps({'device': 'dev-d', 'source_image': image, 'stored_manifest_sha256': digest,
                  'stored_manifest_media_type': found.get('mediaType'), 'pinned_manifest_media_type': pinned.get('mediaType'),
                  'same_pinned_config': same_config, 'same_pinned_layers': same_layers,
                  'stored_config_sha256_verified': config is not None,
                  'stored_uncompressed_layers_match_pinned_config_diff_ids': same_uncompressed,
                  'stored_manifest_in_observed_repodigests': digest_observed,
                  'read_only': True, 'pulls': 0, 'store_mutations': 0,
                  'exported_layer_bytes_not_yet_verified': True,
                  'eligible_for_leased_export': same_config and config is not None and digest_observed
                              and image['architecture'] == 'amd64' and image['os'] == 'linux'}, sort_keys=True))
'''


def main():
    raw = (HERE / 'upstream-pg16-index.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == INDEX
    index = json.loads(raw)
    platform = [x for x in index['manifests'] if x.get('platform', {}).get('architecture') == 'amd64'
                and x.get('platform', {}).get('os') == 'linux']
    assert len(platform) == 1
    manifest_raw = (HERE / 'upstream-pg16-amd64-manifest.json').read_bytes()
    assert 'sha256:' + hashlib.sha256(manifest_raw).hexdigest() == platform[0]['digest']
    pinned = json.loads(manifest_raw)
    isolated = subprocess.run([str(LAB), 'inspect', 'woowbk-dev-d', '--format',
                               '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    assert isolated.returncode == 0 and isolated.stdout.strip() == b'true none {}'
    code = CODE.replace('IMAGE_ID', repr(IMAGE)).replace('PINNED_MANIFEST', repr(pinned))
    result = subprocess.run([str(LAB), 'exec', '-i', 'woowbk-dev-d', '/usr/local/bin/woowbk-owner',
                             'python3', '-I', '-'], input=code.encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode != 0:
        report = {'status': 'read-only-inventory-incomplete', 'exit': result.returncode, 'pulls': 0, 'store_mutations': 0}
    else:
        report = json.loads(result.stdout)
        report.update(status='pinned-config-verified-export-layer-check-pending' if report['eligible_for_leased_export'] else 'pin-chain-incomplete', index_digest='sha256:' + INDEX,
                      pinned_amd64_manifest=platform[0]['digest'], host_free_bytes=shutil.disk_usage(HERE).free,
                      reserve_bytes=13 * 1024**3)
    (HERE / 'dev-d-inventory-20261127.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get('eligible_for_leased_export') else 1


if __name__ == '__main__':
    sys.exit(main())
