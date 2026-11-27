"""Read only public pinned registry metadata; never save anonymous pull tokens."""
import hashlib
import json
import urllib.request
from pathlib import Path


def get(url, token=None):
    headers = {'Accept': ', '.join(('application/vnd.oci.image.index.v1+json',
        'application/vnd.docker.distribution.manifest.list.v2+json',
        'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'))}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=25) as response:
        raw = response.read(2 * 1024 ** 2 + 1)
    assert len(raw) <= 2 * 1024 ** 2
    return raw


def inspect(registry, repository, reference):
    auth = ('https://ghcr.io/token?service=ghcr.io&scope=repository:' if registry == 'ghcr.io'
            else 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:')
    token = json.loads(get(auth + repository + ':pull'))['token']
    url = 'https://' + registry + '/v2/' + repository
    raw = get(url + '/manifests/' + reference, token)
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if reference.startswith('sha256:'):
        assert digest == reference
    manifest = json.loads(raw)
    result = {'registry': registry, 'repository': repository, 'reference': reference,
              'resolved_digest': digest, 'media_type': manifest.get('mediaType')}
    if 'manifests' in manifest:
        result['platforms'] = [{'digest': x['digest'], 'platform': x.get('platform')} for x in manifest['manifests']]
    else:
        config_raw = get(url + '/blobs/' + manifest['config']['digest'], token)
        assert 'sha256:' + hashlib.sha256(config_raw).hexdigest() == manifest['config']['digest']
        config = json.loads(config_raw)
        result.update(architecture=config.get('architecture'), os=config.get('os'),
                      labels=config.get('config', {}).get('Labels'),
                      compressed_bytes=sum(x['size'] for x in manifest['layers']))
    return result


if __name__ == '__main__':
    queries = [('ghcr.io', 'juanfont/headscale', 'sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f'),
               ('ghcr.io', 'juanfont/headscale', 'v0.29.4'),
               ('registry-1.docker.io', 'library/debian', 'sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef')]
    results = []
    for query in queries:
        try:
            results.append(inspect(*query))
        except Exception as error:
            results.append({'registry': query[0], 'repository': query[1], 'reference': query[2],
                            'error': type(error).__name__})
    path = Path('tests/e2e/lab/evidence/arm54-service-20261122/public-image-metadata.json')
    path.write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results))
