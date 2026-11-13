"""Builders for the tar files nested inside a backup: OCI archives and volume exports (test helpers).

The layouts match what podman 4.9.3 produces (checked on the lab device):
* `podman save --format oci-archive`: `blobs/`, `blobs/sha256/`, `blobs/sha256/<hex>`, `index.json`,
  `oci-layout`; one manifest annotated `org.opencontainers.image.ref.name: <full ref>`; image id = config digest.
* `podman volume export`: relative names without a root entry (`files/`, `files/a.bin`), uid/gid 0.
"""
import hashlib
import io
import json
import tarfile

OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def config_for(ref, env=()):
    return json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {'Env': list(env)},
                       'rootfs': {'type': 'layers', 'diff_ids': []}, 'comment': ref}, sort_keys=True).encode()


def image_id(ref, env=()):
    return 'sha256:' + sha(config_for(ref, env))


def _add(tar, name, data=b'', kind=tarfile.REGTYPE, mode=0o644, linkname='', **fields):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.mode = mode
    info.size = len(data) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    info.linkname = linkname
    for key, value in fields.items():
        setattr(info, key, value)
    tar.addfile(info, io.BytesIO(data) if info.size else None)


def oci_archive(ref, *, env=(), layer=b'layer-data', annotation=None, manifests=1, config=None, extra=(),
                manifest_digest=None, prefix=''):
    """A podman-style OCI archive for `ref`. Keyword arguments build hostile variants."""
    config = config if config is not None else config_for(ref, env)
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': OCI_MANIFEST,
                           'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                                      'digest': 'sha256:' + sha(config), 'size': len(config)},
                           'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                                       'digest': 'sha256:' + sha(layer), 'size': len(layer)}]}).encode()
    descriptor = {'mediaType': OCI_MANIFEST, 'digest': manifest_digest or 'sha256:' + sha(manifest),
                  'size': len(manifest), 'annotations': {'org.opencontainers.image.ref.name': annotation or ref}}
    index = json.dumps({'schemaVersion': 2, 'manifests': [descriptor] * manifests}).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        _add(tar, prefix + 'blobs/', kind=tarfile.DIRTYPE, mode=0o755)
        _add(tar, prefix + 'blobs/sha256/', kind=tarfile.DIRTYPE, mode=0o755)
        for blob in (config, layer, manifest):
            _add(tar, f'{prefix}blobs/sha256/{sha(blob)}', blob)
        _add(tar, prefix + 'index.json', index)
        _add(tar, prefix + 'oci-layout', b'{"imageLayoutVersion": "1.0.0"}')
        for item in extra:
            _add(tar, **item)
    return buffer.getvalue()


def read_oci(data):
    """(ref annotation, image id) of an OCI archive, as `podman load` would name and identify it."""
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        names = {member.name: member for member in tar.getmembers()}
        index = json.loads(tar.extractfile(names['index.json']).read())
        descriptor = index['manifests'][0]
        manifest = json.loads(tar.extractfile(names['blobs/sha256/' + descriptor['digest'][7:]]).read())
        return descriptor['annotations']['org.opencontainers.image.ref.name'], manifest['config']['digest']


def volume_tar(members=None):
    """A `podman volume export`-style tar. `members`: list of _add keyword dicts (defaults to a small tree)."""
    if members is None:
        members = [
            {'name': 'files/', 'kind': tarfile.DIRTYPE, 'mode': 0o755},
            {'name': 'files/a.bin', 'data': b'A' * 3000, 'mode': 0o644},
            {'name': 'files/b.txt', 'data': b'hello', 'mode': 0o4755},
            {'name': 'files/current', 'kind': tarfile.SYMTYPE, 'linkname': '/data/files/a.bin', 'mode': 0o777},
            {'name': 'files/a-link.bin', 'kind': tarfile.LNKTYPE, 'linkname': 'files/a.bin'},
        ]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for item in members:
            _add(tar, **item)
    return buffer.getvalue()


def tar_listing(data):
    """[(name, type, mode, size, linkname, sha256 of content)] for comparing tars by content."""
    rows = []
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        for member in tar.getmembers():
            content = tar.extractfile(member).read() if member.isreg() else b''
            rows.append((member.name.rstrip('/'), member.type, member.mode, member.size, member.linkname,
                         sha(content)))
    return rows
