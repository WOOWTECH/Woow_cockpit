"""Strict streaming OCI-save to link-free Docker-save adapter for opt-in PG16 releases.

Podman's Docker exporter adds legacy symlinks. Those remain forbidden by pg16_bundle. Export OCI instead;
this adapter accepts only regular blobs, authenticates descriptors/config/ordered diff_ids, and never extracts.
"""
import hashlib
import json
import os
import tarfile

MANIFEST_TYPES = {'application/vnd.oci.image.manifest.v1+json',
                  'application/vnd.docker.distribution.manifest.v2+json'}
CONFIG_TYPES = {'application/vnd.oci.image.config.v1+json',
                'application/vnd.docker.container.image.v1+json'}
LAYER_TYPES = {'application/vnd.oci.image.layer.v1.tar', 'application/vnd.oci.image.layer.v1.tar+gzip',
               'application/vnd.docker.image.rootfs.diff.tar', 'application/vnd.docker.image.rootfs.diff.tar.gzip'}
ERROR_LAYOUT = 'Invalid or unsafe PG16 OCI archive.'
ERROR_DESCRIPTOR = 'PG16 OCI descriptor SHA256/size mismatch.'
ERROR_IDENTITY = 'PG16 OCI ref/config differs from the release pin.'


def convert_archive(source, target, bundle, arch, image_id, *, expected_tag=None, abort=None):
    """Write a quarantined regular-only Docker archive; return only after the production verifier passes."""
    def require(ok, reason=ERROR_LAYOUT):
        if not ok:
            raise bundle.BundleError(reason)
    source.seek(0, os.SEEK_END)
    end = source.tell()
    require(0 < end <= bundle.MAX_ARCHIVE)
    source.seek(0)
    positions, names = {}, set()
    while source.tell() < end:
        bundle._tick(abort)
        header = source.read(512)
        if header == bytes(512):
            while True:
                bundle._tick(abort)
                tail = source.read(bundle.CHUNK)
                if not tail:
                    break
                require(not any(tail))
            break
        try:
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        except (tarfile.TarError, ValueError, UnicodeError):
            raise bundle.BundleError(ERROR_LAYOUT) from None
        name = info.name.rstrip('/') if info.isdir() else info.name
        require(bool(name) and not name.startswith('/') and '\\' not in name and len(name) <= 255
                and not any(p in ('', '.', '..') for p in name.split('/')) and name not in names
                and len(names) < 4096 and info.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                and info.size >= 0 and not (info.isdir() and info.size))
        names.add(name)
        start = source.tell()
        next_header = start + ((info.size + 511) // 512) * 512
        require(next_header <= end)
        if info.isfile():
            require(name in ('index.json', 'oci-layout') or
                    (name.startswith('blobs/sha256/') and bundle._hex(name[13:])))
            positions[name] = start, info.size
        source.seek(next_header)

    def small(name):
        require(name in positions)
        start, size = positions[name]
        require(size <= bundle.MAX_JSON)
        source.seek(start)
        return bundle._json(source.read(size))

    require(small('oci-layout') == {'imageLayoutVersion': '1.0.0'})
    index = small('index.json')
    require(isinstance(index, dict) and type(index.get('schemaVersion')) is int and index['schemaVersion'] == 2)
    manifests = index.get('manifests')
    require(isinstance(manifests, list) and len(manifests) == 1 and isinstance(manifests[0], dict))
    expected_tag = expected_tag or bundle.TAG
    annotations = manifests[0].get('annotations', {})
    require(isinstance(annotations, dict) and annotations.get('org.opencontainers.image.ref.name')
            in (expected_tag, expected_tag.rsplit(':', 1)[1]), ERROR_IDENTITY)

    used = {'index.json', 'oci-layout'}
    def descriptor(value, media_types):
        require(isinstance(value, dict) and value.get('mediaType') in media_types)
        digest, size = value.get('digest'), value.get('size')
        require(isinstance(digest, str) and digest.startswith('sha256:') and bundle._hex(digest[7:])
                and type(size) is int and 0 <= size <= bundle.MAX_ARCHIVE)
        name = 'blobs/sha256/' + digest[7:]
        require(name in positions and positions[name][1] == size, ERROR_DESCRIPTOR)
        used.add(name)
        return name, digest

    def hash_blob(name):
        start, left = positions[name]
        source.seek(start)
        digest = hashlib.sha256()
        while left:
            bundle._tick(abort)
            data = source.read(min(left, bundle.CHUNK))
            require(bool(data))
            digest.update(data)
            left -= len(data)
        require(digest.hexdigest() == name[13:], ERROR_DESCRIPTOR)

    manifest_name, _ = descriptor(manifests[0], MANIFEST_TYPES)
    hash_blob(manifest_name)
    manifest = small(manifest_name)
    require(isinstance(manifest, dict) and type(manifest.get('schemaVersion')) is int
            and manifest['schemaVersion'] == 2)
    config_name, config_digest = descriptor(manifest.get('config'), CONFIG_TYPES)
    require(config_digest == image_id, ERROR_IDENTITY)
    hash_blob(config_name)
    layers = manifest.get('layers')
    require(isinstance(layers, list) and 0 < len(layers) <= 4096)
    layer_names = [descriptor(layer, LAYER_TYPES)[0] for layer in layers]
    require(len(set(layer_names)) == len(layer_names) and set(positions) == used)
    for name in layer_names:
        hash_blob(name)

    # Fixed regular headers only; config/layer payloads are copied byte-for-byte in bounded chunks.
    def header(name, size):
        info = tarfile.TarInfo(name)
        info.size, info.mode = size, 0o644
        target.write(info.tobuf(format=tarfile.USTAR_FORMAT))
    config_out = image_id[7:] + '.json'
    layer_out = [name[13:] + '.tar' for name in layer_names]
    for original, output in [(config_name, config_out), *zip(layer_names, layer_out)]:
        start, left = positions[original]
        source.seek(start)
        header(output, left)
        while left:
            bundle._tick(abort)
            data = source.read(min(left, bundle.CHUNK))
            require(bool(data))
            target.write(data)
            left -= len(data)
        target.write(bytes(-positions[original][1] % 512))
        require(target.tell() <= bundle.MAX_ARCHIVE)
    raw = json.dumps([{'Config': config_out, 'RepoTags': [bundle.TAG], 'Layers': layer_out}],
                     separators=(',', ':')).encode()
    header('manifest.json', len(raw))
    target.write(raw)
    target.write(bytes(-len(raw) % 512 + 1024))
    require(target.tell() <= bundle.MAX_ARCHIVE)
    target.flush()
    bundle.validate_archive(target, arch, image_id, abort=abort)
