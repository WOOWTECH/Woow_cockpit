"""Stream Docker directory transport into a regular-only PG16 Docker-save archive.

Unlike OCI conversion, this transport preserves Docker config JSON bytes. The independently supplied config SHA
binds the release identity and every ordered uncompressed layer. No extraction or image engine is used here.
"""
import hashlib
import json
import os
import tarfile

ERROR_DIRECTORY = 'Invalid or unsafe PG16 Docker directory.'
ERROR_DESCRIPTOR = 'PG16 Docker directory descriptor SHA256/size mismatch.'
ERROR_PIN = 'PG16 Docker directory config differs from the release pin.'


def convert_directory(path, target, bundle, arch, image_id, *, abort=None):
    def require(ok, reason=ERROR_DIRECTORY):
        if not ok:
            raise bundle.BundleError(reason)
    with bundle._directory(path) as dfd:
        names = set()
        with os.scandir(dfd) as entries:
            for entry in entries:
                require(len(names) < 4096)
                names.add(entry.name)
        require(2 < len(names) <= 4096 and {'manifest.json', 'version'} <= names)
        with bundle._file(dfd, 'version') as source:
            require(bundle._small(source).strip() == b'Directory Transport Version: 1.1')
        with bundle._file(dfd, 'manifest.json') as source:
            manifest = bundle._json(bundle._small(source))
        require(isinstance(manifest, dict) and type(manifest.get('schemaVersion')) is int
                and manifest['schemaVersion'] == 2
                and manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.v2+json')
        config, layers = manifest.get('config'), manifest.get('layers')
        require(isinstance(config, dict) and config.get('mediaType') == 'application/vnd.docker.container.image.v1+json'
                and isinstance(layers, list) and 0 < len(layers) < 4096)
        require(config.get('digest') == image_id, ERROR_PIN)
        descriptors = [config, *layers]
        for value in descriptors:
            require(isinstance(value, dict))
            digest, size = value.get('digest'), value.get('size')
            require(isinstance(digest, str) and digest.startswith('sha256:') and bundle._hex(digest[7:])
                    and type(size) is int and 0 <= size <= bundle.MAX_ARCHIVE)
        require(all(x.get('mediaType') in ('application/vnd.docker.image.rootfs.diff.tar',
                                         'application/vnd.docker.image.rootfs.diff.tar.gzip') for x in layers))
        digests = [x['digest'][7:] for x in descriptors]
        require(len(set(digests)) == len(digests) and names == {'manifest.json', 'version', *digests})
        config_out = image_id[7:] + '.json'
        layer_out = [x['digest'][7:] + '.tar' for x in layers]
        def header(name, size):
            info = tarfile.TarInfo(name)
            info.size, info.mode = size, 0o644
            target.write(info.tobuf(format=tarfile.USTAR_FORMAT))
        for descriptor, name in zip(descriptors, [config_out, *layer_out]):
            bundle._tick(abort)
            digest = hashlib.sha256()
            with bundle._file(dfd, descriptor['digest'][7:]) as source:
                size = os.fstat(source.fileno()).st_size
                require(size == descriptor['size'], ERROR_DESCRIPTOR)
                header(name, size)
                left = size
                while left:
                    bundle._tick(abort)
                    data = source.read(min(left, bundle.CHUNK))
                    require(bool(data), ERROR_DESCRIPTOR)
                    target.write(data)
                    digest.update(data)
                    left -= len(data)
                    require(target.tell() <= bundle.MAX_ARCHIVE)
            require('sha256:' + digest.hexdigest() == descriptor['digest'], ERROR_DESCRIPTOR)
            target.write(bytes(-size % 512))
        raw = json.dumps([{'Config': config_out, 'RepoTags': [bundle.TAG], 'Layers': layer_out}],
                         separators=(',', ':')).encode()
        header('manifest.json', len(raw))
        target.write(raw)
        target.write(bytes(-len(raw) % 512 + 1024))
        require(target.tell() <= bundle.MAX_ARCHIVE)
        target.flush()
        bundle.validate_archive(target, arch, image_id, abort=abort)
