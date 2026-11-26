#!/usr/bin/env python3
"""Package a pre-exported, release-reviewed PG16 Docker archive. No pulls or Podman invocation.

Get --image-id from the trusted platform manifest of pg16_bundle.PINNED_REF, not from the input archive itself.
Publish the printed manifest_sha256 in authenticated release metadata, separately from the bundle.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location('pg16_bundle', Path(__file__).resolve().parents[1]
                                           / 'backup-engine/woowbackup/pg16_bundle.py')
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)
OCI_SPEC = importlib.util.spec_from_file_location('pg16_oci', Path(__file__).resolve().parents[1]
                                               / 'backup-engine/woowbackup/pg16_oci.py')
oci = importlib.util.module_from_spec(OCI_SPEC)
OCI_SPEC.loader.exec_module(oci)


def package(archive, arch, image_id, output, *, input_format='docker-archive', abort=None):
    if input_format not in ('docker-archive', 'oci-archive'):
        raise bundle.BundleError('Unsupported PG16 package input format.')
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise bundle.BundleError('Output already exists; choose a new release directory.')
    stage = Path(tempfile.mkdtemp(prefix='.pg16-package-', dir=output.parent))
    try:
        with bundle._directory(Path(archive).absolute().parent) as dfd, \
                bundle._file(dfd, Path(archive).name) as source, open(stage / bundle.ARCHIVE, 'x+b') as target:
            if input_format == 'oci-archive':
                oci.convert_archive(source, target, bundle, arch, image_id, abort=abort)
                sha256, size = bundle.copy_hash(target, abort=abort)
            else:
                sha256, size = bundle.copy_hash(source, target, abort=abort)
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o644)
        with open(stage / bundle.ARCHIVE, 'rb') as source:
            bundle.validate_archive(source, arch, image_id, abort=abort)
        raw = bundle.manifest_bytes(arch, image_id, sha256, size)
        bundle._write(stage / 'manifest.json', raw)
        os.chmod(stage, 0o755)
        os.rename(stage, output)
        return {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'architecture': arch,
                'image_id': image_id, 'archive_size': size, 'path': str(output)}
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--input-format', choices=('docker-archive', 'oci-archive'), default='docker-archive',
                        help='Use oci-archive for Podman exports; Docker archives still refuse every link.')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--image-id', required=True, help='sha256 config ID from trusted platform manifest.')
    parser.add_argument('--output', type=Path, required=True, help='New directory, outside the Git checkout.')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(package(args.archive, args.architecture, args.image_id, args.output,
                                 input_format=args.input_format), indent=2))
    except (ValueError, OSError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
