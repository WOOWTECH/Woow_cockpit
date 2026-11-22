"""Opt-in internal EMQX caller for verified encrypted cold HA fixtures.

No CLI, installer or driver registration. The caller owns isolation, private
staging, secret registration and workload authorization. Never a public import.
"""
import copy
import re
import os
from pathlib import Path
import shutil
import stat
import tempfile
import sys
from emqx_candidate_stage import mark, current

from woowbackup import archive, hacommon, ha_emqx, ha_n8n, hasecuretar, tempctr

from ha_real_fixture import require, source_binding


def build_verified_candidate(work, app, adapter, target, backup, staging, job_id, *,
                             expected_sha256, keys, private_capture=None):
    """Build/package only; keys and archive bindings live in this call's memory.

    `target` must describe the reviewed disposable target with a pinned local
    image ID. Existing work hooks/budget are retained on a shallow copy; source
    callbacks on the caller's work are never replaced. No plaintext source
    archive is saved. Product staging/output can contain secrets and remains
    the caller's private, bounded responsibility.
    """
    mark('input_contract')
    require(app.id == 'emqx', 'wrong-app-binding')
    require(isinstance(keys, hasecuretar.Keys), 'invalid-private-key-input')
    require(isinstance(expected_sha256, str) and
            re.fullmatch(r'[0-9a-f]{64}', expected_sha256), 'invalid-source-digest')
    require(isinstance(target.image, str) and
            re.fullmatch(r'sha256:[0-9a-f]{64}', target.image), 'pinned-target-required')
    require(isinstance(job_id, str) and tempctr.JOB_RE.fullmatch(job_id), 'invalid-job-id')
    volumes = (target.data_volume, target.log_volume)
    require(all(isinstance(v, str) and archive.VOLUME_RE.fullmatch(v) for v in volumes)
            and volumes[0] != volumes[1], 'invalid-target-volumes')
    staging = Path(staging).absolute()
    # Reject symlink components, including ancestors; do not chmod caller paths.
    for component in (staging, *staging.parents):
        require(not component.is_symlink(), 'unsafe-staging')
    info = staging.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'unsafe-staging')
    bound = copy.copy(work)
    mark('image_version')
    version = hacommon.semver(hacommon.image_labels(bound, app, target.image).get(
        'org.opencontainers.image.version'))
    require(version is not None, 'unknown-target-version')
    private = None
    try:
        # Keep final source validation and role cleanup inside the failure scope.
        mark('archive_verify')
        with source_binding(backup, app.id, version, expected_sha256, keys=keys,
                            required_encryption='v3') as source:
            mark('source_reuse')
            if private_capture is not None:
                source = private_capture(source)
            for name, function in source.items():
                setattr(bound, name, function)
            private = Path(tempfile.mkdtemp(prefix=job_id + '-', dir=staging))
            mark('temp_objects')
            tmp = tempctr.TempObjects(bound.runner(app), job_id, memory='768m', pids=512, cpus='1')
            try:
                mark('product_build')
                built = ha_emqx._build_candidate(bound, app, tmp, target, private, version=version)
                mark('product_package')
                log_root = ha_n8n.volume_root(bound, app, target.log_volume)
                result = ha_emqx._package_candidate(
                    bound, tmp, target, private, private / 'candidate-output', built[3],
                    ids=adapter.owner_ids(), log_root=log_root)
            finally:
                failed=sys.exc_info()[0] is not None
                previous=current();mark('temp_cleanup')
                if tmp.cleanup():
                    raise RuntimeError('real-fixture temporary objects remain')
                if failed:mark(previous)
            mark('archive_final')
        return result
    except BaseException:
        # Only remove our exclusively created directory, never arbitrary staging.
        if private is not None:
            try:
                shutil.rmtree(private)
            except OSError:
                mark('private_cleanup')
                raise RuntimeError('real-fixture private cleanup failed') from None
        raise
