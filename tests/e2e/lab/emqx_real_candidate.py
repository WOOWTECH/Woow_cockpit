"""Opt-in internal EMQX caller for verified encrypted cold HA fixtures.

No CLI, installer or driver registration. The caller owns isolation, private
staging, secret registration and workload authorization. Never a public import.
"""
import copy
import re

from woowbackup import hacommon, ha_emqx, ha_n8n, hasecuretar, tempctr

from ha_real_fixture import require, source_binding


def build_verified_candidate(work, app, adapter, target, backup, staging, job_id, *,
                             expected_sha256, keys):
    """Build/package only; keys and archive bindings live in this call's memory.

    `target` must describe the reviewed disposable target with a pinned local
    image ID. Existing work hooks/budget are retained on a shallow copy; source
    callbacks on the caller's work are never replaced. No plaintext source
    archive is saved. Product staging/output can contain secrets and remains
    the caller's private, bounded responsibility.
    """
    require(app.id == 'emqx', 'wrong-app-binding')
    require(isinstance(keys, hasecuretar.Keys), 'invalid-private-key-input')
    require(isinstance(expected_sha256, str) and
            re.fullmatch(r'[0-9a-f]{64}', expected_sha256), 'invalid-source-digest')
    require(isinstance(target.image, str) and
            re.fullmatch(r'sha256:[0-9a-f]{64}', target.image), 'pinned-target-required')
    bound = copy.copy(work)
    version = hacommon.semver(hacommon.image_labels(bound, app, target.image).get(
        'org.opencontainers.image.version'))
    require(version is not None, 'unknown-target-version')
    # Digest, cold state, version, strict archive and v3 checks precede temp roles.
    with source_binding(backup, app.id, version, expected_sha256, keys=keys,
                        required_encryption='v3') as source:
        for name, function in source.items():
            setattr(bound, name, function)
        tmp = tempctr.TempObjects(bound.runner(app), job_id, memory='768m', pids=512, cpus='1')
        try:
            built = ha_emqx._build_candidate(bound, app, tmp, target, staging, version=version)
            log_root = ha_n8n.volume_root(bound, app, target.log_volume)
            return ha_emqx._package_candidate(
                bound, tmp, target, staging, staging / 'candidate-output', built[3],
                ids=adapter.owner_ids(), log_root=log_root)
        finally:
            if tmp.cleanup():
                raise RuntimeError('real-fixture temporary objects remain')
