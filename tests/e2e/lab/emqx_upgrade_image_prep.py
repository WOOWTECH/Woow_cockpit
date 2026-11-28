#!/usr/bin/env python3
"""EMQX upgrade test (emqx_upgrade_after_import.py): the pinned OLDER open-source EMQX image (docker.io/emqx/emqx:5.8.8,
Apache-2.0) into dev-d's owner store, while dev-d keeps network none (the version the package pins today, 5.8.9, is there
already). Host side; only ~/.woowbk-lab/bin/labpodman (the separate LAB store), never the host's own podman store.

  python3 -B -I tests/e2e/lab/emqx_upgrade_image_prep.py                plan: the pinned target and the steps (no network,
                                                                        no lab access)
  python3 -B -I tests/e2e/lab/emqx_upgrade_image_prep.py --pull         THE ONLY NETWORK STEP: labpodman pull of the pinned
                                                                        tag@index-digest (linux/amd64) into the LAB store;
                                                                        the image ID must be the pinned amd64 config digest
  HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock .../heavy.sh \\
      python3 -B -I tests/e2e/lab/emqx_upgrade_image_prep.py --stream   LAB store -> dev-d's owner store under dev-d's lock:
                                                                        `labpodman save --format docker-archive <image ID>`
                                                                        piped into `woowbk-owner podman load` inside dev-d,
                                                                        then `podman tag <ID> docker.io/emqx/emqx:5.8.8`;
                                                                        checks ID, tag, digest, `podman image exists
                                                                        <tag>@<digest>`; writes the private receipt
                                                                        ~/.woowbk-lab/run/emqx_upgrade_image_prep.json that
                                                                        the run's lease binds (its SHA-256 and the digest)
  python3 -B -I tests/e2e/lab/emqx_upgrade_image_prep.py --verify       read-only: dev-d's copy against the receipt
  HEAVY_FREE=/tmp/woowbk-dev-d-mutation.lock .../heavy.sh \\
      python3 -B -I tests/e2e/lab/emqx_upgrade_image_prep.py --remove   after the test: the tag (and so the image) out of
                                                                        dev-d again, only while no container uses it
  ... --remove-lab                                                      the image out of the LAB store (no container uses it)

A `podman load` writes a new manifest (the image ID stays: it is the config digest), so dev-d's digest differs from the
registry's; the run pins dev-d's digest in its throwaway package copy, exactly as deploy-batch1.sh did for 5.8.9. Every
step prints one JSON line; exit 0 ok, 1 a check failed, 2 refused before anything changed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
LAB = Path.home() / '.woowbk-lab'
LP = LAB / 'bin' / 'labpodman'
DEVICE = 'woowbk-dev-d'
OWNER = '/usr/local/bin/woowbk-owner'
LOCK = '/tmp/woowbk-dev-d-mutation.lock'
RECEIPT = LAB / 'run' / 'emqx_upgrade_image_prep.json'
TAG = 'docker.io/emqx/emqx:5.8.8'          # open-source edition, Apache-2.0 (image labels), OTP 26.2.5.14-1 like 5.8.9
INDEX_DIGEST = 'sha256:4593b6e30196754779fa14483332cb0be56c233f1c8a387b1308bec4337c0144'
AMD64_MANIFEST = 'sha256:2bbadcd6ebdf1e2d032bdd8149c9615867ed25f32b1a09ec5bd92ddcf159e1aa'
IMAGE_ID = '5a96e36027e748efeb6fef8d05ea6d9b3036810540fd7286227b2e0f951a447f'
PULL_REF = TAG + '@' + INDEX_DIGEST
COMPRESSED_BYTES = 108_392_173            # 6 gzip layers of the amd64 manifest (103.4 MiB), read 2026-11-28
FLOOR = 13 * 1024 ** 3                    # the team keeps >= 12 GiB free on the host (+1 GiB margin)
PEAK = 3 * 1024 ** 3                      # pull + save | load (podman copies stdin, keeps blob copies): generous
WRAPPER_MARK = '--root "$HOME/.woowbk-lab/storage"'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv, *, timeout=600, data=None):
    proc = subprocess.run(argv, input=data, stdin=None if data is not None else subprocess.DEVNULL,
                          capture_output=True, timeout=timeout)
    return proc.returncode, proc.stdout


class Host:
    """The only side effects of this helper (replaced by the offline tests)."""

    run = staticmethod(run)

    @staticmethod
    def free():
        return shutil.disk_usage(str(LAB)).free

    @staticmethod
    def wrapper_ok():
        try:
            text = LP.read_text(encoding='utf-8')
        except OSError:
            return False
        return LP.is_file() and not LP.is_symlink() and WRAPPER_MARK in text and 'exec podman' in text

    @staticmethod
    def stream(save_argv, load_argv, timeout=1800):
        """save | load with the archive's SHA-256 and size counted on the way; (save rc, load rc, sha256, bytes)."""
        digest, size = hashlib.sha256(), 0
        save = subprocess.Popen(save_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        load = subprocess.Popen(load_argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + timeout
        try:
            for chunk in iter(lambda: save.stdout.read(1 << 20), b''):
                digest.update(chunk)
                size += len(chunk)
                load.stdin.write(chunk)
                if time.monotonic() > deadline:
                    raise subprocess.TimeoutExpired(save_argv, timeout)
            load.stdin.close()
            return save.wait(timeout=300), load.wait(timeout=900), digest.hexdigest(), size
        except BaseException:
            for proc in (save, load):
                proc.kill()
                proc.wait()
            raise

    @staticmethod
    def lock():
        guard = _load('dev_d_guard')
        fd, _waited = guard.acquire(timeout=600)
        return fd

    @staticmethod
    def unlock(fd):
        os.close(fd)

    @staticmethod
    def isolated():
        guard = _load('dev_d_guard')
        try:
            guard.verify_isolation(HERE / 'owner.sh')
            return True
        except guard.GuardError:
            return False


def lp(*args):
    return [str(LP), *args]


def owner(*args):
    return lp('exec', '-i', DEVICE, OWNER, *args)


def out(host, argv, timeout=600):
    rc, data = host.run(argv, timeout=timeout)
    return rc, data.decode('utf-8', 'replace').strip()


def lab_image(host):
    """(image ID, os/arch) of the pinned image in the LAB store, or (None, None): by the pulled tag@index-digest, else by
    the pinned image ID (the config digest: the same content whatever name it carries)."""
    for ref in (PULL_REF, IMAGE_ID):
        rc, text = out(host, lp('image', 'inspect', '--format', '{{.Id}}|{{.Os}}|{{.Architecture}}', ref), timeout=120)
        parts = text.split('|') if rc == 0 else []
        if len(parts) == 3:
            return parts[0], parts[1] + '/' + parts[2]
    return None, None


def device_image(host):
    """dev-d's copy: {present, id, digest, tags, exists_by_digest}."""
    rc, text = out(host, owner('podman', 'image', 'inspect', '--format', '{{.Id}}|{{.Digest}}|{{json .RepoTags}}', TAG),
                   timeout=120)
    parts = text.split('|', 2) if rc == 0 else []
    if len(parts) != 3:
        return {'present': False}
    try:
        tags = sorted(json.loads(parts[2]) or [])
    except ValueError:
        tags = []
    found = {'present': True, 'id': parts[0], 'digest': parts[1], 'tags': tags}
    found['exists_by_digest'] = DIGEST.fullmatch(parts[1]) is not None and host.run(
        owner('podman', 'image', 'exists', TAG + '@' + parts[1]), timeout=120)[0] == 0
    return found


def device_ok(found):
    return (found.get('present') is True and found.get('id') == IMAGE_ID and TAG in found.get('tags', [])
            and DIGEST.fullmatch(str(found.get('digest'))) is not None and found.get('exists_by_digest') is True)


def save_receipt(doc, path=RECEIPT):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.tmp')
    if os.path.lexists(temp):
        temp.unlink()
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, sort_keys=True)
        handle.write('\n')
    os.replace(temp, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan():
    return {'stage': 'emqx_upgrade_image_plan', 'tag': TAG, 'index_digest': INDEX_DIGEST, 'amd64_manifest': AMD64_MANIFEST,
            'image_id': IMAGE_ID, 'pull_ref': PULL_REF, 'compressed_bytes': COMPRESSED_BYTES, 'store': 'lab',
            'steps': ['--pull (network, lab store)', 'HEAVY_FREE=' + LOCK + ' heavy.sh ... --stream (dev-d lock)',
                      '--verify', 'after the test: --remove (and --remove-lab)'], 'device_access': False}


def pull(host):
    if not host.wrapper_ok():
        return 2, {'stage': 'emqx_upgrade_image_pull', 'ok': False, 'reason': 'labpodman_wrapper'}
    if host.free() - PEAK < FLOOR:
        return 2, {'stage': 'emqx_upgrade_image_pull', 'ok': False, 'reason': 'host_disk'}
    have, platform = lab_image(host)
    if have != IMAGE_ID:
        rc, _ = host.run(lp('pull', '--quiet', '--platform', 'linux/amd64', PULL_REF), timeout=1800)
        if rc != 0:
            return 1, {'stage': 'emqx_upgrade_image_pull', 'ok': False, 'reason': 'pull_failed'}
        have, platform = lab_image(host)
    ok = have == IMAGE_ID and platform == 'linux/amd64'
    return (0 if ok else 1), {'stage': 'emqx_upgrade_image_pull', 'ok': ok, 'image_id_matches': have == IMAGE_ID,
                              'platform': (platform or 'none').replace('/', '_')}


def seat_ok(environ):
    return environ.get('HEAVY_FREE') == LOCK


def stream(host, environ=os.environ, receipt=RECEIPT):
    stage = 'emqx_upgrade_image_stream'
    if not seat_ok(environ) or not host.wrapper_ok():
        return 2, {'stage': stage, 'ok': False, 'reason': 'heavy_seat_or_wrapper'}
    if host.free() - PEAK < FLOOR:
        return 2, {'stage': stage, 'ok': False, 'reason': 'host_disk'}
    have, platform = lab_image(host)
    if have != IMAGE_ID or platform != 'linux/amd64':
        return 2, {'stage': stage, 'ok': False, 'reason': 'not_in_lab_store'}
    fd = host.lock()
    try:
        if not host.isolated():
            return 2, {'stage': stage, 'ok': False, 'reason': 'dev_d_isolation'}
        found = device_image(host)
        streamed = None
        if not device_ok(found):
            if found.get('present') and found.get('id') != IMAGE_ID:
                return 1, {'stage': stage, 'ok': False, 'reason': 'tag_taken_by_another_image'}
            try:
                save_rc, load_rc, archive_sha, size = host.stream(lp('save', '--format', 'docker-archive', IMAGE_ID),
                                                                 owner('podman', 'load'))
            except (OSError, subprocess.TimeoutExpired):
                save_rc = load_rc = None
            if save_rc != 0 or load_rc != 0:
                return 1, {'stage': stage, 'ok': False, 'reason': 'save_or_load_failed'}
            streamed = {'archive_sha256': archive_sha, 'archive_bytes': size}
            rc, text = out(host, owner('podman', 'image', 'inspect', '--format', '{{.Id}}', IMAGE_ID), timeout=120)
            if rc != 0 or text != IMAGE_ID:
                return 1, {'stage': stage, 'ok': False, 'reason': 'loaded_id_differs'}
            if host.run(owner('podman', 'tag', IMAGE_ID, TAG), timeout=120)[0] != 0:
                return 1, {'stage': stage, 'ok': False, 'reason': 'tag_failed'}
            found = device_image(host)
        if not device_ok(found):
            return 1, {'stage': stage, 'ok': False, 'reason': 'device_copy_incomplete'}
        doc = {'schema': 1, 'device': DEVICE, 'image': TAG, 'index_digest': INDEX_DIGEST, 'amd64_manifest': AMD64_MANIFEST,
               'image_id': IMAGE_ID, 'device_digest': found['digest'], 'loaded': True, 'removed': False,
               'streamed': streamed, 'created': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
        digest = save_receipt(doc, receipt)
        return 0, {'stage': stage, 'ok': True, 'device_digest': found['digest'], 'receipt_sha256': digest,
                   'loaded_now': streamed is not None}
    finally:
        host.unlock(fd)


def verify(host, receipt=RECEIPT):
    try:
        doc = json.loads(Path(receipt).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return 2, {'stage': 'emqx_upgrade_image_verify', 'ok': False, 'reason': 'no_receipt'}
    found = device_image(host)
    ok = device_ok(found) and found.get('digest') == doc.get('device_digest') and doc.get('image_id') == IMAGE_ID
    return (0 if ok else 1), {'stage': 'emqx_upgrade_image_verify', 'ok': ok,
                              'device_digest_matches': found.get('digest') == doc.get('device_digest')}


def remove(host, environ=os.environ, receipt=RECEIPT):
    stage = 'emqx_upgrade_image_remove'
    if not seat_ok(environ) or not host.wrapper_ok():
        return 2, {'stage': stage, 'ok': False, 'reason': 'heavy_seat_or_wrapper'}
    fd = host.lock()
    try:
        if not host.isolated():
            return 2, {'stage': stage, 'ok': False, 'reason': 'dev_d_isolation'}
        found = device_image(host)
        if found.get('present') and found.get('id') != IMAGE_ID:
            return 1, {'stage': stage, 'ok': False, 'reason': 'tag_taken_by_another_image'}
        if found.get('present'):
            rc, users = out(host, owner('podman', 'ps', '-a', '--filter', 'ancestor=' + IMAGE_ID, '--format', '{{.Names}}'),
                            timeout=120)
            if rc != 0 or users:
                return 1, {'stage': stage, 'ok': False, 'reason': 'image_in_use'}
            if host.run(owner('podman', 'rmi', TAG), timeout=300)[0] != 0:
                return 1, {'stage': stage, 'ok': False, 'reason': 'rmi_failed'}
        gone = host.run(owner('podman', 'image', 'exists', IMAGE_ID), timeout=120)[0] == 1
        if gone and os.path.exists(receipt):
            doc = json.loads(Path(receipt).read_text(encoding='utf-8'))
            save_receipt(dict(doc, removed=True, removed_at=time.strftime('%Y-%m-%dT%H:%M:%S%z')), receipt)
        return (0 if gone else 1), {'stage': stage, 'ok': gone}
    finally:
        host.unlock(fd)


def remove_lab(host):
    stage = 'emqx_upgrade_image_remove_lab'
    if not host.wrapper_ok():
        return 2, {'stage': stage, 'ok': False, 'reason': 'labpodman_wrapper'}
    rc, users = out(host, lp('ps', '-a', '--filter', 'ancestor=' + IMAGE_ID, '--format', '{{.Names}}'), timeout=120)
    if rc != 0 or users:
        return 1, {'stage': stage, 'ok': False, 'reason': 'image_in_use'}
    host.run(lp('rmi', IMAGE_ID), timeout=300)
    gone = host.run(lp('image', 'exists', IMAGE_ID), timeout=120)[0] == 1
    return (0 if gone else 1), {'stage': stage, 'ok': gone}


def main(argv=None, host=Host):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    group = parser.add_mutually_exclusive_group()
    for flag in ('--pull', '--stream', '--verify', '--remove', '--remove-lab'):
        group.add_argument(flag, action='store_true')
    args = parser.parse_args(argv)
    steps = {'pull': pull, 'stream': stream, 'verify': verify, 'remove': remove, 'remove_lab': remove_lab}
    chosen = next((name for name in steps if getattr(args, name)), None)
    try:
        code, doc = steps[chosen](host) if chosen else (0, plan())
    except Exception as error:   # noqa: BLE001 - one fixed line, never a value
        code, doc = 1, {'stage': 'emqx_upgrade_image_' + str(chosen), 'ok': False, 'reason': type(error).__name__}
    print(json.dumps(doc, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
