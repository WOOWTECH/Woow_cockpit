"""Pinned rootless native-tool runner. Only invocation-owned mounts/containers."""
import os
import pathlib
import subprocess
import tempfile
import uuid

from emqx_semantic_readers import SemanticRefused

IMAGE = 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b'
# Wall-clock bounds only (CPU stays ulimit cpu=10s). At host load ~27 on 4 CPUs
# (2026-11-23) the old 5/15/20s bounds refused unchanged inputs: a native fixture
# failed 3 of 4 runs and a real payload-history phase refused after passing before.
PODMAN_SECONDS = 30
WALL_SECONDS = 60


def run_native(directory, script, args=(), *, writable_directory=None, output):
    """Trusted local scripts only; writable mount is for synthetic/owner files.

    No inventory, volume enumeration or production mounts. Caller supplies an
    already private directory and bounded regular output file. No implicit image
    volumes; cleanup targets only a fresh random name used by this invocation.
    """
    name = 'emqx-native-' + uuid.uuid4().hex
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(pathlib.Path.home()),
           'XDG_RUNTIME_DIR': '/run/user/' + str(os.getuid())}
    command = ['podman', '--runtime=crun']
    created = False
    try:
        # Exact two-field metadata only; never container/volume inventory.
        with tempfile.TemporaryFile() as info:
            checked = subprocess.run(command + ['info', '--format',
                '{{.Host.Security.Rootless}} {{.Host.OCIRuntime.Name}}'],
                stdin=subprocess.DEVNULL, stdout=info, stderr=subprocess.DEVNULL,
                timeout=PODMAN_SECONDS, check=False, env=env)
            info.seek(0)
            if checked.returncode or info.read(64).strip() != b'true crun':
                raise ValueError()
        mounts = ['-v', str(directory) + ':/input:ro']
        if writable_directory is not None:
            mounts += ['-v', str(writable_directory) + ':/work:rw']
        created = True
        result = subprocess.run(command + [
            'run', '--name', name, '--rm', '--pull=never', '--image-volume=ignore',
            '--network=none', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--memory=256m', '--memory-swap=256m',
            '--pids-limit=64', '--ulimit=cpu=10:10', '--ulimit=fsize=8388608:8388608',
            '--log-driver=none', '--timeout=' + str(WALL_SECONDS), '--stop-timeout=1', '--userns=keep-id', '--user=' + str(os.getuid()) + ':' + str(os.getgid()),
            '-e', 'EXPORT_OWNER_UID=' + str(os.getuid()),
            '-e', 'ERL_CRASH_DUMP=/dev/null', *mounts,
            '--entrypoint', '/opt/emqx/erts-14.2.5.11/bin/escript', IMAGE,
            '/input/' + script, *args], stdin=subprocess.DEVNULL, stdout=output,
            stderr=subprocess.DEVNULL, timeout=WALL_SECONDS + 15, check=False, env=env)
        return result.returncode
    except Exception:
        raise SemanticRefused() from None
    finally:
        if created:
            try:
                cleaned = subprocess.run(command + ['rm', '--force', '--ignore', name],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=PODMAN_SECONDS, check=False, env=env)
                absent = subprocess.run(command + ['container', 'exists', name],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=PODMAN_SECONDS, check=False, env=env)
                if cleaned.returncode or absent.returncode != 1:
                    raise ValueError()
            except Exception:
                raise SemanticRefused() from None
