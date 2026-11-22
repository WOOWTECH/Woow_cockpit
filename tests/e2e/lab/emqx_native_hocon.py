"""Opt-in pinned, networkless native parser; no broker or host data mounts."""
import pathlib
import subprocess
import tempfile
from emqx_semantic_readers import MAX_INPUT, MAX_OUTPUT, SemanticRefused

IMAGE = 'sha256:3f60addfad2bfc6c09400aa48cfbc1b2b2aab04fb6a64d6392c016e02d7fb57b'
SCRIPT = pathlib.Path(__file__).with_name('emqx_hocon_native.escript')


def native_hocon(raw):
    """Owner-selected code only. Bounded per-file input/output, 15s wall limit.

    Requires cached pinned image and rootless podman; never pulls an image.
    Temp input is private and deleted on success/failure. No private diagnostics.
    """
    try:
        if type(raw) is not bytes or len(raw) > MAX_INPUT:
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='emqx-hocon-private-') as directory:
            root = pathlib.Path(directory)
            (root / 'source.hocon').write_bytes(raw)
            (root / 'source.hocon').chmod(0o600)
            (root / 'parser.escript').write_bytes(SCRIPT.read_bytes())
            # Output is a bounded private regular file, never a pipe accumulated
            # without a limit. Container itself has an output/file size limit.
            with tempfile.TemporaryFile() as output:
                result = subprocess.run([
                    'podman', 'run', '--rm', '--pull=never', '--network=none',
                    '--read-only', '--image-volume=ignore', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                    '--memory=256m', '--memory-swap=256m', '--pids-limit=64',
                    '--ulimit=cpu=8:8', '--ulimit=fsize=1048576:1048576',
                    '--log-driver=none', '--timeout=12', '--stop-timeout=1', '--userns=keep-id',
                    '-v', directory + ':/input:ro', '--entrypoint',
                    '/opt/emqx/erts-14.2.5.11/bin/escript', IMAGE,
                    '/input/parser.escript'], stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.DEVNULL, timeout=15, check=False,
                    env={'PATH': '/usr/bin:/bin', 'HOME': str(pathlib.Path.home()),
                         'XDG_RUNTIME_DIR': '/run/user/' + str(__import__('os').getuid())})
                output.seek(0)
                encoded = output.read(MAX_OUTPUT + 1)
                if result.returncode or len(encoded) > MAX_OUTPUT:
                    raise ValueError()
                return encoded
    except Exception:
        raise SemanticRefused() from None
