"""Opt-in pinned, networkless native parser; no broker or host data mounts."""
import pathlib
import tempfile
from emqx_semantic_readers import MAX_INPUT, MAX_OUTPUT, SemanticRefused

from emqx_native_runtime import IMAGE, run_native

SCRIPT = pathlib.Path(__file__).with_name('emqx_hocon_native.escript')


def native_hocon(raw):
    """Owner-selected code only. Bounded per-file input/output, 20s client wall limit.

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
                code = run_native(directory, 'parser.escript', output=output)
                output.seek(0)
                encoded = output.read(MAX_OUTPUT + 1)
                if code or len(encoded) > MAX_OUTPUT:
                    raise ValueError()
                return encoded
    except Exception:
        raise SemanticRefused() from None
