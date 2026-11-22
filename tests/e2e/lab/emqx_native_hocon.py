"""Opt-in pinned, networkless native parser; no broker or host data mounts."""
import pathlib
import tempfile
from emqx_semantic_readers import MAX_INPUT, MAX_OUTPUT, SemanticRefused

from emqx_native_runtime import IMAGE, run_native

SCRIPT = pathlib.Path(__file__).with_name('emqx_hocon_native.escript')


def native_hocon(raw):
    return _native_hocon(raw, SCRIPT)


def native_hocon_context(raw):
    """Explicit original-AST occurrence adapter; strict adapter is unchanged."""
    return _native_hocon(raw, SCRIPT.with_name('emqx_hocon_context_native.escript'))


def native_hocon_http_context(raw):
    """Separate fixed HTTP-body profile; never render or issue HTTP requests."""
    return _native_hocon(raw, SCRIPT.with_name('emqx_hocon_context_native.escript'),
                         args=('--http-body',))


def _native_hocon(raw, script, args=()):
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
            (root / 'parser.escript').write_bytes(script.read_bytes())
            # Output is a bounded private regular file, never a pipe accumulated
            # without a limit. Container itself has an output/file size limit.
            with tempfile.TemporaryFile() as output:
                code = run_native(directory, 'parser.escript', args=args, output=output)
                output.seek(0)
                encoded = output.read(MAX_OUTPUT + 1)
                if code or len(encoded) > MAX_OUTPUT:
                    raise ValueError()
                return encoded
    except Exception:
        raise SemanticRefused() from None


def native_hocon_diagnostic(raw):
    """Fixed native parser phase only; never a semantic capture or gate override."""
    import json
    try:
        if type(raw) is not bytes or len(raw)>MAX_INPUT:
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='emqx-hocon-private-') as directory:
            root=pathlib.Path(directory)
            (root/'source.hocon').write_bytes(raw)
            (root/'source.hocon').chmod(0o600)
            (root/'parser.escript').write_bytes(SCRIPT.read_bytes())
            with tempfile.TemporaryFile() as output:
                status=run_native(directory,'parser.escript',args=('--diagnose',),output=output)
                output.seek(0)
                data=output.read(1025)
            doc=json.loads(data)
            if (status!=2 or len(data)>1024 or type(doc) is not dict
                or set(doc)!={'contract','phase','result'}
                or doc['contract']!='emqx-hocon-diagnostic-v1'
                or doc['result']!='refused'
                or doc['phase'] not in ('input','tokenize','references','parse','syntax',
                                        'transform','encode','file_dependency','reference')):
                raise ValueError()
            return doc['phase']
    except Exception:
        raise SemanticRefused() from None
