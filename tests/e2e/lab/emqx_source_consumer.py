"""Private, bounded source consumer. No filesystem, environment or runtime access.

Supported source: strict bounded HA tar with addon JSON, cookie, node name and
explicitly opted-in native HOCON. Mnesia and all other members remain gated.
This intentionally cannot attest a real EMQX broker source yet.
"""
import contextlib
import io
import json
import tarfile

from woowbackup import habackup, hasecuretar
from emqx_private_boundary import Registry, PrivateFailure, SOURCES, MAX_VALUE, MAX_TOTAL
from emqx_real_candidate import build_verified_candidate
from emqx_semantic_readers import read_hocon, MAX_INPUT, SemanticRefused

MAX_STREAM = 8 * 1024 * 1024


def json_values(raw):
    """Read every string leaf; reject references, duplicate keys and complex input."""
    if not isinstance(raw, bytes) or len(raw) > MAX_VALUE:
        refuse()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PrivateFailure('private-source-refused')
            result[key] = value
        return result
    doc = json.loads(raw, object_pairs_hook=pairs,
                     parse_constant=lambda _: refuse())
    pending, values, count = [(doc, 0)], [], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 16 or count > 4096:
            refuse()
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, str):
            # No implicit file/env/vault/URL dereference support.
            if any(token in value for token in ('${', 'file:', 'env:', 'vault:', '://')):
                refuse()
            if value:
                values.append(value.encode('utf-8'))
        elif value is not None and not isinstance(value, (bool, int, float)):
            refuse()
    return values


def refuse():
    raise PrivateFailure('private-source-refused')


class Capture:
    """Consume once to EOF, validate, register, seal, then replay identical bytes.

    Target inputs are exact category -> JSON bytes snapshots from an owner;
    no missing categories or implicit empty acknowledgements are accepted.
    JSON readers are for self-contained data only, never HOCON or Mnesia.
    """
    def __init__(self, password, target_documents, *, hocon_parser=None, spool_directory=None):
        self._hocon_parser = hocon_parser
        self._spool_directory = spool_directory
        self._stack = None
        if not isinstance(password, str) or not password:
            refuse()
        self.keys = hasecuretar.Keys(password)
        self.registry = Registry()
        self.registry.register('backup-key', [password.encode('utf-8')])
        expected = SOURCES - {'backup-key', 'source-options', 'source-cookie'}
        if not isinstance(target_documents, dict) or set(target_documents) != expected:
            refuse()
        total = 0
        for name in sorted(expected):
            raw = target_documents[name]
            if not isinstance(raw, bytes) or len(raw) > MAX_VALUE:
                refuse()
            total += len(raw)
            if total > MAX_TOTAL:
                refuse()
            self.registry.register(name, json_values(raw))
        self._used = False

    def __enter__(self):
        self._stack = contextlib.ExitStack()
        return self

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)

    def __repr__(self):
        return '<EMQX private capture>'

    def __call__(self, source):
        if self._used:
            refuse()
        self._used = True
        slug = source['addon_member']('woow-emqx')
        with source['open'](slug) as stream:
            if self._spool_directory is not None:
                if self._stack is None:
                    refuse()
                from emqx_private_spool import capture
                captured, _, _ = self._stack.enter_context(
                    capture(stream, self._spool_directory))
            else:
                chunks, size = [], 0
                while True:
                    chunk = stream.read(min(65536, MAX_STREAM + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_STREAM:
                        refuse()
                    chunks.append(chunk)
                if hasattr(stream, 'finish'):
                    stream.finish()
                captured = io.BytesIO(b''.join(chunks))
        report = habackup.Report()
        for entry in habackup.iter_entries(captured, report=report, addon=True):
            if entry.kind not in ('dir', 'file'):
                refuse()
        if not report.complete:
            refuse()
        captured.seek(0)
        found = set()
        source_options = []
        with tarfile.open(fileobj=captured, mode='r:*') as archive:
            for entry in archive:
                name = entry.name.removeprefix('./')
                if entry.isdir():
                    continue
                is_hocon = name in ('data/emqx/data/configs/cluster.hocon',
                                    'data/emqx/etc/emqx.conf',
                                    'data/emqx/etc/base.hocon')
                limit = MAX_INPUT if is_hocon else MAX_VALUE
                if name.startswith('data/emqx/data/mnesia/'):
                    raise PrivateFailure('private-source-native-mnesia-unsupported')
                if not entry.isfile() or entry.size > limit or name in found:
                    refuse()
                found.add(name)
                raw = archive.extractfile(entry).read(limit + 1)
                if name == 'addon.json':
                    source_options.extend(json_values(raw))
                elif name == 'data/emqx/node.cookie':
                    if not raw.strip():
                        refuse()
                    self.registry.register('source-cookie', [raw, raw.strip()])
                elif name == 'data/emqx/node.name':
                    if not raw.startswith(b'emqx@'):
                        refuse()
                elif is_hocon:
                    if self._hocon_parser is None:
                        raise PrivateFailure('private-source-format-unsupported')
                    try:
                        source_options.extend(read_hocon(raw, self._hocon_parser).values)
                    except SemanticRefused:
                        raise PrivateFailure('private-source-hocon-unsupported') from None
                else:
                    raise PrivateFailure('private-source-format-unsupported')
        if not {'addon.json', 'data/emqx/node.cookie', 'data/emqx/node.name'} <= found:
            refuse()
        self.registry.register('source-options', source_options)
        self.registry.seal()
        @contextlib.contextmanager
        def replay(requested):
            if requested != slug:
                refuse()
            captured.seek(0)
            yield captured
        return dict(source, open=replay)


def build_consumed_candidate(*args, password, target_documents, hocon_parser=None, spool_directory=None, **kwargs):
    """Callable private candidate path; fixed errors only, no secret diagnostics."""
    try:
        if 'keys' in kwargs or 'private_capture' in kwargs:
            refuse()
        capture = Capture(password, target_documents, hocon_parser=hocon_parser,
                          spool_directory=spool_directory)
        import copy
        work = copy.copy(args[0])
        work.log = lambda *a, **k: None
        with capture:
            return build_verified_candidate(work, *args[1:], keys=capture.keys,
                                            private_capture=capture, **kwargs)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('candidate-cancelled') from None
    except Exception:
        raise PrivateFailure('candidate-refused') from None
