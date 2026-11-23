"""Private bounded source registration with opt-in native semantic adapters.

Cold history is a value superset, not restore/replay or final-row semantics.
Source-only registration cannot authorize diagnostics or candidate replay.
"""
import contextlib
import io
import json
import tarfile
import hashlib
import re
import os
import operator
from urllib.parse import unquote_to_bytes

from woowbackup import habackup, hasecuretar, ha_emqx
from emqx_private_boundary import Registry, PrivateFailure, SOURCES, MAX_VALUE, MAX_TOTAL
from emqx_real_candidate import build_verified_candidate
from emqx_semantic_readers import read_hocon, MAX_INPUT, SemanticRefused

MAX_STREAM = 8 * 1024 * 1024


def json_values(raw, *, metadata_urls=False):
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
            if any(token in value for token in ('${', 'file:', 'env:', 'vault:')) or ('://' in value and not metadata_urls):
                refuse()
            if value:
                values.append(value.encode('utf-8'))
                if metadata_urls and '://' in value:
                    # Literal metadata only: never resolve/fetch. Capture any
                    # URL userinfo components in raw and percent-decoded forms.
                    authority = value.split('://', 1)[1]
                    for delimiter in ('/', '?', '#'):
                        authority = authority.split(delimiter, 1)[0]
                    if '@' in authority:
                        userinfo = authority.rsplit('@', 1)[0]
                        for part in userinfo.split(':', 1):
                            if part:
                                values.extend((part.encode(), unquote_to_bytes(part)))
        elif value is not None and not isinstance(value, (bool, int, float)):
            refuse()
    return values


def addon_values(raw):
    """Strict JSON metadata URLs are literals; active user options keep ref gates.

    No metadata string is executed or dereferenced. All private string leaves
    remain registered, including raw/decoded URL credential components.
    """
    from woowbackup import util
    doc = util.loads_strict(raw, max_bytes=MAX_VALUE)
    if not isinstance(doc, dict):
        refuse()
    values = []
    for key, value in doc.items():
        encoded = json.dumps(value, ensure_ascii=False).encode()
        values.extend(json_values(encoded, metadata_urls=key != 'user'))
    return values


def refuse():
    raise PrivateFailure('private-source-refused')


class ImmutableReplay(io.RawIOBase):
    """Read-only immutable memory input; no writable backing object exposed."""
    def __init__(self, data):
        super().__init__()
        self._data, self._position = bytes(data), 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def read(self, size=-1):
        if self.closed:
            raise ValueError('closed source replay')
        size = -1 if size is None else operator.index(size)
        end = len(self._data) if size < 0 else min(len(self._data), self._position + size)
        result = self._data[self._position:end]
        self._position = max(self._position, end)
        return result

    def readinto(self, output):
        chunk = self.read(len(output))
        output[:len(chunk)] = chunk
        return len(chunk)

    def write(self, data):
        raise io.UnsupportedOperation('source replay is read-only')

    def truncate(self, size=None):
        raise io.UnsupportedOperation('source replay is read-only')

    def tell(self):
        if self.closed:
            raise ValueError('closed source replay')
        return self._position

    def seek(self, offset, whence=os.SEEK_SET):
        if self.closed:
            raise ValueError('closed source replay')
        bases = {os.SEEK_SET: 0, os.SEEK_CUR: self._position, os.SEEK_END: len(self._data)}
        if whence not in bases:
            raise ValueError('invalid source seek')
        position = bases[whence] + operator.index(offset)
        if position < 0:
            raise ValueError('negative source seek')
        self._position = position
        return position


@contextlib.contextmanager
def readonly_replay(captured):
    if isinstance(captured, io.BytesIO):
        with ImmutableReplay(captured.getvalue()) as reader:
            yield reader
    else:
        # A dup() would preserve O_RDWR: reopen the already-bound inode readonly.
        descriptor = os.open('/proc/self/fd/' + str(captured.fileno()), os.O_RDONLY)
        with os.fdopen(descriptor, 'rb') as reader:
            yield reader


def cold_kind(name, size):
    """Pinned OTP file policy, not archive-selected executable/parser code."""
    prefix = ha_emqx.DATA + '/mnesia/'
    parts = name[len(prefix):].split('/') if name.startswith(prefix) else []
    if len(parts) != 2 or not ha_emqx.NODE_RE.fullmatch(parts[0]):
        refuse()
    filename = parts[1]
    if filename == 'schema.DAT':
        return 'schema-dat'
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.DCD', filename):
        return 'empty-dcd' if size == 8 else 'dcd'
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.DCL', filename):
        return 'dcl'
    logs = {'LATEST.LOG': 'transaction-log', 'PREVIOUS.LOG': 'transaction-log',
            'DECISION.LOG': 'decision-log', 'PDECISION.LOG': 'decision-log',
            'DECISION_TAB.LOG': 'decision-tab'}
    if filename in logs:
        return logs[filename]
    raise PrivateFailure('private-source-native-mnesia-unsupported')


class Capture:
    """Consume once to EOF, validate and register identical replay bytes.

    Normal mode requires exact category -> JSON bytes owner target snapshots
    and seals after source registration. source_only() defers target documents
    and refuses scan/summary/replay until supply_target_documents() succeeds.
    No missing categories or implicit empty acknowledgements are accepted.
    Native HOCON/cold-history adapters remain explicit opt-ins.
    """
    def __init__(self, password, target_documents, *, hocon_parser=None, spool_directory=None, product_selection=False, cold_decoder=None, source_only=False):
        if type(source_only) is not bool or (source_only and target_documents is not None):
            refuse()
        self._source_only = source_only
        self._source_ready = False
        self._closed = False
        self._target_attempted = False
        self._private_binding = None
        self._owner_source_proof = None
        if type(product_selection) is not bool:
            refuse()
        if cold_decoder is not None and (not callable(cold_decoder) or not product_selection):
            refuse()
        self._cold_decoder = cold_decoder
        self.cold_receipt = None
        self._product_selection = product_selection
        self.discarded = {"files": 0, "bytes": 0}
        self._hocon_parser = hocon_parser
        self._source_phase = 'SETUP'
        self.hocon_file_receipts = ()
        self._spool_directory = spool_directory
        self._stack = None
        if not isinstance(password, str) or not password:
            refuse()
        self.keys = hasecuretar.Keys(password)
        self.registry = Registry()
        self.registry.register('backup-key', [password.encode('utf-8')])
        if not source_only:
            self._register_targets(target_documents)
        self._used = False

    @classmethod
    def source_only(cls, password, **kwargs):
        """Register only source categories; no fabricated target acknowledgement."""
        return cls(password, None, source_only=True, **kwargs)

    def _register_targets(self, target_documents):
        expected = SOURCES - {'backup-key', 'source-options', 'source-cookie'}
        if not isinstance(target_documents, dict) or set(target_documents) != expected:
            refuse()
        total = 0
        parsed = {}
        for name in sorted(expected):
            raw = target_documents[name]
            if not isinstance(raw, bytes) or len(raw) > MAX_VALUE:
                refuse()
            total += len(raw)
            if total > MAX_TOTAL:
                refuse()
            parsed[name] = json_values(raw)
        for name, values in parsed.items():
            self.registry.register(name, values)

    def supply_target_documents(self, documents):
        """Complete the registry with explicit owner snapshots, once, in context.

        Presence is an owner acknowledgement, not independent target coverage
        proof. A failed attempt cannot be retried to upgrade a partial registry.
        """
        if (not self._source_only or not self._source_ready or self._closed
                or self._stack is None or self._target_attempted):
            refuse()
        self._target_attempted = True
        self._register_targets(documents)
        self.registry.seal()

    def __enter__(self):
        self._stack = contextlib.ExitStack()
        return self

    def __exit__(self, *exc):
        self._closed = True
        return self._stack.__exit__(*exc)

    def __repr__(self):
        return '<EMQX private capture>'

    def __call__(self, source, *, fixture_profile=None, verified_sha256=None,
                 file_dependency_profile=None, product_image=None):
        if self._used or self._closed:
            refuse()
        self._used = True
        if fixture_profile is not None and self._spool_directory is None:
            refuse()
        self._source_phase = 'SELECT'
        slug = source['addon_member']('woow-emqx')
        self._source_phase = 'SPOOL'
        with source['open'](slug) as stream:
            if self._spool_directory is not None:
                if self._stack is None:
                    refuse()
                from emqx_private_spool import capture
                captured, _, _ = self._stack.enter_context(
                    capture(stream, self._spool_directory, fixture_profile=fixture_profile,
                            verified_sha256=verified_sha256))
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
        self._source_phase = 'TAR'
        report = habackup.Report()
        for entry in habackup.iter_entries(captured, report=report, addon=True):
            if entry.kind not in ('dir', 'file'):
                refuse()
        if not report.complete:
            refuse()
        captured.seek(0)
        found = set()
        source_options = []
        cold_records = {}
        cold_bytes = 0
        with tarfile.open(fileobj=captured, mode='r:') as archive:
            for entry in archive:
                self._source_phase = 'SELECT'
                name = habackup.normalize(entry.name)
                if entry.isdir():
                    continue
                # The product never opens/copies files outside its STAGED roots.
                # Whole tar safety and EOF have already been verified above.
                staged = any(name == ha_emqx.DATA + '/' + item or
                             name.startswith(ha_emqx.DATA + '/' + item + '/')
                             for item in ha_emqx.STAGED)
                identity = name in ('addon.json', ha_emqx.NODE_FILE,
                                    'data/emqx/node.cookie')
                if self._product_selection and (name in habackup.NEVER_READ or not (staged or identity)):
                    self.discarded['files'] += 1
                    self.discarded['bytes'] += entry.size
                    continue
                is_hocon = name in ('data/emqx/data/configs/cluster.hocon',
                                    'data/emqx/etc/emqx.conf',
                                    'data/emqx/etc/base.hocon')
                is_cold = name.startswith(ha_emqx.DATA + '/mnesia/')
                limit = MAX_INPUT if is_hocon or is_cold else MAX_VALUE
                if is_cold and self._cold_decoder is None:
                    raise PrivateFailure('private-source-native-mnesia-unsupported')
                if not entry.isfile() or entry.size > limit or name in found:
                    refuse()
                found.add(name)
                raw = archive.extractfile(entry).read(limit + 1)
                if is_cold:
                    self._source_phase = 'COLD_INVENTORY'
                    cold_bytes += len(raw)
                    if len(cold_records) >= 64 or cold_bytes > 32 * 1024 ** 2:
                        refuse()
                    cold_records[name] = (raw, cold_kind(name, len(raw)))
                elif name == 'addon.json':
                    self._source_phase = 'ADDON_METADATA'
                    source_options.extend(addon_values(raw))
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
                    self._source_phase = 'HOCON_CONTRACT'
                    def observed_parser(data):
                        self._source_phase = 'HOCON_NATIVE'
                        encoded = self._hocon_parser(data)
                        self._source_phase = 'HOCON_CONTRACT'
                        return encoded
                    try:
                        values = read_hocon(raw, observed_parser,
                            file_profile=file_dependency_profile, product_image=product_image)
                        source_options.extend(values.values)
                        self.hocon_file_receipts += getattr(values, 'file_receipts', ())
                    except SemanticRefused as error:
                        if self._source_phase != 'HOCON_NATIVE':
                            from emqx_hocon_context import SYNTAX_PHASES
                            self._source_phase = {
                                'syntax':'HOCON_SYNTAX','walk':'HOCON_WALK',
                                'vendor_observer':'VENDOR_OBSERVER','receipt':'VENDOR_RECEIPT',
                                'register':'HOCON_REGISTER',
                                **{phase:'HOCON_'+phase.upper() for phase in SYNTAX_PHASES},
                            }.get(getattr(error,'owner_phase',None),'HOCON_CONTRACT')
                        raise PrivateFailure('private-source-hocon-unsupported') from None
                else:
                    raise PrivateFailure('private-source-format-unsupported')
        self._source_phase = 'SELECT'
        required = {'addon.json', 'data/emqx/node.name'}
        if not self._product_selection:
            required.add('data/emqx/node.cookie')
        elif 'data/emqx/node.cookie' not in found:
            # Exhaustive tar inventory observed absence; the product never uses it.
            self.registry.register('source-cookie', [])
        if not required <= found:
            refuse()
        if self._cold_decoder is not None:
            self._source_phase = 'COLD_INVENTORY'
            from emqx_cold_history import HistoryInventory
            if not cold_records or sum(kind == 'schema-dat' for _, kind in cold_records.values()) != 1:
                refuse()
            receipts = {name: {'kind': kind, 'bytes': len(raw),
                              'sha256': hashlib.sha256(raw).hexdigest()}
                        for name, (raw, kind) in cold_records.items()}
            def observed_cold(raw, kind):
                self._source_phase = 'COLD_NATIVE'
                encoded = self._cold_decoder(raw, kind)
                self._source_phase = 'COLD_TYPED'
                return encoded
            inventory = HistoryInventory(receipts, observed_cold)
            for name, (raw, _) in cold_records.items():
                self._source_phase = 'COLD_NATIVE'
                inventory.consume(name, raw)
            self._source_phase = 'COLD_FINISH'
            source_options.extend(inventory.finish().values)
            self.cold_receipt = {'scope': 'historical-values-only',
                                 'files': len(receipts), 'bytes': cold_bytes,
                                 'final_state': False}
        self._source_phase = 'REGISTER'
        self.registry.register('source-options', source_options)
        self._source_ready = True
        if not self._source_only:
            self.registry.seal()
        @contextlib.contextmanager
        def replay(requested):
            if requested != slug or self._closed:
                refuse()
            self.registry.summary()  # A source-only registry cannot authorize replay.
            with readonly_replay(captured) as reader:
                yield reader
        from emqx_captured_candidate import CapturedBinding
        self._private_binding = CapturedBinding(self, dict(source, open=replay))
        return self._private_binding


def build_consumed_candidate(*args, password, target_documents, hocon_parser=None, spool_directory=None, product_selection=False, cold_decoder=None, **kwargs):
    """Callable private candidate path; fixed errors only, no secret diagnostics."""
    try:
        if 'keys' in kwargs or 'private_capture' in kwargs:
            refuse()
        capture = Capture(password, target_documents, hocon_parser=hocon_parser,
                          spool_directory=spool_directory, product_selection=product_selection, cold_decoder=cold_decoder)
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
