"""Private historical-value capture, not restore/replay or final-row semantics.

Native decode is opt-in trusted code running offline, never Python ETF. Callers
must cover every used cold file and validate archive EOF/finish separately.
"""
import hashlib
from pathlib import Path
import tempfile

from emqx_native_runtime import run_native
from emqx_semantic_readers import (
    MAX_INPUT, MAX_OUTPUT, Values, SemanticRefused, _contract, _term,
)

CONTAINERS = {
    'schema-dat': ('dets9-set-keypos2', 'dets-fold-complete'),
    **{kind: ('disk-log-internal-halt', 'disk-log-eof') for kind in
       ('empty-dcd', 'dcd', 'dcl', 'transaction-log', 'decision-log', 'decision-tab')},
}
SCRIPT = Path(__file__).with_name('emqx_cold_terms.escript')


def native_cold_history(raw, kind):
    """Bounded per-file native data decode, no Mnesia startup or backend calls."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT or kind not in CONTAINERS:
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='emqx-cold-private-') as directory:
            root = Path(directory)
            (root / 'source.native').write_bytes(raw)
            (root / 'source.native').chmod(0o600)
            (root / SCRIPT.name).write_bytes(SCRIPT.read_bytes())
            with tempfile.TemporaryFile() as output:
                code = run_native(root, SCRIPT.name, (kind,), output=output)
                output.seek(0)
                encoded = output.read(MAX_OUTPUT+1)
                if code or len(encoded) > MAX_OUTPUT:
                    raise ValueError()
                return encoded
    except Exception:
        raise SemanticRefused() from None


def read_cold_history(raw, kind, decoder=None):
    """Return every binary/atom/charlist and canonical numeric private value.

    No five-table filter: unknown table NAMES are data, not skipped. An unknown
    container or executable/runtime term refuses the entire file. No adapter is
    installed by default. Terms include log headers and all historical mutations.
    """
    try:
        if kind not in CONTAINERS or not callable(decoder):
            raise ValueError()
        doc = _contract(raw, lambda value: decoder(value, kind), 'emqx-cold-history-json-v1')
        expected = {'contract','version','otp_release','erts_version','input_sha256',
                    'input_bytes','complete','kind','container','traversal','semantics',
                    'final_state','empty_container','term_count','terms'}
        container, traversal = CONTAINERS[kind]
        if (set(doc) != expected or doc['kind'] != kind or doc['container'] != container
                or doc['traversal'] != traversal or doc['otp_release'] != '26'
                or doc['erts_version'] != '14.2.5.11'
                or doc['semantics'] != 'historical-value-superset' or doc['final_state'] is not False
                or type(doc['terms']) is not list or type(doc['term_count']) is not int
                or not 0 <= doc['term_count'] == len(doc['terms']) <= 4096
                or type(doc['empty_container']) is not bool
                or (kind == 'empty-dcd' and not (doc['empty_container'] is True
                    and doc['term_count'] == 0 and len(raw) == 8))
                or (kind != 'empty-dcd' and not (doc['empty_container'] is False
                    and doc['term_count'] > 0))):
            raise ValueError()
        result = Values()
        for term in doc['terms']:
            _term(term, result, historical=True)
        return result
    except Exception:
        raise SemanticRefused() from None


class HistoryInventory:
    """All expected USED files exactly once; caller-owned, not archive authority.

    expected maps canonical archive path -> exact {kind, bytes, sha256}. It must
    come from complete validated tar traversal and product copy/use policy. No
    ignored-file inference, substring classification, or registration/seal occurs
    here. Per-file 8MiB, total32MiB, <=64 files; all existing value limits apply.
    """
    def __init__(self, expected, decoder=None):
        try:
            if type(expected) is not dict or not 1 <= len(expected) <= 64:
                raise ValueError()
            total = 0
            self._expected = {}
            for path, receipt in expected.items():
                if (type(path) is not str or not path or path.startswith('/')
                        or len(path.encode('utf-8')) > 4096 or '\\' in path or '\x00' in path
                        or any(part in ('', '.', '..') for part in path.split('/'))
                        or type(receipt) is not dict or set(receipt) != {'kind','bytes','sha256'}
                        or receipt['kind'] not in CONTAINERS or type(receipt['bytes']) is not int
                        or not 0 < receipt['bytes'] <= MAX_INPUT
                        or type(receipt['sha256']) is not str or len(receipt['sha256']) != 64
                        or any(c not in '0123456789abcdef' for c in receipt['sha256'])):
                    raise ValueError()
                total += receipt['bytes']
                self._expected[path] = dict(receipt)
            if total > 32*1024*1024:
                raise ValueError()
            self._decoder, self._seen, self._values = decoder, set(), Values()
            self._failed = self._finished = False
        except Exception:
            raise SemanticRefused() from None

    def __repr__(self):
        return '<EMQX private cold history inventory>'

    def consume(self, path, raw):
        try:
            if self._failed or self._finished or path not in self._expected or path in self._seen:
                raise ValueError()
            receipt = self._expected[path]
            if (type(raw) is not bytes or len(raw) != receipt['bytes']
                    or hashlib.sha256(raw).hexdigest() != receipt['sha256']):
                raise ValueError()
            values = read_cold_history(raw, receipt['kind'], self._decoder)
            for value in values.values:
                self._values.add(value)
            self._seen.add(path)
        except Exception:
            self._failed = True
            raise SemanticRefused() from None

    def finish(self):
        if self._failed or self._finished or self._seen != set(self._expected):
            self._failed = True
            raise SemanticRefused() from None
        self._finished = True
        return self._values


def native_cold_diagnostic(raw, kind):
    """Fixed-phase refusal diagnosis only; never return native terms/exception text.

    Independent diagnostic mode cannot satisfy read_cold_history's contract or
    authorize registry sealing/recovery. Same bounded offline runtime as decode.
    """
    import json
    phases = {'BOOT','VERSION','INPUT','HASH','VERIFY','OUTPUT','COMPLETE',
              'SCHEMA_OPEN','SCHEMA_INFO','SCHEMA_PROPERTIES','SCHEMA_TYPED','SCHEMA_EOF',
              'SCHEMA_EXTERNAL_DEPENDENCIES','SCHEMA_USER_DEPENDENCIES','SCHEMA_INDEX_DEPENDENCIES',
              'SCHEMA_USER_LIST','SCHEMA_USER_KEY_SHAPES','SCHEMA_USER_DUPLICATE_KEYS',
              'SCHEMA_BACKEND_METADATA','SCHEMA_BACKEND_UNREVIEWED_ALIAS',
              'SCHEMA_BACKEND_UNREVIEWED_MODULE','SCHEMA_BACKEND_METADATA_SHAPE',
              'LOG_OPEN','LOG_HEADER','TYPED','UNSUPPORTED_PID','UNSUPPORTED_REF',
              'UNSUPPORTED_PORT','UNSUPPORTED_FUN','UNSUPPORTED_TERM'}
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT or kind not in CONTAINERS:
            raise ValueError()
        with tempfile.TemporaryDirectory(prefix='emqx-cold-diagnostic-private-') as directory:
            root = Path(directory)
            (root / 'source.native').write_bytes(raw)
            (root / 'source.native').chmod(0o600)
            (root / SCRIPT.name).write_bytes(SCRIPT.read_bytes())
            with tempfile.TemporaryFile() as output:
                code = run_native(root, SCRIPT.name, (kind, '--diagnose'), output=output)
                output.seek(0)
                encoded = output.read(4097)
            if len(encoded) > 4096:
                raise ValueError()
            doc = json.loads(encoded)
            if (type(doc) is not dict or set(doc) != {'phase','result'}
                    or doc['phase'] not in phases
                    or (code, doc['result']) not in ((0,'PASSED'),(2,'REFUSED'))):
                raise ValueError()
            return doc
    except Exception:
        return {'phase':'PROTOCOL','result':'REFUSED'}
