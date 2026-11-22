"""Private EMQX 5.8.9 semantic readers; no IO, runtime or deserialization.

Adapters are TRUSTED code, never selected by an archive or its metadata. A HOCON
adapter must parse the entire input with includes/substitutions disabled, report
all references, and emit the contract below. A Mnesia adapter must traverse the
entire checkpoint read-only using the pinned native implementation, validate its
schema and emit typed records. These assertions cannot make an untrusted adapter
safe. Raw HA DAT/DCD/DCL files are NOT checkpoint exports and are unsupported.
Adapters must enforce their own runtime/memory limits before returning JSON;
this module bounds input/output and traversal, not execution of trusted code.
"""
import base64
import hashlib
import json
import math

VERSION = '5.8.9'
MAX_INPUT = 8 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
MAX_VALUE = 64 * 1024
MAX_NODES = 8192
MAX_DEPTH = 16
MAX_VALUES = 4096

# Verified at EMQX a8319fe2390169e1f2483e3ec80dd01a6cdb233d (v5.8.9).
# Other tables and older/migrated attribute layouts explicitly remain unsupported.
TABLES = {
    'emqx_authn_mnesia': ('user_info', ('user_id', 'password_hash', 'salt', 'is_superuser')),
    'emqx_authn_scram_mnesia': ('user_info', ('user_id', 'stored_key', 'server_key', 'salt', 'is_superuser')),
    'emqx_acl': ('emqx_acl', ('who', 'rules')),
    'emqx_admin': ('emqx_admin', ('username', 'pwdhash', 'description', 'role', 'extra')),
    'emqx_app': ('emqx_app', ('name', 'api_key', 'api_secret_hash', 'enable', 'extra', 'expired_at', 'created_at')),
}


class SemanticRefused(Exception):
    def __init__(self):
        super().__init__('emqx-semantic-source-unsupported')


def refuse():
    raise SemanticRefused() from None


class Values:
    """Private values only; repr never displays source material or adapter output."""
    def __init__(self):
        self._values = set()
        self._total = 0
        self._nodes = 0

    def __repr__(self):
        return '<EMQX private semantic values>'

    @property
    def values(self):
        return tuple(sorted(self._values))

    def add(self, value):
        if type(value) is not bytes or len(value) > MAX_VALUE:
            refuse()
        if not value or value in self._values:
            return
        self._total += len(value)
        if self._total > MAX_OUTPUT or len(self._values) >= MAX_VALUES:
            refuse()
        self._values.add(value)

    def tick(self, depth):
        self._nodes += 1
        if depth > MAX_DEPTH or self._nodes > MAX_NODES:
            refuse()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse()
        result[key] = value
    return result


def _text(value):
    if type(value) is not str:
        refuse()
    raw = value.encode('utf-8')
    if len(raw) > MAX_VALUE:
        refuse()
    return raw


def _json_walk(value, values, depth=0):
    values.tick(depth)
    if type(value) is dict:
        for key, child in value.items():
            values.add(_text(key))
            # File dependency collection is deliberately not implemented here.
            if (key in ('certfile', 'keyfile', 'cacertfile', 'bootstrap_file', 'init_file')
                    or key.endswith('_file')) and child:
                refuse()
            _json_walk(child, values, depth + 1)
    elif type(value) is list:
        for child in value:
            _json_walk(child, values, depth + 1)
    elif type(value) is str:
        if any(token in value for token in ('${', 'file:', 'env:', 'vault:')):
            refuse()
        values.add(_text(value))
    elif value is None or type(value) is bool:
        pass
    elif type(value) is int:
        if not -(2 ** 63) <= value < 2 ** 63:
            refuse()
    elif type(value) is float and math.isfinite(value):
        pass
    else:
        refuse()


def _contract(raw, adapter, kind):
    if type(raw) is not bytes or len(raw) > MAX_INPUT or not callable(adapter):
        refuse()
    encoded = adapter(raw)
    if type(encoded) is not bytes or len(encoded) > MAX_OUTPUT:
        refuse()
    doc = json.loads(encoded.decode('utf-8'), object_pairs_hook=_pairs,
                     parse_constant=lambda _: refuse())
    if (type(doc) is not dict or doc.get('contract') != kind or doc.get('version') != VERSION
            or doc.get('input_sha256') != hashlib.sha256(raw).hexdigest()
            or type(doc.get('input_bytes')) is not int or doc['input_bytes'] != len(raw)
            or doc.get('complete') is not True):
        refuse()
    return doc


def read_hocon(raw, parser=None):
    """Return private string leaves/keys from a complete, nonresolving parse.

    Contract keys are exact. `references` lists ALL include/substitution/external
    dependencies encountered before resolution and must be empty. `document` is
    the full binary-key JSON representation, not a redacted/projected subset.
    No adapter is installed or inferred. Ordinary JSON is not treated as HOCON.
    """
    try:
        doc = _contract(raw, parser, 'emqx-hocon-json-v1')
        if (set(doc) != {'contract', 'version', 'input_sha256', 'input_bytes', 'complete',
                         'resolution', 'references', 'document'}
                or doc['resolution'] != 'disabled' or doc['references'] != []
                or type(doc['document']) is not dict):
            refuse()
        result = Values()
        _json_walk(doc['document'], result)
        return result
    except Exception:
        raise SemanticRefused() from None


def _term(term, values, depth=0, *, historical=False):
    """Strict typed JSON terms; never ETF, pickle, eval, atom creation or code."""
    values.tick(depth)
    if type(term) is not dict or set(term) != {'type', 'value'}:
        refuse()
    kind, value = term['type'], term['value']
    if kind == 'binary':
        if type(value) is not str or len(value) > 4 * ((MAX_VALUE + 2) // 3):
            refuse()
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode('ascii') != value:
            refuse()
        values.add(raw)
    elif kind == 'atom':
        values.add(_text(value))
    elif kind == 'integer':
        if type(value) is not int or not -(2 ** 63) <= value < 2 ** 63:
            refuse()
        if historical:
            values.add(str(value).encode('ascii'))
    elif kind == 'float' and historical:
        if type(value) is not float or not math.isfinite(value):
            refuse()
        values.add(repr(value).encode('ascii'))
    elif kind in ('tuple', 'list'):
        if type(value) is not list:
            refuse()
        for child in value:
            _term(child, values, depth + 1, historical=historical)
        # Erlang charlists can carry secrets too, including byte-oriented lists.
        if kind == 'list' and value and all(type(x) is dict and x.get('type') == 'integer'
                                           and type(x.get('value')) is int for x in value):
            points = [x['value'] for x in value]
            if all(0 <= x <= 255 for x in points):
                values.add(bytes(points))
            values.add(''.join(chr(x) for x in points).encode('utf-8'))
    elif kind == 'map':
        if type(value) is not list:
            refuse()
        seen = set()
        for pair in value:
            if type(pair) is not list or len(pair) != 2:
                refuse()
            key = json.dumps(pair[0], sort_keys=True, separators=(',', ':'))
            if key in seen:
                refuse()
            seen.add(key)
            for child in pair:
                _term(child, values, depth + 1, historical=historical)
    else:
        refuse()


def read_mnesia(raw, table, exporter=None):
    """Read a complete trusted native checkpoint export of ONE supported table.

    Contract includes exact attributes, record name and every row as tagged
    tuples. Schema/header records are validated by the native exporter, not
    silently filtered by this reader. No arbitrary binary deserialization here.
    Callers must account for every source table/file; this is not a coverage seal.
    """
    try:
        if type(table) is not str or table not in TABLES:
            refuse()
        doc = _contract(raw, exporter, 'emqx-mnesia-checkpoint-json-v1')
        record, attributes = TABLES[table]
        if (set(doc) != {'contract', 'version', 'input_sha256', 'input_bytes', 'complete',
                         'table', 'record_name', 'attributes', 'rows', 'schema_validated'}
                or doc['table'] != table or doc['record_name'] != record
                or doc['attributes'] != list(attributes) or doc['schema_validated'] is not True
                or type(doc['rows']) is not list):
            refuse()
        result = Values()
        for row in doc['rows']:
            if (type(row) is not dict or row.get('type') != 'tuple'
                    or type(row.get('value')) is not list
                    or len(row['value']) != len(attributes) + 1
                    or row['value'][0] != {'type': 'atom', 'value': record}):
                refuse()
            _term(row, result)
        return result
    except Exception:
        raise SemanticRefused() from None
