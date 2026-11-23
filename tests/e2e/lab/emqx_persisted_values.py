"""Private persisted-value companion; business table projection is unnecessary.

Trusted owner inventory and native cold exporter only. No file discovery, ETF
loading or broker IO. Existing native checkpoint JSON contract is unchanged.
Every inventoried table must traverse native EOF, including empty JWT tables.
"""
import base64
import json
import hashlib
import re
from urllib.parse import quote_from_bytes

from emqx_private_boundary import PrivateFailure, MAX_TOTAL
from emqx_runtime_credentials import parse_json, read_bounded
from emqx_semantic_readers import (
    VERSION, MAX_INPUT, Values, _contract, _term,
)


# Supported unquoted native atom names only; never filesystem paths or code.
MAX_NATIVE_NAME = 255
_NATIVE_NAME = re.compile(r'[a-z][a-z0-9_]*', re.ASCII)


def native_name(value):
    return (type(value) is str and 1 <= len(value) <= MAX_NATIVE_NAME
            and _NATIVE_NAME.fullmatch(value) is not None)


def refuse():
    raise PrivateFailure('persisted-values-unsupported') from None


class PersistedValues:
    def __init__(self, generation, scope, tables, values):
        self.generation, self.scope = generation, scope
        self.tables = frozenset(tables)
        self._bindings = {name: (item['input_sha256'], item['input_bytes'])
                          for name, item in tables.items()}
        self._values = tuple(values)

    def __repr__(self):
        return '<EMQX private persisted values>'

    def matches(self, table, raw):
        return self._bindings.get(table) == (hashlib.sha256(raw).hexdigest(), len(raw))

    def scan(self, payload):
        if type(payload) is not bytes or len(payload) > MAX_TOTAL:
            refuse()
        for value in self._values:
            needles = {value, base64.b64encode(value), value.hex().encode(),
                       quote_from_bytes(value, safe='').encode()}
            try:
                decoded = value.decode('utf-8')
            except UnicodeDecodeError:
                pass
            else:
                needles.update(json.dumps(decoded, ensure_ascii=flag)[1:-1].encode()
                               for flag in (True, False))
            if any(needle in payload for needle in needles):
                raise PrivateFailure('persisted-private-leak') from None


def capture_persisted_values(*, private_inventory, private_table, exporter,
                             generation, scope):
    """Inventory callback -> private JSON stream; table(name) -> checkpoint stream.

    Native inventory describes ALL tables/files in one owner-quiesced generation,
    including empty tables, not just supported table names. Exporter(table, raw) uses
    the existing emqx-mnesia-checkpoint-json-v1 contract and MUST validate native
    schema/header and full checkpoint EOF, not a listing or selected rows.
    All byte/charlist/map/atom leaves are registered as a conservative superset.
    Unknown native term kinds still refuse; schema knowledge is delegated to
    reviewed native code (e.g. Mencius coldreader), never to arbitrary data.
    """
    try:
        if (scope not in ('source', 'target') or type(generation) is not str
                or not generation or not all(callable(x) for x in
                    (private_inventory, private_table, exporter))):
            refuse()
        stream = private_inventory()
        try:
            inventory = parse_json(read_bounded(stream))
            if hasattr(stream, 'finish'):
                stream.finish()
        finally:
            stream.close()
        if (type(inventory) is not dict or set(inventory) != {
                'contract', 'version', 'generation', 'scope', 'complete', 'eof', 'tables'}
                or inventory['contract'] != 'emqx-persistent-inventory-v1'
                or inventory['version'] != VERSION or inventory['generation'] != generation
                or inventory['scope'] != scope or inventory['complete'] is not True
                or inventory['eof'] is not True or type(inventory['tables']) is not list
                or not 1 <= len(inventory['tables']) <= 256):
            refuse()
        # Validate the entire inventory before any table callback.
        tables = {}
        for item in inventory['tables']:
            if (type(item) is not dict or set(item) != {
                    'table', 'input_sha256', 'input_bytes', 'record_name', 'attributes'}
                    or not native_name(item['table'])
                    or item['table'] in tables
                    or not native_name(item['record_name'])
                    or type(item['attributes']) is not list or not item['attributes']
                    or not all(native_name(a) for a in item['attributes'])
                    or len(set(item['attributes'])) != len(item['attributes'])
                    or type(item['input_bytes']) is not int
                    or not 0 <= item['input_bytes'] <= MAX_INPUT
                    or type(item['input_sha256']) is not str
                    or len(item['input_sha256']) != 64):
                refuse()
            tables[item['table']] = item
        values = Values()
        total_input = 0
        for table, item in tables.items():
            stream = private_table(table)
            try:
                raw = read_bounded(stream, MAX_INPUT)
                # A cold stream may report final integrity failure after EOF.
                if hasattr(stream, 'finish'):
                    stream.finish()
            finally:
                stream.close()
            total_input += len(raw)
            if total_input > 256 * MAX_INPUT:
                refuse()
            doc = _contract(raw, lambda source: exporter(table, source),
                            'emqx-mnesia-checkpoint-json-v1')
            if (set(doc) != {'contract', 'version', 'input_sha256', 'input_bytes',
                    'complete', 'table', 'record_name', 'attributes', 'rows', 'schema_validated'}
                    or any(doc[key] != item[key] for key in (
                        'table', 'input_sha256', 'input_bytes', 'record_name', 'attributes'))
                    or doc['schema_validated'] is not True or type(doc['rows']) is not list):
                refuse()
            for row in doc['rows']:
                if (type(row) is not dict or row.get('type') != 'tuple'
                        or type(row.get('value')) is not list
                        or len(row['value']) != len(item['attributes']) + 1
                        or row['value'][0] != {'type': 'atom', 'value': item['record_name']}):
                    refuse()
                _term(row, values)
        return PersistedValues(generation, scope, tables, values.values)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('persisted-values-cancelled') from None
    except Exception:
        raise PrivateFailure('persisted-values-unsupported') from None


def capture_cold_persisted_values(*, expected, private_file, finish_inventory,
                                  generation, decoder=None, history_factory=None):
    """Bridge Mencius HistoryInventory into source fullscan, without replay.

    expected is the existing caller-owned canonical path -> {kind,bytes,sha256}
    mapping from complete authenticated tar inventory. finish_inventory() MUST
    perform/verify overall archive EOF+finish and raise on failure. Per-file EOF
    does not substitute for that callback. The existing cold history reader owns
    native format/OTP/traversal validation and captures historical supersets;
    this bridge never treats history as final rows or opens the source gate.
    No native implementation is copied or modified here. Missing dependency or
    absent/unsupported native decoder refuses; no Python ETF fallback.
    """
    try:
        if (type(generation) is not str or not generation
                or not callable(private_file) or not callable(finish_inventory)):
            refuse()
        if history_factory is None:
            from emqx_cold_history import HistoryInventory
            history_factory = HistoryInventory
        # HistoryInventory validates/copies exact path receipts and aggregate bounds.
        history = history_factory(expected, decoder=decoder)
        for path, receipt in expected.items():
            stream = private_file(path)
            try:
                raw = read_bounded(stream, min(receipt['bytes'], MAX_INPUT))
                if hasattr(stream, 'finish'):
                    stream.finish()
            finally:
                stream.close()
            history.consume(path, raw)
        finish_inventory()
        values = history.finish()
        # Reapply companion aggregate limits; never accept arbitrary unbounded
        # values from a decoder. A trusted history reader supplies byte values.
        bounded = Values()
        for value in values.values:
            bounded.add(value)
        result = PersistedValues(generation, 'source', {}, bounded.values)
        result.files = frozenset(expected)
        return result
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('persisted-values-cancelled') from None
    except Exception:
        raise PrivateFailure('persisted-values-unsupported') from None
