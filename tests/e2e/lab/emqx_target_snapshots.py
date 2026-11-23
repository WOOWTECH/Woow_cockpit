"""Strict owner-normalized target snapshots; no discovery or evidence writer.

Owner adapters supply complete private captures, not masked REST listings.
Only inline values are supported. External/file/secret references refuse.
Raw PEM material must be supplied for TLS; paths/fingerprints cannot substitute.
"""
import base64
import re

from emqx_private_boundary import PrivateFailure, MAX_VALUE, MAX_TOTAL, MAX_VALUES
from emqx_runtime_credentials import TARGET_CATEGORIES, parse_json, read_bounded, refused

# Exact version-1 owner schema, intentionally not an arbitrary EMQX REST schema.
FIELDS = {
    'mqtt-auth': {'username', 'password_hash', 'salt'},
    'api-keys': {'api_key', 'api_secret'},
    'connectors': {'type', 'username', 'password'},
    'tls': {'cert_pem', 'key_pem', 'password'},
    'target-bootstrap': {'username', 'password'},
}
EMPTY_ALLOWED = {'salt', 'username', 'password'}


def inline(value, *, empty=False):
    if not isinstance(value, str) or (not value and not empty):
        refused()
    if value and set(value) == {'*'}:
        refused()
    if any(part in value.lower() for part in ('${', 'file:', 'env:', 'vault:', '://', '******', '<redacted>')):
        refused()
    raw = value.encode('utf-8')
    if len(raw) > MAX_VALUE:
        refused()
    return raw


def pem(raw, kind):
    labels = '(?:CERTIFICATE)' if kind == 'cert' else '(?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|ENCRYPTED PRIVATE KEY)'
    match = re.fullmatch(rb'-----BEGIN (' + labels.encode() + rb')-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END \1-----\s*', raw)
    if not match:
        refused()
    body = b''.join(match.group(2).split())
    try:
        decoded = base64.b64decode(body, validate=True)
    except Exception:
        raise PrivateFailure('runtime-private-refused') from None
    if not decoded:
        refused()
    # Register PEM, body, DER and each base64 line; no cryptographic validity claim.
    return [raw, body, decoded, *match.group(2).splitlines()]


def register_target_snapshots(registry, readers):
    """Exact category -> private callable returning a bounded JSON byte stream.

    Each JSON document: {"schema":1,"complete":true,"records":[...]}.
    Explicit empty records acknowledge absence; missing/unknown category, fields,
    pagination or unsupported record forms refuse. Commit is atomic across all
    five categories; no partial snapshots become evidence-ready.
    """
    try:
        if (not isinstance(readers, dict) or set(readers) != TARGET_CATEGORIES
                or not all(callable(reader) for reader in readers.values())):
            refused()
        pending, total, record_count = {}, 0, 0
        for category in sorted(TARGET_CATEGORIES):
            stream = readers[category]()
            try:
                raw = read_bounded(stream)
            finally:
                stream.close()
            total += len(raw)
            if total > MAX_TOTAL:
                refused()
            doc = parse_json(raw)
            if (not isinstance(doc, dict) or set(doc) != {'schema', 'complete', 'records'}
                    or type(doc['schema']) is not int or doc['schema'] != 1
                    or doc['complete'] is not True or not isinstance(doc['records'], list)):
                refused()
            values = []
            for row in doc['records']:
                record_count += 1
                if record_count > MAX_VALUES or not isinstance(row, dict) or set(row) != FIELDS[category]:
                    refused()
                for field, value in row.items():
                    raw_value = inline(value, empty=field in EMPTY_ALLOWED)
                    if raw_value and not (category == 'connectors' and field == 'type'):
                        values.append(raw_value)
                    if category == 'tls' and field in ('cert_pem', 'key_pem'):
                        values.extend(pem(raw_value, 'cert' if field == 'cert_pem' else 'key'))
                if category == 'connectors' and row['type'] != 'mqtt':
                    refused()
                if category == 'target-bootstrap' and not row['username']:
                    refused()
                if category in ('connectors', 'target-bootstrap') and not row['password']:
                    refused()
                if category == 'tls' and 'ENCRYPTED PRIVATE KEY' in row['key_pem'] and not row['password']:
                    refused()
            pending[category] = values
        registry.register_bundle(pending, target=True)
        return registry.summary()
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise PrivateFailure('runtime-private-refused') from None
