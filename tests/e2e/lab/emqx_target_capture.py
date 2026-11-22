"""Restricted private target producer; no IO/default native exporter installed.

Uses the existing semantic exporter contract unchanged. This module does not
implement Mnesia traversal and does not attest whole-target inventory coverage.
Only a complete username-based password-hash table can currently be projected.
"""
import base64
import io
import json

from emqx_private_boundary import PrivateFailure
from emqx_runtime_credentials import TARGET_CATEGORIES, parse_json
from emqx_semantic_readers import read_mnesia
from emqx_target_snapshots import inline


class TargetCaptureUnsupported(PrivateFailure):
    def __init__(self):
        super().__init__('target-capture-unsupported')


def unsupported():
    raise TargetCaptureUnsupported() from None


def _binary(term):
    if not isinstance(term, dict) or set(term) != {'type', 'value'} or term['type'] != 'binary':
        unsupported()
    return base64.b64decode(term['value'], validate=True)


def _group_matches(term, expected):
    # Live 5.8.9 global chains use atom groups. Compare the already validated
    # native atom NAME to an independently owner-verified provider group; no
    # atom creation, row-derived expected group, coercion of other types or filter.
    if type(term) is dict and set(term) == {'type', 'value'} and term['type'] == 'atom':
        if type(term['value']) is not str:
            unsupported()
        return term['value'].encode('utf-8') == expected
    return _binary(term) == expected


def mqtt_password_table(raw, *, exporter, username_group):
    """Trusted pinned native exporter(raw) -> complete typed table JSON bytes.

    username_group is owner-verified native authentication group bytes, never
    inferred from data. Native binary or UTF-8 atom group names must exactly
    match it; every row must belong to that group. Client-id auth,
    SCRAM, other tables and non-UTF8 binary hashes remain unsupported. Empty
    salt must be an actual exported empty binary, never a missing-field default.
    This is table coverage only, NOT discovery of every authenticator/listener.
    """
    try:
        if type(username_group) is not bytes or not username_group or not callable(exporter):
            unsupported()
        # Execute exactly once. Existing validator checks digest, version, schema,
        # all typed terms and bounds before any projection becomes available.
        encoded = None
        def once(source):
            nonlocal encoded
            encoded = exporter(source)
            return encoded
        read_mnesia(raw, 'emqx_authn_mnesia', once)
        doc = parse_json(encoded)
        records, seen = [], set()
        for row in doc['rows']:
            _, identity, password_hash, salt, superuser = row['value']
            if (identity['type'] != 'tuple' or len(identity['value']) != 2
                    or not _group_matches(identity['value'][0], username_group)
                    or superuser not in ({'type': 'atom', 'value': 'true'},
                                         {'type': 'atom', 'value': 'false'})):
                unsupported()
            username = _binary(identity['value'][1]).decode('utf-8')
            if username in seen:
                unsupported()
            seen.add(username)
            record = {'username': username,
                      'password_hash': _binary(password_hash).decode('utf-8'),
                      'salt': _binary(salt).decode('utf-8')}
            for field, value in record.items():
                inline(value, empty=field == 'salt')
            records.append(record)
        result = json.dumps({'schema': 1, 'complete': True, 'records': records}).encode()
        # Same bound/duplicate policy as exact target readers.
        parse_json(result)
        return result
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise TargetCaptureUnsupported() from None


def exact_target_readers(raw, *, exporter, username_group):
    """Return exact category callables, with explicit unsupported category gates.

    register_target_snapshots remains atomic: unsupported api-keys, connectors,
    tls or bootstrap prevents ANY target registration. No empty placeholders.
    Mnesia emqx_app cannot supply plaintext api_secret. An eventual creation
    credential producer also needs full inventory and runtime issuance coverage.
    """
    def mqtt():
        return io.BytesIO(mqtt_password_table(
            raw, exporter=exporter, username_group=username_group))
    return {category: mqtt if category == 'mqtt-auth' else unsupported
            for category in TARGET_CATEGORIES}


def mqtt_table_reader(raw, *, exporter, username_group):
    """Private single-category reader for owner integration; NOT full acceptance.

    Caller must separately establish whole-target inventory and install remaining
    producers before register_target_snapshots/login_preflight can be used.
    The returned stream is consumed/closed by the existing reader contract.
    """
    encoded = mqtt_password_table(raw, exporter=exporter, username_group=username_group)
    return lambda: io.BytesIO(encoded)
