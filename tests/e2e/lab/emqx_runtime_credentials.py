"""Private EMQX owner adapters. No logging, evidence, files, or network defaults.

The supplied transport must be private: it must never log request/response data.
Registration precedes returning any login capability. Registry.scan is the
parent evidence writer's bounded bytes interface, not permission to publish
arbitrary broker output. No secret appears in repr or fixed exception text.
"""
import base64
import json
from urllib.parse import quote_from_bytes

from emqx_private_boundary import PrivateFailure, MAX_VALUE, MAX_TOTAL, MAX_VALUES

TARGET_CATEGORIES = frozenset(('mqtt-auth', 'api-keys', 'connectors', 'tls', 'target-bootstrap'))


def refused():
    raise PrivateFailure('runtime-private-refused')


def read_bounded(stream, maximum=MAX_VALUE):
    chunks, size = [], 0
    while True:
        chunk = stream.read(min(4096, maximum + 1 - size))
        if not isinstance(chunk, bytes):
            refused()
        if not chunk:
            return b''.join(chunks)
        size += len(chunk)
        if size > maximum:
            refused()
        chunks.append(chunk)


def parse_json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_VALUE:
        refused()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refused()
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: refused())
    except Exception:
        raise PrivateFailure('runtime-private-refused') from None


class RuntimeRegistry:
    """Atomic bounded registration; dynamic tokens remain registerable after snapshots.

    scan refuses until all target categories were captured. Parent must serialize
    registration/scan/write in its exclusive owner; no cross-thread attestation.
    """
    def __init__(self):
        self._values = set()
        self._categories = {}
        self._target_complete = False

    def __repr__(self):
        return '<EMQX runtime registry>'

    def register_bundle(self, categories, *, target=False):
        if not isinstance(categories, dict) or not categories:
            refused()
        if target and (self._target_complete or set(categories) != TARGET_CATEGORIES):
            refused()
        allowed = TARGET_CATEGORIES if target else {'runtime-login-input', 'runtime-login-token'}
        pending = set()
        counts = dict(self._categories)
        for category, values in categories.items():
            if category not in allowed or not isinstance(values, (list, tuple)) or len(values) > MAX_VALUES:
                refused()
            for value in values:
                if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_VALUE:
                    refused()
                pending.add(value)
                if len(pending) > MAX_VALUES or sum(map(len, pending)) > MAX_TOTAL:
                    refused()
            counts[category] = counts.get(category, 0) + len(values)
        combined = self._values | pending
        if len(combined) > MAX_VALUES or sum(map(len, combined)) > MAX_TOTAL:
            refused()
        self._values, self._categories = combined, counts
        if target:
            self._target_complete = True

    def scan(self, payload):
        if not self._target_complete or not isinstance(payload, bytes) or len(payload) > MAX_TOTAL:
            refused()
        self._scan_values(payload)

    def scan_login_evidence(self, payload):
        """Runtime producer only: no source or target completeness assertion."""
        if (self._categories.get('runtime-login-input', 0) < 2
                or self._categories.get('runtime-login-token', 0) < 2
                or not isinstance(payload, bytes) or len(payload) > MAX_TOTAL):
            refused()
        self._scan_values(payload)

    def _scan_values(self, payload):
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
                raise PrivateFailure('runtime-private-leak')

    def summary(self):
        if not self._target_complete:
            refused()
        return {category: count for category, count in sorted(self._categories.items())}


class LoginCredential:
    def __init__(self, token):
        self._token = token

    def __repr__(self):
        return '<EMQX private login credential>'

    def with_bearer(self, private_consumer):
        """Only for a reviewed private transport; never an evidence/log callback."""
        return private_consumer(b'Bearer ' + self._token)


def login_registered(registry, private_transport, *, username, password):
    """Transport(username bytes, password bytes) -> (status, content_type, stream).

    Transport owns stream cleanup; returned stream is consumed/closed here.
    No response, field, token or raw transport error is exposed to diagnostics.
    All failures have fixed text. Token is usable only after registry commit.
    """
    try:
        if not all(isinstance(v, bytes) and 1 <= len(v) <= MAX_VALUE for v in (username, password)):
            refused()
        registry.register_bundle({'runtime-login-input': [username, password]})
        status, content_type, stream = private_transport(username, password)
        try:
            if status != 200 or content_type != 'application/json':
                refused()
            doc = parse_json(read_bounded(stream))
        finally:
            stream.close()
        allowed = {'token', 'username', 'role', 'version', 'license'}
        if not isinstance(doc, dict) or not {'token'} <= set(doc) <= allowed:
            refused()
        token = doc['token']
        # EMQX JWT/bearer token is an ASCII, non-whitespace opaque value.
        if (not isinstance(token, str) or not token or len(token) > MAX_VALUE
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            refused()
        raw = token.encode('ascii')
        registry.register_bundle({'runtime-login-token': [raw, b'Bearer ' + raw]})
        return LoginCredential(raw)
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('runtime-private-cancelled') from None
    except Exception:
        raise PrivateFailure('runtime-private-refused') from None
