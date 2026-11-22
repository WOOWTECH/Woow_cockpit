"""Internal producer acknowledgements; no filesystem discovery or secret loading.

Trusted producers supply bytes in memory, explicitly declaring empty categories.
This records coverage assertions, not proof that a producer found every secret.
"""
import base64
import copy
import json
from urllib.parse import quote_from_bytes

from emqx_real_candidate import build_verified_candidate

SOURCES = frozenset(('backup-key', 'source-options', 'source-cookie', 'mqtt-auth',
                     'api-keys', 'tls', 'target-bootstrap', 'connectors'))
MAX_VALUE = 64 * 1024
MAX_TOTAL = 1024 * 1024
MAX_VALUES = 4096


class PrivateFailure(Exception):
    """Only fixed codes may cross the public diagnostic boundary."""


class Registry:
    def __init__(self):
        self._sources = set()
        self._counts = {}
        self._values = set()
        self._total = 0
        self._sealed = False

    def __repr__(self):
        return '<EMQX private registry>'

    def register(self, source, values, *, encoding='raw'):
        if (self._sealed or source not in SOURCES or source in self._sources
                or encoding != 'raw' or not isinstance(values, (tuple, list))
                or len(values) > MAX_VALUES):
            raise PrivateFailure('private-registration-refused')
        pending = set()
        for value in values:
            if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_VALUE:
                raise PrivateFailure('private-registration-refused')
            pending.add(value)
            if sum(map(len, pending - self._values)) + self._total > MAX_TOTAL:
                raise PrivateFailure('private-registration-refused')
        new = pending - self._values
        if (len(self._values | pending) > MAX_VALUES
                or self._total + sum(map(len, new)) > MAX_TOTAL):
            raise PrivateFailure('private-registration-refused')
        if source == 'backup-key' and not pending:
            raise PrivateFailure('private-registration-refused')
        self._values.update(new)
        self._total += sum(map(len, new))
        self._sources.add(source)
        self._counts[source] = len(pending)

    def seal(self):
        if self._sources != SOURCES:
            raise PrivateFailure('private-registration-incomplete')
        self._sealed = True

    def summary(self):
        """Counts of actual unique registrations; no secret values exposed."""
        if not self._sealed:
            raise PrivateFailure('private-registration-incomplete')
        return dict(self._counts)

    def scan(self, payload):
        """Bounded diagnostic snapshot scan; never use to publish private artifacts."""
        if not self._sealed or not isinstance(payload, bytes) or len(payload) > MAX_TOTAL:
            raise PrivateFailure('private-scan-refused')
        for value in self._values:
            needles = {value, base64.b64encode(value), value.hex().encode(),
                       quote_from_bytes(value, safe='').encode()}
            try:
                text = value.decode('utf-8')
            except UnicodeDecodeError:
                pass
            else:
                needles.update(json.dumps(text, ensure_ascii=ascii_only)[1:-1].encode()
                               for ascii_only in (True, False))
            if any(needle in payload for needle in needles):
                raise PrivateFailure('private-diagnostic-leak')


class Producer:
    """Call each reviewed source reader at the producer boundary, in memory.

    Readers return a bounded list/tuple of raw byte secrets. Empty means that
    reader explicitly observed no secrets in that category (key cannot be empty).
    Unknown references/formats must raise, never be skipped by a reader. No
    paths, environment lookups, production readers or default readers are added.
    """
    def __init__(self, readers):
        if (not isinstance(readers, dict) or set(readers) != SOURCES
                or not all(callable(reader) for reader in readers.values())):
            raise PrivateFailure('private-producer-refused')
        self._readers = dict(readers)

    def __repr__(self):
        return '<EMQX private producer>'

    def __call__(self, registry):
        for source in sorted(SOURCES):
            registry.register(source, self._readers[source]())


def build_registered_candidate(*args, producer, **kwargs):
    """Fail closed before transport unless all named producers acknowledge.

    producer(registry) must register actual values (or explicit empty lists)
    before execution. Unsupported/unknown sources must cause producer refusal.
    No producer output, paths, exception text or product log text is published.
    Returned package paths are private and must never be used as evidence.
    """
    registry = Registry()
    try:
        producer(registry)
        registry.seal()
        work = copy.copy(args[0])
        # Discard arbitrary product log payloads, even unregistered secret values.
        work.log = lambda *a, **k: None
        result = build_verified_candidate(work, *args[1:], **kwargs)
        return result
    except (KeyboardInterrupt, SystemExit):
        raise PrivateFailure('candidate-cancelled') from None
    except Exception:
        # Includes producer, transport, filesystem and product exceptions.
        raise PrivateFailure('candidate-refused') from None
