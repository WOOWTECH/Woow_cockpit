"""Declared credential sources of one lab run and the evidence scan that refuses to run while one is missing.

A run declares, before it starts, every source that will issue or carry a credential (lab secret files, values
read from the HA backup, values the run generates, values a service issues during the run). Each source must be
registered with its value(s) before the scan; `scan` raises CoverageError when any declared source has no value, so
a new or skipped credential path cannot silently fall out of the leak scan. Matching covers the raw bytes, the
stripped value and both JSON string escapings. Only source names and counts ever leave this module.
"""
import json
import re

SOURCE_RE = re.compile(r'[a-z][a-z0-9_.-]{1,63}\Z')
MIN_LEN = 6


class CoverageError(RuntimeError):
    """Coverage or scan failure; messages hold source names and counts only, never values."""


def _bytes(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, (bytes, bytearray)):
        raise CoverageError('credential value must be text or bytes')
    return bytes(value)


class Ledger:
    __slots__ = ('_declared', '_values')

    def __init__(self, declared):
        declared = tuple(declared)
        if not declared or len(set(declared)) != len(declared) or not all(
                isinstance(name, str) and SOURCE_RE.fullmatch(name) for name in declared):
            raise CoverageError('declared credential sources must be unique lower-case names')
        self._declared = frozenset(declared)
        self._values = {name: [] for name in declared}

    def __repr__(self):
        return f'<Ledger sources={len(self._declared)}>'

    def register(self, source, value):
        """Add one value of a declared source (several values per source are allowed; duplicates are kept once)."""
        if source not in self._declared:
            raise CoverageError(f'undeclared credential source: {source if SOURCE_RE.fullmatch(str(source)) else "?"}')
        raw = _bytes(value)
        if len(raw.strip()) < MIN_LEN:
            raise CoverageError(f'credential value too short for a reliable scan: {source}')
        if raw not in self._values[source]:
            self._values[source].append(raw)

    def registered(self, source):
        return bool(self._values.get(source))

    def missing(self):
        return sorted(name for name in self._declared if not self._values[name])

    def needles(self):
        found = set()
        for values in self._values.values():
            for raw in values:
                for item in {raw, raw.strip()}:
                    found.add(item)
                    try:
                        text = item.decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                    for ascii_only in (False, True):
                        found.add(json.dumps(text, ensure_ascii=ascii_only)[1:-1].encode('utf-8'))
        return found

    def contains(self, data):
        """True when `data` (text or bytes) holds any registered value; never says which."""
        raw = _bytes(data)
        return any(needle in raw for needle in self.needles())

    def scan(self, blobs=(), paths=()):
        """Count registered values in in-memory blobs and files (streamed, matches across chunk borders).
        Raises CoverageError first when a declared source was never registered."""
        missing = self.missing()
        if missing:
            raise CoverageError('credential sources not registered: ' + ','.join(missing))
        needles = self.needles()
        longest = max(map(len, needles))
        matches = 0
        for blob in blobs:
            raw = _bytes(blob)
            matches += sum(raw.count(n) for n in needles)
        for path in paths:
            tail = b''
            with open(path, 'rb') as handle:
                while chunk := handle.read(1024 * 1024):
                    block = tail + chunk
                    # Count only occurrences that end inside the new chunk (the tail was counted already).
                    matches += sum(_count_ending_after(block, n, len(tail)) for n in needles)
                    tail = block[-(longest - 1):] if longest > 1 else b''
        values = sum(len(v) for v in self._values.values())
        return {'sources': len(self._declared), 'values': values, 'blobs': len(blobs), 'files': len(paths),
                'matches': matches}

    def require_clean(self, blobs=(), paths=()):
        result = self.scan(blobs, paths)
        if result['matches']:
            raise CoverageError(f'registered credential found in scanned output: matches={result["matches"]}')
        return result


def _count_ending_after(block, needle, start):
    count = 0
    index = block.find(needle)
    while index != -1:
        if index + len(needle) > start:
            count += 1
        index = block.find(needle, index + 1)
    return count
