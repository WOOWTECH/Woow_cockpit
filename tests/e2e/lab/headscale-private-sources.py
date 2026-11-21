#!/usr/bin/env python3
"""Extract test-only private material into a private event pipe, never stdout logs.

The output is sensitive JSON intended solely for the acknowledged register
helper. Unknown Tailscale state formats fail closed instead of counting hashes.
"""
import base64
import binascii
import json
import io
import os
import re
import stat
import sys
import tarfile

MAX_FILE = 4 * 1024 * 1024
PRIVATE = re.compile(r'(?<![A-Za-z0-9_])(?:privkey|nodepriv|machinepriv|discpriv):([0-9a-fA-F]{64})(?![0-9a-fA-F])')
PEM = re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END (?:RSA |EC )?PRIVATE KEY-----')


def pem_values(data):
    text = data.decode('ascii')
    match = PEM.fullmatch(text.strip())
    if not match:
        raise ValueError('private PEM missing')
    body = ''.join(match.group(1).split())
    if len(base64.b64decode(body, validate=True)) < 32:
        raise ValueError('private PEM invalid')
    # Retain both whole PEM and its base64 payload/lines; no public hashes.
    return sorted({text.strip(), body, *(line for line in match.group(1).splitlines() if len(line) >= 32)})


def private_key(data):
    text = data.decode('ascii').strip()
    match = PRIVATE.fullmatch(text)
    if not match or set(match.group(1)) == {'0'}:
        raise ValueError('private key missing')
    return [text, match.group(1)]


def client_keys(data):
    # Go's file store can contain base64-encoded JSON values. Decode nested
    # text values, bounded by size and depth, and require two private keys.
    root = json.loads(data)
    pending = [(root, 0, None)]
    found = {'machine': set(), 'node': set()}
    visited = 0
    while pending:
        value, depth, role = pending.pop()
        visited += 1
        if visited > 10000 or depth > 8:
            raise ValueError('state too complex')
        if isinstance(value, dict):
            for name, item in value.items():
                field = re.sub(r'[^a-z]', '', str(name).lower())
                kind = ('machine' if field in ('machinekey', 'privatemachinekey') else
                        'node' if field in ('privatenodekey', 'nodeprivatekey', 'privateoldnodekey') else role)
                pending.append((item, depth + 1, kind))
        elif isinstance(value, list):
            pending.extend((v, depth + 1, role) for v in value)
        elif isinstance(value, str):
            for match in PRIVATE.finditer(value):
                if role and set(match.group(1)) != {'0'}:
                    found[role].add(match.group(0))
            if len(value) <= MAX_FILE and len(value) >= 8:
                try:
                    decoded = base64.b64decode(value, validate=True).decode('utf-8')
                    try:
                        pending.append((json.loads(decoded), depth + 1, role))
                    except ValueError:
                        pending.append((decoded, depth + 1, role))
                except (binascii.Error, UnicodeError, ValueError):
                    pass
    if not found['machine'] or not found['node'] or found['machine'] == found['node']:
        raise ValueError('client machine/node private keys missing or unsupported state')
    keys = found['machine'] | found['node']
    return sorted(keys | {item.split(':', 1)[1] for item in keys})


def volume_key(path, name):
    # Podman volume export produces plain tar. Use the same bounded, no-follow
    # descriptor reader as other sources; reject compressed input as unsupported.
    matches = []
    with tarfile.open(fileobj=io.BytesIO(read_source(path)), mode='r:') as archive:
        for member in archive:
            if member.name.removeprefix('./') == name:
                if not member.isfile() or member.size > 4096:
                    raise ValueError('private key not a regular file')
                matches.append(archive.extractfile(member).read())
    if len(matches) != 1:
        raise ValueError('private key missing or duplicated')
    return private_key(matches[0])


def read_source(path):
    # Synthetic fixtures live under the runner's private directory. Reject a
    # symlink at the leaf and inspect the opened descriptor, avoiding a
    # check/open race. NONBLOCK lets us reject FIFOs without waiting on a writer.
    # Parent directories are trusted; this is not a general path sandbox.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('source is not a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(MAX_FILE + 1)
        if not data or len(data) > MAX_FILE:
            raise ValueError('source missing or too large')
        return data
    finally:
        os.close(fd)


def main():
    try:
        kind, path = sys.argv[1:3]
        if kind == 'volume':
            values = volume_key(path, sys.argv[3])
        else:
            data = read_source(path)
            values = {'pem': pem_values, 'client': client_keys}[kind](data)
        sys.stdout.write(json.dumps(values, ensure_ascii=True))
    except Exception:
        print('Synthetic private source missing, invalid or unsupported', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
