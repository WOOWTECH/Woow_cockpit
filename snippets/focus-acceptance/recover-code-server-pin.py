#!/usr/bin/env python3
"""Run as root INSIDE leased dev-e, after the existing image transfer completes.

Use existing heavy.sh + dev-e mutation lock. Prints only fixed fields and hashes.
Never runs the package installer. Stops unless the unit is inactive and the
already-loaded image has the exact reviewed config ID. The private old unit is
retained before changing only its Image= line.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

OWNER = '/usr/local/bin/woowbk-owner'
EXPECTED = '7999790230ec6267ae55b82ab0e8d725add734658d15a8ec7a139a6d4087b0a1'
UNIT = Path('/home/appowner/.config/containers/systemd/code-server.container')
PRIOR = Path('/home/appowner/.woowbk-pin-recovery-focus-20261127/code-server.container.before')


def owner(*args, check=True):
    p = subprocess.run([OWNER, *args], capture_output=True, timeout=60)
    if check and p.returncode:
        raise RuntimeError('owner operation refused; private output withheld')
    return p


if not UNIT.is_file() or UNIT.is_symlink():
    raise SystemExit('unexpected installed Quadlet')
state = owner('systemctl', '--user', 'is-active', 'code-server.service', check=False).stdout.strip()
if state != b'inactive':
    raise SystemExit('code-server must be inactive')
image = owner('podman', 'image', 'inspect', '--format', '{{.Id}} {{.Digest}}', EXPECTED).stdout.decode().strip().split()
if len(image) != 2 or image[0].removeprefix('sha256:') != EXPECTED or not re.fullmatch('sha256:[0-9a-f]{64}', image[1]):
    raise SystemExit('loaded image identity is not the reviewed config')
pin = 'ghcr.io/woowtech/woow-code-server-amd64:4.139.1-8@' + image[1]
if owner('podman', 'image', 'exists', pin, check=False).returncode:
    raise SystemExit('new digest reference is unavailable locally')
old = UNIT.read_bytes()
lines = old.decode().splitlines(keepends=True)
positions = [i for i, line in enumerate(lines) if line.startswith('Image=')]
if len(positions) != 1:
    raise SystemExit('expected exactly one installed Image line')
index = positions[0]
lines[index] = 'Image=' + pin + '\n'
new = ''.join(lines).encode()
changed = new != old
if changed:
    PRIOR.parent.mkdir(mode=0o700, exist_ok=False)
    with os.fdopen(os.open(PRIOR, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
        out.write(old)
    UNIT.write_bytes(new)  # existing inode, owner and permissions preserved
    owner('systemctl', '--user', 'daemon-reload')
    if UNIT.read_bytes() != new:
        raise SystemExit('installed pin changed unexpectedly')
print(json.dumps({'same_expected_config_id': True, 'expected_config_id': EXPECTED,
                  'unit_state_before': 'inactive', 'image_line_changed': changed,
                  'only_image_line_changed': all(a == b for i, (a, b) in enumerate(zip(old.decode().splitlines(keepends=True), lines)) if i != index),
                  'old_unit_retained_private': PRIOR.is_file() if changed else False,
                  'before_sha256': hashlib.sha256(old).hexdigest(), 'after_sha256': hashlib.sha256(new).hexdigest(),
                  'loaded_digest': image[1]}))
