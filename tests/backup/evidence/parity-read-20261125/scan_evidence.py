"""Scans the evidence folder for secrets: every value of the lab credential file (read here, never printed), the fixture passwords, and
credential-shaped text. Prints counts and file names only. usage: scan_evidence.py DIR"""
import os, re, shlex, sys
DIR = sys.argv[1]
values = set()
path = os.path.expanduser('~/.woowbk-lab/secrets/ha-import-creds.env')
try:
    for line in open(path):
        for tok in shlex.split(line, comments=True):
            if '=' in tok:
                v = tok.split('=', 1)[1]
                if len(v) >= 6:
                    values.add(v)
except OSError:
    pass
sys.path.insert(0, '/tmp/parity-read-20261125')
try:
    from tests.backup import hafixtures as hx
    values.update(v for v in (hx.PASSWORD, hx.WRONG_PASSWORD, *hx.SECRETS) if isinstance(v, str) and len(v) >= 6)
except Exception:
    pass
shape = re.compile(rb'(?i)(password|passwd|secret|token|api[_-]?key|credential)\s*[:=]\s*[\'"]?[A-Za-z0-9+/_\-]{12,}')
long_blob = re.compile(rb'[A-Za-z0-9+/]{60,}={0,2}')
hits, files = [], 0
for root, _dirs, names in os.walk(DIR):
    for name in names:
        files += 1
        data = open(os.path.join(root, name), 'rb').read()
        for v in values:
            if v.encode() in data:
                hits.append((name, 'a known secret value'))
        if shape.search(data):
            hits.append((name, 'credential-shaped text'))
        for blob in long_blob.findall(data):
            if len(set(blob)) < 6 or re.fullmatch(rb'[0-9a-f]{64}', blob):  # a run of one letter, a SHA-256 digest: no secret
                continue
            hits.append((name, 'long base64-like text'))
            break
print({'files': files, 'known_values_checked': len(values), 'hits': hits})
sys.exit(1 if hits else 0)
