#!/usr/bin/env python3
"""Compare the reference host's installed files of Nextcloud, code-server and OpenDesign with dev-e's (read only).

    python3 -I tests/e2e/lab/compare_batch2.py [nextcloud] [code-server] [opendesign]    # default: the apps dev-e has

Run as the account that owns the apps on the host (it reads ~/.config of that account and the host's
/etc/woowtech-cockpit/backup/apps/*.json; dev-e's copies through labpodman as appowner). Prints, per app:
  * Quadlet files, the packages' own units and rendered configs: identical, or the changed lines (they hold no secret
    value: secrets are podman secrets referenced by name; any other line with a secret-like word is masked);
  * the env file: whether the key sets and their order match, then each key whose value differs, with both values only
    for allow-listed tuning keys (binds, ports, limits, data paths) and "set"/"empty" for everything else, URLs included;
  * the catalog entry: the keys that differ;
  * the image of every container: the host's image ID for the Quadlet reference and the ID dev-e's container runs.
The only host Podman command is `podman image inspect <reference>`. The output can name the host's data paths: keep it
in the lab evidence, not in the repository."""
import difflib, json, os, re, subprocess, sys
HOME = os.path.expanduser('~')
LP = os.path.join(HOME, '.woowbk-lab/bin/labpodman')
DEVICE = 'woowbk-dev-e'
Q = '.config/containers/systemd/'
U = '.config/systemd/user/'
FILES = {
    'nextcloud': [Q + f for f in ('nextcloud.network', 'nextcloud-db.container', 'nextcloud-redis.container',
                                  'nextcloud-app.container', 'nextcloud-office.container', 'nextcloud-gateway.container')]
                 + [U + f for f in ('nextcloud.target', 'nextcloud-cron.service', 'nextcloud-cron.timer')]
                 + ['.config/nextcloud/gateway.conf'],
    'code-server': [Q + f for f in ('code-server.container', 'woow-code-server-pi.volume', 'woow-code-server-ide.volume',
                                    'woow-code-server-extensions.volume')]
                   + [U + f for f in ('code-server-health.service', 'code-server-health.timer')],
    'opendesign': [Q + f for f in ('open-design.network', 'open-design-data.volume', 'open-design-mcp-data.volume',
                                   'open-design-mcp-run.volume', 'open-design.container', 'open-design-mcp.container',
                                   'open-design-nginx.container', 'open-design-terminal.container')]
                  + ['.config/open-design/' + f for f in ('nginx.conf', 'nginx-auth.conf', 'nginx-paseo.conf',
                                                          'od-export-bridge.js')],
}
HOST_ONLY = {'opendesign': [U + 'open-design-local-health.service', U + 'open-design-local-health.timer']}
ENVS = {'nextcloud': '.config/nextcloud/nextcloud.env', 'code-server': '.config/woow-code-server/woow-code-server.env',
        'opendesign': '.config/open-design/open-design.env'}
CATALOG = {'nextcloud': 'nextcloud', 'opendesign': 'open-design', 'code-server': None}
FIRST = {'nextcloud': Q + 'nextcloud-app.container', 'code-server': Q + 'code-server.container',
         'opendesign': Q + 'open-design.container'}
SAFE_KEYS = re.compile(r'(BIND|PORT|MEMORY|CPUS|_DIR|LIMIT|REGION|_PASEO|TAILSCALE|ADMIN_USER|WORKSPACE|GITCONFIG|HOST_BIN|'
                       r'PROVIDER|MODEL|SANDBOX|TERMINATION|NODE_OPTIONS|WOOW_OD_AUTH)$')
SECRETISH = re.compile(r'PWD|PASS|KEY|TOKEN|SECRET|CRED|AUTH|SIG', re.I)


def prod(rel):
    try:
        return open(os.path.join(HOME, rel), encoding='utf-8').read()
    except FileNotFoundError:
        return None


def lab(rel):
    p = subprocess.run([LP, 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner', 'cat', '/home/appowner/' + rel],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def masked(line):
    body = line[1:]
    if body.startswith('Secret=') or not SECRETISH.search(body):
        return line
    return line[0] + re.sub(r'([=:]\s*).*$', r'\1<masked>', body)


def env(text):
    out = {}
    for line in (text or '').splitlines():
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def host_image(ref):
    p = subprocess.run(['podman', 'image', 'inspect', '--format', '{{.Id}}', ref], capture_output=True, text=True)
    return p.stdout.strip()[:12] if p.returncode == 0 else 'missing'


def lab_container_image(name):
    p = subprocess.run([LP, 'exec', '-i', DEVICE, '/usr/local/bin/woowbk-owner', 'podman', 'container', 'inspect',
                        '--format', '{{.Image}}', name], capture_output=True, text=True)
    return p.stdout.strip()[:12] if p.returncode == 0 else 'absent'


apps = sys.argv[1:] or [a for a in FILES if lab(FIRST[a]) is not None]
for app in apps:
    print(f'===== {app}')
    for rel in FILES[app]:
        a, b = prod(rel), lab(rel)
        if a is None or b is None:
            print(f'  {rel}: prod {"missing" if a is None else "present"}, dev-e {"missing" if b is None else "present"}')
            continue
        if a == b:
            print(f'  {rel}: identical')
            continue
        diff = [l for l in difflib.unified_diff(a.splitlines(), b.splitlines(), 'prod', 'dev-e', n=0, lineterm='')
                if not l.startswith(('---', '+++', '@@'))]
        print(f'  {rel}: {len(diff)} changed lines')
        for l in diff:
            print('     ' + masked(l)[:220])
    for rel in HOST_ONLY.get(app, []):
        print(f'  {rel}: prod {"present" if prod(rel) is not None else "missing"}, dev-e '
              f'{"present" if lab(rel) is not None else "missing"} (not part of the package)')
    a, b = env(prod(ENVS[app])), env(lab(ENVS[app]))
    keys_a, keys_b = list(a), list(b)
    print(f'  {ENVS[app]}: keys {"same set" if set(keys_a) == set(keys_b) else "DIFFER"}'
          f'{", same order" if keys_a == keys_b else ", other order"}')
    for k in sorted(set(a) | set(b)):
        if a.get(k) == b.get(k):
            continue
        if SAFE_KEYS.search(k) and not SECRETISH.search(k.replace('WOOW_OD_AUTH', '')):
            print(f'     {k}: prod={a.get(k)!r} dev-e={b.get(k)!r}')
        else:
            print(f'     {k}: prod={"set" if a.get(k) else "empty"} dev-e={"set" if b.get(k) else "empty"} (value not shown)')
    cid = CATALOG[app]
    if cid:
        pa = f'/etc/woowtech-cockpit/backup/apps/{cid}.json'
        ca = json.load(open(pa))
        p = subprocess.run([LP, 'exec', DEVICE, 'cat', pa], capture_output=True, text=True)
        if p.returncode != 0:
            print(f'  catalog {cid}.json: not installed in dev-e')
        else:
            cb = json.loads(p.stdout)
            print(f'  catalog {cid}.json: differing keys {[k for k in sorted(set(ca) | set(cb)) if ca.get(k) != cb.get(k)]}')
    else:
        print('  catalog: the host has no entry for this app (not onboarded)')
    for rel in FILES[app]:
        if not rel.endswith('.container'):
            continue
        text = prod(rel) or ''
        m = re.search(r'^Image=(.+)$', text, re.M)
        n = re.search(r'^ContainerName=(.+)$', text, re.M)
        if m and n:
            hi, li = host_image(m.group(1).strip()), lab_container_image(n.group(1).strip())
            print(f'  image {n.group(1).strip()}: host {hi} dev-e {li} {"same" if hi == li else "DIFFERENT"}')
