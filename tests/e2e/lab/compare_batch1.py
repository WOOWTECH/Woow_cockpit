#!/usr/bin/env python3
"""Compare the reference host's installed files of Omnigent, Hermes, EMQX and Headscale with dev-d's (read only).

    python3 -I tests/e2e/lab/compare_batch1.py [omnigent] [hermes] [emqx] [headscale]     # default: all four

Run as the account that owns the apps on the host (it reads ~/.config of that account and the host's
/etc/woowtech-cockpit/backup/apps/*.json; dev-d's copies through labpodman as appowner). Prints, per app:
  * Quadlet files, the packages' own units and rendered configs: identical, or a unified diff (these hold no secret:
    secrets are podman secrets referenced by name);
  * Headscale's htpasswd: only whether it is identical (it holds a password hash);
  * the env file: whether the key sets and their order match, then each key whose value differs, with both values
    only for allow-listed non-secret keys (binds, ports, URLs, modes) and "set"/"empty" for everything else;
  * the catalog entry: the keys that differ and what is only on one side.
The output names the host's own addresses and URLs: keep it in the lab evidence, not in the repository."""
import difflib, hashlib, json, os, re, subprocess, sys
HOME = os.path.expanduser('~')
LP = os.path.join(HOME, '.woowbk-lab/bin/labpodman')
Q = '.config/containers/systemd/'
U = '.config/systemd/user/'
FILES = {
    'omnigent': [Q + f for f in ('omnigent.network', 'omnigent-pi.volume', 'omnigent-postgres.volume', 'omnigent-server.volume',
                                 'omnigent-postgres.container', 'omnigent-server.container', 'omnigent-runner.container')]
                + [U + 'omnigent-server-health.service', U + 'omnigent-server-health.timer'],
    'hermes': [Q + f for f in ('hermes.network', 'hermes-data.volume', 'hermes-postgres-data.volume', 'hermes-redis-data.volume',
                               'hermes-postgres.container', 'hermes-redis.container', 'hermes-agent.container')]
              + [U + 'hermes-provision.service'],
    'emqx': [Q + f for f in ('emqx.network', 'emqx-data.volume', 'emqx-log.volume', 'emqx.container', 'emqx-entrance.container')]
            + ['.config/emqx/base.hocon', '.config/emqx/acl.conf', '.config/emqx/entrance.conf'],
    'headscale': [Q + f for f in ('headscale.network', 'headscale-data.volume', 'headscale-run.volume', 'headplane-data.volume',
                                  'headscale-ngrok.container', 'headscale.container', 'headplane.container',
                                  'headscale-entrance.container')]
                 + ['.config/headscale/' + f for f in ('headscale/config.yaml', 'headscale/policy.json', 'headscale/extra_records.json',
                                                       'headplane/config.yaml', 'entrance/nginx.conf', 'ngrok-sync.py')],
}
HASH_ONLY = {'headscale': ['.config/headscale/entrance/htpasswd']}
ENVS = {'omnigent': '.config/omnigent/omnigent.env', 'hermes': '.config/hermes/hermes.env', 'emqx': '.config/emqx/emqx.env',
        'headscale': '.config/headscale/headscale.env'}
SAFE_KEYS = re.compile(r'(BIND|PORT|PORT_[A-Z]+|MEMORY|CPUS|LEVEL|USERNAME|_USER|STATE|NGROK|NGROK_MODE|NGROK_ENABLED|'
                       r'BASE_DOMAIN|PREFIX|EXPIRY|MAGIC_DNS|NAMESERVERS|POLICY_MODE|CREATE_DEFAULT_USER|COOKIE_SECURE|'
                       r'IMAGE_TARGET|_VOLUME|URL|ORIGIN|NGROK_DOMAIN|NGROK_REMOTE_ADDR)$')
SECRETISH = re.compile(r'PWD|PASS|KEY|TOKEN|SECRET|CRED|AUTH|SIG', re.I)

def prod(rel):
    try:
        return open(os.path.join(HOME, rel), encoding='utf-8').read()
    except FileNotFoundError:
        return None

def lab(rel):
    p = subprocess.run([LP, 'exec', '-i', 'woowbk-dev-d', '/usr/local/bin/woowbk-owner', 'cat', '/home/appowner/' + rel],
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None

def env(text):
    out = {}
    for line in (text or '').splitlines():
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out

for app in sys.argv[1:] or FILES:
    print(f'===== {app}')
    for rel in FILES[app]:
        a, b = prod(rel), lab(rel)
        if a is None or b is None:
            print(f'  {rel}: prod {"missing" if a is None else "present"}, dev-d {"missing" if b is None else "present"}')
            continue
        if a == b:
            print(f'  {rel}: identical')
            continue
        diff = [l for l in difflib.unified_diff(a.splitlines(), b.splitlines(), 'prod', 'dev-d', n=0, lineterm='')
                if not l.startswith(('---', '+++', '@@'))]
        print(f'  {rel}: {len(diff)} changed lines')
        for l in diff:
            print('     ' + l[:220])
    for rel in HASH_ONLY.get(app, []):
        a, b = prod(rel), lab(rel)
        print(f'  {rel}: ' + ('identical' if a == b else 'differs (hash of a different generated password; not shown)'))
    a, b = env(prod(ENVS[app])), env(lab(ENVS[app]))
    keys_a, keys_b = list(a), list(b)
    print(f'  {ENVS[app]}: keys {"same set" if set(keys_a) == set(keys_b) else "DIFFER"}'
          f'{", same order" if keys_a == keys_b else ", other order"}')
    for k in sorted(set(a) | set(b)):
        if a.get(k) == b.get(k):
            continue
        if SAFE_KEYS.search(k) and not SECRETISH.search(k.replace('NGROK_ENABLED', '')):
            print(f'     {k}: prod={a.get(k)!r} dev-d={b.get(k)!r}')
        else:
            print(f'     {k}: prod={"set" if a.get(k) else "empty"} dev-d={"set" if b.get(k) else "empty"} (value not shown)')
    pa = f'/etc/woowtech-cockpit/backup/apps/{app}.json'
    ca = json.load(open(pa))
    cb = json.loads(subprocess.run([LP, 'exec', 'woowbk-dev-d', 'cat', pa], capture_output=True, text=True, check=True).stdout)
    diffs = [k for k in sorted(set(ca) | set(cb)) if ca.get(k) != cb.get(k)]
    print(f'  catalog {app}.json: differing keys {diffs}')
    for k in diffs:
        if isinstance(ca.get(k), list) and isinstance(cb.get(k), list):
            print(f'     {k}: only on prod {[x for x in ca[k] if x not in cb[k]]}, only on dev-d {[x for x in cb[k] if x not in ca[k]]}')
        elif isinstance(ca.get(k), dict) and isinstance(cb.get(k), dict):
            for kk in sorted(set(ca[k]) | set(cb[k])):
                if ca[k].get(kk) != cb[k].get(kk):
                    print(f'     {k}.{kk}: only on prod {[x for x in ca[k].get(kk, []) if x not in cb[k].get(kk, [])]}')
        else:
            print(f'     {k}: prod={ca.get(k)!r} dev-d={cb.get(k)!r}')
