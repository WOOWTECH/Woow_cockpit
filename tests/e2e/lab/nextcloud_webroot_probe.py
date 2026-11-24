#!/usr/bin/env python3
"""What keeps the users' files private on this device (dev-e, lab only, never acceptance).

Measured on dev-e's own running Nextcloud, under the dev-e lock, everything put back by the same shell (trap):
  1. as installed: an ordinary static file is served (control), a user's picture below /data/ is not;
  2. with data/.htaccess moved aside for one request: is that picture served without a login?
  3. with a probe folder in the data dir that holds its own .htaccess (a: `Require all granted` alone; b: with the older
     `Order`/`Allow`/`Satisfy` words too, as many site folders have; rewriting off): are its picture and its PHP file
     served, although data/.htaccess denies everything?
  4. afterwards: the probe folder is gone, data/.htaccess is the same file (inode, size, time, SHA-256).
This is why ha_nextcloud writes DATA_HTACCESS itself and refuses any other .htaccess in HA's data directory.
    flock -w 3600 /tmp/woowbk-dev-e-mutation.lock python3 -I tests/e2e/lab/nextcloud_webroot_probe.py <evidence.json>
stdout and the evidence hold HTTP status codes and booleans only.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

LP = str(Path.home() / '.woowbk-lab' / 'bin' / 'labpodman')
OWNER = [LP, 'exec', '-i', 'woowbk-dev-e', '/usr/local/bin/woowbk-owner']
SCRIPT = r'''
set -u
cd /var/www/html/data || exit 3
code() { curl -s -o /tmp/woowbk-probe.out -w '%{http_code}' "http://127.0.0.1/$1"; }
put_back() {
    [ -e .woowbk-htaccess-aside ] && mv .woowbk-htaccess-aside .htaccess
    rm -f woowbkprobe/x.png woowbkprobe/x.php woowbkprobe/.htaccess /tmp/woowbk-probe.out
    [ -d woowbkprobe ] && rmdir woowbkprobe
    :
}
trap put_back EXIT
[ ! -e .woowbk-htaccess-aside ] && [ ! -e woowbkprobe ] && [ -f .htaccess ] || exit 4
before=$(stat -c '%i %s %Y' .htaccess; sha256sum < .htaccess)
pic=$(find . -type f -path './*/files/*' \( -name '*.jpg' -o -name '*.png' \) | grep -v ' ' | LC_ALL=C sort | head -n 1)
[ -n "$pic" ] || exit 5
pic=data/${pic#./}
echo "control=$(code core/img/logo/logo.svg)"
echo "installed_picture=$(code "$pic")"
mv .htaccess .woowbk-htaccess-aside
echo "no_htaccess_picture=$(code "$pic")"
mv .woowbk-htaccess-aside .htaccess
mkdir woowbkprobe
printf 'RewriteEngine off\nRequire all granted\n' > woowbkprobe/.htaccess
cp "/var/www/html/core/img/logo/logo.png" woowbkprobe/x.png 2>/dev/null || printf 'x' > woowbkprobe/x.png
printf '%s' '<?php echo "probe-".(6*7);' > woowbkprobe/x.php
echo "require_only_picture=$(code data/woowbkprobe/x.png)"
printf 'RewriteEngine off\nRequire all granted\nOrder Deny,Allow\nAllow from all\nSatisfy Any\n' > woowbkprobe/.htaccess
echo "own_htaccess_picture=$(code data/woowbkprobe/x.png)"
echo "own_htaccess_php=$(code data/woowbkprobe/x.php)"
echo "own_htaccess_php_ran=$(grep -c '^probe-42$' /tmp/woowbk-probe.out)"
put_back
echo "after_picture=$(code "$pic")"
[ "$before" = "$(stat -c '%i %s %Y' .htaccess; sha256sum < .htaccess)" ] && echo same_file=1 || echo same_file=0
[ -e woowbkprobe ] && echo probe_left=1 || echo probe_left=0
'''


def main(argv):
    target = Path(argv[0])
    if target.exists():
        raise SystemExit('evidence file exists; never overwrite an attempt')
    started = time.monotonic()
    commit = subprocess.run(['git', '-C', str(Path(__file__).resolve().parents[3]), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True).stdout.strip()
    iso = subprocess.run([LP, 'inspect', 'woowbk-dev-e', '--format',
                          '{{.State.Running}} {{.HostConfig.NetworkMode}} {{json .HostConfig.PortBindings}}'],
                         capture_output=True, timeout=60).stdout.decode().strip()
    proc = subprocess.run(OWNER + ['podman', 'exec', '-i', '-u', 'www-data', 'nextcloud-app', 'sh', '-s'],
                          input=SCRIPT.encode(), capture_output=True, timeout=600)
    found = {}
    for line in proc.stdout.decode('utf-8', 'replace').splitlines():
        key, sep, value = line.partition('=')
        if sep and key.replace('_', '').isalpha() and value.isdigit():
            found[key] = int(value)
    put_back = found.get('same_file') == 1 and found.get('probe_left') == 0 and proc.returncode == 0
    denied = {403, 404}
    checks = {
        'dev-e isolation true none {}': iso == 'true none {}',
        'as installed: a static file is served, a user picture below /data/ is not':
            found.get('control') == 200 and found.get('installed_picture') in denied,
        'put back exactly: data/.htaccess is the same file, the probe folder is gone': put_back,
        'afterwards the user picture is denied again': found.get('after_picture') in denied}
    doc = {'kind': 'nextcloud-webroot-probe', 'date': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'source_commit': commit,
           'device': 'woowbk-dev-e', 'codes': found, 'checks': {k: 'PASS' if v else 'FAIL' for k, v in checks.items()},
           'measured': {
               'without data/.htaccess the picture is served without a login': found.get('no_htaccess_picture') == 200,
               'a folder whose own .htaccess says only Require all granted is served': found.get('require_only_picture') == 200,
               'a folder with its own .htaccess is served although data/.htaccess denies everything':
                   found.get('own_htaccess_picture') == 200,
               'a PHP file in such a folder runs': found.get('own_htaccess_php_ran') == 1},
           'exit': proc.returncode, 'elapsed_s': round(time.monotonic() - started, 1),
           'acceptance': 'not acceptance (why DATA_HTACCESS is written and every other .htaccess refused)'}
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'x', encoding='utf-8') as handle:
        json.dump(doc, handle, indent=1, ensure_ascii=False)
        handle.write('\n')
    for name, value in {**doc['checks'], **{k: v for k, v in doc['measured'].items()}}.items():
        print(f'{name}: {value}')
    return 0 if all(checks.values()) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
