#!/usr/bin/env python3
"""Install/verify/roll back WOOWTECH Cockpit packages; Python stdlib only."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
STATE = 'var/lib/woowtech-cockpit/installed.json'
BACKUPS = 'var/backups/woowtech-cockpit-source'
BRAND = 'etc/cockpit/branding'
PREVIEW = 'usr/local/share/cockpit/woowtechpreview'
SERVICES = 'usr/local/share/cockpit/woowtechservices'
APPS = 'usr/local/share/cockpit/woowtechapps'
HELPER = 'usr/local/libexec/woowtech-cockpit-services'
SERVICE_CONFIG = 'etc/woowtech-cockpit/services.json'
PODMAN = 'usr/share/cockpit/podman'
NATIVE = ('systemd/logs.html', 'systemd/services.html', 'systemd/hwinfo.html',
          'systemd/terminal.html', 'networkmanager/firewall.html')
LINK = '  <link href="../../static/branding.css" rel="stylesheet" />\n'
SHELL_SCRIPT = '  <script defer src="../../static/mobile-navigation.js"></script>\n'
SHOTS = ('00-login', '01-overview', '02-logs', '03-storage', '04-network',
         '05-podman', '06-accounts', '07-services', '08-applications',
         '09-updates', '10-terminal', '11-hardware', '12-metrics',
         '13-podman-images', '14-mobile-login', '15-mobile-overview',
         'admin-auth-prompt')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(root, relative):
    rel = Path(relative)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise ValueError(f'Unsafe relative path: {relative}')
    path = root
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f'Refusing symlink target: {path}')
    return path


def file_hash(path):
    return digest(path.read_bytes()) if path.is_file() else None


def atomic_write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.woow-cockpit-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def cockpit_version(root):
    status_file = safe_path(root, 'var/lib/dpkg/status')
    if not status_file.is_file():
        raise ValueError('Ubuntu/Debian dpkg database missing; install Cockpit first.')
    for block in status_file.read_text().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
        if fields.get('Package') == 'cockpit-bridge' and fields.get('Status') == 'install ok installed':
            version = fields['Version']
            match = re.match(r'(?:\d+:)?(\d+)', version)
            if not match or int(match[1]) < 362:
                raise ValueError(f'Cockpit {version}: this PF6 theme requires Cockpit >= 362. Use Ubuntu backports.')
            return version
    raise ValueError('cockpit-bridge is not installed. Run scripts/bootstrap-ubuntu.sh first.')


def source_files(directory):
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'Source symlink is not supported: {path}')
        if path.is_file():
            yield path.relative_to(directory).as_posix(), path.read_bytes()


def desired_files(root, include_preview=True, screenshots=None, include_services=True, service_owners=None):
    version = cockpit_version(root)
    desired = {}
    for name, data in source_files(SOURCE / 'branding'):
        desired[f'{BRAND}/{name}'] = (data, 'branding')
    if include_preview:
        for name, data in source_files(SOURCE / 'preview'):
            # Locally captured runtime evidence is always opt-in, even if in the checkout.
            if name.startswith(('screenshots/', 'layout-images/')):
                continue
            desired[f'{PREVIEW}/{name}'] = (data, 'preview')
        for directory in ('assets', 'fonts'):
            for name, data in source_files(SOURCE / 'branding' / directory):
                desired[f'{PREVIEW}/{directory}/{name}'] = (data, 'preview')
        desired[f'{PREVIEW}/assets/favicon.ico'] = ((SOURCE / 'branding/favicon.ico').read_bytes(), 'preview')
        for name, data in source_files(SOURCE / 'licenses'):
            desired[f'{PREVIEW}/licenses/{name}'] = (data, 'preview')
        if (SOURCE / 'NOTICE.md').is_file():
            desired[f'{PREVIEW}/NOTICE.md'] = ((SOURCE / 'NOTICE.md').read_bytes(), 'preview')
    if screenshots:
        if not include_preview:
            raise ValueError('--screenshots needs the preview package.')
        for name in SHOTS:
            src = Path(screenshots) / f'{name}.png'
            if src.is_file() and not src.is_symlink():
                data = src.read_bytes()
                if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) > 30 * 1024 * 1024:
                    raise ValueError(f'Invalid or oversized PNG: {src.name}')
                desired[f'{PREVIEW}/screenshots/{src.name}'] = (data, 'screenshot')
    if include_services and (SOURCE / 'services/service-manager.py').is_file():
        for name in ('manifest.json', 'index.html', 'service.css', 'service.js'):
            desired[f'{SERVICES}/{name}'] = ((SOURCE / 'services' / name).read_bytes(), 'services')
        if (SOURCE / 'apps-catalog').is_dir():
            for name, data in source_files(SOURCE / 'apps-catalog'):
                desired[f'{APPS}/{name}'] = (data, 'apps-catalog')
        desired[HELPER] = ((SOURCE / 'services/service-manager.py').read_bytes(), 'helper')
        config_path = safe_path(root, SERVICE_CONFIG)
        if service_owners is not None:
            owners = list(dict.fromkeys(service_owners))
            for owner in owners:
                if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}\$?', owner) or owner == 'root':
                    raise ValueError(f'Invalid service owner: {owner}')
                if root == Path('/'):
                    pwd.getpwnam(owner)
            config_data = (json.dumps({'owners': owners}, indent=2) + '\n').encode()
        elif config_path.is_file():
            config_data = config_path.read_bytes()
        else:
            config_data = b'{"owners": []}\n'
        config = json.loads(config_data)
        if not isinstance(config, dict) or not isinstance(config.get('owners'), list):
            raise ValueError('Invalid service owner configuration.')
        desired[SERVICE_CONFIG] = (config_data, 'service-config')
    elif service_owners is not None:
        raise ValueError('--service-owner requires the services package.')
    # This integration is built from exactly cockpit-podman 124. Never overwrite
    # a newer distribution bundle with an older implementation.
    podman_bundle = SOURCE / 'native/podman/dist/index.js.gz'
    package_status = safe_path(root, 'var/lib/dpkg/status').read_text()
    native_supported = bool(re.search(r'(?m)^Package: cockpit-podman\n(?:(?!\n\n)[\s\S])*?^Version: (?:\d+:)?124(?:[-+~.]|$)', package_status))
    if include_services and native_supported and podman_bundle.is_file():
        for suffix in ('', '.gz'):
            target = f'{PODMAN}/index.js{suffix}'
            if safe_path(root, target).is_file():
                data = podman_bundle.read_bytes()
                desired[target] = (data if suffix else gzip.decompress(data), 'native-podman-integration')
        for name, data in source_files(SOURCE / 'native/podman/dist/licenses'):
            desired[f'{PODMAN}/woowtech-licenses/{name}'] = (data, 'native-podman-license')
        desired[f'{PODMAN}/index.js.LEGAL.txt'] = ((SOURCE / 'native/podman/dist/index.js.LEGAL.txt').read_bytes(), 'native-podman-license')
    for name in NATIVE:
        relative = f'usr/share/cockpit/{name}'
        target = safe_path(root, relative)
        compressed = False
        if not target.exists():
            relative += '.gz'
            target = safe_path(root, relative)
            compressed = True
        if not target.exists():
            continue  # Optional Cockpit application not installed.
        original = target.read_bytes()
        html = gzip.decompress(original).decode() if compressed else original.decode()
        if 'static/branding.css' not in html:
            if '</head>' not in html:
                raise ValueError(f'Unknown native template: {relative}; no changes applied.')
            html = html.replace('</head>', LINK + '</head>', 1)
            data = gzip.compress(html.encode(), mtime=0) if compressed else html.encode()
        else:
            data = original
        desired[relative] = (data, 'native-stylesheet-link')
    # Load the mobile shortcut only in the shell; the script is a separately
    # installed local branding asset, and does not replace Cockpit's bundle.
    relative = 'usr/share/cockpit/shell/index.html'
    target = safe_path(root, relative)
    if target.is_file():
        html = target.read_text()
        if 'static/mobile-navigation.js' not in html:
            if '</head>' not in html:
                raise ValueError(f'Unknown native template: {relative}; no changes applied.')
            html = html.replace('</head>', SHELL_SCRIPT + '</head>', 1)
        desired[relative] = (html.encode(), 'native-mobile-navigation')
    for relative in desired:
        target = safe_path(root, relative)
        if target.exists() and not target.is_file():
            raise ValueError(f'Target is not a regular file: {target}')
    state = {'schema': 1, 'source_version': (SOURCE / 'VERSION').read_text().strip(),
             'cockpit_version': version, 'preview': include_preview,
             'files': {name: {'sha256': digest(data), 'role': role}
                       for name, (data, role) in sorted(desired.items())}}
    desired[STATE] = ((json.dumps(state, indent=2, ensure_ascii=False) + '\n').encode(), 'state')
    safe_path(root, STATE)
    return desired, state


def changes(root, desired):
    return [name for name, (data, _) in desired.items()
            if file_hash(safe_path(root, name)) != digest(data)
            or (name in (HELPER, SERVICE_CONFIG) and
                (stat.S_IMODE(safe_path(root, name).stat().st_mode) != desired_mode(name)
                 or (root == Path('/') and safe_path(root, name).stat().st_uid != 0)))]


def desired_mode(name):
    if name == HELPER:
        return 0o755
    return 0o600 if name in (STATE, SERVICE_CONFIG) else 0o644


def restore_records(root, backup, records):
    for rec in reversed(records):
        target = safe_path(root, rec['path'])
        if rec['existed']:
            content = safe_path(backup / 'files', rec['path']).read_bytes()
            if digest(content) != rec['before_sha256']:
                raise ValueError(f'Corrupt backup: {rec["path"]}')
            atomic_write(target, content, rec['mode'])
            if os.geteuid() == 0:
                os.chown(target, rec['uid'], rec['gid'])
        elif target.exists():
            target.unlink()


def install(root, desired, state):
    names = changes(root, desired)
    if not names:
        return {'changed': 0, 'status': 'already-current'}
    backup_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = safe_path(root, f'{BACKUPS}/{backup_id}')
    backup.mkdir(parents=True, mode=0o700)
    records = []
    for name in names:
        target = safe_path(root, name)
        rec = {'path': name, 'existed': target.exists(), 'before_sha256': file_hash(target),
               'after_sha256': digest(desired[name][0])}
        if target.exists():
            st = target.stat()
            rec.update(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
            atomic_write(safe_path(backup / 'files', name), target.read_bytes(), 0o600)
        records.append(rec)
    journal = {'schema': 1, 'id': backup_id, 'status': 'prepared', 'files': records}
    atomic_write(backup / 'transaction.json', json.dumps(journal, indent=2).encode(), 0o600)
    applied = []
    try:
        for rec in records:
            atomic_write(safe_path(root, rec['path']), desired[rec['path']][0], desired_mode(rec['path']))
            applied.append(rec)
    except Exception:
        restore_records(root, backup, applied)
        journal['status'] = 'failed-restored'
        atomic_write(backup / 'transaction.json', json.dumps(journal, indent=2).encode(), 0o600)
        raise
    journal['status'] = 'installed'
    atomic_write(backup / 'transaction.json', json.dumps(journal, indent=2).encode(), 0o600)
    return {'status': 'installed', 'changed': len(names), 'backup_id': backup_id,
            'backup': str(backup), 'source_version': state['source_version']}


def allowed_target(name):
    return name in (STATE, HELPER, SERVICE_CONFIG, 'usr/share/cockpit/shell/index.html', f'{PODMAN}/index.js', f'{PODMAN}/index.js.gz', f'{PODMAN}/index.js.LEGAL.txt') or name.startswith((BRAND + '/', PREVIEW + '/', SERVICES + '/', APPS + '/', PODMAN + '/woowtech-licenses/')) or name in {
        'usr/share/cockpit/' + n + suffix for n in NATIVE for suffix in ('', '.gz')}


def rollback(root, backup_id):
    if not re.fullmatch(r'\d{8}T\d{12}Z', backup_id):
        raise ValueError('Use the backup_id printed by install (not a filesystem path).')
    backup = safe_path(root, f'{BACKUPS}/{backup_id}')
    manifest = backup / 'transaction.json'
    journal = json.loads(manifest.read_text())
    if journal['status'] not in ('installed', 'prepared'):
        raise ValueError(f'Transaction is {journal["status"]}; refusing repeat rollback.')
    records = journal['files']
    for rec in records:
        if not allowed_target(rec['path']):
            raise ValueError('Backup contains an unmanaged path.')
        current = file_hash(safe_path(root, rec['path']))
        allowed = {rec['after_sha256']}
        if journal['status'] == 'prepared':
            allowed.add(rec['before_sha256'])
        if current not in allowed:
            raise ValueError(f'Changed since installation: {rec["path"]}; refusing to overwrite newer work.')
        if rec['existed'] and file_hash(safe_path(backup / 'files', rec['path'])) != rec['before_sha256']:
            raise ValueError(f'Corrupt backup: {rec["path"]}; nothing restored.')
    restore_records(root, backup, records)
    journal['status'] = 'rolled-back'
    atomic_write(manifest, json.dumps(journal, indent=2).encode(), 0o600)
    return {'status': 'rolled-back', 'restored': len(records), 'backup_id': backup_id}


def verify(root):
    state = json.loads(safe_path(root, STATE).read_text())
    drift = [name for name, meta in state['files'].items()
             if not allowed_target(name) or file_hash(safe_path(root, name)) != meta['sha256']]
    for name in (HELPER, SERVICE_CONFIG):
        if name in state['files'] and name not in drift:
            st = safe_path(root, name).stat()
            if stat.S_IMODE(st.st_mode) != desired_mode(name) or (root == Path('/') and st.st_uid != 0):
                drift.append(name)
    return {'status': 'drift' if drift else 'verified', 'files': len(state['files']),
            'source_version': state['source_version'], 'drift': drift}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='Alternate Ubuntu root for image/fixture validation.')
    subs = parser.add_subparsers(dest='command', required=True)
    for name in ('plan', 'install'):
        sub = subs.add_parser(name)
        sub.add_argument('--no-preview', action='store_true', help='Do not manage the reference gallery; existing gallery is kept.')
        sub.add_argument('--screenshots', type=Path, help='Opt-in local PNGs from scripts/capture.mjs; never committed.')
        sub.add_argument('--no-services', action='store_true', help='Do not manage the service management package; existing files are kept.')
        sub.add_argument('--service-owner', action='append', help='Rootless service owner; repeat for several accounts. Omit to preserve device config.')
    subs.add_parser('verify')
    sub = subs.add_parser('rollback')
    sub.add_argument('backup_id')
    args = parser.parse_args()
    root = args.root.resolve()
    if root == Path('/') and args.command in ('install', 'rollback') and os.geteuid() != 0:
        parser.error('Live installation/rollback requires sudo.')
    try:
        if args.command in ('plan', 'install'):
            desired, state = desired_files(root, not args.no_preview, args.screenshots, not args.no_services, args.service_owner)
            if args.command == 'plan':
                result = {'source_version': state['source_version'], 'cockpit_version': state['cockpit_version'],
                          'changed': changes(root, desired), 'managed_files': len(desired) - 1}
            else:
                result = install(root, desired, state)
                print('After installation, sign out/in and force-refresh the browser. No Cockpit service restart was requested.', file=sys.stderr)
        elif args.command == 'rollback':
            result = rollback(root, args.backup_id)
        else:
            result = verify(root)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1 if result.get('status') == 'drift' else 0
    except (OSError, ValueError, KeyError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
