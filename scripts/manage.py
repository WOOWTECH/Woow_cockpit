#!/usr/bin/env python3
"""Install/verify/roll back WOOWTECH Cockpit packages; Python stdlib only."""
import argparse
from datetime import datetime, timezone
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import posixpath
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
# Backup & restore package, laid out as in docs/backup/CONTRACT.md section 3.
BACKUP_UI = 'usr/local/share/cockpit/woowtechbackup'
BACKUP_LIB = 'usr/local/lib/woowtech-cockpit-backup'
BACKUP_ENGINE = f'{BACKUP_LIB}/woowbackup'
BACKUP_VERSION = f'{BACKUP_LIB}/VERSION'
BACKUP_HELPER = 'usr/local/libexec/woowtech-cockpit-backup'
BACKUP_CONFIG = 'etc/woowtech-cockpit/backup'
BACKUP_CATALOG = f'{BACKUP_CONFIG}/apps'
BACKUP_SHARE = 'usr/local/share/woowtech-cockpit-backup'
BACKUP_TEMPLATES = f'{BACKUP_SHARE}/catalog'
DEMO_APP = 'woowbk-demo'
DEMO_CATALOG = f'{BACKUP_CATALOG}/{DEMO_APP}.json'
DEMO_TEMPLATES = f'{BACKUP_TEMPLATES}/{DEMO_APP}'
# catalog-examples/woowbk-demo/README.md marks only the Quadlet files as trusted templates.
DEMO_TEMPLATE_DIRS = ('quadlet',)
HELPER_SHEBANG = b'#!/usr/bin/python3 -I\n'
# Engine runtime data (keys, archives, uploads, jobs, locks). The installer never plans, writes,
# backs up, verifies or rolls back anything at or below these paths.
BACKUP_RUNTIME = ('var/lib/woowtech-backup', f'{BACKUP_CONFIG}/keys', 'run/woowtech-backup')
# Directory trees owned by the backup package. Every directory in them is exactly root 0755: the
# helper's trust check and the catalog loader reject group/world-writable or non-root directories.
BACKUP_DIR_ROOTS = (BACKUP_UI, BACKUP_LIB, BACKUP_SHARE, BACKUP_CATALOG)
DIR_MODE = 0o755
QUADLET_FILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]*\.(?:container|network|volume|pod)')
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


def under(name, base):
    return name == base or name.startswith(base + '/')


def normalized(name):
    return isinstance(name, str) and bool(name) and all(part not in ('', '.', '..') for part in name.split('/'))


def runtime_path(name):
    return any(under(name, base) for base in BACKUP_RUNTIME)


def backup_path(name):
    """Files of the backup package; their mode and owner are part of the contract."""
    return name in (BACKUP_HELPER, BACKUP_VERSION, DEMO_CATALOG) or name.startswith(
        (BACKUP_UI + '/', BACKUP_ENGINE + '/', DEMO_TEMPLATES + '/'))


def owned_directory(name):
    return any(under(name, base) for base in BACKUP_DIR_ROOTS)


def file_hash(path):
    return digest(path.read_bytes()) if path.is_file() else None


def set_directory_mode(path, mode):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def make_directory(path, mode=DIR_MODE):
    # Create privately first, then set the final mode: the result never depends on the umask.
    os.mkdir(path, 0o700)
    set_directory_mode(path, mode)


def make_parents(path):
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        make_directory(directory)


def atomic_write(path, data, mode=0o644):
    make_parents(path)
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


def package_files(directory):
    """Regular payload files below `directory`; caches and hidden files are never deployed."""
    if directory.is_symlink():
        raise ValueError(f'Source symlink is not supported: {directory}')
    for path in sorted(directory.rglob('*')):
        parts = path.relative_to(directory).parts
        if any(part == '__pycache__' or part.startswith('.') for part in parts) or path.suffix in ('.pyc', '.pyo'):
            continue
        if path.is_symlink():
            raise ValueError(f'Source symlink is not supported: {path}')
        if path.is_file():
            yield '/'.join(parts), path.read_bytes()


def unique_keys(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise ValueError(f'duplicate key {key!r}')
        data[key] = value
    return data


def demo_catalog(fixture):
    """The lab-only woowbk-demo catalog entry, checked against where its templates are installed."""
    path = fixture / 'catalog.json'
    where = path.relative_to(SOURCE).as_posix()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'--backup-demo-catalog: {where} not found in the source tree; nothing was installed.')
    raw = path.read_bytes()
    try:
        entry = json.loads(raw, object_pairs_hook=unique_keys)
    except ValueError as error:
        raise ValueError(f'--backup-demo-catalog: {where} is not valid JSON ({error}).') from None
    quadlet = entry.get('quadlet') if isinstance(entry, dict) else None
    if not isinstance(quadlet, dict) or entry.get('id') != DEMO_APP:
        raise ValueError(f'--backup-demo-catalog: {where} must describe app "{DEMO_APP}" with a "quadlet" object.')
    expected = f'/{DEMO_TEMPLATES}/quadlet'
    if quadlet.get('template_dir') != expected:
        raise ValueError(f'--backup-demo-catalog: quadlet.template_dir in {where} must be {expected}, '
                         'where the installer places the templates.')
    files = quadlet.get('files')
    if not isinstance(files, list) or not files:
        raise ValueError(f'--backup-demo-catalog: quadlet.files in {where} must list the template files.')
    for name in files:
        if not isinstance(name, str) or not QUADLET_FILE.fullmatch(name) or not (fixture / 'quadlet' / name).is_file():
            raise ValueError(f'--backup-demo-catalog: Quadlet template {name!r} from {where} is missing in '
                             f'{fixture.relative_to(SOURCE).as_posix()}/quadlet.')
    return raw


def backup_payload(desired, demo, notices):
    """Add the backup & restore package to `desired`; return the prefixes it fully manages."""
    managed = []
    ui = SOURCE / 'backup'
    if (ui / 'manifest.json').is_file():
        for name, data in package_files(ui):
            desired[f'{BACKUP_UI}/{name}'] = (data, 'backup-ui')
        managed.append(BACKUP_UI + '/')
    else:
        notices.append('Skipped the backup & restore page: backup/manifest.json is not in the source tree; '
                       'files already installed there are kept.')
    engine = SOURCE / 'backup-engine'
    helper = engine / 'woowtech-cockpit-backup'
    required = (helper, engine / 'woowbackup/__init__.py', engine / 'woowbackup/cli.py')
    missing = [path.relative_to(SOURCE).as_posix() for path in required if not path.is_file()]
    if missing:
        notices.append(f'Skipped the backup engine and helper: {", ".join(missing)} not in the source tree; '
                       'files already installed there are kept.')
    else:
        if helper.is_symlink():
            raise ValueError(f'Source symlink is not supported: {helper}')
        data = helper.read_bytes()
        if not data.startswith(HELPER_SHEBANG):
            raise ValueError('backup-engine/woowtech-cockpit-backup must start with "#!/usr/bin/python3 -I"; '
                             'nothing was installed.')
        desired[BACKUP_HELPER] = (data, 'backup-helper')
        for name, data in package_files(engine / 'woowbackup'):
            desired[f'{BACKUP_ENGINE}/{name}'] = (data, 'backup-engine')
        desired[BACKUP_VERSION] = ((SOURCE / 'VERSION').read_bytes(), 'backup-engine')
        managed.append(BACKUP_ENGINE + '/')
    if demo:
        fixture = SOURCE / 'catalog-examples' / DEMO_APP
        desired[DEMO_CATALOG] = (demo_catalog(fixture), 'backup-demo-catalog')
        for sub in DEMO_TEMPLATE_DIRS:
            for name, data in package_files(fixture / sub):
                desired[f'{DEMO_TEMPLATES}/{sub}/{name}'] = (data, 'backup-demo-template')
        managed.append(DEMO_TEMPLATES + '/')
    return managed


def obsolete_files(root, desired, prefixes, notices):
    """Mark previously installed backup files that the source no longer ships for removal.

    Only files recorded in the installed state below a prefix managed by this run are removed
    (with a backup), so an old engine module or UI asset cannot linger and shadow new code.
    """
    if not prefixes:
        return
    state_file = safe_path(root, STATE)
    if not state_file.is_file():
        return
    try:
        previous = list(json.loads(state_file.read_text())['files'])
    except (ValueError, KeyError, TypeError):
        notices.append('The installed state file is unreadable; obsolete backup files were not removed.')
        return
    for name in previous:
        if (normalized(name) and name.startswith(tuple(prefixes)) and name not in desired
                and safe_path(root, name).is_file()):
            desired[name] = (None, 'obsolete')


def backup_directories(desired):
    """Directories the backup package owns (exactly root 0755), from every managed file."""
    found = {BACKUP_CATALOG}
    for name, (data, _) in desired.items():
        if data is None or not backup_path(name):
            continue
        parent = posixpath.dirname(name)
        while owned_directory(parent):
            found.add(parent)
            parent = posixpath.dirname(parent)
    return sorted(found)


def desired_files(root, include_preview=True, screenshots=None, include_services=True, service_owners=None,
                  include_backup=True, backup_demo_catalog=False, notices=None):
    notices = [] if notices is None else notices
    if backup_demo_catalog and not include_backup:
        raise ValueError('--backup-demo-catalog needs the backup package; drop --no-backup.')
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
    directories = []
    if include_backup:
        prefixes = backup_payload(desired, backup_demo_catalog, notices)
        obsolete_files(root, desired, prefixes, notices)
        directories = backup_directories(desired)
    for relative in desired:
        if runtime_path(relative):
            raise ValueError(f'Refusing to manage backup runtime data: {relative}')
        target = safe_path(root, relative)
        if target.exists() and not target.is_file():
            raise ValueError(f'Target is not a regular file: {target}')
    for relative in directories:
        target = safe_path(root, relative)
        if target.exists() and not target.is_dir():
            raise ValueError(f'Target is not a directory: {target}')
    state = {'schema': 1, 'source_version': (SOURCE / 'VERSION').read_text().strip(),
             'cockpit_version': version, 'preview': include_preview,
             'backup': include_backup, 'backup_demo_catalog': backup_demo_catalog,
             'files': {name: {'sha256': digest(data), 'role': role}
                       for name, (data, role) in sorted(desired.items()) if data is not None},
             'directories': directories}
    desired[STATE] = ((json.dumps(state, indent=2, ensure_ascii=False) + '\n').encode(), 'state')
    safe_path(root, STATE)
    return desired, state


def desired_mode(name):
    if name in (HELPER, BACKUP_HELPER):
        return 0o755
    return 0o600 if name in (STATE, SERVICE_CONFIG) else 0o644


def mode_checked(name):
    return name in (HELPER, SERVICE_CONFIG) or backup_path(name)


def metadata_drift(path, name, live):
    st = path.stat()
    return stat.S_IMODE(st.st_mode) != desired_mode(name) or (live and st.st_uid != 0)


def changes(root, desired):
    live = root == Path('/')
    names = []
    for name, (data, _) in desired.items():
        target = safe_path(root, name)
        if data is None:
            if target.exists():
                names.append(name)
        elif file_hash(target) != digest(data) or (mode_checked(name) and metadata_drift(target, name, live)):
            names.append(name)
    return names


def directory_plan(root, state, live=None, uid=0):
    """Directory changes the backup package needs, parents first. Nothing is changed here.

    Owned directories (state['directories']) are created or set to exactly 0755. Their parents
    (system or shared directories) are only created when missing. On a live root every existing
    directory on the way must already be root-owned, and parents must not be writable by
    group/others, because the root helper and the trusted catalog live below them.
    """
    live = root == Path('/') if live is None else live
    owned = list(state.get('directories', []))
    if not owned:
        return []
    wanted = set(owned)
    if BACKUP_HELPER in state.get('files', {}):
        wanted.add(posixpath.dirname(BACKUP_HELPER))
    parents = set()
    for directory in wanted:
        parent = posixpath.dirname(directory)
        while parent:
            parents.add(parent)
            parent = posixpath.dirname(parent)
    if live:
        st = os.lstat(root)
        if st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o022:
            raise ValueError(f'Refusing: {root} must be root-owned and not writable by group/others; nothing was changed.')
    plan = []
    for directory in sorted(wanted | parents, key=lambda name: (name.count('/'), name)):
        path = safe_path(root, directory)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            plan.append({'path': directory, 'existed': False, 'mode_before': None, 'mode_after': DIR_MODE})
            continue
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(f'Target is not a directory: {path}')
        mode = stat.S_IMODE(st.st_mode)
        if live and st.st_uid != uid:
            raise ValueError(f'Refusing: {path} is not owned by root; the backup helper only trusts root-owned '
                             'directories. Nothing was changed.')
        if directory in owned:
            if mode != DIR_MODE:
                plan.append({'path': directory, 'existed': True, 'mode_before': mode, 'mode_after': DIR_MODE})
        elif live and mode & 0o022:
            raise ValueError(f'Refusing: {path} is writable by group/others ({mode:04o}); run "chmod go-w {path}" '
                             'before installing the root backup helper. Nothing was changed.')
    return plan


def apply_directory(root, rec):
    path = safe_path(root, rec['path'])
    if rec['existed']:
        set_directory_mode(path, rec['mode_after'])
    else:
        make_directory(path, rec['mode_after'])


def undo_directories(root, records):
    """Reverse directory changes, deepest first; return directories kept because they are in use.

    Directories created by the transaction are removed once empty again. An earlier mode of an
    owned directory is restored unless it was writable by group/others (never re-open that hole).
    """
    kept = []
    for rec in reversed(records):
        path = safe_path(root, rec['path'])
        if not rec['existed']:
            try:
                os.rmdir(path)
            except FileNotFoundError:
                pass
            except OSError as error:
                if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                    raise
                kept.append(rec['path'])
        elif owned_directory(rec['path']) and path.is_dir() and not rec['mode_before'] & 0o022:
            set_directory_mode(path, rec['mode_before'])
    return kept


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
    directories = directory_plan(root, state)
    if not names and not directories:
        return {'changed': 0, 'status': 'already-current'}
    backup_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = safe_path(root, f'{BACKUPS}/{backup_id}')
    make_parents(backup)
    backup.mkdir(mode=0o700)
    records = []
    for name in names:
        target = safe_path(root, name)
        data = desired[name][0]
        rec = {'path': name, 'existed': target.exists(), 'before_sha256': file_hash(target),
               'after_sha256': None if data is None else digest(data)}
        if target.exists():
            st = target.stat()
            rec.update(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
            atomic_write(safe_path(backup / 'files', name), target.read_bytes(), 0o600)
        records.append(rec)
    journal = {'schema': 1, 'id': backup_id, 'status': 'prepared', 'files': records, 'directories': directories}
    atomic_write(backup / 'transaction.json', json.dumps(journal, indent=2).encode(), 0o600)
    applied, made = [], []
    try:
        for rec in directories:
            apply_directory(root, rec)
            made.append(rec)
        for rec in records:
            data = desired[rec['path']][0]
            if data is None:
                safe_path(root, rec['path']).unlink()
            else:
                atomic_write(safe_path(root, rec['path']), data, desired_mode(rec['path']))
            applied.append(rec)
    except Exception:
        restore_records(root, backup, applied)
        undo_directories(root, made)
        journal['status'] = 'failed-restored'
        atomic_write(backup / 'transaction.json', json.dumps(journal, indent=2).encode(), 0o600)
        raise
    journal['status'] = 'installed'
    atomic_write(backup / 'transaction.json', json.dumps(journal, indent=2).encode(), 0o600)
    return {'status': 'installed', 'changed': len(names) + len(directories), 'files': len(names),
            'removed': sum(1 for rec in records if rec['after_sha256'] is None),
            'directories': len(directories), 'backup_id': backup_id,
            'backup': str(backup), 'source_version': state['source_version']}


def allowed_target(name):
    if not normalized(name) or runtime_path(name):
        return False
    return name in (STATE, HELPER, SERVICE_CONFIG, 'usr/share/cockpit/shell/index.html', f'{PODMAN}/index.js', f'{PODMAN}/index.js.gz', f'{PODMAN}/index.js.LEGAL.txt') or name.startswith((BRAND + '/', PREVIEW + '/', SERVICES + '/', APPS + '/', PODMAN + '/woowtech-licenses/')) or name in {
        'usr/share/cockpit/' + n + suffix for n in NATIVE for suffix in ('', '.gz')} or backup_path(name)


def allowed_directory(name):
    """Directories a journal may ask rollback to remove (only when created and empty) or re-mode."""
    if not normalized(name) or runtime_path(name):
        return False
    bases = BACKUP_DIR_ROOTS + (posixpath.dirname(BACKUP_HELPER),)
    return any(under(name, base) or base.startswith(name + '/') for base in bases)


def valid_directory_record(rec):
    if not isinstance(rec, dict) or not allowed_directory(rec.get('path')) or not isinstance(rec.get('existed'), bool):
        return False
    before = rec.get('mode_before')
    return not rec['existed'] or (isinstance(before, int) and not isinstance(before, bool) and 0 <= before <= 0o7777)


def rollback(root, backup_id):
    if not re.fullmatch(r'\d{8}T\d{12}Z', backup_id):
        raise ValueError('Use the backup_id printed by install (not a filesystem path).')
    backup = safe_path(root, f'{BACKUPS}/{backup_id}')
    manifest = backup / 'transaction.json'
    if root == Path('/'):
        for path in (backup, manifest):
            st = os.lstat(path)
            if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                raise ValueError(f'Refusing: {path} must be root-owned and not writable by group/others.')
    journal = json.loads(manifest.read_text())
    if journal['status'] not in ('installed', 'prepared'):
        raise ValueError(f'Transaction is {journal["status"]}; refusing repeat rollback.')
    records = journal['files']
    directories = journal.get('directories', [])
    for rec in directories:
        if not valid_directory_record(rec):
            raise ValueError('Backup contains an unmanaged path.')
        safe_path(root, rec['path'])
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
    kept = undo_directories(root, directories)
    journal['status'] = 'rolled-back'
    atomic_write(manifest, json.dumps(journal, indent=2).encode(), 0o600)
    result = {'status': 'rolled-back', 'restored': len(records), 'backup_id': backup_id}
    if kept:
        result['kept_directories'] = kept
    return result


def verify(root):
    live = root == Path('/')
    state = json.loads(safe_path(root, STATE).read_text())
    drift = [name for name, meta in state['files'].items()
             if not allowed_target(name) or file_hash(safe_path(root, name)) != meta['sha256']]
    for name in state['files']:
        if name not in drift and mode_checked(name) and metadata_drift(safe_path(root, name), name, live):
            drift.append(name)
    for directory in state.get('directories', []):
        if not (allowed_directory(directory) and owned_directory(directory)):
            drift.append(f'{directory}/')
            continue
        try:
            st = os.lstat(safe_path(root, directory))
        except FileNotFoundError:
            drift.append(f'{directory}/')
            continue
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != DIR_MODE or (live and st.st_uid != 0):
            drift.append(f'{directory}/')
    return {'status': 'drift' if drift else 'verified', 'files': len(state['files']),
            'directories': len(state.get('directories', [])),
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
        sub.add_argument('--no-backup', action='store_true',
                         help='Do not manage the backup & restore package (page, engine, helper, catalog directory); existing files are kept.')
        sub.add_argument('--backup-demo-catalog', action='store_true',
                         help='LAB ONLY: also install the woowbk-demo trusted catalog entry and its Quadlet templates.')
    subs.add_parser('verify')
    sub = subs.add_parser('rollback')
    sub.add_argument('backup_id')
    args = parser.parse_args()
    root = args.root.resolve()
    if root == Path('/') and args.command in ('install', 'rollback') and os.geteuid() != 0:
        parser.error('Live installation/rollback requires sudo.')
    try:
        if args.command in ('plan', 'install'):
            notices = []
            desired, state = desired_files(root, not args.no_preview, args.screenshots, not args.no_services,
                                           args.service_owner, not args.no_backup, args.backup_demo_catalog, notices)
            if args.backup_demo_catalog:
                notices.append(f'--backup-demo-catalog adds the lab fixture "{DEMO_APP}" to the trusted backup catalog; '
                               'never use it on customer devices.')
            for notice in notices:
                print(f'Note: {notice}', file=sys.stderr)
            if args.command == 'plan':
                result = {'source_version': state['source_version'], 'cockpit_version': state['cockpit_version'],
                          'changed': changes(root, desired),
                          'remove': [name for name, (data, _) in desired.items() if data is None],
                          'directories': [f'{rec["path"]}/' for rec in directory_plan(root, state)],
                          'managed_files': len(state['files']), 'notices': notices}
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
