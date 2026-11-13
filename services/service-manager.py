#!/usr/bin/python3 -I
"""Cockpit privileged service operations. Fixed commands, configured user scopes."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

CONFIG = Path('/etc/woowtech-cockpit/services.json')
LOCK_DIR = Path('/run/woowtech-cockpit-services')
UNIT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:@\\-]{0,239}\.service\Z')
OWNER = re.compile(r'[a-z_][a-z0-9_-]{0,31}\$?\Z')
METRICS = ('MainPID', 'MemoryCurrent', 'CPUUsageNSec', 'TasksCurrent', 'NRestarts',
           'ActiveEnterTimestamp', 'InactiveEnterTimestamp', 'ExecMainStatus', 'Type', 'Restart', 'Requires', 'Wants', 'After', 'TriggeredBy',
           'RequiredBy', 'BoundBy', 'ConsistsOf')
PROPERTIES = 'Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,SourcePath,CanStart,CanStop,Result,' + ','.join(METRICS)
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'}


class ServiceError(Exception):
    pass


def validate_unit(unit):
    if not isinstance(unit, str) or not UNIT.fullmatch(unit):
        raise ServiceError('服務名稱格式不正確。')
    return unit


def load_config():
    if CONFIG.is_symlink():
        raise ServiceError('服務管理設定不可使用符號連結。')
    st = CONFIG.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ServiceError('服務管理設定必須由 root 擁有，且不可讓其他帳號寫入。')
    config = json.loads(CONFIG.read_text())
    if not isinstance(config, dict):
        raise ServiceError('服務管理設定格式不正確。')
    owners = config.get('owners', [])
    if not isinstance(owners, list) or len(owners) > 32:
        raise ServiceError('服務擁有者設定不正確。')
    for name in owners:
        if not isinstance(name, str) or not OWNER.fullmatch(name) or name == 'root':
            raise ServiceError('服務擁有者名稱不正確。')
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            raise ServiceError(f'找不到服務擁有者：{name}') from None
        if entry.pw_uid == 0:
            raise ServiceError('Root 服務請使用本機系統範圍。')
    return {'owners': list(dict.fromkeys(owners))}


def scopes(config):
    result = [{'id': 'system', 'label': '本機系統', 'owner': 'root', 'uid': 0}]
    result.extend({'id': f'user:{name}', 'label': f'{name} 的服務', 'owner': name, 'uid': pwd.getpwnam(name).pw_uid} for name in config['owners'])
    return {'scopes': result, 'default_scope': result[1 if config['owners'] else 0]['id']}


class Scope:
    def __init__(self, key, config):
        self.key = key
        self.user = None
        if key == 'system':
            self.owner = 'root'
        elif key.startswith('user:') and key[5:] in config['owners']:
            self.owner = key[5:]
            self.user = pwd.getpwnam(self.owner)
            runtime = Path(f'/run/user/{self.user.pw_uid}')
            if not runtime.is_dir() or not (runtime / 'bus').exists():
                raise ServiceError('此使用者的服務管理器尚未啟動，請先登入該帳號或配置 linger。')
        else:
            raise ServiceError('此服務範圍未設定為可管理。')

    def command(self, program, *args):
        command = [program, *args]
        if self.user:
            command = ['/usr/sbin/runuser', '-u', self.owner, '--', '/usr/bin/env',
                       f'XDG_RUNTIME_DIR=/run/user/{self.user.pw_uid}',
                       f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{self.user.pw_uid}/bus', *command]
        return command

    def systemctl(self, *args):
        return self.command('/usr/bin/systemctl', *(['--user'] if self.user else []), *args)


def run(command, timeout=20, allow_failure=False):
    try:
        result = subprocess.run(command, capture_output=True, text=True, env=ENV, timeout=timeout, errors='replace')
    except subprocess.TimeoutExpired:
        raise ServiceError('操作逾時，結果尚未確認；請重新整理狀態後再決定是否重試。') from None
    except OSError as error:
        raise ServiceError(f'無法執行管理工具：{error.strerror}') from None
    if result.returncode and not allow_failure:
        raise ServiceError(result.stderr.strip()[:1500] or '系統管理操作失敗。')
    return result.stdout


def show_units(scope, names):
    names = sorted({validate_unit(name) for name in names})
    if not names:
        return {}
    output = run(scope.systemctl('show', '--no-pager', f'--property={PROPERTIES}', '--', *names))
    records = {}
    for block in output.strip().split('\n\n'):
        fields = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        name = fields.get('Id', '')
        if not UNIT.fullmatch(name) or fields.get('LoadState') in ('not-found', 'error'):
            continue
        records[name] = fields
    if not records:
        raise ServiceError('找不到可讀取的服務；請重新整理服務清單。')
    return records


def unit_details(scope, name):
    validate_unit(name)
    if '@.service' in name:
        raise ServiceError('請選擇已命名的服務實例。')
    records = show_units(scope, [name])
    fields = records.get(name) or next(iter(records.values()))  # systemd may resolve an alias.
    return fields


def protected(name):
    return name in {'cockpit.service', 'dbus.service', 'systemd-logind.service'} or name.startswith(('cockpit-session@', 'cockpit-wsinstance-', 'user@'))


def kind(fields):
    source = fields.get('SourcePath', '')
    fragment = fields.get('FragmentPath', '')
    if source.endswith(('.container', '.pod', '.kube', '.network', '.volume', '.image', '.build')):
        return 'quadlet'
    if fragment.startswith(('/etc/systemd/', '/usr/local/')) or '/.config/systemd/user/' in fragment:
        return 'local'
    return 'system'


def container_inventory(scope):
    data = json.loads(run(scope.command('/usr/bin/podman', 'ps', '--all', '--format=json')))
    result = []
    for row in data:
        names = row.get('Names', [])
        name = names[0] if isinstance(names, list) and names else names
        unit = (row.get('Labels') or {}).get('PODMAN_SYSTEMD_UNIT')
        if not isinstance(unit, str) or not UNIT.fullmatch(unit):
            unit = None
        ports = row.get('Ports') or []
        port_text = ', '.join(f'{p.get("host_ip", "")}:{p.get("host_port", "")} → {p.get("container_port", "")}/{p.get("protocol", "tcp")}' for p in ports if isinstance(p, dict))
        result.append({'id': row.get('Id', ''), 'name': str(name or row.get('Id', '')[:12]),
                       'image': row.get('Image', ''), 'state': row.get('State', ''),
                       'status': row.get('Status', ''), 'unit': unit, 'ports': port_text})
    return sorted(result, key=lambda row: row['name'])


def inventory(scope):
    loaded = json.loads(run(scope.systemctl('list-units', '--all', '--type=service', '--no-pager', '--output=json')))
    installed = json.loads(run(scope.systemctl('list-unit-files', '--type=service', '--no-pager', '--output=json')))
    names = {row['unit'] for row in loaded} | {row['unit_file'] for row in installed}
    # Bare templates make systemctl show abort the remaining batch. Enumerate
    # concrete service instances only, including inactive/generated instances.
    fields = show_units(scope, [name for name in names if UNIT.fullmatch(name) and '@.service' not in name])
    warnings = []
    try:
        containers = container_inventory(scope)
    except (ServiceError, ValueError):
        containers = []
        warnings.append('此範圍的 Podman 清單暫時無法讀取；服務清單仍可使用。')
    services = []
    for name, row in fields.items():
        services.append({'id': name, 'name': name.removesuffix('.service'), 'description': row.get('Description', name),
                         'active': row.get('ActiveState', 'unknown'), 'sub': row.get('SubState', 'unknown'),
                         'enabled': row.get('UnitFileState', ''), 'kind': kind(row),
                         'can_start': row.get('CanStart') == 'yes' and not protected(name) and '@.service' not in name,
                         'can_stop': row.get('CanStop') == 'yes' and not protected(name),
                         'protected': protected(name),
                         'containers': [c['name'] for c in containers if c['unit'] == name]})
    return {'scope': scope.key, 'owner': scope.owner, 'services': sorted(services, key=lambda s: s['id']),
            'containers': containers, 'warnings': warnings, 'captured_at': datetime.now(timezone.utc).isoformat()}


def logs(scope, name):
    name = unit_details(scope, name)['Id']
    # --user-unit under root implicitly selects root's user journal. Execute
    # as the actual owner, just as for systemctl, to preserve journal scope.
    command = scope.command('/usr/bin/journalctl', *(['--user'] if scope.user else []),
                            '--no-pager', '--output=short-iso', '--lines=100', f'--unit={name}')
    return {'logs': run(command)[-100000:]}


def details(scope, name):
    f = unit_details(scope, name)
    resolved = f['Id']
    return {'unit': {'id': resolved, 'description': f.get('Description', resolved), 'active': f.get('ActiveState'),
                     'sub': f.get('SubState'), 'enabled': f.get('UnitFileState', ''),
                     'source': f.get('SourcePath', ''), 'fragment': f.get('FragmentPath', ''),
                     'can_start': f.get('CanStart') == 'yes' and not protected(resolved) and '@.service' not in resolved,
                     'can_stop': f.get('CanStop') == 'yes' and not protected(resolved),
                     'metrics': {key: f.get(key, '') for key in METRICS}, 'result': f.get('Result', '')}, **logs(scope, resolved)}


def audit(scope, name, verb, result):
    # The elevated Cockpit session owns authentication; never log credentials or command output.
    try:
        run(['/usr/bin/logger', '-t', 'woowtech-cockpit-services', '--', f'scope={scope.key} unit={name} action={verb} result={result}'], timeout=3)
    except ServiceError:
        pass


def action(scope, name, verb):
    if verb not in ('start', 'stop', 'restart'):
        raise ServiceError('不支援此服務操作。')
    f = unit_details(scope, name)
    name = f['Id']
    if protected(name):
        raise ServiceError('管理連線依賴此服務；請使用本機維護終端處理。')
    if '@.service' in name:
        raise ServiceError('請選擇已命名的服務實例。')
    if (verb != 'stop' and f.get('CanStart') != 'yes') or (verb != 'start' and f.get('CanStop') != 'yes'):
        raise ServiceError('此服務不支援要求的操作。')
    lock_dir = LOCK_DIR
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    key = hashlib.sha256(f'{scope.key}/{name}'.encode()).hexdigest()
    fd = os.open(lock_dir / key, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ServiceError('此服務已有操作正在執行，請稍後重新整理。') from None
        audit(scope, name, verb, 'requested')
        try:
            run(scope.systemctl(verb, '--', name), timeout=45)
        except ServiceError:
            audit(scope, name, verb, 'unconfirmed')
            raise
        f = unit_details(scope, name)
        audit(scope, name, verb, f.get('ActiveState', 'unknown'))
        if f.get('ActiveState') == 'failed':
            raise ServiceError(f'操作後 {name} 處於失敗狀態，請查看服務日誌；不會自動重試。')
        if verb == 'stop' and f.get('ActiveState') != 'inactive':
            raise ServiceError(f'{name} 尚未進入停止狀態，請重新整理確認。')
    return {'ok': True, 'unit': name, 'action': verb, 'active': f.get('ActiveState'), 'sub': f.get('SubState')}


def main(argv):
    if os.geteuid() != 0:
        raise ServiceError('請先在 Cockpit 右上角開啟管理員存取權限。')
    config = load_config()
    if argv == ['scopes']:
        return scopes(config)
    if len(argv) not in (2, 3, 4):
        raise ServiceError('服務管理指令格式不正確。')
    command = argv[0]
    scope = Scope(argv[1], config)
    if command == 'inventory' and len(argv) == 2:
        return inventory(scope)
    if command == 'details' and len(argv) == 3:
        return details(scope, argv[2])
    if command == 'logs' and len(argv) == 3:
        return logs(scope, argv[2])
    if command == 'action' and len(argv) == 4:
        return action(scope, argv[2], argv[3])
    raise ServiceError('不支援此服務管理指令。')


if __name__ == '__main__':
    try:
        print(json.dumps(main(sys.argv[1:]), ensure_ascii=False))
    except (ServiceError, OSError, ValueError, KeyError) as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False))
        sys.exit(1)
