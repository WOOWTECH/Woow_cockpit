"""Quadlet + PostgreSQL + named volumes + Podman secrets + config files. Owner: E2.

Facts this adapter relies on (verified with Podman 4.9 rootless + systemd --user):
* `podman secret inspect --showsecret --format {{.SecretData}}` prints the exact secret bytes plus
  one trailing newline (binary-safe); the JSON form mangles non-UTF-8 bytes. Empty secrets and
  secrets >= 512000 bytes are rejected by `podman secret create`.
* `podman volume export` re-opens /dev/stdout and fails with EACCES on a root-owned fd, so exports
  run through the owner-side relay. `podman volume import` *merges* into a non-empty volume and
  accepts a truncated tar with exit 0 (integrity comes from the archive digests).
* Quadlet adds `--replace --rm` and `ExecStop=podman rm -v -f`; named volumes survive unit stops.
* The postgres image's first-start init server only listens on the Unix socket, so readiness is
  tested over TCP 127.0.0.1 inside the container.
"""
import json
import os
import platform
import re
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..archive import Entry
from ..errors import BackupError
from ..podman import DEVNULL, CommandError, stderr_tail
from .base import Adapter

QUADLET_DIR = '.config/containers/systemd'
MAX_QUADLET_BYTES = 1024 * 1024
MAX_SECRET_BYTES = 511999  # podman: "secret data must be larger than 0 and less than 512000 bytes"
MAX_HTTP_BODY = 1024 * 1024
IMAGE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}\Z')
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
ENTRY_RE = re.compile(r'apps/([a-z0-9][a-z0-9-]{1,40})/(images|postgres|volumes|secrets|config|quadlet)/'
                      r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,200}\Z')
ARCH = {'x86_64': 'amd64', 'aarch64': 'arm64', 'armv7l': 'arm', 'ppc64le': 'ppc64le', 's390x': 's390x'}

STOP_TIMEOUT = 180
START_TIMEOUT = 600
DUMP_TIMEOUT = 3 * 3600
EXPORT_TIMEOUT = 3 * 3600
IMAGE_TIMEOUT = 3600
RESTORE_TIMEOUT = 3 * 3600
SHORT_TIMEOUT = 60
PG_READY_TIMEOUT = 180
HEALTH_INTERVAL = 2.0
SPACE_RESERVE = 512 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - never follow
        return None


def loopback_get(url, timeout):
    """GET a catalog URL on the loopback interface only: no proxies, no redirects, bounded body."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', 'localhost') or parts.username or parts.password:
        raise ValueError('only loopback http URLs are allowed')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'woowtech-cockpit-backup', 'Accept': 'application/json'})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            if len(body) > MAX_HTTP_BODY:
                raise ValueError('response too large')
            return response.status, body
    except urllib.error.HTTPError as error:
        return error.code, b''


def parse_unit_file(text):
    """Minimal systemd/Quadlet parser: {section: [(key, value), ...]} with continuation lines."""
    sections, current, pending = {}, None, ''
    for raw in text.splitlines():
        line = pending + raw.strip()
        pending = ''
        if line.endswith('\\'):
            pending = line[:-1] + ' '
            continue
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        if current is not None and '=' in line:
            key, value = line.split('=', 1)
            sections[current].append((key.strip(), value.strip()))
    return sections


def last_value(sections, section, key):
    values = [v for k, v in sections.get(section, []) if k == key]
    return values[-1] if values else None


def quadlet_unit(file_name):
    stem, kind = file_name.rsplit('.', 1)
    return f'{stem}.service' if kind == 'container' else f'{stem}-{kind}.service'


def _create(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(fd, 'wb')


def _write_private(path, data):
    with _create(path) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def file_digest(path):
    import hashlib
    digest, size = hashlib.sha256(), 0
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _human(n):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if n < 1024 or unit == 'TiB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024
    return str(n)


def pg_major(version_num):
    num = int(version_num)
    return num // 10000 if num >= 100000 else num // 100


class QuadletPostgresAdapter(Adapter):
    name = 'quadlet-postgres'
    version = 1

    def __init__(self, app, runner, log, *, phase=None, checkpoint=None, writers_hook=None, http_get=None, clock=None,
                 sleep=None, runtime_ready=None, templates_uid=0, statvfs=None):
        super().__init__(app, runner, log, phase=phase, checkpoint=checkpoint, writers_hook=writers_hook)
        self.http_get = http_get or loopback_get
        self.clock = clock or time.monotonic
        self.sleep = sleep or time.sleep
        self._runtime_ready_fn = runtime_ready
        self.templates_uid = templates_uid
        self.statvfs = statvfs or os.statvfs

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def qrel(name):
        return f'{QUADLET_DIR}/{name}'

    def runtime_ready(self):
        if self._runtime_ready_fn is not None:
            return bool(self._runtime_ready_fn())
        return os.path.exists(f'/run/user/{self.runner.uid}/bus')

    def _log_command_error(self, error):
        if isinstance(error, CommandError):
            for line in stderr_tail(error.stderr):
                self.log(f'  {line}')

    def unit_states(self, units):
        units = list(units)
        out = self.runner.systemctl('show', '--property=Id,LoadState,ActiveState,SubState', '--', *units,
                                    timeout=SHORT_TIMEOUT).stdout or b''
        blocks = [b for b in out.decode('utf-8', 'replace').split('\n\n') if b.strip()]
        states = {}
        for unit, block in zip(units, blocks):
            states[unit] = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        for unit in units:
            states.setdefault(unit, {'LoadState': 'not-found', 'ActiveState': 'inactive'})
        return states

    def aux_units(self):
        """Oneshot units Quadlet generates for .network/.volume/.pod files (RemainAfterExit=yes)."""
        return [quadlet_unit(name) for name in self.app.quadlet_files if not name.endswith('.container')]

    def _reset_aux_units(self):
        # A oneshot network unit stays "active (exited)" after its network was removed; stopping it makes
        # the next start of a dependent unit re-run `podman network create --ignore`.
        for unit in self.aux_units():
            self.runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT, check=False)

    def _quadlet_presence(self):
        rels = {name: self.qrel(name) for name in self.app.quadlet_files}
        stats = self.runner.stat_files(list(rels.values()))
        return {name: stats.get(rel, {}).get('type', 'missing') for name, rel in rels.items()}

    def _read_owner_quadlets(self):
        return {name: self.runner.read_file(self.qrel(name), MAX_QUADLET_BYTES) for name in self.app.quadlet_files}

    def read_templates(self):
        """Trusted templates read by root from the root-owned template dir (never from an archive)."""
        app = self.app
        if not app.template_dir:
            raise BackupError('incompatible', f'應用「{app.name}」沒有部署範本，無法在尚未部署的設備上還原。', app=app.id)
        try:
            dfd = os.open(app.template_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise BackupError('incompatible', f'找不到應用「{app.name}」的部署範本目錄。', app=app.id) from None
        try:
            st = os.fstat(dfd)
            if st.st_uid != self.templates_uid or st.st_mode & 0o022:
                raise BackupError('permission-denied', '部署範本目錄必須由 root 擁有且不可讓其他帳號寫入。', app=app.id)
            result = {}
            for name in app.quadlet_files:
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
                except OSError:
                    raise BackupError('incompatible', f'部署範本缺少 {name}（或為符號連結）。', app=app.id) from None
                with os.fdopen(fd, 'rb') as handle:
                    fst = os.fstat(handle.fileno())
                    if not stat.S_ISREG(fst.st_mode) or fst.st_uid != self.templates_uid or fst.st_mode & 0o022:
                        raise BackupError('permission-denied', f'部署範本 {name} 必須是 root 擁有的一般檔案。', app=app.id)
                    data = handle.read(MAX_QUADLET_BYTES + 1)
                if len(data) > MAX_QUADLET_BYTES:
                    raise BackupError('limit-exceeded', f'部署範本 {name} 過大。', app=app.id)
                result[name] = data
            return result
        finally:
            os.close(dfd)

    def container_images(self, sources):
        """{unit: image ref} from `.container` sources; refs are validated before any use in argv."""
        images = {}
        for name in self.app.quadlet_files:
            if not name.endswith('.container') or name not in sources:
                continue
            sections = parse_unit_file(sources[name].decode('utf-8', 'replace'))
            ref = last_value(sections, 'Container', 'Image')
            if ref is None:
                continue
            if not IMAGE_RE.fullmatch(ref) or ref.endswith(('.image', '.build')):
                raise BackupError('incompatible', f'{name} 的 Image= 設定不受支援：{ref[:120]}', app=self.app.id)
            images[quadlet_unit(name)] = ref
        return images

    def _named_objects(self, sources):
        """Networks, volumes and pods that Quadlet creates for this app (for fresh-mode cleanup)."""
        found = {'network': [], 'volume': [], 'pod': []}
        for name, data in sources.items():
            stem, kind = name.rsplit('.', 1)
            if kind not in found:
                continue
            sections = parse_unit_file(data.decode('utf-8', 'replace'))
            key = {'network': 'NetworkName', 'volume': 'VolumeName', 'pod': 'PodName'}[kind]
            value = last_value(sections, kind.capitalize(), key) or f'systemd-{stem}'
            if NAME_RE.fullmatch(value):
                found[kind].append(value)
        return found

    def image_inspect(self, ref):
        result = self.runner.podman('image', 'inspect', ref, timeout=SHORT_TIMEOUT, check=False)
        if result.returncode != 0:
            return None
        try:
            data = json.loads((result.stdout or b'[]').decode('utf-8'))[0]
        except (ValueError, IndexError, KeyError):
            return None
        image_id = str(data.get('Id') or '')
        if image_id and not image_id.startswith('sha256:'):
            image_id = 'sha256:' + image_id
        config = data.get('Config') or {}
        return {'id': image_id, 'digest': str(data.get('Digest') or ''), 'arch': str(data.get('Architecture') or ''),
                'size': int(data.get('Size') or 0), 'env': list(config.get('Env') or [])}

    @staticmethod
    def _bare_id(image_id):
        return image_id.split(':', 1)[1] if image_id.startswith('sha256:') else image_id

    def _image_exists(self, ref_or_id):
        return self.runner.podman('image', 'exists', ref_or_id, timeout=SHORT_TIMEOUT, check=False).returncode == 0

    def _image_pullable(self, ref):
        if ref.startswith('localhost/'):
            return False
        return self.runner.podman('manifest', 'inspect', ref, stdout=DEVNULL, timeout=90, check=False).returncode == 0

    @staticmethod
    def _env_pg_major(info):
        for item in (info or {}).get('env', []):
            if isinstance(item, str) and item.startswith('PG_MAJOR='):
                try:
                    return int(item.split('=', 1)[1].split('.')[0])
                except ValueError:
                    return None
        return None

    def psql_scalar(self, pg, sql, database=None):
        out = self.runner.podman('exec', pg['container'], 'psql', '-X', '-w', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                                 '-U', pg['user'], '-d', database or pg['database'], '-c', sql,
                                 timeout=SHORT_TIMEOUT).stdout or b''
        return out.decode('utf-8', 'replace').strip()

    # ----------------------------------------------------------------- probe
    def probe(self):
        app = self.app
        units = [{'name': unit, 'active': False} for unit in app.units]
        if not self.runtime_ready():
            return {'deployed': False, 'state': 'error', 'units': units,
                    'problems': [f'帳號 {self.runner.owner} 的使用者服務管理器未啟動，請為此帳號啟用 linger。']}
        problems = []
        presence = self._quadlet_presence()
        present = [name for name, kind in presence.items() if kind == 'file']
        for name, kind in presence.items():
            if kind not in ('file', 'missing'):
                problems.append(f'Quadlet 設定檔 {name} 不是一般檔案或路徑含有符號連結。')
        if not present and not problems:
            return {'deployed': False, 'state': 'not-deployed', 'units': units, 'problems': []}
        missing = [name for name, kind in presence.items() if kind == 'missing']
        if missing:
            problems.append(f'部分 Quadlet 設定檔不存在：{", ".join(missing)}。')
        states = self.unit_states(app.units)
        units = [{'name': unit, 'active': states[unit].get('ActiveState') == 'active'} for unit in app.units]
        for unit in app.units:
            if states[unit].get('LoadState') in ('not-found', 'error', 'bad-setting'):
                problems.append(f'找不到服務 {unit}；請確認 Quadlet 已載入（systemctl --user daemon-reload）。')
        if problems:
            state = 'error'
        elif all(u['active'] for u in units):
            state = 'running'
        elif not any(u['active'] for u in units):
            state = 'stopped'
        else:
            state = 'partial'
        return {'deployed': True, 'state': state, 'units': units, 'problems': problems}

    def detect_mode(self):
        presence = self._quadlet_presence()
        kinds = set(presence.values())
        if kinds == {'file'}:
            return 'inplace'
        if kinds == {'missing'}:
            return 'fresh'
        raise BackupError('incompatible', f'應用「{self.app.name}」的 Quadlet 設定檔不完整或含有符號連結，'
                                          '無法判斷還原方式；請先修復部署。', app=self.app.id)

    def ensure_databases_running(self):
        """Start inactive database units (needed to dump a pre-restore safety backup); raises if they cannot run."""
        states = self.unit_states(self.app.units)
        started = []
        for pg in self.app.postgres:
            if states[pg['unit']].get('ActiveState') != 'active':
                self.log(f'啟動資料庫服務 {pg["unit"]}，以便建立還原前備份')
                self.runner.systemctl('start', '--', pg['unit'], timeout=START_TIMEOUT)
                started.append(pg['unit'])
            self._wait_for_postgres(pg)
        return started

    def estimate_bytes(self, *, include_images=False):
        total = 1024 * 1024
        for pg in self.app.postgres:
            try:
                total += int(self.psql_scalar(pg, 'SELECT pg_database_size(current_database())') or 0)
            except (BackupError, ValueError):
                raise BackupError('job-failed', f'無法讀取資料庫 {pg["id"]} 的大小；請確認資料庫服務正在執行。',
                                  app=self.app.id) from None
        for volume in self.app.volumes:
            total += self._volume_size(volume['name'])
        if include_images:
            for ref in dict.fromkeys(self.container_images(self._read_owner_quadlets()).values()):
                info = self.image_inspect(ref)
                total += info['size'] if info else 0
        return total

    def _volume_size(self, name):
        result = self.runner.podman('volume', 'inspect', '--format', '{{.Mountpoint}}', name,
                                    timeout=SHORT_TIMEOUT, check=False)
        mountpoint = (result.stdout or b'').decode('utf-8', 'replace').strip()
        if result.returncode != 0 or not mountpoint.startswith('/'):
            raise BackupError('not-deployed', f'找不到資料卷 {name}。', app=self.app.id, volume=name)
        du = self.runner.podman('unshare', 'du', '-s', '-B1', '--apparent-size', '--', mountpoint,
                                timeout=600, check=False)
        try:
            return int((du.stdout or b'').split()[0])
        except (IndexError, ValueError):
            raise BackupError('job-failed', f'無法估算資料卷 {name} 的大小。', app=self.app.id) from None

    # ----------------------------------------------------------------- backup
    def backup(self, staging_dir, *, include_images):
        app = self.app
        staging = Path(staging_dir)
        staging.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.probe()
        if not info['deployed']:
            raise BackupError('not-deployed', f'應用「{app.name}」尚未部署在此設備，無法備份。', app=app.id)
        if info['problems']:
            raise BackupError('job-failed', f'應用「{app.name}」狀態異常：{info["problems"][0]}', app=app.id)
        active = {u['name']: u['active'] for u in info['units']}
        was_running = all(active.get(unit) for unit in app.units)
        for pg in app.postgres:
            if not active.get(pg['unit']):
                raise BackupError('job-failed', f'資料庫服務 {pg["unit"]} 未執行，無法匯出資料庫。', app=app.id)
        quadlets = self._read_owner_quadlets()
        images = []
        for ref in dict.fromkeys(self.container_images(quadlets).values()):
            image = self.image_inspect(ref)
            if image is None:
                raise BackupError('job-failed', f'找不到應用使用的映像 {ref}。', app=app.id)
            images.append({'ref': ref, **image})
        snapshot = self._snapshot_for_backup()
        for sub in ('postgres', 'volumes', 'secrets', 'config', 'quadlet', 'images'):
            (staging / sub).mkdir(mode=0o700, exist_ok=True)

        writers = [unit for unit in app.units if unit in app.writer_units and active.get(unit)]
        stopped = []
        self.phase('stop')
        if writers:
            self.writers_hook(list(writers))
        started_at = self.clock()
        try:
            for unit in reversed(writers):
                self.log(f'暫停寫入服務 {unit}')
                self.runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT)
                stopped.append(unit)
            self.phase('dump')
            dumps = [self._dump_database(pg, staging) for pg in app.postgres]
            self.phase('export')
            volumes = [self._export_volume(v['name'], staging) for v in app.volumes]
            secrets = [self._read_secret(s['name'], staging) for s in app.secrets]
            configs = [self._read_config(i, c, staging) for i, c in enumerate(app.config_files)]
            for name in app.quadlet_files:
                _write_private(staging / 'quadlet' / name, quadlets[name])
        except BaseException as error:
            self._log_command_error(error)
            self._restart_writers(stopped, started_at, raise_errors=False)
            raise
        self._restart_writers(stopped, started_at, raise_errors=True)
        if was_running:
            self._log_health_after_backup()
        else:
            # Waiting out the catalog health timeout for an app that was already down only delays the job
            # (e.g. the safety backup taken before restoring an app a killed restore left stopped).
            self.log('備份前應用並未完整執行，略過備份後的健康檢查。')

        if include_images:
            for i, image in enumerate(images):
                image['file'] = self._save_image(i, image, staging)

        entries = []

        def entry(kind, name, path):
            size, digest = file_digest(path)
            item = Entry(path=f'apps/{app.id}/{kind}/{name}', source=Path(path), size=size, sha256=digest)
            entries.append(item)
            return item.path

        manifest = {
            'id': app.id, 'name': app.name, 'adapter': self.name, 'adapter_version': self.version,
            'catalog_sha256': app.sha256, 'owner': {'name': self.runner.owner, 'uid': self.runner.uid},
            'images': [], 'postgres': [], 'volumes': [], 'secrets': [], 'config_files': [], 'quadlet_files': [],
            'verify_snapshot': snapshot,
        }
        for dump in dumps:
            manifest['postgres'].append({'id': dump['id'], 'database': dump['database'],
                                         'server_version': dump['server_version'], 'major': dump['major'],
                                         'entry': entry('postgres', f'{dump["id"]}.dump', dump['file'])})
        for volume in volumes:
            manifest['volumes'].append({'name': volume['name'],
                                        'entry': entry('volumes', f'{volume["name"]}.tar', volume['file'])})
        for secret in secrets:
            manifest['secrets'].append({'name': secret['name'], 'entry': entry('secrets', secret['name'], secret['file'])})
        for i, config in enumerate(configs):
            manifest['config_files'].append({'path': config['path'], 'mode': config['mode'],
                                             'entry': entry('config', str(i), config['file'])})
        for name in app.quadlet_files:
            manifest['quadlet_files'].append({'name': name, 'entry': entry('quadlet', name, staging / 'quadlet' / name)})
        for i, image in enumerate(images):
            item = {'ref': image['ref'], 'id': image['id'], 'digest': image['digest'], 'arch': image['arch']}
            if image.get('file'):
                item['entry'] = entry('images', f'{i}.oci.tar', image['file'])
            manifest['images'].append(item)
        return manifest, entries

    def _snapshot_for_backup(self):
        if not self.app.verify:
            return {}
        try:
            return self.verify_snapshot()
        except BackupError as error:
            self.log(f'警告：無法取得備份時的資料核對快照（{error.message}）；還原後將無法比對資料。')
            return {}

    def _restart_writers(self, stopped, started_at, *, raise_errors):
        self.phase('start')
        failed = []
        for unit in [u for u in self.app.units if u in stopped]:
            for attempt in (1, 2):
                try:
                    self.runner.systemctl('start', '--', unit, timeout=START_TIMEOUT)
                    self.log(f'已恢復服務 {unit}')
                    break
                except BackupError as error:
                    self._log_command_error(error)
                    if attempt == 2:
                        failed.append(unit)
                        self.log(f'無法重新啟動服務 {unit}')
                    else:
                        self.sleep(2)
        # Downtime caused by the backup: none when no writer had to be stopped (it was not running).
        self.last_downtime = max(0.0, self.clock() - started_at) if stopped else 0.0
        if stopped:
            self.writers_hook(failed)
        if failed and raise_errors:
            raise BackupError('job-failed', f'備份後無法重新啟動服務：{", ".join(failed)}；請到服務頁檢查。',
                              app=self.app.id, units=failed)

    def _log_health_after_backup(self):
        for check in self.health():
            if check['status'] != 'ok':
                self.log(f'警告：{check["message"]}')

    def _dump_database(self, pg, staging):
        number = self.psql_scalar(pg, 'SHOW server_version_num')
        version = self.psql_scalar(pg, 'SHOW server_version').split(' ')[0][:32]
        try:
            major = pg_major(number)
        except ValueError:
            raise BackupError('job-failed', f'無法判斷資料庫 {pg["id"]} 的版本。', app=self.app.id) from None
        dest = staging / 'postgres' / f'{pg["id"]}.dump'
        self.log(f'匯出資料庫 {pg["id"]}（{pg["database"]}，PostgreSQL {version}）')
        with _create(dest) as handle:
            self.runner.podman('exec', pg['container'], 'pg_dump', '-w', '-U', pg['user'], '-d', pg['database'], '-Fc',
                               stdout=handle, timeout=DUMP_TIMEOUT)
            handle.flush()
            os.fsync(handle.fileno())
        if dest.stat().st_size == 0:
            raise BackupError('job-failed', f'資料庫 {pg["id"]} 匯出結果為空。', app=self.app.id)
        with open(dest, 'rb') as handle:
            self.runner.podman('exec', '-i', pg['container'], 'pg_restore', '--list', input=handle, stdout=DEVNULL,
                               timeout=DUMP_TIMEOUT)
        self.log(f'資料庫 {pg["id"]} 匯出完成並通過 pg_restore --list 檢查（{_human(dest.stat().st_size)}）')
        return {'id': pg['id'], 'database': pg['database'], 'server_version': version, 'major': major, 'file': dest}

    def _export_volume(self, name, staging):
        dest = staging / 'volumes' / f'{name}.tar'
        self.log(f'匯出資料卷 {name}')
        with _create(dest) as handle:
            self.runner.relay(['volume', 'export', name], stdout=handle, timeout=EXPORT_TIMEOUT)
            handle.flush()
            os.fsync(handle.fileno())
        if dest.stat().st_size < 1024:
            raise BackupError('job-failed', f'資料卷 {name} 匯出結果不完整。', app=self.app.id)
        return {'name': name, 'file': dest}

    def _read_secret(self, name, staging):
        result = self.runner.podman('secret', 'inspect', '--showsecret', '--format', '{{.SecretData}}', name,
                                    timeout=SHORT_TIMEOUT)
        data = result.stdout or b''
        result.stdout = None
        if not data.endswith(b'\n') or len(data) < 2:
            raise BackupError('job-failed', f'無法讀取密鑰 {name}。', app=self.app.id)
        dest = staging / 'secrets' / name
        _write_private(dest, data[:-1])
        self.log(f'已讀取密鑰 {name}（內容不記錄）')
        return {'name': name, 'file': dest}

    def _read_config(self, index, config, staging):
        data = self.runner.read_file(config['path'])
        dest = staging / 'config' / str(index)
        _write_private(dest, data)
        return {'path': config['path'], 'mode': config['mode'], 'file': dest}

    def _save_image(self, index, image, staging):
        dest = staging / 'images' / f'{index}.oci.tar'
        self.log(f'匯出映像 {image["ref"]}')
        with _create(dest) as handle:
            self.runner.podman('save', '--quiet', '--format', 'oci-archive', image['ref'], stdout=handle,
                               timeout=IMAGE_TIMEOUT)
            handle.flush()
            os.fsync(handle.fileno())
        after = self.image_inspect(image['ref'])
        if not after or after['id'] != image['id']:
            raise BackupError('job-failed', f'映像 {image["ref"]} 在備份期間變更，請重新備份。', app=self.app.id)
        return dest

    # ----------------------------------------------------------------- restore
    def match_items(self, app_manifest):
        """Local catalog is the authority: returns (found {kind: {key: entry}}, missing [str], extra [str])."""
        app = self.app

        def index(key, field):
            return {x.get(field): x for x in app_manifest.get(key) or [] if isinstance(x, dict)}

        archive = {'postgres': index('postgres', 'id'), 'volumes': index('volumes', 'name'),
                   'secrets': index('secrets', 'name'), 'config': index('config_files', 'path')}
        local = {'postgres': [p['id'] for p in app.postgres], 'volumes': [v['name'] for v in app.volumes],
                 'secrets': [s['name'] for s in app.secrets], 'config': [c['path'] for c in app.config_files]}
        labels = {'postgres': '資料庫', 'volumes': '資料卷', 'secrets': '密鑰', 'config': '設定檔'}
        found, missing, extra = {}, [], []
        for kind, keys in local.items():
            found[kind] = {}
            for key in keys:
                item = archive[kind].get(key)
                if item is None or not isinstance(item.get('entry'), str):
                    missing.append(f'{labels[kind]} {key}')
                else:
                    found[kind][key] = item
            for key in archive[kind]:
                if key not in keys:
                    extra.append(f'{labels[kind]} {key}')
        return found, missing, extra

    def entry_path(self, root, entry):
        match = ENTRY_RE.fullmatch(entry or '')
        if not match or match.group(1) != self.app.id:
            raise BackupError('corrupt-archive', '備份內容的項目路徑不正確。', app=self.app.id)
        path = Path(root) / entry
        try:
            st = os.lstat(path)
        except OSError:
            raise BackupError('corrupt-archive', f'備份內容缺少項目 {entry}。', app=self.app.id) from None
        if not stat.S_ISREG(st.st_mode):
            raise BackupError('corrupt-archive', f'備份內容的項目 {entry} 不是一般檔案。', app=self.app.id)
        return path

    def preflight(self, app_manifest, *, mode, entry_sizes=None):
        app = self.app
        checks = []
        seen = {}

        def add(check_id, status, message):
            seen[check_id] = seen.get(check_id, 0) + 1
            suffix = f'-{seen[check_id]}' if seen[check_id] > 1 else ''
            checks.append({'id': f'{app.id}/{check_id}{suffix}', 'status': status, 'message': message})

        add('owner', 'ok', f'將以此設備帳號 {self.runner.owner}（UID {self.runner.uid}）還原。')
        if not self.runtime_ready():
            add('runtime', 'fail', f'帳號 {self.runner.owner} 的使用者服務管理器未啟動，請先啟用 linger。')
        if app_manifest.get('adapter') != self.name:
            add('adapter', 'fail', '備份使用的應用轉接器與此設備不同。')
        elif not isinstance(app_manifest.get('adapter_version'), int) or app_manifest['adapter_version'] > self.version:
            add('adapter', 'fail', '備份由較新版本的轉接器建立，請先更新此設備的備份元件。')
        if app_manifest.get('catalog_sha256') != app.sha256:
            add('catalog', 'warn', '此設備的應用設定與備份時不同；將以此設備的設定為準。')
        _found, missing, extra = self.match_items(app_manifest)
        if missing:
            add('items', 'fail', f'備份缺少此設備設定需要的項目：{", ".join(missing)}。')
        else:
            add('items', 'ok', '備份包含此設備設定需要的所有資料、密鑰與設定檔。')
        if extra:
            add('extra', 'warn', f'備份中有此設備未設定的項目，將略過：{", ".join(extra)}。')

        sources = None
        if mode == 'fresh':
            try:
                sources = self.read_templates()
                add('templates', 'ok', '此應用尚未部署，將以此設備的受信任範本建立。')
            except BackupError as error:
                add('templates', 'fail', error.message)
            if self.runtime_ready():
                for name in [v['name'] for v in app.volumes] + [p['data_volume'] for p in app.postgres]:
                    if self.runner.podman('volume', 'exists', name, timeout=SHORT_TIMEOUT, check=False).returncode == 0:
                        add('volume-conflict', 'fail', f'此設備已存在同名資料卷 {name}；為避免覆寫既有資料，請先處理後再還原。')
                for secret in app.secrets:
                    if self.runner.podman('secret', 'exists', secret['name'], timeout=SHORT_TIMEOUT,
                                          check=False).returncode == 0:
                        add('secret-existing', 'warn', f'此設備已存在密鑰 {secret["name"]}，還原時會被取代。')
        else:
            try:
                sources = self._read_owner_quadlets()
            except BackupError as error:
                add('quadlet', 'fail', error.message)
            if self.runtime_ready():
                states = self.unit_states(app.units)
                lost = [u for u in app.units if states[u].get('LoadState') in ('not-found', 'error', 'bad-setting')]
                if lost:
                    add('units', 'fail', f'找不到服務：{", ".join(lost)}。')
                down = [p['unit'] for p in app.postgres if states[p['unit']].get('ActiveState') != 'active']
                if down and not lost:
                    add('database-down', 'warn', f'資料庫服務 {", ".join(down)} 目前未執行；建立還原前備份時會先嘗試啟動它。')
            add('safety', 'ok', '還原前會先建立並驗證此應用的還原前備份；失敗時會自動回復。')

        if sources is not None and self.runtime_ready():
            self._preflight_images(app_manifest, sources, add)
        self._preflight_space(app_manifest, entry_sizes, add)
        return checks

    def _preflight_images(self, app_manifest, sources, add):
        try:
            needed = self.container_images(sources)
        except BackupError as error:
            add('images', 'fail', error.message)
            return
        archived = {img.get('ref'): img for img in app_manifest.get('images') or [] if isinstance(img, dict)}
        local_arch = ARCH.get(platform.machine(), platform.machine())
        majors = {}
        for unit, ref in needed.items():
            image = archived.get(ref)
            if image and image.get('entry'):
                if image.get('arch') and image['arch'] != local_arch:
                    add('image', 'fail', f'備份中的映像 {ref} 架構為 {image["arch"]}，與此設備（{local_arch}）不同。')
                else:
                    add('image', 'ok', f'映像 {ref} 已包含在備份中。')
                majors[unit] = 'archive'
            elif self._image_exists(ref):
                add('image', 'ok', f'使用此設備現有的映像 {ref}。')
                majors[unit] = self._env_pg_major(self.image_inspect(ref))
            elif self._image_pullable(ref):
                add('image', 'warn', f'映像 {ref} 不在此設備，還原時將自動下載。')
                majors[unit] = None
            else:
                add('image', 'fail', f'缺少映像 {ref}：備份未包含，且此設備無法取得。')
                majors[unit] = None
        archived_pg = {p.get('id'): p for p in app_manifest.get('postgres') or [] if isinstance(p, dict)}
        for pg in self.app.postgres:
            source = archived_pg.get(pg['id'], {}).get('major')
            target = majors.get(pg['unit'])
            if target == 'archive':
                continue
            if not isinstance(source, int):
                continue
            if target is None:
                add('postgres-version', 'warn', f'無法事先確認資料庫 {pg["id"]} 的目標版本，還原時會再檢查。')
            elif source > target:
                add('postgres-version', 'fail', f'備份的 PostgreSQL 主版本 {source} 高於此設備的 {target}，無法還原。')
            else:
                add('postgres-version', 'ok', f'PostgreSQL 主版本相容（備份 {source}，此設備 {target}）。')

    def _preflight_space(self, app_manifest, entry_sizes, add):
        if not entry_sizes:
            return
        prefix = f'apps/{self.app.id}/'
        need = sum(size for path, size in entry_sizes.items() if path.startswith(prefix))
        try:
            st = self.statvfs(self.runner.home)
            free = st.f_bavail * st.f_frsize
        except OSError:
            add('space', 'warn', '無法確認應用擁有者家目錄的可用空間。')
            return
        required = 2 * need + SPACE_RESERVE
        if free < required:
            add('space', 'fail', f'應用資料所在磁碟空間不足：需要約 {_human(required)}，可用 {_human(free)}。')
        else:
            add('space', 'ok', f'應用資料所在磁碟空間足夠（可用 {_human(free)}）。')

    def restore(self, app_manifest, extracted_dir, *, mode):
        app = self.app
        root = Path(extracted_dir)
        self.destructive_started = False
        found, missing, _extra = self.match_items(app_manifest)
        if missing:
            raise BackupError('incompatible', f'備份缺少此設備設定需要的項目：{", ".join(missing)}。', app=app.id)
        files = {kind: {key: self.entry_path(root, item['entry']) for key, item in items.items()}
                 for kind, items in found.items()}
        templates = self.read_templates() if mode == 'fresh' else None
        sources = templates if mode == 'fresh' else self._read_owner_quadlets()
        needed = self.container_images(sources)
        self._prepare_images(app_manifest, root, needed)
        self.checkpoint()

        self.phase('stop')
        self.destructive_started = True
        try:
            if mode == 'inplace':
                for unit in reversed(app.units):
                    self.log(f'停止服務 {unit}')
                    self.runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT)
            else:
                for name in app.quadlet_files:
                    self.runner.write_file(self.qrel(name), templates[name], 0o644)
                self.log('已安裝部署範本')
                self.runner.systemctl('daemon-reload', timeout=SHORT_TIMEOUT)
            self._reset_aux_units()

            self.phase('restore')
            for secret in app.secrets:
                self._recreate_secret(secret['name'], files['secrets'][secret['name']])
            for config in app.config_files:
                with open(files['config'][config['path']], 'rb') as handle:
                    self.runner.write_file(config['path'], handle, config['mode'])
                self.log(f'已寫入設定檔 ~/{config["path"]}')
            for volume in app.volumes:
                self._recreate_volume(volume['name'], files['volumes'][volume['name']])
            for pg in app.postgres:
                self.runner.podman('volume', 'rm', '-f', pg['data_volume'], timeout=STOP_TIMEOUT)

            self.phase('start')
            started = []
            for pg in sorted(app.postgres, key=lambda p: app.units.index(p['unit'])):
                if pg['unit'] not in started:
                    self._start(pg['unit'])
                    started.append(pg['unit'])
                self._wait_for_postgres(pg)
                self._check_target_major(pg, app_manifest)
                self._ensure_database(pg)
                self._restore_database(pg, files['postgres'][pg['id']])
            for unit in app.units:
                if unit not in started:
                    self._start(unit)
                    started.append(unit)
        except BackupError as error:
            self._log_command_error(error)
            raise

    def _start(self, unit):
        self.log(f'啟動服務 {unit}')
        self.runner.systemctl('start', '--', unit, timeout=START_TIMEOUT)

    def _prepare_images(self, app_manifest, root, needed):
        archived = {img.get('ref'): img for img in app_manifest.get('images') or [] if isinstance(img, dict)}
        for ref in dict.fromkeys(needed.values()):
            image = archived.get(ref)
            if image and image.get('entry'):
                path = self.entry_path(root, image['entry'])
                self.log(f'載入映像 {ref}')
                with open(path, 'rb') as handle:
                    self.runner.podman('load', '--quiet', input=handle, timeout=IMAGE_TIMEOUT)
                self._ensure_tag(image.get('id'), ref)
            elif image and image.get('id') and self._image_exists(self._bare_id(image['id'])):
                self._ensure_tag(image['id'], ref)
            elif self._image_exists(ref):
                continue
            elif ref.startswith('localhost/'):
                raise BackupError('incompatible', f'缺少映像 {ref}：備份未包含，且此設備無法取得。', app=self.app.id)
            else:
                self.log(f'下載映像 {ref}')
                self.runner.podman('pull', '--quiet', ref, stdout=DEVNULL, timeout=IMAGE_TIMEOUT)

    def _ensure_tag(self, image_id, ref):
        if not isinstance(image_id, str) or not re.fullmatch(r'(sha256:)?[0-9a-f]{64}', image_id):
            return
        current = self.image_inspect(ref)
        if current and current['id'] == (image_id if image_id.startswith('sha256:') else 'sha256:' + image_id):
            return
        if not self._image_exists(self._bare_id(image_id)):
            raise BackupError('incompatible', f'映像 {ref} 載入後找不到預期的版本。', app=self.app.id)
        self.runner.podman('tag', self._bare_id(image_id), ref, timeout=SHORT_TIMEOUT)
        self.log(f'已將 {ref} 指向備份時的映像版本')

    def _check_target_major(self, pg, app_manifest):
        source = next((p.get('major') for p in app_manifest.get('postgres') or []
                       if isinstance(p, dict) and p.get('id') == pg['id']), None)
        try:
            target = pg_major(self.psql_scalar(pg, 'SHOW server_version_num', database='postgres'))
        except (BackupError, ValueError):
            return
        if isinstance(source, int) and source > target:
            raise BackupError('incompatible', f'備份的 PostgreSQL 主版本 {source} 高於此設備的 {target}。', app=self.app.id)

    def _recreate_secret(self, name, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as handle:
            data = handle.read(MAX_SECRET_BYTES + 1)
        if not data or len(data) > MAX_SECRET_BYTES:
            raise BackupError('incompatible', f'密鑰 {name} 的大小不受 Podman 支援。', app=self.app.id)
        if self.runner.podman('secret', 'exists', name, timeout=SHORT_TIMEOUT, check=False).returncode == 0:
            self.runner.podman('secret', 'rm', name, timeout=SHORT_TIMEOUT)
        # `podman secret create NAME -` insists on a pipe: a regular-file stdin is rejected, so feed bytes.
        self.runner.podman('secret', 'create', name, '-', input=data, timeout=SHORT_TIMEOUT)
        self.log(f'已重建密鑰 {name}（內容不記錄）')

    def _recreate_volume(self, name, path):
        self.runner.podman('volume', 'rm', '-f', name, timeout=STOP_TIMEOUT)
        self.runner.podman('volume', 'create', name, timeout=SHORT_TIMEOUT)
        with open(path, 'rb') as handle:
            self.runner.podman('volume', 'import', name, '-', input=handle, timeout=EXPORT_TIMEOUT)
        self.log(f'已重建資料卷 {name}')

    def _wait_for_postgres(self, pg):
        deadline = self.clock() + PG_READY_TIMEOUT
        while True:
            result = self.runner.podman('exec', pg['container'], 'pg_isready', '-h', '127.0.0.1', '-p', '5432',
                                        '-U', pg['user'], '-d', pg['database'], '-t', '5', timeout=30, check=False)
            if result.returncode == 0:
                return
            if self.clock() >= deadline:
                raise BackupError('job-failed', f'資料庫 {pg["id"]} 未在 {PG_READY_TIMEOUT} 秒內就緒。', app=self.app.id)
            self.sleep(1)

    def _ensure_database(self, pg):
        # Identifiers are validated against ^[A-Za-z_][A-Za-z0-9_]{0,62}$ by the catalog.
        exists = self.psql_scalar(pg, f"SELECT 1 FROM pg_database WHERE datname = '{pg['database']}'",
                                  database='postgres')
        if exists != '1':
            self.runner.podman('exec', pg['container'], 'createdb', '-w', '-U', pg['user'], pg['database'],
                               timeout=SHORT_TIMEOUT)

    def _restore_database(self, pg, path):
        self.log(f'還原資料庫 {pg["id"]}（{pg["database"]}）')
        with open(path, 'rb') as handle:
            self.runner.podman('exec', '-i', pg['container'], 'pg_restore', '--exit-on-error', '--single-transaction',
                               '--no-owner', '--no-privileges', '-w', '-U', pg['user'], '-d', pg['database'],
                               input=handle, timeout=RESTORE_TIMEOUT)

    def start_units(self, units):
        failed = []
        for unit in [u for u in self.app.units if u in units]:
            try:
                self._start(unit)
            except BackupError:
                failed.append(unit)
        return failed

    def remove_fresh(self):
        app = self.app
        errors = []
        for unit in reversed(app.units):
            try:
                self.runner.systemctl('stop', '--', unit, timeout=STOP_TIMEOUT)
            except BackupError:
                errors.append(unit)
        self._reset_aux_units()
        try:
            sources = self.read_templates()
        except BackupError:
            sources = {}
        for name in app.quadlet_files:
            try:
                self.runner.remove_file(self.qrel(name))
            except BackupError:
                errors.append(name)
        try:
            self.runner.systemctl('daemon-reload', timeout=SHORT_TIMEOUT)
        except BackupError:
            errors.append('daemon-reload')
        for unit in [*app.units, *self.aux_units()]:
            self.runner.systemctl('reset-failed', '--', unit, timeout=SHORT_TIMEOUT, check=False)
        for name in [p['data_volume'] for p in app.postgres] + [v['name'] for v in app.volumes]:
            try:
                self.runner.podman('volume', 'rm', '-f', name, timeout=STOP_TIMEOUT)
            except BackupError:
                errors.append(name)
        for secret in app.secrets:
            if self.runner.podman('secret', 'exists', secret['name'], timeout=SHORT_TIMEOUT, check=False).returncode == 0:
                try:
                    self.runner.podman('secret', 'rm', secret['name'], timeout=SHORT_TIMEOUT)
                except BackupError:
                    errors.append(secret['name'])
        for config in app.config_files:
            try:
                self.runner.remove_file(config['path'])
            except BackupError:
                errors.append(config['path'])
        objects = self._named_objects(sources)
        for pod in objects['pod']:
            self.runner.podman('pod', 'rm', '-f', pod, timeout=STOP_TIMEOUT, check=False)
        for volume in objects['volume']:
            self.runner.podman('volume', 'rm', '-f', volume, timeout=STOP_TIMEOUT, check=False)
        for network in objects['network']:
            self.runner.podman('network', 'rm', '-f', network, timeout=SHORT_TIMEOUT, check=False)
        if errors:
            raise BackupError('job-failed', f'無法完整移除新部署的項目：{", ".join(errors[:6])}；需人工處理。',
                              app=app.id)
        self.log(f'已移除應用「{app.name}」新建立的所有項目')

    # ----------------------------------------------------------------- checks
    def health(self):
        checks = []
        for i, spec in enumerate(self.app.health, 1):
            ok, detail = self._poll(spec)
            message = (f'健康檢查通過（{spec["url"]}）' if ok
                       else f'健康檢查未通過（{spec["url"]}）：{detail}')
            checks.append({'id': f'{self.app.id}/health-{i}', 'status': 'ok' if ok else 'fail', 'message': message})
        return checks

    def _poll(self, spec):
        deadline = self.clock() + spec['timeout_seconds']
        last = '沒有回應'
        while True:
            try:
                status, _body = self.http_get(spec['url'], min(10, spec['timeout_seconds']))
                if status == spec['expect_status']:
                    return True, f'HTTP {status}'
                last = f'HTTP {status}'
            except Exception:  # noqa: BLE001 - any transport error is "not healthy yet"
                last = '無法連線'
            if self.clock() >= deadline:
                return False, last
            self.sleep(HEALTH_INTERVAL)

    def verify_snapshot(self):
        snapshot = {}
        for spec in self.app.verify:
            try:
                status, body = self.http_get(spec['url'], 15)
            except Exception:  # noqa: BLE001
                raise BackupError('job-failed', f'無法取得資料核對結果（{spec["url"]}）。', app=self.app.id) from None
            if status != 200:
                raise BackupError('job-failed', f'無法取得資料核對結果（{spec["url"]}，HTTP {status}）。', app=self.app.id)
            try:
                data = json.loads(body.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                data = None
            if not isinstance(data, dict):
                raise BackupError('job-failed', f'資料核對結果不是 JSON 物件（{spec["url"]}）。', app=self.app.id)
            values = {key: data.get(key) for key in spec['compare']}
            if len(json.dumps(values, ensure_ascii=False)) > 16384:
                raise BackupError('job-failed', '資料核對結果過大。', app=self.app.id)
            snapshot[spec['id']] = values
        return snapshot
