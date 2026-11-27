"""Record what the real apt-get (C locale) writes in each failure class and what manage.HostTools.ensure() makes of it.
usage: record.py <worktree> [case ...]   (output below ./out/<case>/)"""
import fcntl, importlib.util, json, os, pathlib, re, shutil, subprocess, sys, time
import lib

TREE = sys.argv[1]
WANT = set(sys.argv[2:])
OUT = lib.HERE / 'out'
spec = importlib.util.spec_from_file_location('manage', TREE + '/scripts/manage.py')
m = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(m)
real = m.run_fixed
calls = []
LOCK_TIMEOUT = os.environ.get('LOCK_TIMEOUT')  # shorten the dpkg lock wait of the recording only


def run(argv, env=None, timeout=120):
    argv = list(argv)
    if argv[0] != m.APT_GET:
        return 127, '', ''  # every probe answers "does not work"
    shown = list(argv)
    if LOCK_TIMEOUT:
        argv = [f'DPkg::Lock::Timeout={LOCK_TIMEOUT}' if a == 'DPkg::Lock::Timeout=300' else a for a in argv]
    extra = {'STUB_EXIT': os.environ['STUB_EXIT']} if 'STUB_EXIT' in os.environ else {}
    out = real(argv, {**env, **extra, 'APT_CONFIG': str(lib.ROOT / 'apt.conf')}, timeout)
    calls.append({'argv': shown, 'ran': argv, 'rc': out[0], 'out': out[1], 'err': out[2]})
    return out


m.run_fixed = run
m.print = lambda *a, **k: None  # the Note lines are not the subject here


def clean(text, server_ports=()):
    """Host names and addresses of the harness replaced: 127.0.0.1 is repo.example, 127.0.0.2 the third-party host."""
    text = text.replace(str(lib.ROOT), '<root>')
    text = re.sub(r'127\.0\.0\.([12]):(\d+)', lambda m: ('repo' if m.group(1) == '1' else 'third') + '.example:80', text)
    text = re.sub(r'127\.0\.0\.([12]) (\d+)\]', lambda m: f'192.0.2.{m.group(1)} 80]', text)
    return re.sub(r'127\.0\.0\.([12])', lambda m: f'192.0.2.{m.group(1)}', text)


def case(name, text, setup, *, packages=None, env=None, after=None):
    if WANT and name not in WANT:
        return
    calls.clear()
    for key in ('http_proxy', 'https_proxy', 'no_proxy'):
        os.environ.pop(key, None)
    for key, value in (env or {}).items():
        os.environ[key] = value
    state = setup()
    left = packages or list(m.TOOL_PACKAGES)
    try:
        report = m.HostTools().ensure()
    finally:
        if after:
            after(state)
    ports = state.get('ports', ()) if isinstance(state, dict) else ()
    folder = OUT / name
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    (folder / 'case.txt').write_text(text + '\n')
    for number, call in enumerate(calls):
        kind = 'update' if call['argv'][-1] == 'update' else 'install'
        (folder / f'{kind}.argv').write_text(' '.join(call['argv']) + ('\n(ran with ' + ' '.join(call['ran'][4:8]) + ')\n' if call['ran'] != call['argv'] else '\n'))
        (folder / f'{kind}.rc').write_text(f'{call["rc"]}\n')
        (folder / f'{kind}.out').write_text(clean(call['out'], ports))
        (folder / f'{kind}.err').write_text(clean(call['err'], ports))
    notice = (report.get('notices') or ['(no notice: ' + json.dumps(report, ensure_ascii=False) + ')'])[0]
    (folder / 'notice.txt').write_text(clean(notice, ports) + '\n')
    for key in ('http_proxy', 'https_proxy', 'no_proxy'):
        os.environ.pop(key, None)
    reason = re.search(r'自動補裝沒有成功：(.*?)。更新照常進行', notice)
    print(f'## {name}: {reason.group(1) if reason else notice[:200]}')


def online(*, signed=False, key=True, size=None, extra=None, drop=(), valid_until=None, trusted_flag=True):
    """A reachable repository (the dummy packages minus `drop`), the apt root pointing at it. `signed`: InRelease and
    Release.gpg are made with the test key, which apt trusts only when `key` is true; otherwise the source is
    [trusted=yes]."""
    lib.new_root(trusted=signed and key)
    repo = lib.HERE / 'repo'
    shutil.rmtree(repo, ignore_errors=True)
    lib.build_debs(repo, extra=extra)
    for name in drop:
        for deb in repo.glob(f'{name}_*.deb'):
            deb.unlink()
    lib.index(repo, size=size)
    if drop:
        text = (repo / 'Packages').read_text()
        keep = [block for block in text.strip().split('\n\n') if not any(block.startswith(f'Package: {n}\n') for n in drop)]
        (repo / 'Packages').write_text('\n\n'.join(keep) + '\n')
        (repo / 'Release').write_text(lib.sh(['apt-ftparchive', 'release', '.'], cwd=repo).stdout)
    if signed:
        lib.sign(repo, valid_until=valid_until)
    server = lib.Server(repo)
    flag = '' if signed or not trusted_flag else '[trusted=yes] '
    (lib.ROOT / 'etc/sources.list').write_text(f'deb {flag}http://127.0.0.1:{server.port} ./\n')
    return {'server': server, 'repo': repo, 'ports': [server.port]}


def stop(state):
    for key in ('server', 'server2'):
        if key in state:
            state[key].stop()
    for proc in state.get('procs', ()):
        proc.kill()


def apt(*args, **kw):
    return real([m.APT_GET, '-q', '-o', 'Acquire::Retries=1', *args], {**m.SAFE_ENV, 'APT_CONFIG': str(lib.ROOT / 'apt.conf')}, 120)


# ---------------------------------------------------------------------------------------------------------------- cases
def s_offline_no_index():
    lib.new_root(trusted=True)
    (lib.ROOT / 'etc/sources.list').write_text('deb [trusted=yes] http://127.0.0.1:9/ubuntu ./\n')
    return {'ports': [9]}


case('offline-no-index', 'closed port, no package index was ever downloaded', s_offline_no_index)


def s_offline_dns():
    lib.new_root(trusted=True)
    (lib.ROOT / 'etc/sources.list').write_text('deb [trusted=yes] http://no-such-host.invalid/ubuntu ./\n')
    return {}


case('offline-dns', 'a source whose name does not resolve (.invalid), no index', s_offline_dns)


def s_offline_old_index():
    state = online()
    apt('update')
    state['server'].stop()  # the repository is gone, the index of the first run stays
    shutil.rmtree(lib.ROOT / 'cache', ignore_errors=True)
    (lib.ROOT / 'cache/archives/partial').mkdir(parents=True)
    return {'ports': state['ports']}


case('offline-old-index', 'the index was downloaded earlier, the repository is not reachable now, no .deb cached', s_offline_old_index)


def s_proxy_down():
    state = online()
    apt('update')
    shutil.rmtree(lib.ROOT / 'cache', ignore_errors=True)
    (lib.ROOT / 'cache/archives/partial').mkdir(parents=True)
    return state


case('proxy-down-old-index', 'old index; the administrator proxy (http_proxy) does not answer', s_proxy_down,
     env={'http_proxy': 'http://127.0.0.2:9'}, after=stop)


def s_universe_off():
    return online(drop=('age',))


case('universe-off', 'the reachable index has zstd and the python packages but not age', s_universe_off, after=stop)


def s_no_sources():
    lib.new_root(trusted=True)
    return {}


case('no-sources', 'no package source is configured at all', s_no_sources)


class NotFound(lib.Quiet):
    def do_GET(self):
        self.send_error(404)


class ProxyAuth(lib.Quiet):
    def do_GET(self):
        self.send_response(407)
        self.send_header('Proxy-Authenticate', 'Basic realm="proxy"')
        self.send_header('Content-Length', '0')
        self.end_headers()


class Portal(lib.Quiet):
    """A captive portal: every address answers 200 with a login page."""

    def do_GET(self):
        body = b'<html><body>please log in</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def s_third_party():
    state = online(drop=('age',))
    second = lib.Server(None, handler=NotFound, host='127.0.0.2')
    state['server2'] = second
    state['ports'].append(second.port)
    (lib.ROOT / 'etc/sources.list.d/third.list').write_text(f'deb http://127.0.0.2:{second.port}/thirdparty noble main\n')
    return state


case('third-party-404', 'age is not in the reachable index and a third-party source answers 404 (its repository was removed)',
     s_third_party, after=stop)


def s_third_party_ok():
    """The packages are available from the main source while a third-party source is broken: the update warns, install works."""
    state = online()
    second = lib.Server(None, handler=NotFound, host='127.0.0.2')
    state['server2'] = second
    state['ports'].append(second.port)
    (lib.ROOT / 'etc/sources.list.d/third.list').write_text(f'deb http://127.0.0.2:{second.port}/thirdparty noble main\n')
    return state


case('third-party-404-but-packages-available', 'a broken third-party source while the main source has every package: installs',
     s_third_party_ok, after=stop)


def s_unreadable():
    state = online()
    (lib.ROOT / 'etc/sources.list.d/broken.list').write_text('deb http://127.0.0.1:1/ubuntu\n')
    return state


case('sources-unreadable', 'a file in sources.list.d is malformed', s_unreadable, after=stop)


def s_no_key():
    return online(signed=True, key=False)


case('signature-no-key', 'the repository is signed, apt has no key for it, no earlier index', s_no_key, after=stop)


def s_expired():
    return online(signed=True, valid_until='Mon, 01 Jan 2024 00:00:00 UTC')


case('release-expired', 'the Release file says Valid-Until in the past', s_expired, after=stop)


def s_expired_old_index():
    state = online(signed=True)
    apt('update')  # a good index first
    (state['repo'] / 'Release').unlink()
    release = lib.sh(['apt-ftparchive', 'release', '.'], cwd=state['repo']).stdout
    (state['repo'] / 'Release').write_text(release)
    lib.sign(state['repo'], valid_until='Mon, 01 Jan 2024 00:00:00 UTC')
    return state


case('release-expired-old-index', 'an earlier good index; the repository now serves an expired Release', s_expired_old_index,
     after=stop)


def s_not_valid_yet():
    return online(signed=True, valid_until=None) | {}


def s_wrong_clock():
    state = online(signed=True)
    release = (state['repo'] / 'Release').read_text()
    release = re.sub(r'Date: .*', 'Date: Wed, 01 Jan 2031 00:00:00 UTC', release)
    (state['repo'] / 'Release').write_text(release)
    lib.sign(state['repo'])
    return state


case('release-not-valid-yet', 'the Release file is dated in the future (the clock of this device is wrong)', s_wrong_clock,
     after=stop)


def hold(path):
    """A process that keeps the POSIX lock apt takes on `path` (like another apt-get or unattended-upgrades)."""
    code = ('import fcntl,sys,time; f=open(sys.argv[1],"a+"); fcntl.lockf(f, fcntl.LOCK_EX); print("held", flush=True); time.sleep(600)')
    proc = subprocess.Popen([sys.executable, '-c', code, str(path)], stdout=subprocess.PIPE, text=True)
    proc.stdout.readline()
    return proc


def s_locked():
    state = online()
    state['procs'] = [hold(lib.ROOT / 'lists/lock'), hold(lib.ROOT / 'dpkg/lock-frontend')]
    return state


LOCK_TIMEOUT = '2'
case('locked', 'another process holds the lock of the package lists and the dpkg frontend lock', s_locked, after=stop)
LOCK_TIMEOUT = os.environ.get('LOCK_TIMEOUT')


def s_gone():
    state = online()
    apt('update')
    for deb in state['repo'].glob('*.deb'):
        deb.unlink()
    return state


case('package-gone', 'the index lists the packages, the files are gone from the server (404)', s_gone, after=stop)


def s_disk():
    state = online(size=10 ** 15)
    return state


case('disk-full', 'the index says the packages are enormous: not enough free space in the apt cache', s_disk, after=stop)


def s_interrupted():
    state = online()
    (lib.ROOT / 'dpkg/updates').mkdir(parents=True, exist_ok=True)
    (lib.ROOT / 'dpkg/updates/0001').write_text('')
    return state


case('dpkg-interrupted', 'dpkg has a half-done job (updates/ is not empty)', s_interrupted, after=stop)


def s_held():
    state = online()
    lib.installed('age', '1.0.0-1', status='hold ok installed')
    return state


case('held', 'age is installed at an older version and apt-mark hold keeps it', s_held, after=stop)


def s_conflict():
    state = online(extra={'age': 'Conflicts: zstd\n'})
    lib.installed('zstd', '1.0-1')
    return state


case('conflict', 'age conflicts with an installed package: apt would have to remove it', s_conflict, after=stop)


def s_unmet():
    return online(extra={'age': 'Depends: woowbk-no-such-library\n'})


case('unmet-dependencies', 'a package depends on one that no source has', s_unmet, after=stop)


def s_dpkg_fails():
    state = online()
    os.environ['STUB_EXIT'] = '1'
    return state


def end_dpkg_fails(state):
    os.environ.pop('STUB_EXIT', None)
    stop(state)


case('dpkg-fails', 'dpkg ends with an error while it installs', s_dpkg_fails, after=end_dpkg_fails)


def s_proxy_407():
    state = online()
    proxy = lib.Server(None, handler=ProxyAuth, host='127.0.0.2')
    state['server2'] = proxy
    state['ports'].append(proxy.port)
    os.environ['http_proxy'] = f'http://127.0.0.2:{proxy.port}'
    return state


case('proxy-407', 'a proxy asks for a login (407)', s_proxy_407, after=stop)


def s_portal():
    lib.new_root(trusted=True)
    server = lib.Server(None, handler=Portal)
    (lib.ROOT / 'etc/sources.list').write_text(f'deb http://127.0.0.1:{server.port} ./\n')
    return {'server': server, 'ports': [server.port]}


case('captive-portal', 'every address answers 200 with a login page', s_portal, after=stop)


def s_ok():
    return online()


case('ok-then-works', 'everything reachable (the probes of this harness still say "does not work")', s_ok, after=stop)


def s_damaged_offline_no_index():
    lib.new_root(trusted=True)
    (lib.ROOT / 'etc/sources.list').write_text('deb [trusted=yes] http://127.0.0.1:9/ubuntu ./\n')
    for name, version in lib.PACKAGES.items():
        lib.installed(name, version)
    return {'ports': [9]}


case('damaged-offline-no-index', 'the packages are installed (a tool does not answer), no index, the repository is not reachable',
     s_damaged_offline_no_index, packages=['zstd'])


def s_damaged_offline_old_index():
    state = online()
    apt('update')
    for name, version in lib.PACKAGES.items():
        lib.installed(name, version)
    state['server'].stop()
    shutil.rmtree(lib.ROOT / 'cache', ignore_errors=True)
    (lib.ROOT / 'cache/archives/partial').mkdir(parents=True)
    return {'ports': state['ports']}


case('damaged-offline-old-index', 'installed, old index, repository not reachable: a reinstall needs a download', s_damaged_offline_old_index)


def s_damaged_online():
    state = online()
    for name, version in lib.PACKAGES.items():
        lib.installed(name, version)
    return state


case('damaged-online', 'installed, index and files reachable: a reinstall works', s_damaged_online, after=stop)


# ------------------------------------------------------------------- the same with the layout of the Ubuntu archive (dists/)
def online_dists(*, signed=False, key=True, valid_until=None, date=None, components=('main',), age_in='main'):
    """http://127.0.0.1:PORT/ubuntu noble <components>: dists/noble/Release and pool/, like archive.ubuntu.com."""
    lib.new_root(trusted=signed and key)
    top = lib.HERE / 'repo-dists'
    shutil.rmtree(top, ignore_errors=True)
    site = top / 'ubuntu'
    lib.build_debs(site / 'pool/stage')
    for component in ('main', 'universe'):
        (site / f'pool/{component}').mkdir(parents=True, exist_ok=True)
        (site / f'dists/noble/{component}/binary-amd64').mkdir(parents=True, exist_ok=True)
    for deb in (site / 'pool/stage').glob('*.deb'):
        target = 'universe' if deb.name.startswith('age_') and age_in == 'universe' else 'main'
        deb.rename(site / 'pool' / target / deb.name)
    shutil.rmtree(site / 'pool/stage')
    for component in ('main', 'universe'):
        packages = lib.sh(['apt-ftparchive', 'packages', f'pool/{component}'], cwd=site).stdout
        (site / f'dists/noble/{component}/binary-amd64/Packages').write_text(packages)
    release = lib.sh(['apt-ftparchive', '-o', 'APT::FTPArchive::Release::Codename=noble', '-o', 'APT::FTPArchive::Release::Suite=noble',
                      '-o', 'APT::FTPArchive::Release::Architectures=amd64', '-o', 'APT::FTPArchive::Release::Components=main universe',
                      'release', 'dists/noble'], cwd=site).stdout
    (site / 'dists/noble/Release').write_text(release)
    if date:
        text = re.sub(r'Date: .*', f'Date: {date}', (site / 'dists/noble/Release').read_text())
        (site / 'dists/noble/Release').write_text(text)
    if signed:
        lib.sign(site / 'dists/noble', valid_until=valid_until)
    server = lib.Server(top)
    (lib.ROOT / 'etc/sources.list').write_text(
        f'deb {"" if signed else "[trusted=yes] "}http://127.0.0.1:{server.port}/ubuntu noble {" ".join(components)}\n')
    return {'server': server, 'ports': [server.port], 'site': site}


def s_dists_offline_old_index():
    state = online_dists(components=('main', 'universe'), age_in='universe')
    apt('update')
    state['server'].stop()
    shutil.rmtree(lib.ROOT / 'cache', ignore_errors=True)
    (lib.ROOT / 'cache/archives/partial').mkdir(parents=True)
    return {'ports': state['ports']}


case('dists-offline-old-index', 'archive layout (noble main universe): index downloaded earlier, the archive is not reachable now',
     s_dists_offline_old_index)


def s_dists_universe_off():
    return online_dists(components=('main',), age_in='universe')


case('dists-universe-off', 'archive layout: "noble main" only, age lives in universe', s_dists_universe_off, after=stop)


def s_dists_expired():
    return online_dists(signed=True, valid_until='Mon, 01 Jan 2024 00:00:00 UTC')


case('dists-release-expired', 'archive layout: InRelease says Valid-Until in the past', s_dists_expired, after=stop)


def s_dists_future():
    return online_dists(signed=True, date='Wed, 01 Jan 2031 00:00:00 UTC')


case('dists-release-not-valid-yet', 'archive layout: InRelease is dated in the future (the clock is wrong)', s_dists_future,
     after=stop)


def s_dists_no_key():
    return online_dists(signed=True, key=False)


case('dists-signature-no-key', 'archive layout: signed, apt has no key for it', s_dists_no_key, after=stop)


def s_third_party_down():
    state = online(drop=('age',))
    (lib.ROOT / 'etc/sources.list.d/third.list').write_text('deb http://127.0.0.2:9/thirdparty noble main\n')
    state['ports'].append(9)
    return state


case('third-party-down', 'age is not in the reachable index and a third-party source cannot be reached', s_third_party_down,
     after=stop)


def s_unsigned():
    return online(trusted_flag=False)


case('unsigned-source', 'a repository without any signature and without [trusted=yes]: apt does not take its index', s_unsigned,
     after=stop)
