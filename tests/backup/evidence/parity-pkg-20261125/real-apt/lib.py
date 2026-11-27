"""Private, unprivileged apt root with dummy packages and a local HTTP repository, for recording what the REAL apt-get
(2.8.4, C locale) writes. No host file outside this directory is touched; dpkg is a stub that only logs and unpacks."""
import functools, http.server, os, pathlib, shutil, subprocess, threading, textwrap, hashlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE / 'root'
GNUPG = HERE / 'gnupg'
PACKAGES = {'age': '1.1.1-1', 'zstd': '1.5.5-1', 'python3-nacl': '1.5.0-4', 'python3-cryptography': '41.0.7-4'}


def sh(argv, **kw):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kw)


def build_debs(directory, extra=None, only=None):
    """One tiny .deb per package; extra[name] adds control lines (Depends, Conflicts)."""
    directory.mkdir(parents=True, exist_ok=True)
    work = HERE / 'debwork'
    for name, version in PACKAGES.items():
        if only is not None and name not in only:
            continue
        tree = work / name
        shutil.rmtree(tree, ignore_errors=True)
        (tree / 'DEBIAN').mkdir(parents=True)
        (tree / 'DEBIAN/control').write_text(
            f'Package: {name}\nVersion: {version}\nArchitecture: all\nMaintainer: Test <test@example.invalid>\n'
            f'Description: dummy {name}\n{(extra or {}).get(name, "")}')
        (tree / 'usr/share/doc').mkdir(parents=True)
        (tree / 'usr/share/doc' / name).write_text(name)
        sh(['dpkg-deb', '--build', '-Zgzip', str(tree), str(directory / f'{name}_{version}_all.deb')])


def index(directory, size=None):
    """Packages (+ .gz not needed) and Release of a flat repository; `size` overrides the Size: of every package."""
    packages = sh(['apt-ftparchive', 'packages', '.'], cwd=directory).stdout
    if size is not None:
        packages = '\n'.join(f'Size: {size}' if line.startswith('Size: ') else line for line in packages.split('\n'))
    (directory / 'Packages').write_text(packages)
    release = sh(['apt-ftparchive', '-o', 'APT::FTPArchive::Release::Origin=woowbk-test',
                  '-o', 'APT::FTPArchive::Release::Label=woowbk-test', 'release', '.'], cwd=directory).stdout
    (directory / 'Release').write_text(release)


def make_key():
    if not (GNUPG / 'ok').exists():
        shutil.rmtree(GNUPG, ignore_errors=True)
        GNUPG.mkdir(mode=0o700)
        env = {**os.environ, 'GNUPGHOME': str(GNUPG)}
        parameters = ('%no-protection\nKey-Type: RSA\nKey-Length: 2048\nKey-Usage: sign\nName-Real: woowbk test\n'
                      'Name-Email: test@example.invalid\nExpire-Date: 0\n%commit\n')
        subprocess.run(['gpg', '--batch', '--gen-key'], input=parameters, text=True, env=env, check=True, capture_output=True)
        pub = sh(['gpg', '--armor', '--export', 'woowbk test'], env=env).stdout
        (GNUPG / 'test.asc').write_text(pub)
        (GNUPG / 'ok').write_text('1')
    return GNUPG


def sign(directory, valid_until=None):
    """InRelease (clearsigned) and Release.gpg of a flat repository."""
    make_key()
    env = {**os.environ, 'GNUPGHOME': str(GNUPG)}
    release = (directory / 'Release').read_text()
    if valid_until:
        release = release.replace('Date:', f'Valid-Until: {valid_until}\nDate:', 1)
        (directory / 'Release').write_text(release)
    for name in ('InRelease', 'Release.gpg'):
        (directory / name).unlink(missing_ok=True)
    sh(['gpg', '--batch', '--yes', '--clearsign', '-o', str(directory / 'InRelease'), str(directory / 'Release')], env=env)
    sh(['gpg', '--batch', '--yes', '--detach-sign', '-o', str(directory / 'Release.gpg'), str(directory / 'Release')], env=env)


class Server:
    def __init__(self, directory, handler=None, host='127.0.0.1'):
        handler = handler or functools.partial(Quiet, directory=str(directory))
        self.host = host
        self.http = http.server.ThreadingHTTPServer((host, 0), handler)
        self.port = self.http.server_address[1]
        threading.Thread(target=self.http.serve_forever, daemon=True).start()

    def stop(self):
        self.http.shutdown()
        self.http.server_close()


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def new_root(trusted=False):
    """A fresh apt root: empty lists and cache, no installed package, dpkg stub; Debug::NoLocking off."""
    shutil.rmtree(ROOT, ignore_errors=True)
    for sub in ('etc/apt.conf.d', 'etc/preferences.d', 'etc/sources.list.d', 'etc/trusted.gpg.d', 'dpkg', 'lists/partial',
                'cache/archives/partial', 'log', 'root'):
        (ROOT / sub).mkdir(parents=True, exist_ok=True)
    (ROOT / 'dpkg/status').write_text('')
    (ROOT / 'etc/sources.list').write_text('')
    stub = ROOT / 'dpkg-stub'
    stub.write_text(textwrap.dedent(f'''\
        #!/bin/bash
        # stands in for dpkg: logs its arguments and unpacks the .deb files below {ROOT}/root
        printf '%s\\n' "$*" >> "{ROOT}/dpkg-calls"
        for a in "$@"; do
          case $a in
            *.deb) /usr/bin/dpkg-deb -x "$a" "{ROOT}/root" ;;
            /tmp/apt-dpkg-install-*) for f in "$a"/*.deb; do /usr/bin/dpkg-deb -x "$f" "{ROOT}/root"; done ;;
          esac
        done
        exit ${{STUB_EXIT:-0}}
        '''))
    stub.chmod(0o755)
    conf = f'''\
Dir "{ROOT}";
Dir::Etc "{ROOT}/etc";
Dir::Etc::sourcelist "{ROOT}/etc/sources.list";
Dir::Etc::sourceparts "{ROOT}/etc/sources.list.d";
Dir::Etc::parts "{ROOT}/etc/apt.conf.d";
Dir::Etc::preferences "{ROOT}/etc/preferences";
Dir::Etc::preferencesparts "{ROOT}/etc/preferences.d";
Dir::Etc::trusted "{ROOT}/etc/trusted.gpg";
Dir::Etc::trustedparts "{ROOT}/etc/trusted.gpg.d";
Dir::State "{ROOT}/dpkg";
Dir::State::lists "{ROOT}/lists/";
Dir::State::status "{ROOT}/dpkg/status";
Dir::State::extended_states "{ROOT}/dpkg/extended_states";
Dir::Cache "{ROOT}/cache";
Dir::Log "{ROOT}/log";
Dir::Bin::dpkg "{ROOT}/dpkg-stub";
APT::Sandbox::User "";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
'''
    (ROOT / 'apt.conf').write_text(conf)
    if trusted:
        make_key()
        shutil.copy(GNUPG / 'test.asc', ROOT / 'etc/trusted.gpg.d/woowbk-test.asc')
    return ROOT


def installed(name, version, status='install ok installed'):
    with open(ROOT / 'dpkg/status', 'a') as handle:
        handle.write(f'Package: {name}\nStatus: {status}\nPriority: optional\nSection: misc\nArchitecture: all\n'
                     f'Version: {version}\nMaintainer: Test <test@example.invalid>\nDescription: dummy\n\n')
