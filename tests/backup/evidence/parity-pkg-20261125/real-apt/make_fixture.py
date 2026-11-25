"""Turn ./out/<case>/ (record.py) into the APT_RECORDED block of tests/test_manage.py (verbatim lines, one literal per line)."""
import pathlib, re, sys
OUT = pathlib.Path(__file__).resolve().parent / 'out'
CASES = ['offline-no-index', 'offline-dns', 'offline-old-index', 'dists-offline-old-index', 'proxy-407', 'captive-portal',
         'dists-universe-off', 'no-sources', 'third-party-404', 'third-party-down', 'sources-unreadable', 'signature-no-key',
         'release-expired', 'dists-release-expired', 'dists-release-not-valid-yet', 'unsigned-source', 'locked', 'package-gone', 'disk-full',
         'dpkg-interrupted', 'held', 'conflict', 'unmet-dependencies', 'dpkg-fails', 'damaged-offline-no-index',
         'damaged-offline-old-index']


def text(path):
    data = path.read_text()
    return re.sub(r'NO_PUBKEY [0-9A-F]{16}', 'NO_PUBKEY 0000000000000000', data)  # id of a throwaway test key


def literal(data, indent):
    """Adjacent string literals, one per line of apt's output."""
    if not data:
        return "''"
    pad = ' ' * indent
    return f'\n{pad}'.join(repr(line) for line in data.splitlines(keepends=True))


rows = []
for case in CASES:
    folder = OUT / case
    parts = []
    for kind in ('update', 'install'):
        rc = int((folder / f'{kind}.rc').read_text())
        out, err = text(folder / f'{kind}.out'), text(folder / f'{kind}.err')
        parts.append(f'({rc},\n         {literal(out, 9)},\n         {literal(err, 9)})')
    rows.append(f"    {case!r}: (\n        {parts[0]},\n        {parts[1]}),")
block = ('# What the real apt-get 2.8.4 wrote in the C locale: {case: (update, install)}, each (exit code, stdout, stderr). Recorded\n'
         '# 2026-11-25 with the exact argv of manage.HostTools in a private unprivileged apt root (local repository, dpkg replaced by a\n'
         '# stub; host names, ports and paths replaced), every line as apt wrote it. The raw files and the script that made them:\n'
         '# tests/backup/evidence/parity-pkg-20261125/real-apt/.\n'
         'APT_RECORDED = {\n' + '\n'.join(rows) + '\n}\n')
pathlib.Path(sys.argv[1]).write_text(block)
print(len(block), 'bytes,', block.count('\n'), 'lines')
