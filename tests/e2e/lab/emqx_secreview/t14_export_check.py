"""T14 (iteration 5): the product's check_export on EMQX 5.8.9's OWN libraries, without booting a broker.

Every case is a small archive with harmless configuration (`sysmon` stands for "a root the import must not bring").
The product's unmodified expression (ha_emqx.export_expression) is evaluated in a throwaway container of the EMQX image
(--network none, read-only, no capabilities) by the image's own Erlang, the way `emqx eval` evaluates it
(erl_scan / erl_parse / erl_eval), with the image's erl_tar, hocon and emqx_utils; check_export decides on the answer.
The archive folder is mounted read-only at /work/in, the path the product uses. A component check: the product flow
with real brokers is T11 (real backups) and T13 (forged export).
Run: python3 -I t14_export_check.py <codebase>"""
import gzip
import io
import json
import os
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402

NAME = 'emqx-export-2026-11-24-00-00-00.000.tar.gz'
BASE = NAME[:-len('.tar.gz')]
DATA = ('authentication = [\n  {\n    backend = built_in_database\n    mechanism = password_based\n'
        '    password_hash_algorithm {name = sha256, salt_position = suffix}\n  }\n]\n'
        'authorization {\n  no_match = deny\n  sources = [{enable = true, path = "/opt/emqx/etc/acl.conf", type = file}]\n}\n'
        'rule_engine {\n  rules {\n    rule_0 {\n      sql = """~\n        SELECT * FROM "t/#" WHERE a = "x {y} = z [w]"\n      ~"""\n'
        '    }\n  }\n}\n')
EXTRA = 'sysmon {os {cpu_check_interval = 70s}}\n'
EVAL = '''#!/usr/bin/env escript
%% what nodetool/emqx_ctl do with `emqx eval <expression>`
main([File]) ->
    [code:add_pathz(D) || D <- filelib:wildcard("/opt/emqx/lib/*/ebin")],
    {ok, Bin} = file:read_file(File),
    {ok, Tokens, _} = erl_scan:string(unicode:characters_to_list(Bin)),
    {ok, Exprs} = erl_parse:parse_exprs(Tokens),
    {value, V, _} = erl_eval:exprs(Exprs, []),
    io:format("~p~n", [V]).
'''


def tar_of(entries):
    """entries: [(name, bytes | ('link', target) | ('dir',))]; a plain (uncompressed) tar."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                info.type = tarfile.SYMTYPE if value[0] == 'link' else tarfile.DIRTYPE
                info.linkname = value[1] if value[0] == 'link' else ''
                tar.addfile(info)
            else:
                info.size = len(value)
                tar.addfile(info, io.BytesIO(value))
    return buf.getvalue()


def members(hocon=DATA, tables=('emqx_authn_mnesia', 'emqx_acl', 'emqx_admin'), extra=()):
    out = [(f'{BASE}/META.hocon', b'edition = ce\nversion = "5.8.9"\n')]
    if hocon is not None:
        out.append((f'{BASE}/cluster.hocon', hocon if isinstance(hocon, bytes) else hocon.encode()))
    out += [(f'{BASE}/mnesia/{t}', b'x' * 40) for t in tables]
    return out + list(extra)


def two_gzip_members():
    """One tar cut into two gzip members: a reader that stops after the first does not see the second half."""
    raw = tar_of(members(extra=[(f'{BASE}/mnesia/other_table', b'x')]))
    cut = raw.index(f'{BASE}/mnesia/other_table'.encode())
    return gzip.compress(raw[:cut]) + gzip.compress(raw[cut:])


def cases(ha_emqx):
    gz = gzip.compress
    long_list = [(f'{BASE}/mnesia/{t}', b'x') for t in ha_emqx.TABLES]
    yield 'healthy', gz(tar_of(members())), 'pass'
    yield 'healthy-all-tables', gz(tar_of([m for m in members(tables=())] + long_list)), 'pass'
    yield 'healthy-no-cluster-hocon', gz(tar_of(members(hocon=None))), 'pass'
    yield 'healthy-empty-cluster-hocon', gz(tar_of(members(hocon=''))), 'pass'
    for label, text in (('root-plain', EXTRA), ('root-quoted', '"sysmon" {os {cpu_check_interval = 70s}}\n'),
                        ('root-colon', 'sysmon : {os {cpu_check_interval = 70s}}\n'),
                        ('root-dotted', 'sysmon.os.cpu_check_interval = 70s\n'),
                        ('root-after-quote-in-comment', '# "\n' + EXTRA + '# "\n'),
                        ('root-after-triple-quote-in-comment', '# """\n' + EXTRA + '# """\n'),
                        ('root-nbsp', 'sysmon {os {cpu_check_interval = 70s}}\n'),
                        ('root-same-line', 'retainer {enable = true}, ' + EXTRA)):
        yield label, gz(tar_of(members(hocon=DATA + text))), 'refuse'
    yield 'document-in-braces', gz(tar_of(members(hocon='{\n' + DATA + EXTRA + '}\n'))), 'refuse'
    yield 'include-directive', gz(tar_of(members(hocon=DATA + 'include "mnesia/emqx_acl"\n'))), 'refuse'
    yield 'not-hocon', gz(tar_of(members(hocon='{{{'))), 'refuse'
    yield 'not-utf8', gz(tar_of(members(hocon=b'\xff\xfe\x00'))), 'refuse'
    yield 'other-table', gz(tar_of(members(extra=[(f'{BASE}/mnesia/other_table', b'x')]))), 'refuse'
    yield 'other-table-second-gzip-member', two_gzip_members(), 'refuse'
    yield 'other-file', gz(tar_of(members(extra=[(f'{BASE}/authz/acl.conf', b'x')]))), 'refuse'
    yield 'other-top-folder', gz(tar_of(members(extra=[('other/META.hocon', b'x')]))), 'refuse'
    yield 'parent-path', gz(tar_of(members(extra=[(f'{BASE}/../x', b'x')]))), 'refuse'
    yield 'symlink-table', gz(tar_of(members(tables=(), extra=[(f'{BASE}/mnesia/emqx_acl', ('link', '/etc/hostname'))]))), 'refuse'
    yield 'symlink-cluster-hocon', gz(tar_of(members(hocon=None, extra=[(f'{BASE}/cluster.hocon', ('link', '/etc/hostname'))]))), 'refuse'
    yield 'cluster-hocon-twice', gz(tar_of(members() + [(f'{BASE}/cluster.hocon', (DATA + EXTRA).encode())])), 'refuse'
    yield 'folder-entry', gz(tar_of(members(extra=[(f'{BASE}/mnesia', ('dir',))]))), 'refuse'
    yield 'cluster-hocon-too-large', gz(tar_of(members(hocon=DATA + '#' * ha_emqx.MAX_HOCON + '\n'))), 'refuse'
    yield 'not-gzip', b'plain text, not an archive', 'refuse'
    yield 'empty-file', b'', 'refuse'
    yield 'truncated', gz(tar_of(members()))[:-60], 'refuse'


def main(codebase):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': "T14 check_export on EMQX 5.8.9's own erl_tar/hocon (no broker)", 'codebase': codebase,
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)', 'cases': {}}
    base = os.path.join(L.SR, 'runs')
    work = tempfile.mkdtemp(prefix='t14-', dir=base)
    os.chmod(work, 0o755)
    for sub in ('in', 'eval'):
        os.mkdir(os.path.join(work, sub), 0o755)
    with open(os.path.join(work, 'eval', 'eval.escript'), 'w') as handle:
        handle.write(EVAL)

    def execute(command):
        with open(os.path.join(work, 'eval', 'expression.txt'), 'w') as handle:
            handle.write(command[2])
        run = L.lab('run', '--rm', '--network', 'none', '--read-only', '--memory', '512m', '--pids-limit', '128',
                    '--cap-drop=all', '--security-opt', 'no-new-privileges', '--pull=never',
                    '--entrypoint', '/opt/emqx/erts-14.2.5.11/bin/escript',
                    '-v', os.path.join(work, 'in') + ':/work/in:ro', '-v', os.path.join(work, 'eval') + ':/eval:ro',
                    L.IMAGE, '/eval/eval.escript', '/eval/expression.txt', check=False)
        return SimpleNamespace(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)

    for label, data, want in cases(ha_emqx):
        with open(os.path.join(work, 'in', NAME), 'wb') as handle:
            handle.write(data)
        os.chmod(os.path.join(work, 'in', NAME), 0o644)
        try:
            ha_emqx.check_export(execute, NAME)
            got, message = 'pass', ''
        except L.BackupError as error:
            got, message = 'refuse', error.message
        result['cases'][label] = {'want': want, 'got': got, 'message': message}
        print(label, got, 'OK' if got == want else 'UNEXPECTED', message[:140])
    for root, _dirs, names in os.walk(work):
        for name in names:
            os.unlink(os.path.join(root, name))
    result['as_expected'] = sum(case['want'] == case['got'] for case in result['cases'].values())
    result['total'] = len(result['cases'])
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps({k: result[k] for k in ('as_expected', 'total', 'elapsed_s')}))
    L.evidence(os.path.join(base, f't14-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
