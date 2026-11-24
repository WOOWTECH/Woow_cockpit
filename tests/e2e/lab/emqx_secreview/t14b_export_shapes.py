"""T14b (iteration 6): more archive shapes for the product's check_export, and a parser differential.

Part 1: archive shapes T14 did not build (hard link, FIFO, character device, PAX `path` override, GNU long name,
absolute name, `./` and `//` spellings, a folder in another case, a declared size over the limit) and more HOCON
spellings (byte-order mark, CR/LF and CR-only line ends, tab, `//` comment, a `\\u` escape in a quoted key, a quoted
dotted key, `include required(...)`, the word `include` in a comment or a string, a data root given twice). Content
is harmless: `sysmon` stands for "a root the import must not bring", like T14. The product's unmodified expression
runs in a throwaway container of the EMQX image (--network none, read-only, no capabilities), check_export decides.

Part 2 (differential): the check parses cluster.hocon with `hocon:binary` on the member read into memory, the vendor
import with `hocon:files` on the member extracted to a folder (emqx_mgmt_data_backup.erl:880-884, :904-909). For every
HOCON document of T14 and T14b the same container extracts the member both ways and compares the root names the two
calls return (or that both fail). A difference where `hocon:files` sees a root `hocon:binary` does not would let a
root past the check; any other difference only refuses more.
Run: python3 -I t14b_export_shapes.py <codebase>"""
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
import t14_export_check as T  # noqa: E402

NAME, BASE, DATA, EXTRA = T.NAME, T.BASE, T.DATA, T.EXTRA
DIFF_EXPR = ('F = "/work/in/' + NAME + '", C = filename:basename(F, ".tar.gz") ++ "/cluster.hocon", '
             '{ok, [{C, B}]} = erl_tar:extract(F, [compressed, memory, {files, [C]}]), '
             'D = "/tmp/diff", ok = filelib:ensure_dir(D ++ "/x"), '
             'ok = erl_tar:extract(F, [compressed, {cwd, D}, {files, [C]}]), '
             'K = fun(R) -> case R of {ok, M} when is_map(M) -> lists:sort(maps:keys(M)); _ -> <<"error">> end end, '
             'RB = K(catch hocon:binary(B)), RF = K(catch hocon:files([filename:join(D, C)])), '
             'io:format("WOOWDIFF:~s:END~n", [base64:encode(emqx_utils_json:encode(#{binary => RB, files => RF}))]).')


def tar_entries(entries, fmt=tarfile.USTAR_FORMAT):
    """entries: dicts {name, data | type (+ linkname), pax}; regular files carry data."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=fmt) as tar:
        for entry in entries:
            info = tarfile.TarInfo(entry['name'])
            info.type = entry.get('type', tarfile.REGTYPE)
            info.linkname = entry.get('linkname', '')
            if 'pax' in entry:
                info.pax_headers = dict(entry['pax'])
            if info.type == tarfile.REGTYPE:
                info.size = len(entry['data'])
                tar.addfile(info, io.BytesIO(entry['data']))
            else:
                tar.addfile(info)
    return buf.getvalue()


def healthy(**kwargs):
    return [{'name': name, 'data': data} for name, data in T.members(**kwargs)]


def raw_member(name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info.tobuf(format=tarfile.USTAR_FORMAT) + data + b'\0' * ((512 - len(data) % 512) % 512)


def declared_size_over_limit(limit):
    """Healthy members, then an emqx_acl header that claims limit + 1 bytes; the archive ends right after it."""
    raw = b''.join(raw_member(name, data) for name, data in T.members(tables=('emqx_authn_mnesia', 'emqx_admin')))
    info = tarfile.TarInfo(f'{BASE}/mnesia/emqx_acl')
    info.size = limit + 1
    return gzip.compress(raw + info.tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024)


HOCON_EXTRA = (   # label, cluster.hocon text, want ('refuse', 'pass' or None = no expectation, the differential decides)
    ('bom-data-only', '﻿' + DATA, None),
    ('bom-root', '﻿' + DATA + EXTRA, 'refuse'),
    ('crlf-root', (DATA + EXTRA).replace('\n', '\r\n'), 'refuse'),
    ('cr-only-root', (DATA + EXTRA).replace('\n', '\r'), 'refuse'),
    ('tab-root', DATA + '\t' + EXTRA, 'refuse'),
    ('slash-comment-root', DATA + '// a comment\n' + EXTRA, 'refuse'),
    ('unicode-escape-quoted-key', DATA + '"\\u0073ysmon" {os {cpu_check_interval = 70s}}\n', 'refuse'),
    ('quoted-dotted-key', DATA + '"sysmon.os" {cpu_check_interval = 70s}\n', 'refuse'),
    ('include-required', DATA + 'include required("mnesia/emqx_acl")\n', 'refuse'),
    ('include-word-in-comment', DATA + '# include "mnesia/emqx_acl"\n', 'pass'),
    ('include-word-in-string', DATA + 'retainer {enable = true, note = "include mnesia/emqx_acl"}\n', 'pass'),
    ('data-root-twice', DATA + 'authorization {no_match = deny}\n', 'pass'),
)
T14_HOCON = (   # T14's documents, for the differential only (their check results are in iteration5/t14-fix.json)
    ('t14-healthy', DATA), ('t14-root-plain', DATA + EXTRA),
    ('t14-root-quoted', DATA + '"sysmon" {os {cpu_check_interval = 70s}}\n'),
    ('t14-root-colon', DATA + 'sysmon : {os {cpu_check_interval = 70s}}\n'),
    ('t14-root-dotted', DATA + 'sysmon.os.cpu_check_interval = 70s\n'),
    ('t14-root-after-quote-in-comment', DATA + '# "\n' + EXTRA + '# "\n'),
    ('t14-root-after-triple-quote-in-comment', DATA + '# """\n' + EXTRA + '# """\n'),
    ('t14-root-nbsp', DATA + 'sysmon {os {cpu_check_interval = 70s}}\n'),
    ('t14-root-same-line', DATA + 'retainer {enable = true}, ' + EXTRA),
    ('t14-document-in-braces', '{\n' + DATA + EXTRA + '}\n'),
    ('t14-include-directive', DATA + 'include "mnesia/emqx_acl"\n'),
    ('t14-not-hocon', '{{{'),
)


def cases(ha_emqx):
    gz = gzip.compress
    plain = healthy(tables=('emqx_authn_mnesia', 'emqx_admin'))
    acl = f'{BASE}/mnesia/emqx_acl'
    yield 'hard-link-table', gz(tar_entries(plain + [{'name': acl, 'type': tarfile.LNKTYPE,
                                                     'linkname': f'{BASE}/mnesia/emqx_admin'}])), 'refuse', None
    yield 'fifo-table', gz(tar_entries(plain + [{'name': acl, 'type': tarfile.FIFOTYPE}])), 'refuse', None
    yield 'char-device-table', gz(tar_entries(plain + [{'name': acl, 'type': tarfile.CHRTYPE}])), 'refuse', None
    yield ('pax-path-other-table', gz(tar_entries(plain + [{'name': acl, 'data': b'x' * 40,
                                                          'pax': {'path': f'{BASE}/mnesia/other_table'}}],
                                                  fmt=tarfile.PAX_FORMAT)), 'refuse', None)
    yield ('pax-path-cluster-hocon', gz(tar_entries(healthy(hocon=None) + [
        {'name': f'{BASE}/notes.txt', 'data': (DATA + EXTRA).encode(), 'pax': {'path': f'{BASE}/cluster.hocon'}}],
        fmt=tarfile.PAX_FORMAT)), 'refuse', None)
    yield ('gnu-long-name', gz(tar_entries(healthy() + [{'name': f'{BASE}/mnesia/' + 'a' * 120, 'data': b'x'}],
                                           fmt=tarfile.GNU_FORMAT)), 'refuse', None)
    yield 'absolute-name', gz(tar_entries(plain + [{'name': '/' + acl, 'data': b'x' * 40}])), 'refuse', None
    yield ('dot-segment-cluster-hocon', gz(tar_entries(healthy() + [
        {'name': f'{BASE}/./cluster.hocon', 'data': (DATA + EXTRA).encode()}])), 'refuse', None)
    yield ('double-slash-cluster-hocon', gz(tar_entries(healthy() + [
        {'name': f'{BASE}//cluster.hocon', 'data': (DATA + EXTRA).encode()}])), 'refuse', None)
    yield 'folder-other-case', gz(tar_entries(plain + [{'name': f'{BASE}/MNESIA/emqx_acl', 'data': b'x'}])), 'refuse', None
    yield 'declared-size-over-limit', declared_size_over_limit(ha_emqx.MAX_EXPORT), 'refuse', None
    for label, text, want in HOCON_EXTRA:
        yield label, gz(tar_entries(healthy(hocon=text))), want, True
    for label, text in T14_HOCON:
        yield label, gz(tar_entries(healthy(hocon=text))), None, True


def main(codebase):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T14b more archive shapes for check_export + hocon:binary vs hocon:files differential',
              'codebase': codebase, 'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)',
              'check': 'check_export', 'cases': {}}
    base = os.path.join(L.SR, 'runs')
    work = tempfile.mkdtemp(prefix='t14b-', dir=base)
    os.chmod(work, 0o755)
    for sub in ('in', 'eval'):
        os.mkdir(os.path.join(work, sub), 0o755)
    with open(os.path.join(work, 'eval', 'eval.escript'), 'w') as handle:
        handle.write(T.EVAL)

    def execute(command):
        with open(os.path.join(work, 'eval', 'expression.txt'), 'w') as handle:
            handle.write(command[2])
        run = L.lab('run', '--rm', '--network', 'none', '--read-only', '--memory', '512m', '--pids-limit', '128',
                    '--cap-drop=all', '--security-opt', 'no-new-privileges', '--pull=never',
                    '--entrypoint', '/opt/emqx/erts-14.2.5.11/bin/escript',
                    '-v', os.path.join(work, 'in') + ':/work/in:ro', '-v', os.path.join(work, 'eval') + ':/eval:ro',
                    L.IMAGE, '/eval/eval.escript', '/eval/expression.txt', check=False)
        return SimpleNamespace(returncode=run.returncode, stdout=run.stdout, stderr=run.stderr)

    def differential():
        body = execute(['emqx', 'eval', DIFF_EXPR]).stdout or b''
        if not body.startswith(b'WOOWDIFF:'):
            return {'ran': False}
        import base64
        answer = json.loads(base64.b64decode(body[9:].split(b':END', 1)[0]))
        return {'ran': True, 'binary': answer['binary'], 'files': answer['files'],
                'equal': answer['binary'] == answer['files']}

    for label, data, want, diff in cases(ha_emqx):
        with open(os.path.join(work, 'in', NAME), 'wb') as handle:
            handle.write(data)
        os.chmod(os.path.join(work, 'in', NAME), 0o644)
        try:
            ha_emqx.check_export(execute, NAME)
            got, message = 'pass', ''
        except L.BackupError as error:
            got, message = 'refuse', error.message
        case = {'want': want, 'got': got, 'message': message[:200]}
        if diff:
            case['differential'] = differential()
        result['cases'][label] = case
        print(label, got, 'n/a' if want is None else ('OK' if got == want else 'UNEXPECTED'),
              json.dumps(case.get('differential', {}), ensure_ascii=True)[:160])
    for root, _dirs, names in os.walk(work):
        for name in names:
            os.unlink(os.path.join(root, name))
    expected = [c for c in result['cases'].values() if c['want'] is not None]
    diffs = [c['differential'] for c in result['cases'].values() if 'differential' in c]
    result['as_expected'] = sum(c['want'] == c['got'] for c in expected)
    result['with_expectation'] = len(expected)
    result['total'] = len(result['cases'])
    result['differential_ran'] = sum(d['ran'] for d in diffs)
    result['differential_total'] = len(diffs)
    result['differential_equal'] = sum(d.get('equal', False) for d in diffs)
    # the dangerous direction only: a root hocon:files returns that hocon:binary does not (or binary parses, files not)
    result['files_sees_more_roots'] = sorted(
        label for label, c in result['cases'].items() if c.get('differential', {}).get('ran')
        and isinstance(c['differential']['files'], list) and (
            not isinstance(c['differential']['binary'], list)
            or set(c['differential']['files']) - set(c['differential']['binary'])))
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps({k: result[k] for k in ('as_expected', 'with_expectation', 'total', 'differential_ran',
                                             'differential_total', 'differential_equal', 'files_sees_more_roots',
                                             'elapsed_s')}))
    L.evidence(os.path.join(base, f't14b-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
