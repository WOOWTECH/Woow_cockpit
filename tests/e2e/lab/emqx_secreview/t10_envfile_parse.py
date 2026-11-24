"""T10 (SR-9): does the product's Target.candidate_env() read an EnvironmentFile exactly as podman --env-file does?
Real podman (labpodman, --network none, entrypoint /usr/bin/env, tmpfs on both image VOLUME paths) is the oracle.
Values are generated test strings (no credential); the record keeps outcomes and digests only."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L  # noqa: E402

CODEBASE = sys.argv[1] if len(sys.argv) > 1 else 'tip'
OUT = os.path.join(L.SR, 'runs', f't10-{CODEBASE}.json')
CASES = {
    'crlf': b'EMQX_T1=v1\r\n',
    'vt_inside': b'EMQX_T2=a\x0bEMQX_T2B=b\n',
    'fs_inside': b'EMQX_T3=a\x1cEMQX_T3B=b\n',
    'u2028_inside': 'EMQX_T4=a EMQX_T4B=b\n'.encode(),
    'nel_inside': 'EMQX_T5=a\u0085EMQX_T5B=b\n'.encode(),
    'lone_cr_inside': b'EMQX_T6=a\rEMQX_T6B=b\n',
    'invalid_utf8': b'EMQX_T7=a\xffb\n',
    'tab_inside': b'EMQX_T8=a\tb\n',
    'leading_blanks': b'   EMQX_T9=v\n',
    'leading_tab': b'\tEMQX_T10=v\n',
    'inline_comment': b'EMQX_T11=v # c\n',
    'ff_inside': b'EMQX_T12=a\x0cEMQX_T12B=b\n',
    'no_final_newline': b'EMQX_T13=v',
    'space_before_eq': b'EMQX_T14 =v\n',
    'export_prefix': b'export EMQX_T16=v\n',
    'two_equals': b'EMQX_T17=a=b\n',
    'leading_ideographic_space': '　EMQX_T19=v\n'.encode(),
    'leading_fs': b'\x1cEMQX_T20=v\n',
    'empty_value': b'EMQX_T21=\n',
    'utf8_value': 'EMQX_T22=café\n'.encode(),
    'gs_inside': b'EMQX_T23=a\x1dEMQX_T23B=b\n',
    'rs_inside': b'EMQX_T24=a\x1eEMQX_T24B=b\n',
    'u2029_inside': 'EMQX_T25=a\u2029EMQX_T25B=b\n'.encode(),
    'crlf_twice': b'EMQX_T26=a\r\nEMQX_T26B=b\r\n',
    'leading_us': b'\x1fEMQX_T27=v\n',
}


class OwnerFiles:
    def __init__(self, home):
        self.home = home

    def read_file(self, rel, max_bytes):
        fd = os.open(os.path.join(self.home, rel), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            return handle.read(max_bytes)


def podman_env(path):
    r = L.lab('run', '--rm', '--network', 'none', '--pull=never', '--memory', '128m', '--env-file', path,
              '--tmpfs', '/opt/emqx/data', '--tmpfs', '/opt/emqx/log', '--entrypoint', '/usr/bin/env', L.IMAGE, '-0',
              check=False, timeout=120)
    if r.returncode:
        return None, r.returncode
    env = {}
    for item in r.stdout.split(b'\0'):
        if b'=' in item:
            k, v = item.split(b'=', 1)
            env[k] = v
    return env, 0


def candidate_env_in_container(ha_emqx, env, env_files):
    """The environment of a container the product starts with TempObjects.run(env=..., env_files=...), as
    target_broker does (job volumes on both image VOLUME paths, removed by the job's cleanup)."""
    runner = L.make_runner()
    with L.temp(runner, memory='256m') as tmp:
        tmp.volume('t10-data')
        tmp.volume('t10-log')
        r = tmp.run('t10', L.IMAGE, ['-0'], entrypoint='/usr/bin/env', read_only_root=True, env=env,
                    env_files=env_files, volumes=[(tmp.name('t10-data'), ha_emqx.DATA_TARGET, None),
                                                  (tmp.name('t10-log'), ha_emqx.LOG_TARGET, None)], timeout=120)
    found = {}
    for item in (r.stdout or b'').split(b'\0'):
        if b'=' in item:
            k, v = item.split(b'=', 1)
            if b'EMQX_T' in k:
                found[k] = v
    return found


def main():
    ha_emqx = L.use(CODEBASE)
    home = os.path.join(L.SR, 'runs', 't10-home')
    os.makedirs(home, mode=0o700, exist_ok=True)
    rows = {}
    for name, content in CASES.items():
        path = os.path.join(home, 'emqx.env')
        with open(path, 'wb') as handle:
            handle.write(content)
        target = ha_emqx.Target.__new__(ha_emqx.Target)
        target.env, target.env_files, target._runner, target.home = {}, ['%h/emqx.env'], OwnerFiles(home), home
        try:
            got = ha_emqx.Target.candidate_env(target)
            if isinstance(got, tuple):   # fixed product: podman reads the files; read the started candidate's env
                product = candidate_env_in_container(ha_emqx, got[0], got[1])
            else:
                product = {k.encode(): v.encode('utf-8', 'surrogateescape') for k, v in got.items()}
            product_refused = False
        except L.BackupError as error:
            product, product_refused = None, error.code
        oracle, rc = podman_env(path)
        oracle_t = None if oracle is None else {k: v for k, v in oracle.items() if b'EMQX_T' in k}
        if product_refused:
            outcome = 'REFUSED'
        elif oracle is None:
            outcome = 'PODMAN-REFUSES-FILE'
        elif product == oracle_t:
            outcome = 'SAME'
        else:
            outcome = 'DIFFERENT'
        rows[name] = {'outcome': outcome, 'refusal_code': product_refused or None, 'podman_rc': rc,
                      'product_keys': None if product is None else sorted(k.decode('ascii', 'replace') for k in product),
                      'podman_keys': None if oracle_t is None else sorted(k.decode('utf-8', 'replace').encode(
                          'unicode_escape').decode() for k in oracle_t),
                      'values_equal_for_common_keys': None if product is None or oracle_t is None else
                      all(product[k] == oracle_t[k] for k in set(product) & set(oracle_t))}
        os.unlink(path)
    summary = {}
    for row in rows.values():
        summary[row['outcome']] = summary.get(row['outcome'], 0) + 1
    record = {'test': 'T10 EnvironmentFile parsing: product vs podman --env-file (SR-9)', 'codebase': CODEBASE,
              'podman': L.lab('version', '--format', '{{.Client.Version}}').stdout.decode().strip(),
              'summary': summary, 'cases': rows}
    L.evidence(OUT, record)
    print(json.dumps(summary))
    for name, row in rows.items():
        if row['outcome'] == 'DIFFERENT':
            print(name, row['product_keys'], row['podman_keys'], row['values_equal_for_common_keys'])


if __name__ == '__main__':
    main()
