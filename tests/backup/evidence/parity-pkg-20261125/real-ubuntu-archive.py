"""manage.HostTools.ensure() of the final code with the REAL apt-get 2.8.4 and the REAL Ubuntu archive, in a private unprivileged
apt root (dpkg is a stub that only unpacks; the probes look at the packages below the private root). Nothing outside the
private root is touched."""
import importlib.util, json, os, sys
R = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('manage', sys.argv[1] + '/scripts/manage.py')
m = importlib.util.module_from_spec(spec); sys.dont_write_bytecode = True; spec.loader.exec_module(m)
calls = []
real = m.run_fixed
PROBE_ENV = {**m.SAFE_ENV, 'PATH': f'{R}/root/usr/bin', 'LD_LIBRARY_PATH': f'{R}/root/usr/lib/x86_64-linux-gnu'}


def run(argv, env=None, timeout=120):
    argv = list(argv)
    if argv[0] == m.APT_GET:
        out = real(argv, {**env, 'APT_CONFIG': f'{R}/apt.conf'}, timeout)
        calls.append({'argv': argv, 'rc': out[0], 'stderr_lines': len(out[2].splitlines()), 'stdout_tail': out[1].splitlines()[-4:]})
        return out
    if argv[0] == m.PROBE[0]:  # the packages below the private root only (-S: not this host's dist-packages)
        code = f"import sys; sys.path[:0] = ['{R}/root/usr/lib/python3/dist-packages']; " + argv[-1]
        argv = [argv[0], '-I', '-B', '-S', '-c', code]
    return real(argv, PROBE_ENV, timeout)


m.run_fixed = run
host = m.HostTools()
print('before', json.dumps(host.working()))
calls.clear()
print('first ensure ->', json.dumps(host.ensure(), ensure_ascii=False))
for call in calls:
    print('  apt-get', ' '.join(call['argv'][1:]), '| rc', call['rc'], '| stderr lines', call['stderr_lines'], '|', ' / '.join(call['stdout_tail'])[:200])
print('after', json.dumps(host.working()))
calls.clear()
print('second ensure ->', json.dumps(host.ensure()), '| apt-get runs:', len(calls))
