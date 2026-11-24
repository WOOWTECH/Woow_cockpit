"""Pure helpers of arm54_final_emqx.py (lane arm54-2 item D, EMQX on .54), importable on the host for unit tests
(arm54_final_emqx.py itself needs a .54 workspace). No Podman, no network, no secret."""
import ast

from woowbackup import tempctr

IMAGE = 'docker.io/emqx/emqx:5.8.9@sha256:35b46f7aa7a0d51f3959e4344221ac5ec7f948b03e43099286b6c40a07bb393b'
CONTAINER = 'woow-emqx'
QUADLET_FILES = ('emqx.container', 'emqx-data.volume', 'emqx-log.volume', 'emqx.network')
DATA, LOG = 'woow_emqx_data', 'woow_emqx_log'
VOLUMES = (DATA, LOG)
SECRET_NAMES = ('woow-emqx-dashboard-password', 'woow-emqx-node-cookie', 'woow-emqx-mqtt-password',
                'woow-emqx-mqtt-bootstrap')
MQTT_USER = 'woow'   # config/emqx.env.example WOOW_EMQX_MQTT_USER
TARGET_MEMORY = '1g'
JOBS = {name: 'j20261123T160000Z-a54e%04x' % i for i, name in enumerate(
    ('check-file', 'convert-file', 'check-builtin', 'convert-builtin'), start=0xc001)}
READY_TIMEOUT = 300
CLONE_NEWNET = 0x40000000
# The dev-d product harness's probe (emqx_product_real_ha.py @ 92e306b): the only changes for this device.
PROBE_SUBSTITUTIONS = (
    ('E = "http://127.0.0.1:18083"', 'E = "http://127.0.0.1:18093"'),   # no entrance: the Dashboard's own listener
    ('os.path.expanduser("~/.config/emqx/acl.conf")', 'REQ["acl_path"]'),  # this run's %h
)
PROBE_OVERRIDES = r'''
# .54 (lane arm54-2): this device's generated secrets come in the request; podman is the run's private store.
def secret(name):
    return REQ["device_secrets"][name]
def pexec(*argv, input=None, timeout=300):
    feed = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    p = subprocess.run(REQ["podman"] + ["exec", "-i", *argv], capture_output=True, text=True, timeout=timeout, **feed)
    return p.returncode, p.stdout, p.stderr
'''


# ---------------------------------------------------------------- pure helpers (unit tested on the host)

def string_constant(source, name):
    """The string literal assigned to `name` at module level of `source` (read, never executed)."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and [getattr(t, 'id', None) for t in node.targets] == [name]:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise LookupError(name)


def probe_body(source):
    """The probe's own text: the last operand of `PROBE = drv.PROBE_COMMON + MQTT + r'''...'''`."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and [getattr(t, 'id', None) for t in node.targets] == ['PROBE']:
            value = node.value
            if (isinstance(value, ast.BinOp) and isinstance(value.right, ast.Constant)
                    and isinstance(value.left, ast.BinOp) and getattr(value.left.right, 'id', None) == 'MQTT'
                    and getattr(value.left.left, 'attr', None) == 'PROBE_COMMON'):
                return value.right.value
    raise LookupError('PROBE')


def probe_program(product_source, b1_source):
    """PROBE_COMMON (ha_import_b1_e2e) + this device's two overrides + MQTT + the probe body with the asserted
    substitutions (each must hit exactly once)."""
    body = probe_body(product_source)
    for old, new in PROBE_SUBSTITUTIONS:
        if body.count(old) != 1:
            raise ValueError('probe substitution does not apply exactly once: ' + old[:40])
        body = body.replace(old, new)
    program = string_constant(b1_source, 'PROBE_COMMON') + PROBE_OVERRIDES + string_constant(product_source, 'MQTT') + body
    compile(program, 'emqx-probe', 'exec')
    return program


def dev_d_probe_program(product_source, b1_source):
    """The dev-d product harness's probe program UNCHANGED (PROBE_COMMON + MQTT + body), for the production OwnerRunner
    target: run as the owner, the entrance published at 127.0.0.1:18083, podman from the owner's PATH."""
    program = string_constant(b1_source, 'PROBE_COMMON') + string_constant(product_source, 'MQTT') + probe_body(product_source)
    compile(program, 'emqx-dev-d-probe', 'exec')
    return program


def function_from(source, name, namespace=None):
    """A module-level function of `source` compiled alone (the dev-d acceptance function, unchanged)."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            space = dict(namespace or {})
            exec(compile(ast.Module(body=[node], type_ignores=[]), name, 'exec'), space)  # noqa: S102
            return space[name]
    raise LookupError(name)


def bootstrap_csv(user, password):
    """install.sh step 5: EMQX_BOOTSTRAP_CSV = "user_id,password,is_superuser\\n<user>,<password>,false"."""
    return 'user_id,password,is_superuser\n%s,%s,false' % (user, password)


def container_args(text, home, label, *, network='none', memory=TARGET_MEMORY):
    """`podman run` arguments of the package's emqx.container (rendered), and the keys deliberately not translated."""
    units = tempctr.parse_unit(text.decode() if isinstance(text, bytes) else text)
    args, skipped, name, image = [], [], None, None
    keys = set()
    for key, value in units.get('Container', []):
        if key == 'Environment':
            keys.add(value.split('=', 1)[0].strip('"'))
    env = tempctr.quadlet_environment(text, keys)
    for key, value in units.get('Container', []):
        if key == 'ContainerName':
            name = value
        elif key == 'Image':
            image = value
        elif key == 'HostName':
            args += ['--hostname', value]
        elif key == 'Label':
            args += ['--label', value]
        elif key == 'EnvironmentFile':
            args += ['--env-file', value.replace('%h', home.rstrip('/'), 1)]
        elif key == 'Secret':
            args += ['--secret', value]
        elif key == 'Volume':
            parts = value.split(':')
            source = parts[0]
            if source.endswith('.volume'):
                source = {'emqx-data.volume': DATA, 'emqx-log.volume': LOG}[source]
            elif source.startswith('%h/'):
                source = home.rstrip('/') + '/' + source[3:]
            args += ['--volume', ':'.join([source] + parts[1:])]
        elif key == 'NoNewPrivileges' and value == 'true':
            args += ['--security-opt', 'no-new-privileges']
        elif key == 'PodmanArgs' and value == '--stop-timeout=30':
            args += ['--stop-timeout', '30']
        elif key != 'Environment':
            skipped.append(key)
    for key in sorted(env):
        args += ['--env', '%s=%s' % (key, env[key])]
    args = ['--name', name, '--network', network, '--memory', memory, '--pids-limit', '2048', '--label', label] + args
    return name, image, args, sorted(set(skipped))


SAFE_LEAF = __import__('re').compile(r'[a-z0-9_.:/-]{1,40}\Z')
SECRET_PATH = __import__('re').compile(r'(password|passwd|secret|cookie|token|key|cert|private)', __import__('re').I)


def config_diff(target, candidate, limit=60):
    """Paths where two configuration documents differ: [path, what, target side, candidate side]. Sides are value
    types, or the value itself only for booleans/numbers/None and enum-like short strings on paths whose name is not
    secret-like (the run's secret scan still suppresses the whole output if a known value appears)."""
    out = []

    def side(path, value):
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str) and not SECRET_PATH.search(path) and SAFE_LEAF.match(value):
            return 'str:' + value
        if isinstance(value, (list, dict, str)):
            return '%s(len %d)' % (type(value).__name__, len(value))
        return type(value).__name__

    def walk(x, y, path):
        if len(out) >= limit:
            return
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y), key=str):
                p = '%s.%s' % (path, k) if path else str(k)
                if k not in y:
                    out.append([p, 'only-target', side(p, x[k]), None])
                elif k not in x:
                    out.append([p, 'only-candidate', None, side(p, y[k])])
                else:
                    walk(x[k], y[k], p)
        elif isinstance(x, list) and isinstance(y, list) and len(x) == len(y):
            for i, (p_, q_) in enumerate(zip(x, y)):
                walk(p_, q_, '%s[%d]' % (path, i))
        elif x != y:
            out.append([path, 'differs', side(path, x), side(path, y)])

    walk(target, candidate, '')
    return out

