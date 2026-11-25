"""haos_doc (the mirror in test_ha_backup.py) against the real Supervisor schema: validate.py executed with stubs."""
import sys, types, json, importlib.util, enum
sys.path.insert(0, '/tmp/parity-read-20261125'); sys.path.insert(0, '/tmp/parity-read-20261125/backup-engine')
H = '/tmp/claude-1000/-home-woowtechopenclaw/fbefdf50-77b9-4f2f-a609-4d7d82a72cee/scratchpad/hasrc/supervisor/supervisor/'
import voluptuous as vol
from awesomeversion import AwesomeVersion
import re
def mod(name, **kw):
    m = types.ModuleType(name); m.__dict__.update(kw); sys.modules[name] = m; return m
pkg = mod('supervisor'); pkg.__path__ = []
b = mod('supervisor.backups'); b.__path__ = []
class BackupType(enum.StrEnum):
    FULL = 'full'; PARTIAL = 'partial'
mod('supervisor.backups.const', BackupType=BackupType)
class Folder(enum.StrEnum):
    SHARE = 'share'; APPS = 'apps/local'; SSL = 'ssl'; MEDIA = 'media'
names = 'ATTR_ADDONS ATTR_COMPRESSED ATTR_DATE ATTR_DAYS_UNTIL_STALE ATTR_EXCLUDE_DATABASE ATTR_EXTRA ATTR_FOLDERS ATTR_HOMEASSISTANT ATTR_NAME ATTR_PROTECTED ATTR_REPOSITORIES ATTR_SIZE ATTR_SLUG ATTR_SUPERVISOR_VERSION ATTR_TYPE ATTR_VERSION'.split()
c = {n: n[5:].lower() for n in names}
src = open(H + 'const.py').read()
for n in names:  # the real values
    c[n] = re.search(r'^%s = "([^"]+)"' % n, src, re.M).group(1)
mod('supervisor.const', FOLDER_ADDONS='addons/local', FOLDER_HOMEASSISTANT='homeassistant', Folder=Folder, **c)
vsrc = open(H + 'validate.py').read()
ns = {}
RE_REPOSITORY = re.compile(re.search(r'RE_REPOSITORY = re.compile\(\s*r"([^"]+)"', vsrc, re.S).group(1)) if 'RE_REPOSITORY = re.compile(' in vsrc else re.compile(r'^(?P<url>[^#]+)(?:#(?P<branch>[\w\-/.]+))?$')
class Builtin(enum.StrEnum):
    CORE = 'core'; LOCAL = 'local'
def version_tag(value):
    if value is None: return None
    if isinstance(value, AwesomeVersion): return value
    return AwesomeVersion(value)
mod('supervisor.validate', version_tag=version_tag, RE_REPOSITORY=RE_REPOSITORY)
s = mod('supervisor.store'); s.__path__ = []
mod('supervisor.store.const', BuiltinRepository=Builtin)
def load(name, path, package):
    spec = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(spec); m.__package__ = package
    sys.modules[name] = m; spec.loader.exec_module(m); return m
sys.modules['supervisor.const'].ATTR_MAINTAINER = 'maintainer'; sys.modules['supervisor.const'].ATTR_URL = 'url'
load('supervisor.store.validate', H + 'store/validate.py', 'supervisor.store')
v = load('supervisor.backups.validate', H + 'backups/validate.py', 'supervisor.backups')
from tests.backup import test_ha_backup as t
case = t.HaosParityTests('test_documents')
agree = total = 0; bad = []
for label, doc in case.documents():
    raw = json.loads(json.dumps(doc))
    try:
        v.SCHEMA_BACKUP(json.loads(json.dumps(doc))); real = True
    except vol.Invalid: real = False
    except Exception as e: real = False
    mine = t.haos_doc(raw); total += 1
    if real == mine: agree += 1
    else: bad.append((label, real, mine))
print('documents', total, 'agree', agree, bad[:20])
