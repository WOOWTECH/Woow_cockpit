import json, os
def secret_scan_needles(values):
    """Cover raw bytes and JSON string escaping used by evidence and journals.

    This covers one JSON encoding layer, in both Unicode modes. It does not
    claim coverage for arbitrary encodings, encryption, or nested serialization.
    """
    needles = set()
    for value in values:
        raw = value if isinstance(value, bytes) else value.encode('utf-8')
        if not raw:
            continue
        needles.add(raw)
        try:
            decoded = raw.decode('utf-8')
        except UnicodeDecodeError:
            continue
        for ascii_only in (False, True):
            needles.add(json.dumps(decoded, ensure_ascii=ascii_only)[1:-1].encode('utf-8'))
    return needles

def scan_paths(root):
    """A required JSON file is read directly; only directories are walked."""
    if not os.path.exists(root) or os.path.islink(root):
        raise RuntimeError('scan root unsafe')
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        raise RuntimeError('scan root nonregular')
    def walk_error(error):
        raise RuntimeError('scan enumeration failed') from None
    paths=[]
    for directory, dirs, files in os.walk(root,onerror=walk_error,followlinks=False):
        if any(os.path.islink(os.path.join(directory,name)) for name in dirs):
            raise RuntimeError('scan path unsafe')
        paths.extend(os.path.join(directory,name) for name in files)
    return paths


import hashlib, subprocess, sys
from pathlib import Path
req=json.load(sys.stdin)
values=req['values']; registered=req['registered']
assert 0<len(values)<=64 and all(isinstance(v,str) and v and len(v)<=16384 for v in values)
assert isinstance(req['since'],int)
groups={hashlib.sha256(v.encode()).hexdigest():secret_scan_needles([v]) for v in values}
assert len(groups)==len(set(values))
counts={key:{'hits':0,'categories':{}} for key in groups}
all_needles=secret_scan_needles(values);reg_needles=secret_scan_needles(registered)
total=reg_hits=scanned=sidecars=json_roots=0
base='/var/lib/woowtech-backup/'
roots=[('jobs',base+'jobs'),('ha_metadata',base+'ha-backups'),('ha_registry',base+'ha-imports.json'),
 ('requests',base+'requests.json'),('archives',base+'archives'),('run','/run/woowtech-backup'),
 ('uploads',base+'uploads'),('staging',base+'staging'),('pending',base+'pending'),('exports',base+'exports')]
def count(data,category):
 global total,reg_hits
 total+=sum(data.count(n) for n in all_needles)
 reg_hits+=sum(data.count(n) for n in reg_needles)
 for key,needles in groups.items():
  hits=sum(data.count(n) for n in needles)
  if hits:
   row=counts[key]; row['hits']+=hits
   part=row['categories'].setdefault(category,{'hits':0,'matched_files':0})
   part['hits']+=hits; part['matched_files']+=1
for category,root in roots:
 for p in scan_paths(root):
  if os.path.islink(p):raise RuntimeError('unsafe scan path')
  if p.endswith('.tar') and category in ('archives','ha_metadata'):continue
  data=open(p,'rb').read();scanned+=1
  actual_category=category
  if category=='archives' and p.endswith('.json'):
   sidecars+=1;actual_category='archive_index_sidecars'
  if p in (base+'ha-imports.json',base+'requests.json'):json_roots+=1
  count(data,actual_category)
journal=subprocess.run(['journalctl','--no-pager','-o','cat','--since','@%d'%req['since']],
 capture_output=True,check=True,timeout=60).stdout
count(journal,'journal')
expected=len(list(Path(base+'archives').rglob('*.json')))
assert json_roots==2 and sidecars==expected and sidecars>0 and scanned>0
print(json.dumps({'scanned':scanned,'archive_index_sidecars_scanned':sidecars,
 'actual_archive_index_sidecars_expected':expected,'regular_json_roots_scanned':json_roots,
 'journal_bytes':len(journal),'all_values_hits':total,'registered_values_hits':reg_hits,'values':counts}))
