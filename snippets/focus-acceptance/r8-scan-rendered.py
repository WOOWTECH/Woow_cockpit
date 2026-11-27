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

import json, os, subprocess, sys
req=json.load(sys.stdin)
values=list(req["values"])
for name in req.get("podman_secrets",[]):
    p=subprocess.run(["/usr/local/bin/woowbk-owner","podman","secret","inspect","--showsecret","--format","{{.SecretData}}",name],capture_output=True,check=True)
    values.append(p.stdout.rstrip(b"\n"))
needles=secret_scan_needles(values)
hits=scanned=index_sidecars=json_roots=0
base="/var/lib/woowtech-backup/"
for root in [base+x for x in ("jobs","ha-backups","ha-imports.json","requests.json","archives","uploads","staging","pending","exports")]+["/run/woowtech-backup"]:
    for p in scan_paths(root):
        if os.path.islink(p): raise RuntimeError("scan path unsafe")
        if p.endswith(".tar") and ("/archives/" in p or "/ha-backups/" in p): continue
        data=open(p,"rb").read(); scanned+=1
        if p in (base+"ha-imports.json",base+"requests.json"): json_roots+=1
        if "/archives/" in p and p.endswith(".json"): index_sidecars+=1
        hits+=sum(data.count(x) for x in needles)
j=subprocess.run(["journalctl","--no-pager","-o","cat","--since","@%d"%req["since"]],capture_output=True,check=True).stdout
hits+=sum(j.count(x) for x in needles)
print(json.dumps({"scanned":scanned,"hits":hits,"journal_bytes":len(j),"archive_index_sidecars_scanned":index_sidecars,"regular_json_roots_scanned":json_roots}))
