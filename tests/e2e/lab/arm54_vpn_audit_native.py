"""Post-restore fixed predicates; no raw state, keys or log text leave ARM."""
import sys,json
from pathlib import Path
root=Path(sys.argv[1]);trial=Path(json.loads((root/'probe-result.json').read_text())['fixture']); state=trial/'client-state'
assert trial.parent==root
with (state/'daemon.log').open('rb') as f: log=f.read(1024*1024).lower()
predicates={s:s.encode() in log for s in ['registerreq','machineauthorized=true','mapresponse','netmap','running','100.64.0.1','fd7a:115c:a1e0::1','logininteractive','authurl is','needslogin','control server key from https://127.0.0.1:8080']}
print(json.dumps({'restored_log_predicates':predicates,'authkey_file_absent':not (state/'authkey').exists(),'bounded_log_bytes':len(log),'raw_logs_exported':False},sort_keys=True))
