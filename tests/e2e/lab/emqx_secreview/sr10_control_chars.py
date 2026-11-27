"""SR-10 proof (iteration 4): a control/bidi/line-separator character in an HA EMQX plugin name, a /share path or a
skipped-symlink name must not (a) reach a check warning raw or (b) forge a second job-log line. In-process only
(no container, no network): drives ha_emqx._source_analysis / hocon_notes (the real check warning builders) and
jobs.LOG_CONTROL_RE (the real job-log sink). Benign: this is log-injection / name-spoofing, not a network attack.
Run: SECREV_ENGINE=<tree>/backup-engine python3 -I sr10.py <label>"""
import importlib, json, os, re, sys, time

ENGINE = os.environ['SECREV_ENGINE']
sys.path.insert(0, ENGINE)
sys.dont_write_bytecode = True
ha_emqx = importlib.import_module('woowbackup.ha_emqx')
hacommon = importlib.import_module('woowbackup.hacommon')
jobs = importlib.import_module('woowbackup.jobs')

# A sample of the twelve characters the fix must neutralise, plus a bare line feed.
BIDI = '‮⁦⁩‎؜'          # bidirectional controls
SEP = '  '                              # Unicode line/paragraph separators
C1 = '\x85\x9b'                                   # C1 controls
C0 = '\n\r\x00\x1b'                               # C0 incl. LF/CR and ESC
EVIL = 'plug' + BIDI + SEP + C1 + C0 + 'in'
CONTROLS = BIDI + SEP + C1 + C0


def has_control(text):
    return [hex(ord(c)) for c in text if c in CONTROLS]


label = sys.argv[1] if len(sys.argv) > 1 else os.path.basename(os.path.dirname(ENGINE))
out = {'test': 'SR-10 control/bidi/line-separator in plugin name, /share path and skipped-symlink name',
       'engine_dir': ENGINE, 'label': label, 'controls_tested': [hex(ord(c)) for c in CONTROLS]}

# (a) plugin names reach the check warnings through hacommon.names (ha_emqx._source_analysis)
src = type('S', (), {'hocon': '', 'plugins': {EVIL}, 'addon': type('A', (), {'state': 'stopped', 'version': '5.9.1'})(),
                     'files': 1, 'bytes': 0})()
blockers, warnings = ha_emqx._source_analysis(src, None, addon_version='5.9.1', version='5.8.9')
plugin_warn = next((w for w in warnings if '外掛' in w), '')
out['plugin_warning_present'] = bool(plugin_warn)
out['plugin_warning_leaks_control'] = has_control(plugin_warn)

# /share, /ssl, /config file references reach the warnings through hocon_notes -> hacommon.names
hocon = 'actions { a { parameters { body = "/share/' + BIDI + '/x.pem" } } }'
notes = ha_emqx.hocon_notes(hocon)
share_note = next((n for n in notes if '資料夾以外' in n), '')
out['share_note_present'] = bool(share_note)
out['share_note_leaks_control'] = has_control(share_note)

# (b) a skipped-symlink sample name reaches the job log; the sink (jobs.LOG_CONTROL_RE) must keep it one line
report = jobs_report = None
hb = importlib.import_module('woowbackup.habackup')
report = hb.Report()
report.skipped_symlinks = 1
report.skipped_symlink_samples = ['certs/' + SEP + C1 + BIDI + 'evil = forged job line']
note = report.warnings()[0]
out['symlink_note_raw_has_separator'] = bool(re.search(r'[  \n\r]', note))   # raw note still has it
# Mirror the real job-log sink of whichever tree: the hardened sink (LOG_CONTROL_RE) or the old CR/LF-only one.
if hasattr(jobs, 'LOG_CONTROL_RE'):
    sunk = jobs.LOG_CONTROL_RE.sub(' ', note)
else:
    sunk = note.replace('\r', ' ').replace('\n', ' ')
out['symlink_logline_leaks_control'] = has_control(sunk)
out['symlink_logline_is_single_line'] = ('\n' not in sunk and '\r' not in sunk
                                          and ' ' not in sunk and ' ' not in sunk)

# What the OLD tree lacked: show the fix is load-bearing. A naive join (no hacommon.names, no LOG_CONTROL_RE)
# would leak every control character -- that is the 865c930f behaviour the verifier saw (forged=True).
naive_plugin = 'HA 的 EMQX 外掛（' + '、'.join(sorted({EVIL})) + '）'
naive_log = '、'.join(report.skipped_symlink_samples)
out['naive_plugin_would_leak'] = bool(has_control(naive_plugin))
out['naive_logline_would_forge'] = bool(re.search(r'[  \n\r]', naive_log))

out['forged'] = bool(out['plugin_warning_leaks_control'] or out['share_note_leaks_control']
                     or out['symlink_logline_leaks_control'] or not out['symlink_logline_is_single_line'])
out['ok'] = (out['plugin_warning_present'] and out['share_note_present']
             and not out['forged'] and out['naive_plugin_would_leak'] and out['naive_logline_would_forge'])
print(json.dumps(out, ensure_ascii=False, indent=1))
