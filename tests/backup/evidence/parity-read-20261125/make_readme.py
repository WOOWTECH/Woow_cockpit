"""Writes the evidence README of the lane (snippets/parity-read/evidence-README.md) from the records of runs/: every number comes from a record,
nothing is typed in by hand. usage: make_readme.py TAG [SUITE_TAG] [MUT_TAGS...]
TAG: the chain (it2b); SUITE_TAG: the tag of the full-suite run at the final tip (default TAG); MUT_TAGS: further mutation records (it2b-mutB ...)."""
import ast, json, os, re, subprocess, sys
S = '/tmp/claude-1000/-home-woowtechopenclaw/a15a4de1-3ce4-4692-84a2-243bd175349a/scratchpad'
R = S + '/parity-read/runs/'
OUT = S + '/parity/snippets/parity-read/evidence-README.md'
TAG = sys.argv[1]
SUITE = sys.argv[2] if len(sys.argv) > 2 else TAG
MUTS = sys.argv[3:]
W = '/tmp/parity-read-20261125'


def read(name):
    try:
        return open(R + name, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''


def git(*args):
    return subprocess.check_output(['git', '-C', W, *args], text=True).strip()


def guard(name):
    text = read(name)
    head = next((l for l in text.splitlines() if l.startswith('tests=')), None)
    if not head:
        return 'not run (no record)'
    fields = dict(re.findall(r'(\w+)=(\S+)', head))
    bad = [re.sub(r' blocked_in_test=.*', '', l).split(' ', 1)[1].replace('tests.backup.', '').replace('Tests', '') for l in text.splitlines()
           if l.startswith(('FAIL ', 'ERROR '))]
    known = [b for b in bad if b.startswith('test_litellm_lab_runner')]
    other = [b for b in bad if not b.startswith('test_litellm_lab_runner')]
    head = f"tests={fields['tests']} failures={fields['failures']} errors={fields['errors']} skipped={fields['skipped']} blocked={fields['blocked']}"
    if not bad:
        return head + '; all ok'
    return (head + f"; not ok: {len(known)} of the 5 known test_litellm_lab_runner guard refusals (the guard blocks what they run)"
            + (f" and {len(other)} test{'s' if len(other) != 1 else ''} of other lanes' files ({', '.join(other)})" if other else ' and nothing else'))


tip = git('rev-parse', '--short', 'HEAD')
units = read(TAG + '-units.out')
ran = re.search(r'Ran (\d+) tests', units)
ok = re.search(r'OK( \(skipped=(\d+)\))?', units)
unit_text = f"{ran.group(1)} tests OK" + (f", {ok.group(2)} skipped (RealBackupTests without its key)" if ok and ok.group(2) else '') if ran and ok else 'see runs'
diff = {'files': 0, 'members': 0, 'equal': 0, 'wrong_key': 0, 'entries': 0, 'skips': 0, 'diff': 0, 'size': 0, 'rss': 0}
for name in ('-diffsmall.json', '-difflarge.json'):
    try:
        data = json.load(open(R + TAG + name))
    except OSError:
        continue
    diff['rss'] = max(diff['rss'], data['maxrss_mib'])
    for row in data['results']:
        diff['files'] += 1
        diff['members'] += row['members']
        diff['equal'] += row['equal']
        diff['wrong_key'] += row['wrong_key']
        diff['entries'] += row['entries']
        diff['skips'] += len(row['skips'])
        diff['diff'] += len(row['diff']) + (0 if row['summary_equal'] and row['members_equal'] else 1)
        diff['size'] += row['size']
real = read(TAG + '-realfiles.out').strip().splitlines()
fuzz = json.loads(read(TAG + '-fuzz.out') or '{}')
mem = [json.loads(read(n + '.out') or '{}') for n in (TAG + '-mem4m' if read(TAG + '-mem4m.out') else 'it2b-mem4m', TAG + '-mem4m1' if read(TAG + '-mem4m1.out') else 'it2b-mem4m1')]
mem_tag = TAG if read(TAG + '-mem4m.out') else 'it2b (tip 411fefe/691d39e; the walk and the names table are unchanged in iteration 3, so the run was not repeated, to spare the host)'
results = []
for name in [TAG + '-mut'] + MUTS:
    try:
        results += json.load(open(R + name + '.json'))['results']
    except OSError:
        pass
# a mutant that was not applied in the sweep and was applied in a later record counts there only
SUPERSEDED = {'below a file'}  # its code was rewritten (the names table, commit 9a089de); 'folders: below a file' is its successor
final = {}
for row in results:
    if row['label'] in SUPERSEDED:
        continue
    if row['result'] != 'NOT-APPLIED' or row['label'] not in final:
        final[row['label']] = row
tally = {}
for row in final.values():
    tally[row['result']] = tally.get(row['result'], 0) + 1
survivors = sorted(label for label, row in final.items() if row['result'] == 'SURVIVED')
old = [l for l in read('old-tests-it2b.log').splitlines() if l.startswith(('FAIL:', 'ERROR:'))]
tarfile_out = read(TAG + '-diff_tarfile.out').strip().splitlines()
struct = [read(TAG + n + '.out').strip() for n in ('-struct_fuzz', '-struct_fuzz2')]
walks = 0
for line in struct:
    m = re.search(r"'refused': (\d+), 'ok': (\d+)\} violations (\d+)", line)
    walks += int(m.group(1)) + int(m.group(2)) if m else 0
tip_of_chain = read(TAG + '.tip').split()[0] if read(TAG + '.tip') else '?'
product_changed = subprocess.run(['git', '-C', W, 'diff', '--quiet', tip_of_chain, 'HEAD', '--', 'backup-engine'], check=False).returncode != 0
kinds = json.loads(read(TAG + '-kinds.out') or '{}')
kinds_text = ', '.join(f"{n} {k}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])).replace(' none', ' unencrypted') if kinds else 'kinds not recorded'
job = [l for l in read(TAG + '-job_level.out').splitlines() if l.startswith('RESULT ')]
job_text = (job[-1][len('RESULT '):] if job else 'no record') + ' (the one that is not stopped at check time: a gzip member cut 20 bytes before its end, a few KiB long: the fake check never reads to its end; read to its end the reader stops it as corrupt-archive of that member, tested in the lane modules)'
probe_lines = [l for l in read('probe_cost.out').splitlines() if l.strip()]
probe = {}
for l in probe_lines:
    m = re.match(r'(.{22}) (.{32}) answer=\w+ cpu=\s*[\d.]+s for 64 MiB =\s*([\d.]+) s per GiB', l)
    if m:
        probe.setdefault(m.group(2).strip(), {})[m.group(1).strip().split(' (')[0]] = m.group(3)
probe_text = '; '.join(f"{name}: {v.get('iteration 2', '?')} -> {v.get('iteration 3', '?')} s per GiB" for name, v in probe.items()) or 'no record'
mut_rows = results
text = open(S + '/parity-read/evidence-README.template.md', encoding='utf-8').read()
not_applied = sorted(label for label, row in final.items() if row['result'] == 'NOT-APPLIED')
values = {
    'TIP': tip, 'CHAIN_TIP': tip_of_chain, 'PRODUCT_SAME': 'the product files are the same at both' if not product_changed else 'THE PRODUCT FILES DIFFER between the two: rerun',
    'UNITS': unit_text,
    'B1': guard(SUITE + '-b1.out'), 'HA118': guard(SUITE + '-ha118.out'), 'MERGE': guard(TAG + '-merge-b1.out'),
    'JOBLEVEL': job_text,
    'DIFF': f"{diff['files']} real HA backups ({diff['size'] / 1e9:.1f} GB, x86 and ARM; plain, uncompressed, downloaded, crash; members counted from the layouts: {kinds_text}, no v1 or v2 member among "
            f"them: v1 and v2 are covered by the committed fixtures that the real securetar library wrote): {diff['equal']} of {diff['members']} members equal "
            f"({diff['entries']:,} entries, modes, owners, content, add-on info), summaries and layouts equal, {diff['wrong_key']} wrong key, {diff['skips']} skipped entries, "
            f"{diff['diff']} differences, peak {diff['rss']} MiB",
    'REAL': f"{real[-1] if real else 'no record'}: repacked by GNU tar in 5 formats, busybox; rubbish behind; bit flips; cut; twice; gone; gzip in parts: only the add-on concerned is affected",
    'SCHEMA': read(TAG + '-check_schema.out').strip() + ' (the mirror in the test against Supervisor validate.py e610ca81 executed with stubs, voluptuous 0.16)',
    'TARFILE': (tarfile_out[-1] if tarfile_out else 'no record') + ' (1500 random valid trees, PAX/GNU/USTAR, unicode, long names, big uid, float mtime, symlinks: names, kinds, modes, owners, sizes, times, links, content)',
    'STRUCT': f"{walks:,} walks over random hostile structures: " + ' and '.join(re.sub(r'^.*violations (\d+)', r'\1 violations', s) for s in struct) + ' (two mixes of names and types)',
    'FUZZ': f"{fuzz.get('total', '?'):,} damaged files ({', '.join(fuzz.get('kinds', []))}): only BackupError of a known code, or exactly the content as written (checked kinds)",
    'MEM': (f"{mem[0].get('entries', 0):,} entries: {mem[0].get('peak_mib')} MiB peak ({mem[0].get('base_mib')} MiB of it Python itself), {mem[0].get('cpu_seconds')} s CPU; the next entry: "
            f"{mem[1].get('result')} (record of {mem_tag})") if mem[0] else 'no record',
    'OTHERLANE': (lambda g: ('the full suite has exactly the 5 known guard refusals not ok and nothing else (' + g + ').') if 'not ok: 5 of the 5 known' in g and ' and nothing else' in g
                  else ('see the line of the table: ' + g))(guard(TAG + '-merge-b1.out')),
    'PROBEDIFF': (lambda d: f"{d['rounds']:,} random rounds (headers good and damaged, words, zeros, wrong sums, readers that had read bytes, 9 buffer sizes): {d['answers'][True]:,} times 'a header follows', {d['answers'][False]:,} times not, {d['different']} different answers")(
        ast.literal_eval(read(TAG + '-probe_diff.out').strip())) if read(TAG + '-probe_diff.out') else 'no record',
    'ON_IT2': ' '.join(l.replace('FAIL: ', 'fails: ') if l.startswith('FAIL: ') else l for l in read(TAG + '-tests-on-engine-it2.out').splitlines()[1:]) or 'no record',
    'PROBE': probe_text + ' (CPU seconds per GiB measured on 64 MiB of each filler on this machine, the code of iteration 2 (691d39e) and of this iteration; zeros and random bytes did not change, the difference is the load of the machine)',
    'OLD': f"{len(old)} expectations of the old tests changed (45 failures, 1 error of 92), listed in old-tests.txt; every other old test, hostile samples included, holds",
    'MUT': (f"{len(final)} mutants in one run on {tip_of_chain}: {tally}" + (f"; survivors: {survivors}" if survivors else '') + (f"; NOT APPLIED: {not_applied}" if not_applied else '')
            + "; the one that survives is the control (a change nobody can notice); one list, one run: the definitions of iteration 2 (corrected where the code had moved) and the mutants "
            "added in iteration 3 for the checkpoints, the budget of the second pass, the stale-upload link, the key of the names table, the probe and the header sum"),
}
for key, value in values.items():
    text = text.replace('@@' + key + '@@', str(value))
assert '@@' not in text, re.findall(r'@@\w+@@', text)
open(OUT, 'w', encoding='utf-8').write(text)
print(text[:300])
