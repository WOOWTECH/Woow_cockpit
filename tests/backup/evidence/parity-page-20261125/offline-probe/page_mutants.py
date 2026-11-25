#!/usr/bin/env python3
"""Mutation sweep of lane PAGE: every mutant is a copy of backup/ with ONE change, served to tests/backup-ui.mjs through BRAND_UI_ROOT,
run with the tests named in `pattern` only. A mutant is CAUGHT when the node run exits non-zero. One heavy step (run it through heavy.sh).
usage: page_mutants.py OUTDIR [id ...]   (no ids: all). Writes OUTDIR/summary.txt (one line per mutant) and OUTDIR/<id>.log."""
import os, shutil, subprocess, sys, time
REPO = '/tmp/parity-page-20261125'
OUT = sys.argv[1]
ONLY = sys.argv[2:]
MAIN = 'HAOS 一次確認: the check says'
DB = 'HAOS 一次確認: the only database that can move'
RETRY = 'HAOS 一次確認: an import whose start'
NOANS = 'HAOS 一次確認: a start that never answers'
ADOPT = 'HAOS 一次確認: when every try ran out of time'
KEY = 'HAOS 一次確認: a key with a Tab'
NOKEY = 'HAOS 一次確認: no device key yet'
NOKEY2 = 'HAOS 一次確認: the engine could not make'
STOPAFTER = 'HAOS 一次確認: 做完這個應用就停止'
CANCEL = 'HAOS 一次確認: cancelling the import'
RECONF = 'HAOS 一次確認: a line whose names changed'
JOB = 'HAOS 一次確認: a job that is not found'
RELOAD = 'HAOS 一次確認: a job of an import found again'
LEGACY = 'HAOS 一次確認: a conversion that reports no new backup'
RESTORE = 'HAOS 一次確認: the restore check of a converted backup'
CHOICE = 'HAOS 一次確認: a choice the check asks for'
# (id, what is taken away, old text, new text, tests that must notice)
MUTANTS = [
 ('m01', 'no tick needed to start', 'const ready = can.length > 0 && !pending && ticked && !wizard.busy && !active;', 'const ready = can.length > 0 && !pending && !wizard.busy && !active;', [MAIN]),
 ('m02', 'a tick survives another database', "const haConfirmSignature = lines => JSON.stringify(lines.map(({ app, issue }) => [app, issue.id, issue.database, issue.key || issue.message]).sort());", "const haConfirmSignature = lines => 'always';", [MAIN]),
 ('m03', 'the confirmation keys are not sent', 'if (Object.keys(acknowledged).length) request.acknowledged = acknowledged;\n    if (Object.keys(choices).length) request.choices = choices;', 'if (Object.keys(choices).length) request.choices = choices;', [MAIN, DB]),
 ('m04', 'the shared lines are not acknowledged', 'const keys = (result[app || HA_SHARED] ||= []);', 'const keys = (result[app || "odoo"] ||= []);', [MAIN]),
 ('m05', 'overwrite is not sent', 'if (thenRestore) request.overwrite = true;', '', [MAIN]),
 ('m06', 'apps that cannot go are sent too', 'const apps = can.map(app => app.app_id);\n    const key = haKey(wizard);\n    const acknowledged', 'const apps = [...wizard.selected];\n    const key = haKey(wizard);\n    const acknowledged', [MAIN]),
 ('m07', 'the choices are not sent', 'if (Object.keys(choices).length) request.choices = choices;\n    if (wizard.checkJobId)', 'if (wizard.checkJobId)', [MAIN, DB]),
 ('m08', 'the only database is not chosen for the customer (UI-16)', 'usable.length === 1 ? usable[0] : usable.includes(preferred) ? preferred : null });', 'null });', [DB]),
 ('m09', 'every database can be chosen (UI-19)', 'return row ? row.ok : db.ok === true;\n  }', 'return true;\n  }', [MAIN, DB]),
 ('m10', 'one app that cannot go holds back the rest (UI-14)', 'const ready = can.length > 0 && !pending && ticked && !wizard.busy && !active;', 'const ready = can.length > 0 && cannot.length === 0 && !pending && ticked && !wizard.busy && !active;', [MAIN]),
 ('m11', 'an app without a result holds back the rest (UI-15)', 'const ready = can.length > 0 && !pending && ticked && !wizard.busy && !active;', 'const ready = can.length > 0 && missing.length === 0 && !pending && ticked && !wizard.busy && !active;', [DB]),
 ('m12', 'a start that does not answer is not asked again (UI-22)', 'const HA_START_TRIES = 3;', 'const HA_START_TRIES = 1;', [RETRY]),
 ('m13', 'the status never decides (UI-22)', 'if (job && adopt && ACTIVE.has(job.state) && adopt(job)) {', 'if (false) {', [ADOPT]),
 ('m14', 'a key with a control character is stopped again (UI-12)', 'if (value.includes("\\u0000")) return "金鑰不能包含空字元（NUL）。";', 'if (CONTROL_RE.test(value)) return "金鑰不能包含換行或其他控制字元。";', [KEY]),
 ('m15', 'no hint when the job is not found (X-JOB-03)', 'const error = cause.code === "not-found" ? new HelperError(', 'const error = false ? new HelperError(', [JOB]),
 ('m16', 'the created key is not announced (D11)', 'keyCreated: data.key_created === true,', 'keyCreated: false,', [NOKEY]),
 ('m17', 'the chain is not followed', 'if (info.next) {\n      Object.assign(wizard, { jobId: info.next,', 'if (false) {\n      Object.assign(wizard, { jobId: info.next,', [MAIN, STOPAFTER, RECONF]),
 ('m18', 'the apps left out are not rows of the result', 'excluded: haExcludedRows(wizard) }),\n      wizard.jobId', 'excluded: [] }),\n      wizard.jobId', [MAIN]),
 ('m19', 'after-this is a plain cancel', 'await call("job-cancel", { job_id: wizard.jobId, after_this: true });', 'await call("job-cancel", { job_id: wizard.jobId });', [STOPAFTER]),
 ('m20', 'the restore confirmation is not sent', 'confirm: true };\n    if (Object.keys(acknowledged).length) request.acknowledged = acknowledged;\n    if (wizard.key)', 'confirm: true };\n    if (wizard.key)', [RESTORE]),
 ('m21', 'no device key stops the new flow again (UI-17)', "const ready = can.length > 0 && !pending && ticked && !wizard.busy && !active;", "const ready = can.length > 0 && !haNoDeviceKey() && !pending && ticked && !wizard.busy && !active;", [NOKEY]),
 ('m22', 'a conversion without a backup id is an error again (UI-21)', 'Object.assign(wizard, { step: "options", jobId: null, error: null,', 'Object.assign(wizard, { step: "options", jobId: null, error: new HelperError("轉換已完成，但作業沒有回報新的備份。", { code: "bad-output" }),', [LEGACY]),
 ('m23', 'a stop line of an app is not shown (reason of the app that cannot go)', 'stops.length ? h("ul", { class: "ha-issues ha-issues-stop", "aria-label": `${name} 不能匯入的原因` }, stops.map(issue => haIssueItem(issue))) : null,', 'null,', [MAIN]),
 ('m24', 'the add-on choice is not sent with the check', 'if (Object.keys(choices).length) request.choices = choices;\n    if (key) request.key = key;\n    Object.assign(wizard, { busy: true, error: null, notice: null, keyError: null });\n    render();\n    try {\n      const data = await haStartCall(wizard, "ha-check-start"', 'if (key) request.key = key;\n    Object.assign(wizard, { busy: true, error: null, notice: null, keyError: null });\n    render();\n    try {\n      const data = await haStartCall(wizard, "ha-check-start"', [CHOICE]),
 ('m25', 'the confirmation-required result has no way on', "if (reconfirm && info.haId && !result.backup_id) {", "if (false) {", [RECONF]),
 ('m26', 'cancel of the import is not asked', 'button("取消匯入", () => cancelHaJob(wizard), { focus: "ha-cancel-import", icon: "stop-circle-outline", danger: true })', 'button("取消匯入", () => call("job-cancel", { job_id: wizard.jobId }), { focus: "ha-cancel-import", icon: "stop-circle-outline", danger: true })', [CANCEL]),
 ('m27', 'the reload view does not list the apps of the import', 'fill(nodes.group, ...haGroupJobSection(job));', 'fill(nodes.group);', [RELOAD]),
]

def run(root, pattern_titles):
    env = dict(os.environ, BRAND_UI_ROOT=root)
    args = ['node'] + [f'--test-name-pattern={title}' for title in pattern_titles] + ['tests/backup-ui.mjs']
    started = time.time()
    done = subprocess.run(args, cwd=REPO, env=env, capture_output=True, text=True, timeout=1800)
    tail = [line for line in done.stdout.splitlines() if line.startswith(('# pass', '# fail', '# tests'))]
    return done.returncode, round(time.time() - started), tail, done.stdout + done.stderr

os.makedirs(OUT, exist_ok=True)
summary = open(os.path.join(OUT, 'summary.txt'), 'a', encoding='utf-8')
def note(line):
    summary.write(line + '\n'); summary.flush(); print(line, flush=True)

def tree(name, change):
    root = os.path.join(OUT, name)
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    shutil.copytree(os.path.join(REPO, 'backup'), os.path.join(root, 'backup'))
    os.symlink(os.path.join(REPO, 'branding'), os.path.join(root, 'branding'))
    if change:
        old, new = change
        path = os.path.join(root, 'backup', 'backup.js')
        text = open(path, encoding='utf-8').read()
        if text.count(old) != 1:
            return None, f'the text to change is there {text.count(old)} times'
        open(path, 'w', encoding='utf-8').write(text.replace(old, new))
    return root, None

if not ONLY:
    # the control: the same tests on the unchanged page must pass
    titles = sorted({title for _id, _what, _old, _new, tests in MUTANTS for title in tests})
    root, _problem = tree('control', None)
    code, secs, tail, text = run(root, titles)
    open(os.path.join(OUT, 'control.log'), 'w', encoding='utf-8').write(text)
    note(f'control rc={code} seconds={secs} {" ".join(tail)}')
for mutant_id, what, old, new, tests in MUTANTS:
    if ONLY and mutant_id not in ONLY:
        continue
    root, problem = tree(mutant_id, (old, new))
    if problem:
        note(f'{mutant_id} BROKEN-MUTANT {problem} :: {what}')
        continue
    code, secs, tail, text = run(root, tests)
    open(os.path.join(OUT, f'{mutant_id}.log'), 'w', encoding='utf-8').write(text)
    note(f'{mutant_id} {"CAUGHT" if code != 0 else "NOT-CAUGHT"} rc={code} seconds={secs} {" ".join(tail)} :: {what}')
    shutil.rmtree(root, ignore_errors=True)
note('sweep done')
