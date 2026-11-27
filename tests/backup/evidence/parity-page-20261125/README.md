# Evidence of lane PAGE (PG-OWNER-1735, 2026-11-25), branch parity/page-20261125 @ 1119389

What it shows and what it does not (DESIGN G5; nothing here is a service acceptance):

- `evidence/full1-backup-ui.tap`: the whole `node tests/backup-ui.mjs` on a clean detached worktree of 1119389 (headless Chromium, the fixture engine of the test file, fake window.cockpit),
  through team/heavy.sh and the host lock, 19:05 to 19:21 by date: 128 tests, 128 ok (108 of the base, among them the legacy two-step HA tests that were changed for UI-14 and UI-17,
  and 20 new ones whose titles start with 「HAOS 一次確認」). No secret or key value is in it (it is the TAP list of test titles).
- `offline-probe/`: the same page and the same fixture engine in jsdom (no layout, no contrast, no focus rings): `scenarios.cjs` 18 scenarios and `scenarios_legacy.cjs` 4, all passed;
  `page_mutants.py` lists 27 one-line changes of backup.js, `jsdom_mutants.py` runs them against the scenarios: 27 of 27 caught (`evidence/jsdom-mutation-summary-*.txt`; the first sweep caught 23, four
  mutants showed weak tests (the created-key notice and the apps left out only looked at in the result, the cancel that did not have to ask, a mutant text that had moved); tests and scenarios were made stricter, the second summary
  shows the four caught, and the Playwright tests of the final tip carry the same stricter assertions and passed).
- Static: node --check of both files, scripts/check_source.py passed (backup page: manifest, CSP, DOM sinks), no undeclared name (TypeScript checker, `offline-probe/undef_check.cjs`).
- NOT run: a Playwright-judged mutation sweep (main's heavy-step economy rule of 19:0x; the jsdom-judged sweep stands in and says so), anything on a real device (R8 of DESIGN G4: the REAL lane).
- The fixture engine simulates ha-import-start, the chain of its jobs (next_job_id, GroupResult, cancel, after_this, confirmation-required) as CONTRACT sections 7 and 8 describe them. Whether the real engine answers
  exactly so was read in backup-engine/woowbackup (cli.py, hachain.py, haissues.py) but not run by this lane.
