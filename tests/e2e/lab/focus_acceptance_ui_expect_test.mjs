// Offline: what the page is told to select and expect, and the exact confirmation keys of the page-emqx case.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pageExpectations, R8_PAGE, issueKeys, issueKeyCount, confirmLineCount, acknowledgedOf, exactAcknowledged,
  validImportIntent } from './focus_acceptance_ui_protocol.mjs';

const R8_CONFIG = { ha_id: 'ha-' + '1'.repeat(20), fixture: '/f.tar', password: 'p', key: 'k', evidence: '/e',
  result: '/e/browser.json', playwright: '/p.mjs', chromium: '/c', since: 1, cookie_scan: 's', base: 'https://127.0.0.1:1' };
const EMQX = { apps: ['emqx'], importable: ['emqx'], blocked: [], result_rows: [['emqx', 'imported']], exact: true,
  select_stage: 'select-emqx', texts: { upload: 'UI uploaded original real fixture through actual page',
    select: 'UI selects only EMQX', view: 'UI check shows EMQX importable',
    result: 'UI result shows EMQX imported as the only row',
    intent: 'UI one click sends one real acknowledged import intent for EMQX only',
    lines: 'UI lists every confirmation line of the EMQX check',
    keys: 'UI import carries every listed confirmation key exactly once' } };
const K = n => `emqx.device-psk:${String(n).repeat(16)}`;
const S = 'files.skipped:' + 'a'.repeat(16);

test('the R8 controller config (none of the new keys) keeps every old selection, expectation and check name', () => {
  const expect = pageExpectations(R8_CONFIG);
  assert.deepEqual(expect.apps, ['emqx', 'omnigent', 'hermes']);
  assert.deepEqual(expect.importable, ['hermes', 'omnigent']);
  assert.deepEqual(expect.blocked, ['emqx']);
  assert.deepEqual(expect.result_rows, [['hermes', 'imported'], ['omnigent', 'imported'], ['emqx', 'excluded']]);
  assert.deepEqual(expect.importApps, ['hermes', 'omnigent']);
  assert.equal(expect.exact, false);
  assert.equal(expect.select_stage, 'select-three-apps');
  assert.deepEqual([expect.texts.upload, expect.texts.select, expect.texts.view, expect.texts.result, expect.texts.intent], [
    'UI uploaded derived real fixture through actual page', 'UI selects exactly the three reviewed apps',
    'UI corrupt EMQX blocked and both other apps importable', 'UI result imports both apps and retains excluded EMQX row',
    'UI one click sends one real acknowledged import intent for only importable apps']);
  assert.deepEqual(pageExpectations(undefined), pageExpectations({}));
  expect.apps.push('changed');   // a copy: the frozen defaults stay as they are
  assert.deepEqual(R8_PAGE.apps, ['emqx', 'omnigent', 'hermes']);
});

test('the page-emqx config selects only EMQX and expects it importable and imported, by its own names', () => {
  const expect = pageExpectations({ ...R8_CONFIG, ...EMQX });
  assert.deepEqual([expect.apps, expect.importable, expect.blocked, expect.importApps], [['emqx'], ['emqx'], [], ['emqx']]);
  assert.deepEqual(expect.result_rows, [['emqx', 'imported']]);
  assert.equal(expect.exact, true);
  assert.deepEqual(expect.texts, EMQX.texts);
});

test('inconsistent, partial or unnamed selections are refused', () => {
  const bad = [
    { apps: [] }, { apps: ['emqx', 'emqx'] }, { apps: ['EMQX'] }, { importable: [] },
    { importable: ['emqx'], blocked: ['emqx'] }, { importable: ['hermes'] }, { blocked: ['hermes'] },
    { result_rows: [['emqx', 'excluded']] }, { result_rows: [['emqx', 'imported'], ['emqx', 'imported']] },
    { result_rows: [['hermes', 'imported']] }, { result_rows: 'rows' }, { exact: 'yes' }, { select_stage: 'Select EMQX' },
    { texts: { ...EMQX.texts, view: 'semi;colon' } }, { texts: { ...EMQX.texts, other: 'UI other' } }, { texts: null },
    { texts: Object.fromEntries(Object.entries(EMQX.texts).filter(([name]) => name !== 'intent')) },
  ];
  for (const change of bad)
    assert.throws(() => pageExpectations({ ...R8_CONFIG, ...EMQX, ...change }), /invalid page expectations/, JSON.stringify(change));
  // A different selection must bring its own check names; the R8 names would describe another flow.
  assert.throws(() => pageExpectations({ ...R8_CONFIG, apps: ['emqx'], importable: ['emqx'], blocked: [],
    result_rows: [['emqx', 'imported']] }), /invalid page expectations/);
  // The R8 config's `result` is the private result path, never an expectation.
  assert.equal(pageExpectations(R8_CONFIG).result_rows.length, 3);
});

const CHECK = { schema: 2, shared: [{ level: 'confirm', key: S, message: 'skipped' }, { level: 'auto', message: 'key' }],
  apps: [{ app_id: 'emqx', importable: true, issues: [{ level: 'confirm', key: K(1), message: 'psk' },
    { level: 'confirm', key: K(1), message: 'psk again' }, { level: 'confirm', key: K(2), message: 'other' },
    { level: 'notice', message: 'hot backup' }] },
  { app_id: 'hermes', importable: false, issues: [{ level: 'confirm', key: K(3), message: 'not shown' }] }] };

test('expected keys are every listed key once, by group, only of importable apps', () => {
  assert.deepEqual(issueKeys(CHECK), { _shared: [S], emqx: [K(1), K(2)] });
  assert.equal(issueKeyCount(CHECK), 3);
  assert.deepEqual(issueKeys({ schema: 2, shared: [], apps: [{ app_id: 'emqx', importable: true, issues: [] }] }), {});
  assert.throws(() => issueKeys({ schema: 1, apps: [] }), /schema/);
  assert.throws(() => issueKeys({ ...CHECK, shared: [{ level: 'confirm', key: 'bad', message: 'x' }] }), /key/);
  assert.throws(() => issueKeys({ schema: 2, shared: [], apps: [{ app_id: 'emqx', importable: true, issues: [] },
    { app_id: 'emqx', importable: true, issues: [] }] }), /group/);
});

test('every shown confirmation line of the shared part and the importable apps is counted', () => {
  assert.equal(confirmLineCount(CHECK), 4);   // three EMQX lines (one key twice) and one shared line
  const odoo = { schema: 2, shared: [], apps: [{ app_id: 'odoo', importable: true, issues: [
    { level: 'confirm', key: K(4), message: 'whole app' }, { level: 'confirm', key: K(5), message: 'one db', database: 'db1' },
    { level: 'confirm', key: K(6), message: '' }] }] };
  assert.equal(confirmLineCount(odoo), 1);
});

test('the sent acknowledgement is copied as keys only, and must match exactly', () => {
  const expected = issueKeys(CHECK);
  assert.deepEqual(acknowledgedOf(undefined), {});
  assert.equal(acknowledgedOf(null), null);
  assert.equal(acknowledgedOf({ emqx: ['plain text'] }), null);
  assert.equal(acknowledgedOf({ emqx: 'k' }), null);
  assert.equal(exactAcknowledged(expected, acknowledgedOf({ emqx: [K(2), K(1)], _shared: [S] })), true);
  assert.equal(exactAcknowledged({}, acknowledgedOf(undefined)), true);
  for (const sent of [{ emqx: [K(1)], _shared: [S] }, { emqx: [K(1), K(2), K(2)], _shared: [S] },
    { emqx: [K(1), K(2), S] }, { emqx: [K(1), K(2)], _shared: [S], hermes: [K(3)] }, { emqx: [K(1), K(2)], _shared: [] },
    { emqx: [K(1), K(2)], _shared: [S, 'x'] }, null, [], 'keys'])
    assert.equal(exactAcknowledged(expected, sent), false, JSON.stringify(sent));
  assert.equal(exactAcknowledged(null, {}), false);
});

test('the intent check takes the expected import apps and keeps the R8 default', () => {
  const wire = { check_starts: 1, unique_import_requests: 1, import_apps: ['emqx'], then_restore: true, confirm: true,
    overwrite: true, expected_acknowledged_keys: 3, acknowledged_keys: 3, separate_restore_starts: 0, malformed: 0 };
  assert.equal(validImportIntent(wire, 1, 1, ['emqx']), true);
  assert.equal(validImportIntent(wire, 1, 1), false);
  assert.equal(validImportIntent({ ...wire, import_apps: ['hermes', 'omnigent'] }, 1, 1), true);
  for (const change of [{ import_apps: ['emqx', 'hermes'] }, { acknowledged_keys: 2 }, { check_starts: 2 }, { malformed: 1 }])
    assert.equal(validImportIntent({ ...wire, ...change }, 1, 1, ['emqx']), false);
  assert.equal(validImportIntent(wire, 2, 1, ['emqx']), false);
});
