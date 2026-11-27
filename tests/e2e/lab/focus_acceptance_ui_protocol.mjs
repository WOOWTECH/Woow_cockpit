// Offline helpers for the R8 page case (three selected, two importable) and the page-emqx case (EMQX only).
export function issueKeyCount(check) {
  if (check?.schema !== 2 || !Array.isArray(check.apps)) throw new Error('check schema unavailable');
  const groups = [check.shared || [], ...check.apps.filter(app => app.importable === true).map(app => app.issues || [])];
  return groups.reduce((total, issues) => {
    const keys = new Set();
    for (const issue of issues) {
      if (issue.level !== 'confirm') continue;
      if (typeof issue.key !== 'string' || !issue.key) throw new Error('confirmation key unavailable');
      keys.add(issue.key);
    }
    return total + keys.size;
  }, 0);
}

export function validImportIntent(wire, ticks, clicks, importApps = ['hermes', 'omnigent']) {
  return clicks === 1 && ticks === 1 && wire.check_starts === 1 && wire.unique_import_requests === 1
    && JSON.stringify(wire.import_apps) === JSON.stringify(importApps)
    && wire.then_restore && wire.confirm && wire.overwrite
    && Number.isInteger(wire.expected_acknowledged_keys) && wire.expected_acknowledged_keys >= 0
    && wire.acknowledged_keys === wire.expected_acknowledged_keys
    && wire.separate_restore_starts === 0 && wire.malformed === 0;
}

// What the controller tells the page to select and expect. A key the config does not carry keeps the R8 case's value,
// so the R8 controller's config (none of these keys) runs exactly the three-selected/two-importable flow.
export const R8_PAGE = Object.freeze({
  apps: Object.freeze(['emqx', 'omnigent', 'hermes']),   // checked in this order
  importable: Object.freeze(['hermes', 'omnigent']),     // [data-importable="yes"], exactly once each, in this order
  blocked: Object.freeze(['emqx']),                      // [data-importable="no"] with a stop line
  result_rows: Object.freeze([Object.freeze(['hermes', 'imported']), Object.freeze(['omnigent', 'imported']),
    Object.freeze(['emqx', 'excluded'])]),
  exact: false,                                          // true: lines, keys and result rows are compared exactly too
  select_stage: 'select-three-apps',
  texts: Object.freeze({
    upload: 'UI uploaded derived real fixture through actual page',
    select: 'UI selects exactly the three reviewed apps',
    view: 'UI corrupt EMQX blocked and both other apps importable',
    result: 'UI result imports both apps and retains excluded EMQX row',
    intent: 'UI one click sends one real acknowledged import intent for only importable apps',
    lines: 'UI lists every confirmation line of the check',
    keys: 'UI import carries every listed confirmation key exactly once',
  }),
});
const APP_ID = /^[a-z0-9][a-z0-9-]{1,40}$/;
const STAGE = /^[a-z0-9-]{1,40}$/;
const CHECK_TEXT = /^[A-Za-z0-9 ,()/:'<>.=_-]{3,140}$/;   // the capture's fixed status vocabulary
export const CONFIRMATION_KEY = /^[a-z0-9.-]{4,70}:[0-9a-f]{16}$/;   // haissues.KEY_RE, the page's HA_ISSUE_KEY_RE
const SHARED = '_shared';

export function pageExpectations(config) {
  const source = config !== null && typeof config === 'object' ? config : {};
  const take = name => (source[name] === undefined ? R8_PAGE[name] : source[name]);
  const textsGiven = source.texts === undefined ? {} : source.texts;
  if (textsGiven === null || typeof textsGiven !== 'object' || Array.isArray(textsGiven))
    throw new Error('invalid page expectations');
  const value = { apps: take('apps'), importable: take('importable'), blocked: take('blocked'), result_rows: take('result_rows'),
    exact: take('exact'), select_stage: take('select_stage'), texts: { ...R8_PAGE.texts, ...textsGiven } };
  const ids = list => Array.isArray(list) && list.every(id => typeof id === 'string' && APP_ID.test(id))
    && new Set(list).size === list.length;
  const statusOf = id => (value.importable.includes(id) ? 'imported' : 'excluded');
  // Another selection must name its own checks: the R8 names would describe a flow the page is not running.
  const ownSelection = ['apps', 'importable', 'blocked', 'result_rows'].some(name => source[name] !== undefined);
  if ((ownSelection && ['upload', 'select', 'view', 'result', 'intent'].some(name => !Object.hasOwn(textsGiven, name)))
      || !ids(value.apps) || !value.apps.length || !ids(value.importable) || !value.importable.length || !ids(value.blocked)
      || ![...value.importable, ...value.blocked].every(id => value.apps.includes(id))
      || value.importable.some(id => value.blocked.includes(id))
      || value.importable.length + value.blocked.length !== value.apps.length
      || !Array.isArray(value.result_rows) || value.result_rows.length !== value.apps.length
      || !value.result_rows.every(row => Array.isArray(row) && row.length === 2 && value.apps.includes(row[0]) && row[1] === statusOf(row[0]))
      || new Set(value.result_rows.map(row => row[0])).size !== value.result_rows.length
      || typeof value.exact !== 'boolean' || typeof value.select_stage !== 'string' || !STAGE.test(value.select_stage)
      || Object.keys(value.texts).some(name => !Object.hasOwn(R8_PAGE.texts, name))
      || Object.values(value.texts).some(text => typeof text !== 'string' || !CHECK_TEXT.test(text)))
    throw new Error('invalid page expectations');
  return { apps: [...value.apps], importable: [...value.importable], blocked: [...value.blocked],
    result_rows: value.result_rows.map(row => [...row]), exact: value.exact, select_stage: value.select_stage,
    texts: { ...value.texts }, importApps: [...value.importable].sort() };
}

// The distinct confirmation keys of the one confirmation by group (`_shared`, then every importable app), as the page's
// acknowledgement must carry them: each listed key exactly once. Groups without a key are left out, as the page does.
export function issueKeys(check) {
  if (check?.schema !== 2 || !Array.isArray(check.apps)) throw new Error('check schema unavailable');
  const groups = [[SHARED, check.shared || []],
    ...check.apps.filter(app => app.importable === true).map(app => [app.app_id, app.issues || []])];
  const seen = new Set(), result = {};
  for (const [group, issues] of groups) {
    if (typeof group !== 'string' || !group || seen.has(group) || !Array.isArray(issues))
      throw new Error('confirmation group unavailable');
    seen.add(group);
    const keys = new Set();
    for (const issue of issues) {
      if (issue?.level !== 'confirm') continue;
      if (typeof issue.key !== 'string' || !CONFIRMATION_KEY.test(issue.key)) throw new Error('confirmation key unavailable');
      keys.add(issue.key);
    }
    if (keys.size) result[group] = [...keys].sort();
  }
  return result;
}

// How many lines the one confirmation lists for this check: every shown confirmation line of the shared part and of each
// importable app that is about the whole app (a line about one Odoo database shows only with that database chosen).
export function confirmLineCount(check) {
  if (check?.schema !== 2 || !Array.isArray(check.apps)) throw new Error('check schema unavailable');
  const shown = issue => issue?.level === 'confirm' && typeof issue.message === 'string' && issue.message !== '';
  const whole = issue => !(typeof issue.database === 'string' && issue.database);
  return (check.shared || []).filter(shown).length + check.apps.filter(app => app.importable === true)
    .reduce((total, app) => total + (app.issues || []).filter(issue => shown(issue) && whole(issue)).length, 0);
}

// The `acknowledged` of an import request as observed on the wire: absent = {}; anything but groups of keys = null.
export function acknowledgedOf(value) {
  if (value === undefined) return {};
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const result = {};
  for (const [group, keys] of Object.entries(value)) {
    if (!Array.isArray(keys) || !keys.every(key => typeof key === 'string' && CONFIRMATION_KEY.test(key))) return null;
    result[group] = [...keys];
  }
  return result;
}

// Every expected key sent exactly once in its own group, and nothing else.
export function exactAcknowledged(expected, sent) {
  if (!expected || typeof expected !== 'object' || !sent || typeof sent !== 'object' || Array.isArray(sent)) return false;
  const groups = Object.keys(sent);
  return groups.length === Object.keys(expected).length && groups.every(group => {
    const keys = sent[group], want = expected[group];
    return Array.isArray(keys) && Array.isArray(want) && keys.length > 0 && new Set(keys).size === keys.length
      && keys.every(key => typeof key === 'string' && CONFIRMATION_KEY.test(key))
      && JSON.stringify([...keys].sort()) === JSON.stringify(want);
  });
}
