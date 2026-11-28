// Offline helpers for the R8 page case (three selected, two importable), the page-emqx case (EMQX only) and the page
// import bridge (focus_page_bridge.py: any lab device, any selection, an unencrypted HA backup, the choices a check offers).
//
// `options` of issueKeyCount / issueKeys / confirmLineCount: absent = exactly the earlier behaviour (the R8, page-emqx and
// OpenDesign runs); `{ database }` (a run with choices) = the lines the product's one confirmation really lists
// (backup.js haConfirmLines): those of the shared part and, of each importable app, the shown lines about the whole app plus,
// for Odoo, the lines of the chosen database (`database` null: no database chosen).
const applies = (app, issue, options) => (options === undefined ? true
  : !(typeof issue?.database === 'string' && issue.database) || (app.app_id === 'odoo' && issue.database === options.database));
const listed = (issue, options) => options === undefined || (typeof issue?.message === 'string' && issue.message !== '');

export function issueKeyCount(check, options) {
  if (check?.schema !== 2 || !Array.isArray(check.apps)) throw new Error('check schema unavailable');
  const groups = [check.shared || [], ...check.apps.filter(app => app.importable === true)
    .map(app => (app.issues || []).filter(issue => applies(app, issue, options)))];
  return groups.reduce((total, issues) => {
    const keys = new Set();
    for (const issue of issues) {
      if (issue.level !== 'confirm' || !listed(issue, options)) continue;
      if (typeof issue.key !== 'string' || !issue.key) throw new Error('confirmation key unavailable');
      keys.add(issue.key);
    }
    return total + keys.size;
  }, 0);
}

// `checks`: how many checks the page started (a recheck with a chosen add-on or node makes it two); R8 and page-emqx one.
export function validImportIntent(wire, ticks, clicks, importApps = ['hermes', 'omnigent'], checks = 1) {
  return clicks === 1 && ticks === 1 && wire.check_starts === checks && wire.unique_import_requests === 1
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
// The lab device whose Cockpit the page must be on (its hostname); a config without `device` is dev-d's, as before.
export const DEFAULT_DEVICE = 'woowbk-dev-d';
const DEVICE = /^woowbk-dev-[a-z]$/;
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
    exact: take('exact'), select_stage: take('select_stage'), texts: { ...R8_PAGE.texts, ...textsGiven },
    device: source.device === undefined ? DEFAULT_DEVICE : source.device };
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
      || Object.values(value.texts).some(text => typeof text !== 'string' || !CHECK_TEXT.test(text))
      || typeof value.device !== 'string' || !DEVICE.test(value.device)
      // An unencrypted HA backup (`encrypted: false`): no key step and no key anywhere. Choices are judged exactly only.
      || (source.encrypted !== undefined && typeof source.encrypted !== 'boolean')
      || (source.choices !== undefined && (value.exact !== true || !validChoices(source.choices, value.importable))))
    throw new Error('invalid page expectations');
  // `encrypted` and `choices` appear only when the config carries them: an earlier config's expectations stay as they were.
  const extra = {};
  if (source.encrypted !== undefined) extra.encrypted = source.encrypted;
  if (source.choices !== undefined)
    extra.choices = Object.fromEntries(Object.entries(source.choices).map(([app, kinds]) => [app, { ...kinds }]));
  return { apps: [...value.apps], importable: [...value.importable], blocked: [...value.blocked],
    result_rows: value.result_rows.map(row => [...row]), exact: value.exact, select_stage: value.select_stage,
    texts: { ...value.texts }, importApps: [...value.importable].sort(), device: value.device, ...extra };
}

// The distinct confirmation keys of the one confirmation by group (`_shared`, then every importable app), as the page's
// acknowledgement must carry them: each listed key exactly once. Groups without a key are left out, as the page does.
export function issueKeys(check, options) {
  if (check?.schema !== 2 || !Array.isArray(check.apps)) throw new Error('check schema unavailable');
  const groups = [[SHARED, check.shared || []],
    ...check.apps.filter(app => app.importable === true).map(app => [app.app_id, app.issues || [], app])];
  const seen = new Set(), result = {};
  for (const [group, issues, app] of groups) {
    if (typeof group !== 'string' || !group || seen.has(group) || !Array.isArray(issues))
      throw new Error('confirmation group unavailable');
    seen.add(group);
    const keys = new Set();
    for (const issue of issues) {
      if (issue?.level !== 'confirm' || !listed(issue, options) || (app && !applies(app, issue, options))) continue;
      if (typeof issue.key !== 'string' || !CONFIRMATION_KEY.test(issue.key)) throw new Error('confirmation key unavailable');
      keys.add(issue.key);
    }
    if (keys.size) result[group] = [...keys].sort();
  }
  return result;
}

// How many lines the one confirmation lists for this check: every shown confirmation line of the shared part and of each
// importable app that is about the whole app (a line about one Odoo database shows only with that database chosen).
// With `options` (a run with choices) also the chosen Odoo database's own lines and the page's own line naming the
// databases that stay on HA (backup.js haLeftDatabases: two or more databases, one chosen, no engine line saying it).
export function confirmLineCount(check, options) {
  if (check?.schema !== 2 || !Array.isArray(check.apps)) throw new Error('check schema unavailable');
  const shown = issue => issue?.level === 'confirm' && typeof issue.message === 'string' && issue.message !== '';
  const whole = issue => !(typeof issue.database === 'string' && issue.database);
  if (options === undefined)
    return (check.shared || []).filter(shown).length + check.apps.filter(app => app.importable === true)
      .reduce((total, app) => total + (app.issues || []).filter(issue => shown(issue) && whole(issue)).length, 0);
  const lines = [...(check.shared || []).filter(shown), ...check.apps.filter(app => app.importable === true)
    .flatMap(app => (app.issues || []).filter(issue => shown(issue) && applies(app, issue, options)))];
  const odoo = check.apps.find(app => app?.app_id === 'odoo' && app.importable === true);
  const left = Boolean(odoo) && typeof options.database === 'string' && databaseNames(odoo).length >= 2
    && !lines.some(issue => issue.id === 'odoo.databases-left');
  return lines.length + (left ? 1 : 0);
}

// ------------------------------------------------------------------ the choices a check offers (CONTRACT §7 HaCheck)

export const CHOICE_KINDS = Object.freeze(['addon', 'node', 'database']);
const CHOICE_VALUE = /^[A-Za-z0-9_.@:+-]{1,100}$/;   // safe inside a quoted attribute selector and a check record
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// `choices.<kind>` of one app as the page reads them (backup.js haChoicesOf): rows with a value; ok unless false.
function choiceRows(app, kind) {
  const source = isObject(app?.choices) ? app.choices : {};
  return (Array.isArray(source[kind]) ? source[kind] : []).filter(row => isObject(row) && typeof row.value === 'string' && row.value)
    .map(row => ({ value: row.value, ok: row.ok !== false, default: row.default === true }));
}

// Every database name of an Odoo check (backup.js haOdooDatabasesV2): those of `choices.database`, then the section's.
function databaseNames(odoo) {
  const section = (Array.isArray(odoo?.odoo?.databases) ? odoo.odoo.databases : []).filter(db => isObject(db) && typeof db.name === 'string');
  return [...new Set([...choiceRows(odoo, 'database').map(row => row.value), ...section.map(db => db.name)])];
}

// The Odoo databases that can move (backup.js applyHaCheck / haDatabaseOk): a `choices.database` row says it itself, else
// the section's `ok`. None when Odoo is not importable.
export function usableDatabases(check) {
  const odoo = (Array.isArray(check?.apps) ? check.apps : []).find(app => app?.app_id === 'odoo');
  if (!odoo || odoo.importable !== true) return [];
  const rows = choiceRows(odoo, 'database');
  const section = (Array.isArray(odoo.odoo?.databases) ? odoo.odoo.databases : []).filter(db => isObject(db) && typeof db.name === 'string');
  const names = [...new Set([...section.map(db => db.name), ...rows.map(row => row.value)])];
  return names.filter(name => {
    const row = rows.find(item => item.value === name);
    return row ? row.ok : section.some(db => db.name === name && db.ok === true);
  });
}

// What the page must do so that exactly the run's named choices are imported, from what THIS check offers (nothing is
// invented): `named` {app: {kind: value}} from the run, `picked` the add-on/node radios the page already set.
//  - an importable app whose check offers two or more add-ons or nodes (the page shows radios) needs a named one that the
//    check lists as possible; the radio already showing it (picked, else the check's default) needs no click, any other
//    named one is clicked and the check has to run again with it (backup.js haPendingChoice);
//  - a named add-on or node of a kind without radios must be the one row the check offers;
//  - Odoo: the named database must be one that can move; without a name only the single one that can move (the page
//    preselects it, UI-16); several without a name is a stop;
//  - a name for an app the check does not call importable, or a kind it never offers, is a stop.
// importChoices / checkChoices: what the import and a recheck must then carry (backup.js haImportChoices / haCheckChoices).
export function planChoices(check, named, picked = {}) {
  const problems = [], clicks = [], importChoices = {}, checkChoices = {};
  const apps = (Array.isArray(check?.apps) ? check.apps : []).filter(app => isObject(app) && typeof app.app_id === 'string');
  const importable = apps.filter(app => app.importable === true);
  const put = (target, app, kind, value) => { (target[app] ||= {})[kind] = value; };
  for (const [app, kinds] of Object.entries(named || {}))
    if (!importable.some(row => row.app_id === app)) problems.push(`${app}: a choice was named for an app the check does not import`);
    else for (const kind of Object.keys(kinds || {}))
      if (!CHOICE_KINDS.includes(kind) || (kind === 'database' && app !== 'odoo')) problems.push(`${app}: no ${kind} choice`);
  let database = null;
  for (const app of importable) {
    const id = app.app_id;
    for (const kind of ['addon', 'node']) {
      const rows = choiceRows(app, kind), value = named?.[id]?.[kind], already = picked?.[id]?.[kind];
      if (rows.length >= 2) {
        if (value === undefined) { problems.push(`${id}: the check offers a ${kind} choice and the run named none`); continue; }
        if (!rows.some(row => row.value === value && row.ok)) { problems.push(`${id}: the named ${kind} is not one the check offers`); continue; }
        // The radio shows the page's own pick, else the check's default; only a pick the page made is sent (haChoice).
        const click = (already ?? rows.find(row => row.default)?.value ?? null) !== value;
        if (click) clicks.push({ app: id, kind, value });
        if (click || already !== undefined) {
          put(importChoices, id, kind, value);
          put(checkChoices, id, kind, value);
        }
      } else if (value !== undefined && !(rows.length === 1 && rows[0].value === value && rows[0].ok))
        problems.push(`${id}: the named ${kind} is not one the check offers`);
    }
    if (id === 'odoo') {
      const usable = usableDatabases(check), value = named?.odoo?.database;
      if (value !== undefined && !usable.includes(value)) problems.push('odoo: the named database is not one the check can move');
      else if (value === undefined && usable.length !== 1) problems.push('odoo: the check offers several databases and the run named none');
      else {
        database = value ?? usable[0];
        put(importChoices, 'odoo', 'database', database);
      }
    }
  }
  return { problems, clicks, database, importChoices, checkChoices };
}

// The choices the page and the bridge are told: {app: {kind: value}} of selected importable apps, safe values only.
export function validChoices(choices, importable) {
  return isObject(choices) && Object.entries(choices).every(([app, kinds]) => typeof app === 'string' && APP_ID.test(app)
    && importable.includes(app) && isObject(kinds) && Object.keys(kinds).length > 0
    && Object.entries(kinds).every(([kind, value]) => CHOICE_KINDS.includes(kind) && (kind !== 'database' || app === 'odoo')
      && typeof value === 'string' && CHOICE_VALUE.test(value)));
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
