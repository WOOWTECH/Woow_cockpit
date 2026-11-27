// Offline helpers for this exact three-selected/two-importable R8 case.
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

export function validImportIntent(wire, ticks, clicks) {
  return clicks === 1 && ticks === 1 && wire.check_starts === 1 && wire.unique_import_requests === 1
    && JSON.stringify(wire.import_apps) === JSON.stringify(['hermes', 'omnigent'])
    && wire.then_restore && wire.confirm && wire.overwrite
    && Number.isInteger(wire.expected_acknowledged_keys) && wire.expected_acknowledged_keys >= 0
    && wire.acknowledged_keys === wire.expected_acknowledged_keys
    && wire.separate_restore_starts === 0 && wire.malformed === 0;
}
