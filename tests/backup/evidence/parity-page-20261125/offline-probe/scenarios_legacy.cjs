// jsdom mirror of the legacy (two-step) tests I changed or that touch the changed code. Usage: node scenarios_legacy.cjs
const assert = require('node:assert/strict');
const { loadBuilders, open } = require('./harness.cjs');
const b = loadBuilders();
const scenarios = [];
const scenario = (name, run) => scenarios.push([name, run]);
const hasText = (page, text) => page.$('#view').textContent.includes(text);
const openHa = async (page, id) => { await page.until(() => page.$(`[data-focus="ha-import-${id}"]`), 'row'); page.click(`[data-focus="ha-import-${id}"]`); await page.until(() => page.$('.stepper[aria-label="匯入步驟"]'), 'wizard'); };

scenario('legacy: no device key (UI-17 two-step): info notice first, blocking warn after the check, enabled when the key arrives', async () => {
  const data = b.haFixture({ ha: { backups: [b.haMeta(b.HA_PLAIN, { protected: false })] } });
  data.status.key = null;
  const page = await open(b, data);
  await openHa(page, b.HA_PLAIN);
  assert(page.$$('.wizard-card .notice-info').some(n => n.textContent.includes('這台還沒有加密金鑰。匯入開始時會自動建立一把')));
  assert.equal(page.$('.wizard-card [data-focus="ha-keys"]').getAttribute('href'), '#/keys');
  page.click('[data-focus="ha-apps-next"]');
  await page.until(() => page.$('[data-ha-app="odoo"]'), 'legacy check', 30000);
  assert(page.$$('.wizard-card .notice-warn').some(n => n.textContent.includes('尚未建立加密金鑰。轉換好的備份會依「預設加密備份」用這台設備的金鑰加密')));
  assert.equal(page.$('#ha-db-0').checked, true);
  assert.equal(page.$('[data-focus="ha-convert"]').disabled, true, 'no conversion without the device key');
  page.w.__fixture.status.key = { key_id: b.KEY_ID, created: '2026-11-01T08:00:00Z', kit_confirmed: true };
  await page.until(() => !page.$('#refresh').disabled, 'the refresh button');
  page.click('#refresh');
  await page.until(() => !page.$('[data-focus="ha-convert"]').disabled, 'the convert button');
  assert.equal(page.$$('.wizard-card .notice-warn').filter(n => n.textContent.includes('尚未建立加密金鑰')).length, 0);
});

scenario('legacy: check results, Odoo blocked and n8n ok (UI-14): n8n can go, Odoo is named', async () => {
  const data = b.haFixture({ ha: { backups: [b.haMeta(b.HA_PLAIN, { protected: false, name: '未加密的 HA 備份' })] } });
  const page = await open(b, data);
  const blockedOdoo = b.haCheck({ odoo: { ok: false, blockers: ['這台的 Odoo 缺少 HA 資料庫已安裝的模組。'] }, databases: [{ ...b.haCheck().ha_check.apps[0].odoo.databases[0], ok: false, blockers: ['版本不同'] }] });
  page.w.__fixture.scripts['ha-check'] = b.haScripts({ check: blockedOdoo })['ha-check'];
  await openHa(page, b.HA_PLAIN);
  assert.deepEqual(page.$$('.stepper[aria-label="匯入步驟"] .step-label').map(i => i.textContent), ['選擇應用', '檢查', '結果與選項', '轉換', '還原']);
  page.click('[data-focus="ha-apps-next"]');
  await page.until(() => page.$('[data-ha-app="odoo"]'), 'check', 30000);
  assert.match(page.$('[data-ha-app="odoo"]').className, /is-blocked/);
  assert.equal(page.$('#ha-db-0').disabled, true);
  assert.equal(page.$('[data-focus="ha-convert"]').disabled, false);
  assert(hasText(page, '「Odoo 18」沒有通過檢查，這次不會匯入，這台的它也不會有任何變更；其他應用可以繼續轉換。'));
  // fixed on the device: two databases pass, one has to be chosen
  const odoo = (name, extra) => b.haCheck().ha_check.apps[0].odoo.databases[0] && { ...b.haCheck().ha_check.apps[0].odoo.databases[0], name, ...extra };
  page.w.__fixture.scripts['ha-check'] = b.haScripts({ check: b.haCheck({ databases: [odoo('woowtest'), odoo('archive-2025', { partners: 800 })] }) })['ha-check'];
  page.click('[data-focus="ha-recheck"]');
  await page.until(() => page.$('[data-ha-app="odoo"]:not(.is-blocked)'), 'second check', 30000);
  assert.equal(page.$('[data-focus="ha-convert"]').disabled, true, 'two databases passed: one must be chosen');
  assert(hasText(page, '請先選擇要搬過來的 Odoo 資料庫。'));
});

scenario('legacy: Nextcloud-like single app refused: nothing can go', async () => {
  const data = b.haFixture({ ha: { backups: [b.haMeta(b.HA_PLAIN, { protected: false })] } });
  const page = await open(b, data);
  const refused = b.haCheck({ odoo: { ok: false, blockers: ['x'] }, n8n: { ok: false, blockers: ['y'] } });
  page.w.__fixture.scripts['ha-check'] = b.haScripts({ check: refused })['ha-check'];
  await openHa(page, b.HA_PLAIN);
  page.click('[data-focus="ha-apps-next"]');
  await page.until(() => page.$('[data-ha-app="odoo"]'), 'check', 30000);
  assert.equal(page.$('[data-focus="ha-convert"]').disabled, true);
  assert(hasText(page, '沒有應用通過檢查，無法轉換。請依上面的說明處理後按「重新檢查」，或按「上一步」改選其他應用。'));
});

scenario('legacy: convert, hand over to the restore wizard, restore result with the HA to-dos', async () => {
  const data = b.haFixture({ ha: { backups: [b.haMeta(b.HA_PLAIN, { protected: false })] } });
  const page = await open(b, data);
  await openHa(page, b.HA_PLAIN);
  page.click('[data-focus="ha-apps-next"]');
  await page.until(() => page.$('[data-ha-app="n8n"]'), 'check', 30000);
  page.click('[data-focus="ha-convert"]');
  await page.until(() => page.$('#confirm-ok'), 'dialog');
  page.click('#confirm-ok');
  await page.until(() => page.w.location.hash === `#/restore/${b.B_HA}`, 'the restore wizard', 40000);
  await page.until(() => page.$('.app-preflight'), 'preflight');
  assert(page.$('.ha-banner'));
  page.click('[data-focus="pf-next"]');
  await page.until(() => page.$('#confirm-restore'), 'confirm');
  page.tick('#confirm-restore');
  page.click('[data-focus="confirm-start"]');
  await page.until(() => page.$('#result-heading') && page.text('#result-heading').includes('還原完成'), 'restore result', 40000);
  assert(hasText(page, '請用 HA 那邊 Odoo 的帳號和密碼登入這台的 Odoo。'));
  assert.deepEqual(page.fixtureErrors(), []);
});

(async () => {
  let failed = 0;
  for (const [name, run] of scenarios) {
    const started = Date.now();
    try { await run(); console.log(`PASS ${name} (${Date.now() - started} ms)`); } catch (error) { failed += 1; console.log(`FAIL ${name}\n   ${String(error.stack || error.message).split('\n').slice(0, 14).join('\n   ')}`); }
  }
  console.log(failed ? `${failed} FAILED` : 'ALL PASSED');
  process.exit(failed ? 1 : 0);
})();
