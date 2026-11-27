// jsdom mirror of the new Playwright tests (logic only: no layout, contrast, focus rings). Usage: node scenarios.cjs [name-substring]
const assert = require('node:assert/strict');
const { loadBuilders, open, sleep } = require('./harness.cjs');
const b = loadBuilders();
const scenarios = [];
const scenario = (name, run) => scenarios.push([name, run]);
const HA = b.HA_V2;
const startWizard = async (page, keep) => {
  const { $, $$, click, tick, until } = page;
  await until(() => $(`[data-focus="ha-import-${HA}"]`), 'the HA backup row');
  click(`[data-focus="ha-import-${HA}"]`);
  await until(() => $('#ha-app-odoo'), 'the apps step');
  for (const id of ['odoo', 'n8n', 'emqx', 'hermes']) if (!keep.includes(id)) tick(`#ha-app-${id}`, false);
  click('[data-focus="ha-apps-next"]');
  await until(() => $('[data-summary="check"]'), 'the check result', 30000);
};
const done = page => page.until(() => page.$('[data-result="group"]'), 'the end of the import', 60000);
const rows = page => Object.fromEntries(page.$$('.ha-group-row').map(row => [row.dataset.haApp, row.dataset.status]));
const hasText = (page, text) => page.$('#view').textContent.includes(text);

scenario('main: the check, the one confirmation, one tick, the chain and its results', async () => {
  const page = await open(b, b.v2Fixture({ outcomes: { n8n: { restore: 'rolled-back' } } }));
  const { $, $$, click, tick, until, text } = page;
  await startWizard(page, ['odoo', 'n8n', 'emqx']);
  assert.deepEqual($$('.stepper .step-label').map(item => item.textContent), ['選擇應用', '檢查', '結果與確認', '匯入']);
  assert.equal(text('[data-summary="check"]'), '可以匯入 2 個，不能匯入 1 個');
  assert.equal($('[data-ha-app="emqx"]').dataset.importable, 'no');
  assert(text('[data-ha-app="emqx"]').includes('這份備份是在 EMQX 執行中做的，內建資料庫可能只寫了一半，不能匯入。'));
  assert(text('[data-ha-app="emqx"]').includes('請先在 HA 停止 EMQX 附加元件，再重新做備份後匯入。'));
  assert.equal($('#ha-db-2').disabled, true, 'only the database with a real reason cannot be chosen');
  assert.equal($('#ha-db-0').disabled, false);
  assert.equal($('#ha-db-0').checked, false);
  assert.equal($('[data-focus="ha-import"]').disabled, true);
  tick('#ha-db-0');
  assert.equal($('[data-focus="ha-import"]').disabled, true, 'no tick, no start');
  tick('#ha-ack');
  assert.equal($('[data-focus="ha-import"]').disabled, false);
  tick('#ha-db-1');
  assert.equal($('#ha-ack').checked, false, 'another database untick');
  tick('#ha-db-0');
  tick('#ha-ack');
  click('[data-focus="ha-import"]');
  await until(() => $('.ha-group-list'), 'the import step', 30000);
  assert.equal($('[data-result="group"]'), null);
  assert.equal($('.ha-group-row[data-ha-app="emqx"]').dataset.status, 'excluded');
  await until(() => $('[data-result="group"]'), 'the end of the import', 60000);
  const [request] = page.calls('ha-import-start');
  assert.deepEqual(request.apps, ['odoo', 'n8n']);
  assert.equal(request.overwrite, true);
  assert.deepEqual(request.acknowledged, { _shared: [b.V2_PAUSES.key], odoo: [b.V2_ODOO_MODULES.key], n8n: [b.V2_N8N_KEY.key] });
  assert.deepEqual(request.choices, { odoo: { database: 'prod' } });
  assert.deepEqual(rows(page), { odoo: 'imported', n8n: 'rolled-back', emqx: 'excluded' });
  assert(text('.ha-group-row[data-ha-app="emqx"]').includes('請先在 HA 停止 EMQX 附加元件'));
  assert.equal(text('[data-result="group"] .ha-summary'), '1 個應用已匯入，其他沒有');
  assert.deepEqual(page.fixtureErrors(), []);
});

scenario('database: the only one that can move is chosen, an app without a result is named (UI-15, UI-16)', async () => {
  const page = await open(b, b.v2Fixture({ check: b.v2Check({ odoo: { choices: { database: [{ value: 'prod', label: 'prod', ok: true }, { value: 'test', label: 'test', ok: false }, { value: 'demo-old', label: 'demo-old', ok: false }] } }, apps: ['odoo'] }) }));
  await startWizard(page, ['odoo', 'hermes']);
  assert.equal(page.text('[data-summary="check"]'), '可以匯入 1 個，不能匯入 1 個');
  assert(hasText(page, '檢查結果沒有包含「Hermes 代理」，這次不會匯入它；可以按「重新檢查」再試。'));
  assert.equal(page.$('#ha-db-0').checked, true);
  assert.equal(page.$('#ha-db-1').disabled, true);
  assert(hasText(page, '只有一個資料庫可以搬，已經幫你選好。'));
  assert(!hasText(page, '請先選擇要搬過來的 Odoo 資料庫。'));
  page.tick('#ha-ack');
  page.click('[data-focus="ha-import"]');
  await done(page);
  const [request] = page.calls('ha-import-start');
  assert.deepEqual(request.apps, ['odoo']);
  assert.deepEqual(request.choices, { odoo: { database: 'prod' } });
  assert.deepEqual(request.acknowledged, { _shared: [b.V2_PAUSES.key], odoo: [b.V2_ODOO_MODULES.key] });
  assert.deepEqual(page.fixtureErrors(), []);
});

scenario('choice: add-on from two stores, recheck with choices', async () => {
  const opt = [{ value: '1b7b4ce7_woow-n8n', label: 'n8n（商店 1b7b4ce7，2.43.6）' }, { value: 'a1b2c3d4_woow-n8n', label: 'n8n（商店 a1b2c3d4，1.3.4）' }];
  const first = b.v2Check({ apps: ['n8n'], n8n: { importable: false, ok: false, issues: [b.v2Issue('n8n', 'stop', 'ha.addon-choice', '這份備份裡有兩個 n8n 附加元件，要先選一個。', { items: ['a', 'b'], action: '請選一個，再按「重新檢查」。' })], choices: { addon: opt } } });
  const page = await open(b, b.v2Fixture({ check: first }));
  await startWizard(page, ['n8n']);
  assert.equal(page.text('[data-summary="check"]'), '可以匯入 0 個，不能匯入 1 個');
  assert.equal(page.$('[data-focus="ha-import"]'), null);
  assert(hasText(page, '沒有應用可以匯入。'));
  const radios = page.$$('input[name="ha-addon-n8n"]');
  assert.equal(radios.length, 2);
  page.tick(radios[1]);
  assert(hasText(page, '選好後，請按下方的「重新檢查」。'));
  page.w.__fixture.scripts['ha-check'] = b.haScripts({ check: b.v2Check({ apps: ['n8n'], n8n: { choices: { addon: opt } } }) })['ha-check'];
  page.click('[data-focus="ha-recheck"]');
  await page.until(() => page.$('[data-ha-app="n8n"][data-importable="yes"]'), 'the second check', 30000);
  assert.deepEqual(page.calls('ha-check-start')[1].choices, { n8n: { addon: 'a1b2c3d4_woow-n8n' } });
  assert.equal(page.$$('input[name="ha-addon-n8n"]')[1].checked, true);
  page.tick('#ha-ack');
  page.click('[data-focus="ha-import"]');
  await done(page);
  assert.deepEqual(page.calls('ha-import-start')[0].choices, { n8n: { addon: 'a1b2c3d4_woow-n8n' } });
  assert.deepEqual(page.fixtureErrors(), []);
});

scenario('retry of a start with the same request id (UI-22)', async () => {
  const page = await open(b, b.v2Fixture(), { timeouts: true });
  await startWizard(page, ['n8n']);
  page.tick('#ha-ack');
  page.w.__fixture.hold.push('ha-import-start');
  page.click('[data-focus="ha-import"]');
  await page.until(() => hasText(page, '回應比較久，作業可能已經開始。正在重新確認它的狀態…'), 'the retry notice', 10000);
  await page.until(() => page.calls('ha-import-start').length >= 2, 'the second try', 10000);
  page.w.__fixture.release('ha-import-start');
  await done(page);
  const starts = page.calls('ha-import-start');
  assert.equal(new Set(starts.map(item => item.request_id)).size, 1);
  assert.equal(Object.values(page.w.__fixture.jobs).filter(item => item.chain && item.job.params.group.step === 'convert').length, 1);
  assert.deepEqual(page.fixtureErrors(), []);
});

scenario('never answers: words, then the same button reaches the one job (UI-22)', async () => {
  const page = await open(b, b.v2Fixture(), { timeouts: true });
  await startWizard(page, ['n8n']);
  page.tick('#ha-ack');
  page.w.__fixture.hold.push('ha-import-start');
  page.click('[data-focus="ha-import"]');
  await page.until(() => hasText(page, '這台設備還沒有回應，作業可能已經開始。請再按一次剛才的按鈕'), 'the words', 20000);
  assert.equal(page.calls('ha-import-start').length, 3);
  page.w.__fixture.hold.splice(0);
  page.w.__fixture.release('ha-import-start');
  page.click('[data-focus="ha-import"]');
  await done(page);
  assert.equal(new Set(page.calls('ha-import-start').map(item => item.request_id)).size, 1);
});

scenario('adopt the active job when every try ran out of time (UI-22)', async () => {
  const page = await open(b, b.v2Fixture(), { timeouts: true });
  await startWizard(page, ['odoo', 'n8n']);
  page.tick('#ha-db-0');
  page.tick('#ha-ack');
  page.w.__fixture.hold.push('ha-import-start');
  page.click('[data-focus="ha-import"]');
  await page.until(() => page.calls('ha-import-start').length >= 1, 'the first try');
  const record = b.v2ChainRecord({ app: 'odoo', index: 0, id: b.J_HA_RUN });
  page.w.__fixture.jobs[b.J_HA_RUN] = JSON.parse(JSON.stringify(record));
  page.w.__fixture.status.active_job = JSON.parse(JSON.stringify(record.job));
  await page.until(() => page.$('.ha-group-list'), 'the import step', 20000);
  assert.equal(page.$('.stepper .step.active .step-label').textContent, '匯入');
  assert.equal(page.$('.ha-group-row[data-ha-app="odoo"]').dataset.status, 'pending');
  assert(page.$('.ha-group-row[data-ha-app="odoo"]').textContent.includes('轉換中'));
  assert.equal(page.$$('.wizard-card .notice-error').length, 0);
});

scenario('key with a Tab is tried as it is (UI-12)', async () => {
  const meta = b.v2Meta({ protected: true, addons: b.v2Meta().addons.map(addon => ({ ...addon, encrypted: true })) });
  const page = await open(b, b.v2Fixture({ meta }));
  const { $, click, fill, until } = page;
  await until(() => $(`[data-focus="ha-import-${HA}"]`), 'row');
  click(`[data-focus="ha-import-${HA}"]`);
  await until(() => $('#ha-app-odoo'), 'apps');
  page.tick('#ha-app-hermes', false);
  click('[data-focus="ha-apps-next"]');
  await until(() => $('#ha-key'), 'the key step');
  click('[data-focus="ha-key-next"]');
  await until(() => hasText(page, '請輸入 HA 備份金鑰。'), 'empty refused');
  assert.equal(page.calls('ha-check-start').length, 0);
  fill('#ha-key', 'ABCD\tEFGH');
  assert.equal($('#ha-key-odd').hidden, false);
  click('[data-focus="ha-key-next"]');
  await until(() => hasText(page, '你輸入的金鑰含有 Tab 或換行等看不見的字元'), 'the hint after refusal');
  assert.equal(page.calls('ha-check-start')[0].key, 'ABCD\tEFGH');
  assert(hasText(page, 'HA 備份金鑰不正確，請確認後再試一次。'));
  assert.equal($('.stepper .step.active .step-label').textContent, '金鑰');
});

scenario('no device key: the page does not stop, the banner asks after the import (UI-17, D11)', async () => {
  const page = await open(b, b.v2Fixture({ key: false }));
  const { $, click, until } = page;
  await until(() => $(`[data-focus="ha-import-${HA}"]`), 'row');
  click(`[data-focus="ha-import-${HA}"]`);
  await until(() => $('#ha-app-odoo'), 'apps');
  assert(page.$$('.wizard-card .notice-info').some(n => n.textContent.includes('這台還沒有加密金鑰。匯入開始時會自動建立一把')));
  for (const id of ['odoo', 'emqx', 'hermes']) page.tick(`#ha-app-${id}`, false);
  click('[data-focus="ha-apps-next"]');
  await until(() => $('[data-summary="check"]'), 'check', 30000);
  page.tick('#ha-ack');
  assert.equal($('[data-focus="ha-import"]').disabled, false);
  assert(page.text('#key-banner').includes('需要設定加密金鑰'));
  click('[data-focus="ha-import"]');
  await until(() => $('.ha-group-list'), 'the import step', 30000);
  assert.equal($('[data-result="group"]'), null);
  await until(() => page.$$('.notice-warn').some(n => n.textContent.includes('這次匯入已經自動建立一把')), 'the created-key notice', 30000);
  assert.equal($('[data-result="group"]'), null, 'the notice was there while the import still ran');
  await done(page);
  assert(page.text('#key-banner').includes('請保存緊急金鑰。'));
  assert.equal(page.$$('.notice-warn').filter(n => n.textContent.includes('這次匯入已經自動建立一把')).length, 1);
  assert.equal(page.calls('key-init').length, 0);
});

scenario('refusal no-device-key shows the way to the keys (UI-17)', async () => {
  const page = await open(b, b.v2Fixture({ key: false }));
  await startWizard(page, ['n8n']);
  page.tick('#ha-ack');
  page.w.__fixture.failures.push({ command: 'ha-import-start', code: 'no-device-key', message: '這台設備尚未建立加密金鑰，而且無法自動建立。' });
  page.click('[data-focus="ha-import"]');
  await page.until(() => hasText(page, '這台設備尚未建立加密金鑰，而且無法自動建立。'), 'refusal');
  assert.equal(page.$$('.wizard-card .notice-error a[href="#/keys"]').length, 1);
  assert.equal(page.$('.stepper .step.active .step-label').textContent, '結果與確認');
});

scenario('stop after this app', async () => {
  const page = await open(b, b.v2Fixture());
  await startWizard(page, ['odoo', 'n8n']);
  page.tick('#ha-db-0');
  page.tick('#ha-ack');
  page.click('[data-focus="ha-import"]');
  await page.until(() => page.$('[data-focus="ha-stop-after"]'), 'the import step');
  page.click('[data-focus="ha-stop-after"]');
  await page.until(() => hasText(page, '已要求做完這個應用就停止；後面的應用不會開始。'), 'the notice');
  await done(page);
  assert.equal(page.calls('job-cancel')[0].after_this, true);
  assert.deepEqual(rows(page), { odoo: 'imported', n8n: 'not-started' });
});

scenario('cancel the whole import', async () => {
  const page = await open(b, b.v2Fixture());
  await startWizard(page, ['n8n']);
  page.tick('#ha-ack');
  page.click('[data-focus="ha-import"]');
  await page.until(() => page.$('[data-focus="ha-cancel-import"]'), 'import step');
  page.click('[data-focus="ha-cancel-import"]');
  await page.until(() => page.$('#confirm-dialog').hasAttribute('open'), 'the dialog asks first');
  page.click('#confirm-ok');
  await done(page);
  assert.equal(page.calls('job-cancel')[0].after_this, undefined);
  assert.equal(rows(page).n8n, 'not-started');
});

scenario('reconfirm: confirmation-required of one app', async () => {
  const page = await open(b, b.v2Fixture({ outcomes: { n8n: { convert: 'confirmation-required' } } }));
  await startWizard(page, ['odoo', 'n8n']);
  page.tick('#ha-db-0');
  page.tick('#ha-ack');
  page.click('[data-focus="ha-import"]');
  await done(page);
  assert.equal(rows(page).odoo, 'imported');
  assert.equal(rows(page).n8n, 'skipped');
  page.click('[data-focus="group-recheck-n8n"]');
  await page.until(() => hasText(page, '「n8n 工作流程」的內容和檢查時不一樣，請重新檢查後再確認一次。'), 'reconfirm notice');
  assert.equal(page.$('#ha-app-n8n').checked, true);
  assert.equal(page.$('#ha-app-odoo').checked, false);
  assert.equal(page.$('.stepper .step.active .step-label').textContent, '選擇應用');
});

scenario('only convert (然後 restore later)', async () => {
  const page = await open(b, b.v2Fixture());
  await startWizard(page, ['n8n']);
  page.tick('#ha-ack');
  page.click('[data-focus="ha-convert-only"]');
  await done(page);
  const [request] = page.calls('ha-import-start');
  assert.equal(request.then_restore, false);
  assert.equal(request.overwrite, undefined);
  assert.equal(page.text('[data-result="group"] .ha-summary'), '全部應用都已轉換成備份');
  assert.equal(rows(page).n8n, 'converted');
  assert(page.$('[data-focus="group-restore-n8n"]'));
  assert.equal(page.calls('restore-start').length, 0);
  assert.equal(page.$$('.ha-after').length, 0);
});

scenario('hostile text stays text', async () => {
  const page = await open(b, b.v2Fixture({ check: b.v2Check({ shared: [b.v2Issue('_shared', 'confirm', 'shared.pauses', '會暫停 <img src=x onerror="window.__pwned=1">', { items: ['<b>bold</b>', '"><script>window.__pwned=2</script>'] })],
    odoo: { issues: [b.v2Issue('odoo', 'confirm', 'odoo.missing-modules', '缺少 <i>模組</i>', { items: ['a'.repeat(120)], database: 'prod' })] } }) }));
  await startWizard(page, ['odoo', 'n8n', 'emqx']);
  page.tick('#ha-db-0');
  assert.equal(page.w.__pwned, undefined);
  assert.equal(page.$$('#view img, #view script, #view b, #view i').length, 0);
  assert(page.text('#ha-confirm-list').includes('<img src=x onerror="window.__pwned=1">'));
  assert(page.text('#ha-confirm-list').includes('<b>bold</b>'));
});

scenario('reload: a job of the import in the job view', async () => {
  const data = b.v2Fixture();
  const done1 = { app_id: 'odoo', status: 'imported', convert_job_id: 'j20261118T021000Z-0aa00002', restore_job_id: 'j20261118T023000Z-0aa00005', backup_id: b.B_V2.odoo, safety_backup_id: b.B_V2_SAFETY.odoo, code: null, message: null };
  const record = b.v2ChainRecord({ done: [done1] });
  data.jobs = { [b.J_HA_RUN]: record };
  data.status.active_job = JSON.parse(JSON.stringify(record.job));
  const page = await open(b, data, { hash: '#/overview' });
  await page.until(() => page.w.location.hash === `#/jobs/${b.J_HA_RUN}`, 'the job page');
  const section = await (async () => { await page.until(() => page.$('[data-group="g1a2b3c4d5e6f0042"]'), 'group section'); return page.$('[data-group="g1a2b3c4d5e6f0042"]'); })();
  assert.equal(section.querySelector('.ha-group-row[data-ha-app="odoo"]').dataset.status, 'imported');
  assert.equal(section.querySelector('.ha-group-row[data-ha-app="n8n"]').dataset.status, 'pending');
  assert(section.querySelector('.ha-group-row[data-ha-app="n8n"]').textContent.includes('轉換中'));
  assert(page.text('#view-heading').includes('轉換 HA 備份「n8n 工作流程」'));
});

scenario('job not found (X-JOB-03)', async () => {
  const page = await open(b, b.fixture(), { hash: '#/jobs/j20261113T020000Z-deadbeef' });
  await page.until(() => page.$('.job-error .notice-error'), 'notice');
  assert(page.text('.job-error .notice-error').includes('找不到指定的作業。看不到進度不代表作業停了，它可能還在執行；請按「重試」重新讀取，或到「活動紀錄」確認。'));
  const before = page.calls('job-status').length;
  page.click('.job-error [data-focus="error-retry"]');
  await page.until(() => page.calls('job-status').length > before, 'a second read');
});

scenario('legacy engine: partial convert and UI-21 hint', async () => {
  const data = b.haFixture({ ha: { backups: [b.haMeta(b.HA_PLAIN, { protected: false })] } });
  const page = await open(b, data);
  const { $, click, until } = page;
  page.w.__fixture.scripts['ha-check'] = b.haScripts({ check: b.haCheck({ n8n: { ok: false, blockers: ['HA 的 n8n 還沒有建立管理者帳號。'] } }) })['ha-check'];
  await until(() => $(`[data-focus="ha-import-${b.HA_PLAIN}"]`), 'row');
  click(`[data-focus="ha-import-${b.HA_PLAIN}"]`);
  await until(() => $('#ha-app-odoo'), 'apps');
  click('[data-focus="ha-apps-next"]');
  await until(() => $('[data-ha-app="n8n"]'), 'legacy check', 30000);
  assert.equal($('.stepper .step.active .step-label').textContent, '結果與選項');
  assert(hasText(page, '「n8n 工作流程」沒有通過檢查，這次不會匯入，這台的它也不會有任何變更；其他應用可以繼續轉換。'));
  assert.equal($('[data-focus="ha-convert"]').disabled, false);
  page.w.__fixture.scripts['ha-convert'] = [{ job: { state: 'succeeded', phase: 'verify', phases: b.phasesAt('ha-convert', null), progress: { percent: 100, message: '已完成' }, finished: '2026-11-18T03:05:30Z', cancellable: false,
    result: { size: 1, apps: ['odoo'], encrypted: true, ha_import: b.haImportView(['odoo']) } }, log: ['x'] }];
  click('[data-focus="ha-convert"]');
  await until(() => $('#confirm-ok'), 'dialog');
  click('#confirm-ok');
  await until(() => page.$$('.wizard-card .notice-info').some(n => n.textContent.includes('轉換已完成，但作業沒有回報新的備份編號')), 'the hint', 30000);
  assert.equal(page.$$('.wizard-card .notice-error').length, 0);
  assert.deepEqual(page.calls('ha-convert-start')[0].apps, ['odoo']);
});

scenario('restore of a converted backup: issues, confirmation and re-check (UI-25)', async () => {
  const data = b.haFixture();
  const inspected = b.haInspect();
  const [odoo, n8n] = inspected.preflight.apps;
  odoo.issues = [b.v2Issue('odoo', 'confirm', 'restore.pauses', '還原時會先暫停下列服務，完成後自動啟動回來。', { items: ['檔案管理 filebrowser'] }), b.v2Issue('odoo', 'auto', 'restore.device-key', '這台的加密金鑰會在還原開始時自動建立。')];
  Object.assign(n8n, { restorable: false, checks: [{ id: 'n8n/dir-in-use', status: 'fail', message: '這台 n8n 的資料夾被其他服務佔用，不能還原。' }],
    issues: [b.v2Issue('n8n', 'stop', 'restore.dir-in-use', '這台 n8n 的資料夾被其他服務佔用，不能還原。', { action: '請先停掉那個服務。' })] });
  data.inspect[b.B_HA] = inspected;
  data.backups.unshift(b.convertedMeta());
  const page = await open(b, data, { hash: `#/restore/${b.B_HA}` });
  await page.until(() => page.$('.app-preflight'), 'preflight');
  const cards = page.$$('.app-preflight');
  assert.equal(cards[1].querySelector('input[type="checkbox"]').disabled, true);
  assert(cards[1].textContent.includes('請先停掉那個服務。'));
  assert(/要確認[\s\S]*還原時會先暫停下列服務[\s\S]*檔案管理 filebrowser[\s\S]*系統會自動做[\s\S]*這台的加密金鑰會在還原開始時自動建立。/.test(cards[0].textContent));
  assert.equal(page.$('[data-focus="pf-next"]').disabled, false);
  page.click('[data-focus="pf-next"]');
  await page.until(() => page.$('#restore-confirm-list'), 'the confirm step');
  assert.equal(page.$$('#restore-confirm-list > li').length, 1);
  page.w.__fixture.failures.push({ command: 'restore-start', code: 'confirmation-required', message: '還原 Odoo 18 前還有事情要確認。', details: { apps: { odoo: [] } } });
  page.tick('#confirm-restore');
  page.click('[data-focus="confirm-start"]');
  await page.until(() => hasText(page, '還原 Odoo 18 前還有事情要確認。這和剛才看到的不一樣，已經重新檢查；請看過新的內容後再確認一次。'), 'the notice');
  await page.until(() => page.calls('inspect').length === 2 && page.$('[data-focus="pf-next"]'), 'the second inspect');
  page.click('[data-focus="pf-next"]');
  await page.until(() => page.$('#confirm-restore'), 'confirm again');
  page.tick('#confirm-restore');
  page.click('[data-focus="confirm-start"]');
  await page.until(() => page.$('#result-heading') && page.text('#result-heading').includes('還原完成'), 'restore result', 30000);
  const starts = page.calls('restore-start');
  assert.deepEqual(starts[1].acknowledged, { odoo: [b.keyOf('odoo', 'restore.pauses', ['檔案管理 filebrowser'])] });
});

(async () => {
  const only = process.argv[2] || '';
  let failed = 0;
  for (const [name, run] of scenarios) {
    if (only && !name.includes(only)) continue;
    const started = Date.now();
    try { await run(); console.log(`PASS ${name} (${Date.now() - started} ms)`); } catch (error) { failed += 1; console.log(`FAIL ${name}\n   ${String(error.stack || error.message).split('\n').slice(0, 14).join('\n   ')}`); }
  }
  console.log(failed ? `${failed} FAILED` : 'ALL PASSED');
  process.exit(failed ? 1 : 0);
})();
