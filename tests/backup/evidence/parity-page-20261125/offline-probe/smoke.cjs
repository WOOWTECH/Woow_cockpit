const { loadBuilders, open } = require('./harness.cjs');
(async () => {
  const b = loadBuilders();
  console.log('builders:', Object.keys(b).length, 'HA_V2', b.HA_V2);
  const page = await open(b, b.fixture());
  console.log('view heading:', page.text('#view-heading'), '| errors:', page.errors.length);
  page.close();
})().catch(error => { console.error('SMOKE FAILED', error.message.slice(0, 1500)); process.exit(1); });
