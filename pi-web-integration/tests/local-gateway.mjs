import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import vm from 'node:vm';

const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const close = server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('PI_GATEWAY_')));
const colors = {
  light: { primary: '#8B6B24', hover: '#765B1F', on_primary: '#FFFFFF' },
  dark: { primary: '#C49E53', hover: '#D1AF70', on_primary: '#1C1B1F' },
};
const auth = { cookie: 'cockpit=local-valid; pi_web_session=pi-valid' };

async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'pi-local-ingress-'));
  const brandFile = path.join(dir, 'brand.json');
  await writeFile(brandFile, JSON.stringify({ schema: 1, id: 'apporo', colors }));
  const state = { sessionValid: true, piEnabled: true, guardMalformed: false, forwarded: [], authRequests: [], guards: [] };
  const sockets = new Set();
  const cockpit = http.createServer((req, res) => {
    state.authRequests.push(req.headers);
    res.writeHead(state.sessionValid && req.url === '/cockpit/login' &&
      req.headers.cookie === 'cockpit=local-valid' && req.headers.host === authority &&
      req.headers['x-forwarded-proto'] === 'http' ? 200 : 401).end();
  });
  function accepted(req) {
    state.forwarded.push(req.headers);
    return req.headers.host === `127.0.0.1:${pp}` &&
      (!req.headers.origin || req.headers.origin === `http://127.0.0.1:${pp}`) &&
      req.headers['x-forwarded-proto'] === 'http';
  }
  const pi = http.createServer((req, res) => {
    if (req.url === '/api/web-auth') {
      state.guards.push(req.headers);
      res.end(state.guardMalformed ? 'invalid' : JSON.stringify({ enabled: state.piEnabled })); return;
    }
    if (!accepted(req)) { res.writeHead(403).end('Untrusted native proxy request'); return; }
    if (req.headers.cookie !== 'pi_web_session=pi-valid') { res.writeHead(401).end(); return; }
    if (req.url === '/redirect') { res.writeHead(307, { Location: `http://127.0.0.1:${pp}/login?next=x#ready` }).end(); return; }
    if (req.url === '/html') {
      const body = '<html><head><title>Pi</title></head><body>Pi</body></html>';
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(body),
        ETag: 'original', 'Content-MD5': 'old-digest', 'Content-Security-Policy': "default-src 'self'" });
      res.write(body.slice(0, 12)); res.end(body.slice(12)); return;
    }
    if (req.url === '/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: connected\n\n'); return;
    }
    res.writeHead(200, { 'Set-Cookie': ['cockpit=poison; Path=/', 'pi_web_session=pi-valid; Path=/; HttpOnly'] }).end('Pi');
  });
  pi.on('upgrade', (req, socket) => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket));
    if (!accepted(req) || req.headers.cookie !== 'pi_web_session=pi-valid') {
      socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); return;
    }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n' +
      'Set-Cookie: cockpit=poison; Path=/\r\nSet-Cookie: pi_web_session=pi-valid; Path=/\r\n\r\n');
    socket.pipe(socket);
  });
  const cp = await listen(cockpit), pp = await listen(pi);
  const gatewayProbe = http.createServer(), gp = await listen(gatewayProbe);
  const browserProbe = http.createServer(), bp = await listen(browserProbe);
  const authority = `127.0.0.1:${bp}`, origin = `http://${authority}`;
  await Promise.all([close(gatewayProbe), close(browserProbe)]);
  const child = spawn(process.execPath, ['pi-web-integration/gateway.mjs'], {
    env: { ...environment, PI_GATEWAY_BIND: '127.0.0.1', PI_GATEWAY_HOST: '127.0.0.1',
      PI_GATEWAY_PORT: String(gp), PI_GATEWAY_COCKPIT_PORT: String(cp), PI_GATEWAY_UPSTREAM_PORT: String(pp),
      PI_GATEWAY_LOCAL_ORIGIN: origin, PI_GATEWAY_BRAND_FILE: brandFile }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = ''; child.stderr.on('data', data => stderr += data);
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit'); child.kill(); await exited;
    }
    for (const socket of sockets) socket.destroy();
    await Promise.all([close(cockpit), close(pi), rm(dir, { recursive: true, force: true })]);
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('Gateway startup timeout')), 5000);
    child.stdout.once('data', () => { clearTimeout(timer); resolve(); });
    child.once('exit', code => { clearTimeout(timer); reject(Error(`Gateway exited ${code}: ${stderr}`)); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
  });
  function request(headers = {}, method = 'GET', url = '/resource') {
    return new Promise((resolve, reject) => {
      const req = http.request({ hostname: '127.0.0.1', port: gp, path: url, method,
        headers: { host: authority, ...headers } }, res => {
        let body = ''; res.setEncoding('utf8'); res.on('data', data => body += data);
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on('error', reject); req.end();
    });
  }
  function websocket(headers = {}) {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host: '127.0.0.1', port: gp }, () => {
        const values = { Host: authority, Origin: origin, Cookie: auth.cookie, Connection: 'Upgrade', Upgrade: 'websocket', ...headers };
        socket.write('GET /ws HTTP/1.1\r\n' + Object.entries(values).filter(([, value]) => value !== null)
          .map(([key, value]) => `${key}: ${value}\r\n`).join('') + '\r\n');
      });
      sockets.add(socket); socket.on('close', () => sockets.delete(socket));
      let wire = '';
      function received(data) {
        wire += data;
        if (wire.includes('\r\n\r\n')) { socket.off('data', received); resolve({ wire, socket }); }
      }
      socket.on('data', received); socket.on('error', reject);
    });
  }
  function events() {
    return new Promise((resolve, reject) => {
      const req = http.get({ hostname: '127.0.0.1', port: gp, path: '/events', headers: { host: authority, ...auth } }, res => {
        const closed = new Promise(done => res.once('close', done));
        res.once('data', data => resolve({ res, closed, first: data.toString() }));
      }); req.on('error', reject);
    });
  }
  return { request, websocket, events, state, origin, authority, gp, pp };
}

test('local ingress preserves both auth layers, fixed HTTP forwarding and Apporo theme', { timeout: 10000 }, async t => {
  const f = await fixture(t), { request, state, origin, authority, pp } = f;
  assert.equal((await request()).status, 401);
  assert.equal((await request({ cookie: 'cockpit=wrong' })).status, 401);
  assert.equal((await request({ cookie: 'cockpit=local-valid' })).status, 401, 'Pi login remains independent');
  for (const cookie of ['cockpit=local-valid; cockpit=local-valid', `${auth.cookie}; pi_web_session=other`]) {
    assert.equal((await request({ cookie })).status, 401, 'duplicate cookies fail closed');
  }
  for (const headers of [
    { host: 'untrusted.test', 'x-forwarded-host': authority },
    { host: `127.0.0.1:${f.gp}` },
    { origin: 'https://untrusted.test' },
    { origin: `http://127.0.0.1:${f.gp}` },
    { origin: 'null' },
    { 'sec-fetch-site': 'cross-site' },
  ]) assert.equal((await request({ ...auth, ...headers })).status, 403);
  assert.equal((await request(auth, 'POST')).status, 403);
  const response = await request({ ...auth, origin, cookie: `${auth.cookie}; unrelated=secret`,
    'x-forwarded-proto': 'https', 'x-forwarded-host': 'untrusted.test',
    'x-forwarded-for': '192.0.2.1', 'x-real-ip': '192.0.2.2', 'proxy-authorization': 'Basic fake' }, 'POST');
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['content-security-policy'], `frame-ancestors ${origin}`);
  assert.deepEqual(response.headers['set-cookie'], ['pi_web_session=pi-valid; Path=/; HttpOnly']);
  assert.equal(state.authRequests.at(-1).host, authority);
  assert.equal(state.authRequests.at(-1)['x-forwarded-proto'], 'http');
  assert.equal(state.authRequests.at(-1).cookie, 'cockpit=local-valid');
  const forwarded = state.forwarded.at(-1);
  assert.equal(forwarded.host, `127.0.0.1:${pp}`);
  assert.equal(forwarded.origin, `http://127.0.0.1:${pp}`);
  assert.equal(forwarded['x-forwarded-host'], authority);
  assert.equal(forwarded['x-forwarded-proto'], 'http');
  assert.equal(forwarded.cookie, 'pi_web_session=pi-valid');
  for (const key of ['x-forwarded-for', 'x-real-ip', 'proxy-authorization']) assert.equal(forwarded[key], undefined);
  assert.equal(state.guards.at(-1).host, `127.0.0.1:${pp}`);
  assert.equal(state.guards.at(-1).cookie, undefined);
  assert.equal((await request(auth, 'GET', '/redirect')).headers.location, `${origin}/login?next=x#ready`);

  const html = await request({ ...auth, accept: 'text/html', 'accept-encoding': 'gzip',
    'if-none-match': 'original', 'if-modified-since': 'yesterday' }, 'GET', '/html');
  assert.equal(html.status, 200);
  assert.match(html.body, /<script defer src="\/__woow_cockpit_theme.js"><\/script><\/head>/);
  assert.equal(html.headers['content-security-policy'], `default-src 'self'; frame-ancestors ${origin}`);
  for (const key of ['content-length', 'etag', 'content-md5']) assert.equal(html.headers[key], undefined);
  assert.equal(state.forwarded.at(-1)['accept-encoding'], 'identity');
  for (const key of ['if-none-match', 'if-modified-since']) assert.equal(state.forwarded.at(-1)[key], undefined);
  for (const url of ['/sw.js', '/sw.js?v=1', '/__woow_cockpit_theme.js']) assert.equal((await request({}, 'GET', url)).status, 401);
  const forwardedCount = state.forwarded.length;
  for (const method of ['GET', 'HEAD']) assert.equal((await request(auth, method, '/sw.js?v=1')).status, 404);
  assert.equal(state.forwarded.length, forwardedCount, 'worker never reaches Pi');
  const bridge = await request(auth, 'GET', '/__woow_cockpit_theme.js');
  assert.equal(bridge.status, 200);
  assert.equal(bridge.headers['cache-control'], 'no-store');
  assert.equal(bridge.headers['x-content-type-options'], 'nosniff');
  assert.doesNotMatch(bridge.body, /localStorage/);
  const styles = new Map(), classes = new Set(), listeners = {}, messages = [];
  const parent = { postMessage: (...args) => messages.push(args) };
  const root = { dataset: { theme: 'light' }, style: { setProperty: (key, value) => styles.set(key, value) },
    classList: { contains: key => classes.has(key), toggle: (key, on) => on ? classes.add(key) : classes.delete(key) } };
  const window = { parent, addEventListener: (name, callback) => { listeners[name] = callback; } };
  vm.runInNewContext(bridge.body, { window, document: { documentElement: root }, MutationObserver: class { observe() {} } });
  assert.equal(messages[0][1], origin);
  for (const theme of ['dark', 'light']) {
    listeners.message({ origin, source: parent, data: { type: 'woow-cockpit-theme', theme } });
    assert.equal(root.dataset.theme, theme);
    assert.equal(styles.get('--accent'), colors[theme].primary);
    assert.equal(styles.get('--accent-hover'), colors[theme].hover);
    assert.equal(styles.get('--accent-contrast'), colors[theme].on_primary);
  }
  for (const event of [{ origin: 'https://untrusted.test', source: parent }, { origin, source: {} }]) {
    listeners.message({ ...event, data: { type: 'woow-cockpit-theme', theme: 'dark' } });
    assert.equal(root.dataset.theme, 'light');
  }
  state.piEnabled = false;
  assert.equal((await request(auth)).status, 503);
  state.piEnabled = true; state.guardMalformed = true;
  assert.equal((await request(auth)).status, 503);
});

test('local WebSocket validates browser origin, both sessions and native proxy headers', { timeout: 10000 }, async t => {
  const { websocket, state, origin, authority, pp } = await fixture(t);
  for (const [headers, status] of [
    [{ Host: 'untrusted.test', 'X-Forwarded-Host': authority }, 403],
    [{ Origin: 'https://untrusted.test' }, 403], [{ Origin: null }, 403],
    [{ 'Sec-Fetch-Site': 'cross-site' }, 403],
    [{ Cookie: null }, 401], [{ Cookie: 'cockpit=wrong' }, 401],
    [{ Cookie: 'cockpit=local-valid; cockpit=local-valid' }, 401],
    [{ Cookie: `${auth.cookie}; pi_web_session=other` }, 401],
    [{ Cookie: 'cockpit=local-valid' }, 401],
  ]) {
    const { wire, socket } = await websocket(headers);
    assert.ok(wire.startsWith(`HTTP/1.1 ${status} `), wire); socket.destroy();
  }
  state.piEnabled = false;
  const disabled = await websocket(); assert.match(disabled.wire, /^HTTP\/1\.1 503 /); disabled.socket.destroy();
  state.piEnabled = true;
  const { wire, socket } = await websocket({ Origin: origin, 'X-Forwarded-Proto': 'https' });
  assert.match(wire, /^HTTP\/1\.1 101 /);
  assert.doesNotMatch(wire, /cockpit=poison/);
  assert.match(wire, /pi_web_session=pi-valid/);
  assert.equal(state.forwarded.at(-1).host, `127.0.0.1:${pp}`);
  assert.equal(state.forwarded.at(-1).origin, `http://127.0.0.1:${pp}`);
  assert.equal(state.forwarded.at(-1)['x-forwarded-proto'], 'http');
  assert.equal(state.forwarded.at(-1).cookie, 'pi_web_session=pi-valid');
  const echoed = once(socket, 'data'); socket.write('ping');
  assert.equal((await echoed)[0].toString(), 'ping'); socket.destroy();
});

test('local SSE and WebSocket close when either Cockpit session or Pi protection is revoked', { timeout: 22000 }, async t => {
  await Promise.all(['sessionValid', 'piEnabled'].map(async protection => {
    const { events, websocket, state } = await fixture(t);
    const stream = await events(), upgraded = await websocket();
    assert.equal(stream.res.statusCode, 200); assert.match(stream.first, /connected/);
    assert.match(upgraded.wire, /^HTTP\/1\.1 101 /);
    const socketClosed = once(upgraded.socket, 'close');
    state[protection] = false;
    await Promise.all([stream.closed, socketClosed]);
    assert.equal(stream.res.complete, false, 'gateway terminates the live SSE connection');
  }));
});

test('local ingress configuration rejects noncanonical origins, nonloopback binds and mixed ingress modes', { timeout: 10000 }, async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'pi-local-invalid-'));
  const brandFile = path.join(dir, 'brand.json');
  await writeFile(brandFile, JSON.stringify({ schema: 1, id: 'apporo', colors }));
  const base = { ...environment, PI_GATEWAY_BIND: '127.0.0.1', PI_GATEWAY_HOST: '127.0.0.1', PI_GATEWAY_PORT: '19096',
    PI_GATEWAY_LOCAL_ORIGIN: 'http://127.0.0.1:29092', PI_GATEWAY_BRAND_FILE: brandFile };
  try {
    const invalid = ['https://127.0.0.1:29092', 'http://localhost:29092', 'http://127.1:29092',
      'http://2130706433:29092', 'http://127.0.0.2:29092', 'http://[::1]:29092', 'http://192.0.2.1:29092',
      'http://127.0.0.1', 'http://127.0.0.1:0', 'http://127.0.0.1:80', 'http://127.0.0.1:65536',
      'http://127.0.0.1:029092', 'http://127.0.0.1:29092/', 'http://127.0.0.1:29092/path',
      'http://127.0.0.1:29092?x=1', 'http://127.0.0.1:29092#x', 'http://user:pass@127.0.0.1:29092',
      'HTTP://127.0.0.1:29092', ' http://127.0.0.1:29092'];
    const cases = invalid.map(PI_GATEWAY_LOCAL_ORIGIN => ({ PI_GATEWAY_LOCAL_ORIGIN }));
    cases.push({ PI_GATEWAY_PUBLIC_ORIGIN: 'https://cockpit.example.test' },
      { PI_GATEWAY_BIND: '0.0.0.0', PI_GATEWAY_HOST: '0.0.0.0' },
      { PI_GATEWAY_BIND: '127.0.0.2', PI_GATEWAY_HOST: '127.0.0.2' });
    for (const extra of cases) {
      const child = spawn(process.execPath, ['pi-web-integration/gateway.mjs'], {
        env: { ...base, ...extra }, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let listening = false, errors = '';
      child.stdout.on('data', () => { listening = true; child.kill(); });
      child.stderr.on('data', data => errors += data);
      const timer = setTimeout(() => child.kill(), 2000);
      const [code, signal] = await once(child, 'exit'); clearTimeout(timer);
      assert.equal(listening, false, JSON.stringify(extra));
      assert.equal(signal, null, JSON.stringify(extra));
      assert.notEqual(code, 0, JSON.stringify(extra));
      assert.match(errors, /Error|Invalid/, JSON.stringify(extra));
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
