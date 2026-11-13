import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';

test('HTTPS ingress validates secure Cockpit sessions and preserves independent Pi auth', async () => {
  const origin = 'https://cockpit.example.test';
  let enabled = true, forwarded, authRequest, pp;
  const listen = s => new Promise(r => s.listen(0, '127.0.0.1', () => r(s.address().port)));
  const cockpit = http.createServer((req, res) => {
    authRequest = req.headers;
    res.writeHead(req.url === '/cockpit/login' && req.headers.cookie === 'cockpit=secure-valid' &&
      req.headers.host === 'cockpit.example.test' && req.headers['x-forwarded-proto'] === 'https' ? 200 : 401).end();
  });
  const pi = http.createServer((req, res) => {
    if (req.url === '/api/web-auth') { res.end(JSON.stringify({ enabled })); return; }
    forwarded = req.headers;
    if (req.headers.host !== `127.0.0.1:${pp}`) { res.writeHead(403).end('Untrusted native host'); return; }
    if (req.headers.cookie !== 'pi_web_session=pi-valid') { res.writeHead(401).end(); return; }
    if (req.url === '/redirect') { res.writeHead(307, { Location: `http://127.0.0.1:${pp}/login` }).end(); return; }
    if (req.url === '/html') {
      res.writeHead(200, { 'Content-Type': 'text/html' }).end('<html><head></head><body>Pi</body></html>'); return;
    }
    res.writeHead(200, { 'Set-Cookie': ['cockpit=poison; Path=/', 'pi_web_session=pi-valid; Path=/; Secure; HttpOnly'] }).end('ok');
  });
  const upgrades = new Set();
  pi.on('upgrade', (req, socket) => {
    forwarded = req.headers; upgrades.add(socket); socket.on('close', () => upgrades.delete(socket));
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n');
  });
  const cp = await listen(cockpit); pp = await listen(pi);
  const probe = http.createServer(), gp = await listen(probe);
  await new Promise(r => probe.close(r));
  const child = spawn(process.execPath, ['pi-web-integration/gateway.mjs'], {
    env: { ...process.env, PI_GATEWAY_BIND: '127.0.0.1', PI_GATEWAY_HOST: '127.0.0.1',
      PI_GATEWAY_PORT: String(gp), PI_GATEWAY_COCKPIT_PORT: String(cp), PI_GATEWAY_UPSTREAM_PORT: String(pp),
      PI_GATEWAY_PUBLIC_ORIGIN: origin }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const request = (headers = {}, method = 'GET', path = '/resource') => new Promise((resolve, reject) => {
    const q = http.request({ hostname: '127.0.0.1', port: gp, method, path,
      headers: { host: 'cockpit.example.test', ...headers } }, r => {
      let body = ''; r.on('data', c => body += c); r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body }));
    }); q.on('error', reject); q.end();
  });
  const auth = { cookie: 'cockpit=secure-valid; pi_web_session=pi-valid' };
  try {
    await new Promise((resolve, reject) => {
      child.stdout.once('data', resolve); child.once('exit', c => reject(Error(`gateway exited ${c}`)));
      setTimeout(() => reject(Error('startup timeout')), 5000).unref();
    });
    assert.equal((await request()).status, 401);
    assert.equal((await request({ cookie: 'cockpit=secure-valid' })).status, 401, 'Pi login remains required');
    assert.equal((await request({ ...auth, host: 'untrusted.test' })).status, 403);
    assert.equal((await request({ ...auth, origin: 'https://untrusted.test' }, 'POST')).status, 403);
    assert.equal((await request(auth, 'POST')).status, 403);
    const valid = await request({ ...auth, origin, 'x-forwarded-proto': 'http' }, 'POST');
    assert.equal(valid.status, 200);
    assert.equal(authRequest['x-forwarded-proto'], 'https');
    assert.equal(forwarded['x-forwarded-proto'], 'https');
    assert.equal(forwarded.origin, `https://127.0.0.1:${pp}`);
    assert.equal(forwarded.cookie, 'pi_web_session=pi-valid');
    assert.equal(valid.headers['content-security-policy'], `frame-ancestors ${origin}`);
    assert.deepEqual(valid.headers['set-cookie'], ['pi_web_session=pi-valid; Path=/; Secure; HttpOnly']);
    assert.equal((await request(auth, 'GET', '/redirect')).headers.location, origin + '/login');
    assert.match((await request({ ...auth, accept: 'text/html' }, 'GET', '/html')).body, /__woow_cockpit_theme.js/);
    assert.equal((await request(auth, 'GET', '/sw.js?v=1')).status, 404, 'Pi cannot register a worker over Cockpit scope');
    const wire = await new Promise((resolve, reject) => {
      const s = net.connect({ host: '127.0.0.1', port: gp }, () => s.write(
        `GET /api/terminal/test/events HTTP/1.1\r\nHost: cockpit.example.test\r\nOrigin: ${origin}\r\nCookie: ${auth.cookie}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`));
      s.once('data', d => { resolve(String(d)); s.destroy(); }); s.on('error', reject);
    });
    assert.match(wire, /^HTTP\/1.1 101 /);
    assert.equal(forwarded.cookie, 'pi_web_session=pi-valid');
    enabled = false;
    assert.equal((await request(auth)).status, 503);
  } finally {
    child.kill('SIGTERM'); for (const socket of upgrades) socket.destroy();
    await Promise.all([new Promise(r => cockpit.close(r)), new Promise(r => pi.close(r))]);
  }
});
