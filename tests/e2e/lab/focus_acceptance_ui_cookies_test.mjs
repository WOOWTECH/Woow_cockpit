import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseSetCookie, cookieMetadata, observedValues, coverage, digest, provedPublicTombstone } from './focus_acceptance_ui_cookies.mjs';
const now = Date.parse('2026-11-27T00:00:00Z');
const parse = header => parseSetCookie(header, now);
const jar = (name, value) => ({ name, value });
const sourceProof = () => ({source_version:'337', administrative_root_verified:true, authenticated_cookie_observed:true,
  primary_source_hashes_verified:true,native_package_version:'337-1',native_ws_binary_sha256:'a'.repeat(64)});

test('Max-Age zero and negative are expired, never an automatic non-auth exemption', () => {
  for (const age of ['0', '-1', '-99']) {
    const row = parse(`cockpit=example-credential; Max-Age=${age}; HttpOnly`);
    assert.equal(row.expired, true);
    assert.equal(row.classification, 'http-expired');
    assert.deepEqual(observedValues([row], []), ['example-credential']);
  }
});
test('Expires past and future are parsed without splitting the date comma', () => {
  assert.equal(parse('c=example; Expires=Wed, 21 Oct 2015 07:28:00 GMT').expired, true);
  assert.equal(parse('c=example; Expires=Wed, 21 Oct 2037 07:28:00 GMT').expired, false);
});
test('valid Max-Age overrides contradictory Expires in both directions', () => {
  assert.equal(parse('c=example; Max-Age=60; Expires=Wed, 21 Oct 2015 07:28:00 GMT').classification, 'http-persistent');
  assert.equal(parse('c=example; Max-Age=0; Expires=Wed, 21 Oct 2037 07:28:00 GMT').classification, 'http-expired');
});
test('case-insensitive attributes, optional quotes and padded values retain exact value', () => {
  const row = parse(' cockpit="YXNkPQ=="; mAx-AgE=0; PATH=/; HttpOnly ');
  assert.equal(row.value, 'YXNkPQ=='); assert.equal(row.maxAge, 0);
  assert.equal(row.name, 'cockpit');
});
test('session cookie remains session; no expiry invented from value or length', () => {
  for (const value of ['x', 'example-public-clearing-marker', 'example-long-auth-value'])
    assert.equal(parse('cockpit='+value+'; Path=/; HttpOnly').classification, 'http-session');
});
test('renewals retain all earlier and latest values, including expired prior values', () => {
  const rows = [parse('cockpit=old-value'), parse('cockpit=old-value; Max-Age=0'), parse('cockpit=new-value')];
  assert.deepEqual(observedValues(rows, [jar('cockpit', 'new-value')]), ['old-value', 'new-value']);
  const c = coverage(rows, [jar('cockpit', 'old-value')], [jar('cockpit', 'new-value')], 0);
  assert.equal(c.observations_complete, true);
  assert.equal(c.metadata[0].initial_jar_member, true); assert.equal(c.metadata[0].live_jar_member, false);
  assert.equal(c.metadata[2].live_jar_member, true);
});
test('expired header value still live is ambiguous and coverage fails', () => {
  const rows = [parse('cockpit=example; Max-Age=0')];
  const c = coverage(rows, [], [jar('cockpit', 'example')], 0);
  assert.equal(c.observations_complete, false);
  assert.equal(c.metadata[0].classification, 'ambiguous-expired-but-live');
});
test('unknown or missing live cookie observations and callback failure fail coverage', () => {
  const rows = [parse('cockpit=example')], live = [jar('cockpit', 'example')];
  assert.equal(coverage(rows, [], live, 1).observations_complete, false);
  assert.equal(coverage(rows, [], [], 0).observations_complete, false);
  assert.equal(coverage(rows, [], [jar('cockpit', 'unseen')], 0).observations_complete, false);
});
test('initial jar value absent from headers is scanned and identified as ambiguous even after renewal', () => {
  const rows=[parse('cockpit=new-value')], initial=[jar('cockpit','old-value')], live=[jar('cockpit','new-value')];
  assert.deepEqual(observedValues(rows,live,initial),['new-value','old-value']);
  const c=coverage(rows,initial,live,0);
  assert.equal(c.observations_complete,false);
  assert.equal(c.metadata.at(-1).classification,'ambiguous-unobserved-jar-value');
  assert.equal(c.metadata.at(-1).sha256,digest('old-value'));
});
test('malformed, duplicate and invalid lifetime attributes cannot claim safe expiry', () => {
  for (const attrs of ['Max-Age=no', 'Max-Age=+1', 'Max-Age=9007199254740992', 'Expires=bad',
    'Max-Age=0; Max-Age=60', 'Expires=Wed, 21 Oct 2015 07:28:00 GMT; Expires=bad']) {
    const row = parse('c=example; '+attrs);
    assert.equal(row.classification, 'ambiguous-http-attributes');
    assert.equal(coverage([row], [], [jar('c', 'example')], 0).observations_complete, false);
  }
});
test('folded headers, missing equals, controls and illegal cookie bytes refuse', () => {
  for (const header of ['cockpit', '=example', 'co ok=example', 'c=one, other=two', 'c=x\r\nX:y', 'c="bad value"'])
    assert.throws(() => parse(header), /invalid cookie/);
});
test('empty deletion pair is represented explicitly and never yields complete coverage', () => {
  const row = parse('cockpit=; Max-Age=0');
  assert.equal(row.value, ''); assert.equal(row.expired, true);
  assert.deepEqual(observedValues([row], []), ['']);
  assert.equal(coverage([row], [], [], 0).observations_complete, false);
});
test('public metadata has only name hash length lifetime classification and jar membership', () => {
  const row = parse('cockpit=example-credential; Max-Age=60');
  const safe = cookieMetadata(row, [], [jar('cockpit', row.value)]);
  assert.deepEqual(Object.keys(safe).sort(), ['name', 'sha256', 'length', 'expires', 'maxAge', 'classification', 'initial_jar_member', 'live_jar_member'].sort());
  assert.equal(safe.sha256, digest(row.value));
  assert.equal(safe.length, 18); assert.equal(JSON.stringify(safe).includes(row.value), false);
});
test('old quoted header extraction and parsed real value are both retained for diagnosis', () => {
  const row = parse('cockpit="example"'); row.legacyValue = '"example"';
  assert.deepEqual(observedValues([row], [jar('cockpit', 'example')]), ['example', '"example"']);
});
test('expired real session values never satisfy the pinned public tombstone proof', () => {
  const proof = sourceProof();
  for (const suffix of ['', '; Max-Age=0', '; Expires=Wed, 21 Oct 2015 07:28:00 GMT']) {
    const row = {...parse('cockpit=example-high-entropy-session-value'+suffix), rootGet:true};
    assert.equal(provedPublicTombstone(row, [], proof), false);
    assert.ok(observedValues([row], []).includes(row.value));
  }
});
test('public source constant needs actual root HTTP, matching source version and authenticated frame proof', () => {
  // Reconstruct a documented public source literal without printing it in TAP.
  const row = {...parse('cockpit='+Buffer.from('64656c65746564', 'hex').toString()+'; Path=/; SameSite=Strict; Secure; HttpOnly'), rootGet:true};
  const proof = sourceProof();
  assert.equal(provedPublicTombstone(row, [], proof), true);
  for (const change of [{source_version:'unknown'}, {source_version:'338'},
    {administrative_root_verified:false}, {authenticated_cookie_observed:false},
    {primary_source_hashes_verified:false}, {native_package_version:'338-1'}, {native_ws_binary_sha256:''}])
    assert.equal(provedPublicTombstone(row, [], {...proof,...change}), false);
  for (const change of [{rootGet:false}, {name:'other'}, {ambiguous:true}, {maxAge:0}, {expires:0},
    {path:'/other'}, {sameSite:'lax'}, {secure:false}, {httpOnly:false}])
    assert.equal(provedPublicTombstone({...row,...change}, [], proof), false);
  assert.equal(provedPublicTombstone(row, [jar('cockpit',row.value)], proof), false);
});
