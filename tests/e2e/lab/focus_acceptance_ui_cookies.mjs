// Diagnostic metadata only. No value is exempted from scanning by this module.
import { createHash } from 'node:crypto';

export const digest = value => createHash('sha256').update(value, 'utf8').digest('hex');
const token = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const octets = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

export function parseSetCookie(header, now = Date.now()) {
  // headerValues('set-cookie') supplies separate fields; never split on commas.
  if (typeof header !== 'string' || header.length > 16384 || /[\r\n\x00]/.test(header))
    throw new Error('invalid cookie header');
  const parts = header.split(';');
  const pair = parts.shift().trim();
  const equal = pair.indexOf('=');
  if (equal < 1 || !token.test(pair.slice(0, equal).trim())) throw new Error('invalid cookie pair');
  const name = pair.slice(0, equal).trim();
  let value = pair.slice(equal + 1).trim();
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
  if (!octets.test(value)) throw new Error('invalid cookie value');
  const attrs = new Map();
  let ambiguous = false;
  for (const part of parts) {
    const pos = part.indexOf('=');
    const key = (pos < 0 ? part : part.slice(0, pos)).trim().toLowerCase();
    const val = pos < 0 ? '' : part.slice(pos + 1).trim();
    if (!key) continue;
    if (attrs.has(key)) ambiguous = true;
    attrs.set(key, val);
  }
  let maxAge = null, expires = null;
  if (attrs.has('max-age')) {
    const raw = attrs.get('max-age');
    if (!/^-?\d+$/.test(raw) || !Number.isSafeInteger(Number(raw))) ambiguous = true;
    else maxAge = Number(raw);
  }
  if (attrs.has('expires')) {
    const parsed = Date.parse(attrs.get('expires'));
    if (!Number.isFinite(parsed)) ambiguous = true;
    else expires = Math.floor(parsed / 1000);
  }
  // RFC6265 Max-Age takes precedence over Expires. Expired never means non-auth.
  const expired = maxAge !== null ? maxAge <= 0 : expires !== null ? expires * 1000 <= now : false;
  const classification = ambiguous ? 'ambiguous-http-attributes' : expired ? 'http-expired'
    : maxAge !== null || expires !== null ? 'http-persistent' : 'http-session';
  return { name, value, expires, maxAge, expired, classification, ambiguous,
    path: attrs.get('path'), sameSite: attrs.get('samesite')?.toLowerCase(),
    secure: attrs.has('secure'), httpOnly: attrs.has('httponly') };
}

const member = (row, jar) => jar.some(c => c.name === row.name && c.value === row.value);
export function cookieMetadata(row, initialJar, liveJar) {
  const live = member(row, liveJar);
  return { name: row.name, sha256: digest(row.value), length: Buffer.byteLength(row.value),
    expires: row.expires, maxAge: row.maxAge,
    classification: row.expired && live ? 'ambiguous-expired-but-live' : row.classification,
    initial_jar_member: member(row, initialJar), live_jar_member: live };
}

export function observedValues(rows, liveJar, initialJar = []) {
  // Keep renewed, removed, expired, short and unknown values. Empty pairs make
  // coverage fail explicitly; they are not silently treated as credentials.
  return [...new Set([...rows.flatMap(c => c.legacyValue === undefined ? [c.value] : [c.value, c.legacyValue]),
    ...liveJar.map(c => c.value), ...initialJar.map(c => c.value)])];
}

export function provedPublicTombstone(row, liveJar, proof) {
  // Pinned primary source: Cockpit337 cockpit_auth_empty_cookie_value(),
  // src/ws/cockpitauth.c SHA465dad6d...6952f9 and login-page handler. No
  // exclusion by expiry, length, cookie name alone, or arbitrary literal.
  return proof.source_version === '337' && proof.administrative_root_verified === true
    && proof.primary_source_hashes_verified === true
    && /^(?:[0-9]+:)?337(?:[-+~.]|$)/.test(proof.native_package_version || '')
    && /^[0-9a-f]{64}$/.test(proof.native_ws_binary_sha256 || '')
    && proof.authenticated_cookie_observed === true && row.rootGet === true
    && row.name === 'cockpit' && !row.ambiguous && !member(row, liveJar)
    && row.path === '/' && row.sameSite === 'strict' && row.secure && row.httpOnly
    && row.maxAge === null && row.expires === null
    && digest(row.value) === '1185f37d33b0f89e331f101a51bb8e51165c7efda15950b86a3ebcbb363f898e';
}

export function coverage(rows, initialJar, liveJar, observationErrors) {
  const metadata = rows.map(row => cookieMetadata(row, initialJar, liveJar));
  const everyLiveObserved = liveJar.length > 0 && liveJar.every(c => rows.some(r => r.name === c.name && r.value === c.value));
  const everyInitialObserved = initialJar.every(c => rows.some(r => r.name === c.name && r.value === c.value));
  for (const cookie of [...initialJar, ...liveJar]) {
    if (!metadata.some(r => r.name === cookie.name && r.sha256 === digest(cookie.value)))
      metadata.push({name:cookie.name,sha256:digest(cookie.value),length:Buffer.byteLength(cookie.value),
        expires:cookie.expires > 0 ? cookie.expires : null,maxAge:null,classification:'ambiguous-unobserved-jar-value',
        initial_jar_member:member(cookie,initialJar),live_jar_member:member(cookie,liveJar)});
  }
  return { metadata, observations_complete: observationErrors === 0 && everyLiveObserved && everyInitialObserved
      && rows.length > 0 && observedValues(rows, liveJar, initialJar).every(v => v.length > 0)
      && !metadata.some(r => r.classification.startsWith('ambiguous')),
    every_live_value_observed: everyLiveObserved };
}
