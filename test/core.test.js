import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import {
  CookieJar,
  parseSetCookie,
  parseUrl,
  pathMatches,
  domainMatches,
  defaultPath,
} from '../src/core.js';

// Deterministic clock helper. Returns a function whose "now" is a fixed
// value, optionally advanced by calling .advance(ms).
function fakeClock(initialMs) {
  let t = initialMs;
  const fn = () => t;
  fn.advance = (ms) => { t += ms; };
  fn.set = (ms) => { t = ms; };
  return fn;
}

const BASE = 1_700_000_000_000; // a fixed, arbitrary epoch in ms.

test('parseSetCookie parses a simple name=value', () => {
  const c = parseSetCookie('sid=abc', 'shop.example', BASE);
  assert.equal(c.name, 'sid');
  assert.equal(c.value, 'abc');
  assert.equal(c.domain, 'shop.example');
  assert.equal(c.hostOnly, true);
  assert.equal(c.path, '/');
  assert.equal(c.expires, null);
  assert.equal(c.secure, false);
  assert.equal(c.httpOnly, false);
});

test('parseSetCookie drops a cookie with no =', () => {
  assert.equal(parseSetCookie('broken', 'shop.example', BASE), null);
});

test('parseSetCookie drops a cookie with empty name', () => {
  assert.equal(parseSetCookie('=value', 'shop.example', BASE), null);
});

test('Max-Age takes precedence over Expires', () => {
  // Expires is far in the future; Max-Age=0 forces immediate expiry.
  const far = new Date(BASE + 10 * 365 * 24 * 3600 * 1000).toUTCString();
  const c = parseSetCookie(`x=1; Expires=${far}; Max-Age=0`, 'shop.example', BASE);
  assert.equal(c.expires, BASE); // nowMs + 0
});

test('Max-Age negative value sets a past expiry', () => {
  const c = parseSetCookie('x=1; Max-Age=-10', 'shop.example', BASE);
  assert.equal(c.expires, BASE - 10000);
});

test('Domain attribute strips leading dot and sets hostOnly false', () => {
  const c = parseSetCookie('x=1; Domain=.example.com', 'shop.example', BASE);
  assert.equal(c.domain, 'example.com');
  assert.equal(c.hostOnly, false);
});

test('SameSite must be one of strict/lax/none', () => {
  const c = parseSetCookie('x=1; SameSite=Lax', 'shop.example', BASE);
  assert.equal(c.sameSite, 'lax');
  const c2 = parseSetCookie('x=1; SameSite=banana', 'shop.example', BASE);
  assert.equal(c2.sameSite, null);
});

test('pathMatches: exact, prefix-with-slash, trailing-slash cookie path', () => {
  assert.equal(pathMatches('/a', '/a'), true);
  assert.equal(pathMatches('/a', '/a/b'), true);
  assert.equal(pathMatches('/a/', '/a/b'), true);
  assert.equal(pathMatches('/a', '/ab'), false);
  assert.equal(pathMatches('/a', '/x'), false);
});

test('domainMatches: host-only and subdomain', () => {
  assert.equal(domainMatches('shop.example', 'shop.example'), true);
  assert.equal(domainMatches('example.com', 'shop.example.com'), true);
  assert.equal(domainMatches('example.com', 'shopexample.com'), false);
  assert.equal(domainMatches('com', 'example.com'), false); // bare suffix guarded
});

test('defaultPath per RFC 6265 §5.1.4', () => {
  assert.equal(defaultPath('/'), '/');
  assert.equal(defaultPath('/a'), '/');
  assert.equal(defaultPath('/a/b'), '/a');
  assert.equal(defaultPath('/a/b/c'), '/a/b');
  assert.equal(defaultPath(''), '/');
});

test('parseUrl extracts scheme, host, path, port', () => {
  const u = parseUrl('https://shop.example.com:8443/cart/checkout?x=1');
  assert.equal(u.scheme, 'https');
  assert.equal(u.host, 'shop.example.com');
  assert.equal(u.port, '8443');
  assert.equal(u.path, '/cart/checkout');
});

test('parseUrl returns null for non-URL input', () => {
  assert.equal(parseUrl('not a url'), null);
  assert.equal(parseUrl(''), null);
});

test('storeFromUrl stores a host-only cookie and getCookieHeader returns it', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  assert.equal(jar.storeFromUrl('https://shop.example/cart', 'sid=abc'), true);
  assert.equal(jar.getCookieHeader('https://shop.example/cart'), 'sid=abc');
});

test('host-only cookie does not match a sibling subdomain', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/cart', 'sid=abc');
  assert.equal(jar.getCookieHeader('https://other.example/cart'), '');
});

test('Domain cookie matches subdomains', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example.com/', 'sid=abc; Domain=example.com');
  assert.equal(jar.getCookieHeader('https://other.example.com/'), 'sid=abc');
  assert.equal(jar.getCookieHeader('https://example.com/'), 'sid=abc');
});

test('Domain cookie is rejected if request host does not domain-match', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  assert.equal(jar.storeFromUrl('https://attacker.example/', 'sid=abc; Domain=example.com'), false);
  assert.equal(jar.size(), 0);
});

test('Domain equal to a bare public suffix is rejected', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  assert.equal(jar.storeFromUrl('https://example.com/', 'sid=abc; Domain=com'), false);
});

test('path scoping: cookie set under /a only returned for paths under /a', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/a', 'sid=abc; Path=/a');
  assert.equal(jar.getCookieHeader('https://shop.example/a'), 'sid=abc');
  assert.equal(jar.getCookieHeader('https://shop.example/a/b'), 'sid=abc');
  assert.equal(jar.getCookieHeader('https://shop.example/'), '');
  assert.equal(jar.getCookieHeader('https://shop.example/ab'), '');
});

test('default path is computed when no Path attribute is given', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  // Request path /a/b/c => default cookie path /a/b.
  jar.storeFromUrl('https://shop.example/a/b/c', 'sid=abc');
  assert.equal(jar.getCookieHeader('https://shop.example/a/b/d'), 'sid=abc');
  assert.equal(jar.getCookieHeader('https://shop.example/a/b'), 'sid=abc');
  assert.equal(jar.getCookieHeader('https://shop.example/a'), '');
});

test('expired cookies are not returned and are removed lazily', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/', 'sid=abc; Max-Age=60');
  assert.equal(jar.getCookieHeader('https://shop.example/'), 'sid=abc');
  now.advance(61_000);
  assert.equal(jar.getCookieHeader('https://shop.example/'), '');
  assert.equal(jar.size(), 0);
});

test('Max-Age=0 at store time drops the cookie (overwrite-or-remove)', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/', 'sid=abc');
  assert.equal(jar.storeFromUrl('https://shop.example/', 'sid=abc; Max-Age=0'), false);
  assert.equal(jar.size(), 0);
});

test('cookies are ordered by descending path length in the header', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/a/b', 'p=1; Path=/a/b');
  jar.storeFromUrl('https://shop.example/', 'q=2; Path=/');
  const header = jar.getCookieHeader('https://shop.example/a/b/c');
  assert.equal(header, 'p=1; q=2');
});

test('Secure cookies are not sent over http', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/', 'sid=abc; Secure');
  assert.equal(jar.getCookieHeader('https://shop.example/'), 'sid=abc');
  assert.equal(jar.getCookieHeader('http://shop.example/'), '');
});

test('removeByName with url removes only matching scope', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example.com/', 'sid=abc; Domain=example.com');
  jar.storeFromUrl('https://other.example.com/', 'sid=xyz');
  const removed = jar.removeByName('sid', { url: 'https://shop.example.com/' });
  assert.equal(removed, 1);
  assert.equal(jar.getCookieHeader('https://shop.example.com/'), '');
  assert.equal(jar.getCookieHeader('https://other.example.com/'), 'sid=xyz');
});

test('removeSession drops only session cookies', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/', 'session=1');
  jar.storeFromUrl('https://shop.example/', 'persist=2; Max-Age=3600');
  assert.equal(jar.removeSession(), 1);
  assert.equal(jar.getCookieHeader('https://shop.example/'), 'persist=2');
});

test('clear empties the jar', () => {
  const now = fakeClock(BASE);
  const jar = new CookieJar({ now });
  jar.storeFromUrl('https://shop.example/', 'a=1');
  jar.storeFromUrl('https://shop.example/', 'b=2');
  jar.clear();
  assert.equal(jar.size(), 0);
});
