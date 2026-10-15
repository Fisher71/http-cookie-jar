# HTTP Cookie Jar

A small, zero-dependency TypeScript-free ECMAScript module that stores,
retrieves, and expires cookies per the cookie-store model of RFC 6265,
scoped to a request URL.

## Usage

```js
import { CookieJar } from './src/index.js';

const jar = new CookieJar({ now: () => Date.now() });

// Store a cookie received in a response from this URL.
jar.storeFromUrl('https://shop.example/cart', 'sid=abc; Path=/cart; Secure');

// Build the outgoing Cookie header for a later request.
const header = jar.getCookieHeader('https://shop.example/cart/checkout');
// header === 'sid=abc'

// Remove cookies by name, optionally scoped to a URL.
jar.removeByName('sid', { url: 'https://shop.example/cart' });
```

The exported names are:

- `CookieJar` — the store class. Constructor accepts `{ now }`, a function
  returning milliseconds since epoch (defaults to `Date.now`).
  - `storeFromUrl(url, setCookieValue)` → `boolean` (true if stored).
  - `getCookieHeader(url)` → `string` (the `Cookie` header value, or `''`).
  - `removeByName(name, { url }?)` → `number` (count removed).
  - `removeSession()` → `number`.
  - `clear()`.
  - `size()` → `number`.
- `parseSetCookie`, `parseUrl`, `pathMatches`, `domainMatches`, `defaultPath` —
  the functions the jar is built from, exported for direct testing.

## Why this exists

HTTP clients need to manage cookies between requests, and the rules for
which cookie applies to which URL are subtle enough that ad-hoc handling
breaks on subdomains, path prefixes, and expiry. This library implements
those rules once, in one file, with no dependencies.

The trade-off: it is in-memory and per-process. There is no persistence, no
file-format negotiation, no shared store across processes. If you need
durability, serialise the jar's state yourself or use a different library.

## Edge cases you will hit

- **Clock.** Every expiry decision depends on time. The constructor takes a
  `now` function so tests are deterministic; never rely on wall-clock time.
- **Public suffixes.** The library rejects `Domain` attributes that exactly
  equal a small set of bare suffixes (`com`, `org`, `net`, `edu`, `gov`,
  `io`). It does not ship the full public-suffix list; `Domain=co.uk` would
  be accepted. If you need the full list, this is the wrong library.
- **HttpOnly.** The attribute is parsed and stored but has no effect on
  retrieval, because this library is not a browser and makes no
  `document.cookie`-style API available.
- **SameSite.** Parsed and stored, never consulted on retrieval. Same-site
  enforcement needs request context this library deliberately does not
  model.
- **IPv6 hosts.** Not handled. Cookies are scoped to domain names; an IP-literal
  request host will produce no matches for any `Domain` attribute.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

