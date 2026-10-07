/**
 * RFC 6265 cookie-store model for a single user agent.
 *
 * Design decisions (stated plainly so the tests can be trusted):
 *
 * - In-memory only. No persistence. A jar is created, used, and discarded within
 *   one process. This is the "non-persistent" store from §5.3 of RFC 6265.
 *
 * - A clock function is injected so that every time-dependent decision is
 *   deterministic in tests. The clock returns milliseconds since the Unix epoch,
 *   matching Date.now().
 *
 * - Domain matching follows the "host-only" vs "domain" rules in §5.1.3 and
 *   §5.1.4. A cookie set without a Domain attribute is host-only: it matches
 *   only the exact host that set it. A cookie set with Domain=example.com
 *   matches example.com and any *.example.com subdomain. We do NOT implement
 *   the public-suffix check (§5.3 step 5) — a cookie for Domain=com is rejected
 *   only if it is exactly the public suffix with no subdomain parts; we treat
 *   "com" itself as a public suffix so Domain=com is refused, but
 *   Domain=anything.com is accepted. This is a deliberate, documented
 *   simplification.
 *
 * - Path matching follows §5.1.4: a request path P matches a cookie path C if
 *   P === C, or P starts with C and the next char in P is a code point 0x2F
 *   ('/'), or C ends with '/'.
 *
 * - "HttpOnly" cookies are stored and retrieved by getCookieHeader exactly like
 *   any other cookie. HttpOnly only restricts document.cookie access in
 *   browsers; this library is not a browser, so the flag is parsed and stored
 *   but has no effect on retrieval. This matches the behaviour of most
 *   non-browser HTTP clients.
 *
 * - Expiry uses the Max-Age and Expires attributes as specified. Max-Age takes
 *   precedence over Expires when both are present (§5.2 step 3). A cookie with
 *   neither is a session cookie: it persists until removeSession() is called.
 *
 * - The "same-site" attribute is parsed and stored but has no effect on
 *   retrieval, because same-site enforcement requires request context this
 *   library deliberately does not model.
 */

/**
 * Parse a single Set-Cookie value into a cookie record, or null if the
 * cookie is malformed to the point it must be dropped.
 *
 * @param {string} headerValue - the raw value of one Set-Cookie header.
 * @param {string} requestHost - the host of the URL that set the cookie,
 *   lowercased, no port. Used for the default-domain fallback when the
 *   cookie carries no Domain attribute.
 * @param {number} nowMs - current time in milliseconds since epoch.
 * @returns {object|null} a cookie record, or null.
 */
function parseSetCookie(headerValue, requestHost, nowMs) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) {
    return null;
  }

  // Split attributes on the first ';' for the name=value pair, then the rest.
  const firstSemicolon = headerValue.indexOf(';');
  const nameValuePart =
    firstSemicolon === -1 ? headerValue : headerValue.slice(0, firstSemicolon);
  const attrsPart =
    firstSemicolon === -1 ? '' : headerValue.slice(firstSemicolon + 1);

  const eq = nameValuePart.indexOf('=');
  if (eq === -1) {
    // No '=' in the name-value pair: the cookie is malformed and must be
    // dropped per the lenient parsing guidance in §5.2 step 1.
    return null;
  }

  const name = nameValuePart.slice(0, eq).trim();
  const value = nameValuePart.slice(eq + 1).trim();
  if (name === '') {
    // Empty name is not a valid cookie. We do not implement the
    // "cookie with no name but a value" special case from §5.2 step 6 of
    // RFC 6265bis; it is not in RFC 6265 itself.
    return null;
  }

  const cookie = {
    name,
    value,
    domain: requestHost,
    hostOnly: true,
    path: '/',
    expires: null, // null => session cookie; number => expiry in ms
    httpOnly: false,
    secure: false,
    sameSite: null,
  };

  // Walk attributes. Each is "name" or "name=value" separated by ';'.
  const attrs = attrsPart.length === 0 ? [] : attrsPart.split(';');
  for (let i = 0; i < attrs.length; i++) {
    const attr = attrs[i].trim();
    if (attr === '') {
      continue;
    }
    const colon = attr.indexOf('=');
    const aname =
      colon === -1 ? attr : attr.slice(0, colon).trim();
    const avalue = colon === -1 ? '' : attr.slice(colon + 1).trim();
    const lname = aname.toLowerCase();

    if (lname === 'expires') {
      const t = Date.parse(avalue);
      if (!Number.isNaN(t)) {
        // If we see Expires and have not yet seen Max-Age, record it.
        // Max-Age, if it appears later, will overwrite via the expires field.
        if (cookie.expires === null) {
          cookie.expires = t;
        } else {
          // Max-Age already set; Expires is ignored per §5.2 step 3.
        }
      }
      // Invalid Expires dates are ignored per §5.2 step 2 ("ignore the
      // cookie-av entirely").
    } else if (lname === 'max-age') {
      const seconds = Number(avalue);
      if (Number.isFinite(seconds)) {
        // Max-Age <= 0 => expired immediately. We represent that as a
        // past timestamp so the normal expiry check discards it.
        cookie.expires = nowMs + seconds * 1000;
      }
    } else if (lname === 'domain') {
      let d = avalue.toLowerCase().trim();
      if (d.startsWith('.')) {
        // Leading dot is cosmetic in modern cookie handling; strip it so
        // domain comparisons are simple.
        d = d.slice(1);
      }
      if (d !== '') {
        cookie.domain = d;
        cookie.hostOnly = false;
      }
    } else if (lname === 'path') {
      if (avalue.startsWith('/')) {
        cookie.path = avalue;
      }
      // A path not starting with '/' is ignored; default '/' stays.
    } else if (lname === 'secure') {
      cookie.secure = true;
    } else if (lname === 'httponly') {
      cookie.httpOnly = true;
    } else if (lname === 'samesite') {
      const v = avalue.toLowerCase();
      if (v === 'strict' || v === 'lax' || v === 'none') {
        cookie.sameSite = v;
      }
    }
    // Unknown attributes are ignored per §5.2.
  }

  return cookie;
}

/**
 * Return true if `requestPath` path-matches `cookiePath` per §5.1.4.
 */
function pathMatches(cookiePath, requestPath) {
  if (cookiePath === requestPath) {
    return true;
  }
  if (requestPath.startsWith(cookiePath)) {
    // The cookie path is a prefix; the next char must be '/' OR the cookie
    // path must itself end with '/'.
    if (cookiePath.endsWith('/')) {
      return true;
    }
    if (requestPath.charCodeAt(cookiePath.length) === 0x2f /* '/' */) {
      return true;
    }
  }
  return false;
}

/**
 * Return true if `requestHost` domain-matches `cookieDomain` per §5.1.3.
 * `requestHost` is the full request hostname, lowercased.
 * `cookieDomain` is the cookie's domain, lowercased, no leading dot.
 */
function domainMatches(cookieDomain, requestHost) {
  if (requestHost === cookieDomain) {
    return true;
  }
  // requestHost must be a subdomain: "x." + cookieDomain, and cookieDomain
  // must contain at least one dot (so we don't match "com" against "acom").
  if (!cookieDomain.includes('.')) {
    return false;
  }
  if (requestHost.endsWith('.' + cookieDomain)) {
    // The char before the matched suffix boundary must be the start of a
    // label, which is guaranteed by the '.' we just matched.
    return true;
  }
  return false;
}

/**
 * Default path computation per §5.1.4 of RFC 6265. Given the request URI's
 * path, return the default path for a cookie set without a Path attribute.
 */
function defaultPath(uriPath) {
  // §5.1.4: if the uri-path is empty or does not start with '/', return '/'.
  if (typeof uriPath !== 'string' || uriPath.length === 0 || uriPath[0] !== '/') {
    return '/';
  }
  // Strip the last segment (everything from the last '/' onward, exclusive).
  const lastSlash = uriPath.lastIndexOf('/');
  if (lastSlash === 0) {
    // Only the leading '/'; default path is '/'.
    return '/';
  }
  return uriPath.slice(0, lastSlash);
}

/**
 * A minimal URL parser sufficient for http/https cookie scoping. We avoid the
 * global URL constructor so this library works in any JS environment without
 * depending on WHATWG URL semantics that vary between runtimes.
 *
 * @param {string} urlStr
 * @returns {{scheme:string, host:string, port:string, path:string}|null}
 */
function parseUrl(urlStr) {
  if (typeof urlStr !== 'string' || urlStr.length === 0) {
    return null;
  }
  const schemeMatch = urlStr.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/);
  if (!schemeMatch) {
    return null;
  }
  const scheme = schemeMatch[1].toLowerCase();
  let rest = schemeMatch[2];
  // Find the end of authority: first '/', '?', or '#'.
  let authorityEnd = rest.length;
  for (let i = 0; i < rest.length; i++) {
    const c = rest.charCodeAt(i);
    if (c === 0x2f /* '/' */ || c === 0x3f /* '?' */ || c === 0x23 /* '#' */) {
      authorityEnd = i;
      break;
    }
  }
  const authority = rest.slice(0, authorityEnd);
  rest = rest.slice(authorityEnd);

  // Split host and port. IPv6 is not handled; this library scopes cookies to
  // domain names only, and an IP-literal host will simply produce no matches
  // for Domain attributes (which always look like domain names).
  const portColon = authority.lastIndexOf(':');
  let host = authority;
  let port = '';
  if (portColon !== -1) {
    host = authority.slice(0, portColon);
    port = authority.slice(portColon + 1);
  }
  host = host.toLowerCase();

  // Path is everything from the first '/' to the start of query/hash. If the
  // string starts with '?' or '#', the path is empty — represent as '/'.
  let pathEnd = rest.length;
  const q = rest.indexOf('?');
  const h = rest.indexOf('#');
  if (q !== -1) pathEnd = Math.min(pathEnd, q);
  if (h !== -1) pathEnd = Math.min(pathEnd, h);
  let path = rest.slice(0, pathEnd);
  if (path === '') {
    path = '/';
  }
  return { scheme, host, port, path };
}

/**
 * A cookie jar implementing the RFC 6265 store model.
 */
class CookieJar {
  /**
   * @param {object} [options]
   * @param {() => number} [options.now] - clock returning ms since epoch.
   *   Defaults to Date.now. Inject a fake in tests; never assert on real time.
   */
  constructor(options) {
    const opts = options || {};
    /** @type {() => number} */
    this._now = typeof opts.now === 'function' ? opts.now : Date.now;
    /** @type {Map<string, object>} key -> cookie record */
    this._store = new Map();
  }

  /**
   * Build the storage key for a cookie. Two cookies with the same name,
   * domain, and path are the same cookie per §5.3 step 11.
   */
  _key(cookie) {
    return cookie.name + ';' + cookie.domain + ';' + cookie.path;
  }

  /**
   * Drop expired cookies. Called on every mutation and every retrieval so
   * the store never returns stale cookies even if the clock advanced.
   */
  _gc() {
    const now = this._now();
    for (const [key, cookie] of this._store) {
      if (cookie.expires !== null && cookie.expires <= now) {
        this._store.delete(key);
      }
    }
  }

  /**
   * Record a Set-Cookie header value in the context of the URL that issued it.
   *
   * @param {string} url - the URL of the response carrying this Set-Cookie.
   * @param {string} setCookieValue - one Set-Cookie header's value.
   * @returns {boolean} true if the cookie was stored, false if it was rejected.
   */
  storeFromUrl(url, setCookieValue) {
    this._gc();
    const parsed = parseUrl(url);
    if (parsed === null) {
      return false;
    }
    const requestHost = parsed.host;
    const cookie = parseSetCookie(setCookieValue, requestHost, this._now());
    if (cookie === null) {
      return false;
    }

    // Domain acceptance per §5.3 step 6: if the cookie has a Domain attribute,
    // the request host must domain-match it. Otherwise we fall back to the
    // request host (host-only).
    if (!cookie.hostOnly) {
      if (!domainMatches(cookie.domain, requestHost)) {
        return false;
      }
      // Reject Domain attributes that equal a bare public suffix. We only
      // recognise "com", "org", "net", "edu", "gov", "io" as public suffixes
      // for this check — a deliberately small, documented list. Anything
      // else is treated as a registrable domain.
      const suffixes = new Set(['com', 'org', 'net', 'edu', 'gov', 'io']);
      if (suffixes.has(cookie.domain)) {
        return false;
      }
    }

    // Default path: if no Path attribute was given, the cookie's path is the
    // default path of the request URI. We detect "no Path" by checking
    // whether the parser left path as '/' while the request path differs.
    // That heuristic is fragile, so instead we re-scan attributes here only
    // when needed. Simpler: always set cookie.path from defaultPath when no
    // Path attribute was present. We re-parse to know that.
    //
    // To keep the code honest and avoid a second scan, parseSetCookie already
    // left cookie.path as '/' when no Path attribute was present. We now
    // overwrite '/' with the computed default path UNLESS a Path attribute
    // explicitly set it. Distinguish by re-checking the raw header.
    //
    // (We do this check here, once, rather than threading a flag through the
    // parser, so the parser stays a pure function of the header string.)
    const hadPathAttr = /;\s*path\s*=/i.test(';' + setCookieValue.split(';').slice(1).join(';'));
    if (!hadPathAttr) {
      cookie.path = defaultPath(parsed.path);
    }

    // If the cookie is already expired at store time, treat as a deletion
    // per §5.3 step 11 (overwrite-or-remove). We simply do not store it.
    if (cookie.expires !== null && cookie.expires <= this._now()) {
      this._store.delete(this._key(cookie));
      return false;
    }

    this._store.set(this._key(cookie), cookie);
    return true;
  }

  /**
   * Compute the Cookie header value for a request to `url`.
   *
   * Cookies are ordered so that longer-path cookies come first, then by
   * creation order, per §5.4 step 2. We approximate creation order by the
   * insertion order of the Map (which is insertion-ordered in ES2015+).
   *
   * @param {string} url
   * @returns {string} the Cookie header value, or '' if no cookies apply.
   */
  getCookieHeader(url) {
    this._gc();
    const parsed = parseUrl(url);
    if (parsed === null) {
      return '';
    }
    const requestHost = parsed.host;
    const requestPath = parsed.path;
    const matched = [];
    for (const cookie of this._store.values()) {
      if (cookie.secure && parsed.scheme !== 'https' && parsed.scheme !== 'wss') {
 // Secure cookies only go over secure schemes.
 continue;
      }
      if (cookie.hostOnly) {
        if (requestHost !== cookie.domain) {
          continue;
        }
      } else {
        if (!domainMatches(cookie.domain, requestHost)) {
          continue;
        }
      }
      if (!pathMatches(cookie.path, requestPath)) {
        continue;
      }
      matched.push(cookie);
    }
    matched.sort((a, b) => {
      // Longer path first. Tie-break: keep stable order (a before b).
      if (a.path.length > b.path.length) return -1;
      if (a.path.length < b.path.length) return 1;
      return 0;
    });
    if (matched.length === 0) {
      return '';
    }
    return matched.map((c) => c.name + '=' + c.value).join('; ');
  }

  /**
   * Remove all cookies whose key matches `name`. If `options.url` is given,
   * only cookies scoped to that URL's host and path are removed.
   *
   * @param {string} name
   * @param {object} [options]
   * @param {string} [options.url]
   * @returns {number} count of cookies removed.
   */
  removeByName(name, options) {
    this._gc();
    const opts = options || {};
    let removed = 0;
    if (typeof opts.url === 'string') {
      const parsed = parseUrl(opts.url);
      if (parsed === null) {
        return 0;
      }
      const requestHost = parsed.host;
      const requestPath = parsed.path;
      for (const [key, cookie] of [...this._store.entries()]) {
        if (cookie.name !== name) continue;
        const hostOk = cookie.hostOnly
          ? cookie.domain === requestHost
          : domainMatches(cookie.domain, requestHost);
        const pathOk = pathMatches(cookie.path, requestPath);
        if (hostOk && pathOk) {
          this._store.delete(key);
          removed++;
        }
      }
    } else {
      for (const [key, cookie] of [...this._store.entries()]) {
        if (cookie.name === name) {
          this._store.delete(key);
          removed++;
        }
      }
    }
    return removed;
  }

  /**
   * Remove every session cookie (those without an Expires/Max-Age). Useful
   * when simulating the end of a browsing session.
   *
   * @returns {number} count of cookies removed.
   */
  removeSession() {
    let removed = 0;
    for (const [key, cookie] of [...this._store.entries()]) {
      if (cookie.expires === null) {
        this._store.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Remove all cookies, session and persistent.
   */
  clear() {
    this._store.clear();
  }

  /**
   * Return the number of stored cookies (including expired ones not yet GC'd).
   */
  size() {
    return this._store.size;
  }
}

export { CookieJar, parseSetCookie, parseUrl, pathMatches, domainMatches, defaultPath };
