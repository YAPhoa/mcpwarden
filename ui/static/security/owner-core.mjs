// Owner console helpers without DOM access. Nothing here stores data in the
// browser or holds vault material; the vault worker remains the only place a
// root or credential key exists, and a released key only passes through
// activationBody on its way to the explicit activation request.
const encoder = new TextEncoder();

export class OwnerError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
  // No response means the server may or may not have acted.
  get uncertain() { return this.code === 'network' || this.status >= 500; }
}

const messages = {
  network: 'The gateway could not be reached. Nothing new was started by this page; reload to see the current state.',
  discarded: 'This result arrived after the vault was locked or the account changed, so it was discarded.',
  disabled: 'Owner security is not enabled on this gateway.',
  secure_transport_required: 'Owner security needs HTTPS through a trusted proxy. This connection is not trusted.',
  sign_in_required: 'Your session ended. Sign in again.',
  interactive_owner_required: 'Only a signed-in browser session can use this page.',
  origin_forbidden: 'This page’s origin is not allowed to change security settings.',
  csrf_required: 'The security token expired. Reload the page and try again.',
  reauthentication_required: 'Your account password was not accepted.',
  not_found: 'That item no longer exists. Reload to see the current state.',
  denied: 'The gateway refused this action for this caller.',
  stale: 'The request, credential or policy changed or expired. Ask the agent for a new request, or renew.',
  conflict: 'This changed elsewhere. Reload before saving again.',
  invalid: 'The gateway rejected this request as invalid or unsupported.',
  destination_mismatch: 'The connector’s endpoint or header names changed. Reload and try again.',
  activation_failed: 'The gateway could not authenticate this credential with the released key.',
  idempotency_key_required: 'The activation request was malformed. Nothing was started.',
  rate_limited: 'Too many requests. Wait a minute and try again.',
  locked: 'Execution is locked. Start a new access window to continue.',
  unavailable: 'Security storage is unavailable, so execution is locked.',
  too_large: 'The request is too large.',
  json_required: 'The request was malformed.',
  method_not_allowed: 'The gateway does not support this action.',
  discovery_failed: 'The connector could not be reached or did not return a valid tool list. The inspect window has ended; try again.',
};
export function errorMessage(code) { return messages[code] || 'The request could not be completed.'; }

// OwnerClient talks only to owner routes with the browser session cookie. It
// never sets an Authorization header, so an MCP or API key cannot reach these
// routes through it. reset() discards every response still in flight.
export class OwnerClient {
  #fetch; #csrf = ''; #generation = 0;
  constructor(fetcher = (...args) => globalThis.fetch(...args)) { this.#fetch = fetcher; }
  get generation() { return this.#generation; }
  reset() { this.#generation++; this.#csrf = ''; }
  async #send(method, path, {body, idempotencyKey} = {}, generation) {
    const unsafe = method !== 'GET' && method !== 'HEAD';
    const headers = {'Accept': 'application/json', 'X-MCPWarden-Request': 'browser'};
    if (unsafe) headers['X-CSRF-Token'] = this.#csrf;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
    let response;
    try {
      response = await this.#fetch(path, {method, headers, body, credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer'});
    } catch {
      if (generation !== this.#generation) throw new OwnerError(0, 'discarded', errorMessage('discarded'));
      throw new OwnerError(0, 'network', errorMessage('network'));
    }
    if (generation !== this.#generation) throw new OwnerError(0, 'discarded', errorMessage('discarded'));
    let data = null;
    if (response.status !== 204 && /^application\/json\b/.test(response.headers.get('Content-Type') || '')) {
      try { data = await response.json(); } catch { data = null; }
      if (generation !== this.#generation) throw new OwnerError(0, 'discarded', errorMessage('discarded'));
    }
    return {response, data};
  }
  async #token(generation) {
    const {response, data} = await this.#send('GET', '/api/security/csrf', {}, generation);
    if (!response.ok || typeof data?.token !== 'string' || !data.token) throw failure(response, data);
    this.#csrf = data.token;
  }
  async request(method, path, options = {}) {
    const generation = this.#generation, unsafe = method !== 'GET' && method !== 'HEAD';
    for (let attempt = 0; ; attempt++) {
      if (unsafe && !this.#csrf) await this.#token(generation);
      const {response, data} = await this.#send(method, path, options, generation);
      // A 403 for the CSRF token is refused before the handler runs, so one
      // resend with a fresh token cannot repeat an action.
      if (unsafe && attempt === 0 && response.status === 403 && data?.error === 'csrf_required') { this.#csrf = ''; continue; }
      if (!response.ok) throw failure(response, data);
      return {data, serverDate: Date.parse(response.headers.get('Date') || '')};
    }
  }
}
function failure(response, data) {
  // Unregistered owner routes fall through to the gateway's plain 404.
  let code = typeof data?.error === 'string' && data.error in messages ? data.error : '';
  if (!code) code = response.status === 404 && !data ? 'disabled' : response.status === 401 ? 'sign_in_required' : response.status >= 500 ? 'server' : 'invalid';
  return new OwnerError(response.status, code, errorMessage(code));
}

export function b64url(bytes) {
  let text = ''; for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function fromB64url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('invalid base64url');
  const bytes = Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
  if (b64url(bytes) !== text) throw new Error('invalid base64url');
  return bytes;
}

// RFC 8785 for the values hashed here: objects, arrays, strings, booleans,
// null and safe integers. ECMAScript string serialization matches JCS, and
// keys sort by UTF-16 code units.
export function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isSafeInteger(value)) throw new Error('unsupported number'); return JSON.stringify(value); }
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
  throw new Error('unsupported value');
}
export async function sha256(text) { return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text)))); }

// Normalizes the destination exactly as the gateway hashes it: sorted,
// lowercase header names and sorted private prefixes.
export function destinationDigest(d) {
  const normalized = {...d, header_names: [...d.header_names].sort(), private_prefixes: [...(d.private_prefixes || [])].sort()};
  return sha256(jcs(normalized));
}

// Header credentials for an existing personal HTTP connector. The gateway
// accepts only its exact URL and header names; public HTTPS or direct loopback
// HTTP development endpoints are the supported network profiles for now.
export function destinationFor(connection) {
  const kinds = new Set(['bearer', 'api_key', 'headers']);
  if (!connection || !kinds.has(connection.auth_type)) return {reason: 'This connector has no credential headers.'};
  const names = (connection.header_names || []).map(n => String(n).toLowerCase());
  if (!names.length || names.length > 32 || new Set(names).size !== names.length) return {reason: 'This connector has no credential headers.'};
  let url;
  try { url = new URL(connection.url); } catch { return {reason: 'The connector endpoint is not a valid URL.'}; }
  const base = {schema: 'mcpwarden.destination.v1', endpoint: connection.url, header_names: names.sort()};
  if (url.protocol === 'https:') return {destination: {...base, network: 'public', private_prefixes: [], allow_loopback_http: false}};
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (url.protocol === 'http:') {
    if (host === 'localhost') return {destination: {...base, network: 'private', private_prefixes: ['127.0.0.0/8', '::1/128'], allow_loopback_http: true}};
    if (/^127\.\d+\.\d+\.\d+$/.test(host)) return {destination: {...base, network: 'private', private_prefixes: ['127.0.0.0/8'], allow_loopback_http: true}};
    if (host === '::1') return {destination: {...base, network: 'private', private_prefixes: ['::1/128'], allow_loopback_http: true}};
  }
  return {reason: 'Only HTTPS endpoints, or HTTP on this machine for development, are supported.'};
}

// The plaintext bundle the worker encrypts. Values are never trimmed.
export function headerBundle(connection, values) {
  const headers = (connection.header_names || []).map(name => {
    const raw = values[name] ?? '';
    const value = connection.auth_type === 'bearer' && name.toLowerCase() === 'authorization' ? `Bearer ${raw}` : raw;
    return {name, value};
  });
  return JSON.stringify({kind: 'header_bundle', headers});
}
export function headerValueProblem(value) {
  if (!value) return 'Enter a value.';
  if (value.trim() !== value) return 'Remove spaces at the start or end.';
  if (/[\x00-\x1f\x7f]/.test(value)) return 'Remove line breaks and control characters.';
  if (encoder.encode(value).length > 16000) return 'This value is too long.';
  return '';
}

// Recovery keys are shown as Crockford base32 with a 4-character checksum, so
// they survive handwriting and ambiguous letters. The worker still receives
// the exact 32 bytes as base64url.
const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function base32(bytes) {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) { value = value << 8 | byte; bits += 8; while (bits >= 5) { out += alphabet[value >>> bits - 5 & 31]; bits -= 5; } value &= (1 << bits) - 1; }
  if (bits) out += alphabet[value << 5 - bits & 31];
  return out;
}
async function checksum(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return base32(d.slice(0, 3)).slice(0, 4);
}
export async function formatRecoveryKey(encoded) {
  const bytes = fromB64url(encoded);
  if (bytes.length !== 32) throw new Error('invalid recovery key');
  const text = base32(bytes) + await checksum(bytes); bytes.fill(0);
  return text.match(/.{4}/g).join('-');
}
export async function parseRecoveryKey(input) {
  const text = String(input).toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
  if (!/^[0-9A-HJKMNP-TV-Z]{56}$/.test(text)) throw new Error('Enter all 56 characters of the recovery key.');
  let bits = 0, value = 0; const bytes = [];
  for (const c of text.slice(0, 52)) { value = value << 5 | alphabet.indexOf(c); bits += 5; if (bits >= 8) { bytes.push(value >>> bits - 8 & 255); bits -= 8; value &= (1 << bits) - 1; } }
  const key = Uint8Array.from(bytes);
  if (value !== 0 || key.length !== 32 || await checksum(key) !== text.slice(52)) { key.fill(0); throw new Error('This recovery key is incorrect. Check each group and try again.'); }
  const encoded = b64url(key); key.fill(0);
  return encoded;
}

export function passphraseProblem(passphrase, confirm) {
  if ([...passphrase].length < 15) return 'Use at least 15 characters.';
  if (encoder.encode(passphrase).length > 1024) return 'Use no more than 1024 bytes.';
  if (passphrase !== confirm) return 'The passphrases do not match.';
  return '';
}

// Collision-aware public suffix, matching the Access page.
export function publicHandle(publicID, others = []) {
  if (!/^[0-9a-f]{32}$/.test(publicID || '')) return '';
  let length = 4;
  while (length < 32 && others.some(other => other !== publicID && other.endsWith(publicID.slice(-length)))) length += 4;
  return '…' + publicID.slice(-length);
}

export function durationLabel(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s % 60) return `${s} second${s === 1 ? '' : 's'}`;
  const minutes = s / 60;
  return minutes >= 60 && minutes % 60 === 0 ? `${minutes / 60} hour${minutes === 60 ? '' : 's'}` : `${minutes} minute${minutes === 1 ? '' : 's'}`;
}
export function remainingLabel(ms) {
  if (!(ms > 0)) return '0:00';
  const total = Math.ceil(ms / 1000), h = Math.floor(total / 3600), m = Math.floor(total % 3600 / 60), s = total % 60;
  return h ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `${m}:${String(s).padStart(2, '0')}`;
}

// What an owner can do with a request right now. Server state decides; the
// local clock only hides actions whose server deadline has visibly passed.
export function requestPhase(r, now) {
  const expired = Date.parse(r.expires_at) <= now || r.activation_deadline && r.state === 'approved' && Date.parse(r.activation_deadline) <= now;
  if ((r.state === 'pending' || r.state === 'approved') && expired) return {key: 'expired', label: 'Request expired', tone: ''};
  switch (r.state) {
    case 'pending': return {key: 'pending', label: 'Waiting for your review', tone: 'warning'};
    case 'approved': return {key: 'approved', label: 'Approved · not active yet', tone: 'warning'};
    case 'activated': return {key: 'activated', label: 'Access started', tone: 'success'};
    case 'denied': return {key: 'denied', label: 'Denied', tone: ''};
    case 'stale': return {key: 'stale', label: 'No longer valid', tone: ''};
    default: return {key: r.state, label: 'Request expired', tone: ''};
  }
}

// Separate the window's own state from runtime availability and provider
// connectivity, per spec §18.3.
export function windowPhase(l, now, providerHealthy = true) {
  if (l.state === 'revoked') return {key: 'revoked', label: 'Access stopped', tone: 'failure'};
  if (l.state === 'suspended') return {key: 'suspended', label: 'Suspended · start a new access window', tone: 'warning'};
  if (l.state === 'expired' || Date.parse(l.expires_at) <= now) return {key: 'expired', label: 'Access window ended', tone: ''};
  if (!l.runtime_available) return {key: 'suspended', label: 'Suspended · start a new access window', tone: 'warning'};
  if (!providerHealthy) return {key: 'provider', label: 'Access approved · provider unavailable', tone: 'warning'};
  return {key: 'active', label: 'Active', tone: 'success'};
}
// What the owner reviews before a key is released: the caller, the credential
// version, each tool's exact definition and constraints, the duration and the
// call limit. Request IDs, digests and deadlines differ between requests.
export function reviewedScope(r, durationSeconds = r.duration_seconds) {
  const tools = (r.tools || []).map(t => [t.tool_id, t.definition_sha256, t.constraints || []]).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  return JSON.stringify({requester: r.requester?.access_id, credential: [r.credential?.credential_id, r.credential?.connector_id, String(r.credential?.epoch)],
    duration_seconds: durationSeconds, max_calls: r.max_calls ?? null, tools});
}
export function callsLabel(l) {
  const used = Number(l.admitted_calls) || 0;
  const base = l.max_calls == null ? `${used} call${used === 1 ? '' : 's'} · no call limit` : `${used} of ${l.max_calls} calls used`;
  return l.in_flight ? `${base} · ${l.in_flight} in progress` : base;
}

// A connector's credential lives only in the vault; its calls need a window.
export function credentialSaveEffect(replacing) {
  return `${replacing ? 'Replacing starts a new credential version with a new key.' : 'This stores the credential for this connector.'} Saving ends pending requests and all access windows for your account. Tool calls to this connector need an access window.`;
}
