// Ciphertext protocol primitives. Used inside a dedicated worker, never storage.
// Secrets are byte buffers where possible; JavaScript/WebCrypto cannot promise
// physical memory erasure. Terminating the worker is the session lock boundary.
const encoder = new TextEncoder();
const ALGORITHM = 'AES-256-GCM';
const INFO = Object.freeze({passphrase: 'mcpwarden/v1/passphrase-root-wrap', recovery: 'mcpwarden/v1/recovery-root-wrap', credential: 'mcpwarden/v1/credential-key-wrap'});
const fail = () => { throw new Error('Vault operation failed'); };
const requireValue = condition => { if (!condition) fail(); };

function unicode(value) {
  requireValue(typeof value === 'string');
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      requireValue(next >= 0xdc00 && next <= 0xdfff);
    } else requireValue(c < 0xdc00 || c > 0xdfff);
  }
  return value;
}
function utf8(value) { return encoder.encode(unicode(value)); }

// JSON.parse alone loses duplicate keys and accepts unpaired surrogates. Scan
// every token first, including escaped property names, with finite size/depth.
export function strictParse(raw, maxBytes = 4096, maxDepth = 8) {
  requireValue(typeof raw === 'string' && raw.length <= maxBytes && utf8(raw).length <= maxBytes);
  let i = 0;
  const space = () => { while (i < raw.length && /[\x20\t\r\n]/.test(raw[i])) i++; };
  const string = () => {
    requireValue(raw[i] === '"');
    const start = i++;
    while (i < raw.length) {
      if (raw[i] === '\\') { i += 2; continue; }
      if (raw[i++] === '"') {
        try { return unicode(JSON.parse(raw.slice(start, i))); } catch { fail(); }
      }
    }
    fail();
  };
  const value = depth => {
    requireValue(depth <= maxDepth); space();
    if (raw[i] === '"') { string(); return; }
    if (raw[i] === '{') {
      i++; space(); const seen = new Set();
      if (raw[i] === '}') { i++; return; }
      while (true) {
        space(); const key = string(); requireValue(!seen.has(key)); seen.add(key);
        space(); requireValue(raw[i++] === ':'); value(depth + 1); space();
        const end = raw[i++]; if (end === '}') return; requireValue(end === ',');
      }
    }
    if (raw[i] === '[') {
      i++; space(); if (raw[i] === ']') { i++; return; }
      while (true) { value(depth + 1); space(); const end = raw[i++]; if (end === ']') return; requireValue(end === ','); }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(raw.slice(i));
    requireValue(token); i += token[0].length;
    if (/^[-0-9]/.test(token[0])) requireValue(Number.isFinite(Number(token[0])));
  };
  try { value(0); space(); requireValue(i === raw.length); return JSON.parse(raw); } catch { fail(); }
}

function exact(object, keys) {
  requireValue(object && typeof object === 'object' && !Array.isArray(object));
  const actual = Object.keys(object).sort(), expected = [...keys].sort();
  requireValue(actual.length === expected.length && actual.every((key, i) => key === expected[i]));
}
function canonical(object) {
  // Headers contain strings, bounded fixed integers, and a validated KDF object.
  // ECMAScript number/string encoding and UTF-16 key ordering implement JCS here.
  if (object && typeof object === 'object') return '{' + Object.keys(object).sort().map(key => JSON.stringify(key) + ':' + canonical(object[key])).join(',') + '}';
  return JSON.stringify(object);
}
function b64(bytes) {
  let text = ''; for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function decode(text, min, max = min) {
  requireValue(typeof text === 'string' && /^[A-Za-z0-9_-]+$/.test(text) && text.length >= Math.ceil(min * 4 / 3) && text.length <= Math.ceil(max * 4 / 3));
  let bytes;
  try { bytes = Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)); } catch { fail(); }
  requireValue(bytes.length >= min && bytes.length <= max && b64(bytes) === text);
  return bytes;
}
const random = n => crypto.getRandomValues(new Uint8Array(n));
function version(v) { requireValue(typeof v === 'string' && /^[1-9][0-9]{0,18}$/.test(v) && BigInt(v) <= 9223372036854775807n); }
function id(v) { requireValue(typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v)); }
function owner(v) { const bytes = utf8(v); requireValue(bytes.length > 0 && bytes.length <= 512); }
function rootIdentity(c) { owner(c.owner_id); id(c.root_id); version(c.root_version); }
function rootContext(c) {
  exact(c, ['owner_id','root_id','root_version','wrapper_id','method']); rootIdentity(c); id(c.wrapper_id);
  requireValue(c.method === 'passphrase' || c.method === 'recovery');
}
function credentialContext(c) {
  exact(c, ['owner_id','root_id','root_version','connector_id','credential_id','epoch']); rootIdentity(c); id(c.connector_id); id(c.credential_id); version(c.epoch);
}
function expectedFields(object, header) { for (const [key, value] of Object.entries(header)) requireValue(object[key] === value); }
function passKDF(salt) { return {suite:'ARGON2ID-HKDF-SHA256',argon_version:19,memory_kib:65536,iterations:3,parallelism:4,salt,output_bytes:32,hkdf_info:INFO.passphrase}; }
function recoveryKDF() { return {suite:'HKDF-SHA256',output_bytes:32,hkdf_info:INFO.recovery}; }
function validateKDF(k, method) {
  const fixed = method === 'passphrase' ? passKDF(k?.salt) : recoveryKDF();
  exact(k, Object.keys(fixed)); expectedFields(k, fixed);
  if (method === 'passphrase') decode(k.salt, 16);
}
function rootHeader(c, kdf) { return {format:'mcpwarden.root-wrap.v1',algorithm:ALGORITHM,purpose:'vault-root',...c,kdf}; }
function credentialHeader(c) { return {format:'mcpwarden.credential-wrap.v1',algorithm:ALGORITHM,purpose:'credential-key',...c}; }
function envelopeHeader(c, revision, digest) {
  version(revision); decode(digest, 32);
  return {format:'mcpwarden.secret.v1',algorithm:ALGORITHM,purpose:'upstream-credential',owner_id:c.owner_id,connector_id:c.connector_id,credential_id:c.credential_id,epoch:c.epoch,revision,destination_profile_sha256:digest};
}
function parseEnvelope(raw, header, min = 48, max = min) {
  const w = strictParse(raw, max === 48 ? 4096 : 98304);
  exact(w, [...Object.keys(header), 'nonce', 'ciphertext']); expectedFields(w, header);
  decode(w.nonce, 12); decode(w.ciphertext, min, max); return w;
}
function parseRoot(raw, c) {
  rootContext(c); const w = strictParse(raw); validateKDF(w.kdf, c.method);
  const header = rootHeader(c, w.kdf);
  exact(w, [...Object.keys(header), 'nonce', 'ciphertext']);
  expectedFields(w, {...header, kdf:w.kdf}); decode(w.nonce, 12); decode(w.ciphertext, 48);
  return {w, header};
}
async function hkdf(input, info) {
  const key = await crypto.subtle.importKey('raw', input, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:utf8(info)}, key, {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
}
async function aesKey(raw) { return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt','decrypt']); }
async function seal(key, header, plain) {
  const nonce = random(12);
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:utf8(canonical(header)),tagLength:128}, key, plain);
  return {...header, nonce:b64(nonce), ciphertext:b64(new Uint8Array(ciphertext))};
}
async function open(key, header, w) {
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(w.nonce,12),additionalData:utf8(canonical(header)),tagLength:128}, key, decode(w.ciphertext, 17, 65552)));
}
function bundle(raw) {
  const b = strictParse(raw, 65536, 5); exact(b, ['kind','headers']);
  requireValue(b.kind === 'header_bundle' && Array.isArray(b.headers) && b.headers.length > 0 && b.headers.length <= 32);
  const seen = new Set();
  for (const h of b.headers) {
    exact(h, ['name','value']); requireValue(typeof h.name === 'string' && /^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(h.name));
    const name = h.name.toLowerCase(); requireValue(!seen.has(name)); seen.add(name);
    unicode(h.value); requireValue(utf8(h.value).length > 0 && utf8(h.value).length <= 16384 && h.value.trim() === h.value && !/[\x00-\x1f\x7f]/.test(h.value));
  }
  return utf8(raw);
}

export class VaultSession {
  #argon; #root = null; #identity = null; #generation = 0; #busy = false;
  constructor(argon2id) { requireValue(typeof argon2id === 'function'); this.#argon = argon2id; }
  lock() { this.#generation++; this.#root?.fill(0); this.#root = null; this.#identity = null; }
  async #operation(fn) {
    requireValue(!this.#busy); this.#busy = true; const generation = this.#generation;
    const current = () => requireValue(generation === this.#generation);
    try { const result = await fn(current); current(); return result; } catch { fail(); } finally { this.#busy = false; }
  }
  #check(c) { credentialContext(c); requireValue(this.#root && this.#identity); expectedFields(c, this.#identity); }
  async #passKey(passphrase, kdf) {
    validateKDF(kdf, 'passphrase'); const password = utf8(passphrase), salt = decode(kdf.salt, 16); let output;
    try {
      requireValue(password.length >= 1 && password.length <= 1024);
      output = await this.#argon({password, salt}); requireValue(output instanceof Uint8Array && output.length === 32);
      return await hkdf(output, INFO.passphrase);
    } finally { password.fill(0); salt.fill(0); output?.fill(0); }
  }
  async setup({owner_id, passphrase}) {
    return this.#operation(async current => {
      requireValue(!this.#root); owner(owner_id);
      const identity = {owner_id,root_id:crypto.randomUUID(),root_version:'1'}, root = random(32), recovery = random(32);
      try {
        const p = rootHeader({...identity,wrapper_id:crypto.randomUUID(),method:'passphrase'}, passKDF(b64(random(16))));
        const r = rootHeader({...identity,wrapper_id:crypto.randomUUID(),method:'recovery'}, recoveryKDF());
        const pass = await seal(await this.#passKey(passphrase, p.kdf), p, root);
        current();
        const rec = await seal(await hkdf(recovery, INFO.recovery), r, root);
        current(); this.#root = root.slice(); this.#identity = identity;
        return {...identity,wrapper_revision:'1',passphrase:pass,recovery:rec,recovery_key:b64(recovery)};
      } finally { root.fill(0); recovery.fill(0); }
    });
  }
  async #unlock({context, wrapper, passphrase, recovery_key}, method) {
    return this.#operation(async current => {
      requireValue(!this.#root && context.method === method);
      const {w, header} = parseRoot(wrapper, context); let input, root;
      try {
        let key;
        if (method === 'passphrase') key = await this.#passKey(passphrase, w.kdf);
        else { input = decode(recovery_key, 32); key = await hkdf(input, INFO.recovery); }
        current(); root = await open(key, header, w); requireValue(root.length === 32); current();
        this.#root = root.slice(); this.#identity = {owner_id:context.owner_id,root_id:context.root_id,root_version:context.root_version};
        return {unlocked:true};
      } finally { input?.fill(0); root?.fill(0); }
    });
  }
  unlockPassphrase(input) { return this.#unlock(input, 'passphrase'); }
  unlockRecovery(input) { return this.#unlock(input, 'recovery'); }
  async createCredential({context, revision, destination_profile_sha256, bundle:raw}) {
    return this.#operation(async current => {
      this.#check(context); const header = envelopeHeader(context, revision, destination_profile_sha256);
      const plain = bundle(raw), key = random(32), root = this.#root.slice();
      try {
        const wrapped_key = await seal(await hkdf(root, INFO.credential), credentialHeader(context), key); current();
        const envelope = await seal(await aesKey(key), header, plain); current();
        return {wrapped_key, envelope};
      } finally { key.fill(0); plain.fill(0); root.fill(0); }
    });
  }
  async releaseCredential({context, revision, destination_profile_sha256, wrapped_key, envelope}) {
    return this.#operation(async current => {
      this.#check(context); const wh = credentialHeader(context), eh = envelopeHeader(context, revision, destination_profile_sha256);
      const w = parseEnvelope(wrapped_key, wh), e = parseEnvelope(envelope, eh, 17, 65552), root = this.#root.slice(); let key, plain;
      try {
        key = await open(await hkdf(root, INFO.credential), wh, w); requireValue(key.length === 32); current();
        plain = await open(await aesKey(key), eh, e); current();
        const decoded = new TextDecoder('utf-8', {fatal:true}).decode(plain), checked = bundle(decoded); checked.fill(0);
        return key.slice(); // Only this selected CEK can leave the vault worker.
      } finally { key?.fill(0); plain?.fill(0); root.fill(0); }
    });
  }
  async changePassphrase({passphrase}) {
    return this.#operation(async current => {
      requireValue(this.#root); const root = this.#root.slice();
      try {
        const header = rootHeader({...this.#identity,wrapper_id:crypto.randomUUID(),method:'passphrase'}, passKDF(b64(random(16))));
        const w = await seal(await this.#passKey(passphrase, header.kdf), header, root); current(); return w;
      } finally { root.fill(0); }
    });
  }
}
