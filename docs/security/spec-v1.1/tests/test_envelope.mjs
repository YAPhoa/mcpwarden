// Synthetic deterministic fixture only. Never reuse its key/nonce in production.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

const path = new URL('../reference/envelope-vector.json', import.meta.url);
const vector = JSON.parse(await readFile(path, 'utf8'));
const hex = value => Buffer.from(value, 'hex');
const keyBytes = hex(vector.key_hex);
const key = await webcrypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
const nonce = hex(vector.nonce_hex);
const aad = Buffer.from(vector.aad_utf8, 'utf8');
const plaintext = Buffer.from(vector.plaintext_utf8, 'utf8');
const ciphertext = hex(vector.ciphertext_and_tag_hex);
const options = (iv = nonce, additionalData = aad) => ({name: 'AES-GCM', iv, additionalData, tagLength: 128});
assert.deepEqual(Buffer.from(await webcrypto.subtle.decrypt(options(), key, ciphertext)), plaintext);
assert.deepEqual(Buffer.from(await webcrypto.subtle.encrypt(options(), key, plaintext)), ciphertext);
// Sufficient ONLY for this fixed string-only ASCII header, not a general JCS implementation.
const header = Object.fromEntries(Object.entries(vector.envelope)
  .filter(([name]) => !['nonce', 'ciphertext'].includes(name)).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
assert.equal(JSON.stringify(header), vector.aad_utf8);
assert.equal(ciphertext.toString('base64url'), vector.envelope.ciphertext);
assert.equal(nonce.toString('base64url'), vector.envelope.nonce);
const changedTag = Buffer.from(ciphertext); changedTag[changedTag.length - 1] ^= 1;
const changedNonce = Buffer.from(nonce); changedNonce[0] ^= 1;
const changedKey = Buffer.from(keyBytes); changedKey[0] ^= 1;
const wrongKey = await webcrypto.subtle.importKey('raw', changedKey, 'AES-GCM', false, ['decrypt']);
const wrongOwner = Buffer.from(vector.aad_utf8.replace('"owner_id":"local"', '"owner_id":"other"'));
for (const [opts, candidateKey, candidateCiphertext] of [
  [options(nonce, wrongOwner), key, ciphertext],
  [options(), key, changedTag],
  [options(changedNonce), key, ciphertext],
  [options(), wrongKey, ciphertext],
]) {
  await assert.rejects(() => webcrypto.subtle.decrypt(opts, candidateKey, candidateCiphertext));
}
console.log('PASS Node WebCrypto: AES-GCM roundtrip, exact encoding, wrong owner/tag/nonce/key rejection');
