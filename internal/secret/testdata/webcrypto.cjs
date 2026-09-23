// Public synthetic test data only. This is not browser vault lifecycle code.
const { webcrypto } = require('node:crypto');
const fs = require('node:fs');
(async () => {
  const { key, envelope, plaintext } = JSON.parse(fs.readFileSync(0, 'utf8'));
  const header = { ...envelope };
  delete header.nonce;
  delete header.ciphertext;
  // Every header field is a string. JS key sorting is UTF-16 order and
  // JSON.stringify has the RFC 8785 string encoding needed for this profile.
  const aad = Buffer.from(JSON.stringify(Object.fromEntries(Object.keys(header).sort().map(k => [k, header[k]]))));
  const aes = await webcrypto.subtle.importKey('raw', Buffer.from(key, 'hex'), 'AES-GCM', false, ['decrypt', 'encrypt']);
  const decoded = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(envelope.nonce, 'base64url'), additionalData: aad, tagLength: 128 }, aes, Buffer.from(envelope.ciphertext, 'base64url'));
  if (Buffer.from(decoded).toString('utf8') !== plaintext) throw Error('fixture mismatch');
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, aes, Buffer.from(plaintext));
  process.stdout.write(JSON.stringify({ ...header, nonce: Buffer.from(nonce).toString('base64url'), ciphertext: Buffer.from(encrypted).toString('base64url') }));
})().catch(() => { process.stderr.write('WebCrypto fixture failed\n'); process.exitCode = 1; });
