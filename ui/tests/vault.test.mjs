import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto, createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {VaultSession, strictParse} from '../static/security/vault-core.mjs';

globalThis.crypto ??= webcrypto;
const require = createRequire(import.meta.url);
const {argon2id} = require('../static/vendor/hash-wasm-4.12.0/argon2.umd.min.js');
const derive = ({password,salt}) => argon2id({password,salt,memorySize:65536,iterations:3,parallelism:4,hashLength:32,outputType:'binary'});
const fixture = JSON.parse(readFileSync(new URL('./fixtures/argon2id.json', import.meta.url)));
const context = wrapper => Object.fromEntries(['owner_id','root_id','root_version','wrapper_id','method'].map(key => [key,wrapper[key]]));
const credContext = root => ({owner_id:root.owner_id,root_id:root.root_id,root_version:root.root_version,connector_id:crypto.randomUUID(),credential_id:crypto.randomUUID(),epoch:'1'});
const digest = Buffer.alloc(32, 7).toString('base64url');
const bundle = JSON.stringify({kind:'header_bundle',headers:[{name:'Authorization',value:'Bearer SYNTHETIC_TEST'}]});
const release = (c, sealed) => ({context:c,revision:'1',destination_profile_sha256:digest,wrapped_key:JSON.stringify(sealed.wrapped_key),envelope:JSON.stringify(sealed.envelope)});
const rejected = promise => assert.rejects(promise, {message:'Vault operation failed'});

test('pinned Argon2 asset integrity and independent UTF-8 vectors', async () => {
  const directory = new URL('../static/vendor/hash-wasm-4.12.0/', import.meta.url);
  const provenance = JSON.parse(readFileSync(new URL('provenance.json', directory)));
  for (const [file, hash] of Object.entries(provenance.files)) assert.equal(createHash('sha256').update(readFileSync(new URL(file, directory))).digest('hex'), hash);
  for (const vector of fixture.vectors) {
    const result = await derive({password:new TextEncoder().encode(vector.passphrase),salt:Buffer.from(vector.salt_hex,'hex')});
    assert.equal(Buffer.from(result).toString('hex'), vector.argon2id_hex); result.fill(0);
  }
});

test('strict JSON rejects escaped duplicate keys, invalid Unicode and unbounded input', () => {
  for (const raw of ['{"a":1,"\\u0061":2}','{"nested":{"a":1,"a":2}}','"\\ud800"','"\\udc00"','"\ud800"','[1,]','{"a":1,}','{}{}','[1e999]',' '.repeat(4097), '['.repeat(10)+'0'+']'.repeat(10)]) {
    assert.throws(() => strictParse(raw), {message:'Vault operation failed'});
  }
  assert.deepEqual(strictParse('{"a":[true,null,"é🔐",1.2e1]}'), {a:[true,null,'é🔐',12]});
});

test('setup, passphrase unlock, selected CEK release, rewrap and recovery preserve bindings', async () => {
  const vault = new VaultSession(derive);
  const passphrase = fixture.vectors[1].passphrase;
  const root = await vault.setup({owner_id:'account:alice-🔐',passphrase});
  assert.equal(Buffer.from(root.recovery_key,'base64url').length,32);
  const c = credContext(root), sealed = await vault.createCredential({context:c,revision:'1',destination_profile_sha256:digest,bundle});
  const second = await vault.createCredential({context:{...c,credential_id:crypto.randomUUID()},revision:'1',destination_profile_sha256:digest,bundle});
  assert.notEqual(sealed.wrapped_key.nonce, second.wrapped_key.nonce);
  const key = await vault.releaseCredential(release(c,sealed)); assert.equal(key.length,32);
  const {nonce,ciphertext,...header} = sealed.envelope;
  const aad = new TextEncoder().encode(JSON.stringify(header, Object.keys(header).sort()));
  const cryptoKey = await crypto.subtle.importKey('raw',key,'AES-GCM',false,['decrypt']);
  const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(nonce,'base64url'),additionalData:aad,tagLength:128},cryptoKey,Buffer.from(ciphertext,'base64url'));
  assert.equal(new TextDecoder().decode(plain), bundle);
  const changed = await vault.changePassphrase({passphrase:'NEW SYNTHETIC PASSPHRASE'});
  assert.notEqual(changed.wrapper_id,root.passphrase.wrapper_id); assert.notEqual(changed.kdf.salt,root.passphrase.kdf.salt);
  vault.lock(); await rejected(vault.releaseCredential(release(c,sealed)));
  await rejected(vault.unlockPassphrase({context:context(changed),wrapper:JSON.stringify(changed),passphrase}));
  await vault.unlockPassphrase({context:context(changed),wrapper:JSON.stringify(changed),passphrase:'NEW SYNTHETIC PASSPHRASE'});
  assert.deepEqual(await vault.releaseCredential(release(c,sealed)),key);
  vault.lock(); await rejected(vault.unlockPassphrase({context:context(root.passphrase),wrapper:JSON.stringify(root.passphrase),passphrase:passphrase.trim()}));
  await vault.unlockPassphrase({context:context(root.passphrase),wrapper:JSON.stringify(root.passphrase),passphrase});
  assert.deepEqual(await vault.releaseCredential(release(c,sealed)),key);
  vault.lock(); await rejected(vault.unlockRecovery({context:context(root.recovery),wrapper:JSON.stringify(root.recovery),recovery_key:Buffer.alloc(32).toString('base64url')}));
  await vault.unlockRecovery({context:context(root.recovery),wrapper:JSON.stringify(root.recovery),recovery_key:root.recovery_key});
  assert.deepEqual(await vault.releaseCredential(release(c,sealed)),key); key.fill(0); vault.lock();
});

test('wrapper tampering and unsupported KDFs fail before expensive work', async () => {
  const v = new VaultSession(derive), root = await v.setup({owner_id:'alice',passphrase:'PUBLIC TEST'}); v.lock();
  let calls = 0; const guarded = new VaultSession(async input => {calls++;return derive(input);});
  for (const change of [w => w.kdf.memory_kib=8,w => w.kdf.iterations=1,w => w.kdf.parallelism=100,w => w.kdf.argon_version=16,w => w.kdf.output_bytes=64,w => w.kdf.salt+='=',w => w.kdf.hkdf_info='other',w => w.kdf.extra=true,w => w.extra=true,w => w.nonce='A',w => w.ciphertext='AA',w => delete w.purpose,w => w.owner_id='bob']) {
    const w=structuredClone(root.passphrase); change(w);
    await rejected(guarded.unlockPassphrase({context:context(root.passphrase),wrapper:JSON.stringify(w),passphrase:'PUBLIC TEST'}));
  }
  assert.equal(calls,0);
  // Plausible changed KDF salt passes bounds, then fails the authenticated header.
  const w=structuredClone(root.passphrase);w.kdf.salt=Buffer.alloc(16).toString('base64url');
  await rejected(guarded.unlockPassphrase({context:context(w),wrapper:JSON.stringify(w),passphrase:'PUBLIC TEST'})); assert.equal(calls,1);
});

test('credential wrappers and envelopes reject replay across every binding', async () => {
  const v=new VaultSession(derive),root=await v.setup({owner_id:'alice',passphrase:'PUBLIC TEST'}),c=credContext(root);
  const sealed=await v.createCredential({context:c,revision:'1',destination_profile_sha256:digest,bundle});
  for (const field of ['owner_id','root_id','root_version','connector_id','credential_id','epoch']) {
    const bad={...c,[field]:field==='owner_id'?'bob':field.endsWith('id')?crypto.randomUUID():'2'};
    const w={...sealed.wrapped_key,[field]:bad[field]};
    await rejected(v.releaseCredential({...release(bad,sealed),wrapped_key:JSON.stringify(w)}));
  }
  for (const field of ['revision','destination_profile_sha256','nonce','ciphertext']) {
    const e=structuredClone(sealed.envelope);
    if(field==='revision') e[field]='2'; else if(field==='destination_profile_sha256')e[field]=Buffer.alloc(32,8).toString('base64url');
    else {const b=Buffer.from(e[field],'base64url');b[0]^=1;e[field]=b.toString('base64url');}
    await rejected(v.releaseCredential({...release(c,sealed),revision:e.revision,destination_profile_sha256:e.destination_profile_sha256,envelope:JSON.stringify(e)}));
  }
  const duplicate=JSON.stringify(sealed.envelope).replace('{','{"epoch":"1",');
  await rejected(v.releaseCredential({...release(c,sealed),envelope:duplicate}));
  const otherRoot=new VaultSession(derive),other=await otherRoot.setup({owner_id:'alice',passphrase:'PUBLIC TEST'});
  await rejected(otherRoot.releaseCredential({...release({...c,root_id:other.root_id},sealed)}));
  v.lock();otherRoot.lock();
});

test('locking during KDF cannot publish a subsequently completed unlock', async () => {
  let resume;
  const v=new VaultSession(() => new Promise(resolve=>{resume=()=>resolve(new Uint8Array(32));}));
  const pending=v.setup({owner_id:'alice',passphrase:'PUBLIC TEST'});
  v.lock();resume();await rejected(pending);
  await rejected(v.changePassphrase({passphrase:'PUBLIC TEST'}));
  const bad=new VaultSession(derive);
  await rejected(bad.setup({owner_id:'alice',passphrase:'\ud800'}));
});
