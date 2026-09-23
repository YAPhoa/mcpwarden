// One derivation per worker. The parent always terminates this realm afterwards:
// hash-wasm has private WASM memory that its public API does not explicitly wipe.
importScripts('../vendor/hash-wasm-4.12.0/argon2.umd.min.js');
let used = false;
self.onmessage = async ({data}) => {
  if (used) return;
  used = true;
  const password = data?.password, salt = data?.salt;
  let output;
  try {
    if (!(password instanceof Uint8Array) || password.length < 1 || password.length > 1024 || !(salt instanceof Uint8Array) || salt.length !== 16) throw new Error();
    output = await hashwasm.argon2id({password,salt,memorySize:65536,iterations:3,parallelism:4,hashLength:32,outputType:'binary'});
    password.fill(0); salt.fill(0);
    self.postMessage({output}, [output.buffer]);
  } catch {
    password?.fill?.(0); salt?.fill?.(0); output?.fill?.(0);
    self.postMessage({error:'Vault operation failed'});
  } finally { self.close(); }
};
