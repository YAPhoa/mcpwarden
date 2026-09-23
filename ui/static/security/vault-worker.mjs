import {VaultSession} from './vault-core.mjs';

function argon2id({password, salt}) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./argon2-worker.js', import.meta.url));
    const fail = () => { worker.terminate(); clearTimeout(timer); reject(new Error('Vault operation failed')); };
    const timer = setTimeout(fail, 60000);
    worker.onerror = event => { event.preventDefault(); fail(); };
    worker.onmessageerror = fail;
    worker.onmessage = ({data}) => {
      worker.terminate(); clearTimeout(timer);
      if (data?.output instanceof Uint8Array && data.output.length === 32) resolve(data.output);
      else reject(new Error('Vault operation failed'));
    };
    // Transfer copies; VaultSession clears its originals in finally.
    const p = password.slice(), s = salt.slice();
    worker.postMessage({password:p,salt:s}, [p.buffer,s.buffer]);
  });
}
const vault = new VaultSession(argon2id);
const operations = new Set(['setup','unlockPassphrase','unlockRecovery','createCredential','releaseCredential','changePassphrase']);
let busy = false;
self.onmessage = async ({data}) => {
  const id = data?.id;
  if (!Number.isSafeInteger(id) || id <= 0) return;
  if (busy || !operations.has(data.operation)) { self.postMessage({id,error:'Vault operation failed'}); return; }
  busy = true;
  try {
    const result = await vault[data.operation](data.input);
    self.postMessage({id,result}, result instanceof Uint8Array ? [result.buffer] : []);
  } catch { self.postMessage({id,error:'Vault operation failed'}); }
  finally { busy = false; }
};
