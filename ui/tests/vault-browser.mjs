// Run with PLAYWRIGHT_MODULE pointing at an installed Playwright package.
// Uses a loopback-only static fixture; no live account, credential or API calls.
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {resolve, sep} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';

const playwright = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(resolve(process.env.PLAYWRIGHT_MODULE)) : new URL('../node_modules/playwright/index.mjs', import.meta.url));
const root = fileURLToPath(new URL('../static', import.meta.url));
const browserName = process.env.VAULT_BROWSER || 'firefox';
assert(['chromium','firefox','webkit'].includes(browserName), 'Unsupported test browser');
const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'none'";
const server = createServer(async (req,res) => {
  try {
    if (req.url === '/') { res.writeHead(200, {'Content-Type':'text/html','Content-Security-Policy':csp}); res.end('<!doctype html><title>Local synthetic vault test</title>'); return; }
    const path = resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
    if (!path.startsWith(root + sep) || !/\.(js|mjs)$/.test(path)) {res.writeHead(404);res.end();return;}
    const body = await readFile(path);
    res.writeHead(200, {'Content-Type':'application/javascript','Content-Security-Policy':csp,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(body);
  } catch { res.writeHead(404);res.end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await playwright[browserName].launch({headless:true,...(browserName === 'firefox' && process.env.FIREFOX_EXECUTABLE ? {executablePath:process.env.FIREFOX_EXECUTABLE} : {})});
  const page = await browser.newPage(), requests=[], errors=[];
  page.on('request', request => requests.push(request.url()));
  page.on('pageerror', () => errors.push('browser page error'));
  await page.goto(origin);
  const result = await page.evaluate(async () => {
    const {VaultClient} = await import('/security/vault-client.mjs');
    const v=new VaultClient(), start=performance.now();
    const root=await v.setup({owner_id:'synthetic-browser:密碼',passphrase:'  PUBLIC e\u0301 🔐  '});
    const setup_ms=Math.round(performance.now()-start);
    const context={owner_id:root.owner_id,root_id:root.root_id,root_version:root.root_version,connector_id:crypto.randomUUID(),credential_id:crypto.randomUUID(),epoch:'1'};
    const digest=btoa(String.fromCharCode(...new Uint8Array(32))).replace(/=+$/,'');
    const sealed=await v.createCredential({context,revision:'1',destination_profile_sha256:digest,bundle:JSON.stringify({kind:'header_bundle',headers:[{name:'Authorization',value:'Bearer SYNTHETIC_BROWSER_TEST'}]})});
    const input={context,revision:'1',destination_profile_sha256:digest,wrapped_key:JSON.stringify(sealed.wrapped_key),envelope:JSON.stringify(sealed.envelope)};
    const key=await v.releaseCredential(input);const before=Array.from(key);key.fill(0);
    v.lock();let denied=false;try{await v.releaseCredential(input);}catch{denied=true;}
    const ctx=w=>Object.fromEntries(['owner_id','root_id','root_version','wrapper_id','method'].map(k=>[k,w[k]]));
    const startUnlock=performance.now();
    await v.unlockPassphrase({context:ctx(root.passphrase),wrapper:JSON.stringify(root.passphrase),passphrase:'  PUBLIC e\u0301 🔐  '});
    const unlock_ms=Math.round(performance.now()-startUnlock);
    const pass=await v.releaseCredential(input);const passMatches=pass.every((b,i)=>b===before[i]);pass.fill(0);
    v.lock();await v.unlockRecovery({context:ctx(root.recovery),wrapper:JSON.stringify(root.recovery),recovery_key:root.recovery_key});
    const rec=await v.releaseCredential(input);const recoveryMatches=rec.every((b,i)=>b===before[i]);rec.fill(0);before.fill(0);v.lock();
    const pending=v.setup({owner_id:'synthetic-lock',passphrase:'PUBLIC TEST'});v.lock();let cancelled=false;try{await pending;}catch{cancelled=true;}
    const fresh=new VaultClient();let reloadLocked=false;try{await fresh.releaseCredential(input);}catch{reloadLocked=true;}fresh.lock();
    return {setup_ms,unlock_ms,denied,passMatches,recoveryMatches,cancelled,reloadLocked,localStorage:localStorage.length,sessionStorage:sessionStorage.length};
  });
  for (const key of ['denied','passMatches','recoveryMatches','cancelled','reloadLocked']) assert.equal(result[key],true,key);
  assert.equal(result.localStorage,0);assert.equal(result.sessionStorage,0);assert.deepEqual(errors,[]);
  assert(requests.every(url=>url.startsWith(origin+'/')), 'external request');
  assert(requests.some(url=>url.includes('argon2.umd.min.js')), 'pinned Argon2 asset was not loaded');
  console.log(JSON.stringify({engine:browserName,browser:browser.version(),...result,network:'loopback static assets only'}));
} finally { await browser?.close();await new Promise(resolve=>server.close(resolve)); }
