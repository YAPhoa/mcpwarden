// End-to-end owner console flows against a real gateway, an isolated
// PostgreSQL database and a synthetic upstream. Run with
// MCPWARDEN_TEST_DATABASE_URL pointing at the local test fixture and
// OWNER_BROWSER set to chromium, firefox or webkit. All data is synthetic.
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {startFixture, proxyErrors} from './owner-fixture.mjs';

const playwright = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(resolve(process.env.PLAYWRIGHT_MODULE)) : new URL('../node_modules/playwright/index.mjs', import.meta.url));
const browserName = process.env.OWNER_BROWSER || 'chromium';
assert(['chromium', 'firefox', 'webkit'].includes(browserName), 'Unsupported test browser');

const ALICE = {username: 'alice', password: 'synthetic account password alice'};
const BOB = {username: 'bob', password: 'synthetic account password bob'};
const PASSPHRASE = 'synthetic vault passphrase one';
const NEW_PASSPHRASE = 'synthetic vault passphrase two';
const SECRETS = ['vault-synthetic-credential-one', 'vault-synthetic-credential-two', 'vault-synthetic-credential-three'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const sleep = ms => new Promise(done => setTimeout(done, ms));

const log = {requests: [], responses: [], errors: [], csp: [], owner: []};
const pages = [];
let current = 'startup';
// The gateway allows 120 owner-route requests per owner per minute. Steps wait
// for headroom so the flows exercise the console, not the rate limiter.
const OWNER_ROUTE = /^\/api\/(vault|access-requests|approvals|leases|security)(\/|\?|$)/;
let watchdog, budgetWait = false, action = '';
const began = Date.now();
const stamp = () => ((Date.now() - began) / 1000).toFixed(1).padStart(6);
async function step(name) {
  current = name; action = ''; console.log(`· ${stamp()} ${name}`);
  clearTimeout(watchdog);
  // No step needs this long; report where it stalled instead of hanging CI.
  watchdog = setTimeout(async () => {
    console.error(`owner flow stalled during: ${name} (${budgetWait ? 'waiting for owner-route budget' : `last action: ${action || 'none'}`}; ${recentOwner()} owner-route requests in the last 61 s)\nlast requests:\n${log.requests.slice(-15).map(r => `${r.at} ${r.page} ${r.method} ${r.path}`).join('\n')}\nlast responses:\n${log.responses.slice(-15).join('\n')}`);
    if (proxyErrors.length) console.error('proxy errors:', proxyErrors);
    const dump = await fixture.dumpGoroutines().catch(error => `goroutine dump failed: ${error}`);
    console.error('gateway log and goroutines:\n' + dump.split('\n').slice(-2000).join('\n'));
    process.exit(1);
  }, 240000);
  watchdog.unref();
  budgetWait = true;
  // Bounded, so a console that never stops calling owner routes shows up as
  // 429s and a diagnosis rather than a silent wait.
  for (const started = Date.now(); Date.now() - started < 90000; await sleep(1000)) {
    if (recentOwner() <= 60) { budgetWait = false; return; }
  }
  budgetWait = false;
  console.error(`owner-route rate stayed high before "${name}": ${recentOwner()} requests in the last 61 s`);
}
// Names the action a stalled step was on; only the watchdog reads it.
function mark(label) { action = `${stamp()} ${label}`; }
function recentOwner() { return log.owner.filter(at => at > Date.now() - 61000).length; }
function counted(owner) { return (...args) => { log.owner.push(Date.now()); return owner(...args); }; }

// Request interception is switched on once, before the page starts any vault
// worker, and never toggles. Switching it on later sends an untimed protocol
// call to every session, including workers the console may be tearing down;
// two stalled runs stopped at the first page.route after vault workers had come
// and gone. Later routes sit on top of this pass-through.
async function watch(page, label) {
  pages.push(page);
  await page.route('**/*', route => route.fallback());
  page.setDefaultTimeout(45000);
  page.on('request', r => {
    const url = new URL(r.url());
    if (OWNER_ROUTE.test(url.pathname) && !r.headers().authorization) log.owner.push(Date.now());
    if (url.pathname.startsWith('/api/')) log.requests.push({at: stamp(), page: label, method: r.method(), path: url.pathname + url.search, headers: r.headers(), body: r.postData() || ''});
  });
  page.on('response', r => { const url = new URL(r.url()); if (url.pathname.startsWith('/api/')) log.responses.push(`${stamp()} ${label} ${r.request().method()} ${url.pathname} ${r.status()}`); });
  page.on('pageerror', error => log.errors.push(`${label}: ${error.message}`));
  page.on('console', message => { if (/content.security.policy/i.test(message.text())) log.csp.push(`${label}: ${message.text()}`); });
  page.addInitScript(() => document.addEventListener('securitypolicyviolation', event => {
    (window.__cspViolations ||= []).push(`${event.violatedDirective} ${event.blockedURI}`);
  }));
  return page;
}
async function waitText(page, selector, text) {
  await page.waitForFunction(([s, t]) => document.querySelector(s)?.textContent.includes(t), [selector, text]);
}
async function activeElement(page) {
  return page.evaluate(() => ({id: document.activeElement?.id || '', window: document.activeElement?.dataset?.window || '', action: document.activeElement?.dataset?.action || '', connector: document.activeElement?.dataset?.connectorId || ''}));
}
// Test-only calls from the signed-in page, as the rest of the console makes them.
function pageApi(page, method, path, body) {
  return page.evaluate(async ([method, path, body]) => {
    const response = await fetch(path, {method, credentials: 'same-origin', headers: {'X-MCPWarden-Request': 'browser', ...(body ? {'Content-Type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined});
    const text = await response.text();
    let data = null; try { data = JSON.parse(text); } catch { data = text; }
    return {status: response.status, data};
  }, [method, path, body ?? null]);
}

// Holds the page's Web Crypto digests, which recovery-key checksums use, until
// released. Workers are unaffected.
function holdDigests(page) {
  return page.evaluate(() => {
    let release;
    const gate = new Promise(done => { release = done; }), original = crypto.subtle.digest.bind(crypto.subtle);
    window.__digests = 0;
    window.__releaseDigests = () => { delete crypto.subtle.digest; release(); };
    crypto.subtle.digest = async (...args) => { window.__digests++; await gate; return original(...args); };
  });
}

const fixture = await startFixture();
const browser = await playwright[browserName].launch({headless: true, ...(process.env.BROWSER_EXECUTABLE ? {executablePath: process.env.BROWSER_EXECUTABLE} : {})});
const ui = fixture.ui;

async function signedIn(page) {
  await page.locator('#login-screen').waitFor({state: 'hidden'});
}
async function register(page, account) {
  await page.goto(ui + '/vault');
  await page.locator('#login-screen').waitFor();
  await page.click('#toggle-registration');
  await page.fill('#account-username', account.username);
  await page.fill('#account-password', account.password);
  await page.fill('#account-confirm', account.password);
  await page.click('#account-submit');
  await signedIn(page);
}
async function signIn(page, account) {
  await page.locator('#login-screen').waitFor();
  if (await page.locator('#confirm-label').isVisible()) await page.click('#toggle-registration');
  await page.fill('#account-username', account.username);
  await page.fill('#account-password', account.password);
  await page.click('#account-submit');
  await signedIn(page);
}
async function openVault(page, section = 'access') {
  if (!(await page.locator('#vault-page').isVisible())) await page.click('a.nav-item[data-view="vault"]');
  await page.locator('#vault-page').waitFor();
  await page.click(`[data-vault-section="${section}"]`);
  await page.locator(`#vault-${section}-panel`).waitFor();
}
async function reload(page) {
  await page.click('#vault-reload');
  await page.waitForFunction(() => !document.getElementById('vault-reload').disabled);
}
async function unlock(page, secret, method = 'passphrase') {
  await page.click('#vault-unlock-open');
  await unlockWith(page, secret, method);
}
async function unlockWith(page, secret, method = 'passphrase') {
  await page.locator('#vault-unlock').waitFor();
  await page.check(`[name="vault-unlock-method"][value="${method}"]`);
  await page.fill('#vault-unlock-secret', secret);
  await page.click('#vault-unlock-submit');
  await waitText(page, '#vault-status-title', 'Vault unlocked');
}
async function cookieHeader(context) {
  return (await context.cookies(ui + '/api/')).map(c => `${c.name}=${c.value}`).join('; ');
}
async function windowState(page, leaseID) {
  return page.getAttribute(`[data-window-card="${leaseID}"]`, 'data-state');
}
async function waitWindow(page, requestID, owner) {
  for (let i = 0; i < 100; i++) {
    const leases = await owner('GET', '/api/leases?include=ended');
    assert.equal(leases.status, 200, JSON.stringify(leases));
    const found = leases.data.find(l => l.request_id === requestID);
    if (found) { await page.locator(`[data-window-card="${found.lease_id}"]`).waitFor(); return found; }
    await sleep(300);
  }
  throw new Error(`no window for request ${requestID}`);
}

let failed = false;
try {
  const alice = await browser.newContext({viewport: {width: 1280, height: 900}});
  const page = await watch(await alice.newPage(), 'alice');

  await step('register and prepare a header-authenticated connector and two agent keys');
  await register(page, ALICE);
  const connection = await pageApi(page, 'POST', '/api/connections', {name: 'synthetic', url: fixture.upstream, auth_type: 'api_key', headers: {'X-API-Key': 'legacy-synthetic-key'}, call_timeout: '30s'});
  assert.equal(connection.status, 201, JSON.stringify(connection));
  let tool;
  for (let i = 0; i < 100 && !tool; i++) {
    const tools = await pageApi(page, 'GET', '/api/tools');
    tool = (Array.isArray(tools.data) ? tools.data : tools.data?.items || []).find(t => t.display_name === 'search');
    if (!tool) await sleep(100);
  }
  assert(tool?.id, 'synthetic tools were not discovered');
  const agentKey = await pageApi(page, 'POST', '/api/access', {name: 'Laptop <b>agent</b>', role: 'client', expires_days: 30});
  const runnerKey = await pageApi(page, 'POST', '/api/access', {name: 'CI runner', role: 'client', expires_days: 30});
  assert.equal(agentKey.status, 201); assert.equal(runnerKey.status, 201);
  const agent = fixture.key(agentKey.data.token), runner = fixture.key(runnerKey.data.token);
  const owner = counted(fixture.owner(await cookieHeader(alice)));
  const ask = async (key, extra = {}) => {
    const credentials = (await key('GET', '/api/vault/credentials')).data;
    const r = await key('POST', '/api/access-requests', {credential_id: credentials[0].credential_id, duration_seconds: 900,
      tools: [{tool_id: tool.id, constraints: [{pointer: '/repo', operator: 'equals', value: 'example'}]}], ...extra});
    assert.equal(r.status, 201, JSON.stringify(r));
    return r.data;
  };

  await step('set up the vault: passphrase checks, recovery key, verification');
  await openVault(page);
  await waitText(page, '#vault-status-title', 'Vault not set up');
  assert(await page.locator('#vault-scope-note').isVisible(), 'legacy execution disclaimer missing');
  await page.click('#vault-setup-open');
  assert.equal((await activeElement(page)).id, 'vault-new-passphrase');
  await page.fill('#vault-new-passphrase', 'too short');
  await page.fill('#vault-new-confirm', 'too short');
  await page.click('#vault-setup-create');
  await waitText(page, '#vault-setup-error', 'at least 15 characters');
  await page.fill('#vault-new-passphrase', PASSPHRASE);
  await page.fill('#vault-new-confirm', PASSPHRASE + '!');
  await page.click('#vault-setup-create');
  await waitText(page, '#vault-setup-error', 'do not match');
  assert.equal(await page.getAttribute('#vault-new-passphrase', 'aria-invalid'), 'true');
  assert.equal((await activeElement(page)).id, 'vault-new-passphrase');
  await page.fill('#vault-new-passphrase', PASSPHRASE);
  await page.fill('#vault-new-confirm', PASSPHRASE);
  await page.click('#vault-setup-create');
  await page.waitForFunction(() => /^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{4}$/.test(document.getElementById('vault-recovery-key').textContent));
  const recovery = await page.textContent('#vault-recovery-key');
  assert.equal((await activeElement(page)).id, 'vault-recovery-key');
  assert.equal(await page.inputValue('#vault-new-passphrase'), '', 'passphrase stayed in the form');
  assert.equal((await owner('GET', '/api/vault/state')).data.configured, false, 'vault saved before recovery confirmation');
  await page.click('#vault-recovery-saved');
  assert.equal(await page.textContent('#vault-recovery-key'), '', 'recovery key stayed on screen');
  const wrongKey = (recovery[0] === '0' ? '1' : '0') + recovery.slice(1);
  await page.fill('#vault-verify-key', wrongKey);
  await page.fill('#vault-setup-password', ALICE.password);
  await page.click('#vault-verify-submit');
  await waitText(page, '#vault-verify-error', 'incorrect');
  assert.equal((await activeElement(page)).id, 'vault-verify-key');
  await page.click('#vault-verify-back');
  assert.equal(await page.textContent('#vault-recovery-key'), recovery, 'the same key must be shown again');
  await page.click('#vault-recovery-saved');
  // Typed in lower case with spaces, as a person might copy it by hand.
  await page.fill('#vault-verify-key', recovery.toLowerCase().replaceAll('-', ' '));
  await page.fill('#vault-setup-password', 'not the account password');
  await page.click('#vault-verify-submit');
  await waitText(page, '#vault-verify-error', 'password was not accepted');
  assert.equal((await owner('GET', '/api/vault/state')).data.configured, false, 'vault saved with a wrong account password');
  await page.fill('#vault-verify-key', recovery);
  await page.fill('#vault-setup-password', ALICE.password);
  await page.click('#vault-verify-submit');
  await waitText(page, '#vault-notice', 'Vault ready');
  await waitText(page, '#vault-status-title', 'Vault unlocked');
  const root = (await owner('GET', '/api/vault/wrappers')).data.root;
  assert.equal(root.wrapper_revision, '1'); assert(root.passphrase && root.recovery);

  await step('encrypt a credential for the existing connector');
  await openVault(page, 'credentials');
  const addButton = page.locator('#vault-credentials button[data-connector-id]');
  await waitText(page, '#vault-credentials', 'Not in the vault yet');
  assert.equal(await addButton.textContent(), 'Add encrypted credential');
  await addButton.click();
  await page.locator('#vault-credential-dialog[open]').waitFor();
  assert.equal((await activeElement(page)).id, 'vault-header-0');
  await page.fill('#vault-header-0', ` ${SECRETS[0]}`);
  await page.click('#vault-credential-save');
  await waitText(page, '#vault-credential-error', 'Remove spaces');
  await page.fill('#vault-header-0', SECRETS[0]);
  await page.click('#vault-credential-save');
  await waitText(page, '#vault-notice', 'saved as version 1');
  await page.locator('#vault-credential-dialog').waitFor({state: 'hidden'});
  await waitText(page, '#vault-credentials', 'Encrypted in vault · version 1');
  const stored = (await owner('GET', '/api/vault/wrappers')).data.credentials;
  assert.equal(stored.length, 1); assert.equal(stored[0].epoch, '1');
  const credentialID = stored[0].credential_id;
  const connections = (await pageApi(page, 'GET', '/api/connections')).data;
  assert.equal(stored[0].connector_id, connections[0].id, 'credential bound to a different connector');
  assert.equal(connections[0].header_names.length, 1, 'legacy header removed');

  await step('review an agent request with untrusted labels and constraints');
  const first = await ask(agent);
  for (const path of [`/api/approvals/${first.id}/begin`, `/api/approvals/${first.id}/activate`]) {
    const r = await agent('POST', path, {request_digest: first.request_digest});
    assert.equal(r.status, 403, `a key reached ${path}`);
  }
  await openVault(page, 'access');
  await reload(page);
  const card = page.locator(`[data-request-card="${first.id}"]`);
  await card.waitFor();
  const cardText = await card.textContent();
  assert(cardText.includes('Allow Laptop <b>agent</b> to use synthetic?'), cardText);
  assert(cardText.includes(`key …${agentKey.data.public_id.slice(-4)}`), 'public handle missing');
  assert(cardText.includes('key expires'), 'key expiry missing');
  assert(cardText.includes('synthetic · version 1'));
  assert(cardText.includes(fixture.upstream) && cardText.includes('headers x-api-key'), 'destination missing');
  assert(cardText.includes('/repo equals "example"'), 'constraint missing');
  assert(cardText.includes('<img src=x'), 'tool description not shown as text');
  assert(cardText.includes('lasts 15 minutes') && cardText.includes('no call limit'), 'duration or limits missing');
  assert.equal(await page.locator('#vault-page b, #vault-page img').count(), 0, 'untrusted markup rendered');
  assert.notEqual(await page.title(), 'pwned');

  await step('confirm mode: explicit activation with one released key');
  const startButton = card.locator('button[data-action="start"]');
  assert.equal(await startButton.textContent(), 'Allow for 15 minutes');
  const activation = page.waitForRequest(r => r.url().endsWith(`/api/approvals/${first.id}/activate`));
  await startButton.click();
  const sent = await activation;
  const headers = sent.headers();
  assert.match(headers['idempotency-key'] || '', UUID);
  assert(headers['x-csrf-token'], 'CSRF token missing');
  assert.equal(headers['x-mcpwarden-request'], 'browser');
  assert.equal(headers.authorization, undefined);
  const activationBody = JSON.parse(sent.postData());
  assert.match(activationBody.cek, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(activationBody.credential_id, credentialID);
  const window1 = await waitWindow(page, first.id, owner);
  await waitText(page, '#vault-notice', 'Access started');
  assert.equal(await windowState(page, window1.lease_id), 'active');
  assert.equal((Date.parse(window1.expires_at) - Date.parse(window1.activated_at)) / 1000, 900);
  const timer = await page.textContent(`[data-window-card="${window1.lease_id}"] [role="timer"]`);
  assert.match(timer, /^1[45]:\d\d$/);
  assert((await page.textContent(`[data-window-card="${window1.lease_id}"]`)).includes('0 calls · no call limit'));

  await step('sign out keeps the window; signing back in shows a locked vault');
  await page.click('#account-launcher-trigger');
  await page.click('#disconnect');
  await page.locator('#login-screen').waitFor();
  assert.equal((await agent('GET', '/api/leases')).data.filter(l => l.state === 'active').length, 1, 'sign-out ended the window');
  await signIn(page, ALICE);
  const owner2 = counted(fixture.owner(await cookieHeader(alice)));
  await openVault(page);
  await waitText(page, '#vault-status-title', 'Vault locked');
  await page.locator(`[data-window-card="${window1.lease_id}"][data-state="active"]`).waitFor();

  await step('renewal needs an unlocked vault; Escape returns focus');
  await page.click(`[data-window-card="${window1.lease_id}"] button[data-action="renew"]`);
  await page.locator('#vault-renew-dialog[open]').waitFor();
  assert.equal(await page.inputValue('#vault-renew-duration'), '900');
  assert.equal(await page.textContent('#vault-renew-submit'), 'Allow for 15 minutes');
  await page.selectOption('#vault-renew-duration', '300');
  assert.equal(await page.textContent('#vault-renew-submit'), 'Allow for 5 minutes');
  await page.click('#vault-renew-submit');
  await waitText(page, '#vault-renew-error', 'Unlock your vault first');
  await page.keyboard.press('Escape');
  await page.locator('#vault-renew-dialog').waitFor({state: 'hidden'});
  await page.waitForFunction(id => document.activeElement?.dataset?.window === id && document.activeElement.dataset.action === 'renew', window1.lease_id);

  await step('unlock failures, then unlock and renew for 5 minutes');
  await page.click('#vault-unlock-open');
  assert.equal((await activeElement(page)).id, 'vault-unlock-secret');
  await page.fill('#vault-unlock-secret', 'not the vault passphrase at all');
  await page.click('#vault-unlock-submit');
  await waitText(page, '#vault-unlock-error', 'did not unlock');
  assert.equal((await activeElement(page)).id, 'vault-unlock-secret');
  await page.check('[name="vault-unlock-method"][value="recovery"]');
  await page.fill('#vault-unlock-secret', 'ABCD-EFGH');
  await page.click('#vault-unlock-submit');
  await waitText(page, '#vault-unlock-error', '56 characters');
  await unlockWith(page, PASSPHRASE);
  assert.equal((await activeElement(page)).id, 'vault-lock');
  await page.click(`[data-window-card="${window1.lease_id}"] button[data-action="renew"]`);
  await page.locator('#vault-renew-dialog[open]').waitFor();
  await page.selectOption('#vault-renew-duration', '300');
  const renewal = page.waitForRequest(r => r.method() === 'POST' && r.url().endsWith('/api/access-requests'));
  await page.click('#vault-renew-submit');
  const renewalBody = JSON.parse((await renewal).postData());
  assert.equal(renewalBody.duration_seconds, 300);
  assert.equal(renewalBody.requester_access_id, agentKey.data.id);
  let window2;
  for (let i = 0; i < 100 && !window2; i++) { window2 = (await owner2('GET', '/api/leases')).data.find(l => l.lease_id !== window1.lease_id); if (!window2) await sleep(300); }
  assert(window2, 'renewal did not start a new window');
  assert.equal((Date.parse(window2.expires_at) - Date.parse(window2.activated_at)) / 1000, 300);
  const unchanged = (await owner2('GET', '/api/leases')).data.find(l => l.lease_id === window1.lease_id);
  assert.equal(unchanged.expires_at, window1.expires_at, 'renewal extended the earlier window');
  await page.locator(`[data-window-card="${window2.lease_id}"][data-state="active"]`).waitFor();

  await step('filters, stop access, lock browser and lock all execution');
  await page.selectOption('#vault-filter-state', 'active');
  assert.equal(await page.locator('#vault-windows [data-window-card]').count(), 2);
  await page.click(`[data-window-card="${window1.lease_id}"] button[data-action="stop"]`);
  await waitText(page, '#vault-notice', 'Access stopped');
  await page.selectOption('#vault-filter-state', 'revoked');
  await page.locator(`[data-window-card="${window1.lease_id}"][data-state="revoked"]`).waitFor();
  assert.equal(await page.locator('#vault-windows [data-window-card]').count(), 1);
  await page.selectOption('#vault-filter-state', '');
  await page.selectOption('#vault-filter-caller', agentKey.data.id);
  assert.equal(await page.locator('#vault-windows [data-window-card]').count(), 2);
  await page.selectOption('#vault-filter-caller', '');
  await page.click('#vault-lock');
  await waitText(page, '#vault-notice', 'keep running');
  await waitText(page, '#vault-status-title', 'Vault locked');
  assert.equal((await owner2('GET', '/api/leases')).data.length, 1, 'browser lock ended a window');
  await page.click('#vault-lock-all');
  await page.locator('#vault-lock-all-dialog[open]').waitFor();
  assert.equal((await activeElement(page)).id, 'vault-lock-all-cancel');
  await page.click('#vault-lock-all-confirm');
  await waitText(page, '#vault-notice', 'All access windows for your account were stopped');
  assert.equal((await owner2('GET', '/api/leases')).data.length, 0, 'lock all left a window running');
  await page.waitForFunction(() => document.activeElement?.id === 'vault-lock-all');

  await step('approval policy: password check and stale revision');
  await openVault(page, 'settings');
  assert(await page.isChecked('[name="vault-policy-mode"][value="confirm"]'));
  await page.check('[name="vault-policy-mode"][value="none"]');
  await page.fill('#vault-policy-password', 'not the account password');
  await page.click('#vault-policy-save');
  await waitText(page, '#vault-policy-error', 'password was not accepted');
  const policy = (await owner2('GET', '/api/vault/state')).data.approval_policy;
  const outOfBand = await owner2('PUT', '/api/security/approval-policy', {mode: 'none', expected_revision: policy.revision, current_password: ALICE.password});
  assert.equal(outOfBand.status, 200, JSON.stringify(outOfBand));
  await page.fill('#vault-policy-password', ALICE.password);
  await page.click('#vault-policy-save');
  await waitText(page, '#vault-policy-error', 'changed elsewhere');
  await waitText(page, '#vault-policy-current', 'No extra confirmation');

  await step('none mode: the owner still starts access explicitly');
  const direct = await ask(agent);
  await openVault(page, 'access');
  await reload(page);
  const directStart = page.locator(`[data-request-card="${direct.id}"] button[data-action="start"]`);
  assert.equal(await directStart.textContent(), 'Start access for 15 minutes');
  await directStart.click();
  await waitText(page, '#vault-unlock-error', 'Unlock your vault, then start access again');
  await unlockWith(page, recovery, 'recovery');
  await waitText(page, '#vault-notice', 'Unlocked with your recovery key');
  await directStart.click();
  const window3 = await waitWindow(page, direct.id, owner2);
  assert.equal(window3.authorization_source, 'client_activation');

  await step('uncertain activation: check status after the gateway acted');
  mark('ask'); const acted = await ask(runner);
  mark('reload'); await reload(page);
  mark('route'); await page.route('**/api/approvals/*/activate', async route => { mark('route.fetch'); await route.fetch(); mark('route.abort'); await route.abort('failed'); }, {times: 1});
  mark('click start'); await page.click(`[data-request-card="${acted.id}"] button[data-action="start"]`);
  mark('wait for uncertain'); await waitText(page, '#vault-error', 'did not confirm');
  mark('click check'); await page.click(`[data-request-card="${acted.id}"] button[data-action="check"]`);
  mark('wait for started'); await waitText(page, '#vault-notice', 'Access did start');
  assert.equal((await owner2('GET', '/api/leases')).data.filter(l => l.request_id === acted.id).length, 1);

  await step('uncertain activation: retry reuses the same Idempotency-Key');
  const lost = await ask(runner);
  await reload(page);
  await page.route('**/api/approvals/*/activate', route => route.abort('failed'), {times: 1});
  await page.click(`[data-request-card="${lost.id}"] button[data-action="start"]`);
  await waitText(page, '#vault-error', 'did not confirm');
  await page.click(`[data-request-card="${lost.id}"] button[data-action="check"]`);
  await waitText(page, '#vault-notice', 'has not started');
  await page.click(`[data-request-card="${lost.id}"] button[data-action="retry"]`);
  await waitWindow(page, lost.id, owner2);
  const keys = log.requests.filter(r => r.path === `/api/approvals/${lost.id}/activate`).map(r => r.headers['idempotency-key']);
  assert.equal(keys.length, 2); assert.equal(keys[0], keys[1], 'retry used a new Idempotency-Key');

  await step('locking while an activation is in flight discards the late response');
  const late = await ask(agent);
  await reload(page);
  await page.route('**/api/approvals/*/activate', async route => { await sleep(1500); await route.continue(); }, {times: 1});
  const inFlight = page.waitForRequest(r => r.url().endsWith(`/api/approvals/${late.id}/activate`));
  await page.click(`[data-request-card="${late.id}"] button[data-action="start"]`);
  await inFlight;
  await page.click('#vault-lock');
  await sleep(2500);
  assert(!(await page.textContent('#vault-notice')).includes('Access started'), 'late activation response was shown');
  await waitText(page, '#vault-status-title', 'Vault locked');
  await reload(page);
  await waitWindow(page, late.id, owner2);
  for (const l of (await owner2('GET', '/api/leases')).data) assert.equal((await owner2('DELETE', `/api/leases/${l.lease_id}`)).status, 204);

  await step('renewal asks for a new review when a tool definition changed, and Cancel stops it');
  const base = await ask(agent);
  await reload(page);
  await unlock(page, PASSPHRASE);
  await page.click(`[data-request-card="${base.id}"] button[data-action="start"]`);
  const baseWindow = await waitWindow(page, base.id, owner2);
  await page.click(`[data-window-card="${baseWindow.lease_id}"] button[data-action="renew"]`);
  await page.locator('#vault-renew-dialog[open]').waitFor();
  const reviewedDigest = base.tools[0].definition_sha256;
  await waitText(page, '#vault-renew-scope', reviewedDigest.slice(0, 12));
  fixture.changeTool('search', {description: 'Synthetic search that now also deletes branches', inputSchema: {type: 'object', properties: {repo: {type: 'string'}, branch: {type: 'string'}}}});
  const refreshed = await pageApi(page, 'POST', '/api/discovery/synthetic/refresh');
  assert(refreshed.status < 300, JSON.stringify(refreshed));
  const releases = () => log.requests.filter(r => /^\/api\/approvals\/[^/]+\/(begin|activate)$/.test(r.path)).length;
  const releasesBefore = releases();
  const renewed = page.waitForResponse(r => r.request().method() === 'POST' && new URL(r.url()).pathname === '/api/access-requests');
  await page.click('#vault-renew-submit');
  const changed = await (await renewed).json();
  assert.notEqual(changed.tools[0].definition_sha256, reviewedDigest, 'discovery did not change the definition');
  await waitText(page, '#vault-renew-error', 'changed after you opened it');
  await waitText(page, '#vault-renew-scope', changed.tools[0].definition_sha256.slice(0, 12));
  await waitText(page, '#vault-renew-scope', 'deletes branches');
  assert(await page.locator('#vault-renew-dialog[open]').isVisible(), 'the renewal dialog closed without a new review');
  assert.equal(releases(), releasesBefore, 'renewal released a key for a definition the owner had not reviewed');
  assert(!(await owner2('GET', '/api/leases')).data.some(l => l.request_id === changed.id), 'renewal started a window for an unreviewed definition');
  await page.click('#vault-renew-submit');
  const changedWindow = await waitWindow(page, changed.id, owner2);

  // Cancel and Escape stop a renewal whose request is still in flight.
  for (const dismiss of ['cancel', 'escape']) {
    await page.click(`[data-window-card="${changedWindow.lease_id}"] button[data-action="renew"]`);
    await page.locator('#vault-renew-dialog[open]').waitFor();
    let releaseRenewal, sawRenewal;
    const heldRenewal = new Promise(done => { releaseRenewal = done; }), renewalSeen = new Promise(done => { sawRenewal = done; });
    await page.route('**/api/access-requests', async route => {
      if (route.request().method() !== 'POST') return route.fallback();
      sawRenewal(); await heldRenewal; await route.continue().catch(() => {});
    }, {times: 1});
    const leasesBefore = (await owner2('GET', '/api/leases')).data.length;
    await page.click('#vault-renew-submit');
    await renewalSeen;
    if (dismiss === 'cancel') await page.click('#vault-renew-cancel'); else await page.keyboard.press('Escape');
    await page.locator('#vault-renew-dialog').waitFor({state: 'hidden'});
    const releasesAtCancel = releases();
    releaseRenewal();
    await sleep(1500);
    assert.equal(releases(), releasesAtCancel, `renewal released a key after ${dismiss}`);
    assert.equal((await owner2('GET', '/api/leases')).data.length, leasesBefore, `renewal started a window after ${dismiss}`);
    await page.click(`[data-window-card="${changedWindow.lease_id}"] button[data-action="renew"]`);
    await page.locator('#vault-renew-dialog[open]').waitFor();
    assert.equal(await page.isDisabled('#vault-renew-submit'), false, `renewal stayed busy after ${dismiss}`);
    await page.click('#vault-renew-cancel');
    await page.locator('#vault-renew-dialog').waitFor({state: 'hidden'});
  }
  for (const l of (await owner2('GET', '/api/leases')).data) assert.equal((await owner2('DELETE', `/api/leases/${l.lease_id}`)).status, 204);
  await page.click('#vault-lock');
  await waitText(page, '#vault-status-title', 'Vault locked');

  await step('a short window counts down and ends at the server expiry');
  const short = await ask(agent, {duration_seconds: 20});
  await reload(page);
  const shortStart = page.locator(`[data-request-card="${short.id}"] button[data-action="start"]`);
  assert.equal(await shortStart.textContent(), 'Start access for 20 seconds');
  await unlock(page, PASSPHRASE);
  await shortStart.click();
  const shortWindow = await waitWindow(page, short.id, owner2);
  assert.match(await page.textContent(`[data-window-card="${shortWindow.lease_id}"] [role="timer"]`), /^0:(20|[01]\d)$/);
  await page.locator(`[data-window-card="${shortWindow.lease_id}"][data-state="expired"]`).waitFor({timeout: 40000});
  assert((await page.textContent(`[data-window-card="${shortWindow.lease_id}"]`)).includes('Access window ended'));

  await step('replacement in another tab wins; this tab sees a conflict');
  await openVault(page, 'credentials');
  await page.click('#vault-credentials button[data-connector-id]');
  await page.locator('#vault-credential-dialog[open]').waitFor();
  const tab = await watch(await alice.newPage(), 'alice-tab');
  await tab.goto(ui + '/vault/credentials');
  await signedIn(tab);
  await tab.locator('#vault-credentials-panel').waitFor();
  await unlock(tab, PASSPHRASE);
  await tab.click('#vault-credentials button[data-connector-id]');
  await tab.fill('#vault-header-0', SECRETS[1]);
  await tab.click('#vault-credential-save');
  await waitText(tab, '#vault-notice', 'saved as version 2');
  await tab.close();
  await page.fill('#vault-header-0', SECRETS[2]);
  await page.click('#vault-credential-save');
  await waitText(page, '#vault-credential-error', 'changed elsewhere');
  await page.click('#vault-credential-cancel');
  await page.waitForFunction(id => document.activeElement?.dataset?.connectorId === id, connections[0].id);
  await waitText(page, '#vault-credentials', 'Encrypted in vault · version 2');
  const replaced = (await owner2('GET', '/api/vault/wrappers')).data.credentials;
  assert.equal(replaced.length, 1); assert.equal(replaced[0].credential_id, credentialID); assert.equal(replaced[0].epoch, '2');

  await step('a cancelled save finishing late leaves a newer credential form alone');
  // Each save reaches the gateway, then its response is held while the owner
  // cancels and starts typing into a new form. The late outcome is reported
  // without closing, clearing or marking that form.
  for (const outcome of ['success', 'failure']) {
    await page.click('#vault-credentials button[data-connector-id]');
    await page.locator('#vault-credential-dialog[open]').waitFor();
    let releaseSave, sawSave;
    const heldSave = new Promise(done => { releaseSave = done; }), saveSeen = new Promise(done => { sawSave = done; });
    await page.route('**/api/vault/credentials/*', async route => {
      if (route.request().method() !== 'PUT') return route.fallback();
      let postData = route.request().postData();
      // A stale expected version makes the gateway itself refuse the save.
      if (outcome === 'failure') { const body = JSON.parse(postData); body.expected.revision = '999'; postData = JSON.stringify(body); }
      const response = await route.fetch({postData});
      sawSave(response.status()); await heldSave; await route.fulfill({response}).catch(() => {});
    }, {times: 1});
    await page.fill('#vault-header-0', SECRETS[0]);
    await page.click('#vault-credential-save');
    const status = await saveSeen;
    assert.equal(status, outcome === 'success' ? 200 : 409, `held save returned ${status}`);
    await page.click('#vault-credential-cancel');
    await page.locator('#vault-credential-dialog').waitFor({state: 'hidden'});
    await page.click('#vault-credentials button[data-connector-id]');
    await page.locator('#vault-credential-dialog[open]').waitFor();
    await page.fill('#vault-header-0', 'typed after cancel');
    // Either outcome refreshes the page; the checks run after that reload.
    const refreshed = page.waitForResponse(r => r.request().method() === 'GET' && new URL(r.url()).pathname === '/api/access');
    releaseSave();
    if (outcome === 'success') await waitText(page, '#vault-notice', 'saved as version 3');
    else await waitText(page, '#vault-error', 'did not confirm an earlier save');
    await refreshed; await sleep(500);
    if (outcome === 'failure') assert((await page.textContent('#vault-error')).includes('did not confirm an earlier save'), 'the refresh erased the late failure');
    assert(await page.locator('#vault-credential-dialog[open]').isVisible(), `a late ${outcome} closed the newer form`);
    assert.equal(await page.inputValue('#vault-header-0'), 'typed after cancel', `a late ${outcome} cleared the newer form`);
    assert.equal(await page.textContent('#vault-credential-error'), '', `a late ${outcome} marked the newer form`);
    assert.equal(await page.isDisabled('#vault-credential-save'), false, `a late ${outcome} left the newer form busy`);
    await page.click('#vault-credential-cancel');
    await page.locator('#vault-credential-dialog').waitFor({state: 'hidden'});
  }
  await waitText(page, '#vault-credentials', 'Encrypted in vault · version 3');
  const afterLate = (await owner2('GET', '/api/vault/wrappers')).data.credentials;
  assert.equal(afterLate.length, 1); assert.equal(afterLate[0].credential_id, credentialID); assert.equal(afterLate[0].epoch, '3');

  await step('change the vault passphrase');
  await openVault(page, 'settings');
  await page.fill('#vault-change-passphrase', NEW_PASSPHRASE);
  await page.fill('#vault-change-confirm', NEW_PASSPHRASE);
  await page.fill('#vault-change-password', ALICE.password);
  await page.click('#vault-passphrase-save');
  await waitText(page, '#vault-notice', 'Vault passphrase changed');
  assert.equal((await owner2('GET', '/api/vault/wrappers')).data.root.wrapper_revision, '2');
  await page.click('#vault-lock');
  await page.click('#vault-unlock-open');
  await page.fill('#vault-unlock-secret', PASSPHRASE);
  await page.click('#vault-unlock-submit');
  await waitText(page, '#vault-unlock-error', 'did not unlock');
  await unlockWith(page, NEW_PASSPHRASE);

  await step('leaving the vault page locks the browser vault');
  await page.click('a.nav-item[data-view="access"]');
  await page.click('a.nav-item[data-view="vault"]');
  await waitText(page, '#vault-notice', 'Vault locked when you left the vault page');
  await waitText(page, '#vault-status-title', 'Vault locked');

  await step('leaving during a recovery unlock keeps the vault locked');
  const wrapperReads = () => log.requests.filter(r => r.page === 'alice' && r.path === '/api/vault/wrappers').length;
  await page.click('#vault-unlock-open');
  await page.check('[name="vault-unlock-method"][value="recovery"]');
  await page.fill('#vault-unlock-secret', recovery);
  await holdDigests(page);
  const readsBefore = wrapperReads();
  await page.click('#vault-unlock-submit');
  await page.waitForFunction(() => window.__digests > 0);
  await page.click('a.nav-item[data-view="access"]');
  await page.evaluate(() => window.__releaseDigests());
  await sleep(1000);
  assert.equal(wrapperReads(), readsBefore, 'a cancelled recovery unlock continued after the page was left');
  await page.click('a.nav-item[data-view="vault"]');
  await waitText(page, '#vault-status-title', 'Vault locked');
  await page.click('#vault-unlock-open');
  assert.equal(await page.textContent('#vault-unlock-submit'), 'Unlock');
  assert.equal(await page.isDisabled('#vault-unlock-submit'), false);
  await unlockWith(page, recovery, 'recovery');
  await waitText(page, '#vault-notice', 'Unlocked with your recovery key');
  await page.click('#vault-lock');
  await waitText(page, '#vault-status-title', 'Vault locked');

  await step('interrupted and cancelled passphrase unlocks can be retried without reloading');
  let releaseWrappers;
  const heldWrappers = new Promise(done => { releaseWrappers = done; });
  await page.route('**/api/vault/wrappers', async route => { await heldWrappers; await route.continue().catch(() => {}); }, {times: 1});
  await page.click('#vault-unlock-open');
  await page.check('[name="vault-unlock-method"][value="passphrase"]');
  await page.fill('#vault-unlock-secret', NEW_PASSPHRASE);
  const wrappersRead = page.waitForRequest(r => r.url().endsWith('/api/vault/wrappers'));
  await page.click('#vault-unlock-submit');
  await wrappersRead;
  assert.equal(await page.textContent('#vault-unlock-submit'), 'Unlocking…');
  await page.click('a.nav-item[data-view="access"]');
  releaseWrappers();
  await sleep(1000);
  await page.click('a.nav-item[data-view="vault"]');
  await waitText(page, '#vault-status-title', 'Vault locked');
  await page.click('#vault-unlock-open');
  assert.equal(await page.textContent('#vault-unlock-submit'), 'Unlock');
  assert.equal(await page.isDisabled('#vault-unlock-submit'), false);
  // Cancel ends a pending unlock: a late wrapper response opens nothing.
  let releaseCancelled;
  const heldCancelled = new Promise(done => { releaseCancelled = done; });
  await page.route('**/api/vault/wrappers', async route => { await heldCancelled; await route.continue().catch(() => {}); }, {times: 1});
  await page.check('[name="vault-unlock-method"][value="passphrase"]');
  await page.fill('#vault-unlock-secret', NEW_PASSPHRASE);
  const cancelledRead = page.waitForRequest(r => r.url().endsWith('/api/vault/wrappers'));
  await page.click('#vault-unlock-submit');
  await cancelledRead;
  await page.click('#vault-unlock-cancel');
  assert(await page.locator('#vault-unlock').isHidden());
  releaseCancelled();
  await sleep(1500);
  await waitText(page, '#vault-status-title', 'Vault locked');
  assert(!(await page.textContent('#vault-notice')).includes('Vault unlocked'), 'a cancelled unlock opened the vault');
  await page.click('#vault-unlock-open');
  assert.equal(await page.isDisabled('#vault-unlock-submit'), false);
  await unlockWith(page, NEW_PASSPHRASE);
  await waitText(page, '#vault-notice', 'Vault unlocked in this browser');
  await page.click('#vault-lock');
  await waitText(page, '#vault-status-title', 'Vault locked');

  await step('gateway restart suspends windows and expires pending requests');
  await openVault(page, 'access');
  const beforeRestart = await ask(agent);
  await reload(page);
  await unlock(page, NEW_PASSPHRASE);
  await page.click(`[data-request-card="${beforeRestart.id}"] button[data-action="start"]`);
  const restartWindow = await waitWindow(page, beforeRestart.id, owner2);
  const pendingBeforeRestart = await ask(runner);
  await fixture.restart();
  // The browser session and this browser's unlocked vault survive a gateway
  // restart; windows never resume and old requests cannot start.
  await reload(page);
  await waitText(page, '#vault-notice', 'The gateway restarted');
  const owner3 = owner2;
  await page.locator(`[data-window-card="${restartWindow.lease_id}"][data-state="suspended"]`).waitFor();
  assert((await page.textContent(`[data-window-card="${restartWindow.lease_id}"]`)).includes('never resumes'));
  await page.locator(`[data-request-card="${pendingBeforeRestart.id}"]`).waitFor();
  assert.equal(await page.locator(`[data-request-card="${pendingBeforeRestart.id}"] button`).count(), 0, 'a pre-restart request stayed actionable');
  await waitText(page, '#vault-status-title', 'Vault unlocked');

  await step('an expired session returns to sign-in and clears the console');
  await alice.clearCookies();
  await page.click('#vault-reload');
  await page.locator('#login-screen').waitFor();
  assert.equal(await page.locator('#vault-requests [data-request-card]').count(), 0, 'requests stayed rendered after sign-out');
  await signIn(page, ALICE);
  await openVault(page);

  await step('idle time locks the browser vault');
  const idle = await watch(await alice.newPage(), 'alice-idle');
  await idle.clock.install();
  await idle.goto(ui + '/vault');
  await signedIn(idle);
  await idle.locator('#vault-access-panel').waitFor();
  await unlock(idle, NEW_PASSPHRASE);
  await idle.clock.fastForward('10:10');
  await waitText(idle, '#vault-status-title', 'Vault locked');
  await waitText(idle, '#vault-notice', 'after 10 minutes without activity');
  await idle.close();

  await step('remove the vault credential while locked; it cannot be added back');
  await openVault(page, 'credentials');
  await waitText(page, '#vault-status-title', 'Vault locked');
  const beforeRemoval = await ask(agent);
  await page.click('#vault-credentials button[data-remove-connector]');
  await page.locator('#vault-remove-dialog[open]').waitFor();
  assert.equal((await activeElement(page)).id, 'vault-remove-cancel', 'removal did not default to keeping the credential');
  await page.keyboard.press('Escape');
  await page.locator('#vault-remove-dialog').waitFor({state: 'hidden'});
  assert.equal(await page.evaluate(() => Boolean(document.activeElement?.dataset?.removeConnector)), true, 'focus did not return to Remove');
  assert.equal((await owner3('GET', '/api/vault/wrappers')).data.credentials.filter(c => !c.deleted).length, 1, 'Escape removed the credential');
  await page.click('#vault-credentials button[data-remove-connector]');
  await page.click('#vault-remove-confirm');
  await page.locator('#vault-remove-dialog').waitFor({state: 'hidden'});
  await waitText(page, '#vault-notice', 'vault credential removed');
  await waitText(page, '#vault-credentials', 'Removed from the vault');
  assert.equal(await page.locator('#vault-credentials button[data-remove-connector]').count(), 0);
  assert(await page.isDisabled('#vault-credentials button[data-connector-id]'), 'a removed credential can be replaced');
  const tombstones = (await owner3('GET', '/api/vault/wrappers')).data.credentials;
  assert.equal(tombstones.length, 1); assert.equal(tombstones[0].deleted, true);
  assert.notEqual((await owner3('GET', `/api/access-requests/${beforeRemoval.id}`)).data.state, 'pending', 'removal left a request pending');
  assert.equal((await owner3('GET', '/api/leases')).data.length, 0, 'removal left an access window running');

  await step('responsive layouts have no horizontal overflow');
  // 720 px is a 1440 px laptop screen at 200% zoom.
  for (const width of [390, 720, 1280]) {
    await page.setViewportSize({width, height: 900});
    for (const section of ['access', 'credentials', 'settings']) {
      if (width < 700) { await page.goto(ui + `/vault${section === 'access' ? '' : '/' + section}`); await signedIn(page); await page.locator(`#vault-${section}-panel`).waitFor(); }
      else await openVault(page, section);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      assert(overflow <= 0, `${section} overflows by ${overflow}px at ${width}px`);
    }
  }

  await step('another account sees none of this owner’s vault');
  const bobContext = await browser.newContext({viewport: {width: 1280, height: 900}});
  const bobPage = await watch(await bobContext.newPage(), 'bob');
  await register(bobPage, BOB);
  await openVault(bobPage);
  await waitText(bobPage, '#vault-status-title', 'Vault not set up');
  await waitText(bobPage, '#vault-requests', 'No access requests');
  await waitText(bobPage, '#vault-windows', 'No access windows yet');
  // Cancelling setup while its recovery key is being formatted discards the result.
  await bobPage.click('#vault-setup-open');
  await bobPage.fill('#vault-new-passphrase', PASSPHRASE);
  await bobPage.fill('#vault-new-confirm', PASSPHRASE);
  await holdDigests(bobPage);
  await bobPage.click('#vault-setup-create');
  await bobPage.waitForFunction(() => window.__digests > 0);
  await bobPage.click('#vault-setup-cancel');
  await bobPage.evaluate(() => window.__releaseDigests());
  await sleep(1000);
  assert(await bobPage.locator('#vault-setup').isHidden(), 'cancelled setup came back');
  assert.equal(await bobPage.textContent('#vault-recovery-key'), '');
  // Leaving announces a lock only if setup material were still held.
  await bobPage.click('a.nav-item[data-view="access"]');
  await bobPage.click('a.nav-item[data-view="vault"]');
  await waitText(bobPage, '#vault-status-title', 'Vault not set up');
  assert((await bobPage.textContent('#vault-notice')).includes('Setup cancelled'), 'cancelled setup still held recovery material');
  await bobPage.click('#vault-setup-open');
  assert(await bobPage.locator('#vault-setup-form').isVisible(), 'setup reopened at a stale step');
  assert.equal(await bobPage.textContent('#vault-setup-create'), 'Create recovery key');
  assert.equal(await bobPage.isDisabled('#vault-setup-create'), false);
  await bobPage.click('#vault-setup-cancel');
  const bob = counted(fixture.owner(await cookieHeader(bobContext)));
  assert.equal((await bob('GET', `/api/access-requests/${beforeRestart.id}`)).status, 404);
  assert.deepEqual((await bob('GET', '/api/leases?include=ended')).data, []);
  assert.equal((await owner3('GET', '/api/leases?include=ended')).data.length > 0, true);

  await step('disabled, untrusted-transport and unavailable states');
  for (const [status, body, text] of [[404, null, 'not enabled'], [403, {error: 'secure_transport_required'}, 'needs HTTPS'], [503, {error: 'unavailable'}, 'Security storage is unavailable']]) {
    await bobPage.route('**/api/vault/state', route => route.fulfill(body ? {status, contentType: 'application/json', body: JSON.stringify(body)} : {status, contentType: 'text/plain', body: '404 page not found'}));
    await bobPage.click('#vault-reload');
    await waitText(bobPage, '#vault-status-text', text);
    assert.equal(await bobPage.locator('.vault-nav').isVisible(), false);
    await bobPage.unroute('**/api/vault/state');
  }

  await step('no secrets in requests, logs or browser storage');
  const forbidden = [PASSPHRASE, NEW_PASSPHRASE, recovery, recovery.replaceAll('-', ''), recovery.toLowerCase().replaceAll('-', ' '), ...SECRETS];
  for (const r of log.requests) {
    for (const value of forbidden) assert(!r.body.includes(value) && !r.path.includes(value), `${r.method} ${r.path} carried vault material`);
    if (r.body.includes('"cek"')) assert.match(r.path, /^\/api\/approvals\/[^/]+\/activate$/, `a key was sent to ${r.path}`);
    assert.equal(r.headers.authorization, undefined, `${r.path} carried an Authorization header`);
  }
  for (const value of forbidden) assert(!fixture.logs().includes(value), 'gateway logs contain vault material');
  for (const p of pages.filter(p => !p.isClosed())) {
    const storage = await p.evaluate(async () => ({local: Object.keys(localStorage), session: sessionStorage.length,
      databases: typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).length : 0, csp: window.__cspViolations || []}));
    assert(storage.local.every(k => /theme|time/i.test(k)), `unexpected localStorage keys ${storage.local}`);
    assert.equal(storage.session, 0); assert.equal(storage.databases, 0);
    assert.deepEqual(storage.csp, []);
  }
  assert.deepEqual(log.csp, []);
  assert.deepEqual(log.errors, []);
  await bobContext.close();
  await alice.close();
  console.log(JSON.stringify({engine: browserName, browser: browser.version(), requests: log.requests.length, result: 'ok'}));
} catch (error) {
  failed = true;
  console.error(`owner flow failed during: ${current}`);
  console.error(error);
  for (const p of pages.filter(p => !p.isClosed())) {
    const shown = await p.evaluate(() => ['vault-status-title', 'vault-status-text', 'vault-notice', 'vault-error'].map(id => `${id}: ${document.getElementById(id)?.textContent || ''}`).join('\n')).catch(() => 'page unavailable');
    console.error(`${p.url()}\n${shown}`);
  }
  if (log.errors.length) console.error('page errors:', log.errors);
  console.error('last responses:\n' + log.responses.slice(-12).join('\n'));
  if (proxyErrors.length) console.error('proxy errors:', proxyErrors);
  console.error('gateway log tail:\n' + fixture.logs().split('\n').slice(-20).join('\n'));
  // A gateway call that timed out means a handler hung; show where.
  if (error?.name === 'TimeoutError') console.error('goroutines:\n' + (await fixture.dumpGoroutines()).split('\n').slice(-2000).join('\n'));
} finally {
  await browser.close();
  await fixture.close();
}
if (failed) process.exit(1);
