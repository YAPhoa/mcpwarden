// Owner vault and access-window console. It talks to owner routes with the
// browser session cookie only, keeps vault material inside the VaultClient
// worker, and releases one selected credential key only when the owner starts
// a window. Locking, sign-out, account changes, leaving the page and idle time
// terminate the worker and discard results that arrive afterwards.
import {VaultClient} from './vault-client.mjs';
import {OwnerClient, OwnerError, b64url, callsLabel, credentialSaveEffect, destinationDigest, destinationFor, durationLabel, errorMessage, formatRecoveryKey,
  headerBundle, headerValueProblem, parseRecoveryKey, passphraseProblem, publicHandle, remainingLabel, requestPhase, reviewedScope, windowPhase} from './owner-core.mjs';

const $ = id => document.getElementById(id);
export const IDLE_LOCK_MS = 10 * 60 * 1000;
const client = new OwnerClient();
let vault = new VaultClient();

const state = {
  epoch: -1, subject: '', mode: '', visible: false, section: 'access',
  phase: 'idle', // idle | loading | ready | disabled | insecure | unavailable | unsupported | failed
  loaded: false, loading: false, busy: '', generation: 0, bootID: '',
  vaultState: null, wrappers: null, requests: [], windows: [], connections: [], providers: [], tools: [], accessItems: [],
  unlocked: false, setup: null, pending: new Map(), clockOffset: 0, lastActivity: Date.now(), reloadQueued: false,
  renew: null, credential: null,
};

// ---- DOM helpers: untrusted text is only ever assigned as text nodes. ----
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}
// Lists are re-rendered on every refresh; keep keyboard focus on the same
// control (matched by its data attributes) when it is replaced.
function replaceKeepingFocus(container, children) {
  const active = document.activeElement, keys = ['request', 'window', 'connectorId', 'action'];
  const match = container.contains(active) && active !== container ? keys.filter(k => active.dataset?.[k] !== undefined).map(k => [k, active.dataset[k]]) : [];
  container.replaceChildren(...children);
  if (!match.length) return;
  const selector = match.map(([k, v]) => `[data-${k.replace(/[A-Z]/g, c => '-' + c.toLowerCase())}="${CSS.escape(v)}"]`).join('');
  container.querySelector(selector)?.focus();
}
function fact(label, ...value) { return [el('dt', {text: label}), el('dd', {}, ...value)]; }
function exact(value) { return value ? window.MCPWardenTime.format(value) : 'Not set'; }
function serverNow() { return Date.now() + state.clockOffset; }
function sensitiveInputs() { return [...document.querySelectorAll('#vault-page input[type="password"], #vault-credential-dialog input, #vault-verify-key')]; }
function clearSensitiveInputs() { for (const input of sensitiveInputs()) { input.value = ''; input.removeAttribute('aria-invalid'); } }
function setError(id, message, input) {
  $(id).textContent = message || '';
  if (input) { if (message) input.setAttribute('aria-invalid', 'true'); else input.removeAttribute('aria-invalid'); }
  if (message && input) input.focus();
}
// A new notice replaces an earlier page error. A refresh clears only the error
// it reported itself, so an action's error outlives the reload it queues.
let refreshError = false;
function notice(message) { $('vault-notice').textContent = message || ''; $('vault-notice').hidden = !message; if (message) pageError(''); }
function pageError(message, refresh = false) { $('vault-error').textContent = message || ''; refreshError = refresh && Boolean(message); }
function unlocked() { return state.unlocked && vault.active; }
function ownerCaller(id) { return state.accessItems.find(item => item.id === id); }
function handleFor(publicID) { return publicHandle(publicID, state.accessItems.map(item => item.public_id).filter(Boolean)); }
function connectorName(credential) { return credential?.connector_name || 'Unknown connector'; }
function providerHealthy(name) { const p = state.providers.find(p => p.name === name); return !p || p.enabled !== false && (p.healthy || p.custody === 'vault'); }
function currentCredential(id) { return state.wrappers?.credentials.find(c => c.credential_id === id && !c.deleted); }
function setup(x) { return x?.purpose === 'setup_discovery'; }
function callerLabel(x) { return setup(x) ? 'Your browser' : x.requester?.label || x.client?.label || 'Unnamed key'; }
function providerFor(name) { return state.providers.find(p => p.name === name); }
function modeLabel(mode) { return mode === 'none' ? 'No extra confirmation' : 'Confirm each request'; }
function startLabel(mode, seconds) { return `${mode === 'none' ? 'Start access' : 'Allow'} for ${durationLabel(seconds)}`; }

// ---- Locking and lifecycle ----
// lock() ends this browser's vault session only. Agent windows keep running.
function lockBrowser(reason = '') {
  state.generation++;
  client.reset();
  vault.lock();
  vault = new VaultClient();
  const wasUnlocked = state.unlocked || state.setup;
  state.unlocked = false; state.setup = null; state.busy = ''; state.renew = null; state.credential = null;
  if (currentOp) { currentOp.alive = false; currentOp = null; }
  idleControls();
  clearSensitiveInputs();
  $('vault-recovery-key').textContent = '';
  for (const id of ['vault-credential-dialog', 'vault-renew-dialog', 'vault-lock-all-dialog', 'vault-remove-dialog']) if ($(id).open) $(id).close();
  $('vault-setup').hidden = true; $('vault-unlock').hidden = true;
  if (reason && wasUnlocked) notice(reason);
  render();
}
function resetAll() {
  lockBrowser();
  Object.assign(state, {phase: 'idle', loaded: false, loading: false, vaultState: null, wrappers: null, requests: [], windows: [], connections: [], providers: [], tools: [], accessItems: [], pending: new Map(), bootID: '', clockOffset: 0});
  notice(''); pageError('');
  render();
}
function authLost() {
  resetAll();
  window.MCPWardenWorkspace?.authLost();
}
// Every async flow captures the generation before its first await and stops
// if it changed. A changed generation means the operation was cancelled.
function guard(generation) { if (generation !== state.generation) throw new OwnerError(0, 'discarded', errorMessage('discarded')); }
// Submit controls owned by one operation. Locking ends every operation, so it
// restores them all; a cancelled operation never touches them again.
function busyControl(id, label) { const button = $(id); button.dataset.idleLabel ??= button.textContent; button.disabled = true; if (label) button.textContent = label; }
function idleControl(button) { if (button.dataset.idleLabel === undefined) return; button.disabled = false; button.textContent = button.dataset.idleLabel; delete button.dataset.idleLabel; }
function idleControls() { for (const button of document.querySelectorAll('[data-idle-label]')) idleControl(button); }
// Flows with a Cancel control run as an operation. Cancel, a browser lock or
// sign-out ends it; its continuation rechecks after every await and cleans up
// only while it is still the current operation, so a later one is untouched.
let currentOp = null;
function beginOperation(kind) {
  const op = {kind, generation: state.generation, alive: true,
    check() { if (!op.alive || op.generation !== state.generation) throw new OwnerError(0, 'discarded', errorMessage('discarded')); }};
  currentOp = op; state.busy = kind;
  return op;
}
function endOperation(op, control) {
  if (currentOp !== op) return;
  currentOp = null; state.busy = '';
  if (control) idleControl($(control));
  render();
}
function cancelOperation(kind) {
  if (currentOp?.kind !== kind) return false;
  currentOp.alive = false; currentOp = null; state.busy = '';
  idleControls(); render();
  return true;
}
function failed(error, target = 'vault-error', input) {
  if (error?.code === 'discarded') return;
  if (error?.code === 'sign_in_required') { authLost(); return; }
  if (target === 'vault-error') pageError(error?.message || errorMessage(''));
  else setError(target, error?.message || errorMessage(''), input);
  if (['stale', 'conflict', 'not_found', 'locked', 'unavailable', 'destination_mismatch'].includes(error?.code)) queueReload();
}
function queueReload() {
  if (state.reloadQueued) return;
  state.reloadQueued = true;
  setTimeout(() => { state.reloadQueued = false; if (state.visible) load(); }, 0);
}

document.addEventListener('mcpwarden:identity', event => identityChanged(event.detail));
document.addEventListener('mcpwarden:route', event => routeChanged(event.detail));
function identityChanged(detail) {
  // A transient inventory failure keeps the session; only sign-out, a 401/403
  // or another account changes the subject.
  const subject = detail?.session?.subject || '';
  if (detail?.epoch === state.epoch && subject === state.subject) return;
  const changed = state.epoch !== -1;
  state.epoch = detail?.epoch ?? -1; state.subject = subject; state.mode = detail?.session?.mode || '';
  if (changed) resetAll();
  if (state.visible && subject) load();
}
function routeChanged(route) {
  const visible = route?.view === 'vault';
  if (state.visible && !visible) lockBrowser('Vault locked when you left the vault page.');
  state.visible = visible;
  if (visible) state.section = route.section || 'access';
  if (visible && state.subject && !state.loaded && !state.loading) load();
  render();
}
addEventListener('pagehide', () => lockBrowser());
for (const type of ['pointerdown', 'keydown', 'input']) addEventListener(type, () => { state.lastActivity = Date.now(); }, {capture: true, passive: true});
setInterval(() => {
  if ((state.unlocked || state.setup) && Date.now() - state.lastActivity >= IDLE_LOCK_MS) lockBrowser('Vault locked after 10 minutes without activity.');
}, 5000);

// ---- Loading ----
async function plain(path, generation) {
  let response;
  try { response = await fetch(path, {cache: 'no-store', credentials: 'same-origin', headers: {'X-MCPWarden-Request': 'browser'}, redirect: 'error'}); }
  catch { throw new OwnerError(0, 'network', errorMessage('network')); }
  guard(generation);
  if (response.status === 401) throw new OwnerError(401, 'sign_in_required', errorMessage('sign_in_required'));
  if (!response.ok) return null;
  try { return await response.json(); } catch { return null; }
}
let loadRun = 0;
async function load() {
  if (!state.subject) return;
  if (state.mode !== 'account') { state.phase = 'unsupported'; render(); return; }
  // A lock discards this load's results, but the newest load still owns the
  // loading flag so the page can refresh again.
  const generation = state.generation, run = ++loadRun;
  state.loading = true; if (!state.loaded) state.phase = 'loading'; render();
  try {
    const vaultState = (await client.request('GET', '/api/vault/state')).data;
    guard(generation);
    const [wrappers, requests, leases, connections, providers, tools, access] = await Promise.all([
      client.request('GET', '/api/vault/wrappers'), client.request('GET', '/api/access-requests'), client.request('GET', '/api/leases?include=ended'),
      plain('/api/connections', generation), plain('/api/providers', generation), plain('/api/tools', generation), plain('/api/access', generation)]);
    guard(generation);
    if (Number.isFinite(leases.serverDate)) { const offset = leases.serverDate - Date.now(); state.clockOffset = Math.abs(offset) > 2000 ? offset : 0; }
    if (state.bootID && vaultState.gateway_boot_id !== state.bootID) notice('The gateway restarted. Earlier windows are suspended and pending requests expired; start new windows as needed.');
    Object.assign(state, {vaultState, bootID: vaultState.gateway_boot_id, wrappers: wrappers.data, requests: requests.data || [], windows: leases.data || [],
      connections: connections || [], providers: providers || [], tools: tools || [], accessItems: access?.items || [], phase: 'ready', loaded: true});
    if (!vaultState.configured && state.unlocked) lockBrowser();
    if (refreshError) pageError('');
  } catch (error) {
    if (error.code === 'discarded') return;
    if (error.code === 'sign_in_required') { authLost(); return; }
    state.phase = error.code === 'disabled' ? 'disabled' : error.code === 'secure_transport_required' ? 'insecure' : ['locked', 'unavailable'].includes(error.code) ? 'unavailable' : state.loaded ? 'ready' : 'failed';
    if (state.phase === 'ready' || state.phase === 'failed') pageError(`Could not refresh. ${error.message}`, true);
  } finally {
    if (run === loadRun) { state.loading = false; render(); }
  }
}

// ---- Rendering ----
function render() {
  const page = $('vault-page');
  if (!page) return;
  const ready = state.phase === 'ready', configured = Boolean(state.vaultState?.configured), open = unlocked();
  const status = {
    idle: 'Sign in with a local account to use the vault.',
    loading: 'Checking the vault…',
    disabled: 'Owner security is not enabled on this gateway. Only connections without authentication can be used.',
    insecure: 'The vault needs HTTPS through a trusted proxy, or direct local development access. This connection is not trusted, so nothing was sent.',
    unavailable: 'Security storage is unavailable, so execution is locked. Try again later.',
    unsupported: 'The vault is available only for local accounts, not shared operator or OAuth workspaces.',
    failed: 'The vault state could not be loaded. Refresh to try again.',
  }[state.phase] || (state.setup ? 'Setting up. Nothing is saved until you confirm the recovery key.' : !configured ? 'No vault yet. Set one up to encrypt connector credentials in this browser.' : open ? 'Unlocked in this browser. It locks after 10 minutes without activity, when you leave this page, or when you sign out.' : 'Locked in this browser. Unlock it to add credentials or start access windows.');
  $('vault-status-text').textContent = status;
  $('vault-status-title').textContent = ready ? (open ? 'Vault unlocked' : configured ? 'Vault locked' : 'Vault not set up') : 'Vault';
  $('vault-setup-open').hidden = !ready || configured || Boolean(state.setup);
  $('vault-unlock-open').hidden = !ready || !configured || open || !$('vault-unlock').hidden;
  $('vault-lock').hidden = !(open || state.setup);
  $('vault-lock-all').disabled = !ready || Boolean(state.busy);
  $('vault-reload').disabled = state.loading;
  $('vault-setup').hidden = !state.setup && $('vault-setup').hidden;
  const sections = ready ? state.section : '';
  document.querySelector('.vault-nav').hidden = !ready;
  for (const link of document.querySelectorAll('[data-vault-section]')) { if (link.dataset.vaultSection === state.section) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); }
  $('vault-access-panel').hidden = sections !== 'access';
  $('vault-credentials-panel').hidden = sections !== 'credentials';
  $('vault-settings-panel').hidden = sections !== 'settings';
  if (!ready) {
    // Nothing from another session, account or failed load stays on screen.
    for (const id of ['vault-requests', 'vault-windows', 'vault-credentials']) $(id).replaceChildren();
    for (const id of ['vault-request-count', 'vault-window-count']) $(id).textContent = '';
    return;
  }
  renderRequests(); renderWindows(); renderCredentials(); renderSettings(); tick();
}

function callerFacts(requester) {
  const key = ownerCaller(requester.access_id), handle = handleFor(requester.public_id);
  return el('span', {}, el('span', {class: 'untrusted-label', text: requester.label || 'Unnamed key'}), handle ? el('span', {class: 'help', text: ` · key ${handle}`}) : '',
    key?.expires_at ? el('span', {class: 'help', text: ` · key expires ${exact(key.expires_at)}`}) : '');
}
function destinationFacts(credentialID) {
  const d = currentCredential(credentialID)?.destination;
  if (!d) return el('span', {class: 'help', text: 'Not available in this vault'});
  return el('span', {}, el('span', {class: 'mono', text: d.endpoint}), el('span', {class: 'help', text: ` · headers ${d.header_names.join(', ')}`}));
}
function constraintText(c) {
  const value = v => JSON.stringify(v);
  return c.operator === 'equals' ? `${c.pointer} equals ${value(c.value)}` : c.operator === 'in' ? `${c.pointer} is one of ${(c.values || []).map(value).join(', ')}` : `${c.pointer} ${c.operator}`;
}
function toolList(tools) {
  return el('ul', {class: 'vault-tools'}, tools.map(t => {
    const known = state.tools.find(item => item.id === t.tool_id);
    return el('li', {}, el('span', {class: 'mono', text: t.name || known?.name || t.tool_id}),
      known?.description ? el('span', {class: 'tool-summary untrusted-label', text: known.description}) : '',
      el('span', {class: 'help', text: t.constraints?.length ? `Only when ${t.constraints.map(constraintText).join('; ')}` : 'Any arguments the tool accepts'}),
      el('span', {class: 'help mono', text: `Definition ${t.definition_sha256.slice(0, 12)}…`}));
  }));
}
function scopeFacts(r) {
  const caps = [`Starts when you start it and lasts ${durationLabel(r.duration_seconds)}`, 'never longer than 60 minutes'];
  const key = ownerCaller(r.requester.access_id);
  if (key?.expires_at) caps.push(`and ends no later than the key’s expiry`);
  return el('dl', {class: 'vault-facts'},
    fact('Caller', callerFacts(r.requester)),
    fact('Credential', `${connectorName(r.credential)} · version ${r.credential.epoch}`),
    fact('Destination', destinationFacts(r.credential.credential_id)),
    fact('Tools', toolList(r.tools)),
    fact('Working window', caps.join(', ') + '.'),
    fact('Calls', r.max_calls == null ? 'Multiple calls, no call limit. Gateway concurrency and rate limits still apply.' : `Up to ${r.max_calls} calls. Gateway concurrency and rate limits still apply.`));
}

function renderRequests() {
  const now = serverNow();
  const list = [...state.requests].sort((a, b) => Number(!['pending', 'approved'].includes(a.state)) - Number(!['pending', 'approved'].includes(b.state)) || Date.parse(b.created_at) - Date.parse(a.created_at));
  const live = list.filter(r => ['pending', 'approved'].includes(requestPhase(r, now).key));
  $('vault-request-count').textContent = `${live.length} waiting`;
  const container = $('vault-requests');
  replaceKeepingFocus(container, list.length ? list.map(r => requestCard(r, now)) : [el('p', {class: 'empty', text: 'No access requests. When an agent asks for access, it appears here for your review.'})]);
}
// A setup request is the owner's own Connect and inspect. It names no tools and
// lists them once; it never allows a call.
function setupCard(r, phase, pending, busy) {
  const actionable = phase.key === 'pending' || phase.key === 'approved', actions = [];
  if (pending?.uncertain) actions.push(el('p', {class: 'help warning', text: 'The gateway did not confirm whether the inspect window started. Check its status before trying again.'}),
    el('button', {type: 'button', 'data-request': r.id, 'data-action': 'check', disabled: busy, text: 'Check status'}));
  else if (actionable) actions.push(el('button', {type: 'button', 'data-request': r.id, 'data-action': 'deny', disabled: Boolean(state.busy), text: 'Cancel'}),
    el('button', {type: 'button', class: 'primary', 'data-request': r.id, 'data-action': 'inspect', disabled: Boolean(state.busy), 'aria-describedby': unlocked() ? null : 'vault-status-text', text: busy ? 'Inspecting…' : 'Connect and inspect'}));
  return el('article', {class: 'access-row vault-request', 'data-request-card': r.id},
    el('div', {class: 'access-record'}, el('h3', {text: `Connect and inspect ${connectorName(r.credential)}`}),
      el('p', {class: 'record-meta'}, el('span', {class: `badge ${phase.tone}`, text: phase.label}), el('span', {text: `Requested ${exact(r.created_at)}`})),
      el('p', {class: 'help', text: 'Lists the connector’s tools once and saves them. It cannot call a tool.'})),
    actions.length ? el('div', {class: 'access-row-actions'}, actions) : '');
}
function requestCard(r, now) {
  const phase = requestPhase(r, now), pending = state.pending.get(r.id), busy = state.busy === r.id;
  if (setup(r)) return setupCard(r, phase, pending, busy);
  const actionable = phase.key === 'pending' || phase.key === 'approved';
  const heading = actionable ? el('h3', {}, 'Allow ', el('span', {class: 'untrusted-label', text: r.requester.label || 'an unnamed key'}), ` to use ${connectorName(r.credential)}?`) : el('h3', {}, el('span', {class: 'untrusted-label', text: r.requester.label || 'Unnamed key'}), ` · ${connectorName(r.credential)}`);
  const meta = [el('span', {class: `badge ${phase.tone}`, text: phase.label}), el('span', {text: `${modeLabel(r.approval_mode)} · requested ${exact(r.created_at)}`})];
  if (actionable) meta.push(el('span', {}, 'Request expires in ', el('span', {role: 'timer', 'data-deadline': r.expires_at}), ` (${exact(r.expires_at)})`));
  if (phase.key === 'approved' && r.activation_deadline) meta.push(el('span', {}, 'Start within ', el('span', {role: 'timer', 'data-deadline': r.activation_deadline})));
  const actions = [];
  if (pending?.uncertain) {
    actions.push(el('p', {class: 'help warning', text: 'The gateway did not confirm whether this window started. Check its status before trying again; a retry reuses the same activation and cannot start a second window.'}),
      el('button', {type: 'button', 'data-request': r.id, 'data-action': 'check', disabled: busy, text: 'Check status'}),
      el('button', {type: 'button', 'data-request': r.id, 'data-action': 'retry', disabled: busy || !unlocked(), text: 'Retry the same activation'}));
  } else if (actionable) {
    if (phase.key === 'approved' && !unlocked()) actions.push(el('p', {class: 'help warning', text: 'Approved · unlock your vault to activate.'}));
    actions.push(el('button', {type: 'button', 'data-request': r.id, 'data-action': 'deny', disabled: Boolean(state.busy), text: 'Deny'}));
    actions.push(el('button', {type: 'button', class: 'primary', 'data-request': r.id, 'data-action': 'start', disabled: Boolean(state.busy), 'aria-describedby': unlocked() ? null : 'vault-status-text',
      text: busy ? 'Starting…' : phase.key === 'approved' ? 'Start access now' : startLabel(r.approval_mode, r.duration_seconds)}));
  }
  return el('article', {class: 'access-row vault-request', 'data-request-card': r.id},
    el('div', {class: 'access-record'}, heading, el('p', {class: 'record-meta'}, meta), actionable || pending ? scopeFacts(r) : '',
      actionable ? el('p', {class: 'help', text: 'The agent may make multiple permitted calls during this window. Your trusted gateway can use this credential until the window ends. The credential is not returned to the agent.'}) : ''),
    actions.length ? el('div', {class: 'access-row-actions'}, actions) : '');
}

function windowView(l) {
  const phase = windowPhase(l, serverNow(), providerHealthy(l.credential.connector_name));
  // An inspect window ends itself after its one run; that is not a stop.
  if (setup(l) && phase.key === 'revoked') return {...l, phase: {key: 'expired', label: 'Inspect ended', tone: ''}};
  return {...l, phase};
}
function renderWindows() {
  const all = state.windows.map(windowView);
  const filters = {state: $('vault-filter-state').value, caller: $('vault-filter-caller').value, connector: $('vault-filter-connector').value};
  syncFilter('vault-filter-caller', 'All callers', [...new Map(all.map(l => [l.client.access_id, callerLabel(l)])).entries()]);
  syncFilter('vault-filter-connector', 'All connectors', [...new Map(all.map(l => [l.credential.connector_id, connectorName(l.credential)])).entries()]);
  const shown = all.filter(l => (!filters.state || l.phase.key === filters.state) && (!filters.caller || l.client.access_id === filters.caller) && (!filters.connector || l.credential.connector_id === filters.connector));
  const active = all.filter(l => l.phase.key === 'active' || l.phase.key === 'provider').length;
  $('vault-window-count').textContent = `${active} active · ${all.length - active} ended in the last 24 hours`;
  replaceKeepingFocus($('vault-windows'), shown.length ? shown.map(windowCard) : [el('p', {class: 'empty', text: all.length ? 'No windows match these filters.' : 'No access windows yet.'})]);
}
function syncFilter(id, all, entries) {
  const select = $(id), value = select.value;
  entries.sort((a, b) => a[1].localeCompare(b[1]));
  select.replaceChildren(el('option', {value: '', text: all}), ...entries.map(([key, label]) => el('option', {value: key, text: label})));
  select.value = entries.some(([key]) => key === value) ? value : '';
}
function setupWindowCard(l, live) {
  const actions = live ? [el('button', {type: 'button', class: 'danger', 'data-window': l.lease_id, 'data-action': 'stop', disabled: Boolean(state.busy), text: 'Stop'}),
    el('button', {type: 'button', class: 'primary', 'data-window': l.lease_id, 'data-action': 'inspect', disabled: Boolean(state.busy), text: state.busy === l.lease_id ? 'Inspecting…' : 'Inspect now'})] : [];
  const ends = live ? el('span', {}, 'Ends at ', el('strong', {text: exact(l.expires_at)}), ' · ', el('span', {role: 'timer', 'data-deadline': l.expires_at, 'data-window-deadline': l.lease_id}), ' left')
    : el('span', {text: `Ended ${exact(l.ended_at || l.expires_at)}`});
  return el('article', {class: 'access-row vault-window', 'data-window-card': l.lease_id, 'data-state': l.phase.key},
    el('div', {class: 'access-record'}, el('h3', {text: `Connect and inspect · ${connectorName(l.credential)}`}),
      el('p', {class: 'record-meta'}, el('span', {class: `badge ${l.phase.tone}`, text: l.phase.label}), ends, el('span', {text: 'Lists tools only · no tool calls'}))),
    actions.length ? el('div', {class: 'access-row-actions'}, actions) : '');
}
function windowCard(l) {
  const live = l.phase.key === 'active' || l.phase.key === 'provider', handle = handleFor(l.client.public_id);
  if (setup(l)) return setupWindowCard(l, live);
  const actions = [];
  if (live) actions.push(el('button', {type: 'button', class: 'danger', 'data-window': l.lease_id, 'data-action': 'stop', disabled: Boolean(state.busy), text: 'Stop access'}));
  actions.push(el('button', {type: 'button', 'data-window': l.lease_id, 'data-action': 'renew', disabled: Boolean(state.busy), text: 'Renew'}));
  const ends = live ? el('span', {}, 'Ends at ', el('strong', {text: exact(l.expires_at)}), ' · ', el('span', {role: 'timer', 'data-deadline': l.expires_at, 'data-window-deadline': l.lease_id}), ' left')
    : el('span', {text: `${l.phase.key === 'expired' ? 'Ended' : l.phase.key === 'revoked' ? 'Stopped' : 'Suspended'} ${exact(l.ended_at || l.expires_at)}`});
  return el('article', {class: 'access-row vault-window', 'data-window-card': l.lease_id, 'data-state': l.phase.key},
    el('div', {class: 'access-record'},
      el('h3', {}, el('span', {class: 'untrusted-label', text: l.client.label || 'Unnamed key'}), handle ? el('small', {text: ` ${handle}`}) : '', ` · ${connectorName(l.credential)}`),
      el('p', {class: 'record-meta'}, el('span', {class: `badge ${l.phase.tone}`, text: l.phase.label}), ends, el('span', {text: callsLabel(l)})),
      l.phase.key === 'provider' ? el('p', {class: 'help warning', text: 'The provider is not connected. Calls fail until it reconnects; nothing is replayed automatically.'}) : '',
      l.phase.key === 'suspended' ? el('p', {class: 'help', text: 'The gateway restarted or execution was locked. A suspended window never resumes; renew to start a new one.'}) : '',
      el('details', {class: 'record-details'}, el('summary', {text: 'Exact times and approval'}),
        el('dl', {class: 'access-times'},
          el('div', {}, fact('Started', exact(l.activated_at))), el('div', {}, fact('Scheduled end', exact(l.expires_at))),
          l.ended_at ? el('div', {}, fact('Ended', exact(l.ended_at))) : '',
          el('div', {}, fact('Approval', `${modeLabel(l.approval_mode)} · ${l.authorization_source === 'client_activation' ? 'started directly by you' : 'confirmed by you'}`)),
          el('div', {}, fact('Renewal', l.renewal_requires_confirmation ? 'Needs your confirmation and a new start' : 'Needs a new start by you'))))),
    el('div', {class: 'access-row-actions'}, actions));
}

function renderCredentials() {
  const rows = state.connections.map(c => {
    const {destination, reason} = destinationFor(c), stored = state.wrappers?.credentials.find(k => k.connector_id === c.id);
    const status = stored?.deleted ? 'Removed from the vault' : stored ? `Encrypted in vault · version ${stored.epoch}` : 'Not in the vault yet';
    const disabled = !destination || stored?.deleted || !unlocked() || Boolean(state.busy);
    const p = providerFor(c.name), live = stored && !stored.deleted, inspected = Boolean(p?.last_discovered || p?.tool_count);
    const tools = !live ? '' : inspected ? `${p.tool_count} tool${p.tool_count === 1 ? '' : 's'} saved · inspected ${exact(p.last_discovered)}` : 'No tools yet. Connect and inspect to list them.';
    return el('article', {class: 'access-row', 'data-connector': c.id},
      el('div', {class: 'access-record'}, el('h3', {text: c.name}), el('p', {class: 'record-meta'}, el('span', {class: `badge ${live ? 'success' : ''}`, text: status}), el('span', {class: 'mono', text: c.url})),
        el('p', {class: 'help', text: destination ? `Header${c.header_names.length === 1 ? '' : 's'}: ${c.header_names.join(', ')}` : reason}),
        tools ? el('p', {class: 'help', text: tools}) : ''),
      el('div', {class: 'access-row-actions'},
        live ? el('button', {type: 'button', class: 'primary', 'data-inspect-connector': c.id, disabled: !unlocked() || Boolean(state.busy) || p?.enabled === false, 'aria-describedby': unlocked() ? null : 'vault-status-text',
          text: state.busy === c.id ? 'Inspecting…' : inspected ? 'Connect and inspect again' : 'Connect and inspect'}) : '',
        el('button', {type: 'button', 'data-connector-id': c.id, disabled, 'aria-describedby': unlocked() ? null : 'vault-status-text', text: stored ? 'Replace credential' : 'Add encrypted credential'}),
        // Removing needs no key, so it stays available while the vault is locked.
        stored && !stored.deleted ? el('button', {type: 'button', class: 'danger', 'data-remove-connector': c.id, disabled: Boolean(state.busy), text: 'Remove'}) : ''));
  });
  replaceKeepingFocus($('vault-credentials'), rows.length ? rows : [el('p', {class: 'empty', text: 'Add a personal HTTP upstream with header authentication first. Its credential can then be encrypted here.'})]);
}
function renderSettings() {
  const p = state.vaultState?.approval_policy;
  if (p && !state.busy) for (const input of document.querySelectorAll('[name="vault-policy-mode"]')) if (!$('vault-policy-form').dataset.dirty) input.checked = input.value === p.mode;
  $('vault-policy-current').textContent = p ? `Current: ${modeLabel(p.mode)}${p.changed_at ? ` since ${exact(p.changed_at)}` : ' (default)'}.` : '';
  $('vault-policy-save').disabled = Boolean(state.busy);
  const open = unlocked();
  for (const id of ['vault-change-passphrase', 'vault-change-confirm', 'vault-change-password', 'vault-passphrase-save']) $(id).disabled = !open || Boolean(state.busy);
  $('vault-passphrase-help').textContent = open ? 'Changing the passphrase protects future copies; an old backup can still be opened with the old passphrase. Your recovery key stays the same.' : 'Unlock the vault first to change its passphrase.';
}

// Countdowns come from server end times; traffic never changes them.
function tick() {
  const now = serverNow();
  let ended = false;
  for (const node of document.querySelectorAll('#vault-page [data-deadline]')) {
    const left = Date.parse(node.dataset.deadline) - now;
    node.textContent = remainingLabel(left);
    if (left <= 0 && node.dataset.windowDeadline) ended = true;
  }
  if (ended && !state.loading) queueReload();
}
setInterval(() => { if (state.visible && state.phase === 'ready') tick(); }, 1000);

// ---- Vault setup ----
$('vault-setup-open').addEventListener('click', () => {
  pageError(''); $('vault-setup').hidden = false; showSetupStep(1); $('vault-new-passphrase').focus();
});
function showSetupStep(step) {
  $('vault-setup-form').hidden = step !== 1; $('vault-recovery-step').hidden = step !== 2; $('vault-verify-form').hidden = step !== 3;
  for (const item of document.querySelectorAll('[data-setup-step]')) { if (Number(item.dataset.setupStep) === step) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current'); }
  if (step !== 2) $('vault-recovery-key').textContent = '';
}
function cancelSetup() { lockBrowser(); notice('Setup cancelled. Nothing was saved.'); $('vault-setup-open').focus(); }
for (const id of ['vault-setup-cancel', 'vault-recovery-cancel', 'vault-verify-cancel']) $(id).addEventListener('click', cancelSetup);
$('vault-setup-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  const passphrase = $('vault-new-passphrase').value, problem = passphraseProblem(passphrase, $('vault-new-confirm').value);
  if (problem) { setError('vault-setup-error', problem, $('vault-new-passphrase')); return; }
  setError('vault-setup-error', '', $('vault-new-passphrase'));
  clearSensitiveInputs();
  const generation = state.generation, worker = vault; state.busy = 'setup'; busyControl('vault-setup-create', 'Creating…');
  try {
    const result = await worker.setup({owner_id: state.subject, passphrase});
    guard(generation);
    const {recovery_key: recoveryKey, ...root} = result;
    const formatted = await formatRecoveryKey(recoveryKey);
    guard(generation);
    state.setup = {root, recoveryKey, formatted};
    $('vault-recovery-key').textContent = formatted; $('vault-recovery-copy-status').textContent = '';
    showSetupStep(2); $('vault-recovery-key').focus();
  } catch (error) {
    if (error.code !== 'discarded') { worker.lock(); setError('vault-setup-error', 'The vault could not be created in this browser. Try again.', $('vault-new-passphrase')); }
  } finally {
    if (generation === state.generation) { state.busy = ''; idleControl($('vault-setup-create')); render(); }
  }
});
$('vault-recovery-copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(state.setup?.formatted || ''); $('vault-recovery-copy-status').textContent = 'Copied. Paste it somewhere safe, then clear your clipboard.'; }
  catch { $('vault-recovery-copy-status').textContent = 'Copy is not available. Select the key and write it down.'; }
});
$('vault-recovery-saved').addEventListener('click', () => { showSetupStep(3); $('vault-verify-key').focus(); });
$('vault-verify-back').addEventListener('click', () => { if (!state.setup) return; clearSensitiveInputs(); $('vault-recovery-key').textContent = state.setup.formatted; showSetupStep(2); $('vault-recovery-key').focus(); });
$('vault-verify-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy || !state.setup) return;
  const typed = $('vault-verify-key').value, password = $('vault-setup-password').value;
  if (!password) { setError('vault-verify-error', 'Enter your account password.', $('vault-setup-password')); return; }
  const generation = state.generation, {root, recoveryKey} = state.setup; state.busy = 'setup'; busyControl('vault-verify-submit', 'Verifying…');
  const check = new VaultClient();
  try {
    let encoded;
    try { encoded = await parseRecoveryKey(typed); } catch (error) { guard(generation); throw new OwnerError(0, 'verify', error.message); }
    guard(generation);
    if (encoded !== recoveryKey) throw new OwnerError(0, 'verify', 'This is not the recovery key shown for this vault. Check each group and try again.');
    setError('vault-verify-error', '', $('vault-verify-key'));
    $('vault-setup-password').value = ''; $('vault-verify-key').value = '';
    // Prove the typed key opens the recovery wrapper before anything is saved.
    const w = root.recovery;
    await check.unlockRecovery({context: {owner_id: w.owner_id, root_id: w.root_id, root_version: w.root_version, wrapper_id: w.wrapper_id, method: 'recovery'}, wrapper: JSON.stringify(w), recovery_key: encoded});
    check.lock(); guard(generation);
    await client.request('POST', '/api/vault/setup', {body: JSON.stringify({current_password: password, root})});
    guard(generation);
    state.setup = null; state.unlocked = true; $('vault-setup').hidden = true;
    notice('Vault ready. Your recovery key worked, and only encrypted data was saved.');
    await load(); $('vault-status-title').focus();
  } catch (error) {
    check.lock();
    if (error.code === 'discarded') return;
    if (error.code === 'verify') { setError('vault-verify-error', error.message, $('vault-verify-key')); return; }
    if (error.code === 'conflict' || error.code === 'invalid') { lockBrowser(); pageError('A vault already exists for this account, perhaps from another browser. Unlock it instead.'); load(); return; }
    if (error instanceof OwnerError) failed(error, 'vault-verify-error', $('vault-setup-password'));
    else setError('vault-verify-error', 'The recovery key could not be verified. Try again.', $('vault-verify-key'));
  } finally {
    if (generation === state.generation) { state.busy = ''; idleControl($('vault-verify-submit')); render(); }
  }
});

// ---- Unlock and lock ----
$('vault-unlock-open').addEventListener('click', () => openUnlock());
function openUnlock(message = '') {
  $('vault-unlock').hidden = false; setError('vault-unlock-error', message); render(); $('vault-unlock-secret').focus();
}
// Cancel ends a pending unlock: its worker is terminated and nothing opens later.
$('vault-unlock-cancel').addEventListener('click', () => { if (cancelOperation('unlock')) { vault.lock(); vault = new VaultClient(); } clearSensitiveInputs(); $('vault-unlock').hidden = true; setError('vault-unlock-error', ''); render(); $('vault-unlock-open').focus(); });
for (const radio of document.querySelectorAll('[name="vault-unlock-method"]')) radio.addEventListener('change', () => {
  const recovery = document.querySelector('[name="vault-unlock-method"]:checked')?.value === 'recovery';
  $('vault-unlock-label').textContent = recovery ? 'Recovery key' : 'Vault passphrase';
  $('vault-unlock-secret').value = ''; $('vault-unlock-secret').autocomplete = recovery ? 'off' : 'current-password';
});
$('vault-unlock-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  const method = document.querySelector('[name="vault-unlock-method"]:checked')?.value === 'recovery' ? 'recovery' : 'passphrase';
  const secret = $('vault-unlock-secret').value;
  if (!secret) { setError('vault-unlock-error', method === 'recovery' ? 'Enter your recovery key.' : 'Enter your vault passphrase.', $('vault-unlock-secret')); return; }
  // Leaving the page while this runs locks the vault and replaces the worker;
  // this operation keeps its own worker and generation and never unlocks later.
  const op = beginOperation('unlock'), worker = vault; busyControl('vault-unlock-submit', 'Unlocking…');
  try {
    let recoveryKey = '';
    if (method === 'recovery') { try { recoveryKey = await parseRecoveryKey(secret); } catch (error) { op.check(); throw new OwnerError(0, 'unlock', error.message); } }
    op.check();
    $('vault-unlock-secret').value = '';
    const wrappers = (await client.request('GET', '/api/vault/wrappers')).data;
    op.check();
    const w = wrappers.root?.[method];
    if (!w || w.owner_id !== state.subject) throw new OwnerError(404, 'not_found', 'No vault is set up for this account.');
    const context = {owner_id: w.owner_id, root_id: w.root_id, root_version: w.root_version, wrapper_id: w.wrapper_id, method};
    try {
      if (method === 'recovery') await worker.unlockRecovery({context, wrapper: JSON.stringify(w), recovery_key: recoveryKey});
      else await worker.unlockPassphrase({context, wrapper: JSON.stringify(w), passphrase: secret});
    } catch { op.check(); worker.lock(); vault = new VaultClient(); throw new OwnerError(0, 'unlock', method === 'recovery' ? 'That recovery key did not unlock the vault.' : 'That passphrase did not unlock the vault.'); }
    op.check();
    state.unlocked = true; state.wrappers = wrappers; state.lastActivity = Date.now();
    $('vault-unlock').hidden = true; setError('vault-unlock-error', '');
    notice(method === 'recovery' ? 'Unlocked with your recovery key. If you forgot your passphrase, set a new one in Vault settings.' : 'Vault unlocked in this browser.');
    render(); $('vault-lock').focus();
  } catch (error) {
    if (error.code === 'unlock') setError('vault-unlock-error', error.message, $('vault-unlock-secret'));
    else failed(error, 'vault-unlock-error', $('vault-unlock-secret'));
  } finally {
    endOperation(op, 'vault-unlock-submit');
  }
});
$('vault-lock').addEventListener('click', () => { lockBrowser('Vault locked in this browser. Access windows you started keep running until they end.'); load(); $('vault-status-title').focus(); });
$('vault-reload').addEventListener('click', () => { pageError(''); load(); });

// ---- Lock all execution ----
$('vault-lock-all').addEventListener('click', () => { setError('vault-lock-all-error', ''); $('vault-lock-all-dialog').showModal(); $('vault-lock-all-cancel').focus(); });
$('vault-lock-all-cancel').addEventListener('click', () => $('vault-lock-all-dialog').close());
$('vault-lock-all-dialog').addEventListener('close', () => $('vault-lock-all').focus());
$('vault-lock-all-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  const generation = state.generation; state.busy = 'lock-all'; busyControl('vault-lock-all-confirm');
  try {
    await client.request('POST', '/api/vault/lock-execution', {body: '{}'});
    guard(generation);
    $('vault-lock-all-dialog').close();
    notice('All access windows for your account were stopped. Your vault in this browser was not changed.');
    await load();
  } catch (error) { failed(error, 'vault-lock-all-error'); }
  finally { if (generation === state.generation) { state.busy = ''; idleControl($('vault-lock-all-confirm')); render(); if (!$('vault-lock-all-dialog').open) $('vault-lock-all').focus(); } }
});

// ---- Requests: deny, confirm and explicit activation ----
$('vault-requests').addEventListener('click', event => {
  const button = event.target.closest('button[data-request]');
  if (!button || state.busy) return;
  const request = state.requests.find(r => r.id === button.dataset.request);
  if (!request) return;
  const action = button.dataset.action;
  if (action === 'deny') deny(request);
  else if (action === 'start') start(request);
  else if (action === 'retry') activate(request, state.pending.get(request.id)?.operation);
  else if (action === 'check') checkRequest(request);
  else if (action === 'inspect') inspectRequest(request);
});
async function deny(request) {
  const generation = state.generation; state.busy = request.id; render();
  try { await client.request('POST', `/api/approvals/${request.id}/deny`, {body: '{}'}); guard(generation); notice('Request denied. The agent can ask again.'); await load(); }
  catch (error) { failed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
async function start(request) {
  if (!unlocked()) { openUnlock('Unlock your vault, then start access again.'); return; }
  const generation = state.generation; state.busy = request.id; render();
  try {
    let current = request;
    if (current.approval_mode === 'confirm' && current.state === 'pending') {
      current = (await client.request('POST', `/api/approvals/${request.id}/begin`, {body: JSON.stringify({request_digest: request.request_digest})})).data;
      guard(generation);
    }
    state.busy = '';
    await activate(current);
  } catch (error) { failed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
// activate releases exactly this request's credential key. The operation ID is
// kept until the outcome is known, so a retry after an uncertain response
// returns the same window instead of starting a new one.
async function activate(request, operation = crypto.randomUUID()) {
  if (!unlocked()) { openUnlock('Unlock your vault to start access.'); return; }
  const generation = state.generation; state.busy = request.id; render();
  try {
    await release(request, operation, generation);
    notice(`Access started for ${request.requester.label || 'the agent'}. The countdown uses the gateway’s end time.`);
    await load();
    document.querySelector('#vault-windows [data-window-card] button')?.focus();
  } catch (error) {
    if (error.code === 'release') { pageError(error.message); return; }
    if (error.uncertain) { pageError('The gateway did not confirm whether access started. Check its status before trying again.'); render(); return; }
    failed(error);
  } finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
// release decrypts this request's credential key in the vault worker and sends
// it once to start the window, which it returns.
async function release(request, operation, generation) {
  let key;
  try {
    const credential = currentCredential(request.credential.credential_id);
    if (!credential || credential.epoch !== request.credential.epoch || !credential.envelope) throw new OwnerError(409, 'stale', 'This credential changed after the request. Ask the agent for a new request, or renew.');
    const root = state.wrappers.root;
    const context = {owner_id: state.subject, root_id: root.root_id, root_version: root.root_version, connector_id: credential.connector_id, credential_id: credential.credential_id, epoch: credential.epoch};
    const digest = await destinationDigest(credential.destination);
    guard(generation);
    try { key = await vault.releaseCredential({context, revision: credential.revision, destination_profile_sha256: digest, wrapped_key: JSON.stringify(credential.wrapped_key), envelope: JSON.stringify(credential.envelope)}); }
    catch { guard(generation); throw new OwnerError(0, 'release', 'This browser could not decrypt the credential. Reload, then try again.'); }
    guard(generation);
    const body = JSON.stringify({gateway_boot_id: request.gateway_boot_id, request_digest: request.request_digest, challenge: request.challenge, credential_id: request.credential.credential_id, credential_epoch: request.credential.epoch, cek: b64url(key)});
    key.fill(0); key = null;
    state.pending.set(request.id, {operation, uncertain: false});
    let started;
    try {
      started = (await client.request('POST', `/api/approvals/${request.id}/activate`, {body, idempotencyKey: operation})).data;
    } catch (error) {
      if (error.uncertain) { state.pending.set(request.id, {operation, uncertain: true}); throw error; }
      state.pending.delete(request.id); throw error;
    }
    guard(generation);
    state.pending.delete(request.id);
    return started;
  } finally { key?.fill(0); }
}

// ---- Connect and inspect ----
// A setup window belongs to this browser session only and lasts at most five
// minutes. The gateway connects once through the vault credential, saves the
// tool list and ends the window in the same step. It never calls a tool, and
// the list does not grant any agent access.
$('vault-credentials').addEventListener('click', event => {
  const button = event.target.closest('button[data-inspect-connector]');
  if (!button || state.busy) return;
  const connection = state.connections.find(c => c.id === button.dataset.inspectConnector);
  const stored = state.wrappers?.credentials.find(k => k.connector_id === button.dataset.inspectConnector && !k.deleted);
  if (connection && stored) inspect(connection, stored);
});
async function inspect(connection, stored) {
  if (!unlocked()) { openUnlock('Unlock your vault, then connect and inspect again.'); return; }
  const generation = state.generation; state.busy = connection.id; render();
  try {
    const request = (await client.request('POST', '/api/access-requests', {body: JSON.stringify({purpose: 'setup_discovery', credential_id: stored.credential_id, duration_seconds: 300})})).data;
    guard(generation);
    await inspectStarted(request, generation, connection.name);
  } catch (error) { inspectFailed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
async function inspectRequest(request) {
  if (!unlocked()) { openUnlock('Unlock your vault, then connect and inspect again.'); return; }
  const generation = state.generation; state.busy = request.id; render();
  try { await inspectStarted(request, generation, connectorName(request.credential)); }
  catch (error) { inspectFailed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
async function inspectStarted(request, generation, name) {
  let current = request;
  if (current.approval_mode === 'confirm' && current.state === 'pending') {
    current = (await client.request('POST', `/api/approvals/${request.id}/begin`, {body: JSON.stringify({request_digest: request.request_digest})})).data;
    guard(generation);
  }
  const started = await release(current, crypto.randomUUID(), generation);
  await discover(started.lease_id, name, generation);
}
async function discover(leaseID, name, generation) {
  const result = (await client.request('POST', `/api/leases/${leaseID}/discover`, {body: '{}'})).data;
  guard(generation);
  notice(`${name}: saved ${result.tool_count} tool${result.tool_count === 1 ? '' : 's'}. The inspect window has ended; agents still need an access window to call them.`);
  await load();
}
function inspectFailed(error) {
  if (error.code === 'release') { pageError(error.message); return; }
  if (error.code === 'stale') error = new OwnerError(error.status, 'stale', 'The inspect window ended, or the credential or connector changed. Reload, then connect and inspect again.');
  failed(error);
  queueReload();
}
async function checkRequest(request) {
  const generation = state.generation; state.busy = request.id; render();
  try {
    const current = (await client.request('GET', `/api/access-requests/${request.id}`)).data;
    guard(generation);
    if (current.state === 'activated') { state.pending.delete(request.id); notice('Access did start. The window is listed below.'); }
    else if (!['pending', 'approved'].includes(requestPhase(current, serverNow()).key)) { state.pending.delete(request.id); notice('This request can no longer start. Renew or ask the agent for a new request.'); }
    else notice('Access has not started. You can retry the same activation.');
    await load();
  } catch (error) { failed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}

// ---- Windows: stop and renew ----
for (const id of ['vault-filter-state', 'vault-filter-caller', 'vault-filter-connector']) $(id).addEventListener('change', renderWindows);
$('vault-windows').addEventListener('click', event => {
  const button = event.target.closest('button[data-window]');
  if (!button || state.busy) return;
  const l = state.windows.find(w => w.lease_id === button.dataset.window);
  if (!l) return;
  if (button.dataset.action === 'stop') stop(l);
  else if (button.dataset.action === 'inspect') inspectWindow(l);
  else openRenew(l, button);
});
async function stop(l) {
  const generation = state.generation; state.busy = l.lease_id; render();
  try { await client.request('DELETE', `/api/leases/${l.lease_id}`); guard(generation); notice(`Access stopped for ${l.client.label || 'the agent'}. Calls already running may finish.`); await load(); }
  catch (error) { failed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
async function inspectWindow(l) {
  const generation = state.generation; state.busy = l.lease_id; render();
  try { await discover(l.lease_id, connectorName(l.credential), generation); }
  catch (error) { inspectFailed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
// Dialog triggers are re-rendered while open, so focus returns by identity.
let renewTrigger = '';
async function openRenew(l, trigger) {
  const generation = state.generation; state.busy = l.lease_id; render();
  try {
    const request = (await client.request('GET', `/api/access-requests/${l.request_id}`)).data;
    guard(generation);
    state.renew = {request, lease: l}; renewTrigger = trigger.dataset.window;
    const mode = state.vaultState?.approval_policy?.mode || 'confirm';
    $('vault-renew-scope').replaceChildren(scopeFacts({...request, duration_seconds: Number($('vault-renew-duration').value)}));
    $('vault-renew-duration').value = '900';
    updateRenewLabel(mode);
    setError('vault-renew-error', '');
    $('vault-renew-dialog').showModal(); $('vault-renew-duration').focus();
  } catch (error) { failed(error); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
}
function updateRenewLabel(mode = state.vaultState?.approval_policy?.mode || 'confirm') {
  const seconds = Number($('vault-renew-duration').value);
  $('vault-renew-submit').textContent = startLabel(mode, seconds);
  if (state.renew) $('vault-renew-scope').replaceChildren(scopeFacts({...state.renew.request, duration_seconds: seconds}));
}
$('vault-renew-duration').addEventListener('change', () => updateRenewLabel());
$('vault-renew-cancel').addEventListener('click', () => $('vault-renew-dialog').close());
// However the dialog closes (Cancel, Escape), a pending renewal ends before any
// key is released. Once Allow goes ahead the operation has already ended.
$('vault-renew-dialog').addEventListener('close', () => { cancelOperation('renew'); state.renew = null; focusOr(`#vault-windows button[data-window="${renewTrigger}"][data-action="renew"]`); });
function focusOr(selector) { (document.querySelector(selector) || $('vault-title')).focus(); }
$('vault-renew-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy || !state.renew) return;
  if (!unlocked()) { setError('vault-renew-error', 'Unlock your vault first. Renewal releases this credential’s key when access starts.'); return; }
  const {request} = state.renew, duration = Number($('vault-renew-duration').value), op = beginOperation('renew'); busyControl('vault-renew-submit');
  try {
    const body = {requester_access_id: request.requester.access_id, credential_id: request.credential.credential_id, duration_seconds: duration, max_calls: request.max_calls,
      tools: request.tools.map(t => ({tool_id: t.tool_id, constraints: t.constraints}))};
    const created = (await client.request('POST', '/api/access-requests', {body: JSON.stringify(body)})).data;
    op.check();
    // The gateway binds the new request to current tool definitions and the
    // current credential version. If those moved since this dialog was drawn,
    // show the new request and release nothing until the owner reviews it.
    if (reviewedScope(created) !== reviewedScope(request, duration)) {
      await load();
      op.check();
      if (!state.renew) return;
      state.renew.request = created;
      $('vault-renew-scope').replaceChildren(scopeFacts(created));
      setError('vault-renew-error', 'This request changed after you opened it, for example a tool definition or the credential version. Review it below, then allow it again.');
      return;
    }
    endOperation(op, 'vault-renew-submit');
    $('vault-renew-dialog').close();
    await start(created);
  } catch (error) { failed(error, 'vault-renew-error'); }
  finally { endOperation(op, 'vault-renew-submit'); }
});

// ---- Credentials ----
let credentialTrigger = '';
$('vault-credentials').addEventListener('click', event => {
  const button = event.target.closest('button[data-connector-id]');
  if (!button || state.busy || !unlocked()) return;
  const connection = state.connections.find(c => c.id === button.dataset.connectorId);
  const {destination} = destinationFor(connection);
  if (!connection || !destination) return;
  const stored = state.wrappers?.credentials.find(k => k.connector_id === connection.id && !k.deleted);
  state.credential = {connection, destination, stored}; credentialTrigger = connection.id;
  $('vault-credential-title').textContent = stored ? `Replace credential for ${connection.name}` : `Add credential for ${connection.name}`;
  $('vault-credential-context').textContent = 'Values are encrypted in this browser. The gateway stores only ciphertext for the vault copy.';
  $('vault-credential-facts').replaceChildren(...fact('Connector', connection.name), ...fact('Endpoint', el('span', {class: 'mono', text: connection.url})), ...fact('Network', destination.network === 'public' ? 'Public HTTPS' : 'This machine (development HTTP)'));
  $('vault-credential-fields').replaceChildren(...connection.header_names.map((name, i) => {
    const bearer = connection.auth_type === 'bearer' && name.toLowerCase() === 'authorization';
    return el('label', {for: `vault-header-${i}`, text: bearer ? 'Bearer token' : `${name} header value`}, el('input', {id: `vault-header-${i}`, type: 'password', autocomplete: 'off', spellcheck: 'false', 'data-header': name, 'aria-describedby': 'vault-credential-error'}));
  }));
  $('vault-credential-effect').textContent = credentialSaveEffect(Boolean(stored));
  setError('vault-credential-error', '');
  $('vault-credential-dialog').showModal(); $('vault-header-0')?.focus();
});
$('vault-credential-cancel').addEventListener('click', () => $('vault-credential-dialog').close());
// Closing the dialog before the upload is sent ends a pending save.
$('vault-credential-dialog').addEventListener('close', () => { cancelOperation('credential'); for (const input of $('vault-credential-fields').querySelectorAll('input')) input.value = ''; $('vault-credential-fields').replaceChildren(); state.credential = null; focusOr(`#vault-credentials button[data-connector-id="${credentialTrigger}"]`); });
$('vault-credential-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy || !state.credential) return;
  if (!unlocked()) { setError('vault-credential-error', 'The vault locked. Unlock it and try again.'); return; }
  const values = {};
  for (const input of $('vault-credential-fields').querySelectorAll('input[data-header]')) {
    const problem = headerValueProblem(input.value);
    if (problem) { setError('vault-credential-error', `${input.labels[0]?.firstChild?.textContent || 'Value'}: ${problem}`, input); return; }
    values[input.dataset.header] = input.value;
  }
  const {connection, destination, stored} = state.credential, root = state.wrappers.root;
  const bundle = headerBundle(connection, values);
  for (const input of $('vault-credential-fields').querySelectorAll('input')) input.value = '';
  for (const name of Object.keys(values)) values[name] = '';
  const op = beginOperation('credential'), generation = op.generation, worker = vault; busyControl('vault-credential-save', 'Encrypting…');
  try {
    const context = {owner_id: state.subject, root_id: root.root_id, root_version: root.root_version, connector_id: connection.id, credential_id: stored?.credential_id || crypto.randomUUID(), epoch: stored ? String(BigInt(stored.epoch) + 1n) : '1'};
    const digest = await destinationDigest(destination);
    op.check();
    let sealed;
    try { sealed = await worker.createCredential({context, revision: '1', destination_profile_sha256: digest, bundle}); }
    catch { op.check(); throw new OwnerError(0, 'encrypt', 'This browser could not encrypt the credential. Unlock the vault again and retry.'); }
    op.check();
    const record = {...context, revision: '1', destination, wrapped_key: sealed.wrapped_key, envelope: sealed.envelope};
    // Once the upload is sent it may land, so closing the dialog no longer
    // discards the outcome; only a lock does. A cancelled save still reports
    // it, but the dialog may now hold a newer form, which it leaves alone.
    await client.request('PUT', `/api/vault/credentials/${context.credential_id}`, {body: JSON.stringify({expected: stored ? {epoch: stored.epoch, revision: stored.revision} : null, record})});
    guard(generation);
    if (op.alive) { endOperation(op, 'vault-credential-save'); $('vault-credential-dialog').close(); }
    notice(`${connection.name}: credential encrypted and saved as version ${context.epoch}. Pending requests and access windows for your account were ended.`);
    await load();
  } catch (error) {
    if (!op.alive) failed(error.code === 'discarded' ? error : new OwnerError(error.status, error.code, `The gateway did not confirm an earlier save for ${connection.name}. ${error.message || errorMessage('')}`));
    else if (error.code === 'encrypt') setError('vault-credential-error', error.message);
    else failed(error, 'vault-credential-error');
  } finally { endOperation(op, 'vault-credential-save'); }
});

// Removal writes a tombstone, so this connector cannot get a vault copy again.
let removing = null;
$('vault-credentials').addEventListener('click', event => {
  const button = event.target.closest('button[data-remove-connector]');
  if (!button || state.busy) return;
  const connection = state.connections.find(c => c.id === button.dataset.removeConnector);
  const stored = state.wrappers?.credentials.find(k => k.connector_id === button.dataset.removeConnector && !k.deleted);
  if (!connection || !stored) return;
  removing = {connection, stored};
  $('vault-remove-title').textContent = `Remove the vault credential for ${connection.name}?`;
  setError('vault-remove-error', '');
  $('vault-remove-dialog').showModal(); $('vault-remove-cancel').focus();
});
$('vault-remove-cancel').addEventListener('click', () => $('vault-remove-dialog').close());
$('vault-remove-dialog').addEventListener('close', () => {
  const id = removing?.connection.id; removing = null;
  focusOr(`#vault-credentials button[data-remove-connector="${id}"], #vault-credentials button[data-connector-id="${id}"]`);
});
$('vault-remove-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy || !removing) return;
  const {connection, stored} = removing, generation = state.generation; state.busy = 'remove'; busyControl('vault-remove-confirm', 'Removing…');
  try {
    await client.request('DELETE', `/api/vault/credentials/${stored.credential_id}`, {body: JSON.stringify({expected: {epoch: stored.epoch, revision: stored.revision}})});
    guard(generation);
    $('vault-remove-dialog').close();
    notice(`${connection.name}: vault credential removed. Pending requests and access windows for your account were ended.`);
    await load();
  } catch (error) { failed(error, 'vault-remove-error'); }
  finally { if (generation === state.generation) { state.busy = ''; idleControl($('vault-remove-confirm')); render(); } }
});

// ---- Settings: approval mode and passphrase ----
for (const input of document.querySelectorAll('[name="vault-policy-mode"]')) input.addEventListener('change', () => { $('vault-policy-form').dataset.dirty = '1'; });
$('vault-policy-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  const mode = document.querySelector('[name="vault-policy-mode"]:checked')?.value, password = $('vault-policy-password').value, policy = state.vaultState?.approval_policy;
  if (!policy || !mode) return;
  if (mode === policy.mode) { setError('vault-policy-error', 'This mode is already active.'); return; }
  if (!password) { setError('vault-policy-error', 'Enter your account password.', $('vault-policy-password')); return; }
  $('vault-policy-password').value = '';
  const generation = state.generation; state.busy = 'policy'; render();
  try {
    await client.request('PUT', '/api/security/approval-policy', {body: JSON.stringify({mode, expected_revision: policy.revision, current_password: password})});
    guard(generation);
    delete $('vault-policy-form').dataset.dirty; setError('vault-policy-error', '');
    notice(`Approval mode saved: ${modeLabel(mode)}. Pending requests and access windows were ended.`);
    await load();
  } catch (error) { failed(error, 'vault-policy-error', $('vault-policy-password')); }
  finally { if (generation === state.generation) { state.busy = ''; render(); } }
});
$('vault-passphrase-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  if (!unlocked()) { setError('vault-passphrase-error', 'Unlock the vault first.'); return; }
  const passphrase = $('vault-change-passphrase').value, password = $('vault-change-password').value;
  const problem = passphraseProblem(passphrase, $('vault-change-confirm').value);
  if (problem) { setError('vault-passphrase-error', problem, $('vault-change-passphrase')); return; }
  if (!password) { setError('vault-passphrase-error', 'Enter your account password.', $('vault-change-password')); return; }
  for (const id of ['vault-change-passphrase', 'vault-change-confirm', 'vault-change-password']) $(id).value = '';
  const generation = state.generation; state.busy = 'passphrase'; render();
  try {
    let wrapper;
    try { wrapper = await vault.changePassphrase({passphrase}); } catch { guard(generation); throw new OwnerError(0, 'rewrap', 'This browser could not create the new passphrase wrapper. Unlock again and retry.'); }
    guard(generation);
    const current = (await client.request('GET', '/api/vault/wrappers')).data.root;
    guard(generation);
    const root = {owner_id: state.subject, root_id: current.root_id, root_version: current.root_version, wrapper_revision: String(BigInt(current.wrapper_revision) + 1n), passphrase: wrapper, recovery: current.recovery};
    await client.request('PUT', '/api/vault/wrappers', {body: JSON.stringify({current_password: password, expected_wrapper_revision: current.wrapper_revision, root})});
    guard(generation);
    setError('vault-passphrase-error', '');
    notice('Vault passphrase changed. Use the new passphrase from now on; older backups still open with the old one. Pending requests and access windows were ended.');
    await load();
  } catch (error) {
    if (error.code === 'rewrap') setError('vault-passphrase-error', error.message);
    else failed(error, 'vault-passphrase-error', $('vault-change-password'));
  } finally { if (generation === state.generation) { state.busy = ''; render(); } }
});

// Pick up the workspace state if app.js announced it before this module ran.
const current = window.MCPWardenWorkspace?.current();
if (current) { identityChanged(current); routeChanged(current.route); }
