const $ = id => document.getElementById(id);
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
let accessData = null, accessLoading = false, accessAction = null, keyMinting = false;
let initialLoad = true;
let token = '', session = null, accountMode = 'operator', registering = false, identityEpoch = 0;
// Remove credentials persisted by earlier versions. Never read or migrate them.
try { sessionStorage.removeItem('mcpwarden-token'); } catch (_) { /* Storage may be disabled. */ }
let providers = [], tools = [], connections = new Map(), selected = '', access = false, loaded = false;
let managedAvailable = false, loading = false, mutating = false, pendingProvider = null;
const refreshState = new Map();
const dialogTriggers = new Map();
const toolViews = new Map();
const connectorScroll = new Map();
// Row expansion is kept per tool key until the workspace changes. A failed save keeps the visibility
// it asked for, so Retry repeats that request; it clears once any save or reload reaches that value.
const expandedTools = new Set(), toolErrors = new Map();
let bulkRequest = null, toastTimer = 0;
function toolScope() {
  const route = readRoute();
  return route.view === 'detail' ? route.name : route.view === 'tools' ? route.provider : '';
}
function toolView() {
  const key = toolScope();
  if (!toolViews.has(key)) toolViews.set(key, {query: '', filter: 'all', page: 1, size: 10});
  return toolViews.get(key);
}
function toolKey(t) { return t.id || t.name; }
function toolLabel(t) { return t.display_name || t.name; }
function isToolDiscoverable(t) { return Boolean(t.allowed && t.visible); }
function isDiscoverable(t) { return Boolean(t.allowed && t.healthy && t.visible && providers.find(p => p.name === t.upstream)?.enabled !== false); }

function clearWorkspace() {
  clearPasswordForm();
  callsLoaded=false;callsLoading=false;callsPage=1;callsRequest++;callsToolOptions=[]; appliedRange={from:'',to:'',fromTime:'',toTime:'',fromISO:'',toISO:''}; $('calls-rows').innerHTML=''; $('calls-filters').reset();
  identityEpoch++; loading = false; accessData = null; accessLoading = false; accessAction = null; token = ''; session = null; toolViews.clear(); expandedTools.clear(); toolErrors.clear(); bulkRequest = null;
  providers = []; tools = []; connections.clear(); selected = ''; loaded = false; access = false; refreshState.clear();
  $('search').value = ''; $('upstream-search').value = ''; $('provider-filter').value = '';
  $('tool-title').textContent = ''; $('tool-identity').textContent = ''; $('tool-description').textContent = '';
  for (const id of ['tool-input', 'tool-output', 'tool-annotations', 'client-token']) $(id).textContent = '';
  $('client-token').value = '';
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  render();
}
// The owner console module listens for route and identity changes so it can
// lock its vault worker and discard late results when the workspace changes.
function announceWorkspace(kind, detail) {
  if (typeof CustomEvent === 'function' && typeof document.dispatchEvent === 'function') document.dispatchEvent(new CustomEvent('mcpwarden:' + kind, {detail}));
}
window.MCPWardenWorkspace = {
  current: () => ({epoch: identityEpoch, access, session: session ? {mode: session.mode, subject: session.subject, username: session.username} : null, route: readRoute()}),
  // Called when an owner route reports that the browser session ended.
  authLost() { clearWorkspace(); accessStatus('Authentication required', 'Sign in again to continue.', 'failure'); $('account-error').textContent = 'Your session ended. Sign in again.'; },
};
function renderIdentity() {
  announceWorkspace('identity', window.MCPWardenWorkspace.current());
  $('gateway-status').hidden=!access;
  if(access){const enabled=providers.filter(p=>p.enabled!==false), healthy=enabled.filter(p=>p.healthy).length;
    $('gateway-status').textContent=!providers.length?'No connectors added':!enabled.length?'All connectors disabled':healthy===enabled.length?'Connectors available':healthy?'Some connectors unavailable':'No connectors available';
    $('gateway-status').className='status-pill '+(!enabled.length?'':healthy===enabled.length?'success':'warning');
  }
  if(!access){$('calls-rows').innerHTML='';$('calls-tool').innerHTML='<option value="">Select an upstream first</option>';$('calls-upstream').innerHTML='<option value="">All upstreams</option>';}
  document.body.classList.toggle('signed-out', !access && !loaded);
  document.body.classList.toggle('auth-loading', initialLoad);
  $('session-loading').hidden = !initialLoad;
  $('login-screen').hidden = initialLoad || access || loaded;
  $('identity-mode').textContent = session?.mode === 'account' || session?.mode === 'oauth' ? 'PERSONAL WORKSPACE' : session?.mode === 'local' ? 'SHARED WORKSPACE' : 'WORKSPACE';
  $('identity-subject').textContent = session?.username || session?.subject || 'Not connected';
  $('identity-help').textContent = session?.mode === 'account' ? 'Your connections and tool choices.' : session?.mode === 'oauth' ? 'Scoped to your verified identity.' : session?.mode === 'local' ? 'All operator-token users share this workspace.' : 'Sign in to view your workspace.';
  $('authenticate').hidden = session?.mode === 'account';
  $('disconnect').hidden = !session;
  renderAccountSettings();
  $('disconnect').textContent = session?.mode === 'account' ? 'Sign out' : session?.mode === 'local' ? 'Forget local credential' : 'Disconnect this browser';
  $('upstream-intro').textContent = session?.mode === 'local' ? 'Manage connections in the shared operator workspace.' : 'Manage your connections and inspect shared gateway upstreams.';
  $('registration-context').textContent = session?.mode === 'local' ? 'This connection will be available to everyone using the operator token.' : 'This connection and its credentials will belong to your account.';
}
function routePath() { return location.hash.startsWith('#/') ? location.hash.slice(1) : location.pathname || '/dashboard'; }
// Upgrade old bookmarks without adding a history entry.
if(location.hash.startsWith('#/'))history.replaceState(null,'',location.hash.slice(1)+location.search);
function readRoute() {
  const parts = routePath().replace(/^\//, '').split('/');
  if (parts[0] === 'settings') return {view:'settings', section:['account','appearance','security'].includes(parts[1])?parts[1]:'account'};
  if (parts[0] === 'history') return {view:'history'};
  if (parts[0] === 'access') return {view:'access'};
  if (parts[0] === 'vault') return {view:'vault', section:['credentials','settings'].includes(parts[1])?parts[1]:'access'};
  if (parts[0] === 'tools') { let provider = ''; try { provider = decodeURIComponent(parts[1] || ''); } catch (_) {} return {view: 'tools', provider: provider.includes(',') ? '' : provider, providerNames: provider ? provider.split(',') : []}; }
  if (parts[0] === 'upstreams' && parts[1]) { let name = ''; try {name = decodeURIComponent(parts[1]);} catch (_) {} return {view: 'detail', name, section:parts[2]==='settings'?'settings':'tools'}; }
  return {view: parts[0] === 'upstreams' ? 'upstreams' : 'dashboard'};
}
function applyRoute(focus = false) {
  const route = readRoute();
  $('discovery-footer').hidden = !['dashboard','upstreams','detail','tools'].includes(route.view);
  $('workspace-nav').classList.remove('mobile-open');
  $('mobile-navigation').setAttribute('aria-expanded','false');
  $('mobile-navigation').setAttribute('aria-label','Open navigation');
  $('settings-page').hidden = route.view !== 'settings';
  if(route.view === 'settings') renderAccountSettings();
  $('calls-page').hidden = route.view !== 'history';
  $('access-page').hidden = route.view !== 'access';
  $('vault-page').hidden = route.view !== 'vault';
  $('dashboard').hidden = route.view !== 'dashboard';
  $('connections').hidden = route.view !== 'upstreams';
  $('connection-view').hidden = route.view !== 'detail';
  $('directory').hidden = route.view !== 'tools';
  if (route.view === 'detail') selected = route.name;
  const title = route.view === 'settings' ? 'Account settings' : route.view === 'history' ? 'History' : route.view === 'access' ? 'Access' : route.view === 'vault' ? 'Vault & windows' : route.view === 'tools' ? 'Tool directory' : route.view === 'detail' ? selected : route.view === 'dashboard' ? 'Dashboard' : 'Upstreams';
  $('breadcrumb-upstreams').hidden = route.view !== 'detail';
  $('breadcrumb-separator').hidden = route.view !== 'detail';
  $('breadcrumb-page').textContent = title;
  document.title = `MCPWarden · ${title}`;
  const slot = $(route.view === 'detail' ? 'connector-tool-slot' : 'directory-tool-slot');
  if ($('tool-panel').parentElement !== slot) slot.appendChild($('tool-panel'));
  $('provider-filter').hidden = route.view === 'detail';
  renderProviderFilter();
  $('tool-intro').hidden = route.view !== 'detail';
  closeBulkMenu();
  const state = toolView();
  $('search').value = state.query;
  $('tool-page-size').value = String(state.size);
  for (const link of document.querySelectorAll('.nav-item')) {
    const active = link.dataset.view === (route.view === 'detail' ? 'upstreams' : route.view);
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  }
  if (route.view === 'tools') {
    $('provider-filter').value = providers.some(p => p.name === route.provider) ? route.provider : '';
    $('directory-intro').textContent = route.providerNames?.length ? `Tools from ${route.providerNames.length} selected upstream${route.providerNames.length === 1 ? '' : 's'}.` : 'Search tools across the upstreams in your workspace.';
  }
  renderDashboard(); renderDetails(); renderTools(); renderAccess();
  if(route.view==='history' && access && !callsLoaded && !callsLoading) loadCalls();
  if (route.view === 'access' && access && !accessData && !accessLoading) loadAccess();
  announceWorkspace('route', route);
  if (focus) $(route.view === 'settings' ? 'settings-title' : route.view === 'history' ? 'calls-title' : route.view === 'access' ? 'access-title' : route.view === 'vault' ? 'vault-title' : route.view === 'tools' ? 'directory-title' : route.view === 'detail' ? 'connection-title' : route.view === 'dashboard' ? 'dashboard-title' : 'page-title').focus();
}
let previousRoute = routePath(), workspaceReturn = '/dashboard', workspaceFocus = null, workspaceScroll = 0;
function routeChanged() {
 const oldRoute=previousRoute;
 const next=routePath(), leavingSecurity=previousRoute==='/settings/security'&&next!==previousRoute;
 if(leavingSecurity && passwordDirty() && !window.confirm('Discard unsaved password changes?')) { history.replaceState(null,'',previousRoute); return; }
 if(leavingSecurity) clearPasswordForm();
 if(!previousRoute.startsWith('/settings') && next.startsWith('/settings')) {workspaceReturn=previousRoute;workspaceFocus=$('account-launcher').contains(document.activeElement)?$('account-launcher-trigger'):document.activeElement;workspaceScroll=window.scrollY;}
 const returning=previousRoute.startsWith('/settings')&&!next.startsWith('/settings');
 previousRoute=next;
 $('account-launcher').open=false;
 applyRoute(true);
 const current=readRoute();
 if(current.view==='detail' && current.section==='tools' && oldRoute==='/upstreams/'+encodeURIComponent(current.name)+'/settings')window.scrollTo(0,connectorScroll.get(current.name)||0);
 if(returning && next===workspaceReturn) {if(workspaceFocus?.isConnected)workspaceFocus.focus();window.scrollTo(0,workspaceScroll);}
}
function navigate(path) {
 if(path===routePath())return;
 history.pushState(null,'',path);
 routeChanged();
}
window.addEventListener('popstate',routeChanged);
window.addEventListener('hashchange',()=>{
 if(!location.hash.startsWith('#/'))return;
 history.replaceState(null,'',location.hash.slice(1)+location.search);
 routeChanged();
});
document.addEventListener('click',event=>{
 if(event.defaultPrevented||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;
 const link=event.target.closest('a[href]');
 if(!link||link.hasAttribute('download')||(link.target&&link.target!=='_self'))return;
 const url=new URL(link.href,location.href);
 if(url.origin!==location.origin||url.hash||!/^\/(dashboard|upstreams|tools|history|access|vault|settings)(\/|$)/.test(url.pathname))return;
 event.preventDefault();navigate(url.pathname+url.search);
});
function openDialog(id) {
  dialogTriggers.set(id, document.activeElement);
  $(id).showModal();
}
for (const dialog of document.querySelectorAll('dialog')) {
  dialog.addEventListener('close', () => {
    const trigger = dialogTriggers.get(dialog.id);
    if (trigger?.isConnected) trigger.focus();
    else $('refresh').focus();
  });
}
function notice(message = '') { $('notice').textContent = message; $('notice').hidden = !message; }
function accessStatus(label, detail, tone = '') {
  $('overall').textContent = label;
  $('overall').className = `status-pill ${tone}`;
  $('access-context').textContent = detail;
}
async function api(path, options = {}) {
  const epoch = identityEpoch;
  let response;
  try {
    response = await fetch(path, {...options, cache: 'no-store', credentials: 'same-origin', headers: {'X-MCPWarden-Request': 'browser', ...(token ? {Authorization: `Bearer ${token}`} : {}), ...options.headers}});
  } catch (_) { throw new Error('Gateway unreachable. Check the connection and reload the inventory.'); }
  if (epoch !== identityEpoch) throw new Error('Workspace changed.');
  if (!response.ok) {
    // Raw upstream errors can contain URLs or credentials. Display safe diagnostics only.
    const error = new Error(response.status === 401 ? (accountMode === 'accounts' ? 'Sign in with your username and password.' : 'Connect with a valid operator or OAuth credential.') : response.status === 403 ? 'Management access denied. In OAuth mode, the token needs mcp:manage scope.' : response.status === 501 ? 'This capability is not configured on the gateway.' : `Request failed (HTTP ${response.status}). Check the connection settings and try again.`);
    error.status = response.status;
    if (response.status === 401 || response.status === 403) {
      access = false;
      accessStatus(response.status === 401 ? 'Authentication required' : 'Management access denied', 'Inventory is unavailable until access is restored.', 'failure');
      providers = []; tools = []; connections.clear(); selected = ''; loaded = false; session = null;
      if (!initialLoad || response.status !== 401) $('account-error').textContent = error.message;
      render();
    }
    throw error;
  }
  return response.status === 204 ? null : response.json();
}
function date(value) { return window.MCPWardenTime.format(value); }
function discovery(p) {
  if (p.enabled === false) return ['Disabled', '', 'Connection paused'];
  const entry = connections.get(p.name);
  if (entry?.auth_type === 'oauth' && !entry.oauth_connected) return ['Connect account', 'warning', 'Authorization required'];
  const local = refreshState.get(p.name);
  if (local?.pending) return ['Refreshing…', '', 'Discovery in progress'];
  if (local?.failed) return [p.last_discovered || p.tool_count ? 'Cached · stale' : 'Refresh failed', p.last_discovered || p.tool_count ? 'warning' : 'failure', 'Latest refresh failed'];
  if (p.healthy) return ['Discovered', 'success', `${p.tool_count} tool${p.tool_count === 1 ? '' : 's'}`];
  if (p.last_discovered || p.tool_count) return ['Cached · stale', 'warning', `${p.tool_count} cached tool${p.tool_count === 1 ? '' : 's'}`];
  return [p.error ? 'Discovery failed' : 'Not discovered', p.error ? 'failure' : '', 'No successful discovery recorded'];
}
function providerActions(p) {
  const pending = pendingProvider?.name === p.name;
  const enabled = pending ? pendingProvider.enabled : p.enabled !== false;
  const refreshing = refreshState.get(p.name)?.pending;
  const locked = !access || mutating || refreshing;
  return `<div class="provider-actions"><label class="visibility-toggle"><input type="checkbox" role="switch" class="provider-toggle" data-provider="${escapeHTML(p.name)}" aria-label="Enable ${escapeHTML(p.name)} upstream" ${enabled ? 'checked' : ''} ${locked || !managedAvailable ? 'disabled' : ''}><span>${enabled ? 'Enabled' : 'Disabled'}</span></label><button type="button" class="provider-refresh" data-provider="${escapeHTML(p.name)}" aria-label="Refresh tools for ${escapeHTML(p.name)}" ${locked || !enabled ? 'disabled' : ''}>${refreshing ? 'Refreshing…' : 'Refresh'}</button></div>`;
}
function toolCounts(name) {
  const inventory = tools.filter(t => t.upstream === name);
  const enabled = inventory.filter(t => t.visible).length;
  return `${enabled} enabled · ${inventory.length - enabled} disabled · ${inventory.length} total tools`;
}
function renderUpstreams() {
  const query = $('upstream-search').value.trim().toLowerCase();
  const visible = providers.filter(p => `${p.name} ${connections.get(p.name)?.url || ''}`.toLowerCase().includes(query));
  $('upstreams').innerHTML = visible.length ? visible.map(p => {
    const [label, tone, detail] = discovery(p);
    return `<li class="provider-row"><a class="upstream-row" data-name="${escapeHTML(p.name)}" href="/upstreams/${encodeURIComponent(p.name)}" aria-label="Open ${escapeHTML(p.name)} connection"><span><span class="row-name">${escapeHTML(p.name)}</span><span class="row-meta">${p.transport === 'stdio' ? 'stdio' : 'Streamable HTTP'} · ${p.source === 'personal' ? 'Personal' : 'Config managed'}</span><span class="row-meta tool-counts">${toolCounts(p.name)}</span></span><span class="row-state"><span class="badge ${tone}">${label}</span><span class="row-meta">${escapeHTML(detail)}</span></span></a>${providerActions(p)}</li>`;
  }).join('') : `<li class="empty">${!access ? 'Connect with a valid management token to view upstreams.' : !loaded ? 'Loading upstreams…' : providers.length ? 'No upstreams match your search.' : 'No upstreams registered. Add a remote connection to get started.'}</li>`;
  const enabledCount = providers.filter(p => p.enabled !== false).length;
  $('upstream-summary').textContent = loaded ? `${enabledCount} enabled · ${providers.length - enabledCount} disabled · ${providers.length} total upstreams` : '';
  $('upstream-count').textContent = loaded ? `${visible.length} of ${providers.length} upstreams` : 'Inventory unavailable';
}
function renderDetails() {
  const p = providers.find(p => p.name === selected);
  $('connection-title').textContent = selected || 'Connection';
  $('connection-subtitle').textContent = p ? `${p.source === 'personal' ? 'Personal upstream' : 'Config managed upstream'} · ${p.enabled===false?'Disabled':p.healthy?'Connected':'Not connected'} · Last discovery: ${date(p.last_discovered)}` : '';
  const settings = readRoute().section === 'settings';
  $('connector-tool-slot').hidden = !p || settings;
  $('connection-settings').hidden = !p || !settings;
  $('connection-sections').hidden = !p;
  const base = '/upstreams/'+encodeURIComponent(selected);
  $('connection-tools-link').href = base;
  $('connection-settings-link').href = base+'/settings';
  $('connection-tool-count').textContent = p ? p.tool_count : ''; $('connection-tool-count').hidden = !p;
  for(const [id,active] of [['connection-tools-link',!settings],['connection-settings-link',settings]]) { if(active)$(id).setAttribute('aria-current','page');else $(id).removeAttribute('aria-current'); }
  $('provider-enabled-control').hidden = !p;
  const authEntry = connections.get(p?.name);
  $('connect-upstream-account').hidden = authEntry?.auth_type !== 'oauth';
  $('connect-upstream-account').disabled = !access || mutating;
  $('connect-upstream-account').textContent = authEntry?.oauth_connected ? 'Reconnect account' : 'Connect account';
  const enabled = pendingProvider && pendingProvider.name === p?.name ? pendingProvider.enabled : p?.enabled !== false;
  $('provider-enabled').dataset.enable = String(!enabled);
  $('provider-enabled').textContent = enabled ? 'Disable' : 'Enable';
  $('provider-enabled').className = `connector-action ${enabled ? 'connector-disable' : 'connector-enable'}`;
  $('provider-enabled').disabled = !p || !access || !managedAvailable || mutating || refreshState.get(p.name)?.pending;
  $('refresh-tools').disabled = !p || !access || mutating || p.enabled === false || refreshState.get(p.name)?.pending;
  $('refresh-tools').textContent = refreshState.get(p?.name)?.pending ? 'Refreshing…' : 'Refresh';
  if (!p) { $('upstream-details').innerHTML = `<div class="empty">${loaded ? 'This upstream is not available in your workspace.' : 'Sign in to load this connection.'}</div>`; return; }
  const entry = connections.get(p.name), [label, tone] = discovery(p), local = refreshState.get(p.name);
  const locked = !access || mutating;
  $('upstream-details').innerHTML = `<div class="detail-heading"><div class="eyebrow">UPSTREAM DETAILS</div><h2>${escapeHTML(p.name)}</h2><span class="badge ${tone}">${label}</span></div>
    <section class="detail-section"><h3>Upstream connection</h3><dl><dt>Managed by</dt><dd>${entry ? escapeHTML(session?.username || (session?.mode === 'local' ? 'Shared operator workspace' : session?.subject) || 'Your workspace') : 'Gateway configuration'}</dd><dt>Transport</dt><dd>${p.transport === 'stdio' ? 'stdio' : 'Streamable HTTP'}</dd>${entry ? `<dt>Endpoint</dt><dd class="mono">${escapeHTML(entry.url)}</dd><dt>Call timeout</dt><dd>${escapeHTML(entry.call_timeout || '30s')}</dd>` : '<dt>Settings</dt><dd>Defined in YAML configuration.</dd>'}</dl></section>
    <section class="detail-section"><h3>Discovery</h3><dl><dt>Last successful discovery</dt><dd>${escapeHTML(date(p.last_discovered))}</dd><dt>Metadata</dt><dd>${p.healthy || p.last_discovered || p.tool_count ? `${p.tool_count} ${p.healthy && !local?.failed ? 'discovered' : 'cached'} tools` : 'No successful discovery recorded'}</dd><dt>Gateway-reported connection</dt><dd>${p.enabled === false ? 'Disabled' : p.healthy ? 'Connected' : 'Unavailable'}</dd></dl>${local?.failed || p.error ? '<p class="help failure">Discovery could not complete. Check the upstream endpoint and credentials. Raw diagnostics are omitted to protect credentials.</p>' : ''}<p class="help">Refresh retrieves tool metadata. It does not invoke tools.</p></section>
    ${entry ? `<section class="detail-section"><h3>Authentication</h3><p>${escapeHTML(authLabel(entry.auth_type || (entry.header_names.length ? 'headers' : 'none')))}</p>${entry.auth_type === 'oauth' ? `<p class="help">${entry.oauth_connected ? 'Account authorization saved. Reconnect if permissions have changed or access expired.' : 'Authorize this connector to discover its tools.'}</p>` : ''}</section>` : ''}
    <section class="detail-section"><h3>Saved headers</h3>${entry ? entry.header_names.length ? entry.header_names.map(name => `<div class="saved-header"><span class="mono">${escapeHTML(name)}</span><span>Stored</span></div>`).join('') : '<p class="help">Not set</p>' : '<p class="help">Managed in gateway configuration; header names are not exposed.</p>'}${entry ? '<p class="help">Saved values remain private. This gateway does not support editing saved headers.</p>' : ''}</section>
    <section class="detail-section"><h3>Agent discovery</h3><label for="visibility-mode" class="help">Tools visible to MCP clients</label><select id="visibility-mode" ${locked || !managedAvailable ? 'disabled' : ''}><option value="all" ${p.visibility_mode === 'selected' ? '' : 'selected'}>All tools visible</option><option value="selected" ${p.visibility_mode === 'selected' ? 'selected' : ''}>Selected tools only</option></select><p class="help">Selected mode exposes only enabled tools in the directory. Gateway allow/deny policy still applies.</p></section>
    ${entry ? `<section class="detail-section"><h3>Remove connection</h3><p class="help">Remove this upstream and its saved headers from your gateway identity.</p><button id="remove-upstream" class="danger" type="button" ${locked ? 'disabled' : ''}>Remove upstream</button></section>` : ''}`;
}
function renderDashboard() {
  const disabled = providers.filter(p => p.enabled === false).length;
  const attention = providers.filter(p => p.enabled !== false && (!p.healthy || refreshState.get(p.name)?.failed)).map(p => p.name);
  $('overview-upstreams').textContent = loaded ? providers.length : '—';
  $('overview-upstreams-help').textContent = !loaded ? 'Not loaded' : !providers.length ? 'None added yet' : disabled ? `${providers.length - disabled} enabled · ${disabled} disabled` : 'All enabled';
  $('overview-tools').textContent = loaded ? tools.filter(isDiscoverable).length : '—';
  $('overview-tools-help').textContent = loaded ? `of ${tools.length} found` : 'Not loaded';
  $('overview-attention').textContent = loaded ? attention.length : '—';
  $('overview-attention-help').textContent = !loaded ? 'Not loaded' : attention.length ? attention.join(', ') : 'All connected';
  $('overview-attention-help').title = attention.join(', ');
  $('dashboard-add').disabled = !access || !managedAvailable || mutating;
  const ordered = [...providers].sort((a, b) => Number(a.healthy) - Number(b.healthy) || a.name.localeCompare(b.name));
  $('overview-connections').innerHTML = ordered.length ? ordered.slice(0, 5).map(p => {
    const [label, tone] = discovery(p);
    const count = tools.filter(t => t.upstream === p.name && isDiscoverable(t)).length;
    return `<li class="provider-row"><a class="upstream-row overview-row" href="/upstreams/${encodeURIComponent(p.name)}"><span><span class="row-name">${escapeHTML(p.name)}</span><span class="row-meta">${p.source === 'personal' ? 'Personal connection' : 'Config managed'} · ${count} discoverable tools</span></span><span class="badge ${tone}">${label} →</span></a>${providerActions(p)}</li>`;
  }).join('') : `<li class="empty">${loaded ? 'Your workspace has no upstreams yet. Add a connection to get started.' : 'Connect to load your workspace overview.'}</li>`;
}
function matchesToolScope(t) {
  const route = readRoute();
  return route.view === 'detail' ? t.upstream === route.name : !route.providerNames?.length || route.providerNames.includes(t.upstream);
}
function renderProviderFilter() {
  const names = readRoute().providerNames || [];
  $('provider-filter-label').textContent = names.length === 1 ? names[0] : names.length ? `${names.length} upstreams` : 'All upstreams';
  $('provider-options').innerHTML = providers.map(p => `<label><input type="checkbox" data-provider="${escapeHTML(p.name)}" ${names.includes(p.name) ? 'checked' : ''}>${escapeHTML(p.name)}</label>`).join('');
}
function queriedTools() {
  const query = toolView().query.trim().toLowerCase();
  return tools.filter(t => matchesToolScope(t) && `${toolLabel(t)} ${t.name} ${t.upstream} ${t.description || ''}`.toLowerCase().includes(query));
}
function filteredTools() {
  const filter = toolView().filter;
  return queriedTools().filter(t => filter === 'all' || (filter === 'discoverable' ? isToolDiscoverable(t) : !isToolDiscoverable(t)));
}
const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
function visibilityViewLabel(filter) { return filter === 'discoverable' ? 'Shown only' : filter === 'not-discoverable' ? 'Hidden only' : 'All tools'; }
function toolStateWord(t) { return !t.allowed ? 'Blocked' : t.visible ? 'Shown' : 'Hidden'; }
function toolStatusDetail(t) {
  if (!t.allowed) return `Denied by gateway policy. Clients cannot see it${t.visible ? ' even though your setting shows it' : ''}.`;
  return t.visible ? 'Shown to clients while this connection is enabled and connected.' : 'Hidden from clients by your visibility setting.';
}
const chevronIcon = '<svg aria-hidden="true" class="icon" focusable="false" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg>';
function renderToolRow(t, detailId, provider) {
  const key = escapeHTML(toolKey(t)), label = escapeHTML(toolLabel(t)), open = expandedTools.has(toolKey(t)), failed = toolErrors.get(toolKey(t));
  const error = failed && `Not saved. ${toolLabel(t)} is still ${t.visible ? 'shown' : 'hidden'}.`;
  return `<li class="tool-row"><div class="tool-main"><div class="tool-identity"><button class="tool-expand" type="button" data-expand="${key}" aria-expanded="${open}" aria-controls="${detailId}">${chevronIcon}<span class="tool-label">${label}</span></button>${provider ? '' : `<span class="tool-upstream">${escapeHTML(t.upstream)}</span>`}<p class="tool-description">${escapeHTML(t.description || 'No description supplied.')}</p></div><div class="switch-area"><span class="state-word${t.allowed ? '' : ' blocked'}"${t.allowed ? ' aria-hidden="true"' : ''}>${toolStateWord(t)}</span><label class="switch"><input class="tool-visibility" role="switch" type="checkbox" data-tool="${key}" ${t.visible ? 'checked' : ''} ${!access || !t.allowed || !managedAvailable || mutating ? 'disabled' : ''} aria-label="Show ${label}${provider ? '' : ` from ${escapeHTML(t.upstream)}`} to clients"><span class="switch-track"></span></label></div></div>${error ? `<div class="row-error" role="alert"><span>${escapeHTML(error)}</span><button class="retry" type="button" data-retry="${key}">Retry</button></div>` : ''}<div class="tool-extra" id="${detailId}"${open ? '' : ' hidden'}><dl><dt>MCP name</dt><dd><code>${escapeHTML(t.name)}</code></dd>${provider ? '' : `<dt>Upstream</dt><dd>${escapeHTML(t.upstream)}</dd>`}<dt>Status</dt><dd>${toolStatusDetail(t)}</dd></dl><button class="tool-name" type="button" data-tool="${key}">Schema and call history</button></div></li>`;
}
function renderToolEmpty(scoped, queried, provider, filter) {
  const plain = text => `<li class="tool-empty">${text}</li>`;
  if (!access) return plain('Management access is required to view tools.');
  if (!loaded) return plain('Loading tools…');
  if (!scoped.length) return plain(provider && !providers.some(p => p.name === provider) ? 'No tools match your filters.' : 'No tools have been discovered for this selection.');
  const noMatches = !queried.length;
  const title = noMatches ? 'No tools match your search' : filter === 'not-discoverable' ? 'No hidden tools in this view' : 'No shown tools in this view';
  const copy = noMatches ? 'Try a different name or description.' : 'Switch to All to browse the matching tools.';
  return `<li class="tool-empty"><span aria-hidden="true" class="empty-icon"><svg class="icon" focusable="false" viewBox="0 0 24 24"><circle cx="10.7" cy="10.7" r="6.7"/><path d="m16 16 4 4"/></svg></span><h3>${title}</h3><p>${copy}</p><button type="button" data-empty-action="${noMatches ? 'clear' : 'all'}">${noMatches ? 'Clear search' : 'View all matching tools'}</button></li>`;
}
function renderToolNote(provider) {
  const p = readRoute().view === 'detail' ? providers.find(x => x.name === provider) : null;
  const note = !loaded ? '' : !access ? 'Showing the last loaded snapshot. Reload to change tool visibility.' : !managedAvailable ? 'Visibility settings are not configured on this gateway, so these switches are read-only.' : p?.enabled === false ? 'This connection is disabled. Clients receive none of its tools until you enable it; the choices below are kept.' : p && !p.healthy ? 'This connection is not connected right now. Clients receive its shown tools once it reconnects.' : '';
  $('tool-panel-note').textContent = note; $('tool-panel-note').hidden = !note;
}
function reconcileToolErrors() {
  for (const [key, failed] of toolErrors) { const tool = tools.find(t => toolKey(t) === key); if (!tool || tool.visible === failed.visible) toolErrors.delete(key); }
}
function renderTools() {
  reconcileToolErrors();
  const state = toolView(), provider = toolScope(), detail = readRoute().view === 'detail';
  const scoped = tools.filter(matchesToolScope), queried = queriedTools(), matching = filteredTools();
  const shownCount = queried.filter(isToolDiscoverable).length;
  for (const [id, value] of [['count-all', queried.length], ['count-shown', shownCount], ['count-hidden', queried.length - shownCount]]) $(id).textContent = loaded ? value : '—';
  for (const filter of ['all', 'discoverable', 'not-discoverable']) $('filter-' + filter).checked = state.filter === filter;
  const pages = Math.max(1, Math.ceil(matching.length / state.size));
  state.page = Math.min(Math.max(1, state.page), pages);
  const start = (state.page - 1) * state.size, visible = matching.slice(start, start + state.size);
  const query = state.query.trim(), narrowed = Boolean(query) || state.filter !== 'all';
  $('tool-count').textContent = loaded ? `${scoped.filter(isToolDiscoverable).length} / ${scoped.length} shown` : '—';
  $('tool-summary-count').textContent = !loaded ? '' : narrowed ? `${matching.length} of ${plural(scoped.length, 'tool')} in this view` : `${plural(scoped.length, 'tool')}${detail ? ' in this connection' : ''}`;
  $('tool-result-caption').hidden = !loaded || !narrowed;
  $('tool-result-caption').textContent = `${plural(matching.length, 'tool')}${query ? ` matching “${query}”` : ''} · ${visibilityViewLabel(state.filter)}`;
  $('clear-search').hidden = !state.query;
  $('tool-page-status').textContent = loaded ? `${matching.length ? start + 1 : 0}–${Math.min(start + state.size, matching.length)} of ${matching.length} tools · Page ${state.page} of ${pages}` : 'Inventory unavailable';
  $('tool-previous').disabled = state.page <= 1; $('tool-next').disabled = state.page >= pages;
  $('bulk-tool-actions').hidden = !provider;
  $('bulk-button').disabled = !provider || !access || !managedAvailable || mutating || !matching.length;
  if ($('bulk-button').disabled) closeBulkMenu();
  renderToolNote(provider);
  $('tools').innerHTML = visible.length ? visible.map((t, i) => renderToolRow(t, `tool-detail-${start + i}`, provider)).join('') : renderToolEmpty(scoped, queried, provider, state.filter);
}
function render() {
  $('add-upstream').disabled = !access || !managedAvailable || mutating;
  renderIdentity(); renderUpstreams(); applyRoute();
}
async function refresh(renderAfter = true) {
  if (loading) return;
  const epoch = identityEpoch;
  const snapshot = JSON.stringify([providers, tools, [...connections], session, access, loaded, managedAvailable]);
  loading = true; $('refresh').disabled = true; $('refresh').classList.add('saving-control'); $('refresh').setAttribute('aria-busy', 'true');
  try {
    const results = await Promise.allSettled([api('/api/status'), api('/api/tools'), api('/api/providers'), api('/api/connections')]);
    if (epoch !== identityEpoch) return;
    const failure = results.slice(0, 3).find(r => r.status === 'rejected') || (results[3].status === 'rejected' && results[3].reason.status !== 501 ? results[3] : null);
    if (failure) throw failure.reason;
    const [status, list, providerList] = results.slice(0, 3).map(r => r.value);
    managedAvailable = results[3].status === 'fulfilled';
    connections = new Map((managedAvailable ? results[3].value : []).map(c => [c.name, c]));
    providers = providerList.sort((a,b) => a.name.localeCompare(b.name));
    tools = list.sort((a,b) => toolLabel(a).localeCompare(toolLabel(b)) || a.upstream.localeCompare(b.upstream) || a.name.localeCompare(b.name));
    if (!providers.some(p => p.name === selected)) selected = providers[0]?.name || '';
    session = status.session || null;
    access = true; loaded = true;
    accessStatus(session?.mode === 'account' ? 'Signed in' : 'Management access verified', session?.mode === 'local' ? 'Shared operator workspace' : 'Personal workspace');
    notice(managedAvailable ? '' : 'Remote registration and visibility settings are not configured on this gateway.');
    if (renderAfter && snapshot !== JSON.stringify([providers, tools, [...connections], session, access, loaded, managedAvailable])) render();
  } catch (error) {
    if (epoch !== identityEpoch) return;
    access = false;
    if (error.status !== 401 && error.status !== 403) accessStatus('Inventory unavailable', loaded ? 'Showing the last loaded snapshot. Reload to restore management actions.' : 'The gateway inventory could not be loaded.', 'warning');
    if(initialLoad && error.status!==401 && error.status!==403)$('account-error').textContent=error.message;
    notice(error.message); render();
  } finally { if (epoch === identityEpoch) { loading = false; $('refresh').disabled = false; $('refresh').classList.remove('saving-control'); $('refresh').setAttribute('aria-busy', 'false'); } }
}
$('refresh').addEventListener('click', async () => {
  if (!access || loading || mutating || [...refreshState.values()].some(s=>s.pending)) return;
  const names=providers.filter(p=>p.enabled!==false).map(p=>p.name), failed=[];
  mutating=true; lockMutationControls(); $('refresh').disabled=true; $('refresh').classList.add('saving-control'); $('refresh').setAttribute('aria-busy','true');
  try {
    for (const name of names) {
      try { await api(`/api/discovery/${encodeURIComponent(name)}/refresh`,{method:'POST'});refreshState.delete(name); }
      catch (_) {failed.push(name);refreshState.set(name,{failed:true});if(!access)break;}
    }
    if(access) await refresh(false);
    notice(failed.length ? `Could not refresh: ${failed.join(', ')}. Other enabled connectors were refreshed.` : `Refreshed ${names.length} enabled connector${names.length===1?'':'s'}.`);
  } finally {mutating=false;$('refresh').disabled=!access;$('refresh').classList.remove('saving-control');$('refresh').setAttribute('aria-busy','false');render();}
});
$('upstream-search').addEventListener('input', renderUpstreams);
$('search').addEventListener('input', () => { const state = toolView(); state.query = $('search').value; state.page = 1; closeBulkMenu(); renderTools(); });
function clearToolSearch() { const state = toolView(); state.query = ''; state.page = 1; $('search').value = ''; renderTools(); $('search').focus(); }
$('clear-search').addEventListener('click', clearToolSearch);
function setToolFilter(filter) { const state = toolView(); state.filter = filter; state.page = 1; closeBulkMenu(); renderTools(); }
$('visibility-filters').addEventListener('change', event => { if (event.target.name === 'tool-visibility-filter') setToolFilter(event.target.value); });
$('tool-page-size').addEventListener('change', () => { const state = toolView(); state.size = Number($('tool-page-size').value); state.page = 1; renderTools(); });
$('tool-previous').addEventListener('click', () => { toolView().page--; renderTools(); });
$('tool-next').addEventListener('click', () => { toolView().page++; renderTools(); });
$('provider-options').addEventListener('change', event => {
  const input = event.target.closest('input[data-provider]'); if (!input) return;
  const names = new Set(readRoute().providerNames || []);
  if (input.checked) names.add(input.dataset.provider); else names.delete(input.dataset.provider);
  toolView().page = 1;
  navigate(names.size ? `/tools/${[...names].sort().map(encodeURIComponent).join(',')}` : '/tools');
});
$('provider-all').addEventListener('click', () => { navigate('/tools'); });
window.addEventListener('click', event => { if (!event.target.closest('#provider-filter')) $('provider-filter').open = false; });
window.addEventListener('keydown', event => { if (event.key === 'Escape') { $('provider-filter').open = false; $('provider-filter-label').focus(); } });
$('authenticate').addEventListener('click', () => { $('auth-dialog').returnValue = ''; openDialog('auth-dialog'); });
$('auth-dialog').addEventListener('close', async () => {
  if ($('auth-dialog').returnValue === 'save') {
    const nextToken = $('token').value;
    clearWorkspace(); token = nextToken;
    await refresh();
  }
  $('token').value = '';
});
async function refreshProvider(name) {
  const p = providers.find(p => p.name === name);
  if (!p || !access || mutating || p.enabled === false || refreshState.get(name)?.pending) return;
  refreshState.set(name, {pending: true}); render();
  try {
    await api(`/api/discovery/${encodeURIComponent(name)}/refresh`, {method: 'POST'});
    refreshState.delete(name); await refresh();
  } catch (error) {
    refreshState.set(name, {failed: true});
    if (access) await refresh();
    notice(`Refresh failed for ${name}. ${error.message}`);
  } finally { render(); }
}
function focusProviderAction(container, selector, name) {
  [...$(container).querySelectorAll(selector)].find(el => el.dataset.provider === name)?.focus();
}
for (const container of ['upstreams', 'overview-connections']) {
  $(container).addEventListener('click', async event => {
    const button = event.target.closest('.provider-refresh');
    if (!button) return;
    const name = button.dataset.provider;
    await refreshProvider(name);
    focusProviderAction(container, '.provider-refresh', name);
  });
  $(container).addEventListener('change', async event => {
    const input = event.target.closest('.provider-toggle');
    if (!input) return;
    const name = input.dataset.provider;
    await setProviderEnabled(name, input.checked);
    focusProviderAction(container, '.provider-toggle', name);
  });
}
$('refresh-tools').addEventListener('click', async () => { await refreshProvider(selected); $('refresh-tools').focus(); });
$('upstream-details').addEventListener('click', async event => {
  if (event.target.id === 'remove-upstream') {
    $('remove-description').textContent = `You are removing “${selected}”.`;
    $('remove-form').dataset.name = selected;
    $('remove-error').textContent = '';
    openDialog('remove-dialog'); $('cancel-remove').focus();
  }
});
function lockMutationControls() {
  // Keep the native switch and its new checked state mounted until the save completes.
  document.querySelectorAll('.tool-visibility, .provider-toggle, .provider-refresh, #provider-enabled, #refresh-tools, #visibility-mode, #bulk-button, #add-upstream, #dashboard-add, #remove-upstream, #connect-upstream-account').forEach(el => { el.disabled = true; });
}
async function updateVisibility(name, mode, enabled) {
  if (!access || !managedAvailable || mutating) return;
  const epoch = identityEpoch;
  const controls = [...document.querySelectorAll('.tool-visibility, #visibility-mode, #bulk-button')].map(el => [el, el.disabled]);
  mutating = true;
  for (const [el] of controls) { el.classList.add('saving-control'); el.disabled = true; }
  try {
    const saved = await api(`/api/providers/${encodeURIComponent(name)}/visibility`, {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode, enabled})});
    if (epoch !== identityEpoch) return;
    const actualMode = saved?.mode || mode, actualEnabled = saved?.enabled || enabled;
    const provider = providers.find(p => p.name === name);
    if (provider) { provider.visibility_mode = actualMode; provider.enabled_tools = actualEnabled; }
    const names = new Set(actualEnabled);
    for (const tool of tools) if (tool.upstream === name) tool.visible = actualMode === 'all' || names.has(tool.name);
    if (selected === name && $('visibility-mode')) $('visibility-mode').value = actualMode;
    return true;
  }
  catch (error) { notice(`Visibility was not saved. ${error.message}`); return false; }
  finally {
    mutating = false;
    for (const [el, disabled] of controls) { el.disabled = disabled; el.classList.remove('saving-control'); }
    if (epoch === identityEpoch && access) renderTools();
  }
}

$('upstream-details').addEventListener('change', async event => {
  if (event.target.id !== 'visibility-mode') return;
  const p = providers.find(p => p.name === selected);
  await updateVisibility(p.name, event.target.value, p.enabled_tools || []);
  $('visibility-mode')?.focus();
});
function toast(message) {
  clearTimeout(toastTimer); $('toast').textContent = message;
  toastTimer = setTimeout(() => { $('toast').textContent = ''; }, 4500);
}
// Enabled names for one upstream after changing the given tools, starting from the saved selection.
function enabledAfter(name, changes) {
  const p = providers.find(p => p.name === name);
  const enabled = new Set(p?.visibility_mode === 'selected' ? p.enabled_tools || [] : tools.filter(t => t.upstream === name).map(t => t.name));
  for (const [tool, visible] of changes) { if (visible) enabled.add(tool.name); else enabled.delete(tool.name); }
  return [...enabled];
}
async function setToolVisible(item, visible) {
  const key = toolKey(item);
  const saved = await updateVisibility(item.upstream, 'selected', enabledAfter(item.upstream, [[item, visible]]));
  if (saved) { toolErrors.delete(key); toast(`${toolLabel(item)} is now ${visible ? 'shown to' : 'hidden from'} clients.`); }
  else if (access) toolErrors.set(key, {visible});
  if (access) renderTools();
  [...$('tools').querySelectorAll('.tool-visibility')].find(el => el.dataset.tool === key)?.focus();
  if (!document.activeElement || document.activeElement === document.body) $('filter-' + toolView().filter).focus();
}
// Policy-denied tools stay in the view but bulk actions leave them alone, like their disabled switches.
function bulkCounts() {
  const rows = filteredTools(), editable = rows.filter(t => t.allowed);
  return {rows, blocked: rows.length - editable.length, hidden: editable.filter(t => !t.visible), shown: editable.filter(t => t.visible)};
}
function closeBulkMenu(returnFocus = false) {
  const open = !$('bulk-menu').hidden;
  $('bulk-menu').hidden = true; $('bulk-button').setAttribute('aria-expanded', 'false');
  if (returnFocus && open) $('bulk-button').focus();
}
function openBulkMenu(last = false) {
  if ($('bulk-button').disabled) return;
  const state = toolView(), query = state.query.trim(), {rows, hidden, shown} = bulkCounts();
  $('bulk-scope').textContent = `Current view · ${plural(rows.length, query ? 'matching tool' : 'tool')}`;
  $('bulk-query').textContent = `${toolScope()} · ${query ? `“${query}” · ` : ''}${visibilityViewLabel(state.filter)}`;
  $('bulk-show-label').textContent = hidden.length ? `Show ${plural(hidden.length, 'hidden tool')}…` : 'No hidden tools to show';
  $('bulk-hide-label').textContent = shown.length ? `Hide ${plural(shown.length, 'shown tool')}…` : 'No shown tools to hide';
  $('bulk-show').disabled = !hidden.length; $('bulk-hide').disabled = !shown.length;
  $('bulk-menu').hidden = false; $('bulk-button').setAttribute('aria-expanded', 'true');
  const items = [...$('bulk-menu').querySelectorAll('.menu-action:not(:disabled)')];
  (last ? items.at(-1) : items[0])?.focus();
}
// A bulk change covers every allowed tool in the current search and filter, across all pages.
// Policy-blocked tools keep their saved choice. Showing everything on the unfiltered view sends
// mode all, so tools found later are shown too, but only when that leaves no blocked tool changed.
function prepareBulk(show) {
  const state = toolView(), name = toolScope(), {hidden, shown, blocked} = bulkCounts();
  const targets = show ? hidden : shown, whole = !state.query.trim() && state.filter === 'all';
  const enabled = enabledAfter(name, targets.map(t => [t, show]));
  const everything = tools.filter(t => t.upstream === name).every(t => enabled.includes(t.name));
  const body = whole && show && everything ? {mode: 'all', enabled: []} : {mode: 'selected', enabled};
  return {name, show, count: targets.length, unchanged: (show ? shown : hidden).length, blocked, query: state.query.trim(), filter: state.filter, body};
}
function beginBulk(show) {
  const request = prepareBulk(show);
  if (!request.count) return;
  bulkRequest = request; closeBulkMenu(); $('bulk-button').focus();
  const verb = show ? 'Show' : 'Hide', tools = plural(request.count, 'tool');
  $('bulk-confirm-title').textContent = `${verb} ${tools} ${show ? 'to' : 'from'} clients?`;
  $('bulk-confirm-description').textContent = `${show ? 'Include' : 'Exclude'} ${plural(request.count, show ? 'hidden tool' : 'shown tool')} ${show ? 'in' : 'from'} this connection’s client-facing tool list.`;
  $('bulk-confirm-connection').textContent = request.name;
  $('bulk-confirm-scope').textContent = `${request.query ? `Search “${request.query}” · ` : ''}${visibilityViewLabel(request.filter)}`;
  const already = request.unchanged ? `${plural(request.unchanged, 'tool')} in this view ${request.unchanged === 1 ? 'is' : 'are'} already ${show ? 'shown' : 'hidden'}. ` : '';
  const blocked = request.blocked ? `${plural(request.blocked, 'tool')} blocked by gateway policy will not change. ` : '';
  $('bulk-confirm-unchanged').textContent = `${already}${blocked}Tools outside this view will not change.`;
  $('bulk-confirm-error').textContent = '';
  $('bulk-submit').textContent = `${verb} ${tools}`;
  openDialog('bulk-confirm'); $('bulk-cancel').focus();
}
async function applyBulk() {
  const request = bulkRequest;
  if (!request || mutating) return false;
  $('bulk-submit').disabled = $('bulk-cancel').disabled = true;
  try {
    const saved = await updateVisibility(request.name, request.body.mode, request.body.enabled);
    if (!saved) { $('bulk-confirm-error').textContent = 'Visibility was not saved. No tools changed.'; return false; }
    bulkRequest = null; $('bulk-confirm').close?.();
    toast(`${plural(request.count, 'tool')} ${request.show ? 'shown' : 'hidden'}. Other tools unchanged.`);
    return true;
  } finally { $('bulk-submit').disabled = $('bulk-cancel').disabled = false; }
}
$('bulk-button').addEventListener('click', () => $('bulk-menu').hidden ? openBulkMenu() : closeBulkMenu(true));
$('bulk-button').addEventListener('keydown', event => {
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); openBulkMenu(event.key === 'ArrowUp'); }
  else if (event.key === 'Escape' && !$('bulk-menu').hidden) { event.preventDefault(); event.stopPropagation(); closeBulkMenu(true); }
});
$('bulk-menu').addEventListener('keydown', event => {
  const items = [...$('bulk-menu').querySelectorAll('.menu-action:not(:disabled)')], index = items.indexOf(document.activeElement);
  const move = {ArrowDown: index + 1, ArrowUp: index - 1 + items.length, Home: 0, End: items.length - 1}[event.key];
  if (move !== undefined) { event.preventDefault(); items[move % items.length]?.focus(); }
  else if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); closeBulkMenu(true); }
  else if (event.key === 'Tab') closeBulkMenu();
});
$('bulk-show').addEventListener('click', () => beginBulk(true));
$('bulk-hide').addEventListener('click', () => beginBulk(false));
$('bulk-cancel').addEventListener('click', () => $('bulk-confirm').close());
$('bulk-confirm').addEventListener('close', () => { bulkRequest = null; });
$('bulk-confirm-form').addEventListener('submit', async event => { event.preventDefault(); await applyBulk(); });
document.addEventListener('pointerdown', event => { if (!event.target.closest?.('.bulk-wrap')) closeBulkMenu(); });
$('tools').addEventListener('change', async event => {
  const input = event.target.closest('.tool-visibility'); if (!input) return;
  const item = tools.find(t => toolKey(t) === input.dataset.tool);
  const row = input.closest?.('.tool-row');
  if (row) { row.classList.add('pending'); row.querySelector('.state-word').textContent = 'Updating…'; }
  await setToolVisible(item, input.checked);
});
$('tools').addEventListener('click', event => {
  const expand = event.target.closest('.tool-expand');
  if (expand) {
    const key = expand.dataset.expand;
    if (expandedTools.has(key)) expandedTools.delete(key); else expandedTools.add(key);
    renderTools(); [...$('tools').querySelectorAll('.tool-expand')].find(el => el.dataset.expand === key)?.focus();
    return;
  }
  const retry = event.target.closest('.retry');
  if (retry) { const item = tools.find(t => toolKey(t) === retry.dataset.retry), failed = toolErrors.get(retry.dataset.retry); if (item && failed && !mutating) setToolVisible(item, failed.visible); return; }
  const empty = event.target.closest('[data-empty-action]');
  if (empty) {
    if (empty.dataset.emptyAction === 'clear') clearToolSearch(); else { setToolFilter('all'); $('filter-all').focus(); }
    return;
  }
  const button = event.target.closest('.tool-name'); if (!button) return;
  const item = tools.find(t => toolKey(t) === button.dataset.tool);
  $('tool-title').textContent = toolLabel(item); $('tool-identity').textContent = `${item.upstream} · MCP name: ${item.name}`; $('tool-description').textContent = item.description || 'No description supplied.';
  for (const [id, value] of [['tool-input', item.tool?.inputSchema], ['tool-output', item.tool?.outputSchema], ['tool-annotations', item.tool?.annotations]]) $(id).textContent = value == null ? 'Not supplied by upstream.' : JSON.stringify(value, null, 2);
  historyTool = toolKey(item); historyPage = 1; historyRequest++; showToolTab(false);
  openDialog('tool-dialog');
});
$('close-tool').addEventListener('click', () => $('tool-dialog').close());
function openUpstreamForm() {
  $('upstream-form').reset(); renderAuthFields(); $('header-rows').replaceChildren(); $('upstream-error').textContent = '';
  for (const input of $('upstream-form').querySelectorAll('input')) { input.setCustomValidity(''); input.removeAttribute('aria-invalid'); }
  openDialog('upstream-dialog');
}
$('add-upstream').addEventListener('click', openUpstreamForm);
$('dashboard-add').addEventListener('click', openUpstreamForm);
$('cancel-upstream').addEventListener('click', () => $('upstream-dialog').close());
$('upstream-dialog').addEventListener('close', () => { $('auth-secret').value = ''; $('oauth-client-secret').value = ''; $('header-rows').replaceChildren(); $('upstream-form').reset(); });
$('add-header').addEventListener('click', () => {
  const row = document.createElement('div'); row.className = 'header-row';
  row.innerHTML = '<label>Header name<input class="header-name" placeholder="Authorization" required autocomplete="off"></label><label>New value<input class="header-value" type="password" required autocomplete="off" placeholder="Enter value"></label><button type="button" class="danger" aria-label="Remove new header">Remove</button>';
  row.querySelector('button').addEventListener('click', () => { row.remove(); $('add-header').focus(); });
  $('header-rows').appendChild(row); row.querySelector('input').focus();
});
$('upstream-form').addEventListener('input', event => { if (event.target.setCustomValidity) { event.target.setCustomValidity(''); event.target.removeAttribute('aria-invalid'); } });
function invalid(input, message) { input.setCustomValidity(message); input.setAttribute('aria-invalid', 'true'); input.reportValidity(); }
$('upstream-form').addEventListener('submit', async event => {
  event.preventDefault();
  const endpoint = $('upstream-url'), timeout = $('upstream-timeout'), headers = {}, names = new Set();
  const authType = $('upstream-auth-type').value || 'none';
  const url = new URL(endpoint.value);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '[::1]' || /^127\./.test(url.hostname)))) || url.username || url.password || url.search || url.hash) { invalid(endpoint, 'Use HTTPS or loopback HTTP, without credentials, a query string, or a fragment.'); return; }
  if (!/^(?:\d+(?:\.\d+)?(?:ns|us|µs|μs|ms|s|m|h))+$/.test(timeout.value.trim()) || !/[1-9]/.test(timeout.value)) { invalid(timeout, 'Enter a positive duration such as 30s or 1m.'); return; }
  for (const row of (authType === 'headers' ? $('header-rows').children : [])) {
    const input = row.querySelector('.header-name'), valueInput = row.querySelector('.header-value'), name = input.value.trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || names.has(name.toLowerCase()) || /^(host|content-length|connection|transfer-encoding|upgrade|mcp-session-id)$/i.test(name)) { invalid(input, 'Enter a unique, configurable HTTP header name.'); return; }
    if (/[\r\n]/.test(valueInput.value)) { invalid(valueInput, 'Header values cannot contain line breaks.'); return; }
    names.add(name.toLowerCase()); Object.defineProperty(headers, name, {value: valueInput.value, enumerable: true});
  }
  let oauth;
  if (authType === 'bearer' || authType === 'api_key') {
    const header = authType === 'bearer' ? 'Authorization' : $('auth-header').value.trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header) || /^(host|content-length|connection|transfer-encoding|upgrade|mcp-session-id)$/i.test(header)) { invalid($('auth-header'), 'Enter a configurable HTTP header name.'); return; }
    if (!$('auth-secret').value || /[\r\n]/.test($('auth-secret').value)) { invalid($('auth-secret'), 'Enter a credential without line breaks.'); return; }
    Object.defineProperty(headers, header, {value: (authType === 'bearer' ? 'Bearer ' : '') + $('auth-secret').value, enumerable: true});
  }
  if (authType === 'oauth') {
    oauth = {client_id: $('oauth-client-id').value.trim(), client_secret: $('oauth-client-secret').value, issuer: $('oauth-issuer').value.trim(), scopes: $('oauth-scopes').value.trim().split(/\s+/).filter(Boolean)};
    if (oauth.client_id && !oauth.issuer) { invalid($('oauth-issuer'), 'Enter the issuer registered with this client.'); return; }
    if (oauth.client_secret && !oauth.client_id) { invalid($('oauth-client-id'), 'Enter the client ID for this secret.'); return; }
  }
  $('save-upstream').disabled = true; $('save-upstream').textContent = 'Adding…'; $('upstream-error').textContent = '';
  const name = $('upstream-name').value.trim();
  try {
    await api('/api/connections', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name, url: endpoint.value.trim(), call_timeout: timeout.value.trim(), headers, auth_type: authType, oauth})});
    selected = name; $('upstream-search').value = ''; $('upstream-dialog').close(); navigate(`/upstreams/${encodeURIComponent(name)}`); await refresh();
    notice(`Added ${name}. Discovery may still be starting; reload the inventory to see its latest state.`);
  } catch (error) { $('upstream-error').textContent = `Connection was not added. ${error.message}`; }
  finally { $('save-upstream').disabled = false; $('save-upstream').textContent = 'Add upstream'; }
});
$('cancel-remove').addEventListener('click', () => $('remove-dialog').close());
$('remove-form').addEventListener('submit', async event => {
  event.preventDefault(); const name = $('remove-form').dataset.name;
  $('confirm-remove').disabled = true;
  try { await api(`/api/connections/${encodeURIComponent(name)}`, {method: 'DELETE'}); refreshState.delete(name); $('remove-dialog').close(); navigate('/upstreams'); await refresh(); $('refresh').focus(); notice(`Removed ${name}.`); }
  catch (error) { $('remove-error').textContent = error.message; }
  finally { $('confirm-remove').disabled = false; }
});
function setRegistration(value) {
  registering = value;
  $('login-title').textContent = value ? 'Create your workspace' : 'Welcome back';
  $('login-intro').textContent = value ? 'Create an account to keep your connections and credentials separate.' : 'Sign in to manage your connections and tools.';
  $('confirm-label').hidden = !value; $('account-confirm').required = value;
  $('password-help').hidden = !value;
  $('account-password').minLength = value ? 15 : 1;
  $('account-password').autocomplete = value ? 'new-password' : 'current-password';
  $('account-submit').textContent = value ? 'Create account' : 'Sign in';
  $('toggle-registration').textContent = value ? 'Already have an account? Sign in' : 'Create an account';
  $('account-error').textContent = ''; $('account-password').value = ''; $('account-confirm').value = '';
}
$('toggle-registration').addEventListener('click', () => setRegistration(!registering));
$('operator-login').addEventListener('click', () => { $('auth-dialog').returnValue = ''; openDialog('auth-dialog'); });
async function accountRequest(path, body = {}) {
  const response = await fetch(path, {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-MCPWarden-Request': 'browser'}, body: JSON.stringify(body)});
  if (!response.ok) throw new Error(response.status === 401 ? 'Username or password is incorrect.' : response.status === 409 ? 'Registration could not be completed. Try a different username.' : response.status === 429 ? 'Too many attempts. Wait a minute and try again.' : response.status === 403 ? 'This action is not available. Registration may be closed.' : 'The request could not be completed. Please try again.');
  return response.status === 204 ? null : response.json();
}
$('account-form').addEventListener('submit', async event => {
  event.preventDefault(); $('account-error').textContent = '';
  if (registering && $('account-password').value !== $('account-confirm').value) { $('account-error').textContent = 'Passwords do not match.'; $('account-confirm').focus(); return; }
  $('account-submit').disabled = true;
  try {
    await accountRequest(registering ? '/api/auth/register' : '/api/auth/login', {username: $('account-username').value.trim(), password: $('account-password').value});
    clearWorkspace(); setRegistration(false); await refresh(); applyRoute(true);
  } catch (error) { $('account-error').textContent = error.message; }
  finally { $('account-submit').disabled = false; }
});
$('disconnect').addEventListener('click', async () => {
  try { if (accountMode === 'accounts') await accountRequest('/api/auth/logout'); clearWorkspace(); notice(); $('account-username').focus(); }
  catch (error) { notice(`Could not sign out. ${error.message}`); }
});
$('copy-client-token').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('client-token').value); $('client-error').textContent = 'Copied.'; }
  catch (_) { $('client-token').focus(); $('client-token').select(); $('client-error').textContent = 'Select the token and copy it manually.'; }
});
$('close-client').addEventListener('click', () => $('client-dialog').close());
$('client-dialog').addEventListener('close', () => { $('client-token').value = ''; });
async function start() {
  try {
    const response = await fetch('/api/auth/options', {cache: 'no-store'});
    if (response.ok) {
      const options = await response.json(); accountMode = options.mode;
      $('operator-login').hidden = options.mode === 'accounts';
      $('auth-explanation').textContent = options.mode === 'accounts' ? 'This is advanced access to the shared operator workspace. Use username and password for your personal account.' : options.mode === 'oauth' ? 'Use an OAuth token with management permission issued by your identity provider.' : 'Use the configured operator credential for the shared workspace.';
      $('account-form').hidden = options.mode !== 'accounts';
      $('toggle-registration').hidden = !options.registration;
      if (options.mode !== 'accounts') {
        $('login-title').textContent = options.mode === 'oauth' ? 'Connect your personal workspace' : 'Connect to the gateway';
        $('login-intro').textContent = options.mode === 'oauth' ? 'Use an access token from your identity provider. The verified identity selects your workspace.' : 'This gateway uses a shared operator token. Local account registration is not enabled.';
      }
    }
  } catch (_) { $('account-error').textContent = 'Cannot reach the gateway. Check the connection and try again.'; }
  await refresh();
  initialLoad = false;
  renderIdentity();
}
applyRoute(); renderIdentity(); start();

async function setProviderEnabled(name, enabled) {
  if (!access || !managedAvailable || mutating || refreshState.get(name)?.pending) return;
  pendingProvider = {name, enabled};
  mutating = true; lockMutationControls();
  try {
    await api(`/api/providers/${encodeURIComponent(name)}/enabled`, {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled})});
    refreshState.delete(name);
    await refresh(false);
  } catch (error) { notice(`Provider setting was not saved. ${error.message}`); }
  finally { pendingProvider = null; mutating = false; render(); }
}
$('provider-enabled').addEventListener('click', async event => { await setProviderEnabled(selected, event.currentTarget.dataset.enable === 'true'); $('provider-enabled').focus(); });

function authLabel(type) { return ({none:'No authentication',bearer:'Bearer token',api_key:'API key header',headers:'Custom headers',oauth:'OAuth account'})[type] || 'Custom headers'; }
function renderAuthFields() {
  const type = $('upstream-auth-type').value;
  $('auth-secret-fields').hidden = type !== 'bearer' && type !== 'api_key';
  $('auth-secret').required = type === 'bearer' || type === 'api_key';
  $('auth-header-label').hidden = type !== 'api_key';
  $('auth-header').required = type === 'api_key';
  $('upstream-oauth-fields').hidden = type !== 'oauth';
  $('custom-header-fields').hidden = type !== 'headers';
  $('oauth-callback-url').textContent = `${location.origin}/api/upstream-oauth/callback`;
  for (const input of $('custom-header-fields').querySelectorAll('input')) input.disabled = type !== 'headers';
  for (const input of $('upstream-oauth-fields').querySelectorAll('input')) input.disabled = type !== 'oauth';
}
$('upstream-auth-type').addEventListener('change', renderAuthFields);
$('connect-upstream-account').addEventListener('click', async () => {
  const name = selected;
  const popup = window.open('about:blank', '_blank');
  if (!popup) { notice('Allow a new window to connect this account, then try again.'); return; }
  popup.opener = null;
  mutating = true; render();
  try {
    const result = await api(`/api/providers/${encodeURIComponent(name)}/oauth`, {method:'POST'});
    popup.location.href = result.authorization_url;
    notice('Finish authorization in the new window, then reload the inventory.');
  } catch (error) { popup.close(); notice(`Account connection could not start. ${error.message}`); }
  finally { mutating = false; render(); }
});

function activeAccess(item) { return !item.revoked_at && !item.ended_at && !item.deleted_at && (!item.expires_at || new Date(item.expires_at) > new Date()); }
function publicAccessHandle(item, items = []) {
  if (!/^[0-9a-f]{32}$/.test(item.public_id || '')) return '';
  let length = 4;
  while (length < 32 && items.some(other => other.id !== item.id && other.public_id?.endsWith(item.public_id.slice(-length)))) length += 4;
  return '…' + item.public_id.slice(-length);
}
function renderAccess() {
  const items = accessData?.items || [], active = items.filter(activeAccess), limits = accessData?.limits;
  for (const [id, kind, max] of [['access-key-count','api_key','api_keys'],['access-login-count','login','login_sessions'],['access-mcp-count','mcp','mcp_connections']]) {
    const count = active.filter(i => kind === 'login' ? i.kind === 'browser' || i.kind === 'oauth' : i.kind === kind).length;
    $(id).textContent = limits ? `${count} of ${limits[max]} ${kind==='mcp'?'connected':'active'}` : '—';
  }
  $('create-key').disabled = keyMinting || !access || accessLoading || !accessData || active.filter(i => i.kind === 'api_key').length >= (limits?.api_keys || 10);
  $('open-key-create').disabled=$('create-key').disabled;
  $('cancel-key-create').disabled=keyMinting;
  $('reload-access').disabled = !access || accessLoading;
  const row = item => {
    const live = activeAccess(item), current = item.id === accessData?.current_id;
    const kind = ({api_key:'API key',browser:'Browser',oauth:'OAuth',mcp:'MCP connection'})[item.kind] || item.kind;
    const state = item.revoked_at ? 'Revoked' : item.ended_at ? 'Ended' : live ? 'Active' : 'Expired';
    return `<article class="access-row"><div class="access-record"><h3>${escapeHTML(item.name)}${item.public_id ? ` <small title="Public key ID: ${escapeHTML(item.public_id)}">${escapeHTML(publicAccessHandle(item, items))}</small>` : ''}${current ? ' <span class="access-current">This session</span>' : ''}</h3><p class="help">${escapeHTML(kind)} · ${item.role === 'admin' ? 'Admin' : 'Client'} · <span class="badge ${live?'success':''}">${state}</span></p><div class="record-meta"><span>Created ${escapeHTML(accessDate(item.created_at))}</span><span>Last used ${escapeHTML(accessDate(item.last_used_at,true))}</span><span>${item.revoked_at?'Revoked':item.ended_at?'Ended':'Expires'} ${escapeHTML(accessDate(item.revoked_at||item.ended_at||item.expires_at))}</span></div><details class="record-details"><summary>Device and exact timestamps</summary>${item.device ? `<p class="access-device">${escapeHTML(item.device)}</p>` : ''}<dl class="access-times">${item.public_id ? `<div><dt>Public key ID</dt><dd>${escapeHTML(item.public_id)}</dd></div>` : ''}<div><dt>Created</dt><dd>${escapeHTML(date(item.created_at))}</dd></div><div><dt>Last used</dt><dd>${escapeHTML(date(item.last_used_at))}</dd></div><div><dt>${item.revoked_at ? 'Revoked' : item.ended_at ? 'Ended' : 'Expires'}</dt><dd>${escapeHTML(date(item.revoked_at || item.ended_at || item.expires_at))}</dd></div></dl></details></div>${live ? `<div class="access-row-actions"><button type="button" data-access-id="${escapeHTML(item.id)}" data-action="rename">Rename</button><button type="button" class="danger" data-access-id="${escapeHTML(item.id)}" data-action="revoke">Revoke</button></div>` : ''}</article>`;
  };
  for (const [id, list] of [['access-keys',active.filter(i=>i.kind==='api_key')],['access-sessions',active.filter(i=>i.kind==='browser'||i.kind==='oauth')],['access-mcp-sessions',active.filter(i=>i.kind==='mcp')],['access-history',items.filter(i=>!activeAccess(i))]]) $(id).innerHTML = list.length ? list.map(row).join('') : `<p class="empty">${accessLoading ? 'Loading access…' : accessData ? (id==='access-mcp-sessions'?'No active MCP connections.':id==='access-keys'?'No active API keys.':id==='access-sessions'?'No signed-in sessions.':'No past access records.') : 'Access records are unavailable.'}</p>`;
}
async function loadAccess() {
  if (accessLoading || !access) return;
  const epoch = identityEpoch; accessLoading = true; renderAccess();
  try { const data = await api('/api/access'); if (epoch === identityEpoch) accessData = data; }
  catch(error) { if (epoch === identityEpoch) notice(`Could not load access. ${error.message}`); }
  finally { if (epoch === identityEpoch) {accessLoading = false; renderAccess();} }
}
$('reload-access').addEventListener('click', loadAccess);
$('key-form').addEventListener('submit', async event => {
  event.preventDefault(); if(keyMinting)return; keyMinting=true; renderAccess(); $('key-create-error').textContent='';
  const name = $('key-name').value.trim(), role = $('key-role').value;
  try {
    const result = await api('/api/access', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,role,expires_days:Number($('key-expiry').value)})});
    $('client-token').value = result.token; $('client-error').textContent = '';
    $('client-key-description').textContent = `${name} · ${role === 'admin' ? 'Admin: management API and management MCP tools.' : 'Client: enabled tools and provider refresh only.'}`;
    $('key-create').close(); openDialog('client-dialog'); dialogTriggers.set('client-dialog',$('open-key-create')); $('client-token').focus(); $('client-token').select(); $('key-name').value = ''; await loadAccess();
  } catch(error) {$('key-create-error').textContent=`Key was not created. ${error.status === 409 ? 'The active-key limit was reached or storage is unavailable.' : error.message}`;}
  finally {keyMinting=false;renderAccess();}
});
for (const container of ['access-keys','access-sessions','access-mcp-sessions']) $(container).addEventListener('click', event => {
  const button = event.target.closest('button[data-access-id]'); if (!button) return;
  const item = accessData?.items.find(i=>i.id===button.dataset.accessId); if (!item) return;
  accessAction = {id:item.id,action:button.dataset.action};
  const revoke = accessAction.action === 'revoke';
  $('access-action-title').textContent = revoke ? 'Revoke access?' : 'Rename access';
  $('access-action-description').textContent = revoke ? `Revoke “${item.name}”? ${item.id === accessData.current_id ? 'This will disconnect your current session.' : item.kind === 'api_key' ? 'MCP connections using this key will be disconnected.' : 'This session will be disconnected.'}` : 'Choose a name that helps you recognize this app or device.';
  $('access-name-label').hidden = revoke; $('access-name').required = !revoke; $('access-name').value = item.name;
  $('access-action-error').textContent = ''; $('confirm-access-action').textContent = revoke ? 'Revoke' : 'Save name'; $('confirm-access-action').className = revoke ? 'danger' : 'primary';
  openDialog('access-action-dialog'); (revoke ? $('cancel-access-action') : $('access-name')).focus();
});
$('cancel-access-action').addEventListener('click', ()=>$('access-action-dialog').close());
$('access-action-form').addEventListener('submit', async event => {
  event.preventDefault(); if (!accessAction) return;
  const {id,action} = accessAction; $('confirm-access-action').disabled = true;
  try {
    await api(`/api/access/${encodeURIComponent(id)}`,{method:action==='revoke'?'DELETE':'PATCH',headers:{'Content-Type':'application/json'},...(action==='rename'?{body:JSON.stringify({name:$('access-name').value.trim()})}:{})});
    $('access-action-dialog').close();
    if (action==='revoke' && id===accessData.current_id) {clearWorkspace();notice('This session was revoked. Sign in to reconnect.');}
    else await loadAccess();
  }catch(error){$('access-action-error').textContent=error.message;}
  finally{$('confirm-access-action').disabled=false;}
});

function callStatus(r) {
 return ({ok:'Success',tool_error:'Tool error',protocol_error:'Protocol error',timeout:'Timed out',denied:'Denied',unavailable:'Unavailable',unknown:'Outcome unknown',audit_error:'Audit unavailable'})[r.status] || r.status;
}
function callResponse(r) {
 return r.status === 'unknown' ? 'Completion not recorded. Execution may have started; do not assume retry is safe.' : `${Number(r.response_items)} response item${r.response_items===1?'':'s'}${r.structured?' · Structured response':''}`;
}
function callActor(r) {
 if (!r.actor_access_id) return '';
 return `<small class="history-response" title="Access ID: ${escapeHTML(r.actor_access_id)}${r.actor_public_id ? ' · Public ID: '+escapeHTML(r.actor_public_id) : ''}">Caller: ${escapeHTML(r.actor_label_snapshot || r.actor_type)}${r.actor_public_id ? ' · …'+escapeHTML(r.actor_public_id.slice(-8)) : ''}</small>`;
}
function callTiming(r) {
 if (r.status === 'unknown') return 'Completion not recorded';
 if (!r.timing) return `${Number(r.duration_ms)} ms`;
 const ms = us => (Number(us) / 1000).toLocaleString(undefined, {maximumFractionDigits: 3});
 return `${ms(r.timing.handler_us)} ms total · ${r.timing.forwarded ? ms(r.timing.upstream_us)+' ms upstream' : 'Not forwarded'} · ${ms(r.timing.gateway_us)} ms gateway`;
}
function performanceSummary(p) {
 if (!p?.timed_calls) return '';
 const ms = us => (Number(us) / 1000).toLocaleString(undefined, {maximumFractionDigits: 3});
 return ` · ${p.timed_calls} timed · Average: ${ms(p.upstream.mean_us)} ms upstream / ${ms(p.gateway.mean_us)} ms gateway · p95 total ≤ ${ms(p.handler.p95_upper_us)} ms`;
}
let historyTool = '', historyPage = 1, historyRequest = 0;
function showToolTab(history) {
 $('tool-details-panel').hidden=history; $('tool-history-panel').hidden=!history;
 for (const [id,active] of [['tool-details-tab',!history],['tool-history-tab',history]]) {$(id).setAttribute('aria-selected',String(active));$(id).tabIndex=active?0:-1;}
 if(history) loadToolHistory();
}
async function loadToolHistory() {
 const request=++historyRequest,epoch=identityEpoch;
 $('tool-history-status').textContent='Loading history…';$('tool-history-rows').innerHTML='';
 $('history-previous').disabled=$('history-next').disabled=$('history-refresh').disabled=true;
 try {
  const result=await api(`/api/history?tool_id=${encodeURIComponent(historyTool)}&page=${historyPage}`);
  if(request!==historyRequest||epoch!==identityEpoch)return;
  $('tool-history-status').textContent=`${result.total} calls recorded${performanceSummary(result.performance)}`;
  $('tool-history-rows').innerHTML=result.items.length?result.items.map(r=>`<article class="history-row"><div><strong>${escapeHTML(callStatus(r))}</strong><time>${escapeHTML(date(r.ts))}</time></div><p>${escapeHTML(callTiming(r))} · ${escapeHTML(callResponse(r))}</p>${callActor(r)}</article>`).join(''):'<p class="empty">No calls recorded for this tool yet.</p>';
  $('history-page').textContent=`Page ${historyPage} of ${Math.max(1,Math.ceil(result.total/25))}`;
  $('history-previous').disabled=historyPage<=1;$('history-next').disabled=historyPage*25>=result.total||historyPage>=1000;
 }catch(error){if(request===historyRequest)$('tool-history-status').textContent=`History unavailable. ${error.message}`;}
 finally{if(request===historyRequest)$('history-refresh').disabled=false;}
}
$('tool-details-tab').addEventListener('click',()=>showToolTab(false));
$('tool-history-tab').addEventListener('click',()=>showToolTab(true));
for(const id of ['tool-details-tab','tool-history-tab'])$(id).addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();const history=event.key==='End'||(event.key!=='Home'&&id==='tool-details-tab');showToolTab(history);$(history?'tool-history-tab':'tool-details-tab').focus();}});
$('history-previous').addEventListener('click',()=>{historyPage--;loadToolHistory();});
$('history-next').addEventListener('click',()=>{historyPage++;loadToolHistory();});
$('history-refresh').addEventListener('click',loadToolHistory);
$('tool-dialog').addEventListener('close',()=>{historyRequest++;$('tool-history-rows').innerHTML='';});
function passwordDirty() {return ['current-password','new-password','confirm-new-password'].some(id=>$(id).value);}
function clearPasswordForm() {
 $('password-form').reset();$('password-error').textContent='';$('password-success').textContent='';
 for(const button of document.querySelectorAll('[data-password-show]')) {$(button.dataset.passwordShow).type='password';button.textContent='Show';button.setAttribute('aria-pressed','false');button.setAttribute('aria-label','Show '+$(button.dataset.passwordShow).labels[0].textContent.toLowerCase());}
}
function renderAccountSettings() {
 const native=session?.mode==='account', local=session?.mode==='local';
 const name=local?'Local operator':session?.username||session?.subject||'Account';
 for(const id of ['footer-identity','menu-identity','settings-identity-value'])$(id).textContent=name;
 $('menu-mode').textContent=local?'Static operator bearer':native?'Local account':'External identity';
 $('footer-mode').textContent=$('menu-mode').textContent;
 $('settings-identity-label').textContent=local?'Identity':native?'Username':'Verified subject';
 $('settings-mode').textContent=local?'Static operator bearer':native?'Local account':'External identity';
 $('change-password').textContent=native?'Password & security':'Security';
 $('security-title').textContent=local?'Static operator bearer':native?'Change password':'Externally managed identity';
 $('password-form').hidden=!native;
 $('password-provider-help').hidden=native;
 $('password-provider-help').textContent=local?'This workspace uses a configured operator credential and has no personal password. Forget local credential clears this browser’s in-memory access only; it does not rotate or revoke the server token.':'Manage your password with your identity provider. Disconnecting this browser does not sign you out of that provider or revoke its token.';
 const section=readRoute().section||'account';
 for(const name of ['account','appearance','security'])$('settings-'+name).hidden=name!==section;
 for(const link of document.querySelectorAll('[data-settings-section]')) {if(link.dataset.settingsSection===section)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');}
 $('settings-back').href=typeof workspaceReturn==='string'?workspaceReturn:'/dashboard';
}
$('cancel-password').addEventListener('click',()=>{if(!passwordDirty()||window.confirm('Discard unsaved password changes?'))clearPasswordForm();});
for(const button of document.querySelectorAll('[data-password-show]'))button.addEventListener('click',()=>{const input=$(button.dataset.passwordShow),show=input.type==='password';input.type=show?'text':'password';button.textContent=show?'Hide':'Show';button.setAttribute('aria-pressed',String(show));button.setAttribute('aria-label',(show?'Hide ':'Show ')+input.labels[0].textContent.toLowerCase());});
$('password-form').addEventListener('submit',async event=>{
 event.preventDefault();if($('save-password').disabled)return;
 $('password-error').textContent='';$('password-success').textContent='';
 if($('new-password').value!==$('confirm-new-password').value){$('password-error').textContent='New passwords do not match.';$('confirm-new-password').focus();return;}
 const epoch=identityEpoch;
 $('save-password').disabled=true;
 try{await api('/api/auth/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:$('current-password').value,new_password:$('new-password').value})});if(epoch!==identityEpoch)return;clearPasswordForm();$('password-success').textContent='Password changed. Other browser sessions have been signed out.';}
 catch(error){if(epoch!==identityEpoch)return;$('password-error').textContent=error.status===400?'Check your current password. The new password must contain at least 15 characters and no more than 1024 bytes.':error.status===429?'Too many attempts. Wait a minute and try again.':error.status===409?'Your account changed during this request. Please try again.':error.message;}
 finally{$('save-password').disabled=false;}
});
$('account-launcher').addEventListener('keydown',event=>{if(event.key==='Escape'){$('account-launcher').open=false;$('account-launcher-trigger').focus();}});
window.addEventListener('click',event=>{if(!$('account-launcher').contains(event.target))$('account-launcher').open=false;});
window.addEventListener('beforeunload',event=>{if(passwordDirty()){event.preventDefault();event.returnValue='';}});

function historyCallRow(r) {
 const name=r.upstream&&r.tool.startsWith(r.upstream+'__')?r.tool.slice(r.upstream.length+2):r.tool;
 const status=callStatus(r);
 const ms=us=>`${(Number(us)/1000).toLocaleString(undefined,{maximumFractionDigits:3})} ms`;
 const total=r.status==='unknown'?'Not recorded':r.timing?ms(r.timing.handler_us):`${Number(r.duration_ms).toLocaleString()} ms`;
 const upstream=r.timing?(r.timing.forwarded?ms(r.timing.upstream_us):'Not forwarded'):'Not recorded';
 const gateway=r.timing?ms(r.timing.gateway_us):'Not recorded';
 return `<tr><td data-label="Time"><time datetime="${escapeHTML(r.ts)}">${escapeHTML(date(r.ts))}</time></td><td data-label="Tool"><span class="history-tool">${escapeHTML(name)}</span><small class="history-response">${escapeHTML(callResponse(r))}</small>${callActor(r)}</td><td data-label="Upstream provider">${escapeHTML(r.upstream||'Gateway management')}</td><td data-label="Status"><span class="badge ${r.status==='ok'?'success':'warning'}">${escapeHTML(status)}</span></td><td data-label="Total time" class="history-duration">${escapeHTML(total)}</td><td data-label="Upstream time" class="history-duration">${escapeHTML(upstream)}</td><td data-label="Gateway time" class="history-duration">${escapeHTML(gateway)}</td></tr>`;
}

let callsToolOptions=[];
let callsPage=1,callsRequest=0,callsLoaded=false,callsLoading=false;
let appliedRange={from:'',to:'',fromTime:'',toTime:'',fromISO:'',toISO:''};
const rangeRaw=()=>({from:$('calls-from').value,to:$('calls-to').value,fromTime:$('calls-from-time').value,toTime:$('calls-to-time').value});
function writeRange(raw) {
 for(const side of ['from','to']) { $('calls-'+side).value=raw[side];$('calls-'+side+'-time').value=raw[side+'Time']; }
 renderRange();
}
function validateRange(show=false) {
 const raw=rangeRaw(), result={...raw}, errors={};
 for(const side of ['from','to']) {
  const date=raw[side],time=raw[side+'Time'];
  try {
   if(!date&&!time&&!$('calls-'+side).validity?.badInput)result[side+'ISO']='';
   else result[side+'ISO']=window.MCPWardenTime.toISO(`${date}T${time}`);
  } catch(error) {errors[side]=error.message;}
 }
 if(!Object.keys(errors).length&&result.fromISO&&result.toISO&&result.fromISO>=result.toISO)errors.to='Until must be later than From.';
 if(show)for(const side of ['from','to']) {
  const message=errors[side]||'';
  $('calls-'+side+'-error').textContent=message;$('calls-'+side+'-error').hidden=!message;
  for(const suffix of ['', '-time'])$('calls-'+side+suffix).setAttribute('aria-invalid',String(Boolean(message)));
 }
 return {raw:result,errors,valid:!Object.keys(errors).length};
}
function renderRange() {
 const {raw,valid}=validateRange(),dirty=['from','to','fromTime','toTime'].some(key=>raw[key]!==appliedRange[key]);
 $('history-range-revert').disabled=!dirty;
 let description='All time';
 if(!valid)description='Complete a valid date and time';
 else if(raw.fromISO&&raw.toISO) {const minutes=(Date.parse(raw.toISO)-Date.parse(raw.fromISO))/60000;description=`${Math.floor(minutes/60)}h ${minutes%60}m selected`;}
 else if(raw.fromISO||raw.toISO)description='Open-ended range';
 $('history-range-state').title=valid?[raw.fromISO?'From inclusive: '+raw.fromISO:'',raw.toISO?'Until exclusive: '+raw.toISO:''].filter(Boolean).join(' · '):'';
 $('history-range-state').textContent=`${description} · 24-hour time${dirty?' · Not applied — press Apply filters below':''}`;
 $('history-range-summary').textContent='Date & time range · '+(dirty?'Draft':appliedRange.fromISO||appliedRange.toISO?`${appliedRange.from||'Any time'} ${appliedRange.fromTime} → ${appliedRange.to||'Any time'} ${appliedRange.toTime}`:'All time');
}
for(const side of ['from','to'])for(const suffix of ['', '-time'])$('calls-'+side+suffix).addEventListener('input',()=>{renderRange();});
$('history-range-revert').addEventListener('click',()=>{writeRange(appliedRange);validateRange(true);});
for(const button of document.querySelectorAll('[data-range-minutes]'))button.addEventListener('click',()=>{
 const end=Math.floor(Date.now()/60000)*60000,start=end-Number(button.dataset.rangeMinutes)*60000;
 const civil=instant=>{
  const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:window.MCPWardenTime.zone(),year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(instant)).map(p=>[p.type,p.value]));
  return {date:`${p.year}-${p.month}-${p.day}`,time:`${p.hour}:${p.minute}`};
 };
 const a=civil(start),b=civil(end);writeRange({from:a.date,fromTime:a.time,to:b.date,toTime:b.time});validateRange(true);
});

async function loadCalls() {
 if(!access)return;
 const request=++callsRequest,epoch=identityEpoch;callsLoading=true;
 $('calls-refresh').disabled=$('calls-previous').disabled=$('calls-next').disabled=true;
 $('calls-summary').textContent='Loading history…';
 try{
  const params=new URLSearchParams({page:String(callsPage)});
  for(const [key,id]of [['upstream','calls-upstream'],['tool_id','calls-tool'],['status','calls-status']])if($(id).value)params.set(key,$(id).value);
  const from=appliedRange.fromISO,to=appliedRange.toISO;
  if(from)params.set('from',from);if(to)params.set('to',to);
  const result=await api(`/api/history?${params}`);
  if(request!==callsRequest||epoch!==identityEpoch)return;
  callsLoaded=true;
  const upstream=$('calls-upstream').value;
  callsToolOptions=result.tools;
  const services=[...new Set(result.tools.map(t=>t.upstream||'__gateway__'))].sort();
  $('calls-upstream').innerHTML='<option value="">All upstreams</option>'+services.map(name=>`<option value="${escapeHTML(name)}">${escapeHTML(name==='__gateway__'?'Gateway management':name)}</option>`).join('');$('calls-upstream').value=upstream;
  renderCallsToolOptions();
  $('calls-summary').textContent=`${result.total} matching call${result.total===1?'':'s'}${performanceSummary(result.performance)}`;
  $('calls-rows').innerHTML=result.items.length?`<table class="history-table"><caption class="sr-only">Tool call history. Times use ${escapeHTML(window.MCPWardenTime.zone())}.</caption><thead><tr><th scope="col">Time <small class="history-zone">${escapeHTML(window.MCPWardenTime.zone())}</small></th><th scope="col">Tool</th><th scope="col">Upstream provider</th><th scope="col">Status</th><th scope="col">Total time</th><th scope="col">Upstream time</th><th scope="col">Gateway time</th></tr></thead><tbody>${result.items.map(historyCallRow).join('')}</tbody></table>`:'<p class="empty">No calls match these filters.</p>';
  $('calls-pagination').textContent=`Page ${callsPage} of ${Math.max(1,Math.ceil(result.total/25))}`;
  $('calls-previous').disabled=callsPage<=1;$('calls-next').disabled=callsPage*25>=result.total||callsPage>=1000;
 }catch(error){if(request===callsRequest){$('calls-summary').textContent=`History unavailable. ${error.message}`;$('calls-rows').innerHTML='';}}
 finally{if(request===callsRequest){callsLoading=false;$('calls-refresh').disabled=false;}}
}
$('calls-filters').addEventListener('submit',event=>{event.preventDefault();const result=validateRange(true);if(!result.valid){$('history-time-range').open=true;$('calls-'+Object.keys(result.errors)[0]).focus();return;}appliedRange=result.raw;renderRange();callsPage=1;loadCalls();});
$('calls-reset').addEventListener('click',()=>{$('calls-filters').reset();appliedRange={from:'',to:'',fromTime:'',toTime:'',fromISO:'',toISO:''};renderRange();validateRange(true);callsPage=1;loadCalls();});
$('calls-refresh').addEventListener('click',loadCalls);
$('calls-previous').addEventListener('click',()=>{callsPage--;loadCalls();});
$('calls-next').addEventListener('click',()=>{callsPage++;loadCalls();});

function renderCallsToolOptions() {
 const service=$('calls-upstream').value,selected=$('calls-tool').value;
 $('calls-tool').disabled=!service;
 $('calls-tool').innerHTML=`<option value="">${service?'All tools in this service':'Select an upstream first'}</option>`+(service?callsToolOptions.filter(t=>(t.upstream||'__gateway__')===service).map(t=>`<option value="${escapeHTML(t.id)}">${escapeHTML(t.upstream&&t.name.startsWith(t.upstream+'__')?t.name.slice(t.upstream.length+2):t.name)}</option>`).join(''):'');
 $('calls-tool').value=service&&callsToolOptions.some(t=>t.id===selected&&(t.upstream||'__gateway__')===service)?selected:'';
}
$('calls-upstream').addEventListener('change',()=>{$('calls-tool').value='';renderCallsToolOptions();callsPage=1;loadCalls();});

function positionAccountMenu() {
 const launcher=$('account-launcher');if(!launcher.open)return;
 const trigger=$('account-launcher-trigger').getBoundingClientRect(), menu=launcher.querySelector('.account-menu-content');
 const viewport=window.visualViewport, width=viewport?.width||window.innerWidth, height=viewport?.height||window.innerHeight;
 const leftEdge=viewport?.offsetLeft||0, topEdge=viewport?.offsetTop||0;
 const mobile=window.matchMedia('(max-width: 760px)').matches;
 menu.style.maxHeight=Math.max(120,height-24)+'px';
 const box=menu.getBoundingClientRect();
 const left=Math.max(leftEdge+12,Math.min(mobile?trigger.right-box.width:trigger.left,leftEdge+width-box.width-12));
 let top=mobile?trigger.bottom+8:trigger.top-box.height-8;
 if(top+box.height>topEdge+height-12)top=trigger.top-box.height-8;
 top=Math.max(topEdge+12,Math.min(top,topEdge+height-box.height-12));
 menu.style.left=left+'px';menu.style.top=top+'px';menu.style.bottom='auto';
}
function syncAccountPlacement() {
 if(!window.matchMedia)return;
 const mobile=window.matchMedia('(max-width: 760px)').matches;
 const slot=$(mobile?'mobile-account-slot':'desktop-account-slot');
 if($('account-launcher').parentElement!==slot)slot.appendChild($('account-launcher'));
 positionAccountMenu();
}
$('mobile-navigation').addEventListener('click',()=>{
 const open=$('mobile-navigation').getAttribute('aria-expanded')!=='true';
 $('mobile-navigation').setAttribute('aria-expanded',String(open));
 $('mobile-navigation').setAttribute('aria-label',open?'Close navigation':'Open navigation');
 $('workspace-nav').classList.toggle('mobile-open',open);
});
$('workspace-nav').addEventListener('keydown',event=>{if(event.key==='Escape'){$('workspace-nav').classList.remove('mobile-open');$('mobile-navigation').setAttribute('aria-expanded','false');$('mobile-navigation').setAttribute('aria-label','Open navigation');$('mobile-navigation').focus();}});
$('account-launcher').addEventListener('toggle',positionAccountMenu);
window.addEventListener('resize',syncAccountPlacement);
window.addEventListener('scroll',positionAccountMenu,true);
window.visualViewport?.addEventListener('resize',positionAccountMenu);
syncAccountPlacement();

$('connection-settings-link').addEventListener('click',()=>{if(readRoute().section==='tools')connectorScroll.set(selected,window.scrollY||0);});

function renderTimezone() {
 const clock=window.MCPWardenTime;
 $('ui-timezone').innerHTML='<option value="system">Device timezone (automatic)</option>'+clock.zones().map(zone=>`<option value="${escapeHTML(zone)}">${escapeHTML(zone.replaceAll('_',' '))}</option>`).join('');
 $('ui-timezone').value=clock.preference();
 $('timezone-current').textContent=`Current timezone: ${clock.zone()}`;
 $('history-timezone-help').textContent=`Timezone: ${clock.zone()}. Dates and 24-hour times use this zone.`;
}
function timezoneChanged() {
 const dirty=['from','to','fromTime','toTime'].some(key=>rangeRaw()[key]!==appliedRange[key]);
 for(const side of ['from','to'])if(appliedRange[side+'ISO']) {
  const parts=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:window.MCPWardenTime.zone(),year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(appliedRange[side+'ISO'])).map(p=>[p.type,p.value]));
  appliedRange[side]=`${parts.year}-${parts.month}-${parts.day}`;appliedRange[side+'Time']=`${parts.hour}:${parts.minute}`;
 }
 if(!dirty)writeRange(appliedRange);else renderRange();
 renderTimezone(); callsLoaded=false; callsRequest++;callsLoading=false;
 $('calls-rows').innerHTML='';
 render();
 if($('tool-dialog').open&&!$('tool-history-panel').hidden)loadToolHistory();
}
$('ui-timezone').addEventListener('change',()=>{window.MCPWardenTime.set($('ui-timezone').value);timezoneChanged();});
window.addEventListener('storage',event=>{if(event.key==='mcpwarden-timezone'||event.key===null){try{window.MCPWardenTime.set(event.newValue||'system');}catch(_){window.MCPWardenTime.set('system');}timezoneChanged();}});
renderTimezone();

function accessDate(value, time=false) {
 if(!value)return 'not recorded';
 return new Intl.DateTimeFormat(undefined,{timeZone:window.MCPWardenTime.zone(),day:'2-digit',month:'short',year:'numeric',...(time?{hour:'2-digit',minute:'2-digit',hourCycle:'h23',timeZoneName:'short'}:{})}).format(new Date(value));
}
$('open-key-create').addEventListener('click',()=>{$('key-create-error').textContent='';openDialog('key-create');$('key-name').focus();});
$('cancel-key-create').addEventListener('click',()=>{if(!keyMinting)$('key-create').close();});
$('key-create').addEventListener('cancel',event=>{if(keyMinting)event.preventDefault();});
$('key-create').addEventListener('close',()=>{$('key-form').reset();$('key-create-error').textContent='';});
$('open-connection-guide').addEventListener('click',()=>openDialog('connection-guide-dialog'));
$('close-connection-guide').addEventListener('click',()=>$('connection-guide-dialog').close());
