// Synthetic controller checks. These do not replace a rendered browser review.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require('node:path').join(__dirname, '../static/app.js'), 'utf8');
async function app({authGate, providers = [], tools = [], connections = [], status = 200, connectionStatus = 200, session = {mode: 'account', username: 'alice', subject: 'account:alice'}, hash = '#/upstreams'} = {}) {
  const nodes = new Map(), requests = [];
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {classList: {add() {}, remove() {}}, value: '', innerHTML: '', textContent: '', hidden: false, disabled: false, dataset: {}, children: [], handlers: {}, addEventListener(name, handler) {const previous=this.handlers[name]; this.handlers[name] = previous ? async event => {await previous(event); await handler(event);} : handler;}, appendChild(child) {child.parentElement = this;}, querySelectorAll() {return [];}, focus() {}, replaceChildren() {}, setAttribute() {}, removeAttribute() {}});
    return nodes.get(id);
  };
  const payload = {'/api/auth/options': {mode: 'accounts', registration: true}, '/api/status': {ready: providers.some(p => p.healthy), session}, '/api/tools': tools, '/api/providers': providers, '/api/connections': connections};
  let responseStatus = status;
  const context = vm.createContext({location: {hash, pathname:'/', search:''}, history:{replaceState(_state,_title,path){context.location.pathname=path;context.location.hash='';},pushState(_state,_title,path){context.location.pathname=path;context.location.hash='';}}, window: {addEventListener() {}}, document: {addEventListener() {}, body: {classList: {toggle() {}}}, getElementById: node, querySelectorAll() {return [];}}, sessionStorage: {removeItem(key) {assert.equal(key, 'mcpwarden-token');}}, URL, setTimeout, clearTimeout,
    fetch: async (path, options) => {
      requests.push({path, options});
      if(path==='/api/auth/options' && authGate)await authGate;
      const code = responseStatus === 200 && path === '/api/connections' ? connectionStatus : responseStatus;
      return {status: code, ok: code === 200, json: async () => payload[path]};
    }
  });
  vm.runInContext(fs.readFileSync(require('node:path').join(__dirname, '../static/timezone.js'), 'utf8'), context);
  vm.runInContext(source, context);
  await new Promise(resolve => setImmediate(resolve));
  return {node, requests, run: text => vm.runInContext(text, context), fail: code => {responseStatus = code;}};
}
const provider = (overrides = {}) => ({name: 'docs', transport: 'http', source: 'personal', healthy: true, tool_count: 0, visibility_mode: 'all', enabled_tools: [], ...overrides});
test('empty inventory and successful zero-tool discovery are distinct', async () => {
  const empty = await app();
  assert.match(empty.node('upstreams').innerHTML, /No upstreams registered/);
  const zero = await app({providers: [provider()]});
  assert.match(zero.node('upstreams').innerHTML, /Discovered/);
  assert.match(zero.node('upstreams').innerHTML, /0 tools/);
  assert.match(zero.node('upstream-details').innerHTML, /0 discovered tools/);
});
test('never discovered, failure, stale cache, and pending refresh remain distinct', async () => {
  const ui = await app({providers: [provider({healthy: false})]});
  assert.match(ui.node('upstreams').innerHTML, /Not discovered/);
  ui.run("providers[0].error = 'private diagnostic'; render()");
  assert.match(ui.node('upstreams').innerHTML, /Discovery failed/);
  assert.doesNotMatch(ui.node('upstream-details').innerHTML, /private diagnostic/);
  ui.run("providers[0].last_discovered = '2026-09-21T00:00:00Z'; render()");
  assert.match(ui.node('upstreams').innerHTML, /Cached · stale/);
  ui.run("refreshState.set('docs', {pending: true}); render()");
  assert.match(ui.node('upstreams').innerHTML, /Refreshing/);
  ui.run("refreshState.set('docs', {failed: true}); providers[0].healthy = true; render()");
  assert.match(ui.node('upstreams').innerHTML, /Cached · stale/);
});
test('untrusted names, descriptions and saved header names are escaped', async () => {
  const name = '<img src=x onerror=alert(1)>';
  const ui = await app({providers: [provider({name})], connections: [{name, url: 'https://example.test/mcp', header_names: ['<script>'], auth_type: 'headers', custody: 'vault', call_timeout: '30s'}], tools: [{name, upstream: name, description: '<script>alert(1)</script>', allowed: true, healthy: true, visible: true}]});
  for (const id of ['upstreams', 'upstream-details', 'tools']) assert.doesNotMatch(ui.node(id).innerHTML, /<script>|<img/);
  assert.match(ui.node('upstream-details').innerHTML, /Value kept in your vault/);
  assert.doesNotMatch(ui.node('upstream-details').innerHTML, /type="password"/);
});
test('failed requests retain snapshot and disable mutations without reporting zero', async () => {
  const ui = await app({providers: [provider({tool_count: 3})]});
  ui.fail(503); await ui.run('refresh()');
  assert.match(ui.node('upstreams').innerHTML, /3 tools/);
  assert.match(ui.node('access-context').textContent, /last loaded snapshot/);
  assert.equal(ui.node('add-upstream').disabled, true);
});
test('401 and 403 clear prior identity inventory and report different access failures', async () => {
  for (const code of [401, 403]) {
    const ui = await app({providers: [provider()]});
    ui.fail(code); await ui.run('refresh()');
    assert.doesNotMatch(ui.node('upstreams').innerHTML, /data-name="docs"/);
    assert.equal(ui.node('add-upstream').disabled, true);
    assert.match(ui.node('overall').textContent, code === 401 ? /Authentication required/ : /Management access denied/);
  }
});
test('unconfigured managed storage still allows inspection of config upstreams', async () => {
  const ui = await app({providers: [provider({source: 'config', transport: 'stdio'})], connectionStatus: 501});
  assert.match(ui.node('upstreams').innerHTML, /Config managed/);
  assert.match(ui.node('upstream-details').innerHTML, /YAML/);
  assert.equal(ui.node('add-upstream').disabled, true);
  assert.doesNotMatch(ui.node('upstream-details').innerHTML, /id="remove-upstream"/);
});
test('filters preserve selection and distinguish no matches', async () => {
  const ui = await app({providers: [provider()]});
  ui.node('upstream-search').value = 'missing'; ui.run('renderUpstreams()');
  assert.match(ui.node('upstreams').innerHTML, /No upstreams match/);
  assert.equal(ui.run('selected'), 'docs');
});
test('visibility saves exact tool names through the gateway API', async () => {
  const ui = await app({providers: [provider()]});
  await ui.run("updateVisibility('docs', 'selected', ['docs__read'])");
  const request = ui.requests.find(r => r.options.method === 'PUT');
  assert.equal(request.path, '/api/providers/docs/visibility');
  assert.deepEqual(JSON.parse(request.options.body), {mode: 'selected', enabled: ['docs__read']});
});

test('overview, detail, and tool directory are separate routes', async () => {
  const ui = await app({providers: [provider()]});
  assert.equal(ui.node('connections').hidden, false);
  assert.equal(ui.node('directory').hidden, true);
  assert.equal(ui.node('connection-view').hidden, true);
  ui.run("location.hash = '#/upstreams/docs'; applyRoute(true)");
  assert.equal(ui.node('connections').hidden, true);
  assert.equal(ui.node('connection-view').hidden, false);
  assert.equal(ui.node('connection-title').textContent, 'docs');
  ui.run("location.hash = '#/tools/docs'; applyRoute(true)");
  assert.equal(ui.node('connection-view').hidden, true);
  assert.equal(ui.node('directory').hidden, false);
  assert.equal(ui.node('provider-filter').value, 'docs');
});
test('workspace shows server identity and clearly labels shared operator mode', async () => {
  const personal = await app();
  assert.equal(personal.node('identity-subject').textContent, 'alice');
  assert.equal(personal.node('identity-mode').textContent, 'PERSONAL WORKSPACE');
  const local = await app({session: {mode: 'local', subject: 'local'}});
  assert.equal(local.node('identity-mode').textContent, 'SHARED WORKSPACE');
  assert.match(local.node('identity-help').textContent, /share this workspace/);
});
test('deep links do not silently substitute another connection', async () => {
  const ui = await app({providers: [provider()], hash: '#/upstreams/missing'});
  assert.equal(ui.node('connection-title').textContent, 'missing');
  assert.match(ui.node('upstream-details').innerHTML, /not available in your workspace/);
});

test('fresh signed-out visits do not show an authentication error', async () => {
  const ui = await app({status: 401});
  assert.equal(ui.node('account-error').textContent, '');
});
test('missing provider deep links never display other providers tools', async () => {
  const ui = await app({providers: [provider()], tools: [{name: 'docs__read', upstream: 'docs', description: 'Read', allowed: true, healthy: true, visible: true}], hash: '#/tools/missing'});
  assert.doesNotMatch(ui.node('tools').innerHTML, /docs__read/);
  assert.match(ui.node('tools').innerHTML, /No tools match/);
});


test('default route opens the dashboard with real workspace totals', async () => {
  const ui = await app({hash: '', providers: [provider(), provider({name: 'offline', healthy: false})], tools: [{name:'docs__one', upstream:'docs', visible:true, allowed:true, healthy:true}]});
  assert.equal(ui.node('dashboard').hidden, false);
  assert.equal(ui.node('connections').hidden, true);
  assert.equal(ui.node('overview-upstreams').textContent, 2);
  assert.equal(ui.node('overview-tools').textContent, 1);
  assert.equal(ui.node('overview-attention').textContent, 1);
  assert.equal(ui.node('overview-upstreams-help').textContent, 'All enabled');
  assert.equal(ui.node('overview-tools-help').textContent, 'of 1 found');
  assert.equal(ui.node('overview-attention-help').textContent, 'offline');
});
test('connector tools paginate, search and filter using tool visibility and policy', async () => {
  const list = Array.from({length:71}, (_,i) => ({name:`docs__tool_${String(i).padStart(2,'0')}`,upstream:'docs',description:'Fixture',allowed:true,healthy:true,visible:i%2===0}));
  list[0].allowed = false; list[2].healthy = false;
  const ui = await app({providers:[provider({tool_count:71})],tools:list,hash:'#/upstreams/docs'});
  assert.equal(ui.node('breadcrumb-upstreams').hidden,false);
  assert.equal(ui.node('tool-panel').parentElement, ui.node('connector-tool-slot'));
  assert.equal((ui.node('tools').innerHTML.match(/class="tool-row"/g)||[]).length,10);
  assert.match(ui.node('tool-page-status').textContent,/1–10 of 71 tools · Page 1 of 8/);
  ui.run('toolView().page=8; renderTools()');
  assert.match(ui.node('tool-page-status').textContent,/71–71 of 71/);
  assert.equal(ui.node('tool-next').disabled,true);
  ui.run("toolView().filter='discoverable'; toolView().page=1; renderTools()");
  assert.match(ui.node('tool-page-status').textContent,/of 35 tools/);
  ui.run("toolView().filter='not-discoverable'; renderTools()");
  assert.match(ui.node('tool-page-status').textContent,/of 36 tools/);
  ui.run("toolView().filter='all'; toolView().query='tool_70'; renderTools()");
  assert.match(ui.node('tool-page-status').textContent,/1–1 of 1/);
  assert.match(ui.node('tools').innerHTML,/docs__tool_70/);
});
test('connector toggle preserves tools outside current search and page', async () => {
  const list = Array.from({length:25}, (_,i) => ({name:`docs__tool_${i}`,upstream:'docs',description:'',allowed:true,healthy:true,visible:true}));
  const ui = await app({providers:[provider({tool_count:25})],tools:list,hash:'#/upstreams/docs'});
  ui.run("toolView().query='tool_0'; renderTools()");
  await ui.node('tools').handlers.change({target:{closest:()=>({dataset:{tool:'docs__tool_0'},checked:false})}});
  const body=JSON.parse(ui.requests.find(r=>r.options.method==='PUT').options.body);
  assert.equal(body.enabled.length,24);
  assert.ok(body.enabled.includes('docs__tool_24'));
  assert.ok(!body.enabled.includes('docs__tool_0'));
});

test('short labels use UUID actions and retain MCP wire names', async () => {
 const list=['docs','other'].map((upstream,i)=>({id:`uuid-${i}`,display_name:'read',name:`${upstream}__read`,upstream,allowed:true,healthy:true,visible:true}));
 const ui=await app({providers:[provider(),provider({name:'other'})],tools:list,hash:'#/tools'});
 assert.match(ui.node('tools').innerHTML,/data-expand="uuid-0"[^>]*>.*?<span class="tool-label">read<\/span>/);
 assert.match(ui.node('tools').innerHTML,/data-expand="uuid-1"[^>]*>.*?<span class="tool-label">read<\/span>/);
 assert.match(ui.node('tools').innerHTML,/<code>other__read<\/code>/);
 await ui.node('tools').handlers.change({target:{closest:()=>({dataset:{tool:'uuid-1'},checked:false})}});
 const request=ui.requests.find(r=>r.options.method==='PUT');
 assert.equal(request.path,'/api/providers/other/visibility');
 assert.deepEqual(JSON.parse(request.options.body),{mode:'selected',enabled:[]});
});
test('provider switch is independent of tool preferences and disabled is not a failure',async()=>{
 const ui=await app({providers:[provider({enabled:false,healthy:false})],hash:'#/upstreams/docs'});
 assert.equal(ui.node('provider-enabled').textContent,'Enable');
 assert.equal(ui.node('overview-attention').textContent,0);
 assert.match(ui.node('upstreams').innerHTML,/Disabled/);
 await ui.node('provider-enabled').handlers.click({currentTarget:{dataset:{enable:'true'}}});
 const req=ui.requests.find(r=>r.options.method==='PUT');
 assert.equal(req.path,'/api/providers/docs/enabled');
 assert.deepEqual(JSON.parse(req.options.body),{enabled:true});
});

test('vault connections show header names and link to the vault, never values',async()=>{
 const ui=await app({providers:[provider({healthy:false,custody:'vault'})],connections:[{name:'docs',url:'https://example.test/mcp',header_names:['Authorization'],auth_type:'bearer',custody:'vault',call_timeout:'30s'}],hash:'#/upstreams/docs'});
 const html=ui.node('upstream-details').innerHTML;
 assert.match(html,/Bearer token/);
 assert.match(html,/Authorization<\/span><span>Value kept in your vault/);
 assert.match(html,/href="\/vault\/credentials"/);
 assert.doesNotMatch(html,/OAuth|Connect account|type="password"/);
});

async function submitConnection(ui, authType, headerName) {
 ui.node('upstream-url').value='https://example.test/mcp'; ui.node('upstream-timeout').value='30s'; ui.node('upstream-name').value='docs';
 ui.node('upstream-auth-type').value=authType; ui.node('auth-header').value=headerName||'';
 await ui.node('upstream-form').handlers.submit({preventDefault(){}});
 const req=ui.requests.find(r=>r.path==='/api/connections'&&r.options.method==='POST');
 return req&&JSON.parse(req.options.body);
}
test('adding a connection sends header names only',async()=>{
 const session={mode:'account',username:'alice',subject:'account:alice',vault:true};
 const keyed=await submitConnection(await app({session}),'api_key','X-API-Key');
 assert.deepEqual(keyed.header_names,['X-API-Key']);
 assert.equal(keyed.auth_type,'api_key');
 assert.ok(!('headers' in keyed)&&!('oauth' in keyed));
 const bearer=await submitConnection(await app({session}),'bearer');
 assert.deepEqual(bearer.header_names,['Authorization']);
 const open=await submitConnection(await app({session}),'none');
 assert.deepEqual(open.header_names,[]);
});
test('without the owner vault only no-auth connections can be added',async()=>{
 const ui=await app();
 ui.run('renderAuthFields()');
 assert.equal(ui.node('auth-vault-unavailable').hidden,false);
 assert.equal(ui.node('upstream-auth-type').value,'none');
 const withVault=await app({session:{mode:'account',username:'alice',subject:'account:alice',vault:true}});
 withVault.run('renderAuthFields()');
 assert.equal(withVault.node('auth-vault-unavailable').hidden,true);
});

test('upstream summary distinguishes provider state from saved tool choices', async () => {
 const ui = await app({providers:[provider(),provider({name:'paused',enabled:false})],tools:[{name:'docs__a',upstream:'docs',visible:true},{name:'docs__b',upstream:'docs',visible:false}]});
 assert.equal(ui.node('upstream-summary').textContent,'1 enabled · 1 disabled · 2 total upstreams');
 assert.match(ui.node('upstreams').innerHTML,/1 enabled · 1 disabled · 2 total tools/);
});
test('bulk actions change only tools in the current view, across pages',async()=>{
 const list=Array.from({length:30},(_,i)=>({name:`docs__${i<12?'issue':'repo'}_${String(i).padStart(2,'0')}`,upstream:'docs',allowed:i!==1,healthy:true,visible:i%3===0}));
 const ui=await app({providers:[provider({visibility_mode:'selected',enabled_tools:list.filter(t=>t.visible).map(t=>t.name)})],tools:list,hash:'#/upstreams/docs'});
 ui.run("toolView().query='issue'; toolView().page=2; renderTools()");
 assert.equal(ui.node('count-all').textContent,12);
 assert.equal(ui.node('count-shown').textContent,4);
 const show=ui.run('prepareBulk(true)');
 assert.equal(show.count,7);
 assert.equal(show.unchanged,4);
 ui.run('bulkRequest=prepareBulk(true)');
 assert.equal(await ui.run('applyBulk()'),true);
 const body=JSON.parse(ui.requests.find(r=>r.options.method==='PUT').options.body);
 assert.equal(body.mode,'selected');
 assert.deepEqual(body.enabled.sort(),[...list.filter((t,i)=>i<12&&i!==1).map(t=>t.name),...list.filter((t,i)=>i>=12&&t.visible).map(t=>t.name)].sort());
 ui.run("location.hash='#/tools'; applyRoute()");
 assert.equal(ui.node('bulk-tool-actions').hidden,true);
});
test('bulk actions on the unfiltered view set the whole upstream',async()=>{
 const ui=await app({providers:[provider({visibility_mode:'selected',enabled_tools:['docs__read']})],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true},{name:'docs__write',upstream:'docs',visible:false,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 ui.run('bulkRequest=prepareBulk(false)'); await ui.run('applyBulk()');
 ui.run('bulkRequest=prepareBulk(true)'); await ui.run('applyBulk()');
 const writes=ui.requests.filter(r=>r.options.method==='PUT');
 assert.deepEqual(writes.map(r=>JSON.parse(r.options.body)),[{mode:'selected',enabled:[]},{mode:'all',enabled:[]}]);
 assert.ok(writes.every(r=>r.path==='/api/providers/docs/visibility'));
});
test('visibility switch does not repaint stale state while save is pending',async()=>{
 const ui=await app({providers:[provider()],hash:'#/upstreams/docs'});
 ui.run("let finishSave; api = () => new Promise(resolve => { finishSave=resolve; }); let renders=0; render=()=>{renders++}; refresh=async()=>{}; let saving=updateVisibility('docs','selected',[])");
 assert.equal(ui.run('renders'),0);
 assert.equal(ui.run('mutating'),true);
 ui.run('finishSave()');
 await ui.run('saving');
 assert.equal(ui.run('renders'),0);
 assert.equal(ui.run('mutating'),false);
});

test('access limits exclude revoked and expired records and escape device labels',async()=>{
 const ui=await app();
 ui.run(`accessData={current_id:'browser',limits:{api_keys:10,login_sessions:10,mcp_connections:10},items:[...Array.from({length:10},(_,i)=>({id:'key'+i,name:'Key',kind:'api_key',role:'client'})),{id:'old',name:'Old',kind:'api_key',revoked_at:'2026-01-01'},{id:'expired',name:'Expired',kind:'api_key',expires_at:'2020-01-01'},{id:'browser',name:'Work laptop',device:'<script>bad</script>',kind:'browser',role:'admin'}]};renderAccess()`);
 assert.equal(ui.node('access-key-count').textContent,'10 of 10 active');
 assert.equal(ui.node('access-login-count').textContent,'1 of 10 active');
 assert.equal(ui.node('create-key').disabled,true);
 assert.match(ui.node('access-sessions').innerHTML,/This session/);
 assert.doesNotMatch(ui.node('access-sessions').innerHTML,/<script>/);
 ui.run("accessData.items[0].revoked_at='2026-01-01';renderAccess()");
 assert.equal(ui.node('access-key-count').textContent,'9 of 10 active');
 assert.equal(ui.node('create-key').disabled,false);
});

test('connector state does not change tool discovery badges or filter counts', async()=>{
 const ui=await app({providers:[provider()],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 const before=ui.node('tools').innerHTML;
 ui.run("providers[0].enabled=false;tools[0].healthy=false;render()");
 assert.equal(ui.node('tools').innerHTML,before);
 assert.equal(ui.node('count-shown').textContent,1);
 assert.equal(ui.node('tool-summary-count').textContent,'1 tool in this connection');
 assert.equal(ui.node('overview-tools').textContent,0);
});

test('bulk visibility updates only the tool view without reloading inventory',async()=>{
 const ui=await app({providers:[provider()],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 const previous=ui.requests.length;
 ui.run('bulkRequest=prepareBulk(false)'); await ui.run('applyBulk()');
 assert.equal(ui.requests.length,previous+1);
 assert.equal(ui.node('count-shown').textContent,0);
 assert.equal(ui.node('count-hidden').textContent,1);
 ui.run('bulkRequest=prepareBulk(true)'); await ui.run('applyBulk()');
 assert.equal(ui.node('count-shown').textContent,1);
});
test('failed switch saves keep the previous state and offer a retry',async()=>{
 const ui=await app({providers:[provider()],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 ui.fail(500);
 await ui.node('tools').handlers.change({target:{closest:()=>({dataset:{tool:'docs__read'},checked:false})}});
 assert.equal(ui.run('tools[0].visible'),true);
 assert.match(ui.node('tools').innerHTML,/role="alert"><span>Not saved\. docs__read is still shown\.<\/span><button class="retry" type="button" data-retry="docs__read">/);
 ui.fail(200);
 await ui.node('tools').handlers.click({target:{closest:selector=>selector==='.retry'?{dataset:{retry:'docs__read'}}:null}});
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(ui.run('tools[0].visible'),false);
 assert.doesNotMatch(ui.node('tools').innerHTML,/role="alert"/);
});
test('retry repeats the failed request and clears once a bulk save fulfils it',async()=>{
 const ui=await app({providers:[provider()],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true},{name:'docs__list',upstream:'docs',visible:true,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 ui.fail(500);
 await ui.node('tools').handlers.change({target:{closest:()=>({dataset:{tool:'docs__read'},checked:false})}});
 assert.match(ui.node('tools').innerHTML,/data-retry="docs__read"/);
 assert.deepEqual({...ui.run("toolErrors.get('docs__read')")},{visible:false});
 ui.fail(200);
 ui.run("toolView().query='read'; bulkRequest=prepareBulk(false)"); assert.equal(await ui.run('applyBulk()'),true);
 assert.equal(ui.run('tools.find(t=>t.name==="docs__read").visible'),false);
 assert.doesNotMatch(ui.node('tools').innerHTML,/role="alert"/);
 assert.equal(ui.run("toolErrors.size"),0);
 const puts=ui.requests.filter(r=>r.options.method==='PUT').length;
 await ui.node('tools').handlers.click({target:{closest:selector=>selector==='.retry'?{dataset:{retry:'docs__read'}}:null}});
 assert.equal(ui.requests.filter(r=>r.options.method==='PUT').length,puts);
});
test('a stale retry sends the originally requested visibility and a reload clears it',async()=>{
 const ui=await app({providers:[provider()],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 ui.fail(500);
 await ui.node('tools').handlers.change({target:{closest:()=>({dataset:{tool:'docs__read'},checked:false})}});
 ui.fail(200);
 await ui.node('tools').handlers.click({target:{closest:selector=>selector==='.retry'?{dataset:{retry:'docs__read'}}:null}});
 await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(JSON.parse(ui.requests.filter(r=>r.options.method==='PUT').at(-1).options.body),{mode:'selected',enabled:[]});
 const reloaded=await app({providers:[provider()],tools:[{name:'docs__read',upstream:'docs',visible:true,allowed:true,healthy:true}],hash:'#/upstreams/docs'});
 reloaded.fail(500);
 await reloaded.node('tools').handlers.change({target:{closest:()=>({dataset:{tool:'docs__read'},checked:false})}});
 reloaded.run("tools[0].visible=false; renderTools()");
 assert.doesNotMatch(reloaded.node('tools').innerHTML,/role="alert"/);
 assert.equal(reloaded.run('toolErrors.size'),0);
});
test('unfiltered bulk actions keep policy-blocked tools saved choices',async()=>{
 const mixed=blockedVisible=>[{name:'docs__open',upstream:'docs',visible:false,allowed:true,healthy:true},{name:'docs__shown',upstream:'docs',visible:true,allowed:true,healthy:true},{name:'docs__blocked',upstream:'docs',visible:blockedVisible,allowed:false,healthy:true}];
 const saved=list=>provider({visibility_mode:'selected',enabled_tools:list.filter(t=>t.visible).map(t=>t.name)});
 const hiddenBlocked=mixed(false), ui=await app({providers:[saved(hiddenBlocked)],tools:hiddenBlocked,hash:'#/upstreams/docs'});
 const show=ui.run('prepareBulk(true)');
 assert.equal(show.blocked,1);
 assert.deepEqual({mode:show.body.mode,enabled:JSON.parse(JSON.stringify(show.body.enabled)).sort()},{mode:'selected',enabled:['docs__open','docs__shown']});
 ui.run('bulkRequest=prepareBulk(true)'); await ui.run('applyBulk()');
 assert.equal(ui.run('tools.find(t=>t.name==="docs__blocked").visible'),false);
 const hide=ui.run('prepareBulk(false)');
 assert.deepEqual(JSON.parse(JSON.stringify(hide.body)),{mode:'selected',enabled:[]});
 const shownBlocked=mixed(true), other=await app({providers:[saved(shownBlocked)],tools:shownBlocked,hash:'#/upstreams/docs'});
 assert.deepEqual(JSON.parse(JSON.stringify(other.run('prepareBulk(true)').body)),{mode:'all',enabled:[]});
 other.run('bulkRequest=prepareBulk(false)'); await other.run('applyBulk()');
 const body=JSON.parse(other.requests.filter(r=>r.options.method==='PUT').at(-1).options.body);
 assert.deepEqual(body,{mode:'selected',enabled:['docs__blocked']});
 assert.equal(other.run('tools.find(t=>t.name==="docs__blocked").visible'),true);
 assert.equal(other.run('tools.find(t=>t.name==="docs__shown").visible'),false);
});
test('policy-denied tools read as blocked and cannot be switched',async()=>{
 const ui=await app({providers:[provider()],tools:[{name:'docs__drop',upstream:'docs',visible:true,allowed:false,healthy:true}],hash:'#/upstreams/docs'});
 assert.match(ui.node('tools').innerHTML,/<span class="state-word blocked">Blocked<\/span>/);
 assert.match(ui.node('tools').innerHTML,/data-tool="docs__drop" checked disabled/);
 assert.equal(ui.node('count-hidden').textContent,1);
 assert.equal(ui.run('prepareBulk(true).count'),0);
});

test('unchanged inventory reload does not redraw the workspace',async()=>{
 const ui=await app({providers:[provider()]});
 ui.run('let reloadRenders=0;render=()=>{reloadRenders++}');
 await ui.run('refresh()');
 assert.equal(ui.run('reloadRenders'),0);
});

test('Refresh all discovers enabled connectors and skips disabled ones',async()=>{
 const ui=await app({providers:[provider(),provider({name:'paused',enabled:false})]});
 await ui.node('refresh').handlers.click();
 const paths=ui.requests.filter(r=>r.options.method==='POST').map(r=>r.path);
 assert.deepEqual(paths,['/api/discovery/docs/refresh']);
 assert.match(ui.node('notice').textContent,/Refreshed 1 enabled connector/);
});

test('vault-custody connectors count as available and never refresh',async()=>{
 const vault=provider({name:'vaulted',healthy:false,custody:'vault',tool_count:1});
 const ui=await app({providers:[provider(),vault],tools:[{name:'vaulted__search',upstream:'vaulted',allowed:true,healthy:false,visible:true,custody:'vault'}]});
 assert.equal(ui.node('overview-attention').textContent,0);
 assert.equal(ui.node('gateway-status').textContent,'Connectors available');
 assert.equal(ui.run("discovery(providers.find(p=>p.name==='vaulted'))[0]"),'Vault custody');
 assert.match(ui.run("providerActions(providers.find(p=>p.name==='vaulted'))"),/provider-refresh[^>]*disabled/);
 assert.equal(ui.run("isDiscoverable(tools[0])"),true);
 await ui.run("refreshProvider('vaulted')");
 await ui.node('refresh').handlers.click();
 const paths=ui.requests.filter(r=>r.options.method==='POST').map(r=>r.path);
 assert.deepEqual(paths,['/api/discovery/docs/refresh']);
 assert.match(ui.node('notice').textContent,/Refreshed 1 enabled connector\. Skipped 1 in vault custody\./);
 assert.equal(ui.run("refreshState.has('vaulted')"),false);
});

test('authentication does not report green connector availability',async()=>{
 const ui=await app({providers:[provider({healthy:false})]});
 assert.equal(ui.node('overall').textContent,'Signed in');
 assert.doesNotMatch(ui.node('overall').className,/success/);
 assert.equal(ui.node('gateway-status').textContent,'No connectors available');
 assert.match(ui.node('gateway-status').className,/warning/);
 assert.doesNotMatch(ui.node('access-context').textContent,/Gateway not ready/);
});

test('startup keeps login hidden until the existing session check completes', async () => {
 let release; const authGate=new Promise(resolve=>{release=resolve;});
 const ui=await app({authGate});
 assert.equal(ui.node('login-screen').hidden,true);
 assert.equal(ui.node('session-loading').hidden,false);
 release(); await new Promise(resolve=>setImmediate(resolve));
 assert.equal(ui.node('login-screen').hidden,true);
 assert.equal(ui.node('session-loading').hidden,true);
 const signedOut=await app({status:401});
 assert.equal(signedOut.node('login-screen').hidden,false);
 assert.equal(signedOut.node('session-loading').hidden,true);
});

test('date range validates open bounds, incomplete and inverted endpoints without querying', async () => {
 const ui=await app();
 const before=ui.requests.length;
 ui.node('calls-from').value='2026-09-21';
 assert.equal(ui.run('validateRange().valid'),false);
 ui.node('calls-from-time').value='09:30';
 assert.equal(ui.run('validateRange().valid'),true);
 ui.node('calls-to').value='2026-09-21';ui.node('calls-to-time').value='09:30';
 assert.equal(ui.run('validateRange().valid'),false);
 ui.node('calls-to-time').value='10:30';
 assert.equal(ui.run('validateRange().valid'),true);
 assert.equal(ui.requests.length,before);
});
test('range edits remain drafts and Revert restores the applied endpoints', async () => {
 const ui=await app();
 ui.run("writeRange({from:'2026-09-21',fromTime:'09:00',to:'2026-09-21',toTime:'10:00'});appliedRange=validateRange().raw");
 ui.node('calls-to-time').value='11:00';ui.run('renderRange()');
 assert.match(ui.node('history-range-state').textContent,/Not applied/);
 assert.equal(ui.run('appliedRange.toTime'),'10:00');
 await ui.node('history-range-revert').handlers.click();
 assert.equal(ui.node('calls-to-time').value,'10:00');
 assert.equal(ui.node('history-range-revert').disabled,true);
});

test('legacy bookmarks migrate to clean paths and clean connector routes resolve', async () => {
 const ui=await app({hash:'#/upstreams/docs/settings',providers:[provider()]});
 assert.equal(ui.run('location.hash'),'');
 assert.equal(ui.run('location.pathname'),'/upstreams/docs/settings');
 assert.equal(ui.run('readRoute().section'),'settings');
 ui.run("location.pathname='/tools/docs%2Cother'");
 assert.deepEqual(Array.from(ui.run('readRoute().providerNames')),['docs','other']);
});

test('public key handles disambiguate collisions without using token suffixes',async()=>{
 const ui=await app();
 ui.run(`accessData={items:[{id:'a',kind:'api_key',name:'Laptop',role:'client',public_id:'aaaaaaaaaaaaaaaaaaaaaaaa1111abcd',token:'SECRET_MUST_NOT_RENDER'},{id:'b',kind:'api_key',name:'Other',role:'client',public_id:'bbbbbbbbbbbbbbbbbbbbbbbb2222abcd'}],limits:{api_keys:10,login_sessions:10,mcp_connections:10}};renderAccess()`);
 const html=ui.node('access-keys').innerHTML;
 assert.match(html,/…1111abcd/);
 assert.match(html,/…2222abcd/);
 assert.doesNotMatch(html,/SECRET_MUST_NOT_RENDER/);
 assert.match(html,/Public key ID/);
});

test('unknown completion never presents a response or success and escapes caller labels',async()=>{
 const ui=await app();
 const html=ui.run(`historyCallRow({tool:'remote__read',upstream:'remote',status:'unknown',ts:'2026-09-22T00:00:00Z',actor_access_id:'key-a',actor_public_id:'aaaaaaaaaaaaaaaaaaaaaaaa1111abcd',actor_label_snapshot:'<script>spoof</script>'})`);
 assert.match(html,/Outcome unknown/);
 assert.match(html,/Completion not recorded/);
 assert.match(html,/do not assume retry is safe/);
 assert.doesNotMatch(html,/0 response|NaN|<script>|0 ms/);
 assert.match(html,/&lt;script&gt;/);
});
test('credentialed connections check the endpoint the gateway will compare',async()=>{
 const session={mode:'account',username:'alice',subject:'account:alice',vault:true};
 const accepted=['https://mcp.example.com/mcp','https://mcp.example.com/','https://mcp.example.com:8443/v1/mcp','https://8.8.8.8/mcp','http://localhost:8080/mcp','http://127.0.0.1/mcp','http://[::1]:9000/mcp','https://example.com/a%20b','https://mcp.example.com:/mcp','https://mcp.example.com/a[b]'];
 const refused=['https://mcp.example.com','https://MCP.example.com/mcp','https://mcp.example.com./mcp','https://mcp.example.com/a/../b','https://mcp.example.com/a%2Fb','https://mcp.example.com/a%5cb','https://mcp.example.com:0443/mcp','https://mcp.example.com:70000/mcp','HTTPS://mcp.example.com/mcp','http://example.com/mcp','http://127.1/mcp','http://010.0.0.1/mcp','https://-bad.example/mcp','https://mcp.example.com/a b','https://user@mcp.example.com/mcp','https://mcp.example.com/mcp?x=1','https://mcp.example.com/%2e%2e/x','https://mcp.example.com/a%00b','https://127.0.0.1/mcp','https://192.168.1.1/mcp','https://224.0.0.1/mcp'];
 const ui=await app({session});
 for(const url of accepted)assert.equal(ui.run(`vaultEndpoint(${JSON.stringify(url)})`),true,url);
 for(const url of refused)assert.equal(ui.run(`vaultEndpoint(${JSON.stringify(url)})`),false,url);
 const pathless=await app({session});
 pathless.node('upstream-url').value='https://mcp.example.com'; pathless.node('upstream-timeout').value='30s'; pathless.node('upstream-name').value='docs';
 pathless.node('upstream-auth-type').value='bearer';
 Object.assign(pathless.node('upstream-url'),{setCustomValidity(m){this.custom=m;},reportValidity(){}});
 await pathless.node('upstream-form').handlers.submit({preventDefault(){}});
 assert.ok(!pathless.requests.some(r=>r.path==='/api/connections'&&r.options.method==='POST'));
 assert.match(pathless.node('upstream-url').custom,/public HTTPS endpoint/);
 const open=await app({session});
 open.node('upstream-url').value='https://mcp.example.com'; open.node('upstream-timeout').value='30s'; open.node('upstream-name').value='docs';
 open.node('upstream-auth-type').value='none';
 await open.node('upstream-form').handlers.submit({preventDefault(){}});
 assert.ok(open.requests.some(r=>r.path==='/api/connections'&&r.options.method==='POST'));
});
