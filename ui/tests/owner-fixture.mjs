// Isolated end-to-end fixture for the owner console: a scratch PostgreSQL
// database and runtime role, a real gateway binary with owner_security and
// direct loopback development transport, a synthetic header-authenticated MCP
// upstream, and a static UI server that proxies /api/ like the bundled nginx.
// Everything binds to 127.0.0.1 and uses synthetic credentials only.
import {spawn, execFileSync} from 'node:child_process';
import {createServer, request as httpRequest} from 'node:http';
import {mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve, sep, extname} from 'node:path';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const staticRoot = fileURLToPath(new URL('../static', import.meta.url));
export const UPSTREAM_KEY = 'upstream-synthetic-key';
// The main page runs under a strict policy so violations fail the flows. The
// /security/ worker scripts carry the same policy as ui/nginx.conf.
export const PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
const WORKER_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'none'";

function listen(server) { return new Promise(done => server.listen(0, '127.0.0.1', () => done(server.address().port))); }
async function freePort() { const s = createServer(); const port = await listen(s); await new Promise(done => s.close(done)); return port; }
const sleep = ms => new Promise(done => setTimeout(done, ms));

function adminDSN() {
  const raw = process.env.MCPWARDEN_TEST_DATABASE_URL;
  if (!raw) throw new Error('Set MCPWARDEN_TEST_DATABASE_URL to the isolated PostgreSQL test fixture.');
  const url = new URL(raw);
  if (url.pathname !== '/mcpwarden_security_test' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) throw new Error('Owner flows require the local mcpwarden_security_test fixture.');
  return url;
}
function psql(url, sql) { execFileSync('psql', [url.toString(), '-v', 'ON_ERROR_STOP=1', '-q', '-c', sql], {stdio: ['ignore', 'ignore', 'inherit']}); }

export function buildBinaries(dir) {
  if (process.env.MCPWARDEN_BIN_DIR) return process.env.MCPWARDEN_BIN_DIR;
  // The flowtest tag adds a route that seeds cached discovery for vault
  // connectors until setup discovery (roadmap step 5) exists.
  for (const name of ['mcpwarden', 'mcpwarden-security-db']) execFileSync('go', ['build', '-tags', 'flowtest', '-o', join(dir, name), `./cmd/${name}`], {cwd: repo, stdio: 'inherit'});
  return dir;
}

// Minimal Streamable HTTP MCP server answering with JSON. The gateway never
// dials it: its connector is in vault custody and the flows open no calls. It
// refuses requests without a header the gateway does not have.
export async function startUpstream() {
  const tools = [
    {name: 'search', description: 'Synthetic search <img src=x onerror="document.title=\'pwned\'"> across one repository', inputSchema: {type: 'object', properties: {repo: {type: 'string'}}}},
    {name: 'write', description: 'Synthetic write', inputSchema: {type: 'object'}},
  ];
  const server = createServer((req, res) => {
    if (req.headers['x-api-key'] !== UPSTREAM_KEY) { res.writeHead(401); res.end(); return; }
    if (req.method === 'DELETE') { res.writeHead(200); res.end(); return; }
    if (req.method !== 'POST') { res.writeHead(405, {Allow: 'POST'}); res.end(); return; }
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let message;
      try { message = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      if (message.id === undefined) { res.writeHead(202); res.end(); return; }
      const result = message.method === 'initialize' ? {protocolVersion: message.params?.protocolVersion || '2025-06-18', capabilities: {tools: {}}, serverInfo: {name: 'synthetic', version: '1.0.0'}}
        : message.method === 'tools/list' ? {tools} : message.method === 'tools/call' ? {content: [{type: 'text', text: 'synthetic result'}]} : {};
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({jsonrpc: '2.0', id: message.id, result}));
    });
  });
  const port = await listen(server);
  return {url: `http://127.0.0.1:${port}/mcp`, tools, close: () => new Promise(done => server.close(done)),
    // Changes a tool definition as an upstream release would; discovery sees it on refresh.
    change: (name, patch) => Object.assign(tools.find(t => t.name === name), patch)};
}

// Static UI plus an /api/ proxy that forwards only what nginx forwards. It adds
// no forwarding headers, so the gateway sees a direct loopback request.
export const proxyErrors = [];
export async function startUI(gatewayPort) {
  const types = {'.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.mjs': 'application/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.wasm': 'application/wasm', '.json': 'application/json'};
  const target = {port: gatewayPort.value};
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname.startsWith('/api/')) {
      const headers = {...req.headers};
      delete headers.connection;
      const upstream = httpRequest({host: '127.0.0.1', port: target.port, method: req.method, path: req.url, headers, agent: false}, response => {
        res.writeHead(response.statusCode, response.headers); response.pipe(res);
      });
      upstream.on('error', error => { proxyErrors.push(`${req.method} ${url.pathname}: ${error.code || error.message}`); if (!res.headersSent) res.writeHead(502); res.end(); });
      req.pipe(upstream);
      return;
    }
    let path = resolve(staticRoot, '.' + decodeURIComponent(url.pathname));
    const security = url.pathname.startsWith('/security/');
    if (!path.startsWith(staticRoot + sep) || !existsSync(path) || !extname(path)) {
      if (security) { res.writeHead(404); res.end(); return; }
      path = join(staticRoot, 'index.html');
    }
    const headers = {'Content-Type': types[extname(path)] || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'};
    headers['Content-Security-Policy'] = security ? WORKER_CSP : PAGE_CSP;
    res.writeHead(200, headers); res.end(readFileSync(path));
  });
  const port = await listen(server);
  return {origin: `http://127.0.0.1:${port}`, target, close: () => new Promise(done => { server.closeAllConnections?.(); server.close(done); })};
}

export async function startFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'mcpwarden-owner-flows-'));
  const bin = buildBinaries(dir);
  const admin = adminDSN(), suffix = randomBytes(8).toString('hex');
  const database = `mcpwarden_ui_${suffix}`, role = `mcpw_uirt_${suffix}`, password = 'test-only-password';
  psql(admin, `CREATE ROLE ${role} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
  psql(admin, `CREATE DATABASE ${database}`);
  const scratch = new URL(admin); scratch.pathname = '/' + database;
  execFileSync(join(bin, 'mcpwarden-security-db'), ['-runtime-role', role], {env: {...process.env, MCPWARDEN_MIGRATION_DATABASE_URL: scratch.toString()}, stdio: ['ignore', 'ignore', 'inherit']});
  const runtime = new URL(scratch); runtime.username = role; runtime.password = password; runtime.search = '?sslmode=disable';

  const upstream = await startUpstream();
  const gatewayPort = {value: await freePort()};
  const ui = await startUI(gatewayPort);
  const config = join(dir, 'config.yaml');
  writeFileSync(config, [
    `listen: 127.0.0.1:${gatewayPort.value}`,
    `allowed_origins: ["${ui.origin}"]`,
    'upstreams: []',
    'policy:', '  default: allow',
    'audit:', `  path: ${join(dir, 'audit.jsonl')}`,
    'managed_upstreams:', `  path: ${join(dir, 'catalog.enc')}`, '  key_env: MCPWARDEN_TEST_CATALOG_KEY',
    'accounts:', '  allow_registration: true',
    'owner_security:', '  database_url_env: MCPWARDEN_SECURITY_DATABASE_URL', '  allow_insecure_loopback: true', ''].join('\n'));
  const env = {PATH: process.env.PATH, HOME: dir, MCPWARDEN_SECURITY_DATABASE_URL: runtime.toString(), MCPWARDEN_TEST_CATALOG_KEY: randomBytes(32).toString('base64')};
  let child = null, logs = '';
  const gateway = `http://127.0.0.1:${gatewayPort.value}`;
  async function start() {
    child = spawn(join(bin, 'mcpwarden'), ['-config', config], {env, stdio: ['ignore', 'pipe', 'pipe']});
    child.stdout.on('data', d => { logs += d; }); child.stderr.on('data', d => { logs += d; });
    for (let i = 0; i < 200; i++) {
      if (child.exitCode !== null) throw new Error('gateway exited during startup:\n' + logs);
      try { if ((await fetch(gateway + '/api/auth/options')).ok) return; } catch { /* not listening yet */ }
      await sleep(50);
    }
    throw new Error('gateway did not start:\n' + logs);
  }
  async function stop() {
    const gatewayProcess = child;
    if (!gatewayProcess || gatewayProcess.exitCode !== null) return;
    const exited = new Promise(done => gatewayProcess.once('exit', done));
    gatewayProcess.kill('SIGTERM');
    const timer = setTimeout(() => gatewayProcess.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(timer);
  }
  await start();
  return {
    ui: ui.origin, gateway, upstream: upstream.url, upstreamTools: () => structuredClone(upstream.tools), changeTool: upstream.change, logs: () => logs,
    restart: async () => { await stop(); await start(); },
    // Diagnostics for a stalled run: the Go runtime prints every goroutine on SIGQUIT.
    dumpGoroutines: async () => {
      const gatewayProcess = child;
      if (!gatewayProcess || gatewayProcess.exitCode !== null) return logs;
      const exited = new Promise(done => gatewayProcess.once('exit', done));
      gatewayProcess.kill('SIGQUIT');
      await Promise.race([exited, sleep(5000)]);
      return logs;
    },
    // A named API key acting directly against the gateway, as an agent would.
    key: token => async (method, path, body) => {
      const response = await fetch(gateway + path, {method, headers: {Authorization: `Bearer ${token}`, ...(body ? {'Content-Type': 'application/json'} : {})}, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(30000)});
      const text = await response.text();
      return {status: response.status, data: text ? JSON.parse(text) : null};
    },
    // An owner browser session replayed outside the page (another tab).
    owner: cookie => async (method, path, body) => {
      const headers = {Cookie: cookie, Origin: ui.origin, 'X-MCPWarden-Request': 'browser'};
      if (method !== 'GET') {
        const csrf = await (await fetch(gateway + '/api/security/csrf', {headers, signal: AbortSignal.timeout(30000)})).json();
        headers['X-CSRF-Token'] = csrf.token; headers['Content-Type'] = 'application/json';
      }
      const response = await fetch(gateway + path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000)});
      const text = await response.text();
      return {status: response.status, data: text ? JSON.parse(text) : null};
    },
    close: async () => {
      await stop(); await ui.close(); await upstream.close();
      try { psql(admin, `DROP DATABASE IF EXISTS ${database} WITH (FORCE)`); psql(admin, `DROP ROLE IF EXISTS ${role}`); } catch { console.error('scratch database cleanup failed'); }
      rmSync(dir, {recursive: true, force: true});
    },
  };
}
