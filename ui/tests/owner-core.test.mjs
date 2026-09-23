import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto, randomBytes} from 'node:crypto';
import {OwnerClient, OwnerError, b64url, callsLabel, destinationDigest, destinationFor, durationLabel, formatRecoveryKey, headerBundle,
  headerValueProblem, jcs, parseRecoveryKey, passphraseProblem, publicHandle, remainingLabel, requestPhase, windowPhase} from '../static/security/owner-core.mjs';

globalThis.crypto ??= webcrypto;

// Shared with cmd/mcpwarden/security_ui_test.go, which computes the same digests in Go.
test('destination digests match the gateway', async () => {
  assert.equal(await destinationDigest({schema: 'mcpwarden.destination.v1', endpoint: 'https://mcp.example.com/v1/mcp', header_names: ['x-api-key', 'authorization'], network: 'public', private_prefixes: [], allow_loopback_http: false}),
    'vVapFskaiqc3HytDT_xPi4e9f9FFo2SDHLGMcktEZt0');
  assert.equal(await destinationDigest({schema: 'mcpwarden.destination.v1', endpoint: 'http://localhost:4100/mcp', header_names: ['x-api-key'], network: 'private', private_prefixes: ['::1/128', '127.0.0.0/8'], allow_loopback_http: true}),
    'pRRjQdr_3IR_Ey6EaicfR6WZ-eEgHX9rBWiAjyNANPk');
  assert.equal(jcs({b: [1, 'é', null], a: true, 'é': {}}), '{"a":true,"b":[1,"é",null],"é":{}}');
  assert.throws(() => jcs({n: 1.5}));
  assert.throws(() => jcs({n: 2 ** 60}));
});

test('destinations cover only supported header connectors', () => {
  const https = destinationFor({auth_type: 'api_key', url: 'https://mcp.example.com/mcp', header_names: ['X-API-Key']});
  assert.deepEqual(https.destination, {schema: 'mcpwarden.destination.v1', endpoint: 'https://mcp.example.com/mcp', header_names: ['x-api-key'], network: 'public', private_prefixes: [], allow_loopback_http: false});
  assert.deepEqual(destinationFor({auth_type: 'bearer', url: 'http://localhost:4100/mcp', header_names: ['Authorization']}).destination.private_prefixes, ['127.0.0.0/8', '::1/128']);
  assert.deepEqual(destinationFor({auth_type: 'headers', url: 'http://127.0.0.1:9/mcp', header_names: ['A', 'B']}).destination.private_prefixes, ['127.0.0.0/8']);
  assert.deepEqual(destinationFor({auth_type: 'headers', url: 'http://[::1]:9/mcp', header_names: ['A']}).destination.private_prefixes, ['::1/128']);
  for (const connection of [{auth_type: 'oauth', url: 'https://x.example/mcp', header_names: []}, {auth_type: 'none', url: 'https://x.example/mcp', header_names: []},
    {auth_type: 'headers', url: 'http://10.0.0.5/mcp', header_names: ['A']}, {auth_type: 'headers', url: 'https://x.example/mcp', header_names: ['A', 'a']}]) {
    assert.equal(destinationFor(connection).destination, undefined, JSON.stringify(connection));
    assert(destinationFor(connection).reason);
  }
});

test('header bundles keep values exact and prefix bearer tokens', () => {
  assert.equal(headerBundle({auth_type: 'bearer', header_names: ['Authorization']}, {Authorization: 'tok en'}), '{"kind":"header_bundle","headers":[{"name":"Authorization","value":"Bearer tok en"}]}');
  assert.equal(headerBundle({auth_type: 'headers', header_names: ['X-A']}, {'X-A': 'v'}), '{"kind":"header_bundle","headers":[{"name":"X-A","value":"v"}]}');
  assert.equal(headerValueProblem(''), 'Enter a value.');
  assert.match(headerValueProblem(' x'), /spaces/);
  assert.match(headerValueProblem('a\nb'), /line breaks/);
  assert.equal(headerValueProblem('synthetic'), '');
});

test('recovery keys round-trip with a checksum', async () => {
  const raw = b64url(randomBytes(32));
  const shown = await formatRecoveryKey(raw);
  assert.match(shown, /^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(await parseRecoveryKey(shown), raw);
  assert.equal(await parseRecoveryKey(shown.toLowerCase().replaceAll('-', ' ')), raw);
  // Handwriting substitutions map to the same symbols.
  assert.equal(await parseRecoveryKey(shown.replaceAll('1', 'l').replaceAll('0', 'o')), raw);
  const changed = (shown[0] === '2' ? '3' : '2') + shown.slice(1);
  await assert.rejects(parseRecoveryKey(changed), /incorrect/);
  await assert.rejects(parseRecoveryKey(shown.slice(0, -1)), /56 characters/);
  await assert.rejects(parseRecoveryKey('U'.repeat(56)), /56 characters/);
});

test('passphrases, handles and labels', () => {
  assert.match(passphraseProblem('short', 'short'), /15/);
  assert.match(passphraseProblem('a'.repeat(15), 'b'.repeat(15)), /match/);
  assert.match(passphraseProblem('é'.repeat(600), 'é'.repeat(600)), /1024 bytes/);
  assert.equal(passphraseProblem('🔐'.repeat(15), '🔐'.repeat(15)), '');
  const a = 'a'.repeat(28) + '1234', b = 'b'.repeat(28) + '1234';
  assert.equal(publicHandle(a), '…1234');
  assert.equal(publicHandle(a, [a, b]), '…' + a.slice(-8));
  assert.equal(publicHandle('not-a-public-id'), '');
  assert.deepEqual([20, 60, 300, 900, 3600, 7200, 90].map(durationLabel), ['20 seconds', '1 minute', '5 minutes', '15 minutes', '1 hour', '2 hours', '90 seconds']);
  assert.deepEqual([0, -5, 999, 61000, 3601000].map(remainingLabel), ['0:00', '0:00', '0:01', '1:01', '1:00:01']);
  assert.equal(callsLabel({admitted_calls: 1, max_calls: null}), '1 call · no call limit');
  assert.equal(callsLabel({admitted_calls: 2, max_calls: 5, in_flight: 1}), '2 of 5 calls used · 1 in progress');
});

test('request and window phases distinguish every state', () => {
  const now = Date.parse('2026-09-23T12:00:00Z'), later = '2026-09-23T12:05:00Z', earlier = '2026-09-23T11:55:00Z';
  assert.equal(requestPhase({state: 'pending', expires_at: later}, now).key, 'pending');
  assert.equal(requestPhase({state: 'approved', expires_at: later, activation_deadline: later}, now).key, 'approved');
  assert.equal(requestPhase({state: 'approved', expires_at: later, activation_deadline: earlier}, now).key, 'expired');
  assert.equal(requestPhase({state: 'pending', expires_at: earlier}, now).key, 'expired');
  for (const state of ['activated', 'denied', 'stale', 'expired']) assert.equal(requestPhase({state, expires_at: earlier}, now).key, state);
  const live = {state: 'active', expires_at: later, runtime_available: true};
  assert.equal(windowPhase(live, now).key, 'active');
  assert.equal(windowPhase(live, now, false).key, 'provider');
  assert.equal(windowPhase({...live, runtime_available: false}, now).key, 'suspended');
  assert.equal(windowPhase({...live, expires_at: earlier}, now).key, 'expired');
  assert.equal(windowPhase({...live, state: 'revoked'}, now).key, 'revoked');
  assert.equal(windowPhase({...live, state: 'suspended'}, now).key, 'suspended');
  assert.equal(windowPhase({...live, state: 'expired'}, now).key, 'expired');
});

function fakeFetch(responses) {
  const calls = [];
  const fetcher = async (path, init) => {
    calls.push({path, ...init});
    const next = responses.shift();
    if (next instanceof Error) throw next;
    const {status = 200, body, type = 'application/json', gate} = typeof next === 'function' ? await next(path, init) : next;
    if (gate) await gate;
    return new Response(status === 204 ? null : typeof body === 'string' ? body : JSON.stringify(body), {status, headers: {'Content-Type': type, Date: 'Wed, 23 Sep 2026 12:00:00 GMT'}});
  };
  return {fetcher, calls};
}

test('owner client sends cookie-only browser requests with CSRF', async () => {
  const {fetcher, calls} = fakeFetch([{body: {token: 't1'}}, {body: {ok: true}}]);
  const client = new OwnerClient(fetcher);
  const result = await client.request('POST', '/api/approvals/x/activate', {body: '{}', idempotencyKey: 'k'});
  assert.deepEqual(result.data, {ok: true});
  assert.equal(result.serverDate, Date.parse('2026-09-23T12:00:00Z'));
  assert.equal(calls[0].path, '/api/security/csrf');
  const sent = calls[1];
  assert.equal(sent.headers['X-CSRF-Token'], 't1');
  assert.equal(sent.headers['Idempotency-Key'], 'k');
  assert.equal(sent.headers['X-MCPWarden-Request'], 'browser');
  assert.equal(sent.credentials, 'same-origin');
  assert.equal(sent.redirect, 'error');
  for (const call of calls) assert(!Object.keys(call.headers).some(name => name.toLowerCase() === 'authorization'));
});

test('owner client retries a CSRF refusal once only', async () => {
  const refusal = {status: 403, body: {error: 'csrf_required'}};
  const {fetcher, calls} = fakeFetch([{body: {token: 'old'}}, refusal, {body: {token: 'new'}}, refusal]);
  const client = new OwnerClient(fetcher);
  await assert.rejects(client.request('DELETE', '/api/leases/x'), error => error.code === 'csrf_required' && error.status === 403);
  assert.equal(calls.filter(c => c.path === '/api/leases/x').length, 2);
  assert.equal(calls[3].headers['X-CSRF-Token'], 'new');
});

test('owner client maps failures and marks uncertain outcomes', async () => {
  const cases = [[{status: 404, body: '404 page not found', type: 'text/plain'}, 'disabled', false], [{status: 401, body: {error: 'sign_in_required'}}, 'sign_in_required', false],
    [{status: 403, body: {error: 'secure_transport_required'}}, 'secure_transport_required', false], [{status: 409, body: {error: 'conflict'}}, 'conflict', false],
    [{status: 502, body: '', type: 'text/plain'}, 'server', true], [new TypeError('offline'), 'network', true], [{status: 400, body: {error: 'something_new'}}, 'invalid', false]];
  for (const [response, code, uncertain] of cases) {
    const client = new OwnerClient(fakeFetch([response]).fetcher);
    await assert.rejects(client.request('GET', '/api/vault/state'), error => error instanceof OwnerError && error.code === code && error.uncertain === uncertain && Boolean(error.message));
  }
});

test('owner client discards responses that arrive after reset', async () => {
  let release;
  const gate = new Promise(done => { release = done; });
  const client = new OwnerClient(fakeFetch([{body: {configured: true}, gate}]).fetcher);
  const pending = client.request('GET', '/api/vault/state');
  client.reset();
  release();
  await assert.rejects(pending, {code: 'discarded'});
  const failing = new OwnerClient(fakeFetch([async () => { failing.reset(); throw new TypeError('offline'); }]).fetcher);
  await assert.rejects(failing.request('GET', '/api/vault/state'), {code: 'discarded'});
});
