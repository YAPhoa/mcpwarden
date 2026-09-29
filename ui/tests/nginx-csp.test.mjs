import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// The browser flows serve the console under the fixture's policies; nginx must
// send the same ones so those flows describe production. Both servers (HTTP
// and the optional HTTPS one) take their locations from one shared file.
const conf = readFileSync(new URL('../locations.conf', import.meta.url), 'utf8');
const LOCATIONS = 'include /etc/nginx/mcpwarden/locations.conf;';
const fixture = readFileSync(new URL('./owner-fixture.mjs', import.meta.url), 'utf8');

function policy(location) {
  // The next policy after the location line; each location sends one.
  const block = conf.split(`location ${location} {`)[1]?.split(/\nlocation /)[0] ?? '';
  return block.match(/Content-Security-Policy "([^"]+)"/)?.[1];
}
const constant = name => fixture.match(new RegExp(`const ${name} = "([^"]+)"`))?.[1];

test('console pages use the fixture page policy', () => {
  assert.ok(constant('PAGE_CSP'));
  assert.equal(policy('/'), constant('PAGE_CSP'));
});

test('vault workers use the fixture worker policy', () => {
  assert.ok(constant('WORKER_CSP'));
  assert.equal(policy('/security/'), constant('WORKER_CSP'));
});

test('the HTTP and HTTPS servers serve the shared locations only', () => {
  for (const name of ['nginx.conf', 'nginx-tls.conf']) {
    const server = readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
    assert.ok(server.includes(LOCATIONS), name);
    assert.doesNotMatch(server, /\blocation\b|add_header|proxy_/, name);
  }
  const dockerfile = readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8');
  assert.match(dockerfile, /COPY locations\.conf \/etc\/nginx\/mcpwarden\/locations\.conf/);
});

test('the API proxy overwrites the forwarded scheme', () => {
  const api = conf.split('location /api/ {')[1].split(/\n}/)[0];
  assert.match(api, /proxy_set_header X-Forwarded-Proto \$scheme;/);
  assert.match(api, /proxy_set_header Forwarded "";/);
});

test('inline markup has no inline scripts, handlers or style attributes', () => {
  const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);
  assert.doesNotMatch(html, /\sstyle=/i);
  assert.doesNotMatch(html, /<style/i);
});
