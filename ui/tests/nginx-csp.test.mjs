import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// The browser flows serve the console under the fixture's policies; nginx must
// send the same ones so those flows describe production.
const conf = readFileSync(new URL('../nginx.conf', import.meta.url), 'utf8');
const fixture = readFileSync(new URL('./owner-fixture.mjs', import.meta.url), 'utf8');

function policy(location) {
  // The next policy after the location line; each location sends one.
  const block = conf.split(`location ${location} {`)[1]?.split(/\n    location /)[0] ?? '';
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

test('inline markup has no inline scripts, handlers or style attributes', () => {
  const html = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);
  assert.doesNotMatch(html, /\sstyle=/i);
  assert.doesNotMatch(html, /<style/i);
});
