const {test}=require('node:test');
const assert=require('node:assert/strict');
const clock=require('../static/timezone.js');
test('wall times convert independently of the host timezone',()=>{
 assert.equal(clock.toISO('2026-09-21T18:30','Asia/Singapore'),'2026-09-21T10:30:00.000Z');
 assert.equal(clock.toISO('2026-09-21T18:30','Asia/Kathmandu'),'2026-09-21T12:45:00.000Z');
 assert.equal(clock.toISO('2026-09-21T18:30','UTC'),'2026-09-21T18:30:00.000Z');
 assert.equal(clock.toISO('2026-01-15T08:00','America/New_York'),'2026-01-15T13:00:00.000Z');
 assert.equal(clock.toISO('2026-07-15T08:00','America/New_York'),'2026-07-15T12:00:00.000Z');
});
test('DST gaps and repeated times are never silently shifted',()=>{
 assert.throws(()=>clock.toISO('2026-03-08T02:30','America/New_York'),/does not exist/);
 assert.throws(()=>clock.toISO('2026-11-01T01:30','America/New_York'),/occurs twice/);
 assert.throws(()=>clock.toISO('2026-10-04T02:15','Australia/Lord_Howe'),/does not exist/);
 assert.throws(()=>clock.toISO('2026-04-05T01:45','Australia/Lord_Howe'),/occurs twice/);
 assert.equal(clock.toISO('2026-03-08T03:00','America/New_York'),'2026-03-08T07:00:00.000Z');
});
test('invalid calendar dates are rejected',()=>{
 assert.throws(()=>clock.toISO('2026-02-30T12:00','UTC'),/valid date/);
 assert.throws(()=>clock.toISO('2026-09-21T25:00','UTC'),/valid date/);
});
test('formatting uses the preference even without browser storage',()=>{
 clock.set('Asia/Singapore');assert.match(clock.format('2026-09-21T10:30:00Z'),/18:30:00/);
 clock.set('UTC');assert.match(clock.format('2026-09-21T10:30:00Z'),/10:30:00/);
 assert.throws(()=>clock.set('not-a-zone'),/valid timezone/);
 assert.equal(clock.format(null),'Not recorded');clock.set('system');
});
