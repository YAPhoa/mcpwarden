/* Browser-local timezone preference; audit timestamps remain UTC instants. */
(function (root) {
  const key = 'mcpwarden-timezone';
  function valid(value) {
    if (value === 'system') return true;
    if (typeof value !== 'string' || !value) return false;
    try { new Intl.DateTimeFormat('en', {timeZone: value}); return true; } catch (_) { return false; }
  }
  let preference = 'system';
  try { const saved = localStorage.getItem(key); if (valid(saved)) preference = saved; } catch (_) {}
  const zone = () => preference === 'system' ? Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' : preference;
  function set(value) {
    if (!valid(value)) throw new Error('Choose a valid timezone.');
    preference = value;
    try { localStorage.setItem(key, value); } catch (_) {}
  }
  function format(value) {
    if (!value) return 'Not recorded';
    const instant = new Date(value);
    if (!Number.isFinite(instant.getTime())) return 'Not recorded';
    return new Intl.DateTimeFormat(undefined, {timeZone: zone(), year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23', timeZoneName:'short'}).format(instant);
  }
  // Find matching instants using offsets around the requested wall time. Reject
  // nonexistent or repeated DST times instead of silently shifting a boundary.
  function toISO(local, timeZone = zone()) {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(local)) throw new Error('Choose a valid date and time.');
    const wall = Date.parse(local + ':00Z');
    if (!Number.isFinite(wall) || new Date(wall).toISOString().slice(0,16) !== local) throw new Error('Choose a valid date and time.');
    const formatter = new Intl.DateTimeFormat('en-CA', {timeZone, calendar:'gregory', numberingSystem:'latn', year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'});
    const wallAt = instant => {
      const p = Object.fromEntries(formatter.formatToParts(new Date(instant)).map(part=>[part.type,part.value]));
      return `${p.year.padStart(4,'0')}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}`;
    };
    const offsets = new Set();
    for (let hours=-36; hours<=36; hours+=12) {
      const sample=wall+hours*3600000;
      offsets.add(Date.parse(wallAt(sample)+'Z')-sample);
    }
    const matches=[...offsets].map(offset=>wall-offset).filter(instant=>wallAt(instant)===local+':00');
    if (!matches.length) throw new Error(`That time does not exist in ${timeZone} because the clocks change. Choose another time.`);
    if (matches.length>1) throw new Error(`That time occurs twice in ${timeZone} because the clocks change. Choose an unambiguous time, or use UTC.`);
    return new Date(matches[0]).toISOString();
  }
  function zones() {
    const available = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : ['America/New_York','America/Los_Angeles','Asia/Singapore','Asia/Tokyo','Asia/Kolkata','Europe/London','Europe/Paris','Australia/Sydney'];
    return [...new Set(['UTC', zone(), ...available])].sort();
  }
  const api = {zone, preference:()=>preference, set, format, toISO, zones};
  root.MCPWardenTime = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window === 'undefined' ? globalThis : window);
