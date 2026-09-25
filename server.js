// BLACK BOX: a service that records everything in a tamper-evident log,
// and rebuilds the truth after a crash. No packages needed.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = 3000, DIR = path.join(__dirname, 'data'), LOG = path.join(DIR, 'events.log');
fs.mkdirSync(DIR, { recursive: true });

// ---------- 1. The event log: append-only, each entry fingerprints the one before ----------
const fingerprint = e => crypto.createHash('sha256')
  .update(`${e.prev}|${e.seq}|${e.ts}|${e.type}|${JSON.stringify(e.data)}`).digest('hex');
let entries = [], tail = 'GENESIS';

function append(type, data = {}) {
  const e = { seq: entries.length + 1, ts: Date.now(), type, data, prev: tail };
  e.hash = fingerprint(e);
  fs.appendFileSync(LOG, JSON.stringify(e) + '\n'); // written to disk BEFORE we act on it
  entries.push(e); tail = e.hash;
  return e;
}

function load() { // returns true if a half-written last line had to be discarded
  let torn = false;
  if (fs.existsSync(LOG)) {
    for (const line of fs.readFileSync(LOG, 'utf8').split('\n').filter(Boolean)) {
      try { entries.push(JSON.parse(line)); } catch { torn = true; break; }
    }
    if (torn) fs.writeFileSync(LOG, entries.map(e => JSON.stringify(e) + '\n').join(''));
  }
  tail = entries.length ? entries[entries.length - 1].hash : 'GENESIS';
  return torn;
}

function verify() { // re-checks the whole file from scratch, never trusts memory
  let prev = 'GENESIS', n = 0;
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, 'utf8').split('\n').filter(Boolean) : [];
  for (const line of lines) {
    n++; let e;
    try { e = JSON.parse(line); } catch { return { ok: false, count: lines.length, brokenAt: n, reason: 'entry is unreadable' }; }
    if (e.seq !== n) return { ok: false, count: lines.length, brokenAt: n, reason: 'an entry is missing or out of order' };
    if (e.prev !== prev) return { ok: false, count: lines.length, brokenAt: n, reason: 'chain link broken' };
    if (fingerprint(e) !== e.hash) return { ok: false, count: lines.length, brokenAt: n, reason: 'entry contents were modified' };
    prev = e.hash;
  }
  return { ok: true, count: lines.length };
}

// ---------- 2. State is never stored, it is REBUILT by replaying the log ----------
function orders() {
  const o = {};
  for (const { type, data: d, ts } of entries) {
    if (type === 'ORDER_START') o[d.id] = { ...d, status: 'pending', ts };
    else if (o[d.id] && type === 'ORDER_DONE') o[d.id].status = 'completed';
    else if (o[d.id] && type === 'ORDER_ROLLED_BACK') o[d.id].status = 'rolled_back';
  }
  return o;
}
const nextId = () => 'ORD-' + (entries.filter(e => e.type === 'ORDER_START').length + 1);

// ---------- 3. Recovery on every start ----------
const t0 = Date.now(), torn = load(), last = entries[entries.length - 1];
if (last && last.type !== 'SHUTDOWN') { // last thing in the log wasn't a clean shutdown = crash
  const inflight = Object.values(orders()).filter(o => o.status === 'pending').map(o => o.id);
  append('CRASH_DETECTED', { lastEvent: last.type, downtimeMs: t0 - last.ts, inflight, tornWrite: torn });
  inflight.forEach(id => append('ORDER_ROLLED_BACK', { id, reason: 'crashed before completion' }));
  append('RECOVERY_COMPLETE', { recoveryMs: Date.now() - t0, rolledBack: inflight.length });
} else append('BOOT', { firstRun: !last });

process.on('SIGINT', () => { append('SHUTDOWN'); process.exit(0); });

// ---------- 4. The API ----------
const send = (res, obj, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const body = req => new Promise(r => { let s = ''; req.on('data', c => s += c); req.on('end', () => { try { r(JSON.parse(s || '{}')); } catch { r({}); } }); });

http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  if (url === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return fs.createReadStream(path.join(__dirname, 'public', 'index.html')).pipe(res); }

  if (url === '/api/report') {
    const all = orders(), list = Object.values(all), ev = t => entries.filter(e => e.type === t);
    const rec = ev('RECOVERY_COMPLETE').pop();
    return send(res, {
      verify: verify(), entries: entries.slice(-250), orders: list.slice(-8).reverse(),
      score: { events: entries.length, crashes: ev('CRASH_DETECTED').length, completed: list.filter(o => o.status === 'completed').length,
        rolledBack: list.filter(o => o.status === 'rolled_back').length, duplicatesBlocked: ev('DUPLICATE_BLOCKED').length,
        lastRecoveryMs: rec ? rec.data.recoveryMs : null }
    });
  }

  if (url === '/api/orders' && req.method === 'POST') {
    const b = await body(req), requestId = b.requestId || 'req-' + Date.now();
    const dup = Object.values(orders()).find(o => o.requestId === requestId && o.status !== 'rolled_back');
    if (dup) { append('DUPLICATE_BLOCKED', { requestId, orderId: dup.id }); return send(res, { duplicate: true, order: dup }); }
    const id = nextId();
    append('ORDER_START', { id, item: b.item || 'Sample item', amount: b.amount || 100, requestId });
    setTimeout(() => { append('ORDER_DONE', { id }); send(res, { duplicate: false, id }); }, 700); // pretend work takes time
    return;
  }

  if (url === '/api/crash') { // start an order, then die instantly with it half-finished
    const id = nextId();
    append('ORDER_START', { id, item: 'Order in progress at crash', amount: 999, requestId: 'crash-' + Date.now() });
    send(res, { ok: true, inflight: id });
    return setTimeout(() => process.kill(process.pid, 'SIGKILL'), 80);
  }

  if (url === '/api/tamper') { // silently edit an old log line, like an attacker would
    const lines = fs.readFileSync(LOG, 'utf8').split('\n').filter(Boolean);
    const i = lines.findIndex(l => l.includes('"ORDER_START"'));
    if (i < 0) return send(res, { ok: false, message: 'Create an order first.' });
    const e = JSON.parse(lines[i]); e.data.amount = (e.data.amount || 0) + 5000; // hash NOT updated
    lines[i] = JSON.stringify(e); fs.writeFileSync(LOG, lines.join('\n') + '\n');
    return send(res, { ok: true, editedEntry: e.seq });
  }

  if (url === '/api/reset') {
    fs.writeFileSync(LOG, ''); entries = []; tail = 'GENESIS'; append('BOOT', { firstRun: true });
    return send(res, { ok: true });
  }
  send(res, { error: 'not found' }, 404);
}).listen(PORT, () => console.log(`Service running: http://localhost:${PORT}`));
