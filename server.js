import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { scan, getNetworkInfo } from './scanner.js';
import { startSpeedMonitor } from './speed.js';
import { OUI_PATH, reloadVendors } from './vendor.js';
import { fetchOui } from './scripts/fetch-oui.js';
import { TYPES } from './classify.js';
import { recordScan, setName, useNetwork as useKnownFor } from './known.js';
import { addEvents, getHistory, useNetwork as useHistoryFor } from './history.js';
import { networkId, isTrusted, trust, adoptFirstNetwork, lockDownDataDir } from './networks.js';

const HOST = '127.0.0.1'; // local only: other machines can't reach Loknet
const PORT = Number(process.env.PORT) || 3000;
const SCAN_EVERY_MS = 30_000;
const MAX_SSE_CLIENTS = 20;
const indexPath = new URL('./public/index.html', import.meta.url);

// ---- Security: who may talk to this server (see loknet-threat-model.md) ----
// Host allow-list blocks DNS rebinding (TM-001/002): a website that points its own domain at
// 127.0.0.1 still sends its own name in the Host header, so it gets turned away.
const ALLOWED_HOSTS = new Set([`localhost:${PORT}`, `127.0.0.1:${PORT}`]);
const ALLOWED_ORIGINS = new Set([...ALLOWED_HOSTS].map((h) => `http://${h}`));
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Frame-Options': 'DENY', // no framing → no clickjacking (TM-007)
};
const csp = (nonce) => [
  "default-src 'none'",
  `script-src 'nonce-${nonce}'`,
  "style-src 'self' 'unsafe-inline'",
  'img-src data:',
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

let iface = null;
let lastScan = null;
let network = null; // { id, trusted, subnet } of the network we're on

// ---- Server-Sent Events: pushes live updates to every open page ----
const clients = new Set();
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(msg);
}

// Decide per network: full scan on trusted networks, passive mode elsewhere (TM-005).
function decideMode({ gatewayMac, gateway, subnet }) {
  const id = networkId(gatewayMac, gateway);
  adoptFirstNetwork(id, { subnet }); // first network ever seen = home
  const changed = network?.id !== id;
  network = { id, trusted: isTrusted(id), subnet };
  if (changed) {
    console.log(`Network ${id}: ${network.trusted ? 'trusted, full scan' : 'not trusted, passive mode'}`);
    if (network.trusted) { useKnownFor(id); useHistoryFor(id); }
    broadcast('history', network.trusted ? getHistory() : []);
  }
  return network.trusted ? 'full' : 'passive';
}

// Only one scan at a time; concurrent requests share the running one.
let running = null;
function runScan() {
  if (running) return running;
  broadcast('scanning', {});
  running = scan({ decideMode })
    .then((raw) => {
      let result, joined = [], left = [], returned = [];
      if (network.trusted) {
        useKnownFor(network.id); useHistoryFor(network.id);
        ({ scan: result, joined, left, returned } = recordScan(raw));
      } else {
        // Untrusted network: show what's there, but don't remember or alert about strangers' devices.
        result = { ...raw, devices: raw.devices.map((d) => ({ ...d, status: 'online', missed: 0, name: null })), offline: [], joined: [] };
      }
      result.network = { id: network.id, trusted: network.trusted };
      iface = result.interface;
      lastScan = result;
      console.log(`Scan (${raw.mode}): ${raw.devices.length} devices in ${raw.durationMs} ms` +
        (joined.length ? `, ${joined.length} new` : '') + (left.length ? `, ${left.length} left` : ''));
      for (const d of joined) { console.log(`  New device: ${d.type} ${d.ip} ${d.mac}`); broadcast('device-joined', d); }
      for (const d of left) { console.log(`  Device left: ${d.type} ${d.ip} ${d.mac}`); broadcast('device-left', d); }
      if (network.trusted) {
        const events = addEvents([
          ...joined.map((device) => ({ kind: 'joined', device })),
          ...left.map((device) => ({ kind: 'left', device })),
          ...returned.map((device) => ({ kind: 'back', device })),
        ], result.scannedAt ? new Date(result.scannedAt).toISOString() : undefined);
        if (events.length) broadcast('history-add', events);
      }
      broadcast('scan', result);
      return result;
    })
    .catch((err) => { console.warn(`Scan failed: ${err.message}`); broadcast('scan-error', { error: 'Scan failed' }); throw err; })
    .finally(() => { running = null; });
  return running;
}
const rescanSoon = () => (running ? running.catch(() => {}).finally(() => runScan().catch(() => {})) : runScan().catch(() => {}));

function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

// Writes must come from the Loknet page itself: right Origin, JSON body, same-origin fetch.
function writeAllowed(req) {
  const origin = req.headers.origin;
  const site = req.headers['sec-fetch-site'];
  return (!origin || ALLOWED_ORIGINS.has(origin))
    && String(req.headers['content-type']).startsWith('application/json')
    && (!site || site === 'same-origin');
}
async function readJson(req, limit = 2048) {
  let body = '';
  for await (const chunk of req) { body += chunk; if (body.length > limit) throw Object.assign(new Error('Too large'), { status: 413 }); }
  try { return JSON.parse(body); } catch { throw Object.assign(new Error('Bad JSON'), { status: 400 }); }
}
// At most 10 writes a second, so a stuck or hostile page can't hammer the disk.
const writeTimes = [];
function tooManyWrites() {
  const now = Date.now();
  while (writeTimes.length && now - writeTimes[0] > 1000) writeTimes.shift();
  if (writeTimes.length >= 10) return true;
  writeTimes.push(now);
  return false;
}

const server = http.createServer(async (req, res) => {
  // DNS rebinding guard (TM-001/002).
  if (!ALLOWED_HOSTS.has(req.headers.host)) return send(res, 421, { error: 'Misdirected request' });
  const { pathname } = new URL(req.url, `http://${req.headers.host}`);
  // Other websites can't call the API, even blind (TM-003). Browsers send Sec-Fetch-Site; curl doesn't.
  const site = req.headers['sec-fetch-site'];
  if (pathname.startsWith('/api/') && (site === 'cross-site' || site === 'same-site')) {
    return send(res, 403, { error: 'Forbidden' });
  }
  try {
    if (req.method === 'GET' && pathname === '/') {
      const nonce = randomBytes(16).toString('base64');
      const html = (await readFile(indexPath, 'utf8')).replaceAll('<script>', `<script nonce="${nonce}">`);
      return send(res, 200, html, 'text/html; charset=utf-8', { 'Content-Security-Policy': csp(nonce) });
    }
    if (req.method === 'GET' && pathname === '/api/scan') {
      return send(res, 200, await runScan());
    }
    if (req.method === 'POST' && pathname === '/api/name') {
      if (!writeAllowed(req)) return send(res, 403, { error: 'Forbidden' });
      if (tooManyWrites()) return send(res, 429, { error: 'Too many requests' });
      if (!network?.trusted) return send(res, 409, { error: 'Trust this network first' });
      let { mac, name } = (await readJson(req)) ?? {};
      name = String(name ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 40);
      useKnownFor(network.id);
      if (typeof mac !== 'string' || !setName(mac, name)) return send(res, 404, { error: 'Unknown device' });
      for (const d of [...(lastScan?.devices ?? []), ...(lastScan?.offline ?? [])]) if (d.mac === mac) d.name = name || null;
      broadcast('rename', { mac, name: name || null });
      return send(res, 200, { mac, name: name || null });
    }
    if (req.method === 'POST' && pathname === '/api/trust') {
      if (!writeAllowed(req)) return send(res, 403, { error: 'Forbidden' });
      if (tooManyWrites()) return send(res, 429, { error: 'Too many requests' });
      const { id } = (await readJson(req)) ?? {};
      if (!network || id !== network.id) return send(res, 409, { error: 'Not the current network' });
      if (!network.trusted) {
        trust(network.id, { subnet: network.subnet });
        network.trusted = true;
        useKnownFor(network.id); useHistoryFor(network.id);
        broadcast('history', getHistory());
        console.log(`Network ${network.id} trusted by the user.`);
        rescanSoon(); // first full scan becomes this network's baseline (no alerts for what's already there)
      }
      return send(res, 200, { id: network.id, trusted: true });
    }
    if (req.method === 'GET' && pathname === '/api/types') {
      return send(res, 200, TYPES);
    }
    if (req.method === 'GET' && pathname === '/api/events') {
      if (clients.size >= MAX_SSE_CLIENTS) return send(res, 503, { error: 'Too many open pages' });
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-store',
        Connection: 'keep-alive',
      });
      res.write('retry: 3000\n\n');
      if (lastScan) res.write(`event: scan\ndata: ${JSON.stringify(lastScan)}\n\n`);
      res.write(`event: history\ndata: ${JSON.stringify(network?.trusted ? getHistory() : [])}\n\n`);
      if (running) res.write('event: scanning\ndata: {}\n\n');
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }
    send(res, 404, { error: 'Not found' });
  } catch (err) {
    if (err.status) return send(res, err.status, { error: err.message });
    console.error(err);
    if (!res.headersSent) send(res, 500, { error: 'Internal error' }); // details stay in the server log
  }
});
// Slow or half-sent requests are dropped instead of tying up the server.
server.headersTimeout = 10_000;
server.requestTimeout = 10_000;
server.maxHeadersCount = 50;

lockDownDataDir(); // data/ readable only by this user

// Live speed: sample once a second and push to open pages.
getNetworkInfo().then((n) => { iface ??= n.interface; }).catch(() => {});
startSpeedMonitor(() => iface, (sample) => {
  if (clients.size) broadcast('speed', { ...sample, interface: iface });
});

// Fetch the vendor list on first run.
if (!existsSync(OUI_PATH)) {
  console.log('Downloading MAC vendor list (first run only)…');
  fetchOui()
    .then(() => { reloadVendors(); console.log('Vendor list ready.'); })
    .catch((err) => console.warn(`Vendor list unavailable (${err.message}). Run "npm run setup" later.`));
}

// Background scanning: once at start-up, then every 30 s (skipped while a scan is running).
const backgroundScan = () => {
  if (running) return;
  runScan().catch(() => {});
};

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\nPort ${PORT} is already in use, probably by another Loknet that is still running.`);
    console.error(`Stop it (Ctrl+C in its terminal, or: kill $(lsof -tiTCP:${PORT} -sTCP:LISTEN)), then run npm start again.`);
    console.error(`Or run this one on another port: PORT=3001 npm start\n`);
  } else {
    console.error(`Loknet could not start: ${err.message}`);
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`Loknet running at http://localhost:${PORT}`);
  // Scan only once we own the port, so a second copy that fails to start doesn't touch data/.
  backgroundScan();
  setInterval(backgroundScan, SCAN_EVERY_MS);
});
