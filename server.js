import http from 'node:http';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { scan, getNetworkInfo } from './scanner.js';
import { startSpeedMonitor } from './speed.js';
import { OUI_PATH, reloadVendors } from './vendor.js';
import { fetchOui } from './scripts/fetch-oui.js';
import { TYPES } from './classify.js';
import { recordScan } from './known.js';

const HOST = '127.0.0.1'; // local only: other machines can't trigger scans
const PORT = Number(process.env.PORT) || 3000;
const SCAN_EVERY_MS = 30_000;
const indexPath = new URL('./public/index.html', import.meta.url);

let iface = null;
let lastScan = null;

// ---- Server-Sent Events: pushes live updates to every open page ----
const clients = new Set();
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(msg);
}

// Only one scan at a time; concurrent requests share the running one.
let running = null;
function runScan() {
  if (running) return running;
  broadcast('scanning', {});
  running = scan()
    .then((raw) => {
      const { scan: result, joined, left } = recordScan(raw);
      iface = result.interface;
      lastScan = result;
      console.log(`Scan: ${raw.devices.length} devices in ${raw.durationMs} ms` +
        (joined.length ? `, ${joined.length} new` : '') + (left.length ? `, ${left.length} left` : ''));
      for (const d of joined) { console.log(`  New device: ${d.type} ${d.ip} ${d.mac}`); broadcast('device-joined', d); }
      for (const d of left) { console.log(`  Device left: ${d.type} ${d.ip} ${d.mac}`); broadcast('device-left', d); }
      broadcast('scan', result);
      return result;
    })
    .catch((err) => { broadcast('scan-error', { error: err.message }); throw err; })
    .finally(() => { running = null; });
  return running;
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === 'GET' && pathname === '/') {
      return send(res, 200, await readFile(indexPath, 'utf8'), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && pathname === '/api/scan') {
      return send(res, 200, await runScan());
    }
    if (req.method === 'GET' && pathname === '/api/types') {
      return send(res, 200, TYPES);
    }
    if (req.method === 'GET' && pathname === '/api/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-store',
        Connection: 'keep-alive',
      });
      res.write('retry: 3000\n\n');
      if (lastScan) res.write(`event: scan\ndata: ${JSON.stringify(lastScan)}\n\n`);
      if (running) res.write('event: scanning\ndata: {}\n\n');
      clients.add(res);
      req.on('close', () => clients.delete(res));
      return;
    }
    send(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message });
  }
});

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

server.listen(PORT, HOST, () => {
  console.log(`Loknet running at http://localhost:${PORT}`);
});

// Background scanning: once at start-up, then every 30 s (skipped while a scan is running).
const backgroundScan = () => {
  if (running) return;
  runScan().catch((err) => console.warn(`Background scan failed: ${err.message}`));
};
backgroundScan();
setInterval(backgroundScan, SCAN_EVERY_MS);
