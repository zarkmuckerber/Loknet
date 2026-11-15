// Remembers every device ever seen on the current network (data/networks/<id>/known.json, keyed by MAC)
// and works out which devices joined, which are still around and which have left.
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { networkDir, ensureDir } from './networks.js';

let networkIdNow = null;
const paths = () => {
  const dir = networkDir(networkIdNow);
  return { dir, file: new URL('known.json', dir), tmp: new URL('known.json.tmp', dir) };
};

/** Switch to another network's device list (call before recordScan / setName). */
export function useNetwork(id) {
  if (id === networkIdNow) return;
  networkIdNow = id;
  known = null;
  baseline = false;
  lastDevice.clear();
}

// Presence comes from the ARP table, which macOS clears about 2 min after a device stops answering,
// so a short extra wait is enough (sleeping phones still answer ARP).
const MISSES_TO_LEAVE = 2;                    // absent this many scans in a row (≈1 min at 30 s) → "left"
const SHOW_OFFLINE_MS = 24 * 60 * 60 * 1000;  // keep showing devices that left within the last day

let known = null;          // { [mac]: { firstSeen, lastSeen, ip, type, missed, name? } }
let baseline = false;      // true until the first scan has been recorded
const lastDevice = new Map(); // mac → full device object from the latest scan it appeared in (memory only)

// Re-read on every scan so hand edits to known.json take effect without a restart.
// No file → this scan becomes the baseline (no alerts for devices already there).
function load() {
  if (!networkIdNow) throw new Error('known.js: useNetwork() was not called');
  const { file } = paths();
  if (existsSync(file)) {
    try {
      known = JSON.parse(readFileSync(file, 'utf8'));
      return;
    } catch (err) {
      console.warn(`Could not read known.json (${err.message}); keeping the copy in memory.`);
      if (known) return;
    }
  }
  known = {};
  baseline = true;
}

function save() {
  // Atomic: write a temp file, then rename over the real one. Synchronous (the file is tiny),
  // so the next scan's load() always sees the latest state.
  try {
    const { dir, file, tmp } = paths();
    ensureDir(dir);
    writeFileSync(tmp, JSON.stringify(known, null, 2), { mode: 0o600 }); // private to this user
    renameSync(tmp, file);
  } catch (err) {
    console.warn(`Could not save known.json: ${err.message}`);
  }
}

/**
 * Records a scan. Returns the scan with these additions:
 *   devices[]: every device seen now, plus ones missed fewer than MISSES_TO_LEAVE scans (status 'online', missed > 0)
 *   offline[]: devices gone MISSES_TO_LEAVE+ scans that were last seen in the past 24 h (status 'offline')
 *   joined[]:  MACs never seen before (empty on the very first run, which is the baseline)
 * plus lists of joined, left and returned (back after being marked left) devices.
 */
export function recordScan(result) {
  load();
  const now = new Date(result.scannedAt ?? Date.now()).toISOString();
  const present = new Set();
  const joined = [];
  const left = [];
  const returned = [];

  for (const d of result.devices) {
    if (!d.mac) continue;
    present.add(d.mac);
    lastDevice.set(d.mac, d);
    const k = known[d.mac];
    if (!k) {
      known[d.mac] = { firstSeen: now, lastSeen: now, ip: d.ip, type: d.type, missed: 0 };
      if (!baseline) joined.push(d);
    } else {
      if ((k.missed ?? 0) >= MISSES_TO_LEAVE) returned.push(d); // had been marked as left
      Object.assign(k, { lastSeen: now, ip: d.ip, type: d.type, missed: 0 });
    }
  }

  const devices = result.devices.map((d) => ({ ...d, status: 'online', missed: 0 }));
  const offline = [];
  for (const [mac, k] of Object.entries(known)) {
    if (present.has(mac)) continue;
    k.missed = (k.missed ?? 0) + 1;
    const cached = lastDevice.get(mac);
    const base = cached ?? { ip: k.ip, mac, type: k.type, clues: {}, reasons: [] };
    const entry = { ...base, lastSeen: k.lastSeen, missed: k.missed };
    if (k.missed < MISSES_TO_LEAVE) {
      // Probably just asleep or slow to answer: keep it on the map for now.
      if (cached) devices.push({ ...entry, status: 'online' });
    } else {
      if (k.missed === MISSES_TO_LEAVE) left.push({ ...entry, status: 'offline' });
      if (Date.now() - Date.parse(k.lastSeen) < SHOW_OFFLINE_MS) offline.push({ ...entry, status: 'offline' });
    }
  }

  if (baseline) console.log(`Baseline recorded: ${present.size} known devices.`);
  baseline = false;
  save();

  // Attach the user's own names (set with setName) to everything the page shows.
  const named = (d) => ({ ...d, name: known[d.mac]?.name ?? null });
  return {
    scan: { ...result, devices: devices.map(named), offline: offline.map(named), joined: joined.map((d) => d.mac) },
    joined,
    left,
    returned,
  };
}

/** Gives a known device the user's own name (an empty name removes it). Returns false for an unknown MAC. */
export function setName(mac, name) {
  load();
  const k = known[mac];
  if (!k) return false;
  if (name) k.name = name; else delete k.name;
  save();
  return true;
}
