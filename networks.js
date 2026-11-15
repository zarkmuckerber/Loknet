// Trusted networks (data/networks.json) and per-network data folders.
// A network is identified by its router's MAC address. On networks you haven't trusted
// (café, hotel, work…) Loknet runs in passive mode: no port probes, no alerts, nothing saved.
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, chmodSync, readdirSync, statSync } from 'node:fs';

const DATA_DIR = new URL('./data/', import.meta.url);
const NETWORKS_PATH = new URL('./data/networks.json', import.meta.url);
const TMP_PATH = new URL('./data/networks.json.tmp', import.meta.url);

let state = null; // { trusted: { [id]: { trustedAt, subnet } } }

/** Network id from the router's MAC ("68-2a-dd-65-15-85"). Only hex and dashes, so it is safe in a path. */
export function networkId(gatewayMac, gatewayIp) {
  const raw = gatewayMac || `ip-${gatewayIp ?? 'unknown'}`;
  return raw.toLowerCase().replace(/[^0-9a-z]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'unknown';
}

/** Folder holding known.json / history.json for one network. */
export function networkDir(id) {
  if (!/^[0-9a-z-]{1,40}$/.test(id)) throw new Error('bad network id');
  return new URL(`./data/networks/${id}/`, import.meta.url);
}

export function ensureDir(url) {
  mkdirSync(url, { recursive: true, mode: 0o700 });
}

function load() {
  if (state) return state;
  try {
    state = existsSync(NETWORKS_PATH) ? JSON.parse(readFileSync(NETWORKS_PATH, 'utf8')) : null;
  } catch (err) {
    console.warn(`Could not read networks.json (${err.message}).`);
  }
  if (!state || typeof state.trusted !== 'object') state = null;
  return state;
}

function save() {
  try {
    ensureDir(DATA_DIR);
    writeFileSync(TMP_PATH, JSON.stringify(state, null, 2), { mode: 0o600 });
    renameSync(TMP_PATH, NETWORKS_PATH);
  } catch (err) {
    console.warn(`Could not save networks.json: ${err.message}`);
  }
}

export function isTrusted(id) {
  return Boolean(load()?.trusted?.[id]);
}

export function trust(id, info = {}) {
  load();
  state ??= { trusted: {} };
  state.trusted[id] = { trustedAt: new Date().toISOString(), subnet: info.subnet ?? null };
  save();
}

/**
 * The very first network Loknet runs on is trusted automatically (that's normally home).
 * Data saved before networks existed (data/known.json, data/history.json) moves into its folder.
 */
export function adoptFirstNetwork(id, info = {}) {
  if (load()) return;
  trust(id, info);
  const dir = networkDir(id);
  ensureDir(dir);
  for (const name of ['known.json', 'history.json']) {
    const legacy = new URL(name, DATA_DIR);
    const target = new URL(name, dir);
    if (existsSync(legacy) && !existsSync(target)) renameSync(legacy, target);
  }
  console.log(`Trusted this network (${id}) as your home network.`);
}

/** Make data/ private to this user: folders 700, files 600. */
export function lockDownDataDir() {
  const walk = (url) => {
    for (const name of readdirSync(url)) {
      const child = new URL(name, url);
      const isDir = statSync(child).isDirectory();
      try { chmodSync(child, isDir ? 0o700 : 0o600); } catch {}
      if (isDir) walk(new URL(`${name}/`, url));
    }
  };
  try {
    ensureDir(DATA_DIR);
    chmodSync(DATA_DIR, 0o700);
    walk(DATA_DIR);
  } catch (err) {
    console.warn(`Could not tighten data/ permissions: ${err.message}`);
  }
}
