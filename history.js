// Log of network events (joined / left / back online) for the current network,
// kept in data/networks/<id>/history.json, newest first.
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { networkDir, ensureDir } from './networks.js';

const MAX_EVENTS = 200;

let history = null;
let networkIdNow = null;
const paths = () => {
  const dir = networkDir(networkIdNow);
  return { dir, file: new URL('history.json', dir), tmp: new URL('history.json.tmp', dir) };
};

/** Switch to another network's log. */
export function useNetwork(id) {
  if (id === networkIdNow) return;
  networkIdNow = id;
  history = null;
}

function load() {
  if (history) return history;
  if (!networkIdNow) return [];
  try {
    const { file } = paths();
    history = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : [];
    if (!Array.isArray(history)) history = [];
  } catch (err) {
    console.warn(`Could not read history.json (${err.message}); starting a new log.`);
    history = [];
  }
  return history;
}

function save() {
  // Atomic: write a temp file, then rename over the real one.
  try {
    const { dir, file, tmp } = paths();
    ensureDir(dir);
    writeFileSync(tmp, JSON.stringify(history, null, 2), { mode: 0o600 }); // private to this user
    renameSync(tmp, file);
  } catch (err) {
    console.warn(`Could not save history.json: ${err.message}`);
  }
}

export function getHistory() {
  return load();
}

/** list: [{ kind: 'joined'|'left'|'back', device }]. Returns the stored entries, newest first. */
export function addEvents(list, at = new Date().toISOString()) {
  if (!list.length) return [];
  load();
  const entries = list.map(({ kind, device: d }) => ({ at, kind, mac: d.mac, ip: d.ip, type: d.type })).reverse();
  history = [...entries, ...history].slice(0, MAX_EVENTS);
  save();
  return entries;
}
