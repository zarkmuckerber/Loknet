// Log of network events (joined / left / back online), kept in data/history.json, newest first.
import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'node:fs';

const HISTORY_PATH = new URL('./data/history.json', import.meta.url);
const TMP_PATH = new URL('./data/history.json.tmp', import.meta.url);
const MAX_EVENTS = 200;

let history = null;

function load() {
  if (history) return history;
  try {
    history = existsSync(HISTORY_PATH) ? JSON.parse(readFileSync(HISTORY_PATH, 'utf8')) : [];
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
    mkdirSync(new URL('./data/', import.meta.url), { recursive: true });
    writeFileSync(TMP_PATH, JSON.stringify(history, null, 2));
    renameSync(TMP_PATH, HISTORY_PATH);
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
