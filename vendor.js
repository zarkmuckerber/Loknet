// MAC prefix → manufacturer, from the IEEE registry (data/oui.csv, fetched by `npm run setup`).
import { existsSync, readFileSync } from 'node:fs';

export const OUI_PATH = new URL('./data/oui.csv', import.meta.url);

let table = null; // Map<hexPrefix, name>, prefixes of length 6 (MA-L), 7 (MA-M) and 9 (MA-S)

function load() {
  table = new Map();
  if (!existsSync(OUI_PATH)) return;
  const line = /^MA-[LMS],([0-9A-F]{6,9}),(?:"([^"]*)"|([^,]*))/;
  for (const row of readFileSync(OUI_PATH, 'utf8').split('\n')) {
    const m = row.match(line);
    if (m) table.set(m[1], (m[2] ?? m[3]).trim());
  }
}

export function hasVendorData() {
  if (!table) load();
  return table.size > 0;
}

/** Returns the manufacturer for a MAC, or null (always null for randomized MACs). */
export function lookupVendor(mac) {
  if (!table) load();
  const hex = mac.replace(/:/g, '').toUpperCase();
  // Longest (most specific) assignment first.
  return table.get(hex.slice(0, 9)) ?? table.get(hex.slice(0, 7)) ?? table.get(hex.slice(0, 6)) ?? null;
}

/** Reloads the table after the CSV has been (re)downloaded. */
export function reloadVendors() {
  table = null;
}
