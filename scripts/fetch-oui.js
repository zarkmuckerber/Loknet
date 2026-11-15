// Downloads the IEEE MAC vendor registry to data/oui.csv (about 4 MB).
import { mkdir, writeFile } from 'node:fs/promises';
import { OUI_PATH } from '../vendor.js';

const URL_OUI = 'https://standards-oui.ieee.org/oui/oui.csv';

export async function fetchOui() {
  const res = await fetch(URL_OUI, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const text = await res.text();
  if (!text.startsWith('Registry,')) throw new Error('Unexpected file format from IEEE');
  await mkdir(new URL('.', OUI_PATH), { recursive: true });
  await writeFile(OUI_PATH, text);
  return text.split('\n').length - 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('Downloading MAC vendor list from IEEE…');
  fetchOui()
    .then((n) => console.log(`Saved ${n} vendor entries to data/oui.csv`))
    .catch((err) => { console.error(err.message); process.exit(1); });
}
