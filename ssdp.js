// UPnP / SSDP discovery: TVs, media boxes, routers and smart plugs often describe themselves here.
import dgram from 'node:dgram';

const SSDP_ADDR = '239.255.255.250';
const SSDP_PORT = 1900;
const SEARCH = Buffer.from([
  'M-SEARCH * HTTP/1.1',
  `HOST: ${SSDP_ADDR}:${SSDP_PORT}`,
  'MAN: "ssdp:discover"',
  'MX: 2',
  'ST: ssdp:all',
  '', '',
].join('\r\n'));

const tag = (xml, name) => xml.match(new RegExp(`<${name}>([^<]*)</${name}>`, 'i'))?.[1]?.trim() || null;

const MAX_XML_BYTES = 200_000;
const MAX_RESPONDERS = 64;   // ignore floods of (possibly spoofed) replies
const MAX_TYPES = 16;
const cap = (s, n = 128) => (typeof s === 'string' ? s.slice(0, n) : s);

/** Read at most `limit` bytes of a response body, then stop the download. */
async function readCapped(res, limit) {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.length;
      if (size >= limit) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).subarray(0, limit).toString('utf8');
}

/**
 * Fetch a device's description XML (only from the device that announced it).
 * Hardened against hostile devices: no redirects (they could point us anywhere),
 * no cookies or credentials, a size cap and a short timeout.
 */
export async function describe(ip, location) { // exported for tests
  try {
    const url = new URL(location);
    if (url.hostname !== ip || !/^https?:$/.test(url.protocol) || url.username || url.password) return null;
    const res = await fetch(url, { redirect: 'manual', credentials: 'omit', signal: AbortSignal.timeout(1500) });
    if (!res.ok) { res.body?.cancel().catch(() => {}); return null; }
    const xml = await readCapped(res, MAX_XML_BYTES);
    return {
      deviceType: cap(tag(xml, 'deviceType')),
      friendlyName: cap(tag(xml, 'friendlyName'), 64),
      manufacturer: cap(tag(xml, 'manufacturer'), 64),
      modelName: cap(tag(xml, 'modelName'), 64),
    };
  } catch {
    return null;
  }
}

/**
 * Returns Map<ip, { types:Set<string>, server:string|null, deviceType, friendlyName, manufacturer, modelName }>.
 */
export function discoverSsdp(localIp, { durationMs = 2800, fetchDescriptions = true, inSubnet = () => true } = {}) {
  return new Promise((resolve) => {
    const found = new Map();
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    sock.on('message', (msg, rinfo) => {
      const headers = {};
      for (const line of msg.toString('utf8').split('\r\n').slice(1)) {
        const i = line.indexOf(':');
        if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      if (!inSubnet(rinfo.address)) return; // only devices on our own network
      if (!found.has(rinfo.address)) {
        if (found.size >= MAX_RESPONDERS) return;
        found.set(rinfo.address, { types: new Set(), server: null, location: null });
      }
      const e = found.get(rinfo.address);
      const st = headers.st || headers.nt;
      const m = st?.match(/:device:([^:]+):/i);
      if (m && e.types.size < MAX_TYPES) e.types.add(cap(m[1], 64));
      e.server ??= cap(headers.server) || null;
      // Prefer the root device's description.
      if (headers.location && (!e.location || /rootdevice/i.test(st ?? ''))) e.location = headers.location;
    });

    let done = false;
    const finish = async () => {
      if (done) return;
      done = true;
      try { sock.close(); } catch {}
      await Promise.all([...found].map(async ([ip, e]) => {
        // Passive mode (untrusted network): don't make HTTP requests to other people's devices.
        if (fetchDescriptions) Object.assign(e, (e.location && (await describe(ip, e.location))) || {});
        delete e.location;
        if (e.deviceType) e.types.add(e.deviceType.match(/:device:([^:]+):/i)?.[1] ?? e.deviceType);
      }));
      resolve(found);
    };
    sock.on('error', finish);

    sock.bind(0, () => {
      try { sock.setMulticastInterface(localIp); } catch {}
      sock.send(SEARCH, SSDP_PORT, SSDP_ADDR, () => {});
      setTimeout(() => sock.send(SEARCH, SSDP_PORT, SSDP_ADDR, () => {}), 700);
      setTimeout(finish, durationMs);
    });
  });
}
