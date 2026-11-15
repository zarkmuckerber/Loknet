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

/** Fetch a device's description XML (only from the device that announced it). */
async function describe(ip, location) {
  try {
    const url = new URL(location);
    if (url.hostname !== ip || !/^https?:$/.test(url.protocol)) return null;
    const res = await fetch(url, { signal: AbortSignal.timeout(1500) });
    const xml = (await res.text()).slice(0, 200_000);
    return {
      deviceType: tag(xml, 'deviceType'),
      friendlyName: tag(xml, 'friendlyName'),
      manufacturer: tag(xml, 'manufacturer'),
      modelName: tag(xml, 'modelName'),
    };
  } catch {
    return null;
  }
}

/**
 * Returns Map<ip, { types:Set<string>, server:string|null, deviceType, friendlyName, manufacturer, modelName }>.
 */
export function discoverSsdp(localIp, durationMs = 2800) {
  return new Promise((resolve) => {
    const found = new Map();
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    sock.on('message', (msg, rinfo) => {
      const headers = {};
      for (const line of msg.toString('utf8').split('\r\n').slice(1)) {
        const i = line.indexOf(':');
        if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      if (!found.has(rinfo.address)) found.set(rinfo.address, { types: new Set(), server: null, location: null });
      const e = found.get(rinfo.address);
      const st = headers.st || headers.nt;
      const m = st?.match(/:device:([^:]+):/i);
      if (m) e.types.add(m[1]);
      e.server ??= headers.server || null;
      // Prefer the root device's description.
      if (headers.location && (!e.location || /rootdevice/i.test(st ?? ''))) e.location = headers.location;
    });

    let done = false;
    const finish = async () => {
      if (done) return;
      done = true;
      try { sock.close(); } catch {}
      await Promise.all([...found].map(async ([ip, e]) => {
        Object.assign(e, (e.location && (await describe(ip, e.location))) || {});
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
