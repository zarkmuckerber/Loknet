// Per-device probes: a few common TCP ports, and reverse DNS.
import net from 'node:net';
import { Resolver } from 'node:dns/promises';

// Each port is a hint about the device type (see classify.js).
export const PORTS = [
  22,    // SSH
  53,    // DNS (routers)
  80, 443,
  139, 445, // Windows / SMB file sharing
  548,   // AFP (Mac file sharing)
  554,   // RTSP (cameras)
  631,   // IPP (printers)
  1883,  // MQTT (smart home)
  3389,  // Remote Desktop (Windows)
  5000,  // Synology DSM / UPnP
  8001,  // Samsung TV remote API
  8008, 8009, // Chromecast / Google Cast
  8060,  // Roku control
  9100,  // raw printing
  32400, // Plex
  62078, // iPhone / iPad sync service
];

function probe(ip, port, timeoutMs = 400) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port });
    const done = (open) => { s.destroy(); resolve(open); };
    s.setTimeout(timeoutMs);
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
  });
}

/** Returns Map<ip, number[]> of open ports, probing all IPs together. */
export async function scanPorts(ips, concurrency = 128) {
  const jobs = ips.flatMap((ip) => PORTS.map((port) => ({ ip, port })));
  const open = new Map(ips.map((ip) => [ip, []]));
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const { ip, port } = jobs[next++];
      if (await probe(ip, port)) open.get(ip).push(port);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  for (const ports of open.values()) ports.sort((a, b) => a - b);
  return open;
}

const resolver = new Resolver({ timeout: 1000, tries: 1 });

/** Reverse-DNS names (often the router's DHCP names). Returns Map<ip, string|null>. */
export async function reverseLookup(ips) {
  const names = await Promise.all(ips.map(async (ip) => {
    try {
      const [name] = await resolver.reverse(ip);
      // Some routers just echo the IP back; that tells us nothing.
      if (!name || /^\d+\.\d+\.\d+\.\d+\.?$/.test(name) || name.includes(ip)) return null;
      return name.replace(/\.(local|lan|home|localdomain|domain)\.?$/i, '');
    } catch {
      return null;
    }
  }));
  return new Map(ips.map((ip, i) => [ip, names[i]]));
}
