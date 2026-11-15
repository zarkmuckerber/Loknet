// Finds devices on the local network: ping sweep to fill the ARP cache, then read the ARP table.
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { discoverMdns } from './mdns.js';
import { discoverSsdp } from './ssdp.js';
import { scanPorts, reverseLookup } from './probes.js';
import { lookupVendor } from './vendor.js';
import { classify } from './classify.js';

const run = promisify(execFile);

const ipToInt = (ip) => ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
const intToIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

// Pad each octet to two hex digits: macOS prints "d2:91:f2:f6:3:14".
export const normalizeMac = (mac) =>
  mac.toLowerCase().split(':').map((p) => p.padStart(2, '0')).join(':');

// Locally-administered bit set → the device is using a private/randomized MAC.
export const isRandomizedMac = (mac) => (parseInt(mac.slice(0, 2), 16) & 0b10) !== 0;

/** The active IPv4 interface: prefers the one carrying the default route. */
export async function getNetworkInfo() {
  let gateway = null;
  let defaultIface = null;
  try {
    const { stdout } = await run('route', ['-n', 'get', 'default']);
    gateway = stdout.match(/gateway:\s*(\S+)/)?.[1] ?? null;
    defaultIface = stdout.match(/interface:\s*(\S+)/)?.[1] ?? null;
  } catch {
    // No default route (offline); fall back to the first usable interface.
  }

  const candidates = Object.entries(os.networkInterfaces()).flatMap(([name, addrs]) =>
    (addrs ?? [])
      .filter((a) => a.family === 'IPv4' && !a.internal)
      .map((a) => ({ name, ...a })),
  );
  const iface = candidates.find((c) => c.name === defaultIface) ?? candidates[0];
  if (!iface) throw new Error('No active network connection found.');

  // Limit the sweep to at most a /24 around our own address.
  const prefix = Math.max(iface.cidr ? Number(iface.cidr.split('/')[1]) : 24, 24);
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipToInt(iface.address) & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;

  return {
    interface: iface.name,
    ip: iface.address,
    mac: normalizeMac(iface.mac),
    gateway,
    subnet: `${intToIp(network)}/${prefix}`,
    hosts: Array.from({ length: broadcast - network - 1 }, (_, i) => intToIp(network + 1 + i)),
  };
}

/** Ping one host once; resolves to its TTL, or null if it didn't answer. */
async function ping(ip) {
  try {
    const { stdout } = await run('ping', ['-c', '1', '-W', '500', '-n', ip], { timeout: 2000 });
    const ttl = stdout.match(/ttl=(\d+)/i)?.[1];
    return ttl ? Number(ttl) : null;
  } catch {
    return null; // ping exits non-zero when there's no reply
  }
}

/** Ping every host, a limited number at a time. Returns Map<ip, ttl>. */
async function pingSweep(hosts, concurrency = 64) {
  const replies = new Map();
  let next = 0;
  const worker = async () => {
    while (next < hosts.length) {
      const ip = hosts[next++];
      const ttl = await ping(ip);
      if (ttl !== null) replies.set(ip, ttl);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return replies;
}

/** Parse `arp -an`: "? (192.168.0.1) at 68:2a:dd:65:15:85 on en0 ifscope [ethernet]" */
async function readArpTable(ifaceName) {
  const { stdout } = await run('arp', ['-an']);
  const entries = new Map();
  for (const line of stdout.split('\n')) {
    const m = line.match(/\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on (\S+)/i);
    if (!m || m[3] !== ifaceName) continue;
    const mac = normalizeMac(m[2]);
    if (mac === 'ff:ff:ff:ff:ff:ff') continue; // broadcast
    if (mac.startsWith('01:00:5e') || mac.startsWith('33:33')) continue; // multicast
    entries.set(m[1], mac);
  }
  return entries;
}

/** This Mac's Bonjour name (os.hostname() can be just an IP on macOS). */
async function localHostName() {
  try {
    return (await run('scutil', ['--get', 'LocalHostName'])).stdout.trim() || null;
  } catch {
    return null;
  }
}

// Everything below comes from other devices on the network, which may be hostile on public Wi-Fi.
// Keep it short so it can't bloat memory or the page.
const clip = (s, n = 64) => (typeof s === 'string' ? s.slice(0, n) : s ?? null);

/** The router's MAC: identifies which network we're on (before we probe anything). */
async function gatewayMac(net) {
  let mac = (await readArpTable(net.interface)).get(net.gateway);
  if (!mac && net.gateway) {
    await ping(net.gateway);
    mac = (await readArpTable(net.interface)).get(net.gateway);
  }
  return mac ?? null;
}

/**
 * Run a scan of the local network.
 * decideMode({ gatewayMac, gateway, subnet }) returns 'full' or 'passive'. Passive mode (untrusted
 * networks) only pings, reads ARP and listens to Bonjour/UPnP announcements: no port probes and no
 * HTTP requests to other people's devices.
 */
export async function scan({ decideMode = () => 'full' } = {}) {
  const started = Date.now();
  const net = await getNetworkInfo();
  const gwMac = await gatewayMac(net);
  const mode = await decideMode({ gatewayMac: gwMac, gateway: net.gateway, subnet: net.subnet });
  const passive = mode !== 'full';
  const inSubnet = new Set(net.hosts);

  // Bonjour and UPnP listen for a few seconds; run them alongside the ping sweep.
  const [replies, mdns, ssdp] = await Promise.all([
    pingSweep(net.hosts.filter((ip) => ip !== net.ip)),
    discoverMdns(net.ip),
    discoverSsdp(net.ip, { fetchDescriptions: !passive, inSubnet: (ip) => inSubnet.has(ip) }),
  ]);
  const arp = await readArpTable(net.interface);

  const devices = [...arp]
    .filter(([ip]) => inSubnet.has(ip) && ip !== net.ip)
    .map(([ip, mac]) => ({
      ip,
      mac,
      ttl: replies.get(ip) ?? null,
      respondedToPing: replies.has(ip),
      randomizedMac: isRandomizedMac(mac),
      isGateway: ip === net.gateway,
      isSelf: false,
    }));

  // ARP never lists our own machine, so add it.
  devices.push({
    ip: net.ip,
    mac: net.mac,
    ttl: 64,
    respondedToPing: true,
    randomizedMac: isRandomizedMac(net.mac),
    isGateway: false,
    isSelf: true,
  });

  // Per-device probes (our own machine is skipped: we know what it is).
  const remoteIps = devices.filter((d) => !d.isSelf).map((d) => d.ip);
  const [ports, rdns] = await Promise.all([passive ? new Map() : scanPorts(remoteIps), reverseLookup(remoteIps)]);

  for (const d of devices) {
    const m = mdns.get(d.ip);
    const u = ssdp.get(d.ip);
    d.clues = {
      vendor: d.randomizedMac ? null : lookupVendor(d.mac),
      hostname: clip((d.isSelf ? null : rdns.get(d.ip)) ?? [...(m?.hostnames ?? [])][0] ?? (d.isSelf ? await localHostName() : null)),
      names: [...(m?.names ?? [])].filter((n) => !n.includes('@')).slice(0, 8).map((n) => clip(n)),
      services: [...(m?.services ?? [])].sort().slice(0, 32),
      model: clip(m?.model),
      ports: ports.get(d.ip) ?? [],
      upnp: u ? { ...u, types: [...u.types] } : null,
    };
    Object.assign(d, classify(d));
  }

  devices.sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));

  return {
    interface: net.interface,
    subnet: net.subnet,
    gateway: net.gateway,
    gatewayMac: gwMac,
    mode: passive ? 'passive' : 'full',
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    devices,
  };
}
