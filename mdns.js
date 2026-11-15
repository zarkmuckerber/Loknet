// Bonjour / mDNS discovery: asks the network which services each device offers.
// Queries are sent from an ephemeral port, so devices answer by unicast straight to us
// (RFC 6762 "legacy unicast"), and the reply's source address tells us which device it is.
import dgram from 'node:dgram';

const MDNS_ADDR = '224.0.0.251';
const MDNS_PORT = 5353;
const T_A = 1, T_PTR = 12, T_TXT = 16, T_SRV = 33;

export const SERVICE_TYPES = [
  '_services._dns-sd._udp', // "list every service type you offer"
  '_airplay._tcp', '_raop._tcp', '_googlecast._tcp', '_androidtvremote2._tcp', '_amzn-wplay._tcp',
  '_spotify-connect._tcp', '_sonos._tcp',
  '_ipp._tcp', '_ipps._tcp', '_printer._tcp', '_pdl-datastream._tcp', '_scanner._tcp', '_uscan._tcp',
  '_hap._tcp', '_homekit._tcp', '_matter._tcp', '_hue._tcp', '_esphomelib._tcp', '_miio._udp',
  '_companion-link._tcp', '_apple-mobdev2._tcp', '_rdlink._tcp', '_touch-able._tcp',
  '_smb._tcp', '_afpovertcp._tcp', '_ssh._tcp', '_sftp-ssh._tcp', '_workstation._tcp',
  '_nvstream._tcp', '_http._tcp',
];

function encodeName(name) {
  const parts = [];
  for (const label of name.split('.').filter(Boolean)) {
    const b = Buffer.from(label);
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function buildQuery(name) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(1, 4); // one question
  // QTYPE=PTR, QCLASS=IN with the "unicast response" bit set
  return Buffer.concat([header, encodeName(`${name}.local`), Buffer.from([0, T_PTR, 0x80, 0x01])]);
}

function readName(buf, off) {
  const labels = [];
  let end = -1;
  for (let guard = 0; guard < 128; guard++) {
    const len = buf[off];
    if (len === undefined) throw new RangeError('truncated name');
    if (len === 0) { off += 1; break; }
    if ((len & 0xc0) === 0xc0) { // compression pointer
      if (end < 0) end = off + 2;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      continue;
    }
    labels.push(buf.toString('utf8', off + 1, off + 1 + len));
    off += len + 1;
  }
  return { name: labels.join('.'), next: end >= 0 ? end : off };
}

function parsePacket(buf) {
  const qd = buf.readUInt16BE(4);
  const total = buf.readUInt16BE(6) + buf.readUInt16BE(8) + buf.readUInt16BE(10);
  let off = 12;
  for (let i = 0; i < qd; i++) off = readName(buf, off).next + 4;

  const records = [];
  for (let i = 0; i < total; i++) {
    const { name, next } = readName(buf, off);
    const type = buf.readUInt16BE(next);
    const rdlen = buf.readUInt16BE(next + 8);
    const rd = next + 10;
    const rec = { name, type };
    if (type === T_PTR) rec.data = readName(buf, rd).name;
    else if (type === T_SRV) rec.data = readName(buf, rd + 6).name;
    else if (type === T_A && rdlen === 4) rec.data = [...buf.subarray(rd, rd + 4)].join('.');
    else if (type === T_TXT) {
      rec.data = [];
      for (let p = rd; p < rd + rdlen;) {
        const l = buf[p];
        rec.data.push(buf.toString('utf8', p + 1, p + 1 + l));
        p += l + 1;
      }
    }
    records.push(rec);
    off = rd + rdlen;
  }
  return records;
}

const stripLocal = (n) => n.replace(/\.local\.?$/i, '');

/**
 * Browse for Bonjour services for `durationMs`.
 * Returns Map<ip, { services:Set<string>, names:Set<string>, hostnames:Set<string>, model:string|null }>.
 */
export function discoverMdns(localIp, durationMs = 3000) {
  return new Promise((resolve) => {
    const found = new Map();
    const entry = (ip) => {
      if (!found.has(ip)) found.set(ip, { services: new Set(), names: new Set(), hostnames: new Set(), model: null });
      return found.get(ip);
    };

    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    sock.on('error', () => finish());
    sock.on('message', (msg, rinfo) => {
      let records;
      try { records = parsePacket(msg); } catch { return; }
      const e = entry(rinfo.address);
      for (const r of records) {
        if (r.type === T_PTR && r.name === '_services._dns-sd._udp.local') {
          e.services.add(stripLocal(r.data));
        } else if (r.type === T_PTR && r.name.startsWith('_')) {
          const svc = stripLocal(r.name);
          e.services.add(svc);
          const instance = stripLocal(r.data).replace(`.${svc}`, '');
          if (instance && !instance.startsWith('_')) e.names.add(instance);
        } else if (r.type === T_SRV || r.type === T_A) {
          const host = stripLocal(r.type === T_SRV ? r.data : r.name);
          if (host) e.hostnames.add(host);
        } else if (r.type === T_TXT) {
          const model = r.data.find((s) => s.startsWith('model='))?.slice(6);
          if (model && !e.model) e.model = model;
        }
      }
      // A device may answer for its own .local host with a different IP; keep the source only.
    });

    let done = false;
    function finish() {
      if (done) return;
      done = true;
      try { sock.close(); } catch {}
      // Drop sub-services like "_universal._sub._ipp._tcp".
      for (const e of found.values()) for (const s of e.services) if (s.includes('._sub.')) e.services.delete(s);
      resolve(found);
    }

    sock.bind(0, () => {
      try { sock.setMulticastInterface(localIp); } catch {}
      // Ask twice: some devices are slow to answer the first time.
      const sendAll = () => SERVICE_TYPES.forEach((s) =>
        sock.send(buildQuery(s), MDNS_PORT, MDNS_ADDR, () => {}));
      sendAll();
      setTimeout(sendAll, 800);
      setTimeout(finish, durationMs);
    });
  });
}
