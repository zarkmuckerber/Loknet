// Live Wi-Fi usage of this Mac: samples the interface's byte counters once a second.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

async function readCounters(iface) {
  const { stdout } = await run('netstat', ['-ibn', '-I', iface]);
  const lines = stdout.trim().split('\n');
  const header = lines[0].trim().split(/\s+/);
  const link = lines.find((l) => l.includes('<Link#'));
  if (!link) throw new Error(`No counters for ${iface}`);
  const cols = link.trim().split(/\s+/);
  // The Link row has the same columns as the header (it always has an Address).
  return { rx: Number(cols[header.indexOf('Ibytes')]), tx: Number(cols[header.indexOf('Obytes')]) };
}

/**
 * Calls onSample({ down, up, at }) every `intervalMs`, with down/up in bits per second.
 * `getInterface` is called each tick so a changed network is picked up.
 */
export function startSpeedMonitor(getInterface, onSample, intervalMs = 1000) {
  let prev = null;
  const tick = async () => {
    const iface = getInterface();
    if (!iface) return;
    try {
      const now = process.hrtime.bigint();
      const c = await readCounters(iface);
      if (prev && prev.iface === iface) {
        const secs = Number(now - prev.t) / 1e9;
        const down = ((c.rx - prev.rx) * 8) / secs;
        const up = ((c.tx - prev.tx) * 8) / secs;
        // Counters can reset (interface restart); skip that sample.
        if (down >= 0 && up >= 0) onSample({ down, up, at: Date.now() });
      }
      prev = { iface, t: now, ...c };
    } catch {
      prev = null;
    }
  };
  const timer = setInterval(tick, intervalMs);
  tick();
  return () => clearInterval(timer);
}
