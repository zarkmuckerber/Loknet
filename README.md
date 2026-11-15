# Loknet

See every device on your local network: what kind of device it is, its IP and its MAC address. Devices are drawn as a web branching out from your router, next to a live readout of this Mac's Wi-Fi speed.

## Run

```sh
npm start
```

Then open http://localhost:3000.

Requires macOS and Node 20 or newer. There are no npm dependencies. On first start, Loknet downloads the IEEE MAC vendor list (about 4 MB) to `data/oui.csv`. To download it again later, run `npm run setup`.

## How it works

**Finding devices** ([scanner.js](scanner.js))
1. Finds the active interface and its subnet (capped at a /24, so at most 254 addresses).
2. Pings every address once, 64 at a time. This fills the ARP table, so devices that ignore ping still show up.
3. Reads the IP and MAC of each device from `arp -an`.

**Device type** ([classify.js](classify.js)). Clues are collected while the scan runs:
| Clue | Source |
|---|---|
| Maker | MAC prefix looked up in the IEEE vendor list ([vendor.js](vendor.js)) |
| Bonjour services, names and Apple model IDs | mDNS queries ([mdns.js](mdns.js)) |
| UPnP device type and model | SSDP search ([ssdp.js](ssdp.js)) |
| Open ports (19 common ones) and reverse-DNS name | [probes.js](probes.js) |
| Ping TTL, private (randomized) MAC | scanner |

Each rule adds points to a device type, and the type with the most points wins. If no type gets enough points, the device is shown as **Unknown**. Hovering over a device shows the reasons for its type. To change how devices are recognised, edit the rules in `classify.js`.

**Live speed** ([speed.js](speed.js)) reads the interface's byte counters (`netstat -ibn`) once a second. It shows this Mac's own download and upload, not a speed test.

**New-device alerts** ([known.js](known.js)). Loknet scans by itself once a minute (the Scan button scans right away). Every device it has seen is saved by MAC in `data/known.json`. The very first scan is the baseline, so devices already on the network don't trigger alerts. After that:
- A MAC that isn't in `known.json` causes a pop-up on the page ("🔔 New device: …"), and its node pulses on the map. If the Loknet tab is in the background, a macOS notification is shown as well. The browser asks for permission the first time you click **Scan**.
- A device that misses 3 scans in a row (about 3 minutes) is marked offline. It is drawn faded with a dashed line, and it stays listed for 24 hours.
- To forget a device, delete its entry from `known.json`. The file is re-read on every scan, and deleting the whole file starts a new baseline.

**Server** ([server.js](server.js)) listens only on `127.0.0.1`.
- `GET /api/scan` runs a scan.
- `GET /api/events` is a Server-Sent Events stream that pushes `speed` every second, `scan` whenever a scan finishes, and `device-joined` / `device-left`.

## Notes
- Phones and recent Macs use a **private MAC** on each Wi-Fi network, so the maker can't be looked up for them. Loknet then relies on Bonjour names, ports and behaviour instead.
- Phones that change their private MAC from time to time may set off a repeat "new device" alert.
- A sleeping phone may close all its ports, so it can show as "Phone, low confidence" until it wakes up.
