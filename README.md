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
- A device that disappears is marked offline ("left") about 2–4 minutes after it goes. macOS keeps it in its ARP table for about 2 minutes, and Loknet then waits 2 more scans. It is drawn faded with a dashed line, and it stays listed for 24 hours.
- **History** (the 🕘 button at the top) lists every join, leave and "back online" with its time. The number on the button counts events since you last opened it. The log is saved in `data/history.json` and keeps the latest 200 events.
- **Renaming:** hover a row in the device list and click ✎, or double-click a name in the list or a device on the map. Type a name and press Enter (Esc cancels). Leave the box empty to go back to the device type. Names are saved as `name` in `known.json` and appear in the list, on the map, in the hover card and in History.
- To forget a device, delete its entry from `known.json`. The file is re-read on every scan, and deleting the whole file starts a new baseline.

**Server** ([server.js](server.js)) listens only on `127.0.0.1`.
- `GET /api/scan` runs a scan.
- `GET /api/events` is a Server-Sent Events stream that pushes `speed` every second, `scan` whenever a scan finishes, and `device-joined` / `device-left`, and `history` / `history-add` for the log.

## Security
The full threat model is in [loknet-threat-model.md](loknet-threat-model.md). In short:
- **Only this Mac can reach Loknet.** It listens on `127.0.0.1`, and requests must say `localhost` or `127.0.0.1` as the host. This blocks "DNS rebinding", where a website tries to reach local apps through its own domain.
- **Other websites can't use it.** API calls from other sites are refused. Renaming and trusting need a same-origin JSON request from the Loknet page, and both are rate-limited.
- **The page is locked down:** a strict Content-Security-Policy (only Loknet's own script can run), no framing, `nosniff`, `no-referrer`.
- **Data from devices is treated as hostile.** Bonjour/UPnP replies are size-capped and length-capped. UPnP description fetches don't follow redirects, are capped at 200 KB, and only go to the device that answered.
- **Untrusted networks get passive mode.** The first network Loknet runs on (normally home) is trusted. On any other network (café, hotel, work), Loknet only listens: no port probes, no web requests to devices, no alerts, nothing saved. Use **🛡 Trust this network** only on networks you own or manage.
- **Private files:** each trusted network has its own folder, `data/networks/<router MAC>/`. `data/` is readable only by you (700/600) and is git-ignored.

## Notes
- Phones and recent Macs use a **private MAC** on each Wi-Fi network, so the maker can't be looked up for them. Loknet then relies on Bonjour names, ports and behaviour instead.
- Phones that change their private MAC from time to time may set off a repeat "new device" alert.
- A sleeping phone may close all its ports, so it can show as "Phone, low confidence" until it wakes up.
