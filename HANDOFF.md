# Loknet — Session Handoff

Read this file first. It covers what was decided, what's built and what's left, so you can continue without the earlier conversation.

## What Loknet is
A local web app (macOS, Node) that lists every device on the user's home network. For each device it shows **device type, IP and MAC address**, and nothing more. The user explicitly does **not** want the exact model, hostnames in the table, or AI identification.

**UI layout, as the user asked for it:**
- **Top left:** live Wi-Fi download/upload speed. This is this Mac's own live usage, **not** a speed test (the user picked "Live usage").
- **Top right:** the device list (Type / IP / MAC).
- **Centre:** devices drawn as a **spider web branching out from the router**, with the router in the middle.
- **A notification when a new device joins.** (step 4, built)

## Decisions already made (don't re-ask)
- Name: **Loknet**. Location: `~/Projects/loknet/`. Not a git repo yet.
- Stack: plain Node (ESM, Node 20 or newer; the machine has v26), built-in modules only, **no npm dependencies**, vanilla JS + inline SVG on the front end, no build step.
- Device type comes from **rules** (`classify.js`), not AI. Claude/AI for "Unknown" devices was offered and put off. It's only a possible later item.
- The server binds to `127.0.0.1:3000` only.

## Current state: steps 1–4 done
| Step | Status |
|---|---|
| Foundation: ping sweep + ARP → IP/MAC, server, `/api/scan` | ✅ done, verified |
| 1. Device type detection | ✅ done, verified on the real network |
| 2. Spider-web map UI + three-panel layout | ✅ written; **not yet viewed in a browser** (only syntax-checked) |
| 3. Live Wi-Fi speed (SSE) | ✅ done; events verified with curl |
| 4. Background scanning + new-device notifications | ✅ done; join/leave logic verified (real scan + fake-scan test); toast/Notification not yet seen in a browser |

Verified scan on the user's network (192.168.0.0/24, `en0`, gateway 192.168.0.1). A full scan takes about 6.5 s:
```
192.168.0.1   68:2a:dd:65:15:85  router   high    (ZTE, default gateway)
192.168.0.6   4a:e8:87:de:bc:bb  tablet   high    (Bonjour: "iPad Air", model J607AP)
192.168.0.8   32:58:b1:df:35:38  computer high    (this Mac, MacBookPro18,3)
192.168.0.10  d2:91:f2:f6:03:14  phone    medium  (private MAC; port 62078 open only when awake)
```

## Files
```
loknet/
  package.json        npm start → node server.js ; npm run setup → node scripts/fetch-oui.js
  server.js           HTTP server. Routes: GET / , /api/scan , /api/types , /api/events (SSE).
                      runScan() shares one scan between concurrent requests, stores lastScan, broadcasts 'scan'.
                      Speed monitor broadcasts 'speed' every 1 s. Downloads the OUI file on first run if missing.
  scanner.js          getNetworkInfo() (interface, subnet capped at /24, gateway via `route -n get default`),
                      pingSweep (64 at a time, `ping -c 1 -W 500`), readArpTable (`arp -an`), scan().
                      scan() runs mDNS + SSDP alongside the ping sweep, then ports + reverse DNS, then classify().
                      Adds this Mac itself (isSelf) and skips the ARP entry for its own IP. Hostname via `scutil --get LocalHostName`.
  mdns.js             Hand-written mDNS query/parser on dgram (ephemeral port → legacy unicast replies).
                      Returns per IP: services, instance names, hostnames, Apple `model=` from TXT records.
  ssdp.js             M-SEARCH, then fetches the LOCATION XML (only from the IP that announced it). Returned nothing on this network.
  probes.js           TCP connect to 19 ports (400 ms timeout, 128 at a time) + reverse DNS (filters IP-echo names).
  vendor.js           IEEE OUI lookup from data/oui.csv (MA-L/M/S, longest match first). Null for randomized MACs.
  classify.js         TYPES (label + emoji icon) and classify(d): points per rule, best type wins, below 3 → unknown.
                      Confidence: high (≥8 points and ≥3 ahead of the next type), medium (≥5), else low. Returns up to 4 reasons.
  speed.js            startSpeedMonitor(getIface, onSample): `netstat -ibn -I <if>` Link# row, Ibytes/Obytes deltas → bits/s.
  scripts/fetch-oui.js  downloads https://standards-oui.ieee.org/oui/oui.csv to data/oui.csv (already downloaded, ~3.9 MB).
  public/index.html   the whole UI (inline CSS/JS). Grid: side (speed + type legend) | map (SVG web) | list.
                      SSE client: 'speed' → numbers + 60-point sparkline; 'scan' → applyScan().
                      applyScan() already works out newMacs (MACs not seen earlier in this page session) and gives those nodes
                      the class 'new' (pulse animation). Hovering list rows or map nodes cross-highlights them and shows a tooltip with reasons.
  README.md           user-facing docs
  .gitignore          node_modules, data/*.json, data/oui.csv
```

Device object returned by `/api/scan`:
`{ ip, mac, ttl, respondedToPing, randomizedMac, isGateway, isSelf, clues: { vendor, hostname, names[], services[], model, ports[], upnp }, type, confidence, reasons[] }`

## Step 4 as built
- `known.js` → `recordScan(raw)` returns `{ scan, joined, left }`. `known.json` is re-read on every scan (so hand edits work) and written synchronously (tmp file + rename).
- The scan payload now has `devices[]` (each has `status: 'online'` and `missed`; devices missed 1–2 times are kept from an in-memory cache), `offline[]` (missed ≥ 3, last seen < 24 h) and `joined[]` (MACs).
- server.js scans at start-up and then every 60 s. In index.html, `newMacs` comes from `data.joined`, and the old `state.seen` logic is gone.
- A device that comes back after being offline does **not** trigger an alert (it's still in known.json).

Original plan, for reference:
- **server.js:** scan automatically every 60 s (`setInterval(runScan, 60_000)`, skipped if a scan is already running). The Scan button still triggers a scan immediately.
- **Saving known devices:** store `data/known.json` by MAC as `{ firstSeen, lastSeen, ip, type }`. On the very first run, the first scan becomes the baseline, so there are no alerts for devices already present. Write the file atomically (write a tmp file, then rename).
- **Join and leave events:** after each scan, any MAC not in `known.json` → `broadcast('device-joined', device)`. A device missing for 3 scans in a row → `device-left`, shown faded with a dashed line on the map. Include online/offline status in the scan payload, or send it as a separate event.
- **index.html:**
  - A toast that slides in for `device-joined` ("🔔 New device: Phone · 192.168.0.31 · 7a:1c:…") and hides itself after 8 s.
  - The new node pulses (the class already exists).
  - If `document.hidden`, use the browser **Notification API** so it shows as a macOS notification. Ask for permission on the first click of Scan, not on page load.
  - The client-side `newMacs` logic in `applyScan()` can be simplified to use the server's events instead.
- **Known caveat to mention to the user:** phones that rotate private MACs can cause occasional repeat "new device" alerts. Linking those MACs into one device is a "later" item.
- **Verify:** delete one MAC from `data/known.json` (or turn a phone's Wi-Fi off and on) → within about 60 s the toast appears and the node animates in.

## Done after step 4
- UI redesign (Apple-style frosted panels, spring drag, Reset layout), no Scan button (fully live, 30 s scans), speed always in Mbps, one-line header.
- **History:** `history.js` → `data/history.json` (newest first, max 200). known.js now also returns `returned` (back after being marked left). The server sends `history` on SSE connect and `history-add` after scans. In the UI, the 🕘 History button in the header opens a popover, and a badge shows unseen events (localStorage `loknet.historySeen`).

## Still unverified / worth doing
- **Open the UI in a real browser** (http://localhost:3000 after `npm start`) and check the map layout, dark mode, the narrow-width stacking (breakpoints at 1150 px and 700 px) and the tooltips. So far only `node --check` has been run on the page script.
- Emoji icons assume macOS (🛜 needs macOS 14 or newer; the machine is on Darwin 24 = macOS 15).

## Later (offered to the user, not requested)
- Claude as a fallback identifier for "Unknown" devices
- Linking a phone's multiple randomized MACs into one device
- Scan history / "what changed" summary

## Working with this user
- They like to talk features through first and often decline plan approvals or question pop-ups until they're ready. When they say "build" or "do X", go ahead.
- When reporting back, keep it plain-language and short, and be clear about what was verified and what wasn't.

## Test commands
```sh
cd ~/Projects/loknet && npm start                                   # then open http://localhost:3000
curl -s localhost:3000/api/scan | python3 -m json.tool               # scan JSON
curl -s -N -m 4 localhost:3000/api/events | grep '^event'            # expect 1 scan + speed every 1 s
```
