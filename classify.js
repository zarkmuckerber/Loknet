// Rules that turn a device's clues into a device type. Each matching rule adds points;
// the type with the most points wins. Too few points → "unknown".

export const TYPES = {
  router:   { label: 'Router',         icon: '🛜' },
  phone:    { label: 'Phone',          icon: '📱' },
  tablet:   { label: 'Tablet',         icon: '📲' },
  computer: { label: 'Computer',       icon: '💻' },
  tv:       { label: 'TV / Streaming', icon: '📺' },
  speaker:  { label: 'Speaker',        icon: '🔊' },
  printer:  { label: 'Printer',        icon: '🖨️' },
  camera:   { label: 'Camera',         icon: '📷' },
  console:  { label: 'Game console',   icon: '🎮' },
  smart:    { label: 'Smart home',     icon: '💡' },
  nas:      { label: 'NAS / Storage',  icon: '🗄️' },
  unknown:  { label: 'Unknown',        icon: '❔' },
};

const MIN_SCORE = 3;

const V = {
  printer: /brother|canon|seiko epson|epson|lexmark|xerox|kyocera|ricoh|konica|zebra/i,
  camera: /hikvision|dahua|wyze|reolink|amcrest|axis comm|arlo|ring llc|eufy|imou|ezviz|foscam/i,
  tv: /roku|vizio|hisense|tcl|lg electronics|sharp|skyworth|realtek semiconductor|nvidia|sony visual|philips tv/i,
  speaker: /sonos|bose|harman|bang & olufsen|denon|yamaha|marantz|bluesound/i,
  console: /nintendo|sony interactive|valve/i,
  nas: /synology|qnap|western digital|asustor|buffalo|terramaster/i,
  smart: /espressif|tuya|shelly|allterco|signify|philips lighting|lifx|belkin|wemo|ecobee|nest labs|ikea|meross|sonoff|itead|broadlink|xiaomi|aqara|wiz|ring|august|chamberlain|irobot|ecovacs/i,
  router: /ubiquiti|netgear|tp-link|eero|asustek|linksys|zte|huawei|mikrotik|cisco|aruba|ruckus|tenda|d-link|zyxel|technicolor|sagemcom|arris|askey|fiberhome|nokia/i,
  phoneBrand: /apple|samsung|xiaomi|oppo|vivo|oneplus|realme|huawei|honor|motorola|google|nothing tech/i,
  computer: /intel corp|dell|lenovo|hewlett|hp inc|asustek|micro-star|gigabyte|framework|raspberry/i,
};

const N = {
  phone: /iphone|android|galaxy(?!.?tab)|pixel|oneplus|redmi|xiaomi|oppo|vivo|huawei|honor|moto|phone/i,
  tablet: /ipad|galaxy.?tab|\btab\b|kindle|fire.?hd|surface.?go/i,
  computer: /macbook|imac|mac.?mini|mac.?studio|mac.?pro|desktop|laptop|\bpc\b|thinkpad|workstation|ubuntu|windows|raspberry/i,
  tv: /\btv\b|apple.?tv|chromecast|fire.?tv|firestick|roku|shield|bravia|webos|tizen/i,
  speaker: /homepod|sonos|echo|nest.?(mini|audio|hub)|speaker|soundbar/i,
  printer: /printer|laserjet|officejet|deskjet|envy|pixma|ecotank|epson|brother|mfc-/i,
  camera: /cam(era)?\b|doorbell|ipc|nvr/i,
  console: /xbox|playstation|\bps[345]\b|switch|nintendo|steam.?deck/i,
  nas: /\bnas\b|diskstation|synology|qnap|ds\d{3}/i,
  smart: /plug|bulb|light|lamp|thermostat|hue|esp[-_]?\w*|tasmota|shelly|sensor|vacuum|roomba|tado|switch-/i,
};

/** Apple model identifiers from Bonjour's device-info record. */
function appleModel(model) {
  if (!model) return null;
  if (/^iPhone/i.test(model) || /^D\d+AP$/i.test(model)) return { type: 'phone', why: `Apple model ${model} (iPhone)` };
  if (/^iPad/i.test(model)) return { type: 'tablet', why: `Apple model ${model} (iPad)` };
  if (/^(Mac|iMac)/i.test(model)) return { type: 'computer', why: `Apple model ${model} (Mac)` };
  if (/^AppleTV/i.test(model)) return { type: 'tv', why: `Apple model ${model} (Apple TV)` };
  if (/^(AudioAccessory|HomePod)/i.test(model)) return { type: 'speaker', why: `Apple model ${model} (HomePod)` };
  if (/^J\d+AP$/i.test(model)) return { type: 'tablet', why: `Apple board ${model} (iPad family)`, weak: true };
  return null;
}

/**
 * @param {object} d  device with ip, mac, ttl, isGateway, isSelf, randomizedMac and clues:
 *   { vendor, hostname, services[], names[], model, ports[], upnp }
 * @returns {{ type, confidence, reasons: string[] }}
 */
export function classify(d) {
  const c = d.clues;
  const scores = {};
  const reasons = {};
  const add = (type, points, why) => {
    scores[type] = (scores[type] ?? 0) + points;
    (reasons[type] ??= []).push(why);
  };

  const svc = new Set(c.services);
  const port = new Set(c.ports);
  const has = (...s) => s.some((x) => svc.has(x));
  const open = (...p) => p.some((x) => port.has(x));
  const vendor = [c.vendor, c.upnp?.manufacturer].filter(Boolean).join(' ');
  const names = [c.hostname, ...c.names, c.upnp?.friendlyName, c.upnp?.modelName].filter(Boolean).join(' ');
  const upnpTypes = c.upnp?.types ?? [];

  // --- Strong, direct signals ---
  if (d.isGateway) add('router', 10, 'Default gateway of this network');
  if (d.isSelf) add('computer', 10, 'The computer running Loknet');
  const am = appleModel(c.model);
  if (am) add(am.type, am.weak ? 3 : 10, am.why);

  // --- Name hints (hostname, Bonjour name, UPnP name) ---
  for (const [type, re] of Object.entries(N)) {
    const m = names.match(re);
    if (m) add(type, 6, `Name contains “${m[0]}”`);
  }

  // --- Bonjour services ---
  if (has('_ipp._tcp', '_ipps._tcp', '_printer._tcp', '_pdl-datastream._tcp')) add('printer', 7, 'Advertises a printing service');
  if (has('_scanner._tcp', '_uscan._tcp')) add('printer', 2, 'Advertises a scanner service');
  if (has('_googlecast._tcp')) add('tv', 6, 'Advertises Google Cast');
  if (has('_androidtvremote2._tcp')) add('tv', 7, 'Advertises Android TV remote');
  if (has('_amzn-wplay._tcp')) add('tv', 4, 'Advertises Amazon Fire TV casting');
  if (has('_sonos._tcp')) add('speaker', 8, 'Advertises Sonos');
  if (has('_raop._tcp') && !has('_companion-link._tcp')) add('speaker', 3, 'AirPlay audio receiver');
  if (has('_spotify-connect._tcp')) add('speaker', 2, 'Spotify Connect receiver');
  if (has('_hap._tcp', '_homekit._tcp', '_matter._tcp')) add('smart', 4, 'HomeKit / Matter accessory');
  if (has('_hue._tcp')) add('smart', 7, 'Philips Hue bridge');
  if (has('_esphomelib._tcp', '_miio._udp')) add('smart', 7, 'Smart-home firmware (ESPHome / Mi Home)');
  if (has('_smb._tcp', '_afpovertcp._tcp', '_ssh._tcp', '_sftp-ssh._tcp', '_workstation._tcp', '_rdlink._tcp')) add('computer', 3, 'Offers file sharing or remote login');
  if (has('_apple-mobdev2._tcp')) add('phone', 3, 'Apple mobile device sync');
  if (has('_nvstream._tcp')) add('computer', 2, 'NVIDIA GameStream host');

  // --- Open ports ---
  if (open(9100)) add('printer', 5, 'Port 9100 open (raw printing)');
  if (open(631) && !has('_companion-link._tcp')) add('printer', 3, 'Port 631 open (IPP printing)');
  if (open(554)) add('camera', 4, 'Port 554 open (RTSP video stream)');
  if (open(8008, 8009)) add('tv', 5, 'Google Cast ports open');
  if (open(8001)) add('tv', 5, 'Port 8001 open (Samsung TV API)');
  if (open(8060)) add('tv', 7, 'Port 8060 open (Roku)');
  if (open(1883)) add('smart', 4, 'Port 1883 open (MQTT, smart home)');
  if (open(3389)) add('computer', 6, 'Port 3389 open (Windows Remote Desktop)');
  if (open(445, 139)) add('computer', 2, 'Windows file sharing ports open');
  if (open(548)) add('computer', 3, 'Port 548 open (Mac file sharing)');
  if (open(62078)) add('phone', 6, 'Port 62078 open (iPhone/iPad sync)');
  if (open(32400)) add('nas', 2, 'Port 32400 open (Plex media server)');
  if (open(5000) && open(445)) add('nas', 4, 'Storage admin + file sharing ports');
  if (open(53) && open(80) && !d.isGateway) add('router', 3, 'DNS + web admin (mesh node or extender)');

  // --- UPnP device description ---
  if (upnpTypes.some((t) => /InternetGatewayDevice|WANDevice|WFADevice/i.test(t))) add('router', 6, 'UPnP gateway device');
  if (upnpTypes.some((t) => /MediaRenderer/i.test(t))) add('tv', 3, 'UPnP media player');
  if (upnpTypes.some((t) => /MediaServer/i.test(t))) add('nas', 2, 'UPnP media server');
  if (upnpTypes.some((t) => /BinaryLight|DimmableLight|controllee|sensor/i.test(t))) add('smart', 6, 'UPnP smart-home device');
  if (upnpTypes.some((t) => /Printer/i.test(t))) add('printer', 6, 'UPnP printer');

  // --- Manufacturer ---
  for (const type of ['printer', 'camera', 'tv', 'speaker', 'console', 'nas', 'smart', 'router']) {
    const m = vendor.match(V[type]);
    if (m) add(type, type === 'router' || type === 'smart' ? 2 : 4, `Made by ${titleCase(m[0])}`);
  }
  if (V.computer.test(vendor)) add('computer', 2, `Made by ${titleCase(vendor.match(V.computer)[0])}`);
  if (V.phoneBrand.test(vendor) && !c.services.length && !c.ports.length) add('phone', 2, `${titleCase(vendor.match(V.phoneBrand)[0])} device with no open services`);

  // --- Weak behavioural hints ---
  if (d.ttl === 128) add('computer', 3, 'Network behaviour typical of Windows');
  if (d.ttl >= 250) add('router', 2, 'Network behaviour typical of network equipment');
  if (d.randomizedMac && !d.isSelf) {
    if (!c.services.length && !c.ports.length) add('phone', 3, 'Private MAC and no open services (typical of a phone)');
    else add('phone', 1, 'Uses a private MAC address');
  }
  // iPads also run the sync service; an iPad-only sign should beat the generic iPhone port.
  if (scores.tablet && open(62078)) add('tablet', 1, 'Apple mobile device');

  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [best, score] = ranked[0] ?? ['unknown', 0];
  if (score < MIN_SCORE) {
    return { type: 'unknown', confidence: 'low', reasons: Object.values(reasons).flat().slice(0, 3) };
  }
  const margin = score - (ranked[1]?.[1] ?? 0);
  const confidence = score >= 8 && margin >= 3 ? 'high' : score >= 5 ? 'medium' : 'low';
  return { type: best, confidence, reasons: reasons[best].slice(0, 4) };
}

function titleCase(s) {
  return s.replace(/\b\w/g, (ch) => ch.toUpperCase());
}
