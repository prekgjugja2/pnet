'use strict';

const boot = JSON.parse(document.getElementById('pnet-boot').textContent);
const drawer = document.getElementById('drawer');
const main = document.getElementById('main');
let state = null;
let saving = false;
let autoRefreshEnabled = false;
let autoRefreshInterval = null;
let scanAttempted = false;
let routerTab = 'home';
let trafficLive = null;
let trafficPoll = null;
let liveDeviceId = null;
let liveTrafficEnabled = false;

const ROUTER_TABS = [
  ['home', 'Home'],
  ['devices', 'Devices'],
  ['wifi', 'Wi‑Fi'],
  ['internet', 'Internet'],
  ['security', 'Security'],
  ['more', 'More']
];

const WIFI_SECURITY = [['wpa2', 'WPA2 (recommended)'], ['wpa3', 'WPA3'], ['wpa2wpa3', 'WPA2/WPA3'], ['open', 'Open (not safe)']];
const WIFI_BAND = [['both', 'Both 2.4 + 5 GHz'], ['2.4', '2.4 GHz only'], ['5', '5 GHz only']];
const WAN_MODE = [['dhcp', 'Automatic (most homes)'], ['static', 'Manual IP'], ['pppoe', 'PPPoE (some ISPs)']];
const DNS_MODE = [['isp', 'Use ISP DNS'], ['cloudflare', 'Cloudflare (fast)'], ['google', 'Google DNS'], ['quad9', 'Quad9 (security)'], ['custom', 'Custom']];
const QOS_MODE = [['device', 'By device'], ['app', 'By app'], ['priority', 'By priority']];
const VPN_TYPE = [['none', 'None'], ['openvpn', 'OpenVPN'], ['wireguard', 'WireGuard'], ['ipsec', 'IPSec'], ['pptp', 'PPTP']];
const MAC_MODE = [['disabled', 'Off'], ['allow', 'Only allow listed'], ['deny', 'Block listed']];
const CHANNEL_24 = [['auto', 'Auto'], ['1', '1'], ['6', '6'], ['11', '11']];
const CHANNEL_5 = [['auto', 'Auto'], ['36', '36'], ['40', '40'], ['44', '44'], ['48', '48'], ['149', '149'], ['153', '153']];
const PROTOCOLS = [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP & UDP']];
const SCHEDULE_ACTIONS = [['block', 'Block internet'], ['allow', 'Allow only'], ['limit', 'Limit speed']];
const FILTER_MODES = [['allow', 'Allow'], ['deny', 'Block']];

const PAGES = {
  overview: ['Home', 'Overview'],
  wifi: ['Easy setup', 'Router'],
  network: ['Devices', 'Network'],
  traffic: ['Live', 'Internet traffic'],
  firewall: ['Rules', 'Firewall'],
  sites: ['Blocking', 'Blocking'],
  ips: ['Addresses', 'IP addresses'],
  defender: ['Safety', 'Home Defender'],
  cameras: ['Cameras', 'IP cameras'],
  settings: ['Setup', 'Settings']
};

const STATUS = [['online', 'Online'], ['offline', 'Offline'], ['unknown', 'Unknown']];
const TYPES = [['router', 'Router'], ['computer', 'Computer'], ['phone', 'Phone'], ['tablet', 'Tablet'], ['tv', 'TV'], ['console', 'Game console'], ['printer', 'Printer'], ['iot', 'Smart home'], ['camera', 'Camera'], ['speaker', 'Speaker'], ['other', 'Other']];
const KINDS = [['lan', 'LAN'], ['guest', 'Guest'], ['reserved', 'Reserved'], ['blocked', 'Blocked'], ['gateway', 'Gateway'], ['dns', 'DNS'], ['public', 'Public'], ['vpn', 'VPN'], ['other', 'Other']];
const CATEGORIES = [['social', 'Social'], ['games', 'Games'], ['ads', 'Ads'], ['adult', 'Adult'], ['shopping', 'Shopping'], ['custom', 'Custom']];
const SEVERITY = [['info', 'Info'], ['low', 'Low'], ['medium', 'Medium'], ['high', 'High'], ['critical', 'Critical']];
const ALERT_CATS = [['intrusion', 'Intrusion'], ['malware', 'Malware'], ['scan', 'Scan'], ['policy', 'Policy'], ['camera', 'Camera'], ['device', 'Device'], ['other', 'Other']];
const ALERT_STATUS = [['open', 'Open'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved']];
const TRUST = [['trusted', 'Trusted'], ['unknown', 'Unknown'], ['guest', 'Guest'], ['blocked', 'Blocked']];
const ACCESS = [['normal', 'Normal'], ['limited', 'Limited'], ['quarantined', 'Quarantined']];

const DEVICE_ICONS = {
  router: '🌐',
  computer: '💻',
  phone: '📱',
  tablet: '📟',
  tv: '📺',
  console: '🎮',
  printer: '🖨️',
  iot: '🏠',
  camera: '📷',
  speaker: '🔊',
  other: '📦'
};

const LABEL = {
  type: Object.fromEntries(TYPES),
  kind: Object.fromEntries(KINDS),
  category: Object.fromEntries(CATEGORIES.concat(ALERT_CATS)),
  severity: Object.fromEntries(SEVERITY),
  status: Object.fromEntries(STATUS.concat(ALERT_STATUS)),
  trust: Object.fromEntries(TRUST),
  access: Object.fromEntries(ACCESS)
};

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

function label(group, value) {
  return (LABEL[group] && LABEL[group][value]) || value || '';
}

const TYPE_BRAND_FALLBACK = {
  router: 'generic',
  computer: 'computer',
  phone: 'phone',
  tablet: 'tablet',
  tv: 'tv',
  console: 'console',
  printer: 'printer',
  iot: 'iot',
  camera: 'camera',
  speaker: 'speaker',
  other: 'other'
};

function isGatewayDevice(row) {
  const gw = state?.network?.gateway || '';
  return row.type === 'router' || (gw && row.ip === gw);
}

function deviceBrandSlug(row) {
  if (row.brand) return row.brand;
  if (isGatewayDevice(row)) {
    return state?.router?.router_brand || 'generic';
  }
  return TYPE_BRAND_FALLBACK[row.type] || 'other';
}

function deviceIconHtml(row) {
  const brand = deviceBrandSlug(row);
  const alt = row.brand_name || row.vendor || label('type', row.type) || 'Device';
  return `<span class="device-icon ${esc(row.type)} brand"><img src="assets/brands/${esc(brand)}.svg" alt="${esc(alt)}" width="36" height="36" loading="lazy"></span>`;
}

function deviceMeta(row) {
  const typeLabel = label('type', row.type);
  const brand = row.brand_name || row.vendor || '';
  if (brand && brand !== typeLabel && brand !== 'Device') {
    return brand + ' · ' + typeLabel;
  }
  return typeLabel + (row.vendor && row.vendor !== brand ? ' · ' + row.vendor : '');
}

function routerAdminUrl() {
  const r = state.router || {};
  const access = r.access || {};
  const net = state.network || {};
  const gateway = net.gateway || r.lan_ip || '';
  return access.admin_url || r.router_admin_url || (gateway ? `http://${gateway}` : '');
}

function routerIsConnected() {
  const access = state?.router?.access || {};
  // Credentials + reachable is not enough — login must have succeeded.
  return !!(access.has_credentials && access.login_ok);
}

function routerNeedsLoginFix() {
  const access = state?.router?.access || {};
  return !!(access.has_credentials && access.reachable && !access.login_ok);
}

function wifiIsConnected() {
  const wifi = state?.wifi || {};
  return !!(wifi.available || wifi.ssid);
}

function routerBrandLabel() {
  const r = state.router || {};
  const name = (r.router_brand_name || '').trim();
  if (name && name !== 'Router') return name;
  const brand = (r.router_brand || '').trim();
  if (brand && brand !== 'generic') {
    return brand.charAt(0).toUpperCase() + brand.slice(1);
  }
  return 'your router';
}

function isZteRouter() {
  const r = state.router || {};
  const brand = (r.router_brand || '').toLowerCase();
  if (brand === 'zte') return true;
  if (brand && brand !== 'generic') return false;
  const access = r.access || {};
  return /f627|\bzte\b/i.test(String(r.router_model || access.title || ''));
}

function isElectronShell() {
  return /Electron/i.test(navigator.userAgent || '');
}

function isDesktopApp() {
  return !!(window.pnet && window.pnet.isDesktop);
}

function hasDesktopDns() {
  return isDesktopApp()
    && typeof window.pnet.dnsPullWifi === 'function'
    && typeof window.pnet.dnsPushWifi === 'function';
}

function desktopBridgeHint() {
  if (hasDesktopDns()) {
    return '';
  }
  if (isDesktopApp()) {
    return tip('Desktop app detected, but DNS controls are outdated. Close PNet and reopen with the latest build (desktop folder → npm start, or rebuild the installer).');
  }
  if (isElectronShell()) {
    return tip('You are in an Electron window without the PNet bridge. Close this window and start PNet from c:\\xampp\\htdocs\\pnet\\desktop with npm start.');
  }
  return tip('You are in a browser. For Start / Push, open the PNet desktop app. Pull Wi‑Fi DNS still works here.');
}

function hostsApplyBanner() {
  const dnsOn = state.settings.dns_blocker_enabled === '1';
  const dnsHost = state.settings.dns_blocker_host || (state.network && state.network.local_ip) || '';
  if (dnsOn && dnsHost) {
    return tip(`Whole-Wi‑Fi DNS blocker is on. Point your router DNS to ${esc(dnsHost)}. This PC must stay awake.`);
  }
  const applied = state.settings.hosts_applied === '1';
  const count = Number(state.settings.hosts_applied_count || 0);
  const at = state.settings.hosts_applied_at ? when(state.settings.hosts_applied_at) : '';
  if (applied) {
    return tip(`Hosts file applied on this PC only (${count.toLocaleString()} domains${at ? ', ' + esc(at) : ''}). For phones and TVs, start the network blocker.`);
  }
  if (isDesktopApp()) {
    return tip('Start the network blocker so every device on Wi‑Fi is filtered. Apply on this PC is only a fallback for this computer.');
  }
  return tip('Open the PNet desktop app to start the whole-network DNS blocker (AdGuard Home).');
}

async function reportDnsStatus(status) {
  await post({
    action: 'dns_blocker_report',
    running: status.running ? 1 : 0,
    lan_ip: status.lan_ip || '',
    synced: status.synced ? 1 : 0,
  });
}

async function startNetworkDns() {
  if (!isDesktopApp() || typeof window.pnet.dnsStart !== 'function') {
    toast('Open PNet from the desktop app to start whole-Wi‑Fi blocking.', 'bad');
    return;
  }
  saving = true;
  document.body.classList.add('busy');
  toast('Starting network blocker… Approve the admin prompt. First run downloads AdGuard Home.');
  try {
    const status = await window.pnet.dnsStart();
    const data = await post({
      action: 'dns_blocker_report',
      running: status.running ? 1 : 0,
      lan_ip: status.lan_ip || '',
      synced: status.synced ? 1 : 0,
    });
    if (data.state) state = data.state;
    render();
    if (!status.running) {
      toast('Could not start the DNS blocker. Port 53 may already be in use.', 'bad');
      return;
    }
    toast(data.message || `Network blocker on. Set router DNS to ${status.lan_ip || 'this PC'}.`);
  } catch (err) {
    toast(err.message || 'Could not start network blocker.', 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

async function stopNetworkDns() {
  if (!isDesktopApp() || typeof window.pnet.dnsStop !== 'function') {
    toast('Open the PNet desktop app to stop the network blocker.', 'bad');
    return;
  }
  saving = true;
  document.body.classList.add('busy');
  try {
    const status = await window.pnet.dnsStop();
    const data = await post({
      action: 'dns_blocker_report',
      running: 0,
      lan_ip: status.lan_ip || state.settings.dns_blocker_host || '',
      synced: 0,
    });
    if (data.state) state = data.state;
    render();
    toast(data.message || 'Network blocker stopped.');
  } catch (err) {
    toast(err.message || 'Could not stop network blocker.', 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

async function syncNetworkDns() {
  if (!isDesktopApp() || typeof window.pnet.dnsSync !== 'function') {
    toast('Open the PNet desktop app to sync filters.', 'bad');
    return;
  }
  saving = true;
  document.body.classList.add('busy');
  toast('Syncing block list into AdGuard Home…');
  try {
    const status = await window.pnet.dnsSync();
    const data = await post({
      action: 'dns_blocker_report',
      running: 1,
      lan_ip: status.lan_ip || state.settings.dns_blocker_host || '',
      synced: 1,
    });
    if (data.state) state = data.state;
    render();
    toast('Block list synced to the network blocker.');
  } catch (err) {
    toast(err.message || 'Sync failed.', 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

async function pushWifiDns() {
  if (!isDesktopApp() || typeof window.pnet.dnsPushWifi !== 'function') {
    toast('Open the PNet desktop app to push DNS to Wi‑Fi.', 'bad');
    return;
  }
  saving = true;
  document.body.classList.add('busy');
  toast('Pushing PNet DNS onto this PC’s Wi‑Fi…');
  try {
    const status = await window.pnet.dnsPushWifi();
    const dns = (status.wifi_dns || []).join(', ') || '127.0.0.1';
    toast(`Wi‑Fi DNS on this PC set to ${dns}. Phones still need router DNS.`);
    render();
  } catch (err) {
    toast(err.message || 'Could not push Wi‑Fi DNS.', 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

async function pullWifiDns() {
  if (hasDesktopDns()) {
    try {
      const status = await window.pnet.dnsPullWifi();
      const adapter = status.wifi_adapter || 'Wi‑Fi';
      const dns = (status.wifi_dns && status.wifi_dns.length) ? status.wifi_dns.join(', ') : 'automatic (DHCP)';
      toast(`${adapter}: ${dns}${status.wifi_pushed ? ' (PNet)' : ''}`);
    } catch (err) {
      toast(err.message || 'Could not read Wi‑Fi DNS.', 'bad');
    }
    return;
  }
  // Fallback for browser / older desktop builds: read via PHP.
  try {
    const data = await post({ action: 'wifi_dns_info' });
    toast(data.message || 'Wi‑Fi DNS read.');
  } catch (err) {
    toast(err.message || 'Could not read Wi‑Fi DNS.', 'bad');
  }
}

async function pushDnsToRouter() {
  try {
    await run({ action: 'use_pnet_dns' });
    await openRouterAdmin();
    const ip = state.settings.dns_blocker_host || (state.network && state.network.local_ip) || '';
    if (ip && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(ip).catch(() => {});
    }
    toast(ip ? `Router opened. Set DNS to ${ip} (copied).` : 'Router opened. Set LAN DNS to this PC.');
  } catch (err) {
    toast(err.message || 'Could not open router.', 'bad');
  }
}

async function applyHostsOnPc() {
  if (!isDesktopApp() || typeof window.pnet.applyBlocklist !== 'function') {
    toast('Open PNet from the desktop app to block sites on this PC.', 'bad');
    return;
  }
  const custom = state.counts.sites_on || 0;
  const ads = state.settings.ad_block_enabled === '1' ? (state.counts.ads_on || 0) : 0;
  if (custom + ads < 1) {
    if (state.settings.adult_block_enabled === '1') {
      toast('Adult sites are blocked by the network blocker. Start it, then set router DNS to this PC.', 'bad');
    } else {
      toast('Nothing to apply — block a site or turn on the ad blocker first.', 'bad');
    }
    return;
  }
  if (ads > 50000 && !window.confirm(`Applying ${ads.toLocaleString()} AdGuard domains to the Windows hosts file may slow this PC. Prefer Start network blocker for whole Wi‑Fi. Continue anyway?`)) {
    return;
  }
  saving = true;
  document.body.classList.add('busy');
  toast('Applying… Approve the Windows admin prompt if asked.');
  try {
    const result = await window.pnet.applyBlocklist();
    const data = await post({ action: 'mark_hosts_applied', count: result.count || custom + ads });
    if (data.state) state = data.state;
    render();
    toast(data.message || 'Block list applied on this PC.');
  } catch (err) {
    toast(err.message || 'Could not apply block list.', 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

function routerBrandCard() {
  const r = state.router || {};
  const access = r.access || {};
  const net = state.network || {};
  const brand = r.router_brand || 'generic';
  const name = r.router_brand_name || 'Router';
  const model = r.router_model || '';
  const gateway = net.gateway || r.lan_ip || '—';
  const admin = routerAdminUrl();
  const connected = routerIsConnected();
  const subtitle = model && !model.toLowerCase().includes((name || '').toLowerCase()) ? model : (gateway !== '—' ? gateway : 'Scan to detect');
  const wifiOn = wifiIsConnected();
  const status = connected
    ? `<span class="router-status ok">Router login saved${access.title ? ' · ' + esc(access.title) : ''}</span>`
    : routerNeedsLoginFix()
      ? `<span class="router-status off">Login failed — fix password below</span>`
    : wifiOn
      ? `<span class="router-status off">On Wi‑Fi — still need router login</span>`
      : `<span class="router-status off">Not connected</span>`;
  return `<div class="router-brand-card">
    <img class="router-brand-logo" src="assets/brands/${esc(brand)}.svg" alt="${esc(name)}" width="72" height="72" loading="lazy">
    <div class="router-brand-copy">
      <div class="router-brand-label">Your router</div>
      <strong class="router-brand-name">${esc(name)}</strong>
      <div class="router-brand-meta mono">${esc(subtitle)}</div>
      ${status}
      <div class="row-actions">
        ${admin ? `<button type="button" class="btn small" data-act="open-router">Open router</button>` : ''}
        ${connected ? '' : `<button type="button" class="btn small" data-act="router-connect-form">Connect to router</button>`}
      </div>
    </div>
  </div>`;
}

function routerConnectPanel() {
  const r = state.router || {};
  const access = r.access || {};
  const admin = routerAdminUrl() || 'http://192.168.1.1';
  const connected = routerIsConnected();
  const needsFix = routerNeedsLoginFix();
  const wifiOn = wifiIsConnected();
  const isZte = isZteRouter();
  const brandLabel = routerBrandLabel();
  if (connected) {
    return `<section class="panel stack router-connect">
      <h2>Router access</h2>
      <p class="lead">Connected to ${esc(brandLabel)}${access.username ? ' as ' + esc(access.username) : ''}.</p>
      ${tip('Full access is on. PNet can pull DHCP clients, Wi‑Fi stations, and traffic from your TP-Link.')}
      <div class="row-actions">
        <button type="button" class="btn" data-act="router-sync-devices">Pull everything from router</button>
        ${admin ? '<button type="button" class="btn ghost" data-act="open-router">Open router</button>' : ''}
        <button type="button" class="btn ghost" data-act="router-probe">Test</button>
      </div>
      <details class="advanced">
        <summary>Update login</summary>
        <div class="advanced-body">
          <form class="stack" data-action="router_connect">
            <label class="field">Router address<input name="router_admin_url" required maxlength="500" value="${esc(admin)}" placeholder="http://192.168.0.1"></label>
            <label class="field">Username<input name="router_admin_user" maxlength="64" value="${esc(access.username || '')}" placeholder="admin" autocomplete="username"></label>
            <label class="field">Password<input type="password" name="router_admin_password" maxlength="200" placeholder="Saved — leave blank to keep" autocomplete="current-password"></label>
            <div class="row-actions">
              <button class="btn" type="submit">Update login</button>
              ${access.upnp_available ? '<button type="button" class="btn ghost" data-act="router-sync-upnp">Sync port forwards</button>' : ''}
            </div>
          </form>
        </div>
      </details>
    </section>`;
  }
  return `<section class="panel stack router-connect">
    <h2>${needsFix ? 'Fix router login' : `Connect to ${esc(brandLabel === 'your router' ? 'router' : brandLabel)}`}</h2>
    ${needsFix
      ? tip('Router page is reachable, but admin login failed. Re-enter the <strong>router admin</strong> password (not the Wi‑Fi password), then Connect again.')
      : (wifiOn
        ? tip(`You are already on Wi‑Fi. That only joins the network. Enter the <strong>${esc(brandLabel)} admin</strong> username and password (not the Wi‑Fi password) for full access.`)
        : tip('Join home Wi‑Fi first, then enter the router admin login below.'))}
    <form class="stack" data-action="router_connect">
      <label class="field">Router address<input name="router_admin_url" required maxlength="500" value="${esc(admin)}" placeholder="http://192.168.0.1"></label>
      <label class="field">Username<input name="router_admin_user" maxlength="64" value="${esc(access.username || '')}" placeholder="${isZte ? 'admin or user' : 'admin'}" autocomplete="username"></label>
      <label class="field">Password<input type="password" name="router_admin_password" maxlength="200" placeholder="${needsFix ? 'Re-enter admin password' : (isZte ? 'Modem admin password (sticker / ISP)' : 'Router admin password')}" autocomplete="current-password" ${needsFix ? 'required' : 'required'}></label>
      <div class="row-actions">
        <button class="btn" type="submit">${needsFix ? 'Retry login' : 'Connect to router'}</button>
        <button type="button" class="btn ghost" data-act="router-probe">Test reachability</button>
        ${admin ? '<button type="button" class="btn ghost" data-act="open-router">Open router page</button>' : ''}
      </div>
    </form>
    <p class="fine">${isZte
      ? 'ZTE modem pages are often at <span class="mono">http://192.168.1.1</span>. Wrong password can lock the page for about a minute.'
      : `Your Wi‑Fi gateway is usually <span class="mono">${esc(admin || 'http://192.168.0.1')}</span>. Use the admin password, not the Wi‑Fi password.`}</p>
  </section>`;
}

function openRouterConnectForm() {
  if (routerIsConnected()) {
    toast('Already connected to your router.');
    location.hash = '#wifi';
    routerTab = 'home';
    render();
    return;
  }
  location.hash = '#wifi';
  routerTab = 'home';
  render();
  const panel = document.querySelector('.router-connect');
  if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  toast(wifiIsConnected() ? `Enter ${routerBrandLabel()} admin login below.` : 'Join Wi‑Fi first, then enter router login.');
}

async function fetchRouterLogin() {
  try {
    const res = await fetch('api.php?action=router_login', { cache: 'no-store' });
    const data = await res.json().catch(() => null);
    if (!data || !data.ok || !data.login) return null;
    return data.login;
  } catch (_) {
    return null;
  }
}

async function saveCapturedRouterLogin(creds) {
  if (!creds || !creds.password) return;
  let url = '';
  try {
    url = creds.url ? new URL(creds.url).origin : '';
  } catch (_) {
    url = '';
  }
  if (!url) url = routerAdminUrl();
  try {
    await post({
      action: 'router_save_login',
      router_admin_url: url,
      router_admin_user: creds.username || '',
      router_admin_password: creds.password
    });
    toast('Router login saved.');
    render();
  } catch (err) {
    toast(err.message || 'Could not save router login.', 'bad');
  }
}

function bindRouterLoginCapture() {
  if (!window.pnet || typeof window.pnet.onRouterLoginSaved !== 'function') return;
  if (window.__pnetRouterLoginBound) return;
  window.__pnetRouterLoginBound = true;
  window.pnet.onRouterLoginSaved((creds) => {
    saveCapturedRouterLogin(creds);
  });
}

async function openRouterAdmin() {
  const url = routerAdminUrl();
  if (!url) {
    toast('Router address unknown. Run Find devices or Connect first.', 'bad');
    return;
  }
  if (window.pnet && typeof window.pnet.openRouterAdmin === 'function') {
    try {
      const login = await fetchRouterLogin();
      await window.pnet.openRouterAdmin(url, login && login.password ? {
        username: login.username || '',
        password: login.password
      } : null);
      toast(login && login.password ? 'Router opened — login filled if the page supports it.' : 'Router opened in PNet. Sign in once and PNet will save it.');
      return;
    } catch (err) {
      toast(err.message || 'Could not open router window.', 'bad');
      return;
    }
  }
  window.open(url, '_blank', 'noopener');
  toast('Router opened in your browser.');
}

function calculateSecurityScore() {
  if (!state) return { score: 0, level: 'low', message: 'Loading...' };
  
  let score = 100;
  const issues = [];
  
  const openAlerts = state.alerts.filter(a => a.status === 'open');
  const criticalAlerts = openAlerts.filter(a => a.severity === 'critical');
  const highAlerts = openAlerts.filter(a => a.severity === 'high');
  
  score -= criticalAlerts.length * 25;
  score -= highAlerts.length * 15;
  score -= (openAlerts.length - criticalAlerts.length - highAlerts.length) * 5;
  
  const quarantinedDevices = state.devices.filter(d => d.access_profile === 'quarantined').length;
  score -= quarantinedDevices * 10;
  
  const blockedDevices = state.devices.filter(d => d.trust === 'blocked').length;
  score -= blockedDevices * 5;
  
  const allowAllRules = state.rules.filter(r => r.enabled && r.action === 'allow' && r.source === 'any' && r.destination === 'any').length;
  score -= allowAllRules * 20;
  
  const onlineDevices = state.devices.filter(d => d.status === 'online').length;
  if (onlineDevices > 0 && state.settings.ad_block_enabled !== '1' && (state.counts.sites_on || 0) === 0) {
    score -= 10;
  }
  
  score = Math.max(0, Math.min(100, score));
  
  let level = 'low';
  let message = 'Multiple security issues detected';
  
  if (score >= 80) {
    level = 'high';
    message = 'Your network is well protected';
  } else if (score >= 50) {
    level = 'medium';
    message = 'Some security improvements recommended';
  }
  
  if (criticalAlerts.length > 0) {
    message = `${criticalAlerts.length} critical alert${criticalAlerts.length > 1 ? 's' : ''} require attention`;
  }
  
  return { score, level, message };
}

function when(value) {
  if (!value) return '—';
  const date = new Date(String(value).replace(' ', 'T') + 'Z');
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}

function formatBps(bps) {
  const n = Number(bps) || 0;
  if (n <= 0) return '0 bps';
  if (n < 1000) return `${Math.round(n)} bps`;
  if (n < 1000000) return `${(n / 1000).toFixed(n < 10000 ? 1 : 0)} Kbps`;
  if (n < 1000000000) return `${(n / 1000000).toFixed(n < 10000000 ? 2 : 1)} Mbps`;
  return `${(n / 1000000000).toFixed(2)} Gbps`;
}

function trafficForDevice(deviceId) {
  if (!trafficLive || !Array.isArray(trafficLive.devices)) return null;
  return trafficLive.devices.find((row) => Number(row.id) === Number(deviceId)) || null;
}

function trafficCell(deviceId) {
  const row = trafficForDevice(deviceId);
  if (!row) return '<span class="muted">…</span>';
  if (row.down_bps == null && row.up_bps == null) {
    return `<span class="muted" title="${esc(row.note || 'Not available on this PC')}">—</span>`;
  }
  const down = formatBps(row.down_bps || 0);
  const up = formatBps(row.up_bps || 0);
  const active = (row.down_bps || 0) + (row.up_bps || 0) > 0;
  return `<div class="traffic-cell${active ? ' active' : ''}">
    <span class="traffic-down" title="Download">↓ ${esc(down)}</span>
    <span class="traffic-up" title="Upload">↑ ${esc(up)}</span>
  </div>`;
}

function badge(text, kind) {
  const known = ['online', 'offline', 'unknown', 'allow', 'block', 'open', 'acknowledged', 'resolved', 'info', 'low', 'medium', 'high', 'critical', 'on', 'off', 'trusted', 'guest', 'blocked', 'normal', 'limited', 'quarantined'];
  const safe = known.indexOf(kind) !== -1 ? kind : 'unknown';
  return `<span class="badge ${safe}">${esc(text)}</span>`;
}

function currentView() {
  const name = location.hash.replace(/^#/, '');
  return Object.prototype.hasOwnProperty.call(PAGES, name) ? name : 'overview';
}

function toast(message, kind) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind === 'bad' ? ' bad' : '');
  el.textContent = message;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

async function post(body) {
  let res;
  try {
    res = await fetch('api.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      body: JSON.stringify(Object.assign({ csrf: boot.csrf }, body))
    });
  } catch (_) {
    throw new Error('Could not reach PNet. Check that Apache/XAMPP is running.');
  }
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (_) {
    if (res.status === 500 || /Maximum execution time|Fatal error/i.test(text)) {
      throw new Error('Scan took too long. Try Find devices again — it should be faster now.');
    }
    throw new Error('PNet returned an unreadable response.');
  }
  if (!data.ok) throw new Error(data.error || 'Request failed.');
  if (data.state) state = data.state;
  return data;
}

async function run(body) {
  if (saving) return false;
  saving = true;
  document.body.classList.add('busy');
  try {
    const data = await post(body);
    closeDrawer();
    render();
    toast(data.message || 'Saved.');
    return true;
  } catch (err) {
    toast(err.message, 'bad');
    return false;
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

function findRow(list, id) {
  return list.find((row) => String(row.id) === String(id)) || null;
}

function lead(text) {
  return `<p class="lead">${esc(text)}</p>`;
}

function empty(text) {
  return `<div class="empty">${esc(text)}</div>`;
}

function searchAttr(parts) {
  return esc(parts.filter(Boolean).join(' ').toLowerCase());
}

function table(headers, body) {
  if (!body) return empty('Nothing here yet.');
  const head = headers.map((item) => `<th>${item}</th>`).join('');
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div><p id="no-hits" class="lead" hidden>No matches.</p>`;
}

function sampleBanner() {
  if (state.settings.sample_loaded !== '1') return '';
  return `<div class="banner"><p>Sample records are loaded so you can look around. Remove them when you add your real network. Records you have edited are kept.</p><button type="button" class="btn small" data-act="clear-sample">Remove sample records</button></div>`;
}

function pageActions(view) {
  const search = '<input id="q" type="search" placeholder="Filter" aria-label="Filter">';
  const block = '<a class="btn ghost" href="api.php?action=export_hosts">Download block list</a>';
  const policy = '<a class="btn ghost" href="api.php?action=export_policy">Download policy</a>';
  if (view === 'overview') return block + policy;
  if (view === 'wifi') return '<button type="button" class="btn" data-act="discover">Find devices</button><button type="button" class="btn ghost" data-act="reload">Refresh</button>';
  if (view === 'network') {
    const liveBtn = `<button type="button" class="btn ghost${liveTrafficEnabled ? ' active-live' : ''}" data-act="toggle-live-traffic">${liveTrafficEnabled ? 'Live on' : 'Live usage'}</button>`;
    return search + liveBtn + '<button type="button" class="btn ghost" data-act="discover">Find devices</button><button type="button" class="btn ghost" data-act="check-all">Check online</button><button type="button" class="btn" data-act="add-device">Add device</button>';
  }
  if (view === 'traffic') {
    return search + '<button type="button" class="btn ghost" data-act="reload-traffic">Refresh</button><a class="btn ghost" href="#network">All devices</a>';
  }
  if (view === 'firewall') return search + '<button type="button" class="btn" data-act="add-rule">Add rule</button>';
  if (view === 'sites') return search + '<a class="btn ghost" href="api.php?action=export_hosts">Download list</a><button type="button" class="btn" data-act="add-site">Block a site</button>';
  if (view === 'ips') return search + '<button type="button" class="btn" data-act="add-ip">Add address</button>';
  if (view === 'defender') return search + '<button type="button" class="btn ghost" data-act="scan">Run check</button><button type="button" class="btn" data-act="add-alert">Log event</button>';
  if (view === 'cameras') return search + '<button type="button" class="btn ghost" data-act="refresh-snaps">Refresh photos</button><button type="button" class="btn" data-act="add-camera">Add camera</button>';
  return '';
}

function wifiIconSvg(bars) {
  const level = Math.max(0, Math.min(3, Number(bars) || 3));
  const a1 = level >= 1 ? '0.95' : '0.25';
  const a2 = level >= 2 ? '0.95' : '0.25';
  const a3 = level >= 3 ? '0.95' : '0.25';
  return `<svg class="wifi-icon-svg" viewBox="0 0 24 24" width="28" height="28" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 19.5a1.2 1.2 0 1 0 0-2.4 1.2 1.2 0 0 0 0 2.4z" fill="currentColor" stroke="none" opacity="${a1}"/>
    <path d="M8.5 15.5a5 5 0 0 1 7 0" opacity="${a2}"/>
    <path d="M5 12.5a9 9 0 0 1 14 0" opacity="${a3}"/>
  </svg>`;
}

function wifiSignalBars(signal) {
  const text = String(signal || '').trim();
  const pct = parseInt(text.replace('%', ''), 10);
  if (!Number.isNaN(pct)) {
    if (pct >= 70) return 3;
    if (pct >= 40) return 2;
    if (pct > 0) return 1;
  }
  const lower = text.toLowerCase();
  if (/excellent|very strong|full/.test(lower)) return 3;
  if (/good|strong|medium/.test(lower)) return 2;
  if (/weak|poor|low|fair/.test(lower)) return 1;
  return text ? 3 : 0;
}

function overviewWifiCard() {
  const wifi = state.wifi || {};
  const r = state.router || {};
  const brand = r.router_brand || '';
  const brandName = r.router_brand_name || '';
  const connected = !!(wifi.available || wifi.ssid || routerIsConnected());
  const ssid = wifi.ssid || r.wifi_ssid || (connected ? 'Connected' : 'Not connected');
  const signal = wifi.signal || '';
  const bars = wifiSignalBars(signal);
  const brandLogo = brand && brand !== 'generic'
    ? `<img class="wifi-brand-logo" src="assets/brands/${esc(brand)}.svg" alt="${esc(brandName || 'Router')}" width="40" height="40" loading="lazy">`
    : '';
  return `<a class="wifi-status-card${connected ? ' connected' : ''}" href="#wifi">
    <div class="wifi-status-icon">${brandLogo || wifiIconSvg(connected ? (bars || 3) : 0)}</div>
    <div class="wifi-status-copy">
      <div class="wifi-status-label">${connected ? 'Connected to Wi‑Fi' : 'Wi‑Fi'}</div>
      <strong class="wifi-status-name">${esc(ssid)}</strong>
      <div class="wifi-status-meta">${connected
        ? esc([signal ? `Signal ${signal}` : '', brandName, wifi.radio_type || ''].filter(Boolean).join(' · ') || 'Home network')
        : 'Not connected right now'}</div>
    </div>
    ${connected ? `<span class="wifi-status-pill">Online</span>` : `<span class="wifi-status-pill off">Offline</span>`}
  </a>`;
}

function pageOverview() {
  const c = state.counts;
  const wifi = state.wifi || {};
  const wifiConnected = !!(wifi.available || wifi.ssid);
  const stats = [
    ['#wifi', wifiConnected ? wifiIconSvg(wifiSignalBars(wifi.signal) || 3) + `<span class="stat-wifi-text">${esc(wifi.signal || 'On')}</span>` : '—', 'Current Wi-Fi', wifi.ssid || wifi.message || 'Not connected'],
    ['#network', c.devices_online, 'Devices online', c.devices + ' saved'],
    ['#firewall', c.rules_on, 'Firewall rules on', c.rules + ' saved'],
    ['#sites', (c.sites_on || 0) + (state.settings.ad_block_enabled === '1' ? (c.ads_on || 0) : 0) + (state.settings.adult_block_enabled === '1' ? (c.adult_on || 0) : 0), 'Sites blocked', [state.settings.ad_block_enabled === '1' ? 'AdGuard on' : '', state.settings.adult_block_enabled === '1' ? 'Adult sites on' : '', c.sites + ' custom'].filter(Boolean).join(' · ')],
    ['#ips', c.ips_blocked, 'Blocked addresses', c.ips + ' in the book'],
    ['#defender', c.alerts_open, 'Open defender items', 'Home Defender'],
    ['#cameras', c.cameras_online, 'Cameras online', c.cameras + ' saved']
  ].map(([href, num, title, sub]) => {
    const value = typeof num === 'string' && num.includes('<svg')
      ? `<b class="stat-wifi-value">${num}</b>`
      : `<b>${esc(num)}</b>`;
    return `<a class="stat" href="${esc(href)}">${value}<span>${esc(title)}</span><small>${esc(sub)}</small></a>`;
  }).join('');
  
  const securityScore = calculateSecurityScore();
  const scoreWidget = `<div class="security-score">
    <div class="score-circle ${securityScore.level}">${securityScore.score}</div>
    <div class="score-details">
      <h3>Security Score</h3>
      <p>${securityScore.message}</p>
    </div>
  </div>`;
  
  const open = state.alerts.filter((row) => row.status === 'open').slice(0, 5);
  const alerts = open.length ? `<ul class="feed">${open.map((row) => `<li>${badge(row.severity, row.severity)} <strong>${esc(row.title)}</strong><time>${esc(when(row.created_at))}</time></li>`).join('')}</ul>` : empty('No open defender items.');
  const feed = state.activity.length ? `<ul class="feed">${state.activity.map((row) => `<li><time>${esc(when(row.created_at))}</time>${esc(row.detail)}</li>`).join('')}</ul>` : empty('No activity yet.');
  const recentDevices = state.devices.filter((d) => d.status === 'online').slice(0, 8);
  const deviceStrip = recentDevices.length
    ? `<section class="panel stack"><h2>Online now</h2><div class="device-strip">${recentDevices.map((row) => {
        return `<a class="device-chip" href="#network">${deviceIconHtml(row)}<span><strong>${esc(row.name)}</strong><small class="mono">${esc(row.ip)}</small></span></a>`;
      }).join('')}</div></section>`
    : '';
  return `
    ${sampleBanner()}
    ${overviewWifiCard()}
    ${scoreWidget}
    <div class="easy-grid">
      <button type="button" class="easy-card" data-act="discover">
        <strong>1. Find devices</strong>
        <span>Scan your Wi‑Fi and list phones, PCs, and the router.</span>
      </button>
      ${routerIsConnected()
        ? `<a class="easy-card easy-card-wifi" href="#wifi">
        <span class="easy-card-icon">${wifiIconSvg(wifiSignalBars(wifi.signal) || 3)}</span>
        <strong>2. Router linked</strong>
        <span>${esc(wifi.ssid || routerBrandLabel())}. Full admin access saved.</span>
      </a>`
        : wifiConnected
          ? `<a class="easy-card easy-card-wifi" href="#wifi">
        <span class="easy-card-icon">${wifiIconSvg(wifiSignalBars(wifi.signal) || 3)}</span>
        <strong>2. On Wi‑Fi — connect router</strong>
        <span>Next: enter ${esc(routerBrandLabel())} admin login at ${esc(routerAdminUrl() || 'http://192.168.0.1')}.</span>
      </a>`
          : `<a class="easy-card" href="#wifi">
        <strong>2. Set up Wi‑Fi</strong>
        <span>Join home Wi‑Fi, then connect to your router for full access.</span>
      </a>`}
      <a class="easy-card" href="#sites">
        <strong>3. Block ads & adult sites</strong>
        <span>Turn on AdGuard and the adult list, start the network blocker, set router DNS to this PC.</span>
      </a>
    </div>
    <div class="stats">${stats}</div>
    ${deviceStrip}
    <div class="split">
      <section class="panel"><h2>Needs attention</h2>${alerts}</section>
      <section class="panel"><h2>Recent activity</h2>${feed}</section>
    </div>`;
}

function tip(html) {
  return `<div class="tip">${html}</div>`;
}

function formGrid(html) {
  return `<div class="form-grid">${html}</div>`;
}

function advancedBox(html) {
  return `<details class="advanced"><summary>More options</summary><div class="advanced-body">${html}</div></details>`;
}

function detailGrid(items) {
  return `<div class="detail-grid">${items.map(([labelText, value]) => `<div><span>${esc(labelText)}</span><strong>${esc(value || '—')}</strong></div>`).join('')}</div>`;
}

function sortedDevices() {
  return [...state.devices].sort((a, b) => {
    if (a.type === 'router' && b.type !== 'router') return -1;
    if (b.type === 'router' && a.type !== 'router') return 1;
    return String(a.ip).localeCompare(String(b.ip), undefined, { numeric: true });
  });
}

function routerTabs() {
  return `<nav class="router-tabs">${ROUTER_TABS.map(([id, labelText]) =>
    `<button type="button" class="router-tab${routerTab === id ? ' active' : ''}" data-act="router-tab" data-tab="${id}">${esc(labelText)}</button>`
  ).join('')}</nav>`;
}

function fieldSelect(name, options, value) {
  return `<select name="${esc(name)}">${options.map(([v, l]) => `<option value="${esc(v)}"${String(value) === String(v) ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
}

function checkField(name, labelText, checked) {
  return `<label class="check"><input type="checkbox" name="${esc(name)}" value="1"${checked ? ' checked' : ''}> ${esc(labelText)}</label>`;
}

function wifiDeviceTable(full) {
  const devices = sortedDevices();
  if (!devices.length) {
    return empty('Nothing found yet. Tap Find devices.');
  }
  const rows = devices.map((row) => {
    const isRouter = isGatewayDevice(row);
    const ping = row.ping_ms ? `${row.ping_ms}ms` : '—';
    const cap = speedLabel(row.bandwidth_limit || 0);
    const actions = full ? `<td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="check" data-kind="device" data-id="${row.id}">Ping</button>
      <button type="button" class="btn small ghost" data-act="edit-device" data-id="${row.id}">Edit</button>
      ${row.access_profile === 'quarantined'
        ? `<button type="button" class="btn small ghost" data-act="resume-device" data-id="${row.id}">Allow</button>`
        : `<button type="button" class="btn small danger" data-act="quarantine-device" data-id="${row.id}">Block</button>`}
    </div></td>` : '';
    return `<tr data-search="${searchAttr([row.name, row.ip, row.mac, row.vendor, label('type', row.type), row.status])}">
      <td>
        <div class="device-row">
          ${deviceIconHtml(row)}
          <div class="device-info">
            <div class="device-name">${esc(row.name)}${isRouter ? ' <span class="badge on">Router</span>' : ''}</div>
            <div class="device-meta">${esc(deviceMeta(row))}</div>
          </div>
        </div>
      </td>
      <td class="mono">${esc(row.ip)}</td>
      <td class="mono">${esc(row.mac || '—')}</td>
      <td>${badge(label('status', row.status), row.status)}</td>
      <td>${badge(label('access', row.access_profile || 'normal'), row.access_profile || 'normal')}<div class="muted">${esc(cap)}</div></td>
      <td>${esc(ping)}</td>
      ${actions}
    </tr>`;
  }).join('');
  return table(full
    ? ['Device', 'IP', 'MAC', 'Status', 'Access', 'Ping', '']
    : ['Device', 'IP', 'MAC', 'Status', 'Access', 'Ping'], rows);
}

function tabHome() {
  const wifi = state.wifi || {};
  const net = state.network || {};
  const r = state.router || {};
  const online = state.counts.devices_online || 0;
  const total = state.counts.devices || 0;
  return `
    ${routerBrandCard()}
    <section class="panel stack">
      <h2>Your network at a glance</h2>
      ${tip('Start here. Use the big buttons for everyday tasks. Open More only if you need advanced router options.')}
      ${detailGrid([
        ['Wi‑Fi name', wifi.ssid || r.wifi_ssid || 'Not detected'],
        ['Signal', wifi.signal || '—'],
        ['Your computer IP', net.local_ip || '—'],
        ['Router IP', net.gateway || '—'],
        ['Devices online', online + ' of ' + total],
        ['Sites blocked', String(state.counts.sites_on || 0)],
      ])}
      <div class="row-actions">
        <button type="button" class="btn" data-act="open-router">Open router</button>
        <button type="button" class="btn ghost" data-act="discover">Find devices</button>
        <button type="button" class="btn ghost" data-act="router-tab" data-tab="devices">See devices</button>
      </div>
    </section>
    ${routerConnectPanel()}
    <div class="easy-grid">
      <button type="button" class="easy-card" data-act="router-tab" data-tab="wifi">
        <strong>Change Wi‑Fi name</strong>
        <span>Rename the network people connect to at home.</span>
      </button>
      <button type="button" class="easy-card" data-act="router-tab" data-tab="wifi">
        <strong>Guest Wi‑Fi</strong>
        <span>Give visitors internet without sharing your main network.</span>
      </button>
      <button type="button" class="easy-card" data-act="router-tab" data-tab="security">
        <strong>Block sites</strong>
        <span>Stop ads and adult sites from opening on your home Wi‑Fi.</span>
      </button>
      <button type="button" class="easy-card" data-act="router-tab" data-tab="internet">
        <strong>Internet & DNS</strong>
        <span>Pick automatic internet and safer/faster DNS in one place.</span>
      </button>
    </div>`;
}

function tabDevices() {
  return `<section class="panel stack">
    <h2>Devices on your Wi‑Fi</h2>
    ${tip('These are phones, computers, TVs, and your router. Tap Find devices if the list is empty.')}
    <div class="row-actions">
      <button type="button" class="btn" data-act="discover">Find devices</button>
      <button type="button" class="btn ghost" data-act="check-all">Check who is online</button>
      <button type="button" class="btn ghost" data-act="add-device">Add manually</button>
    </div>
    ${wifiDeviceTable(true)}
  </section>`;
}

function tabWifiEasy() {
  const r = state.router || {};
  const wifi = state.wifi || {};
  return `
    <form class="panel stack" data-action="save_router_settings">
      <h2>Wi‑Fi name & security</h2>
      ${tip('Use <strong>Open router</strong> on the Home tab for real changes on your router. Fields here are your saved plan in PNet.')}
      ${tip('Change the name people see when they join your Wi‑Fi. Keep WPA2 or WPA3 for safety.')}
      <input type="hidden" name="section" value="wireless">
      ${formGrid(`
        <label class="field">Wi‑Fi name (2.4 GHz)<input name="wifi_ssid" maxlength="120" value="${esc(r.wifi_ssid || wifi.ssid || '')}" placeholder="HomeWiFi"></label>
        <label class="field">Wi‑Fi name (5 GHz)<input name="wifi_ssid_5g" maxlength="120" value="${esc(r.wifi_ssid_5g)}" placeholder="HomeWiFi-5G"></label>
        <label class="field">Security${fieldSelect('wifi_security', WIFI_SECURITY, r.wifi_security || 'wpa2')}</label>
        <label class="field">Bands to use${fieldSelect('wifi_band', WIFI_BAND, r.wifi_band || 'both')}</label>
      `)}
      ${advancedBox(formGrid(`
        <label class="field">2.4 GHz channel${fieldSelect('wifi_channel', CHANNEL_24, r.wifi_channel || 'auto')}</label>
        <label class="field">5 GHz channel${fieldSelect('wifi_channel_5g', CHANNEL_5, r.wifi_channel_5g || 'auto')}</label>
        <div>${checkField('wifi_hidden', 'Hide network name', r.wifi_hidden === '1')}</div>
        <div>${checkField('wifi_wps', 'Allow WPS button pairing', r.wifi_wps === '1')}</div>
        <div>${checkField('wifi_isolation', 'Keep devices from seeing each other', r.wifi_isolation === '1')}</div>
      `))}
      <button class="btn" type="submit">Save Wi‑Fi</button>
    </form>
    <form class="panel stack" data-action="save_router_settings">
      <h2>Guest Wi‑Fi</h2>
      ${tip('Optional second network for visitors. Leave off if you do not need it.')}
      <input type="hidden" name="section" value="guest">
      ${checkField('guest_enabled', 'Turn on guest Wi‑Fi', r.guest_enabled === '1')}
      ${formGrid(`
        <label class="field">Guest network name<input name="guest_ssid" maxlength="120" value="${esc(r.guest_ssid || 'Guest')}"></label>
        <label class="field">Guest security${fieldSelect('guest_security', [['wpa2', 'WPA2 (recommended)'], ['wpa3', 'WPA3'], ['open', 'Open']], r.guest_security || 'wpa2')}</label>
        <label class="field">Speed limit (Kbps, 0 = no limit)<input type="number" name="guest_bandwidth" min="0" max="100000" value="${esc(r.guest_bandwidth || '0')}"></label>
      `)}
      ${checkField('guest_isolation', 'Guests cannot see home devices', r.guest_isolation !== '0')}
      <button class="btn" type="submit">Save guest Wi‑Fi</button>
    </form>`;
}

function tabInternetEasy() {
  const r = state.router || {};
  const net = state.network || {};
  const rows = (state.dhcp_reservations || []).map((row) => `<tr>
    <td>${esc(row.name)}</td><td class="mono">${esc(row.mac)}</td><td class="mono">${esc(row.ip)}</td>
    <td>${badge(row.enabled ? 'On' : 'Off', row.enabled ? 'on' : 'off')}</td>
    <td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="toggle-dhcp" data-id="${row.id}">On/Off</button>
      <button type="button" class="btn small ghost" data-act="edit-dhcp" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-dhcp" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  return `
    <form class="panel stack" data-action="save_router_settings">
      <h2>Internet connection</h2>
      ${tip('Most homes should leave this on Automatic. Your PC currently sees gateway ' + esc(net.gateway || 'unknown') + '.')}
      <input type="hidden" name="section" value="wan">
      <label class="field">How you connect${fieldSelect('wan_mode', WAN_MODE, r.wan_mode || 'dhcp')}</label>
      ${advancedBox(formGrid(`
        <label class="field">Internet IP<input name="wan_ip" maxlength="45" value="${esc(r.wan_ip)}" placeholder="Only if Manual IP"></label>
        <label class="field">Internet gateway<input name="wan_gateway" maxlength="45" value="${esc(r.wan_gateway)}"></label>
        <label class="field">ISP DNS 1<input name="wan_dns1" maxlength="45" value="${esc(r.wan_dns1 || (net.dns && net.dns[0]) || '')}"></label>
        <label class="field">ISP DNS 2<input name="wan_dns2" maxlength="45" value="${esc(r.wan_dns2 || (net.dns && net.dns[1]) || '')}"></label>
      `))}
      <button class="btn" type="submit">Save internet</button>
    </form>
    <form class="panel stack" data-action="save_router_settings">
      <h2>DNS (website lookup)</h2>
      ${tip(state.settings.dns_blocker_enabled === '1'
        ? `Network blocker is on. Set the router DNS to ${state.settings.dns_blocker_host || (net.local_ip || 'this PC')} so phones and TVs use PNet.`
        : 'DNS turns names like google.com into numbers. For whole-Wi‑Fi blocking, start the network blocker on the Blocking page, then use PNet DNS here.')}
      <input type="hidden" name="section" value="dns">
      <label class="field">DNS choice${fieldSelect('dns_mode', DNS_MODE, r.dns_mode || 'isp')}</label>
      ${advancedBox(formGrid(`
        <label class="field">Custom primary<input name="dns_primary" maxlength="45" value="${esc(r.dns_primary)}" placeholder="1.1.1.1"></label>
        <label class="field">Custom secondary<input name="dns_secondary" maxlength="45" value="${esc(r.dns_secondary)}" placeholder="1.0.0.1"></label>
      `))}
      <div class="row-actions">
        <button class="btn" type="submit">Save DNS</button>
        <button type="button" class="btn ghost" data-act="use-pnet-dns">Use PNet DNS</button>
        <a class="btn ghost" href="#sites">Blocking</a>
      </div>
    </form>
    <form class="panel stack" data-action="save_router_settings">
      <h2>Home address range</h2>
      ${tip('This is the private IP range your router uses inside the house. Leave defaults if you are unsure.')}
      <input type="hidden" name="section" value="lan">
      ${formGrid(`
        <label class="field">Router address<input name="lan_ip" maxlength="45" value="${esc(r.lan_ip || net.gateway || '')}" placeholder="192.168.0.1"></label>
        <label class="field">Subnet mask<input name="lan_mask" maxlength="45" value="${esc(r.lan_mask || net.mask || '255.255.255.0')}"></label>
      `)}
      ${checkField('dhcp_enabled', 'Give devices IPs automatically (DHCP)', r.dhcp_enabled !== '0')}
      ${advancedBox(formGrid(`
        <label class="field">First IP to hand out<input name="dhcp_start" maxlength="45" value="${esc(r.dhcp_start)}" placeholder="192.168.0.100"></label>
        <label class="field">Last IP to hand out<input name="dhcp_end" maxlength="45" value="${esc(r.dhcp_end)}" placeholder="192.168.0.200"></label>
        <label class="field">Keep IP for (hours)<input type="number" name="dhcp_lease" min="0" max="100000" value="${esc(r.dhcp_lease || '24')}"></label>
      `))}
      <button class="btn" type="submit">Save home network</button>
    </form>
    <section class="panel stack">
      <div class="panel-head">
        <h2>Always-same IP for a device</h2>
        <button type="button" class="btn small" data-act="add-dhcp">Add</button>
      </div>
      ${tip('Useful for printers or cameras so their IP never changes.')}
      ${rows ? table(['Name', 'MAC', 'IP', 'On', ''], rows) : empty('None yet. Add one if you need a fixed IP.')}
    </section>`;
}

function tabSecurityEasy() {
  const r = state.router || {};
  const schedules = (state.access_schedules || []).map((row) => `<tr>
    <td>${esc(row.name)}</td><td>${esc(row.target)}</td><td>${esc(row.days)}</td>
    <td class="mono">${esc(row.start_time)}–${esc(row.end_time)}</td>
    <td>${esc(row.action)}</td>
    <td>${badge(row.enabled ? 'On' : 'Off', row.enabled ? 'on' : 'off')}</td>
    <td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="toggle-schedule" data-id="${row.id}">On/Off</button>
      <button type="button" class="btn small ghost" data-act="edit-schedule" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-schedule" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  const macRows = (state.mac_filters || []).map((row) => `<tr>
    <td>${esc(row.name)}</td><td class="mono">${esc(row.mac)}</td><td>${esc(row.mode)}</td>
    <td>${badge(row.enabled ? 'On' : 'Off', row.enabled ? 'on' : 'off')}</td>
    <td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="toggle-mac" data-id="${row.id}">On/Off</button>
      <button type="button" class="btn small ghost" data-act="edit-mac" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-mac" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  const rules = state.rules.filter((row) => row.enabled).slice(0, 5);
  return `
    <section class="panel stack">
      <h2>Ads, adult sites & websites</h2>
      ${tip('Turn on AdGuard, the adult-site list, or add any domain. Then sync the network blocker.')}
      <p class="lead">${state.settings.ad_block_enabled === '1' ? `AdGuard on · ${(state.counts.ads_on || 0).toLocaleString()} domains · ` : ''}${state.settings.adult_block_enabled === '1' ? `Adult sites on · ${(state.counts.adult_on || 0).toLocaleString()} domains · ` : ''}${state.counts.sites_on || 0} custom site${(state.counts.sites_on || 0) === 1 ? '' : 's'} blocked.</p>
      <div class="row-actions">
        <a class="btn" href="#sites">${state.settings.ad_block_enabled === '1' || state.settings.adult_block_enabled === '1' ? 'Manage blocking' : 'Turn on blocking'}</a>
        <a class="btn ghost" href="api.php?action=export_hosts">Download block list</a>
      </div>
    </section>
    <section class="panel stack">
      <div class="panel-head">
        <h2>Bedtime / schedule</h2>
        <button type="button" class="btn small" data-act="add-schedule">Add schedule</button>
      </div>
      ${tip('Example: block a kid tablet from 22:00 to 07:00 on school nights.')}
      ${schedules ? table(['Name', 'Who', 'Days', 'Hours', 'Action', 'On', ''], schedules) : empty('No schedules yet.')}
    </section>
    <section class="panel stack">
      <h2>Firewall</h2>
      ${tip('Advanced allow/block rules. Most people only need website blocking.')}
      ${rules.length ? `<ul class="feed">${rules.map((row) => `<li><strong>${esc(row.name)}</strong> <span class="muted">${esc(row.action)} · ${esc(row.direction)}</span></li>`).join('')}</ul>` : empty('No active firewall rules.')}
      <div class="row-actions">
        <a class="btn ghost" href="#firewall">Open firewall</a>
        <button type="button" class="btn ghost" data-act="add-rule">Add rule</button>
      </div>
    </section>
    <form class="panel stack" data-action="save_router_settings">
      <h2>Who can join (MAC filter)</h2>
      ${tip('Leave Off unless you want to allow or block specific devices by hardware address.')}
      <input type="hidden" name="section" value="macmode">
      <label class="field">Filter mode${fieldSelect('mac_filter_mode', MAC_MODE, r.mac_filter_mode || 'disabled')}</label>
      <button class="btn" type="submit">Save filter mode</button>
    </form>
    <section class="panel stack">
      <div class="panel-head">
        <h2>MAC list</h2>
        <button type="button" class="btn small" data-act="add-mac">Add device MAC</button>
      </div>
      ${macRows ? table(['Name', 'MAC', 'Mode', 'On', ''], macRows) : empty('No MAC entries yet.')}
    </section>`;
}

function tabMoreEasy() {
  const r = state.router || {};
  const forwards = (state.port_forwards || []).map((row) => `<tr>
    <td>${esc(row.name)}</td>
    <td>${esc(row.protocol.toUpperCase())}</td>
    <td class="mono">${esc(row.external_port)}</td>
    <td class="mono">${esc(row.internal_ip)}:${esc(row.internal_port)}</td>
    <td>${badge(row.enabled ? 'On' : 'Off', row.enabled ? 'on' : 'off')}</td>
    <td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="toggle-forward" data-id="${row.id}">On/Off</button>
      <button type="button" class="btn small ghost" data-act="edit-forward" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-forward" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  const capped = state.devices.filter((d) => Number(d.bandwidth_limit || 0) > 0);
  const capRows = capped.map((row) => `<tr>
    <td>${esc(row.name)}</td><td class="mono">${esc(row.ip)}</td>
    <td>${esc(row.bandwidth_limit)} Kbps</td>
    <td><button type="button" class="btn small ghost" data-act="edit-device" data-id="${row.id}">Edit</button></td>
  </tr>`).join('');
  return `
    <section class="panel stack">
      <div class="panel-head">
        <h2>Port forwarding</h2>
        <button type="button" class="btn small" data-act="add-forward">Add</button>
      </div>
      ${tip('Only needed for games, cameras, or servers you host at home. Skip if unsure.')}
      ${forwards ? table(['Name', 'Type', 'Outside port', 'Inside device', 'On', ''], forwards) : empty('None set up.')}
    </section>
    <form class="panel stack" data-action="save_router_settings">
      <h2>Speed limits (QoS)</h2>
      <input type="hidden" name="section" value="qos">
      ${checkField('qos_enabled', 'Turn on speed control', r.qos_enabled === '1')}
      <label class="field">How to limit${fieldSelect('qos_mode', QOS_MODE, r.qos_mode || 'device')}</label>
      <button class="btn" type="submit">Save speed control</button>
    </form>
    <section class="panel stack">
      <h2>Device speed caps</h2>
      ${capRows ? table(['Device', 'IP', 'Limit', ''], capRows) : empty('No caps yet. Edit a device and set Bandwidth limit.')}
    </section>
    <form class="panel stack" data-action="save_router_settings">
      <h2>VPN</h2>
      ${tip('Optional. Most home networks do not need this.')}
      <input type="hidden" name="section" value="vpn">
      ${checkField('vpn_enabled', 'VPN is on', r.vpn_enabled === '1')}
      ${formGrid(`
        <label class="field">VPN type${fieldSelect('vpn_type', VPN_TYPE, r.vpn_type || 'none')}</label>
        <label class="field">Server<input name="vpn_server" maxlength="120" value="${esc(r.vpn_server)}" placeholder="vpn.example.com"></label>
      `)}
      <label class="field">Notes<textarea name="vpn_notes" maxlength="500" rows="2">${esc(r.vpn_notes)}</textarea></label>
      <button class="btn" type="submit">Save VPN</button>
    </form>
    <form class="panel stack" data-action="save_router_settings">
      <h2>Router details</h2>
      ${tip('Save a link to your real router page so you can open it in one click.')}
      <input type="hidden" name="section" value="system">
      ${formGrid(`
        <label class="field">Router login page<input name="router_admin_url" maxlength="500" value="${esc(r.router_admin_url)}" placeholder="http://192.168.0.1"></label>
        <label class="field">Router model<input name="router_model" maxlength="120" value="${esc(r.router_model)}" placeholder="TP-Link / Asus / etc."></label>
      `)}
      <label class="field">Notes<textarea name="router_notes" maxlength="500" rows="2">${esc(r.router_notes)}</textarea></label>
      ${checkField('router_traffic_enabled', 'Use router for live traffic on other devices', r.router_traffic_enabled !== '0')}
      ${checkField('upnp_enabled', 'UPnP (apps open ports automatically)', r.upnp_enabled === '1')}
      ${checkField('remote_admin', 'Allow admin from the internet (risky)', r.remote_admin === '1')}
      <button class="btn" type="submit">Save router details</button>
    </form>`;
}

const ROUTER_PANELS = {
  home: tabHome,
  devices: tabDevices,
  wifi: tabWifiEasy,
  internet: tabInternetEasy,
  security: tabSecurityEasy,
  more: tabMoreEasy
};

function pageWifi() {
  const panel = ROUTER_PANELS[routerTab] || tabHome;
  const wifiOn = wifiIsConnected();
  const brand = routerBrandLabel();
  const leadText = routerIsConnected()
    ? `Connected to ${esc(brand)}. Use <strong>Home</strong> for everyday tasks — advanced options stay under <strong>More</strong>.`
    : wifiOn
      ? `Wi‑Fi is on. Next step: <strong>Connect to router</strong> with the ${esc(brand)} admin username and password (not the Wi‑Fi password).`
      : 'Join home Wi‑Fi first, then connect to your router for full access.';
  return `${sampleBanner()}
    <p class="lead">${leadText}</p>
    ${routerTabs()}
    <div class="router-panel">${panel()}</div>`;
}

function agentUrl() {
  return location.origin + location.pathname.replace(/\/[^/]*$/, '') + '/agent.php';
}

function agentInstallCommand(token) {
  return `scripts\\install-pnet-agent.bat ${token} ${agentUrl()}`;
}

function openAgentInstall(agent, device) {
  if (!agent?.token) return;
  const cmd = agentInstallCommand(agent.token);
  drawer.innerHTML = `<div class="drawer stack">
    <div class="drawer-head"><h2>Install agent</h2><button type="button" class="btn small ghost" data-act="close">Close</button></div>
    <p class="lead">Run this on <strong>${esc(agent.device_name || device?.name || 'the device')}</strong> while it is on your home Wi‑Fi. It reports live apps and speed every few seconds.</p>
    <label class="field">Windows command<textarea rows="3" readonly>${esc(cmd)}</textarea></label>
    <p class="fine">Agent URL: ${esc(location.origin + location.pathname.replace(/\/[^/]*$/, '') + '/agent.php')}</p>
    <div class="row-actions">
      <button type="button" class="btn" data-act="copy" data-value="${esc(cmd)}">Copy command</button>
      <button type="button" class="btn ghost" data-act="view-device-live" data-id="${esc(String(agent.device_id || device?.id || ''))}">Back to live view</button>
    </div>
  </div>`;
  drawer.hidden = false;
}

async function createDeviceAgent(deviceId) {
  if (saving) return;
  saving = true;
  document.body.classList.add('busy');
  try {
    const data = await post({ action: 'create_device_agent', id: Number(deviceId) });
    if (data.state) state = data.state;
    if (data.agent) {
      openAgentInstall(data.agent, findRow(state.devices, deviceId));
      toast(data.message || 'Agent created.');
    } else {
      toast(data.message || 'Agent created.');
    }
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

function deviceLivePanelHtml(device, liveRow) {
  const down = formatBps(liveRow?.down_bps || 0);
  const up = formatBps(liveRow?.up_bps || 0);
  const note = liveRow?.note || '';
  const source = liveRow?.source_label || (liveRow?.is_local ? 'This PC' : '');
  const apps = Array.isArray(liveRow?.apps) ? liveRow.apps : [];
  const appRows = apps.length ? apps.map((app) => {
    const busy = (app.down_bps || 0) + (app.up_bps || 0) > 0;
    const max = Math.max(...apps.map((a) => (a.down_bps || 0) + (a.up_bps || 0)), 1);
    const share = busy ? Math.max(8, Math.round((((app.down_bps || 0) + (app.up_bps || 0)) / max) * 100)) : 4;
    return `<li class="app-row${busy ? ' busy' : ''}">
      <div class="app-head">
        <strong>${esc(app.label || app.name || 'Unknown')}</strong>
        <span class="mono">↓ ${esc(formatBps(app.down_bps || 0))} · ↑ ${esc(formatBps(app.up_bps || 0))}</span>
      </div>
      <div class="app-bar"><span style="width:${share}%"></span></div>
      <div class="muted">${esc(app.tcp || 0)} TCP · ${esc(app.udp || 0)} UDP · ${esc(app.remote_public || 0)} internet links</div>
    </li>`;
  }).join('') : '<li class="empty">No active apps right now.</li>';
  return `<div class="live-panel stack">
    <div class="live-speeds">
      <div class="live-speed"><span>Download</span><strong class="mono">${esc(down)}</strong></div>
      <div class="live-speed"><span>Upload</span><strong class="mono">${esc(up)}</strong></div>
    </div>
    ${source ? `<p class="source-badge">${esc(source)}</p>` : ''}
    ${note ? `<p class="tip">${esc(note)}</p>` : ''}
    <div>
      <h3>Apps using internet</h3>
      <ul class="app-list">${appRows}</ul>
    </div>
    <p class="fine">${liveRow?.is_local ? 'Live from this PC. Updates every 3 seconds.' : liveRow?.source === 'agent' ? 'Live from PNet agent. Updates every 3 seconds.' : liveRow?.source === 'router' ? 'Speed from router. Install agent for app names.' : 'Install agent on this device, or save router login for speed-only stats.'}</p>
  </div>`;
}

function openDeviceLive(device) {
  if (!device) return;
  liveDeviceId = Number(device.id);
  const liveRow = trafficForDevice(device.id);
  drawer.innerHTML = `<div class="drawer stack" data-live-device="${device.id}">
    <div class="drawer-head">
      <div>
        <h2>${esc(device.name)}</h2>
        <p class="muted mono">${esc(device.ip)} · ${esc(label('type', device.type))}</p>
      </div>
      <button type="button" class="btn small ghost" data-act="close">Close</button>
    </div>
    <div id="device-live-panel">${deviceLivePanelHtml(device, liveRow)}</div>
    <div class="row-actions">
      ${device.is_local || liveRow?.is_local ? '' : `<button type="button" class="btn small" data-act="install-agent" data-id="${device.id}">${liveRow?.has_agent ? 'New agent token' : 'Install agent'}</button>`}
      ${liveRow?.has_agent ? `<button type="button" class="btn small danger" data-act="revoke-agent" data-id="${device.id}">Remove agent</button>` : ''}
      <button type="button" class="btn small ghost" data-act="check" data-kind="device" data-id="${device.id}">Check online</button>
      <button type="button" class="btn small ghost" data-act="edit-device" data-id="${device.id}">Edit device</button>
    </div>
  </div>`;
  drawer.hidden = false;
  startTrafficPoll(true);
}

function refreshLivePanels() {
  const panel = document.getElementById('device-live-panel');
  if (panel && liveDeviceId != null) {
    const device = findRow(state.devices, liveDeviceId);
    if (device) {
      panel.innerHTML = deviceLivePanelHtml(device, trafficForDevice(liveDeviceId));
    }
  }
  if (currentView() === 'network' && liveTrafficEnabled) {
    document.querySelectorAll('[data-traffic-id]').forEach((cell) => {
      cell.innerHTML = trafficCell(cell.dataset.trafficId);
    });
  }
  if (currentView() === 'traffic') {
    const total = trafficLive?.total || {};
    const downEl = document.getElementById('traffic-total-down');
    const upEl = document.getElementById('traffic-total-up');
    if (downEl) downEl.textContent = formatBps(total.down_bps || 0);
    if (upEl) upEl.textContent = formatBps(total.up_bps || 0);
    document.querySelectorAll('[data-traffic-id]').forEach((cell) => {
      cell.innerHTML = trafficCell(cell.dataset.trafficId);
    });
  }
}

function shouldPollTraffic() {
  return currentView() === 'traffic'
    || (currentView() === 'network' && liveTrafficEnabled)
    || liveDeviceId != null;
}

function stopTrafficPoll() {
  if (trafficPoll) {
    clearInterval(trafficPoll);
    trafficPoll = null;
  }
}

async function fetchTraffic(deviceId) {
  const url = deviceId ? `api.php?action=traffic&device_id=${encodeURIComponent(deviceId)}` : 'api.php?action=traffic';
  const res = await fetch(url, { cache: 'no-store' });
  const data = await res.json().catch(() => ({ ok: false }));
  if (!data.ok) throw new Error(data.error || 'Could not read live usage.');
  trafficLive = data;
  refreshLivePanels();
}

function startTrafficPoll(force) {
  if (!force && trafficPoll) return;
  stopTrafficPoll();
  const tick = () => {
    fetchTraffic(liveDeviceId).catch(() => {});
  };
  tick();
  trafficPoll = setInterval(tick, 3000);
}

function pageTraffic() {
  const total = trafficLive?.total || {};
  const down = formatBps(total.down_bps || 0);
  const up = formatBps(total.up_bps || 0);
  const warming = !!trafficLive?.warming;
  const localIp = trafficLive?.local_ip || state.network?.local_ip || '';
  const router = trafficLive?.router || {};
  const agents = trafficLive?.agents || {};
  const brand = routerBrandLabel();
  const routerNote = (() => {
    if (!router.has_login) {
      return `Save your ${brand} login under Router (${routerAdminUrl() || 'http://192.168.0.1'}) to pull devices from the gateway.`;
    }
    if (router.source === 'tplink') {
      if (router.clients > 0) {
        return `TP-Link reporting ${router.clients} device${router.clients === 1 ? '' : 's'}${router.has_rates ? ' with live speed' : ''}.`;
      }
      return router.error === 'login_failed'
        ? 'TP-Link login failed. Check username/password under Router.'
        : 'TP-Link login saved. Tap Pull everything from router on the Wi‑Fi page.';
    }
    if (router.source === 'zte' || isZteRouter()) {
      if (router.clients > 0 && router.has_rates) {
        return `ZTE${router.model ? ' ' + router.model : ''} reporting ${router.clients} device${router.clients === 1 ? '' : 's'} with live speed.`;
      }
      if (router.clients > 0) {
        return `ZTE${router.model ? ' ' + router.model : ''} sees ${router.clients} device${router.clients === 1 ? '' : 's'}. Live speed may be limited on this model — use agents for apps.`;
      }
      return router.error === 'login_failed'
        ? 'ZTE login failed. Check username/password under Router.'
        : 'ZTE login saved. Could not read client list yet — try Connect again, or use agents.';
    }
    if (router.clients > 0) {
      return `${brand} reporting ${router.clients} device${router.clients === 1 ? '' : 's'}.`;
    }
    return 'Router login saved. Traffic API not supported on this model yet — use agents.';
  })();
  const agentNote = `${agents.reporting || 0} of ${agents.count || 0} agents reporting live.`;
  const note = warming
    ? 'Measuring speed… keep this page open for a few seconds.'
    : `Tap a device to see apps. This PC is measured locally; other devices use a PNet agent or your ${brand}.`;
  const summary = `<div class="traffic-summary stats">
    <div class="stat traffic-stat"><b class="mono" id="traffic-total-down">${esc(down)}</b><span>Download</span><small>${warming ? 'Measuring…' : 'This PC now'}</small></div>
    <div class="stat traffic-stat"><b class="mono" id="traffic-total-up">${esc(up)}</b><span>Upload</span><small>${warming ? 'Measuring…' : 'This PC now'}</small></div>
    <div class="stat traffic-stat"><b>${esc(String(state.counts.devices_online || 0))}</b><span>Devices online</span><small>${esc(String(state.counts.devices || 0))} on your Wi‑Fi</small></div>
  </div>`;
  const liveDevices = Array.isArray(trafficLive?.devices) ? trafficLive.devices : [];
  const deviceSource = liveDevices.length
    ? liveDevices
    : state.devices.map((d) => ({
      id: d.id,
      name: d.name,
      ip: d.ip,
      type: d.type,
      status: d.status,
      is_local: localIp !== '' && d.ip === localIp,
      down_bps: 0,
      up_bps: 0,
      apps: []
    }));
  if (!deviceSource.length) {
    return `${sampleBanner()}${summary}${lead('Find devices first, then come back here to watch live internet usage.')}${empty('No devices yet.')}<div class="row-actions"><button type="button" class="btn" data-act="discover">Find devices</button></div>`;
  }
  const rows = deviceSource.map((row) => {
    const device = findRow(state.devices, row.id) || row;
    const id = row.id || device.id;
    return `<tr data-search="${searchAttr([device.name, device.ip, label('type', device.type || row.type), device.status || row.status])}">
      <td>
        <div class="device-row">
          ${deviceIconHtml(device)}
          <div class="device-info">
            <button type="button" class="device-name linkish" data-act="view-device-live" data-id="${id}">${esc(device.name || row.name)}</button>
            <div class="device-meta">${esc(deviceMeta(device))}${row.is_local ? ' · This PC' : ''}</div>
          </div>
        </div>
      </td>
      <td class="mono">${esc(device.ip || row.ip)}</td>
      <td data-traffic-id="${id}">${trafficCell(id)}</td>
      <td>${row.source_label ? `<span class="source-badge">${esc(row.source_label)}</span>` : '<span class="muted">—</span>'}</td>
      <td>${badge(label('status', device.status || row.status), device.status || row.status)}</td>
      <td><button type="button" class="btn small ghost" data-act="view-device-live" data-id="${id}">Apps</button></td>
    </tr>`;
  }).join('');
  return `${sampleBanner()}${summary}<section class="panel stack"><h2>Live usage by device</h2><p class="lead">${esc(note)}</p><p class="fine">${esc(routerNote)} ${esc(agentNote)}</p>${table(['Device', 'IP', 'Internet now', 'Source', 'Status', ''], rows)}</section>`;
}

function pageNetwork() {
  const gw = state.network?.gateway || '';
  const rows = sortedDevices().map((row) => {
    const isRouter = isGatewayDevice(row);
    const cap = speedLabel(row.bandwidth_limit || 0);
    const ping = row.ping_ms ? `<span class="ping-indicator ${row.ping_ms < 50 ? 'fast' : row.ping_ms < 150 ? 'medium' : 'slow'}">${row.ping_ms}ms</span>` : '';
    const live = liveTrafficEnabled ? `<td data-traffic-id="${row.id}">${trafficCell(row.id)}</td>` : '';
    return `<tr data-search="${searchAttr([row.name, row.ip, row.mac, row.vendor, label('type', row.type), row.status, row.trust, row.access_profile, isRouter ? 'router gateway' : ''])}"${isRouter ? ' class="router-row"' : ''}>
    <td>
      <div class="device-row">
        ${deviceIconHtml(row)}
        <div class="device-info">
          <button type="button" class="device-name linkish" data-act="view-device-live" data-id="${row.id}">${esc(row.name)}${isRouter ? ' <span class="badge on">Router</span>' : ''}</button>
          <div class="device-meta">${esc(deviceMeta(row))}${isRouter && gw ? ' · Gateway ' + esc(gw) : ''}</div>
        </div>
      </div>
    </td>
    <td class="mono">${esc(row.ip)}</td>
    <td class="mono">${esc(row.mac || '—')}</td>
    ${live}
    <td>${badge(label('status', row.status), row.status)} ${badge(label('trust', row.trust || 'unknown'), row.trust || 'unknown')}</td>
    <td>${badge(label('access', row.access_profile || 'normal'), row.access_profile || 'normal')}<div class="muted">${esc(cap)}</div></td>
    <td>${ping}</td>
    <td>${deviceActionsHtml(row)}</td>
  </tr>`;
  }).join('');
  const autoRefresh = `<div class="auto-refresh-indicator${autoRefreshEnabled ? ' active' : ''}" id="auto-refresh">
    <span class="dot"></span>
    <span>Auto-refresh ${autoRefreshEnabled ? 'on' : 'off'}</span>
    <button type="button" class="btn small ghost" data-act="toggle-auto-refresh">${autoRefreshEnabled ? 'Stop' : 'Start'}</button>
  </div>`;
  const liveBanner = liveTrafficEnabled
    ? `<div class="banner live-banner"><p><strong>Live usage</strong> is on. Click a device name or <em>Live</em> to see apps. Full internet + app details work on this PC; other devices need router stats, a saved router login, or a PNet agent.</p></div>`
    : '';
  const headers = liveTrafficEnabled
    ? ['Device', 'IP', 'MAC', 'Internet now', 'Trust', 'Access', 'Ping', '']
    : ['Device', 'IP', 'MAC', 'Trust', 'Access', 'Ping', ''];
  const routerTip = gw
    ? tip(`Your Wi‑Fi router/gateway is <strong>${esc(gw)}</strong> — look for the green <em>Router</em> badge at the top of the list.`)
    : '';
  return `${sampleBanner()}${liveBanner}${lead('Everyone connected to your home Wi‑Fi. The router is listed first with a Router badge.')}${routerTip}${autoRefresh}${table(headers, rows)}`;
}

function deviceActionsHtml(row) {
  const quarantined = row.access_profile === 'quarantined';
  const hasMac = !!(row.mac && row.mac !== '');
  return `<div class="device-actions">
    <button type="button" class="btn small" data-act="view-device-live" data-id="${row.id}">Live</button>
    <button type="button" class="btn small ghost" data-act="edit-device" data-id="${row.id}">Edit</button>
    <div class="more-menu">
      <button type="button" class="btn small ghost icon-btn" data-act="toggle-more" aria-label="More actions" aria-expanded="false" title="More">⋯</button>
      <div class="more-panel" hidden>
        <button type="button" data-act="check" data-kind="device" data-id="${row.id}">Check online</button>
        ${hasMac ? `<button type="button" data-act="wake-device" data-id="${row.id}">Wake on LAN</button>` : ''}
        <button type="button" data-act="protect-device" data-id="${row.id}">Protect</button>
        ${quarantined
          ? `<button type="button" data-act="resume-device" data-id="${row.id}">Allow again</button>`
          : `<button type="button" class="danger" data-act="quarantine-device" data-id="${row.id}">Block device</button>`}
        <button type="button" class="danger" data-act="delete-device" data-id="${row.id}">Delete</button>
      </div>
    </div>
  </div>`;
}

function pageFirewall() {
  const rows = state.rules.map((row) => {
    const port = row.port ? ':' + row.port : '';
    const path = `${row.direction} · ${row.protocol} · ${row.source} → ${row.destination}${port}`;
    return `<tr data-search="${searchAttr([row.name, path, row.action, row.notes])}">
      <td><button type="button" class="switch${row.enabled === 1 ? ' on' : ''}" data-act="toggle-rule" data-id="${row.id}" aria-label="${row.enabled === 1 ? 'Turn rule off' : 'Turn rule on'}"><span></span></button></td>
      <td class="mono">${esc(row.priority)}</td>
      <td><strong>${esc(row.name)}</strong><div class="muted">${esc(path)}</div></td>
      <td>${badge(row.action, row.action)}</td>
      <td><div class="row-actions">
        <button type="button" class="btn small ghost" data-act="edit-rule" data-id="${row.id}">Edit</button>
        <button type="button" class="btn small danger" data-act="delete-rule" data-id="${row.id}">Delete</button>
      </div></td>
    </tr>`;
  }).join('');
  return `${sampleBanner()}${lead('Simple allow/block rules for your home. Save them here, then apply the same idea on your router if needed.')}${table(['On', 'Priority', 'Rule', 'Action', ''], rows)}`;
}

function pageSites() {
  const adOn = state.settings.ad_block_enabled === '1';
  const adsOn = state.counts.ads_on || 0;
  const adUpdated = state.settings.ad_block_updated ? when(state.settings.ad_block_updated) : '';
  const adultOn = state.settings.adult_block_enabled === '1';
  const adultCount = state.counts.adult_on || 0;
  const adultUpdated = state.settings.adult_block_updated ? when(state.settings.adult_block_updated) : '';
  const dnsOn = state.settings.dns_blocker_enabled === '1';
  const dnsHost = state.settings.dns_blocker_host || (state.network && state.network.local_ip) || '';
  const syncPending = state.settings.dns_blocker_sync_pending === '1';
  const networkPanel = `<section class="panel stack dns-block-panel${dnsOn ? ' on' : ''}">
    <div class="panel-head">
      <div>
        <h2>Whole Wi‑Fi blocker</h2>
        <p class="muted">${dnsOn
    ? `AdGuard Home running · DNS ${dnsHost || 'this PC'}${syncPending ? ' · list changed — sync' : ''}`
    : 'Runs AdGuard Home on this PC so phones, TVs, and PCs are blocked together'}</p>
      </div>
      ${dnsOn ? badge('On', 'on') : badge('Off', 'off')}
    </div>
    ${tip(dnsOn
      ? `Network blocker is on. Push sets this PC’s Wi‑Fi DNS. For phones/TVs use Push to router and set DNS to ${dnsHost || 'this PC'}.`
      : 'Start the blocker, then Push to this Wi‑Fi (this PC) and Push to router (whole network).')}
    ${desktopBridgeHint()}
    <div class="row-actions">
      ${hasDesktopDns()
        ? (dnsOn
          ? `<button type="button" class="btn ghost" data-act="stop-dns">Stop</button>
             <button type="button" class="btn${syncPending ? '' : ' ghost'}" data-act="sync-dns">Sync block list</button>
             <button type="button" class="btn" data-act="push-wifi-dns">Push to this Wi‑Fi</button>
             <button type="button" class="btn ghost" data-act="pull-wifi-dns">Pull Wi‑Fi DNS</button>
             <button type="button" class="btn ghost" data-act="push-router-dns">Push to router</button>
             <button type="button" class="btn ghost" data-act="copy" data-value="${esc(dnsHost)}">Copy DNS IP</button>`
          : `<button type="button" class="btn" data-act="start-dns">Start network blocker</button>
             <button type="button" class="btn ghost" data-act="pull-wifi-dns">Pull Wi‑Fi DNS</button>`)
        : `<button type="button" class="btn ghost" data-act="pull-wifi-dns">Pull Wi‑Fi DNS</button>
           <button type="button" class="btn ghost" data-act="push-router-dns">Push to router</button>
           <span class="muted">${isElectronShell() ? 'Restart desktop app for Start / Push.' : 'Start / Push need the PNet desktop app.'}</span>`}
      <a class="btn ghost" href="#wifi">Router</a>
    </div>
  </section>`;
  const adPanel = `<section class="panel stack ad-block-panel${adOn ? ' on' : ''}">
    <div class="panel-head">
      <div>
        <h2>AdGuard list</h2>
        <p class="muted">${adOn
    ? `${adsOn.toLocaleString()} AdGuard domains${adUpdated ? ` · updated ${esc(adUpdated)}` : ''}`
    : 'Official AdGuard DNS filter (same list as AdGuard Home)'}</p>
      </div>
      <button type="button" class="switch${adOn ? ' on' : ''}" data-act="toggle-ad-block" aria-label="${adOn ? 'Turn ad blocker off' : 'Turn ad blocker on'}"><span></span></button>
    </div>
    ${tip(adOn
      ? 'List is loaded in PNet. Start/sync the network blocker so the whole Wi‑Fi uses it.'
      : 'Turn on to load AdGuard’s DNS filter, then start the network blocker.')}
    <div class="row-actions">
      ${adOn ? '<button type="button" class="btn ghost" data-act="refresh-ad-block">Update from AdGuard</button>' : '<button type="button" class="btn" data-act="toggle-ad-block">Turn on AdGuard list</button>'}
      <a class="btn ghost" href="api.php?action=export_hosts">Download list</a>
      ${isDesktopApp() ? `<button type="button" class="btn ghost" data-act="apply-hosts">${state.settings.hosts_applied === '1' ? 'Re-apply on this PC only' : 'Apply on this PC only'}</button>` : ''}
    </div>
  </section>`;
  const adultPanel = `<section class="panel stack adult-block-panel${adultOn ? ' on' : ''}">
    <div class="panel-head">
      <div>
        <h2>Adult sites</h2>
        <p class="muted">${adultOn
    ? `${adultCount.toLocaleString()} adult domains${adultUpdated ? ` · updated ${esc(adultUpdated)}` : ''}`
    : 'Block adult websites across the whole Wi‑Fi'}</p>
      </div>
      <button type="button" class="switch${adultOn ? ' on' : ''}" data-act="toggle-adult-block" aria-label="${adultOn ? 'Turn adult blocking off' : 'Turn adult blocking on'}"><span></span></button>
    </div>
    ${tip(adultOn
      ? 'The full adult list is on. Sync the network blocker so phones, TVs, and PCs use it. Search engines use safe search. This list is too large for the Windows hosts file.'
      : 'Turn on to block adult websites (about 950,000 domains), then start or sync the network blocker.')}
    <div class="row-actions">
      ${adultOn ? '<button type="button" class="btn ghost" data-act="refresh-adult-block">Update adult list</button>' : '<button type="button" class="btn" data-act="toggle-adult-block">Turn on adult blocking</button>'}
    </div>
  </section>`;
  const cats = [
    ['social', 'Social sites', 'Facebook, Instagram, TikTok, X, Snapchat, Reddit, Discord'],
    ['games', 'Games', 'Roblox, Steam, Xbox, PlayStation, Nintendo, Epic, Minecraft'],
    ['streaming', 'Streaming', 'YouTube, Netflix, Disney+, Hulu, Twitch, Spotify'],
  ];
  const catCards = cats.map(([key, title, blurb]) => {
    const on = state.settings[key + '_block_enabled'] === '1';
    const bedtimeOn = state.settings.bedtime_active === '1' && (state.settings.bedtime_targets || '').split(',').includes(key);
    return `<div class="cat-card${on || bedtimeOn ? ' on' : ''}">
      <div>
        <strong>${esc(title)}</strong>
        <p class="muted">${esc(blurb)}${!on && bedtimeOn ? ' · on for bedtime' : ''}</p>
      </div>
      <button type="button" class="switch${on ? ' on' : ''}" data-act="toggle-category" data-cat="${key}" aria-label="${on ? 'Turn ' + title + ' off' : 'Turn ' + title + ' on'}"><span></span></button>
    </div>`;
  }).join('');
  const targets = (state.settings.bedtime_targets || 'social,games,streaming').split(',');
  const deviceOptions = state.devices.filter((row) => row.type !== 'router').map((row) => `<option value="${row.id}">${esc(row.name)} · ${esc(row.ip)}</option>`).join('');
  const allows = (state.block_allows || []).flatMap((row) => row.categories.map((cat) => `<li>${esc(row.name)} <span class="muted">${esc(row.ip)} · ${esc(cat)}</span> <button type="button" class="btn small ghost" data-act="clear-exception" data-id="${row.device_id}" data-cat="${esc(cat)}">Remove</button></li>`)).join('');
  const extraPanel = `<section class="panel stack">
    <h2>Social, games, and streaming</h2>
    ${tip('These lists block the main sites. Sync the network blocker after you change them. Bedtime can turn them on only at night.')}
    <div class="cat-grid">${catCards}</div>
  </section>
  <form class="panel stack" data-action="save_bedtime">
    <h2>Bedtime</h2>
    <p class="muted">${state.settings.bedtime_active === '1' ? 'Bedtime is on right now.' : 'Outside bedtime, only the switches above stay on.'}</p>
    ${checkField('enabled', 'Block the chosen lists during bedtime', state.settings.bedtime_enabled === '1')}
    <div class="form-grid">
      <label class="field">Start<input type="time" name="bedtime_start" value="${esc(state.settings.bedtime_start || '22:00')}" required></label>
      <label class="field">End<input type="time" name="bedtime_end" value="${esc(state.settings.bedtime_end || '07:00')}" required></label>
    </div>
    ${checkField('bedtime_social', 'Social sites', targets.includes('social'))}
    ${checkField('bedtime_games', 'Games', targets.includes('games'))}
    ${checkField('bedtime_streaming', 'Streaming', targets.includes('streaming'))}
    <button class="btn" type="submit">Save bedtime</button>
  </form>
  <form class="panel stack" data-action="set_block_exception">
    <h2>Let one device through</h2>
    ${tip('That device can still open the list you pick. Everyone else stays blocked. Adult sites stay blocked for the whole house.')}
    <input type="hidden" name="allow" value="1">
    <div class="form-grid">
      <label class="field">Device<select name="device_id" required>${deviceOptions || '<option value="">No devices yet</option>'}</select></label>
      <label class="field">List<select name="category"><option value="social">Social</option><option value="games">Games</option><option value="streaming">Streaming</option></select></label>
    </div>
    <button class="btn" type="submit">Allow this device</button>
    ${allows ? `<ul class="feed">${allows}</ul>` : ''}
  </form>`;
  const rows = state.sites.map((row) => `<tr data-search="${searchAttr([row.domain, row.category, row.notes])}">
    <td><button type="button" class="switch${row.enabled === 1 ? ' on' : ''}" data-act="toggle-site" data-id="${row.id}" aria-label="${row.enabled === 1 ? 'Stop blocking this site' : 'Block this site'}"><span></span></button></td>
    <td class="mono">${esc(row.domain)}</td>
    <td>${esc(label('category', row.category))}</td>
    <td>${esc(row.notes || '—')}</td>
    <td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="edit-site" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-site" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  return `${sampleBanner()}${hostsApplyBanner()}${networkPanel}${adPanel}${adultPanel}${extraPanel}${lead('Block any website (example: facebook.com). Sync the network blocker after changes.')}${table(['On', 'Website', 'Category', 'Notes', ''], rows)}`;
}

function pageIps() {
  const rows = state.ips.map((row) => `<tr data-search="${searchAttr([row.label, row.address, row.kind, row.mac, row.notes])}">
    <td><strong>${esc(row.label)}</strong></td>
    <td class="mono">${esc(row.address)}</td>
    <td>${esc(label('kind', row.kind))}</td>
    <td class="mono">${esc(row.mac || '—')}</td>
    <td>${esc(row.notes || '—')}</td>
    <td><div class="row-actions">
      <button type="button" class="btn small ghost" data-act="edit-ip" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-ip" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  return `${sampleBanner()}${lead('Every address worth remembering: gateway, DNS, reserved, guest, public, VPN, and blocked.')}${table(['Label', 'Address', 'Kind', 'MAC', 'Notes', 'Actions'], rows)}`;
}

function pageDefender() {
  const rows = state.alerts.map((row) => `<tr data-search="${searchAttr([row.title, row.severity, row.source_ip, row.category, row.status, row.details])}">
    <td>${badge(row.severity, row.severity)}</td>
    <td><strong>${esc(row.title)}</strong><div class="muted">${esc(row.details || label('category', row.category))}</div></td>
    <td class="mono">${esc(row.source_ip || '—')}</td>
    <td>${badge(label('status', row.status), row.status)}</td>
    <td>${esc(when(row.created_at))}</td>
    <td><div class="row-actions">
      ${row.status === 'open' ? `<button type="button" class="btn small ghost" data-act="ack-alert" data-id="${row.id}">Ack</button>` : ''}
      ${row.status !== 'resolved' ? `<button type="button" class="btn small ghost" data-act="resolve-alert" data-id="${row.id}">Resolve</button>` : ''}
      <button type="button" class="btn small ghost" data-act="edit-alert" data-id="${row.id}">Edit</button>
      <button type="button" class="btn small danger" data-act="delete-alert" data-id="${row.id}">Delete</button>
    </div></td>
  </tr>`).join('');
  return `${sampleBanner()}${lead('Log suspicious events here, then run a check for duplicate addresses, blocked-address clashes, cameras missing an IP, and inbound allow-all rules.')}${table(['Severity', 'Event', 'Source', 'Status', 'When', 'Actions'], rows)}`;
}

function pageCameras() {
  if (!state.cameras.length) {
    return `${sampleBanner()}${lead('Your cameras, with a snapshot when the browser can reach the camera from this device.')}${empty('Nothing here yet.')}`;
  }
  const cards = state.cameras.map((row) => {
    const shot = /^https?:\/\//i.test(row.snapshot_url)
      ? `<img class="snap" alt="" src="${esc(row.snapshot_url)}" data-src="${esc(row.snapshot_url)}">`
      : `<div class="snap-miss">${esc(row.location || 'No snapshot link')}</div>`;
    const stream = row.stream_url
      ? `<button type="button" class="btn small ghost" data-act="copy" data-value="${esc(row.stream_url)}">Copy stream</button>`
      : '';
    return `<article class="camera" data-search="${searchAttr([row.name, row.ip, row.location, row.status, row.notes])}">
      ${shot}
      <div>
        <h3>${esc(row.name)}</h3>
        <p class="muted">${esc(row.location || 'No location')} · <span class="mono">${esc(row.ip)}</span></p>
        ${badge(label('status', row.status), row.status)}
        <p class="muted">Last check ${esc(when(row.last_seen))}</p>
      </div>
      <div class="row-actions">
        <button type="button" class="btn small ghost" data-act="check" data-kind="camera" data-id="${row.id}">Check</button>
        ${stream}
        <button type="button" class="btn small ghost" data-act="edit-camera" data-id="${row.id}">Edit</button>
        <button type="button" class="btn small danger" data-act="delete-camera" data-id="${row.id}">Delete</button>
      </div>
    </article>`;
  }).join('');
  return `${sampleBanner()}${lead('Your cameras, with a snapshot when the browser can reach the camera from this device. Stream links open in VLC or the camera app.')}<div class="cards">${cards}</div><p id="no-hits" class="lead" hidden>No matches.</p>`;
}

function pageSettings() {
  const home = state.settings.home_name || '';
  const lan = state.settings.lan_cidr || '';
  return `${tip('Only a few settings here. Give your home a name — that is enough for most people.')}
    <form class="panel stack" data-action="save_settings">
      <h2>Your home</h2>
      <label class="field">Home name<input name="home_name" required maxlength="60" value="${esc(home)}" placeholder="My home"></label>
      ${advancedBox(`<label class="field">Network label (optional)<input name="lan_cidr" maxlength="40" value="${esc(lan)}" placeholder="192.168.1.0/24"></label>`)}
      <button class="btn" type="submit">Save</button>
    </form>
    <div class="panel stack">
      <h2>Backup</h2>
      <p class="lead">Save a copy of your PNet data, or restore one later.</p>
      <div class="row-actions">
        <a class="btn ghost" href="api.php?action=export_backup">Download backup</a>
        <label class="btn ghost" for="backup-file">Restore backup<input id="backup-file" type="file" accept="application/json,.json" hidden></label>
      </div>
    </div>`;
}

const RENDER = {
  overview: pageOverview,
  wifi: pageWifi,
  network: pageNetwork,
  traffic: pageTraffic,
  firewall: pageFirewall,
  sites: pageSites,
  ips: pageIps,
  defender: pageDefender,
  cameras: pageCameras,
  settings: pageSettings
};

function render() {
  if (!state) return;
  const view = currentView();
  const page = PAGES[view];
  const eyebrow = view === 'wifi' && routerIsConnected() ? 'Connected' : page[0];
  document.getElementById('eyebrow').textContent = eyebrow;
  document.getElementById('title').textContent = view === 'overview' ? (state.settings.home_name || 'Overview') : page[1];
  document.getElementById('home-name').textContent = state.settings.home_name || 'Home network';
  document.getElementById('actions').innerHTML = pageActions(view);
  main.innerHTML = RENDER[view]();
  document.querySelectorAll('.nav a').forEach((link) => {
    link.classList.toggle('active', link.getAttribute('href') === '#' + view);
  });
  if (shouldPollTraffic()) {
    startTrafficPoll(true);
  } else {
    stopTrafficPoll();
  }
  const input = document.getElementById('q');
  if (!input) return;
  input.addEventListener('input', () => {
    const query = input.value.trim().toLowerCase();
    const rows = Array.from(document.querySelectorAll('#main [data-search]'));
    let shown = 0;
    rows.forEach((row) => {
      const hit = query === '' || (row.dataset.search || '').toLowerCase().includes(query);
      row.hidden = !hit;
      if (hit) shown += 1;
    });
    const note = document.getElementById('no-hits');
    if (note) note.hidden = query === '' || shown > 0 || rows.length === 0;
  });
}

const SPEED_PRESETS = [
  [0, 'Unlimited'],
  [1000, 'Slow'],
  [5000, 'Medium'],
  [20000, 'Fast']
];

function kbpsToMbps(kbps) {
  const n = Number(kbps) || 0;
  if (n <= 0) return 0;
  return Math.max(1, Math.round(n / 1000));
}

function mbpsToKbps(mbps) {
  const n = Number(mbps) || 0;
  return n <= 0 ? 0 : n * 1000;
}

function speedLabel(kbps) {
  const n = Number(kbps) || 0;
  if (n <= 0) return 'Unlimited';
  const mbps = kbpsToMbps(n);
  if (mbps < 1) return 'Very slow';
  if (mbps <= 2) return `Slow · ${mbps} Mbps`;
  if (mbps <= 8) return `Medium · ${mbps} Mbps`;
  return `${mbps} Mbps`;
}

function fieldHtml(field, values) {
  const value = values[field.name] == null ? '' : values[field.name];
  const required = field.required ? ' required' : '';
  if (field.type === 'speed') {
    const kbps = Number(value) || 0;
    const mbps = kbpsToMbps(kbps);
    const presets = SPEED_PRESETS.map(([preset, text]) => {
      const active = kbps === preset || (preset > 0 && Math.abs(kbps - preset) < 1);
      return `<button type="button" class="speed-chip${active ? ' active' : ''}" data-speed-preset="${preset}">${esc(text)}</button>`;
    }).join('');
    return `<div class="speed-control" data-speed-control>
      <div class="speed-head">
        <strong>${esc(field.label || 'Internet speed')}</strong>
        <span class="speed-value" data-speed-label>${esc(speedLabel(kbps))}</span>
      </div>
      <p class="muted">Tap a speed, drag the slider, or use − / + to slow this device down.</p>
      <div class="speed-presets">${presets}</div>
      <div class="speed-slider-row">
        <button type="button" class="speed-step" data-speed-step="-1" aria-label="Slower">−</button>
        <input type="range" min="0" max="50" step="1" value="${mbps}" data-speed-slider aria-label="Speed limit">
        <button type="button" class="speed-step" data-speed-step="1" aria-label="Faster">+</button>
      </div>
      <div class="speed-ends"><span>No limit</span><span>50 Mbps max</span></div>
      <input type="hidden" name="${esc(field.name)}" value="${kbps}" data-speed-input>
    </div>`;
  }
  if (field.type === 'textarea') {
    return `<label class="field">${esc(field.label)}<textarea name="${esc(field.name)}" rows="4" maxlength="${field.max || 500}">${esc(value)}</textarea></label>`;
  }
  if (field.type === 'select') {
    const options = field.options.map(([optionValue, text]) => {
      const selected = String(optionValue) === String(value) ? ' selected' : '';
      return `<option value="${esc(optionValue)}"${selected}>${esc(text)}</option>`;
    }).join('');
    return `<label class="field">${esc(field.label)}<select name="${esc(field.name)}"${required}>${options}</select></label>`;
  }
  if (field.type === 'checkbox') {
    const checked = value === 1 || value === true || value === '1' ? ' checked' : '';
    return `<label class="check"><input type="checkbox" name="${esc(field.name)}"${checked}> ${esc(field.label)}</label>`;
  }
  const type = field.type || 'text';
  const max = field.max && type !== 'number' ? ` maxlength="${field.max}"` : '';
  const minAttr = field.min != null ? ` min="${field.min}"` : '';
  const maxAttr = field.max != null && type === 'number' ? ` max="${field.max}"` : '';
  return `<label class="field">${esc(field.label)}<input type="${esc(type)}" name="${esc(field.name)}" value="${esc(value)}"${required}${max}${minAttr}${maxAttr}></label>`;
}

function wireSpeedControls(root) {
  root.querySelectorAll('[data-speed-control]').forEach((box) => {
    const slider = box.querySelector('[data-speed-slider]');
    const input = box.querySelector('[data-speed-input]');
    const label = box.querySelector('[data-speed-label]');
    if (!slider || !input || !label) return;

    const apply = (kbps) => {
      let value = Math.max(0, Math.min(100000, Number(kbps) || 0));
      const mbps = kbpsToMbps(value);
      if (value > 0 && value < 1000) value = 1000;
      input.value = String(value);
      slider.value = String(mbps);
      label.textContent = speedLabel(value);
      box.querySelectorAll('[data-speed-preset]').forEach((btn) => {
        const preset = Number(btn.dataset.speedPreset);
        btn.classList.toggle('active', value === preset);
      });
    };

    slider.addEventListener('input', () => apply(mbpsToKbps(slider.value)));
    box.querySelectorAll('[data-speed-preset]').forEach((btn) => {
      btn.addEventListener('click', () => apply(btn.dataset.speedPreset));
    });
    box.querySelectorAll('[data-speed-step]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const next = Math.max(0, Math.min(50, Number(slider.value) + Number(btn.dataset.speedStep)));
        apply(mbpsToKbps(next));
      });
    });
    apply(input.value);
  });
}

function openForm(config) {
  const values = config.values || {};
  const simpleCount = Number(config.simpleCount || config.fields.length);
  const simpleFields = config.fields.slice(0, simpleCount).map((field) => fieldHtml(field, values)).join('');
  const extraFields = config.fields.slice(simpleCount).map((field) => fieldHtml(field, values)).join('');
  const advanced = extraFields ? advancedBox(extraFields) : '';
  const hint = config.hint ? `<div class="tip">${esc(config.hint)}</div>` : '';
  drawer.innerHTML = `<form class="drawer stack" data-action="${esc(config.action)}" data-id="${esc(config.id || '')}">
    <div class="drawer-head"><h2>${esc(config.title)}</h2><button type="button" class="btn small ghost" data-act="close">Close</button></div>
    ${hint}${simpleFields}${advanced}
    <button class="btn" type="submit">Save</button>
  </form>`;
  drawer.hidden = false;
  wireSpeedControls(drawer);
  const focus = drawer.querySelector('input:not([type="hidden"]):not([type="range"]), select, textarea');
  if (focus) focus.focus();
}

function closeDrawer() {
  drawer.hidden = true;
  drawer.innerHTML = '';
  liveDeviceId = null;
  if (shouldPollTraffic()) {
    startTrafficPoll(true);
  } else {
    stopTrafficPoll();
  }
}

function deviceForm(row) {
  openForm({
    title: row ? 'Edit device' : 'Add device',
    action: 'save_device',
    id: row && row.id,
    simpleCount: 5,
    values: row || { type: 'other', status: 'unknown', trust: 'unknown', access_profile: 'normal', bandwidth_limit: 0, protected: 0 },
    hint: 'To slow internet for this device, use the speed buttons or slider below.',
    fields: [
      { name: 'name', label: 'Device name', required: true, max: 80 },
      { name: 'ip', label: 'IP address', required: true, max: 45 },
      { name: 'type', label: 'What is it?', type: 'select', options: TYPES },
      { name: 'status', label: 'Online status', type: 'select', options: STATUS },
      { name: 'bandwidth_limit', label: 'Internet speed', type: 'speed' },
      { name: 'mac', label: 'MAC address (optional)', max: 32 },
      { name: 'vendor', label: 'Brand (optional)', max: 80 },
      { name: 'trust', label: 'Trust', type: 'select', options: TRUST },
      { name: 'access_profile', label: 'Access', type: 'select', options: ACCESS },
      { name: 'protected', label: 'Mark as protected', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function ruleForm(row) {
  openForm({
    title: row ? 'Edit firewall rule' : 'Add firewall rule',
    action: 'save_rule',
    id: row && row.id,
    values: row || { direction: 'inbound', action: 'block', protocol: 'any', source: 'any', destination: 'any', priority: 100, enabled: 1 },
    fields: [
      { name: 'name', label: 'Name', required: true, max: 80 },
      { name: 'direction', label: 'Direction', type: 'select', options: [['inbound', 'Inbound'], ['outbound', 'Outbound']] },
      { name: 'action', label: 'Action', type: 'select', options: [['allow', 'Allow'], ['block', 'Block']] },
      { name: 'protocol', label: 'Protocol', type: 'select', options: [['any', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP']] },
      { name: 'source', label: 'Source', max: 80 },
      { name: 'destination', label: 'Destination', max: 80 },
      { name: 'port', label: 'Port', max: 40 },
      { name: 'priority', label: 'Priority', type: 'number', min: 1, max: 9999 },
      { name: 'enabled', label: 'Enabled', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function siteForm(row) {
  openForm({
    title: row ? 'Edit blocked site' : 'Block a website',
    action: 'save_site',
    id: row && row.id,
    values: row || { category: 'custom', enabled: 1 },
    hint: 'Enter a domain like example.com. Subdomains are blocked only when you add them too.',
    fields: [
      { name: 'domain', label: 'Domain', required: true, max: 253 },
      { name: 'category', label: 'Category', type: 'select', options: CATEGORIES },
      { name: 'enabled', label: 'Enabled', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function ipForm(row) {
  openForm({
    title: row ? 'Edit address' : 'Add address',
    action: 'save_ip',
    id: row && row.id,
    values: row || { kind: 'lan' },
    fields: [
      { name: 'label', label: 'Label', required: true, max: 80 },
      { name: 'address', label: 'IP address', required: true, max: 45 },
      { name: 'kind', label: 'Kind', type: 'select', options: KINDS },
      { name: 'mac', label: 'MAC address', max: 32 },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function alertForm(row) {
  openForm({
    title: row ? 'Edit defender item' : 'Log defender event',
    action: 'save_alert',
    id: row && row.id,
    values: row || { severity: 'medium', category: 'other', status: 'open' },
    fields: [
      { name: 'title', label: 'Title', required: true, max: 120 },
      { name: 'severity', label: 'Severity', type: 'select', options: SEVERITY },
      { name: 'category', label: 'Category', type: 'select', options: ALERT_CATS },
      { name: 'status', label: 'Status', type: 'select', options: ALERT_STATUS },
      { name: 'source_ip', label: 'Source IP', max: 45 },
      { name: 'details', label: 'Details', type: 'textarea', max: 1000 }
    ]
  });
}

function cameraForm(row) {
  openForm({
    title: row ? 'Edit camera' : 'Add camera',
    action: 'save_camera',
    id: row && row.id,
    values: row || { status: 'unknown' },
    hint: 'Snapshot URL must be an image link such as http://192.168.1.50/snap.jpg. Leave passwords out of the link. Stream URL can be http, https, or rtsp.',
    fields: [
      { name: 'name', label: 'Name', required: true, max: 80 },
      { name: 'ip', label: 'IP address', required: true, max: 45 },
      { name: 'location', label: 'Location', max: 80 },
      { name: 'snapshot_url', label: 'Snapshot URL', max: 500 },
      { name: 'stream_url', label: 'Stream URL', max: 500 },
      { name: 'status', label: 'Status', type: 'select', options: STATUS },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function forwardForm(row) {
  openForm({
    title: row ? 'Edit port forward' : 'Add port forward',
    action: 'save_port_forward',
    id: row && row.id,
    values: row || { protocol: 'tcp', enabled: 1 },
    fields: [
      { name: 'name', label: 'Name', required: true, max: 80 },
      { name: 'protocol', label: 'Protocol', type: 'select', options: PROTOCOLS },
      { name: 'external_port', label: 'External port', required: true, max: 40 },
      { name: 'internal_ip', label: 'Internal IP', required: true, max: 45 },
      { name: 'internal_port', label: 'Internal port', max: 40 },
      { name: 'enabled', label: 'Enabled', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function dhcpForm(row) {
  openForm({
    title: row ? 'Edit DHCP reservation' : 'Add DHCP reservation',
    action: 'save_dhcp_reservation',
    id: row && row.id,
    values: row || { enabled: 1 },
    fields: [
      { name: 'name', label: 'Name', required: true, max: 80 },
      { name: 'mac', label: 'MAC address', required: true, max: 32 },
      { name: 'ip', label: 'Reserved IP', required: true, max: 45 },
      { name: 'enabled', label: 'Enabled', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function macForm(row) {
  openForm({
    title: row ? 'Edit MAC filter' : 'Add MAC filter',
    action: 'save_mac_filter',
    id: row && row.id,
    values: row || { mode: 'allow', enabled: 1 },
    fields: [
      { name: 'name', label: 'Name', required: true, max: 80 },
      { name: 'mac', label: 'MAC address', required: true, max: 32 },
      { name: 'mode', label: 'Mode', type: 'select', options: FILTER_MODES },
      { name: 'enabled', label: 'Enabled', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function scheduleForm(row) {
  openForm({
    title: row ? 'Edit access schedule' : 'Add access schedule',
    action: 'save_access_schedule',
    id: row && row.id,
    values: row || { days: 'Mon-Fri', start_time: '22:00', end_time: '07:00', action: 'block', enabled: 1 },
    hint: 'Target can be a device name, IP, MAC, or group label.',
    fields: [
      { name: 'name', label: 'Name', required: true, max: 80 },
      { name: 'target', label: 'Target', required: true, max: 120 },
      { name: 'days', label: 'Days', required: true, max: 40 },
      { name: 'start_time', label: 'Start time', required: true, max: 8 },
      { name: 'end_time', label: 'End time', required: true, max: 8 },
      { name: 'action', label: 'Action', type: 'select', options: SCHEDULE_ACTIONS },
      { name: 'enabled', label: 'Enabled', type: 'checkbox' },
      { name: 'notes', label: 'Notes', type: 'textarea', max: 500 }
    ]
  });
}

function arm(btn, labelText) {
  if (btn.dataset.armed === '1') return true;
  const previous = btn.textContent;
  btn.dataset.armed = '1';
  btn.textContent = labelText;
  setTimeout(() => {
    btn.dataset.armed = '0';
    btn.textContent = previous;
  }, 4000);
  return false;
}

function closeAllMoreMenus() {
  document.querySelectorAll('.more-menu.open').forEach((menu) => {
    menu.classList.remove('open');
    const panel = menu.querySelector('.more-panel');
    if (panel) panel.hidden = true;
    const toggle = menu.querySelector('[data-act="toggle-more"]');
    if (toggle) toggle.setAttribute('aria-expanded', 'false');
  });
}

async function onClick(event) {
  const btn = event.target.closest('[data-act]');
  if (!btn || saving) return;
  const act = btn.dataset.act;
  const id = btn.dataset.id;
  if (act === 'close') { closeDrawer(); return; }
  if (act === 'toggle-more') {
    event.preventDefault();
    event.stopPropagation();
    const menu = btn.closest('.more-menu');
    if (!menu) return;
    const open = menu.classList.contains('open');
    closeAllMoreMenus();
    if (!open) {
      menu.classList.add('open');
      const panel = menu.querySelector('.more-panel');
      if (panel) panel.hidden = false;
      btn.setAttribute('aria-expanded', 'true');
    }
    return;
  }
  if (btn.closest('.more-panel')) {
    closeAllMoreMenus();
  }
  if (act === 'view-device-live') {
    const device = findRow(state.devices, id);
    if (!device) return toast('Device not found.', 'bad');
    if (!liveTrafficEnabled) {
      liveTrafficEnabled = true;
      render();
    }
    openDeviceLive(device);
    return;
  }
  if (act === 'install-agent') {
    return createDeviceAgent(id);
  }
  if (act === 'revoke-agent') {
    if (!arm(btn, 'Click again to remove')) return;
    return run({ action: 'revoke_device_agent', id: Number(id) });
  }
  if (act === 'toggle-live-traffic') {
    liveTrafficEnabled = !liveTrafficEnabled;
    if (liveTrafficEnabled) {
      toast('Live usage enabled.');
      startTrafficPoll(true);
    } else {
      stopTrafficPoll();
      toast('Live usage paused.');
    }
    render();
    return;
  }
  if (act === 'open-router') {
    return openRouterAdmin();
  }
  if (act === 'router-connect-form') {
    return openRouterConnectForm();
  }
  if (act === 'router-probe') {
    return run({ action: 'router_probe' });
  }
  if (act === 'router-sync-devices') {
    return run({ action: 'router_sync_devices' });
  }
  if (act === 'router-sync-upnp') {
    return run({ action: 'router_sync_upnp' });
  }
  if (act === 'router-tab') {
    routerTab = btn.dataset.tab || 'status';
    render();
    return;
  }
  if (act === 'reload') { await load(); toast('Refreshed.'); return; }
  if (act === 'reload-traffic') {
    try {
      await fetchTraffic(liveDeviceId);
      toast('Traffic refreshed.');
    } catch (err) {
      toast(err.message || 'Could not refresh traffic.', 'bad');
    }
    return;
  }
  if (act === 'copy') {
    const value = btn.dataset.value || '';
    if (!value) {
      toast('Nothing to copy.', 'bad');
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(() => toast('Copied.'), () => toast('Could not copy.', 'bad'));
    } else {
      toast('Could not copy.', 'bad');
    }
    return;
  }
  if (act === 'refresh-snaps') {
    document.querySelectorAll('img.snap').forEach((img) => {
      const base = img.dataset.src;
      if (!base) return;
      img.src = base + (base.indexOf('?') === -1 ? '?' : '&') + 'pnet=' + Date.now();
    });
    return;
  }
  if (act === 'add-device') return deviceForm(null);
  if (act === 'edit-device') return deviceForm(findRow(state.devices, id));
  if (act === 'add-rule') return ruleForm(null);
  if (act === 'edit-rule') return ruleForm(findRow(state.rules, id));
  if (act === 'add-site') return siteForm(null);
  if (act === 'edit-site') return siteForm(findRow(state.sites, id));
  if (act === 'add-ip') return ipForm(null);
  if (act === 'edit-ip') return ipForm(findRow(state.ips, id));
  if (act === 'add-alert') return alertForm(null);
  if (act === 'edit-alert') return alertForm(findRow(state.alerts, id));
  if (act === 'add-camera') return cameraForm(null);
  if (act === 'edit-camera') return cameraForm(findRow(state.cameras, id));
  if (act === 'add-forward') return forwardForm(null);
  if (act === 'edit-forward') return forwardForm(findRow(state.port_forwards, id));
  if (act === 'add-dhcp') return dhcpForm(null);
  if (act === 'edit-dhcp') return dhcpForm(findRow(state.dhcp_reservations, id));
  if (act === 'add-mac') return macForm(null);
  if (act === 'edit-mac') return macForm(findRow(state.mac_filters, id));
  if (act === 'add-schedule') return scheduleForm(null);
  if (act === 'edit-schedule') return scheduleForm(findRow(state.access_schedules, id));
  if (act === 'toggle-rule') return run({ action: 'toggle_rule', id: Number(id) });
  if (act === 'toggle-site') return run({ action: 'toggle_site', id: Number(id) });
  if (act === 'toggle-ad-block') {
    const next = state.settings.ad_block_enabled !== '1';
    return run({ action: 'set_ad_block', enabled: next ? 1 : 0 });
  }
  if (act === 'refresh-ad-block') {
    return run({ action: 'set_ad_block', enabled: 1 });
  }
  if (act === 'toggle-adult-block') {
    const next = state.settings.adult_block_enabled !== '1';
    return run({ action: 'set_adult_block', enabled: next ? 1 : 0 });
  }
  if (act === 'refresh-adult-block') {
    return run({ action: 'set_adult_block', enabled: 1 });
  }
  if (act === 'toggle-category') {
    const cat = btn.dataset.cat || '';
    const next = state.settings[cat + '_block_enabled'] !== '1';
    return run({ action: 'set_category_block', category: cat, enabled: next ? 1 : 0 });
  }
  if (act === 'clear-exception') {
    return run({ action: 'set_block_exception', device_id: Number(id), category: btn.dataset.cat || '', allow: 0 });
  }
  if (act === 'apply-hosts') {
    return applyHostsOnPc();
  }
  if (act === 'start-dns') {
    return startNetworkDns();
  }
  if (act === 'stop-dns') {
    return stopNetworkDns();
  }
  if (act === 'sync-dns') {
    return syncNetworkDns();
  }
  if (act === 'push-wifi-dns') {
    return pushWifiDns();
  }
  if (act === 'pull-wifi-dns') {
    return pullWifiDns();
  }
  if (act === 'push-router-dns') {
    return pushDnsToRouter();
  }
  if (act === 'use-pnet-dns') {
    return run({ action: 'use_pnet_dns' });
  }
  if (act === 'toggle-forward') return run({ action: 'toggle_port_forward', id: Number(id) });
  if (act === 'toggle-dhcp') return run({ action: 'toggle_dhcp_reservation', id: Number(id) });
  if (act === 'toggle-mac') return run({ action: 'toggle_mac_filter', id: Number(id) });
  if (act === 'toggle-schedule') return run({ action: 'toggle_access_schedule', id: Number(id) });
  if (act === 'protect-device') return run({ action: 'protect_device', id: Number(id) });
  if (act === 'resume-device') return run({ action: 'set_device_access', id: Number(id), access_profile: 'normal' });
  if (act === 'quarantine-device') {
    if (!arm(btn, 'Click again to quarantine')) return;
    return run({ action: 'set_device_access', id: Number(id), access_profile: 'quarantined' });
  }
  if (act === 'ack-alert') return run({ action: 'set_alert_status', id: Number(id), status: 'acknowledged' });
  if (act === 'resolve-alert') return run({ action: 'set_alert_status', id: Number(id), status: 'resolved' });
  if (act === 'check') return run({ action: 'check_host', kind: btn.dataset.kind, id: Number(id) });
  if (act === 'wake-device') return run({ action: 'wake_device', id: Number(id) });
  if (act === 'check-all') {
    const targets = state.devices.filter((d) => d.ip);
    if (!targets.length) {
      toast('No devices to check.', 'bad');
      return;
    }
    toast(`Checking ${targets.length} device${targets.length === 1 ? '' : 's'}…`);
    saving = true;
    document.body.classList.add('busy');
    try {
      let online = 0;
      for (const device of targets) {
        const data = await post({ action: 'check_host', kind: 'device', id: Number(device.id) });
        if (data.state) state = data.state;
        const updated = findRow(state.devices, device.id);
        if (updated && updated.status === 'online') online += 1;
      }
      render();
      toast(`Check complete. ${online} online.`);
    } catch (err) {
      toast(err.message, 'bad');
      render();
    } finally {
      saving = false;
      document.body.classList.remove('busy');
    }
    return;
  }
  if (act === 'toggle-auto-refresh') {
    autoRefreshEnabled = !autoRefreshEnabled;
    if (autoRefreshEnabled) {
      autoRefreshInterval = setInterval(load, 30000);
      toast('Auto-refresh enabled (30s)');
    } else {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
      toast('Auto-refresh disabled');
    }
    render();
    return;
  }
  if (act === 'discover') {
    return discoverDevices(true);
  }
  if (act === 'port-scan') {
    toast('Port scan started. This may take a moment...');
    return run({ action: 'port_scan' });
  }
  if (act === 'scan') return run({ action: 'defender_scan' });
  if (act === 'clear-sample') {
    if (!arm(btn, 'Click again to remove')) return;
    return run({ action: 'clear_sample' });
  }
  const deletes = {
    'delete-device': 'delete_device',
    'delete-rule': 'delete_rule',
    'delete-site': 'delete_site',
    'delete-ip': 'delete_ip',
    'delete-alert': 'delete_alert',
    'delete-camera': 'delete_camera',
    'delete-forward': 'delete_port_forward',
    'delete-dhcp': 'delete_dhcp_reservation',
    'delete-mac': 'delete_mac_filter',
    'delete-schedule': 'delete_access_schedule'
  };
  if (deletes[act]) {
    if (!arm(btn, 'Click again to delete')) return;
    return run({ action: deletes[act], id: Number(id) });
  }
}

async function onSubmit(event) {
  const form = event.target.closest('form[data-action]');
  if (!form) return;
  event.preventDefault();
  const body = { action: form.dataset.action };
  if (form.dataset.id) body.id = Number(form.dataset.id);
  form.querySelectorAll('[name]').forEach((el) => {
    if (el.type === 'checkbox') body[el.name] = el.checked ? 1 : 0;
    else body[el.name] = el.type === 'password' ? el.value : el.value.trim();
  });
  const ok = await run(body);
  if (ok && form.dataset.action === 'router_connect') {
    await openRouterAdmin();
  }
}

function showDiscoveryProgress() {
  main.innerHTML = '<div class="discovery-progress"><div class="spinner"></div><p>Scanning your Wi-Fi for devices…</p></div>';
}

async function discoverDevices(manual) {
  if (saving) return;
  saving = true;
  document.body.classList.add('busy');
  if (manual || ['wifi', 'network', 'overview'].includes(currentView())) {
    showDiscoveryProgress();
  }
  try {
    const data = await post({ action: 'find_devices' });
    state = data.state;
    render();
    toast(data.message || 'Scan complete.');
  } catch (err) {
    render();
    toast(err.message || 'Could not scan devices.', 'bad');
  } finally {
    saving = false;
    document.body.classList.remove('busy');
  }
}

async function autoDiscoverIfNeeded() {
  if (scanAttempted || !state || state.devices.length > 0) return;
  scanAttempted = true;
  await discoverDevices(false);
}

async function probeRouterIfNeeded() {
  const access = state?.router?.access;
  if (!access?.admin_url) return;
  const lastMs = access.last_probe ? Date.parse(String(access.last_probe).replace(' ', 'T')) : 0;
  const stale = !lastMs || Number.isNaN(lastMs) || Date.now() - lastMs > 300000;
  if (access.reachable && !stale) return;
  try {
    await post({ action: 'router_probe' });
    render();
  } catch (_) {
    /* ignore background probe errors */
  }
}

async function load() {
  const res = await fetch('api.php?action=state', { cache: 'no-store' });
  const data = await res.json().catch(() => ({ ok: false, error: 'PNet returned an unreadable response.' }));
  if (!data.ok) throw new Error(data.error || 'Could not load.');
  state = data.state;
  bindRouterLoginCapture();
  render();
  autoDiscoverIfNeeded();
  probeRouterIfNeeded();
}

document.body.addEventListener('click', (event) => {
  if (!event.target.closest('.more-menu')) {
    closeAllMoreMenus();
  }
  onClick(event);
});
document.body.addEventListener('submit', onSubmit);
document.body.addEventListener('change', async (event) => {
  const input = event.target.closest('#backup-file');
  if (!input || !input.files || !input.files[0]) return;
  const file = input.files[0];
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    await run({ action: 'import_backup', backup: JSON.stringify(parsed) });
  } catch (err) {
    toast(err.message || 'The backup file could not be imported.', 'bad');
  } finally {
    input.value = '';
  }
});
window.addEventListener('hashchange', () => {
  closeDrawer();
  if (currentView() !== 'network') {
    liveTrafficEnabled = false;
  }
  render();
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    closeAllMoreMenus();
    closeDrawer();
  }
});
drawer.addEventListener('click', (event) => {
  if (event.target === drawer) closeDrawer();
});
document.body.addEventListener('error', (event) => {
  const img = event.target;
  if (!img.classList || !img.classList.contains('snap')) return;
  const miss = document.createElement('div');
  miss.className = 'snap-miss';
  miss.textContent = 'Snapshot unavailable';
  img.replaceWith(miss);
}, true);

load().catch((err) => {
  main.innerHTML = `<div class="panel"><h2>Could not load</h2><p class="lead">${esc(err.message)}</p></div>`;
});
