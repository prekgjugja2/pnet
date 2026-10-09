const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const https = require('https');

const WEB_URL = process.env.PNET_URL || 'http://localhost/pnet/';
const ROUTER_PARTITION = 'persist:pnet-router';

let routerWindow = null;
let routerAutofill = null;
let lastCapturedKey = '';
let lastCapturedAt = 0;

function enginePath() {
  const candidates = [
    path.join(process.resourcesPath || '', 'engine', 'pnet_scan.exe'),
    path.join(process.resourcesPath || '', 'pnet_scan.exe'),
    path.join(__dirname, '..', 'engine', 'build', 'pnet_scan.exe'),
    path.join(__dirname, 'engine', 'pnet_scan.exe'),
  ];
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

function iconPath() {
  return [
    path.join(__dirname, 'build', 'icon.ico'),
    path.join(__dirname, 'build', 'icon.png'),
    path.join(process.resourcesPath || '', 'build', 'icon.ico'),
  ].find((p) => fs.existsSync(p));
}

function isPrivateHost(hostname) {
  if (!hostname) return false;
  if (hostname === 'localhost' || hostname === '127.0.0.1') return true;
  const m = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  return a === 172 && b >= 16 && b <= 31;
}

function mainAppWindow() {
  return BrowserWindow.getAllWindows().find((w) => w !== routerWindow && !w.isDestroyed()) || null;
}

function notifyRouterLoginSaved(creds) {
  const username = String(creds.username || '').trim();
  const password = String(creds.password || '');
  const url = String(creds.url || '').trim();
  if (!password) return;
  const key = `${username}\n${password}\n${url}`;
  const now = Date.now();
  if (key === lastCapturedKey && now - lastCapturedAt < 5000) return;
  lastCapturedKey = key;
  lastCapturedAt = now;
  routerAutofill = { username, password, url };
  const win = mainAppWindow();
  if (win) {
    win.webContents.send('router-login-saved', { username, password, url });
  }
}

function configureRouterSession() {
  const ses = session.fromPartition(ROUTER_PARTITION);
  ses.setCertificateVerifyProc((request, callback) => {
    if (isPrivateHost(request.hostname)) {
      callback(0);
    } else {
      callback(-2);
    }
  });
  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    try {
      const headers = details.requestHeaders || {};
      const auth = headers.Authorization || headers.authorization || '';
      if (typeof auth === 'string' && /^Basic\s+/i.test(auth)) {
        const host = new URL(details.url).hostname;
        if (isPrivateHost(host)) {
          const decoded = Buffer.from(auth.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
          const idx = decoded.indexOf(':');
          if (idx >= 0) {
            notifyRouterLoginSaved({
              username: decoded.slice(0, idx),
              password: decoded.slice(idx + 1),
              url: details.url,
            });
          }
        }
      }
    } catch (_) {
      /* ignore */
    }
    callback({ requestHeaders: details.requestHeaders });
  });
}

function httpOk(url, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      res.resume();
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.on('error', () => resolve(false));
  });
}

function startApache() {
  const candidates = [
    'C:\\xampp\\apache_start.bat',
    'C:\\xampp\\apache\\bin\\httpd.exe',
    'C:\\xampp\\xampp_start.exe',
  ];
  for (const bin of candidates) {
    if (!fs.existsSync(bin)) continue;
    try {
      if (bin.endsWith('.exe') && bin.includes('httpd')) {
        spawn(bin, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      } else if (bin.endsWith('apache_start.bat')) {
        spawn('cmd.exe', ['/c', bin], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      } else {
        spawn(bin, [], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
      }
      return true;
    } catch (_) {
      /* try next */
    }
  }
  return false;
}

async function waitForWeb(maxMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    if (await httpOk(WEB_URL)) return true;
    await new Promise((r) => setTimeout(r, 700));
  }
  return false;
}

async function ensureWebReady() {
  if (await httpOk(WEB_URL)) return true;
  startApache();
  return waitForWeb(20000);
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#14120f',
    show: false,
    autoHideMenuBar: true,
    title: 'PNet',
    icon: iconPath(),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  win.once('ready-to-show', () => {
    win.show();
    win.focus();
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isPrivateHost(new URL(url).hostname)) {
      openRouterAdmin(url);
      return { action: 'deny' };
    }
    require('electron').shell.openExternal(url);
    return { action: 'deny' };
  });

  return win;
}

function attachRouterHandlers(win) {
  win.webContents.on('login', (event, _request, _authInfo, callback) => {
    if (routerAutofill && routerAutofill.password) {
      event.preventDefault();
      callback(routerAutofill.username || '', routerAutofill.password);
      return;
    }
    // Let Electron show the system login dialog; webRequest will capture Basic auth after.
  });
}

function openRouterAdmin(url, creds) {
  if (!url || typeof url !== 'string') {
    throw new Error('Router address missing.');
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    throw new Error('Router address is not valid.');
  }
  if (!isPrivateHost(parsed.hostname)) {
    throw new Error('Only home router addresses are allowed.');
  }
  if (creds && typeof creds === 'object' && creds.password) {
    routerAutofill = {
      username: String(creds.username || ''),
      password: String(creds.password || ''),
      url,
    };
  }
  if (routerWindow && !routerWindow.isDestroyed()) {
    routerWindow.loadURL(url);
    routerWindow.show();
    routerWindow.focus();
    return true;
  }
  routerWindow = new BrowserWindow({
    width: 1120,
    height: 760,
    minWidth: 800,
    minHeight: 560,
    backgroundColor: '#ffffff',
    autoHideMenuBar: true,
    title: 'Router',
    icon: iconPath(),
    webPreferences: {
      preload: path.join(__dirname, 'router-preload.js'),
      partition: ROUTER_PARTITION,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  attachRouterHandlers(routerWindow);
  routerWindow.on('closed', () => {
    routerWindow = null;
  });
  routerWindow.loadURL(url);
  routerWindow.once('ready-to-show', () => {
    routerWindow.show();
    routerWindow.focus();
  });
  return true;
}

async function loadApp(win) {
  const offline = path.join(__dirname, 'offline.html');
  win.loadFile(offline, { query: { status: 'starting' } });
  const ok = await ensureWebReady();
  if (ok) {
    await win.loadURL(WEB_URL);
    return;
  }
  await win.loadFile(offline, { query: { status: 'offline' } });
}

function applyHostsScriptPath() {
  const candidates = [
    path.join(process.resourcesPath || '', 'scripts', 'apply-pnet-hosts.ps1'),
    path.join(__dirname, '..', 'scripts', 'apply-pnet-hosts.ps1'),
  ];
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

function dnsScriptPath() {
  const candidates = [
    path.join(process.resourcesPath || '', 'scripts', 'pnet-dns.ps1'),
    path.join(__dirname, '..', 'scripts', 'pnet-dns.ps1'),
  ];
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

function dnsWorkDir() {
  const base = process.env.LOCALAPPDATA || app.getPath('userData');
  return path.join(base, 'PNet', 'AdGuardHome');
}

function downloadText(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    mod.get(url, { timeout: 120000 }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        downloadText(res.headers.location).then(resolve, reject);
        res.resume();
        return;
      }
      if (res.statusCode && res.statusCode >= 400) {
        res.resume();
        reject(new Error(`Download failed (${res.statusCode}).`));
        return;
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve(body));
    }).on('timeout', function onTimeout() {
      this.destroy();
      reject(new Error('Download timed out.'));
    }).on('error', reject);
  });
}

function runPowerShellFile(scriptPath, extraArgs, elevated) {
  return new Promise((resolve, reject) => {
    const psArgs = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...extraArgs];
    if (!elevated) {
      const child = spawn('powershell.exe', psArgs, { windowsHide: true });
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => { out += d.toString(); });
      child.stderr.on('data', (d) => { err += d.toString(); });
      child.on('error', reject);
      child.on('close', (code) => {
        if (code === 0) {
          resolve(out.trim());
          return;
        }
        reject(new Error(err.trim() || out.trim() || `Command failed (exit ${code}).`));
      });
      return;
    }
    const argList = psArgs.map((part) => `'${String(part).replace(/'/g, "''")}'`).join(', ');
    const command = `$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList @(${argList}); exit $p.ExitCode`;
    const child = spawn('powershell.exe', ['-NoProfile', '-Command', command], { windowsHide: true });
    let err = '';
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve('');
        return;
      }
      reject(new Error(err.trim() || `Admin action failed (exit ${code}). Did you approve the prompt?`));
    });
  });
}

function runElevatedPowerShell(scriptPath, extraArgs) {
  return runPowerShellFile(scriptPath, extraArgs, true);
}

async function dnsPrepareFromApi() {
  const url = WEB_URL.replace(/\/?$/, '/api.php?action=dns_prepare');
  const raw = await downloadText(url);
  const data = JSON.parse(raw);
  if (!data.ok || !data.dns) {
    throw new Error('Could not prepare DNS blocker files.');
  }
  return data.dns;
}

async function dnsStatusRaw() {
  const script = dnsScriptPath();
  const out = await runPowerShellFile(script, [
    '-Action', 'status',
    '-WorkDir', dnsWorkDir(),
  ], false);
  try {
    return JSON.parse(out);
  } catch (_) {
    return { ok: false, running: false, lan_ip: '', raw: out };
  }
}

function aghRequest(method, apiPath, body, cookie) {
  return new Promise((resolve, reject) => {
    const payload = body == null ? null : JSON.stringify(body);
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path: apiPath,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(cookie ? { Cookie: cookie } : {}),
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
      timeout: 15000,
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        const setCookie = res.headers['set-cookie'];
        let nextCookie = cookie || '';
        if (Array.isArray(setCookie) && setCookie[0]) {
          nextCookie = setCookie.map((c) => String(c).split(';')[0]).join('; ');
        }
        let parsed = null;
        try { parsed = data ? JSON.parse(data) : null; } catch (_) { parsed = data; }
        if (res.statusCode >= 400) {
          reject(new Error(`AdGuard Home API ${res.statusCode}: ${typeof parsed === 'string' ? parsed : data}`));
          return;
        }
        resolve({ status: res.statusCode, cookie: nextCookie, body: parsed });
      });
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('AdGuard Home API timed out.'));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function aghLogin(username, password) {
  const res = await aghRequest('POST', '/control/login', { name: username, password });
  if (!res.cookie) {
    throw new Error('AdGuard Home login failed.');
  }
  return res.cookie;
}

async function aghEnsureFilter(cookie, filters, url, name, enabled) {
  const found = filters.find((f) => f && (f.url === url || f.name === name));
  if (!found) {
    if (!enabled) return;
    await aghRequest('POST', '/control/filtering/add_url', {
      name,
      url,
      whitelist: false,
    }, cookie);
    return;
  }
  await aghRequest('POST', '/control/filtering/set_url', {
    url: found.url,
    data: {
      enabled: !!enabled,
      url: found.url,
      name: found.name || name,
    },
  }, cookie);
}

async function aghSyncFilters(meta) {
  const cookie = await aghLogin(meta.username || 'pnet', meta.password || 'pnet-dns');
  const rules = Array.isArray(meta.user_rules) ? meta.user_rules : [];
  await aghRequest('POST', '/control/filtering/set_rules', { rules }, cookie);
  try {
    const status = await aghRequest('GET', '/control/filtering/status', null, cookie);
    const filters = (status.body && status.body.filters) || [];
    const adUrl = meta.adguard_filter_url || 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt';
    const adultUrl = meta.adult_filter_url || 'https://blocklistproject.github.io/Lists/porn.txt';
    await aghEnsureFilter(cookie, filters, adUrl, 'AdGuard DNS filter', !!meta.ad_block_enabled);
    await aghEnsureFilter(cookie, filters, adultUrl, 'Adult sites', !!meta.adult_block_enabled);
  } catch (_) {
    /* optional */
  }
  try {
    await aghRequest('POST', '/control/safesearch/enable', { enabled: !!meta.adult_block_enabled }, cookie);
  } catch (_) {
    /* older AGH builds may differ */
  }
  try {
    await aghRequest('POST', '/control/filtering/refresh', { whitelist: false }, cookie);
  } catch (_) {
    /* older AGH builds may differ */
  }
  return true;
}

function runScan(args = ['--json']) {
  return new Promise((resolve, reject) => {
    const bin = enginePath();
    if (!fs.existsSync(bin)) {
      reject(new Error('Scanner engine missing.'));
      return;
    }
    const child = spawn(bin, args, {
      windowsHide: true,
      cwd: path.dirname(bin),
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => { err += d.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0 && !out) {
        reject(new Error(err || `Scanner exited with code ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(out.trim()));
      } catch (e) {
        reject(new Error('Scanner returned invalid JSON'));
      }
    });
  });
}

ipcMain.handle('scan-network', async (_evt, opts) => {
  const args = ['--json'];
  if (opts && opts.ports) args.push('--ports');
  if (opts && opts.cidr) args.push('--cidr', String(opts.cidr));
  return runScan(args);
});

ipcMain.handle('engine-path', async () => enginePath());
ipcMain.handle('open-webapp', async () => {
  const wins = BrowserWindow.getAllWindows().filter((w) => w !== routerWindow);
  if (!wins.length) return false;
  const ok = await ensureWebReady();
  if (ok) {
    await wins[0].loadURL(WEB_URL);
    return true;
  }
  return false;
});
ipcMain.handle('web-url', async () => WEB_URL);
ipcMain.handle('open-router-admin', async (_evt, url, creds) => openRouterAdmin(url, creds || null));
ipcMain.handle('router-autofill-creds', async () => routerAutofill);
ipcMain.handle('is-desktop', async () => true);
ipcMain.handle('apply-blocklist', async () => {
  const script = applyHostsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet apply script is missing.');
  }
  const exportUrl = WEB_URL.replace(/\/?$/, '/api.php?action=export_hosts');
  const blocklist = await downloadText(exportUrl);
  const matches = blocklist.match(/^0\.0\.0\.0 /gm);
  const count = matches ? matches.length : 0;
  if (count < 1) {
    throw new Error('Nothing to apply — block a site or turn on the ad blocker first.');
  }
  const tmp = path.join(app.getPath('temp'), `pnet-blocklist-${Date.now()}.txt`);
  fs.writeFileSync(tmp, blocklist, 'utf8');
  try {
    await runElevatedPowerShell(script, ['-BlocklistPath', tmp]);
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ }
  }
  return { ok: true, count };
});
ipcMain.handle('remove-blocklist', async () => {
  const script = applyHostsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet apply script is missing.');
  }
  await runElevatedPowerShell(script, ['-Remove']);
  return { ok: true };
});

ipcMain.handle('dns-status', async () => dnsStatusRaw());

ipcMain.handle('dns-start', async () => {
  const script = dnsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet DNS script is missing.');
  }
  const meta = await dnsPrepareFromApi();
  const args = [
    '-Action', 'start',
    '-WorkDir', dnsWorkDir(),
    '-SourceDir', meta.source_dir,
    '-FilterPath', meta.filter_path,
    '-PasswordHash', meta.password_hash,
  ];
  await runElevatedPowerShell(script, args);
  let status = await dnsStatusRaw();
  for (let i = 0; i < 10 && !status.running; i += 1) {
    await new Promise((r) => setTimeout(r, 700));
    status = await dnsStatusRaw();
  }
  if (status.running) {
    try {
      await aghSyncFilters(meta);
      status.synced = true;
    } catch (err) {
      status.synced = false;
      status.sync_error = err.message;
    }
  }
  status.lan_ip = meta.lan_ip || status.lan_ip || '';
  status.meta = {
    lan_ip: meta.lan_ip,
    ad_block_enabled: meta.ad_block_enabled,
    adult_block_enabled: meta.adult_block_enabled,
  };
  return status;
});

ipcMain.handle('dns-stop', async () => {
  const script = dnsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet DNS script is missing.');
  }
  await runElevatedPowerShell(script, [
    '-Action', 'stop',
    '-WorkDir', dnsWorkDir(),
  ]);
  return dnsStatusRaw();
});

ipcMain.handle('dns-sync', async () => {
  const meta = await dnsPrepareFromApi();
  const status = await dnsStatusRaw();
  if (!status.running) {
    throw new Error('Start the network blocker first.');
  }
  try {
    const dest = path.join(dnsWorkDir(), 'pnet-user-rules.txt');
    if (meta.filter_path && fs.existsSync(meta.filter_path)) {
      fs.copyFileSync(meta.filter_path, dest);
    }
  } catch (_) { /* ignore */ }
  await aghSyncFilters(meta);
  return { ok: true, running: true, lan_ip: meta.lan_ip || status.lan_ip || '', synced: true };
});

ipcMain.handle('dns-push-wifi', async () => {
  const script = dnsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet DNS script is missing.');
  }
  const meta = await dnsPrepareFromApi().catch(() => ({ lan_ip: '' }));
  await runElevatedPowerShell(script, [
    '-Action', 'push-wifi',
    '-WorkDir', dnsWorkDir(),
    '-DnsServer', '127.0.0.1',
  ]);
  const status = await dnsStatusRaw();
  status.lan_ip = meta.lan_ip || status.lan_ip || '';
  status.wifi_pushed = true;
  return status;
});

ipcMain.handle('dns-pull-wifi', async () => {
  const script = dnsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet DNS script is missing.');
  }
  const out = await runPowerShellFile(script, [
    '-Action', 'pull-wifi',
    '-WorkDir', dnsWorkDir(),
  ], false);
  try {
    return JSON.parse(out);
  } catch (_) {
    return { ok: false, wifi_dns: [], wifi_adapter: '', wifi_pushed: false };
  }
});

ipcMain.handle('dns-restore-wifi', async () => {
  const script = dnsScriptPath();
  if (!fs.existsSync(script)) {
    throw new Error('PNet DNS script is missing.');
  }
  await runElevatedPowerShell(script, [
    '-Action', 'restore-wifi',
    '-WorkDir', dnsWorkDir(),
  ]);
  return dnsStatusRaw();
});

ipcMain.on('router-login-captured', (_evt, creds) => {
  notifyRouterLoginSaved(creds || {});
});

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    const wins = BrowserWindow.getAllWindows().filter((w) => w !== routerWindow);
    if (wins.length) {
      if (wins[0].isMinimized()) wins[0].restore();
      wins[0].show();
      wins[0].focus();
    }
  });

  app.whenReady().then(async () => {
    configureRouterSession();
    const win = createWindow();
    await loadApp(win);
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      const win = createWindow();
      loadApp(win);
    }
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
