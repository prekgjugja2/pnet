const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('pnet', {
  isDesktop: true,
  scan: (opts) => ipcRenderer.invoke('scan-network', opts || {}),
  enginePath: () => ipcRenderer.invoke('engine-path'),
  openWebapp: () => ipcRenderer.invoke('open-webapp'),
  webUrl: () => ipcRenderer.invoke('web-url'),
  openRouterAdmin: (url, creds) => ipcRenderer.invoke('open-router-admin', url, creds || null),
  applyBlocklist: () => ipcRenderer.invoke('apply-blocklist'),
  removeBlocklist: () => ipcRenderer.invoke('remove-blocklist'),
  dnsStatus: () => ipcRenderer.invoke('dns-status'),
  dnsStart: () => ipcRenderer.invoke('dns-start'),
  dnsStop: () => ipcRenderer.invoke('dns-stop'),
  dnsSync: () => ipcRenderer.invoke('dns-sync'),
  dnsPushWifi: () => ipcRenderer.invoke('dns-push-wifi'),
  dnsPullWifi: () => ipcRenderer.invoke('dns-pull-wifi'),
  dnsRestoreWifi: () => ipcRenderer.invoke('dns-restore-wifi'),
  onRouterLoginSaved: (handler) => {
    if (typeof handler !== 'function') return () => {};
    const listener = (_event, creds) => handler(creds);
    ipcRenderer.on('router-login-saved', listener);
    return () => ipcRenderer.removeListener('router-login-saved', listener);
  },
});
