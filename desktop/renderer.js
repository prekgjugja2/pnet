const rows = document.getElementById('rows');
const meta = document.getElementById('meta');
const status = document.getElementById('status');
const btnScan = document.getElementById('btn-scan');
const btnPorts = document.getElementById('btn-ports');

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function setBusy(on, message) {
  btnScan.disabled = on;
  btnPorts.disabled = on;
  status.hidden = !on;
  status.innerHTML = on ? `<span class="spinner"></span>${esc(message || 'Scanning…')}` : '';
}

function render(data) {
  meta.textContent = `${data.lan_cidr || 'LAN'} · gateway ${data.gateway || '—'} · ${data.device_count || 0} devices · engine ${window.__engine || ''}`;
  const list = data.devices || [];
  if (!list.length) {
    rows.innerHTML = `<tr><td colspan="6" class="empty">No devices found.</td></tr>`;
    return;
  }
  rows.innerHTML = list.map((d) => {
    const ports = (d.open_ports || []).join(', ') || '—';
    return `<tr>
      <td><div class="name">${esc(d.hostname || d.ip)}</div><div class="type">${esc(d.type || 'other')}</div></td>
      <td class="mono">${esc(d.ip)}</td>
      <td class="mono">${esc(d.mac || '—')}</td>
      <td>${esc(d.vendor || '—')}</td>
      <td><span class="badge ${d.online ? '' : 'off'}">${d.online ? (d.ping_ms != null ? d.ping_ms + ' ms' : 'online') : 'offline'}</span></td>
      <td class="mono">${esc(ports)}</td>
    </tr>`;
  }).join('');
}

async function scan(ports) {
  setBusy(true, ports ? 'Scanning Wi‑Fi + ports…' : 'Scanning your Wi‑Fi…');
  try {
    if (!window.__engine) {
      window.__engine = await window.pnet.enginePath();
    }
    const data = await window.pnet.scan({ ports: !!ports });
    if (!data.ok) throw new Error(data.error || 'Scan failed');
    render(data);
  } catch (err) {
    rows.innerHTML = `<tr><td colspan="6" class="empty">${esc(err.message)}</td></tr>`;
    meta.textContent = err.message;
  } finally {
    setBusy(false);
  }
}

btnScan.addEventListener('click', () => scan(false));
btnPorts.addEventListener('click', () => scan(true));

window.pnet.enginePath().then((p) => {
  window.__engine = p;
  const short = String(p).split(/[/\\]/).slice(-2).join('/');
  meta.textContent = `Ready · engine ${short} · click Discover devices`;
}).catch(() => {
  meta.textContent = 'Ready · click Discover devices';
});

// Auto-scan on first open so the app feels alive after install
scan(false);
