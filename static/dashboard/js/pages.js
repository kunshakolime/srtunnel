let _logStreamTimer = null;
const LOG_STREAM_INTERVAL = 4_000;

function startLogStream() {
  stopLogStream();
  _logStreamTimer = setInterval(_tickLogStream, LOG_STREAM_INTERVAL);
}

function stopLogStream() {
  clearInterval(_logStreamTimer);
  _logStreamTimer = null;
}

async function _tickLogStream() {
  if (document.hidden) return;
  if (_svcMode === 'systemd') {
    for (const key of _expandedLogs) {
      if (key.startsWith('sys-')) _fetchSystemdLog(key.slice(4));
    }
    return;
  }
  const res = await apiFetch(`/api/services?lines=${_svcLogLines}`).catch(() => null);
  if (!res?.ok) return;
  const d = await res.json();
  for (const s of (d.services || [])) {
    if (!_expandedLogs.has(s.name)) continue;
    const el = document.getElementById('log-' + s.name);
    if (!el) continue;
    const pre = el.querySelector('pre');
    if (pre) pre.textContent = (s.log || []).join('\n') || '(no output)';
  }
}

// ── Services ──────────────────────────────────────────────────────────────────

let _svcLogLines = 20;
let _expandedLogs = new Set();
let _svcData = [];
let _svcMode = 'tmux';

async function loadServices() {
  const el = document.getElementById('servicesList');
  el.innerHTML = '<p class="empty-state"><span class="spinner"></span></p>';

  const res = await apiFetch(`/api/services?lines=${_svcLogLines}`);
  if (!res.ok) { el.innerHTML = '<p class="empty-state">Could not load services</p>'; return; }
  const d = await res.json();

  const badge = document.getElementById('watcher-badge');
  const toggleBtn = document.getElementById('watcher-toggle-btn');
  if (d.watcher) {
    badge.textContent = '● Watcher ON';
    badge.style.background = 'rgba(52,199,106,.15)';
    badge.style.color = 'var(--green)';
    toggleBtn.textContent = 'Stop Watcher';
    toggleBtn.className = 'btn-sm btn-danger';
  } else {
    badge.textContent = '○ Watcher OFF';
    badge.style.background = 'rgba(240,64,96,.12)';
    badge.style.color = 'var(--red)';
    toggleBtn.textContent = 'Start Watcher';
    toggleBtn.className = 'btn-sm btn-green';
  }

  const services = d.services || [];
  _svcData = services;
  if (!services.length) { el.innerHTML = '<p class="empty-state">No services configured</p>'; return; }

  const logSel = `
    <div class="svc-log-lines">
      <span class="lbl">Lines:</span>
      ${[10,20,50,100].map(n => `
        <button class="btn-sm svc-lines-btn${_svcLogLines===n?' active':''}"
          onclick="_svcLogLines=${n};loadServices()">${n}</button>
      `).join('')}
    </div>`;

  startLogStream();
  el.innerHTML = logSel + services.map(s => {
    const logOpen = _expandedLogs.has(s.name);
    const statusColor = {keep:'var(--green)', enable:'var(--blue)', disable:'var(--text3)'}[s.status] || 'var(--text3)';
    const statusLabel = {keep:'keep-alive', enable:'run once', disable:'disabled'}[s.status] || s.status;
    const logLines = (s.log || []).join('\n') || '(no output)';

    return `
      <div class="svc-card">
        <div class="svc-card-header">
          <div class="svc-card-left">
            <span class="svc-dot" style="color:${s.running ? 'var(--green)' : 'var(--red)'}">${s.running ? '●' : '○'}</span>
            <span class="svc-name">${s.name}</span>
            <span class="svc-badge" style="background:${statusColor}1a;color:${statusColor}">${statusLabel}</span>
          </div>
          <div class="svc-card-right">
            ${s.running
              ? `<button class="btn-sm" onclick="svcAction('${s.name}','reload')">⟲ Reload</button>
                 <button class="btn-sm" onclick="svcAction('${s.name}','restart')">↺ Restart</button>
                 <button class="btn-danger btn-icon" onclick="svcAction('${s.name}','stop')">■ Stop</button>`
              : `<button class="btn-green btn-sm" onclick="svcAction('${s.name}','start')">▶ Start</button>`
            }
            <select class="btn-sm" style="padding:5px 8px;font-size:11px;font-family:var(--font-mono)"
              onchange="setSvcStatus('${s.name}',this.value)">
              <option value="keep"    ${s.status==='keep'   ?'selected':''}>keep</option>
              <option value="enable"  ${s.status==='enable' ?'selected':''}>once</option>
              <option value="disable" ${s.status==='disable'?'selected':''}>off</option>
            </select>
            <button class="btn-sm" style="font-size:11px" onclick="toggleLog('${s.name}')" id="logbtn-${s.name}">${logOpen ? '▲' : '▼'}</button>
          </div>
        </div>
          <div class="svc-log-wrap" id="log-${s.name}" style="display:${logOpen ? 'block' : 'none'}">
            <pre>${escHtml(logLines)}</pre>
          </div>
      </div>`;
  }).join('');
  filterServices();
}

function toggleLog(name) {
  if (_expandedLogs.has(name)) _expandedLogs.delete(name);
  else _expandedLogs.add(name);
  const el  = document.getElementById('log-' + name);
  const btn = document.getElementById('logbtn-' + name);
  if (el)  el.style.display = _expandedLogs.has(name) ? 'block' : 'none';
  if (btn) btn.textContent  = _expandedLogs.has(name) ? '▲ Hide Log' : '▼ Log';
  if (_expandedLogs.has(name) && name.startsWith('sys-') && _svcMode === 'systemd') {
    _fetchSystemdLog(name.slice(4));
  }
}

function filterServices() {
  const q = document.getElementById('svcSearch').value.toLowerCase();
  const x = document.querySelector('.svc-search-x');
  if (x) x.classList.toggle('visible', q.length > 0);
  const cards = document.querySelectorAll('#servicesList .card');
  cards.forEach((card, i) => {
    if (i >= _svcData.length) return;
    card.style.display = _svcData[i].name.toLowerCase().includes(q) ? '' : 'none';
  });
}

function switchSvcMode(mode) {
  _svcMode = mode;
  document.querySelectorAll('.svc-mode').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
  const watcherBadge = document.getElementById('watcher-badge');
  const watcherBtn   = document.getElementById('watcher-toggle-btn');
  if (mode === 'systemd') {
    watcherBadge.style.display = 'none';
    watcherBtn.style.display   = 'none';
    loadSystemdUnits();
  } else {
    watcherBadge.style.display = '';
    watcherBtn.style.display   = '';
    loadServices();
  }
}

async function loadSystemdUnits() {
  const el = document.getElementById('servicesList');
  el.innerHTML = '<p class="empty-state"><span class="spinner"></span></p>';
  const res = await apiFetch('/api/systemd');
  if (!res.ok) { el.innerHTML = '<p class="empty-state">Could not load systemd units</p>'; return; }
  const d = await res.json();
  const units = d.units || [];
  _svcData = units.map(u => ({ name: u.name }));
  stopLogStream();
  el.innerHTML = units.map(u => {
    const running = u.active === 'active';
    const statusColor = running ? 'var(--green)' : u.active === 'failed' ? 'var(--red)' : 'var(--text3)';
    return `
      <div class="svc-card">
        <div class="svc-card-header">
          <div class="svc-card-left">
            <span class="svc-dot" style="color:${running ? 'var(--green)' : 'var(--red)'}">${running ? '●' : '○'}</span>
            <span class="svc-name">${u.name}</span>
            <span class="svc-badge" style="background:${statusColor}1a;color:${statusColor}">${u.active}/${u.sub}</span>
            <span style="font-size:10px;color:var(--text3);font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px">${u.description}</span>
          </div>
          <div class="svc-card-right">
            ${running
              ? `<button class="btn-sm" onclick="systemdAction('${u.name}','restart')">↺ Restart</button>
                 <button class="btn-danger btn-icon" onclick="systemdAction('${u.name}','stop')">■ Stop</button>`
              : `<button class="btn-green btn-sm" onclick="systemdAction('${u.name}','start')">▶ Start</button>`
            }
            <button class="btn-sm" style="font-size:11px" onclick="toggleLog('sys-${u.name}')" id="logbtn-sys-${u.name}">▼</button>
          </div>
        </div>
        <div class="svc-log-wrap" id="log-sys-${u.name}" style="display:none">
          <pre></pre>
        </div>
      </div>`;
  }).join('');
  for (const name of _expandedLogs) {
    if (name.startsWith('sys-')) _fetchSystemdLog(name.slice(4));
  }
  filterServices();
}

async function _fetchSystemdLog(name) {
  const el = document.getElementById('log-sys-' + name);
  if (!el) return;
  const pre = el.querySelector('pre');
  const res = await apiFetch(`/api/systemd/${name}/logs?lines=${_svcLogLines}`);
  if (res.ok) { const d = await res.json(); pre.textContent = (d.log || []).join('\n') || '(no output)'; }
}

async function systemdAction(name, action) {
  const res = await apiFetch(`/api/systemd/${name}/${action}`, { method: 'POST' });
  if (res.ok) { toast(`${name}: ${action}`); loadSystemdUnits(); }
  else { const d = await res.json(); toast(d.detail || 'Failed', 'err'); }
}

async function svcAction(name, action) {
  const res = await apiFetch(`/api/services/${name}/${action}`, { method: 'POST' });
  if (res.ok) { toast(`${name}: ${action}`); loadServices(); }
  else { const d = await res.json(); toast(d.detail || 'Failed', 'err'); }
}

async function setSvcStatus(name, status) {
  const res = await apiFetch(`/api/services/${name}/status`, {
    method: 'POST',
    body: JSON.stringify({ status })
  });
  if (res.ok) toast(`${name} → ${status}`);
  else { const d = await res.json(); toast(d.detail || 'Failed', 'err'); loadServices(); }
}

async function toggleWatcher() {
  const badge = document.getElementById('watcher-badge');
  const isOn  = badge.textContent.includes('ON');
  const res   = await apiFetch(`/api/services/watcher/${isOn ? 'stop' : 'start'}`, { method: 'POST' });
  if (res.ok) loadServices();
  else toast('Failed', 'err');
}

// ── Speed Test ────────────────────────────────────────────────────────────────

let _stRunning = false;

async function runSpeedtest() {
  if (_stRunning) return;
  _stRunning = true;
  const btn = document.getElementById('st-btn');
  const fill = document.getElementById('st-fill');
  const pct = document.getElementById('st-pct');
  const status = document.getElementById('st-status');
  const results = document.getElementById('st-results');

  btn.disabled = true;
  btn.textContent = '⏳ Running…';
  results.style.display = 'none';
  status.textContent = 'Starting speed test…';
  fill.style.width = '5%';
  pct.textContent = '5%';

  let fake = 5;
  const fakeInterval = setInterval(() => {
    if (fake < 85) { fake += Math.random() * 3; fill.style.width = fake + '%'; pct.textContent = Math.round(fake) + '%'; }
  }, 800);

  try {
    const res = await apiFetch('/api/speedtest');
    clearInterval(fakeInterval);
    fill.style.width = '100%'; pct.textContent = '100%';
    if (!res.ok) { status.textContent = '❌ Speed test failed'; }
    else {
      const d = await res.json();
      status.textContent = `✅ ${d.server_name || 'Test'} — ${d.server_location || ''} · ${d.isp || ''}`;
      results.style.display = 'grid';
      results.innerHTML = `
        <div class="speed-card">
          <div class="speed-val">${d.dl_mbps ? (d.dl_mbps >= 1000 ? (d.dl_mbps/1000).toFixed(2)+' <span style="font-size:14px">Gbps</span>' : d.dl_mbps.toFixed(1)) : '—'}</div>
          <div class="speed-unit">Download ↓ Mbps</div>
          <div style="font-size:11px;color:var(--text3);margin-top:6px">lat ${d.dl_lat_iqm?.toFixed(2)} ms · jitter ${d.dl_lat_jitter?.toFixed(2)} ms</div>
        </div>
        <div class="speed-card">
          <div class="speed-val">${d.ul_mbps ? (d.ul_mbps >= 1000 ? (d.ul_mbps/1000).toFixed(2)+' <span style="font-size:14px">Gbps</span>' : d.ul_mbps.toFixed(1)) : '—'}</div>
          <div class="speed-unit">Upload ↑ Mbps</div>
          <div style="font-size:11px;color:var(--text3);margin-top:6px">lat ${d.ul_lat_iqm?.toFixed(2)} ms · jitter ${d.ul_lat_jitter?.toFixed(2)} ms</div>
        </div>
        <div class="speed-card">
          <div class="speed-val" style="font-size:22px">${d.ping_ms?.toFixed(2)} <span style="font-size:14px">ms</span></div>
          <div class="speed-unit">Ping</div>
          <div style="font-size:11px;color:var(--text3);margin-top:6px">jitter ${d.ping_jitter?.toFixed(3)} ms · loss ${d.packet_loss ?? 0}%</div>
        </div>
        <div class="speed-card">
          <div class="speed-val" style="font-size:16px;color:var(--text2)">${d.server_location || '—'}</div>
          <div class="speed-unit">Server — ${d.server_name || ''}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:6px">${d.external_ip || ''}</div>
        </div>
        ${d.result_url ? `<div style="grid-column:span 2;text-align:center;padding-top:4px">
          <a href="${d.result_url}" target="_blank" style="font-size:12px;color:var(--accent);font-family:var(--font-mono)">
            ↗ View full result on speedtest.net
          </a>
        </div>` : ''}
      `;
    }
  } catch (e) {
    clearInterval(fakeInterval);
    status.textContent = '❌ Request failed';
  }

  btn.disabled = false;
  btn.textContent = '▶ Run Again';
  _stRunning = false;
}

// ── DNS ───────────────────────────────────────────────────────────────────────

async function loadDns() {
  const res = await apiFetch('/api/dns');
  if (res.status === 503) {
    document.getElementById('dnsBody').innerHTML = '<tr><td colspan="5" class="empty-state">Cloudflare not configured — add cf_token and cf_zone to config.yaml</td></tr>';
    return;
  }
  if (!res.ok) { document.getElementById('dnsBody').innerHTML = '<tr><td colspan="5" class="empty-state">Error loading DNS records</td></tr>'; return; }
  const records = await res.json();
  document.getElementById('dnsBody').innerHTML = records.length
    ? records.map(r => `
        <tr>
          <td style="font-family:var(--font-mono);font-size:12px">${r.name}</td>
          <td><span class="badge" style="background:var(--bg4);color:var(--text2)">${r.type}</span></td>
          <td style="font-family:var(--font-mono);font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${r.content}</td>
          <td>${r.proxied ? '🟠 Proxied' : '⚪ DNS only'}</td>
          <td><button class="btn-danger btn-icon" onclick="deleteDns('${r.id}')">✕ Del</button></td>
        </tr>
      `).join('')
    : '<tr><td colspan="5" class="empty-state">No DNS records</td></tr>';
}

async function doCreateDns() {
  const body = {
    type: document.getElementById('dns_type').value,
    name: document.getElementById('dns_name').value,
    value: document.getElementById('dns_value').value,
    proxied: document.getElementById('dns_proxied').checked
  };
  if (!body.name || !body.value) { toast('Name and value required', 'err'); return; }
  const res = await apiFetch('/api/dns', { method: 'POST', body: JSON.stringify(body) });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast('DNS record created');
  closeModal('dnsModal');
  document.getElementById('dns_name').value = '';
  document.getElementById('dns_value').value = '';
  document.getElementById('dns_proxied').checked = false;
  loadDns();
}

async function deleteDns(id) {
  if (!confirm('Delete this DNS record?')) return;
  const res = await apiFetch(`/api/dns/${id}`, { method: 'DELETE' });
  if (res.ok) { toast('DNS record deleted'); loadDns(); }
  else { const d = await res.json(); toast(d.detail || 'Error', 'err'); }
}

// ── Backup ────────────────────────────────────────────────────────────────────

async function downloadBackup() {
  const res = await apiFetch('/api/backup');
  if (!res.ok) { toast('Database not found on server', 'err'); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'users.db'; a.click();
  URL.revokeObjectURL(url);
  toast('Download started');
}

async function handleDb(mode) {
  const inputId = mode === 'restore' ? 'dbFileRestore' : 'dbFileMerge';
  const file = document.getElementById(inputId).files[0];
  if (!file) { toast('Select a .db file first', 'err'); return; }
  if (!file.name.endsWith('.db')) { toast('File must be a .db file', 'err'); return; }
  const endpoint = mode === 'restore' ? '/api/restore-db' : '/api/merge-db';
  const label = mode === 'restore' ? 'Replace' : 'Merge';
  if (mode === 'restore' && !confirm('This will REPLACE the current database. Are you sure?')) return;

  const formData = new FormData();
  formData.append('file', file);
  const res = await apiFetch(endpoint, { method: 'POST', body: formData });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast(`Database ${label === 'Replace' ? 'restored' : 'merged'} successfully`);
  document.getElementById(inputId).value = '';
}

// ── Scope ─────────────────────────────────────────────────────────────────────

async function loadScope() {
  const res = await apiFetch('/api/scope');
  if (!res.ok) return;
  const d = await res.json();
  if (d.max_users)       document.getElementById('sc_max_users').value = d.max_users;
  if (d.default_expiry)  document.getElementById('sc_default_expiry').value = d.default_expiry;
  if (d.max_expiry)      document.getElementById('sc_max_expiry').value = d.max_expiry;
  if (d.max_connections) document.getElementById('sc_max_connections').value = d.max_connections;
  if (d.services) {
    document.getElementById('svc_ssh').checked = d.services.ssh_dropbear !== false;
  }
}

async function saveScope() {
  const body = {
    max_users:       parseInt(document.getElementById('sc_max_users').value) || null,
    default_expiry:  parseInt(document.getElementById('sc_default_expiry').value) || null,
    max_expiry:      parseInt(document.getElementById('sc_max_expiry').value) || null,
    max_connections: parseInt(document.getElementById('sc_max_connections').value) || null,
    services: { ssh_dropbear: document.getElementById('svc_ssh').checked }
  };
  const res = await apiFetch('/api/scope', { method: 'POST', body: JSON.stringify(body) });
  if (res.ok) toast('Scope saved');
  else toast('Save failed', 'err');
}


// ── Servers page ──────────────────────────────────────────────────────────────

function loadServersPage() {
  const homeCard = document.getElementById('homeServerCard');
  const listEl   = document.getElementById('serversList');
  const servers  = getServers();
  const activeId = getActiveId();

  // Home server banner
  homeCard.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px">
      <span style="font-size:18px">👑</span>
      <div>
        <div style="font-size:12px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:var(--text3);margin-bottom:3px">Home Server</div>
        <div style="font-size:13px;font-weight:500">${escHtml(localStorage.getItem('home_api') || '—')}</div>
        <div style="font-size:11px;color:var(--text3);margin-top:2px">This server stores your serverlist.json and is the source of truth for all saved servers.</div>
      </div>
    </div>`;

  // Server list table
  if (!servers.length) {
    listEl.innerHTML = '<div class="empty-state">No servers saved yet</div>';
    return;
  }

  listEl.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr><th></th><th>Name</th><th>API URL</th><th>Token</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          ${servers.map(s => {
            const isHome = s.url === localStorage.getItem('home_api');
            return `<tr>
              <td>${isHome ? '<span title="Home server">👑</span>' : ''}</td>
              <td style="font-weight:500">${escHtml(s.name)}</td>
              <td>
                <span class="mono-cell" title="Click to copy" onclick="navigator.clipboard.writeText('${escHtml(s.url)}').then(()=>toast('URL copied'))" style="cursor:copy">${escHtml(s.url)}</span>
              </td>
              <td>
                <span class="mono-cell dimmed">···${escHtml(s.token?.slice(-8) || '—')}</span>
              </td>
              <td><div class="server-dot ${(_statusCache[s.url]?.online ? 'online' : _statusCache[s.url] ? 'offline' : 'checking')}" id="sp-dot-${s.id}" style="display:inline-block"></div></td>
              <td>
                <div style="display:flex;gap:6px">
                  <button class="btn-sm" onclick="switchServer('${s.id}');showPage('dashboard',document.querySelector('.nav button'))">Switch</button>
                  ${!isHome ? `<button class="btn-sm btn-danger-sm" onclick="hubRemoveServer('${s.id}')">Remove</button>` : ''}
                </div>
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;

}

// ── Tokens page ───────────────────────────────────────────────────────────────

async function loadTokens() {
  const el = document.getElementById('tokensList');
  el.innerHTML = '<div class="empty-state"><span class="spinner"></span></div>';
  const res = await apiFetch('/api/tokens');
  if (!res.ok) { el.innerHTML = '<div class="empty-state">Failed to load tokens</div>'; return; }
  const tokens = await res.json();

  if (!tokens.length) { el.innerHTML = '<div class="empty-state">No active tokens</div>'; return; }

  el.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Label</th><th>User</th><th>Created</th><th>Token</th><th>Actions</th></tr></thead>
        <tbody>
          ${tokens.map(t => {
            const isCurrent = t.token === TOKEN;
            const tid = 'tok-' + t.token.slice(-12).replace(/[^a-z0-9]/gi,'');
            return `
          <tr id="${tid}">
            <td style="font-weight:500">${escHtml(t.label)}${isCurrent ? ' <span style="font-size:10px;color:var(--accent)">(you)</span>' : ''}</td>
            <td><span class="badge badge-perm">${escHtml(t.user)}</span></td>
            <td style="font-size:12px;color:var(--text3)">${escHtml(t.created)}</td>
            <td>
              <span class="mono-cell dimmed token-val" style="cursor:copy" title="Click to copy"
                onclick="navigator.clipboard.writeText('${escHtml(t.token)}').then(()=>toast('Token copied'))">
                ···${escHtml(t.token.slice(-12))}
              </span>
            </td>
            <td>
              <button class="btn-danger" style="padding:5px 12px;font-size:12px" onclick="revokeToken('${escHtml(t.token)}', this)">Revoke</button>
            </td>
          </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;
}

async function revokeToken(token, btn) {
  btn.disabled = true;
  btn.textContent = '…';
  const res = await apiFetch('/api/tokens', {
    method: 'DELETE',
    body: JSON.stringify({ token })
  });
  if (res.ok) {
    toast('Token revoked');
    if (token === TOKEN) { setTimeout(logout, 800); return; }
    loadTokens();
  } else {
    toast('Failed to revoke', 'err');
    btn.disabled = false;
    btn.textContent = 'Revoke';
  }
}

// ── Service Actions ───────────────────────────────────────────────────────────

async function svcAction(name, action) {
  const res = await apiFetch(`/api/services/${name}/${action}`, { method: 'POST' });
  if (res.ok) {
    const d = await res.json();
    const actionDisplay = d.action || action.charAt(0).toUpperCase() + action.slice(1);
    toast(`${actionDisplay}: ${d.status}`);
    loadServices();
  } else {
    const d = await res.json();
    toast(d.detail || `${action} failed`, 'err');
  }
}

async function setSvcStatus(name, status) {
  const res = await apiFetch(`/api/services/${name}/status`, {
    method: 'POST',
    body: JSON.stringify({ status })
  });
  if (res.ok) {
    const d = await res.json();
    toast(`Status set to ${d.status}`);
    loadServices();
  } else {
    const d = await res.json();
    toast(d.detail || 'Status change failed', 'err');
  }
}

// ── Terminal ───────────────────────────────────────────────────────────────────

let _terminalLoaded = false;
let _currentTerminalSession = 'dashboard';

async function loadTerminal(force = false) {
  if (_terminalLoaded && !force) return;
  _terminalLoaded = true;
  await refreshTerminalSessions();
  attachTerminalIframe(_currentTerminalSession);
}

function attachTerminalIframe(sessionName) {
  _currentTerminalSession = sessionName || 'dashboard';
  const token = TOKEN || localStorage.getItem('home_token') || '';
  const el = document.getElementById('terminal-body');
  if (el) {
    el.innerHTML = `<iframe src="/api/terminal/?token=${encodeURIComponent(token)}&arg=${encodeURIComponent(_currentTerminalSession)}" style="width:100%;height:100%;border:none;background:#000"></iframe>`;
  }
}

async function refreshTerminalSessions() {
  try {
    const res = await apiFetch('/api/terminal/sessions');
    if (!res || !res.ok) return;
    const d = await res.json();
    if (d && d.sessions) {
      const sel = document.getElementById('terminal-session-select');
      if (sel) {
        sel.innerHTML = d.sessions.map(s => 
          `<option value="${escHtml(s)}" ${s === _currentTerminalSession ? 'selected' : ''}>${escHtml(s)}</option>`
        ).join('');
        if (!d.sessions.includes(_currentTerminalSession)) {
          _currentTerminalSession = d.sessions[0] || 'dashboard';
        }
        sel.value = _currentTerminalSession;
      }
    }
  } catch (e) {
    console.error('Failed to fetch terminal sessions', e);
  }
}

function switchTerminalSession(sessionName) {
  if (!sessionName) return;
  attachTerminalIframe(sessionName);
}

function promptNewTerminalSession() {
  const name = prompt('Enter new tmux session name:');
  if (!name) return;
  const sanitized = name.replace(/[^a-zA-Z0-9_-]/g, '');
  if (!sanitized) {
    toast('Invalid session name (only letters, numbers, -, _ allowed)', 'err');
    return;
  }
  _currentTerminalSession = sanitized;
  const sel = document.getElementById('terminal-session-select');
  if (sel && !Array.from(sel.options).some(o => o.value === sanitized)) {
    const opt = document.createElement('option');
    opt.value = sanitized;
    opt.textContent = sanitized;
    sel.appendChild(opt);
  }
  if (sel) sel.value = sanitized;
  attachTerminalIframe(sanitized);
}

function detachTerminalSession() {
  const el = document.getElementById('terminal-body');
  if (el) {
    el.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#888;">
        <p style="margin-bottom:12px;font-size:14px;font-family:var(--font-mono)">Detached from tmux session "${escHtml(_currentTerminalSession)}"</p>
        <button class="btn" onclick="attachTerminalIframe(_currentTerminalSession)">Re-attach</button>
      </div>
    `;
  }
  toast(`Detached from session "${_currentTerminalSession}"`, 'info');
}

