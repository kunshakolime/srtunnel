// ── Dashboard ─────────────────────────────────────────────────────────────────

const LOADING_HTML = '<div style="text-align:center;padding:40px"><span class="spinner"></span><div style="margin-top:10px;color:var(--text3)">Loading...</div></div>';

async function loadDashboard() {
  const metricsEl = document.getElementById('metrics');
  const spinEl = document.getElementById('dash-spin');
  if (spinEl) spinEl.classList.add('spinning');

  try {
    const res = await apiFetch('/api/system');
    if (!res.ok) {
      throw new Error('system failed: ' + res.status);
    }
    const d = await res.json();
    const cpu = Math.round(d.cpu || 0);
    const ram = Math.round(d.ram_percent || 0);
    const disk = Math.round(d.disk_percent || 0);
    const conns = d.connections || 0;

    function barColor(pct) {
      if (pct > 85) return 'var(--red)';
      if (pct > 60) return 'var(--yellow)';
      return 'var(--accent)';
    }

    if (!metricsEl.dataset.built) {
      metricsEl.innerHTML = `
        <div class="metric">
          <div class="metric-label">CPU</div>
          <div class="metric-value" id="m-cpu">${cpu}<span style="font-size:14px;color:var(--text3)">%</span></div>
          <div class="bar-wrap"><div class="bar" id="m-cpu-bar" style="width:${cpu}%;background:${barColor(cpu)}"></div></div>
        </div>
        <div class="metric">
          <div class="metric-label">RAM</div>
          <div class="metric-value" id="m-ram">${ram}<span style="font-size:14px;color:var(--text3)">%</span></div>
          <div class="metric-sub" id="m-ram-sub">${parseFloat(d.ram_used||0).toFixed(2)} / ${parseFloat(d.ram_total||0).toFixed(1)} GB</div>
          <div class="bar-wrap"><div class="bar" id="m-ram-bar" style="width:${ram}%;background:${barColor(ram)}"></div></div>
        </div>
        <div class="metric">
          <div class="metric-label">Disk</div>
          <div class="metric-value" id="m-disk">${disk}<span style="font-size:14px;color:var(--text3)">%</span></div>
          <div class="metric-sub" id="m-disk-sub">${parseFloat(d.disk_used||0).toFixed(2)} / ${parseFloat(d.disk_total||0).toFixed(1)} GB</div>
          <div class="bar-wrap"><div class="bar" id="m-disk-bar" style="width:${disk}%;background:${barColor(disk)}"></div></div>
        </div>
        <div class="metric">
          <div class="metric-label">Connections</div>
          <div class="metric-value connections-val" id="m-conns">${conns}</div>
          <div class="metric-sub" id="m-conns-sub">↓ ${d.bandwidth?.rx || '—'} · ↑ ${d.bandwidth?.tx || '—'}</div>
        </div>`;
      document.getElementById('m-ip').textContent = d.ip || '—';
      metricsEl.dataset.built = '1';
    } else {
      document.getElementById('m-cpu').childNodes[0].textContent = cpu;
      document.getElementById('m-cpu-bar').style.width = cpu + '%';
      document.getElementById('m-cpu-bar').style.background = barColor(cpu);
      document.getElementById('m-ram').childNodes[0].textContent = ram;
      document.getElementById('m-ram-bar').style.width = ram + '%';
      document.getElementById('m-ram-bar').style.background = barColor(ram);
      document.getElementById('m-ram-sub').textContent = `${parseFloat(d.ram_used||0).toFixed(2)} / ${parseFloat(d.ram_total||0).toFixed(1)} GB`;
      document.getElementById('m-disk').childNodes[0].textContent = disk;
      document.getElementById('m-disk-bar').style.width = disk + '%';
      document.getElementById('m-disk-bar').style.background = barColor(disk);
      document.getElementById('m-disk-sub').textContent = `${parseFloat(d.disk_used||0).toFixed(2)} / ${parseFloat(d.disk_total||0).toFixed(1)} GB`;
      document.getElementById('m-ip').textContent = d.ip || '—';
      document.getElementById('m-conns').textContent = conns;
      document.getElementById('m-conns-sub').textContent = `↓ ${d.bandwidth?.rx || '—'} · ↑ ${d.bandwidth?.tx || '—'}`;
    }
    markRefresh();
    loadPorts();
    loadKernelTuning();
  } catch (e) {
    console.error('Dashboard error', e);
    if (!metricsEl.dataset.built) {
      metricsEl.innerHTML = '<div class="metric"><div class="metric-label">Error</div><div class="metric-value" style="color:var(--red)">'+e.message+'</div></div>';
    }
  }
  if (spinEl) spinEl.classList.remove('spinning');
}

// ── IP strip ────────────────────────────────────────────────────────────────

function copyIp() {
  const ip = document.getElementById('m-ip').textContent.trim();
  if (!ip || ip === '…' || ip === '—') return;
  navigator.clipboard.writeText(ip).then(() => toast('IP copied'));
}

// ── Ports in use ─────────────────────────────────────────────────────────────

async function loadPorts() {
  const el = document.getElementById('portsBody');
  if (!el) return;
  try {
    const res = await apiFetch('/api/ports');
    if (!res.ok) { el.innerHTML = ''; return; }
    const rows = await res.json();

    // group by process+pid: same process holding many ports → one row
    const groups = new Map();
    for (const r of rows) {
      const key = (r.pid != null ? r.pid : '?') + '|' + (r.process || 'kernel');
      let g = groups.get(key);
      if (!g) {
        g = { pid: r.pid, process: r.process || 'kernel', addrs: new Set(), ports: [] };
        groups.set(key, g);
      }
      g.addrs.add(r.address);
      g.ports.push({ port: r.port, proto: r.proto });
    }
    const WILDCARD = new Set(['0.0.0.0', '::', '']);
    const list = [...groups.values()].map(g => {
      const seen = new Set();
      const ports = g.ports
        .filter(x => { const k = x.proto + x.port; if (seen.has(k)) return false; seen.add(k); return true; })
        .sort((a, b) => (a.proto === b.proto ? a.port - b.port : (a.proto === 'tcp' ? -1 : 1)));
      return {
        pid: g.pid,
        process: g.process,
        specific: [...g.addrs].filter(a => !WILDCARD.has(a)),
        ports
      };
    }).sort((a, b) => (a.ports[0] ? a.ports[0].port : Infinity) - (b.ports[0] ? b.ports[0].port : Infinity));

    el.innerHTML = list.map(g => `
      <div class="port-item">
        <div class="port-line">
          <span class="port-name">${escHtml(g.process)}</span>
          <span class="port-meta">${g.pid != null ? g.pid : '—'}${g.specific.length ? ' · ' + g.specific.map(escHtml).join(' · ') : ''}</span>
        </div>
        <div class="port-chips">
          ${g.ports.map(x => `<span class="port-chip${x.proto === 'udp' ? ' udp' : ''}">${x.port}</span>`).join('')}
        </div>
      </div>`).join('') ||
      '<div class="port-empty">No listeners</div>';
    filterPorts();
  } catch (e) { el.innerHTML = ''; }
}

function filterPorts() {
  const q = document.getElementById('portSearch').value.toLowerCase();
  const x = document.querySelector('.port-search-x');
  if (x) x.classList.toggle('visible', q.length > 0);
  document.querySelectorAll('#portsBody .port-item').forEach(it => {
    it.style.display = it.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// ── Kernel Buffers & Port Forwarding (Compact + Modal) ───────────────────────

let _tuningData = null;

async function loadKernelTuning() {
  try {
    const res = await apiFetch('/api/kernel-tuning');
    if (!res.ok) return;
    _tuningData = await res.json();

    // Compact Card display
    const bufEl = document.getElementById('dash-buf-val');
    if (bufEl) {
      const r = _tuningData.sysctl.live_rmem_max_human || _tuningData.sysctl.rmem_max_human;
      const w = _tuningData.sysctl.live_wmem_max_human || _tuningData.sysctl.wmem_max_human;
      bufEl.textContent = (r === w) ? r : `R ${r} · W ${w}`;
    }

    const chipsEl = document.getElementById('dash-routing-chips');
    if (chipsEl) {
      const rules = _tuningData.routing.rules || [];
      if (rules.length === 0) {
        chipsEl.innerHTML = '<span class="port-chip" style="color:var(--text3)">None configured</span>';
      } else {
        chipsEl.innerHTML = rules.map(rule => {
          let pfx = '';
          if (rule.interface && rule.interface !== 'auto') {
            pfx = `<span style="opacity:0.75;margin-right:3px">[${escHtml(rule.interface)}]</span>`;
          }
          return `<span class="port-chip udp">${pfx}${escHtml(rule.dport)} → :${escHtml(rule.redirect)}</span>`;
        }).join('');
      }
    }
  } catch (e) {
    console.error('loadKernelTuning error', e);
  }
}

function openTuningModal() {
  if (!_tuningData) {
    loadKernelTuning().then(populateTuningModal);
  } else {
    populateTuningModal();
  }
  openModal('tuningModal');
}

function populateTuningModal() {
  if (!_tuningData) return;
  const rmemInput = document.getElementById('modal-input-rmem');
  const wmemInput = document.getElementById('modal-input-wmem');
  if (rmemInput) rmemInput.value = _tuningData.sysctl.rmem_max_human || _tuningData.sysctl.rmem_max;
  if (wmemInput) wmemInput.value = _tuningData.sysctl.wmem_max_human || _tuningData.sysctl.wmem_max;

  const tbody = document.getElementById('modalRoutingBody');
  if (tbody) {
    tbody.innerHTML = '';
    const rules = _tuningData.routing.rules || [];
    if (rules.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text3);padding:14px">No active forwarding rules</td></tr>';
    } else {
      rules.forEach(r => addModalRoutingRow(r.proto, r.dport, r.redirect, r.interface || 'auto'));
    }
  }
}

function setModalBufferPreset(val) {
  const r = document.getElementById('modal-input-rmem');
  const w = document.getElementById('modal-input-wmem');
  if (r) r.value = val;
  if (w) w.value = val;
}

function addModalRoutingRow(proto = 'udp', dport = '', redirect = '', iface = 'auto') {
  const tbody = document.getElementById('modalRoutingBody');
  if (!tbody) return;
  if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {
    tbody.innerHTML = '';
  }

  const detected = (_tuningData && _tuningData.routing && _tuningData.routing.detected_interface) || 'default';
  const avail = (_tuningData && _tuningData.routing && _tuningData.routing.available_interfaces) || [];

  let ifaceOpts = `
    <option value="auto" ${iface === 'auto' ? 'selected' : ''}>Auto (${detected})</option>
    <option value="all" ${iface === 'all' ? 'selected' : ''}>All (Any)</option>
  `;

  avail.forEach(name => {
    ifaceOpts += `<option value="${escHtml(name)}" ${iface === name ? 'selected' : ''}>${escHtml(name)}</option>`;
  });

  if (iface && iface !== 'auto' && iface !== 'all' && !avail.includes(iface)) {
    ifaceOpts += `<option value="${escHtml(iface)}" selected>${escHtml(iface)}</option>`;
  }

  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="padding:4px 6px">
      <select class="m-rule-proto" style="padding:4px;font-size:11px;font-family:var(--font-mono)">
        <option value="udp" ${proto === 'udp' ? 'selected' : ''}>UDP</option>
        <option value="tcp" ${proto === 'tcp' ? 'selected' : ''}>TCP</option>
      </select>
    </td>
    <td style="padding:4px 6px">
      <select class="m-rule-iface" style="padding:4px;font-size:11px;font-family:var(--font-mono)">
        ${ifaceOpts}
      </select>
    </td>
    <td style="padding:4px 6px">
      <input type="text" class="m-rule-dport" placeholder="53 or 1000-2999" value="${escHtml(dport)}" style="padding:4px 6px;font-size:11px;font-family:var(--font-mono)">
    </td>
    <td style="padding:4px 6px">
      <input type="text" class="m-rule-redirect" placeholder="8053" value="${escHtml(redirect)}" style="padding:4px 6px;font-size:11px;font-family:var(--font-mono)">
    </td>
    <td style="padding:4px 6px;text-align:center">
      <button type="button" class="del-btn" onclick="removeModalRoutingRow(this)" title="Delete rule" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:16px;line-height:1">×</button>
    </td>
  `;
  tbody.appendChild(tr);
}

function removeModalRoutingRow(btn) {
  const tr = btn.closest('tr');
  if (tr) tr.remove();
  const tbody = document.getElementById('modalRoutingBody');
  if (tbody && tbody.children.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text3);padding:14px">No active forwarding rules</td></tr>';
  }
}

async function saveModalTuning() {
  const btn = document.getElementById('btn-save-tuning');
  const rmem = document.getElementById('modal-input-rmem').value.trim();
  const wmem = document.getElementById('modal-input-wmem').value.trim();
  const tbody = document.getElementById('modalRoutingBody');

  if (btn) btn.disabled = true;

  const rules = [];
  if (tbody) {
    tbody.querySelectorAll('tr').forEach(tr => {
      const protoEl = tr.querySelector('.m-rule-proto');
      const ifaceEl = tr.querySelector('.m-rule-iface');
      const dportEl = tr.querySelector('.m-rule-dport');
      const redirEl = tr.querySelector('.m-rule-redirect');
      if (protoEl && dportEl && redirEl) {
        const dport = dportEl.value.trim();
        const redirect = redirEl.value.trim();
        const iface = ifaceEl ? ifaceEl.value : 'auto';
        if (dport && redirect) {
          rules.push({
            proto: protoEl.value,
            interface: iface,
            dport: dport,
            redirect: redirect
          });
        }
      }
    });
  }

  try {
    const res = await apiFetch('/api/kernel-tuning', {
      method: 'POST',
      body: JSON.stringify({
        sysctl: { rmem_max: rmem, wmem_max: wmem },
        routing: { enabled: true, rules: rules }
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to save tuning');
    }
    toast('Tuning updated live', 'ok');
    closeModal('tuningModal');
    await loadKernelTuning();
  } catch (e) {
    toast(e.message, 'err');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Users ─────────────────────────────────────────────────────────────────────
function showUsersLoading() {
  document.getElementById('usersBody').innerHTML = '<tr><td colspan="10" style="text-align:center;padding:40px"><span class="spinner"></span><div style="margin-top:10px;color:var(--text3)">Loading...</div></td></tr>';
}

async function loadUsers() {
  showUsersLoading();
  try {
    const [dbRes, sshRes] = await Promise.all([
      apiFetch('/api/users'),
      apiFetch('/api/ssh-users')
    ]);

    if (!dbRes.ok) { throw new Error('users failed: ' + dbRes.status); }
    
    const users = await dbRes.json();
    const sshUsersArr = sshRes.ok ? await sshRes.json() : [];
    const dbUsernames = new Set(users.map(u => u.username));
    const rows = [];

    // Helper for formatting data
    function _fmtBytes(b) {
      if (b >= 1_073_741_824) return (b / 1_073_741_824).toFixed(1) + "G";
      if (b >= 1_048_576) return (b / 1_048_576).toFixed(1) + "M";
      if (b >= 1024) return (b / 1024).toFixed(1) + "K";
      return b;
    }

    // 1. Process Database Users
    for (const u of users) {
      const conns = u.connections || 0;
      const max = u.max_logins;
      const connDisplay = max ? `${conns}/${max}` : conns;
      
      rows.push(`
        <tr style="cursor:pointer" onclick="openUserPanel('${u.username}')">
          <td><strong style="font-family:var(--font-mono)">${u.username}</strong></td>
          <td><code>${u.password}</code></td>
          <td><span class="badge ${u.status === 'Active' ? 'badge-active' : 'badge-inactive'}">${u.status}</span></td>
          <td><span class="badge ${u.temporary ? 'badge-temp' : 'badge-perm'}">${u.temporary ? 'Temp' : 'Perm'}</span></td>
          <td style="font-family:var(--font-mono);font-size:12px">${u.expires ? u.expires.substring(0,10) : 'Never'}</td>
          <td style="font-size:12px">${u.services && u.services.length ? u.services.join(', ') : '—'}</td>
          <td><span class="conn-badge"><span class="conn-dot"></span>${connDisplay}</span></td>
          <td style="font-size:12px">${_fmtBytes(u.download || 0)}</td>
          <td style="font-size:12px">${_fmtBytes(u.upload || 0)}</td>
          <td style="font-family:var(--font-mono);font-size:11px">${u.uuid ? u.uuid.substring(0,8) + '...' : '—'}</td>
          <td onclick="event.stopPropagation()">
            <div style="display:flex;gap:6px">
              <button class="btn-sm btn-icon" onclick="copyToClipboard('${u.uuid || ''}')">📋</button>
              <button class="btn-danger btn-icon" onclick="deleteUser('${u.username}')">✕</button>
            </div>
          </td>
        </tr>
      `);
    }

    // 2. Process SSH-only Users (those not in DB)
    for (const s of sshUsersArr) {
      if (!dbUsernames.has(s.username)) {
        rows.push(`
          <tr style="opacity:0.5" title="Not in database">
            <td><strong style="font-family:var(--font-mono)">${s.username}</strong></td>
            <td colspan="5" style="text-align:center">System/SSH User Only</td>
            <td><span class="conn-badge"><span class="conn-dot"></span>${s.connections}</span></td>
            <td>${_fmtBytes(s.download || 0)}</td>
            <td>${_fmtBytes(s.upload || 0)}</td>
            <td>—</td>
            <td>—</td>
          </tr>
        `);
      }
    }

    // 3. Render to DOM
    const bodyEl = document.getElementById('usersBody');
    if (bodyEl) {
        bodyEl.innerHTML = rows.join('') || '<tr><td colspan="11" class="empty-state">No users found</td></tr>';
    }

    const countEl = document.getElementById('userCount');
    if (countEl) {
        countEl.textContent = users.length;
    }

  } catch (e) {
    console.error('loadUsers error:', e);
    const bodyEl = document.getElementById('usersBody');
    if (bodyEl) bodyEl.innerHTML = `<tr><td colspan="11" style="color:var(--red)">Error: ${e.message}</td></tr>`;
  }
}

  async function doSync() {
  const res = await apiFetch('/api/sync', { method: 'POST' });
  const d = await res.json();
  const n = d.deleted_count || 0;
  toast(n ? `Synced — ${n} expired user(s) removed` : 'Synced', 'ok');
  loadUsers();
}

async function doAddUser() {
  const days = parseInt(document.getElementById('nu_days').value);
  const maxl = parseInt(document.getElementById('nu_maxlogins').value);
  const services = [];
  if (document.getElementById('nu_svc_ssh').checked) services.push('ssh');
  if (document.getElementById('nu_svc_zivpn').checked) services.push('zivpn');

  const body = {
    username: document.getElementById('nu_username').value.trim(),
    password: document.getElementById('nu_password').value || null,
    days: isNaN(days) ? null : days,
    max_logins: isNaN(maxl) ? null : maxl,
    temporary: document.getElementById('nu_temp').checked,
    services: services.length > 0 ? services : null
  };
  if (!body.username) { toast('Username required', 'err'); return; }
  const res = await apiFetch('/api/users', { method: 'POST', body: JSON.stringify(body) });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast(`User "${d.username}" created — pw: ${d.password}`);
  closeModal('addUserModal');
  document.getElementById('nu_username').value = '';
  document.getElementById('nu_password').value = '';
  document.getElementById('nu_days').value = '';
  document.getElementById('nu_maxlogins').value = '';
  document.getElementById('nu_svc_ssh').checked = true;
  document.getElementById('nu_svc_zivpn').checked = true;
  document.getElementById('nu_temp').checked = false;
  loadUsers();
}

async function deleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  const res = await apiFetch(`/api/users/${username}`, { method: 'DELETE' });
  if (res.ok) { toast(`"${username}" deleted`); loadUsers(); }
  else { const d = await res.json(); toast(d.detail || 'Error', 'err'); }
}

// ── User Panel ────────────────────────────────────────────────────────────────

let currentPanelUser = null;

async function openUserPanel(username) {
  const res = await apiFetch(`/api/users/${username}`);
  if (!res.ok) return;
  const u = await res.json();
  currentPanelUser = username;

  document.getElementById('panel_username').textContent = u.username;
  document.getElementById('panel_badges').innerHTML = `
    <span class="badge ${u.status==='Active'?'badge-active':'badge-inactive'}" style="margin-right:6px">${u.status}</span>
    <span class="badge ${u.temporary?'badge-temp':'badge-perm'}">${u.temporary?'Temporary':'Permanent'}</span>
  `;
  document.getElementById('panel_info').innerHTML = `
    <div class="info-item"><div class="lbl">Password</div><div class="val">${u.password}</div></div>
    <div class="info-item"><div class="lbl">Expiry</div><div class="val">${u.expires?u.expires.substring(0,10):'Never'}</div></div>
    <div class="info-item"><div class="lbl">Max Logins</div><div class="val">${u.max_logins||'∞'}</div></div>
    <div class="info-item"><div class="lbl">Services</div><div class="val">${u.services && u.services.length ? u.services.join(', ') : '—'}</div></div>
    <div class="info-item"><div class="lbl">Connections</div><div class="val connections-val">${u.connections||0}</div></div>
  `;
  const isActive = u.status === 'Active';
  const isTemp = u.temporary;
  document.getElementById('panel_actions').innerHTML = `
    <button class="btn-sm" onclick="openPwdModal('${u.username}')">🔑 Password</button>
    <button class="btn-sm" onclick="openExpiryModal('${u.username}')">📅 Expiry</button>
    <button class="btn-sm" onclick="openMaxlogModal('${u.username}',${u.max_logins||0})">🔒 Max Logins</button>
    <button class="btn-sm" onclick="openServicesModal('${u.username}')">🔌 Services</button>
    <button class="btn-sm" onclick="doToggleTemp('${u.username}')">${isTemp?'→ Permanent':'→ Temporary'}</button>
    <button class="${isActive?'btn-danger':'btn-green'}" onclick="doToggleActive('${u.username}',${isActive})">
      ${isActive?'⏸ Deactivate':'▶ Activate'}
    </button>
    <button class="btn-danger" onclick="deleteUser('${u.username}');closePanel()">🗑 Delete</button>
  `;
  document.getElementById('userPanel').classList.add('open');
  document.getElementById('overlay').classList.add('open');
}

function closePanel() {
  document.getElementById('userPanel').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
  currentPanelUser = null;
}

// ── Change Password ───────────────────────────────────────────────────────────

function openPwdModal(username) {
  document.getElementById('pwd_username_lbl').textContent = username;
  document.getElementById('pwd_new').value = '';
  openModal('pwdModal');
}
async function doChangePassword() {
  const username = document.getElementById('pwd_username_lbl').textContent;
  const pass = document.getElementById('pwd_new').value || null;
  const res = await apiFetch(`/api/users/${username}/password`, {
    method: 'POST', body: JSON.stringify({ password: pass })
  });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast(`Password changed → ${d.new_password}`);
  closeModal('pwdModal');
  if (currentPanelUser === username) openUserPanel(username);
  loadUsers();
}

// ── Expiry ────────────────────────────────────────────────────────────────────

function openExpiryModal(username) {
  document.getElementById('exp_username_lbl').textContent = username;
  document.getElementById('exp_days').value = '';
  document.getElementById('exp_extend').checked = false;
  openModal('expiryModal');
}
async function doSetExpiry() {
  const username = document.getElementById('exp_username_lbl').textContent;
  const days = parseInt(document.getElementById('exp_days').value);
  if (isNaN(days) || days <= 0) { toast('Enter a positive number of days', 'err'); return; }
  const extend = document.getElementById('exp_extend').checked;
  const res = await apiFetch(`/api/users/${username}/expiry`, {
    method: 'POST', body: JSON.stringify({ days, extend })
  });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast(`Expiry ${extend ? 'extended' : 'set'} → ${d.expires || 'Never'}`);
  closeModal('expiryModal');
  if (currentPanelUser === username) openUserPanel(username);
  loadUsers();
}
async function doRemoveExpiry() {
  const username = document.getElementById('exp_username_lbl').textContent;
  const res = await apiFetch(`/api/users/${username}/expiry`, { method: 'DELETE' });
  if (res.ok) { toast(`${username} — expiry removed`); closeModal('expiryModal'); if (currentPanelUser === username) openUserPanel(username); loadUsers(); }
  else { const d = await res.json(); toast(d.detail || 'Error', 'err'); }
}

// ── Max Logins ────────────────────────────────────────────────────────────────

function openMaxlogModal(username, current) {
  document.getElementById('maxlog_username_lbl').textContent = username;
  document.getElementById('maxlog_val').value = current || '';
  openModal('maxlogModal');
}
async function doSetMaxlogins() {
  const username = document.getElementById('maxlog_username_lbl').textContent;
  const n = parseInt(document.getElementById('maxlog_val').value) || 0;
  const res = await apiFetch(`/api/users/${username}/maxlogins`, {
    method: 'POST', body: JSON.stringify({ max_logins: n === 0 ? null : n })
  });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast(`Max logins → ${d.max_logins || '∞'}`);
  closeModal('maxlogModal');
  if (currentPanelUser === username) openUserPanel(username);
  loadUsers();
}

// ── Toggle Temp / Active ──────────────────────────────────────────────────────

async function doToggleTemp(username) {
  const res = await apiFetch(`/api/users/${username}/toggle-temporary`, { method: 'POST' });
  const d = await res.json();
  if (res.ok) { toast(`${username} → ${d.temporary ? 'Temporary' : 'Permanent'}`); openUserPanel(username); loadUsers(); }
}

async function doToggleActive(username, isActive) {
  const ep = isActive ? 'deactivate' : 'activate';
  const res = await apiFetch(`/api/users/${username}/${ep}`, { method: 'POST' });
  if (res.ok) { toast(`${username} ${isActive ? 'deactivated' : 'activated'}`); openUserPanel(username); loadUsers(); }
}

// ── Services ─────────────────────────────────────────────────────────────────

function openServicesModal(username) {
  const u = currentPanelUser === username ? document.getElementById('panel_username').textContent : username;
  document.getElementById('svc_username_lbl').textContent = u;
  
  // Fetch current services and update checkboxes
  apiFetch(`/api/users/${u}`).then(r => r.json()).then(user => {
    const svcs = new Set(user.services || []);
    document.getElementById('svc_ssh').checked = svcs.has('ssh');
    document.getElementById('svc_zivpn').checked = svcs.has('zivpn');
    document.getElementById('svc_xray').checked = svcs.has('xray');
  });
  
  openModal('servicesModal');
}

async function doSaveServices() {
  const username = document.getElementById('svc_username_lbl').textContent;
  const services = [];
  if (document.getElementById('svc_ssh').checked) services.push('ssh');
  if (document.getElementById('svc_zivpn').checked) services.push('zivpn');
  if (document.getElementById('svc_xray').checked) services.push('xray');
  
  const res = await apiFetch(`/api/users/${username}/services`, {
    method: 'POST',
    body: JSON.stringify({ services })
  });
  const d = await res.json();
  if (!res.ok) { toast(d.detail || 'Error', 'err'); return; }
  toast(`Services updated → ${d.services.join(', ')}`);
  closeModal('servicesModal');
  if (currentPanelUser === username) openUserPanel(username);
  loadUsers();
}

// ── Utilities ─────────────────────────────────────────────────────────────────

async function copyToClipboard(text) {
  if (!text) { toast('No UUID to copy', 'err'); return; }
  try {
    await navigator.clipboard.writeText(text);
    toast('UUID copied to clipboard');
  } catch (e) {
    // Fallback for older browsers
    const textArea = document.createElement('textarea');
    textArea.value = text;
    document.body.appendChild(textArea);
    textArea.select();
    document.execCommand('copy');
    document.body.removeChild(textArea);
    toast('UUID copied to clipboard');
  }
}