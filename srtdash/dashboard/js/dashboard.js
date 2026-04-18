// ── Dashboard ─────────────────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const res = await apiFetch('/api/system');
    if (!res.ok) {
      const err = await res.text();
      document.getElementById('metrics').innerHTML = '<div class="metric"><div class="metric-label">Unable to load metrics</div><div class="metric-value">See console for details</div></div>';
      document.getElementById('bwDown').textContent = '—';
      document.getElementById('bwUp').textContent = '—';
      toast('Dashboard load failed', 'err');
      console.error('loadDashboard failed:', res.status, err);
      return;
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

    document.getElementById('metrics').innerHTML = `
      <div class="metric">
        <div class="metric-label">CPU</div>
        <div class="metric-value">${cpu}<span style="font-size:14px;color:var(--text3)">%</span></div>
        <div class="bar-wrap"><div class="bar" style="width:${cpu}%;background:${barColor(cpu)}"></div></div>
      </div>
      <div class="metric">
        <div class="metric-label">RAM</div>
        <div class="metric-value">${ram}<span style="font-size:14px;color:var(--text3)">%</span></div>
        <div class="metric-sub">${parseFloat(d.ram_used||0).toFixed(2)} / ${parseFloat(d.ram_total||0).toFixed(1)} GB</div>
        <div class="bar-wrap"><div class="bar" style="width:${ram}%;background:${barColor(ram)}"></div></div>
      </div>
      <div class="metric">
        <div class="metric-label">Disk</div>
        <div class="metric-value">${disk}<span style="font-size:14px;color:var(--text3)">%</span></div>
        <div class="metric-sub">${parseFloat(d.disk_used||0).toFixed(2)} / ${parseFloat(d.disk_total||0).toFixed(1)} GB</div>
        <div class="bar-wrap"><div class="bar" style="width:${disk}%;background:${barColor(disk)}"></div></div>
      </div>
      <div class="metric">
        <div class="metric-label">Public IP</div>
        <div class="metric-value" style="font-size:15px;font-family:var(--font-mono)">${d.ip || '—'}</div>
      </div>
      <div class="metric">
        <div class="metric-label">Connections</div>
        <div class="metric-value connections-val">${conns}</div>
      </div>
    `;
    document.getElementById('bwDown').textContent = d.bandwidth?.rx || '—';
    document.getElementById('bwUp').textContent = d.bandwidth?.tx || '—';
    markRefresh();
  } catch (e) {
    console.error('Dashboard error', e);
  }
}

// ── Users ─────────────────────────────────────────────────────────────────────

async function loadUsers() {
  const res = await apiFetch('/api/users');
  if (!res.ok) {
    const err = await res.text();
    document.getElementById('usersBody').innerHTML = '<tr><td colspan="9" class="empty-state">Could not load users</td></tr>';
    toast('Failed to load users', 'err');
    console.error('loadUsers failed:', res.status, err);
    return;
  }
  const users = await res.json();
  document.getElementById('usersBody').innerHTML = users.map(u => `
    <tr style="cursor:pointer" onclick="openUserPanel('${u.username}')">
      <td><strong style="font-family:var(--font-mono)">${u.username}</strong></td>
      <td><code>${u.password}</code></td>
      <td><span class="badge ${u.status === 'Active' ? 'badge-active' : 'badge-inactive'}">${u.status}</span></td>
      <td><span class="badge ${u.temporary ? 'badge-temp' : 'badge-perm'}">${u.temporary ? 'Temp' : 'Perm'}</span></td>
      <td style="font-family:var(--font-mono);font-size:12px">${u.expires ? u.expires.substring(0,10) : 'Never'}</td>
      <td style="font-family:var(--font-mono);font-size:12px">${u.max_logins || '∞'}</td>
      <td style="font-size:12px">${u.services && u.services.length ? u.services.join(', ') : '—'}</td>
      <td>
        <span class="conn-badge">
          <span class="conn-dot"></span>${u.connections || 0}
        </span>
      </td>
      <td style="font-family:var(--font-mono);font-size:11px;max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${u.uuid || '—'}">${u.uuid ? u.uuid.substring(0,8) + '...' : '—'}</td>
      <td onclick="event.stopPropagation()">
        <div style="display:flex;gap:6px">
          <button class="btn-sm btn-icon" title="Copy UUID" onclick="copyToClipboard('${u.uuid || ''}')">📋</button>
          <button class="btn-sm btn-icon" title="Edit" onclick="openUserPanel('${u.username}')">✎</button>
          <button class="btn-danger btn-icon" title="Delete" onclick="deleteUser('${u.username}')">✕</button>
        </div>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="10" class="empty-state">No users found</td></tr>';
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
  if (document.getElementById('nu_svc_xray').checked) services.push('xray');
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
  document.getElementById('nu_svc_xray').checked = true;
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

// ── Xray ─────────────────────────────────────────────────────────────────────

async function loadXray() {
  try {
    // Load xray.json config
    const configRes = await apiFetch('/api/files/xray.json');
    let config = null;
    if (configRes.ok) {
      const configData = await configRes.json();
      config = JSON.parse(configData.content);
    }

    // Load inbounds
    const inboundsRes = await apiFetch('/api/xray/inbounds');
    let inbounds = [];
    if (inboundsRes.ok) {
      inbounds = await inboundsRes.json();
    }

    // Load users
    const usersRes = await apiFetch('/api/users');
    let users = [];
    if (usersRes.ok) {
      users = await usersRes.json();
    }
    const xrayUsers = users.filter(u => u.services && u.services.includes('xray'));

    document.getElementById('xrayContent').innerHTML = `
      <div class="card">
        <h4>Xray Configuration</h4>
        <div style="margin-bottom:20px">
          <button class="btn" onclick="editXrayConfig()">Edit Config</button>
          <button class="btn" onclick="addXrayInbound()">Add Inbound</button>
        </div>
        
        <h5>Inbounds</h5>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>Tag</th><th>Protocol</th><th>Port</th><th>Users</th><th>Actions</th>
            </tr></thead>
            <tbody id="xrayInboundsBody">
              ${inbounds.map(ib => `
                <tr>
                  <td><strong>${ib.tag}</strong></td>
                  <td>${ib.protocol}</td>
                  <td>${ib.port || '—'}</td>
                  <td>${ib.users ? ib.users.length : 0}</td>
                  <td>
                    <button class="btn-sm" onclick="viewInboundUsers('${ib.tag}')">Users</button>
                    <button class="btn-sm btn-danger" onclick="removeInbound('${ib.tag}')">Remove</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <h5>Xray Users (${xrayUsers.length})</h5>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>Username</th><th>UUID</th><th>Status</th><th>Expiry</th><th>Connections</th>
            </tr></thead>
            <tbody>
              ${xrayUsers.map(u => `
                <tr>
                  <td><strong style="font-family:var(--font-mono)">${u.username}</strong></td>
                  <td style="font-family:var(--font-mono);font-size:11px" title="${u.uuid || '—'}">${u.uuid ? u.uuid.substring(0,8) + '...' : '—'}</td>
                  <td><span class="badge ${u.status === 'Active' ? 'badge-active' : 'badge-inactive'}">${u.status}</span></td>
                  <td style="font-family:var(--font-mono);font-size:12px">${u.expires ? u.expires.substring(0,10) : 'Never'}</td>
                  <td><span class="conn-badge"><span class="conn-dot"></span>${u.connections || 0}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (e) {
    console.error('Xray load error', e);
    document.getElementById('xrayContent').innerHTML = `
      <div class="card" style="text-align:center;padding:40px">
        <p style="color:var(--text3)">Failed to load Xray data</p>
      </div>
    `;
  }
}

async function editXrayConfig() {
  const res = await apiFetch('/api/files/xray.json');
  if (!res.ok) {
    toast('Failed to load config', 'err');
    return;
  }
  const data = await res.json();
  const uniqueId = 'xrayConfigModal-' + Date.now();
  const modal = document.createElement('div');
  modal.id = uniqueId;
  modal.className = 'modal';
  modal.innerHTML = `
    <div class="modal-content" style="width:90%; max-width:1200px; height:80vh; display:flex; flex-direction:column;">
      <div class="modal-header">
        <h3>Edit Xray Config</h3>
        <button class="modal-close" onclick="closeXrayModal('${uniqueId}')">&times;</button>
      </div>
      <div class="modal-body">
        <textarea id="xrayConfigEditor-${uniqueId}" style="width:100%; flex-grow:1; min-height:500px; font-family:monospace; font-size:13px; padding:15px; resize:none;">${data.content}</textarea>
      </div>
      <div class="modal-footer">
        <button class="btn" onclick="saveXrayConfig('${uniqueId}')">Save</button>
        <button class="btn-secondary" onclick="closeXrayModal('${uniqueId}')">Cancel</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.classList.add('open');
  modal.addEventListener('click', e => { if (e.target === modal) closeXrayModal(uniqueId); });
}

async function saveXrayConfig(modalId) {
  const content = document.getElementById('xrayConfigEditor-' + modalId).value;
  
  try {
    // Optional: Validate JSON locally before sending
    JSON.parse(content);

    const res = await apiFetch('/api/files/xray.json', {
      method: 'PUT',
      headers: {
        // Force text/plain so FastAPI treats the body as a single string
        'Content-Type': 'text/plain' 
      },
      body: content // Send the raw string from the textarea
    });

    if (res.ok) {
      toast('Config saved successfully', 'ok');
      closeXrayModal(modalId);
      if (typeof loadXray === 'function') loadXray();
    } else {
      const err = await res.json();
      // Handle the detail object to avoid [object Object]
      const msg = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail);
      toast('Save failed: ' + msg, 'err');
    }
  } catch (e) {
    toast('Invalid JSON format: ' + e.message, 'err');
  }
}

function closeXrayModal(id) {
  const modal = document.getElementById(id);
  if (modal) {
    modal.classList.remove('open');
    setTimeout(() => modal.remove(), 200);
  }
}

async function addXrayInbound() {
  const uniqueId = 'addInboundModal-' + Date.now();
  const modal = document.createElement('div');
  modal.id = uniqueId;
  modal.className = 'modal';
  modal.innerHTML = `
    <div class="modal-box">
      <h4>Add Xray Inbound</h4>
      <div class="form-row">
        <label>Tag</label>
        <input type="text" id="inboundTag-${uniqueId}" placeholder="e.g., vless-inbound">
      </div>
      <div class="form-row">
        <label>Protocol</label>
        <select id="inboundProtocol-${uniqueId}">
          <option value="vless">VLESS</option>
          <option value="vmess">VMess</option>
          <option value="trojan">Trojan</option>
        </select>
      </div>
      <div class="form-row">
        <label>Port</label>
        <input type="number" id="inboundPort-${uniqueId}" placeholder="443">
      </div>
      <div class="form-row">
        <label>Listen Address</label>
        <input type="text" id="inboundListen-${uniqueId}" value="0.0.0.0">
      </div>
      <div class="modal-footer">
        <button class="btn-sm" onclick="closeXrayModal('${uniqueId}')">Cancel</button>
        <button class="btn" onclick="doAddInbound('${uniqueId}')">Add</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.classList.add('open');
  modal.addEventListener('click', e => { if (e.target === modal) closeXrayModal(uniqueId); });
}

async function doAddInbound(modalId) {
  const inbound = {
    tag: document.getElementById('inboundTag-' + modalId).value.trim(),
    protocol: document.getElementById('inboundProtocol-' + modalId).value,
    port: parseInt(document.getElementById('inboundPort-' + modalId).value),
    listen: document.getElementById('inboundListen-' + modalId).value,
    settings: {},
    streamSettings: {}
  };
  
  if (!inbound.tag || !inbound.port) {
    toast('Tag and port required', 'err');
    return;
  }
  
  const res = await apiFetch('/api/xray/inbounds', {
    method: 'POST',
    body: JSON.stringify(inbound)
  });
  const data = await res.json();
  if (res.ok) {
    toast('Inbound added');
    closeXrayModal(modalId);
    loadXray();
  } else {
    toast(data.detail || 'Failed to add inbound', 'err');
  }
}

async function removeInbound(tag) {
  if (!confirm(`Remove inbound "${tag}"?`)) return;
  const res = await apiFetch(`/api/xray/inbounds/${tag}`, { method: 'DELETE' });
  if (res.ok) {
    toast('Inbound removed');
    loadXray();
  } else {
    const data = await res.json();
    toast(data.detail || 'Failed to remove', 'err');
  }
}

async function viewInboundUsers(tag) {
  const res = await apiFetch(`/api/xray/inbounds/${tag}/users`);
  if (!res.ok) {
    toast('Failed to load users', 'err');
    return;
  }
  const users = await res.json();
  const uniqueId = 'viewUsersModal-' + Date.now();
  const modal = document.createElement('div');
  modal.id = uniqueId;
  modal.className = 'modal';
  modal.innerHTML = `
    <div class="modal-content">
      <div class="modal-header">
        <h3>Users in ${tag}</h3>
        <button class="modal-close" onclick="closeXrayModal('${uniqueId}')">&times;</button>
      </div>
      <div class="modal-body">
        ${users.length ? `
          <div class="table-wrap">
            <table>
              <thead><tr><th>Username</th><th>ID</th></tr></thead>
              <tbody>
                ${users.map(u => `<tr><td>${u.username}</td><td style="font-family:monospace;font-size:12px">${u.id}</td></tr>`).join('')}
              </tbody>
            </table>
          </div>
        ` : '<p>No users in this inbound</p>'}
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" onclick="closeXrayModal('${uniqueId}')">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.classList.add('open');
  modal.addEventListener('click', e => { if (e.target === modal) closeXrayModal(uniqueId); });
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
