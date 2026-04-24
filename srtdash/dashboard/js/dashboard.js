// ── Dashboard ─────────────────────────────────────────────────────────────────

const LOADING_HTML = '<div style="text-align:center;padding:40px"><span class="spinner"></span><div style="margin-top:10px;color:var(--text3)">Loading...</div></div>';

async function loadDashboard() {
  document.getElementById('metrics').innerHTML = LOADING_HTML;
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
    document.getElementById('metrics').innerHTML = '<div class="metric"><div class="metric-label">Error</div><div class="metric-value" style="color:var(--red)">'+e.message+'</div></div>';
  }
}
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
    document.getElementById('metrics').innerHTML = '<div class="metric"><div class="metric-label">Error</div><div class="metric-value" style="color:var(--red)">'+e.message+'</div></div>';
  }
}

// ── Users ─────────────────────────────────────────────────────────────────────

const LOADING_HTML = '<div style="text-align:center;padding:40px"><span class="spinner"></span><div style="margin-top:10px;color:var(--text3)">Loading...</div></div>';

// Override loading for users table (needs special formatting)
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
  if (document.getElementById('nu_svc_xray').checked) services.push('xray');

  const xray_inbounds = [];
  if (document.getElementById('nu_svc_xray').checked) {
    const checkboxes = document.querySelectorAll('#xrayInboundsList input:checked');
    checkboxes.forEach(cb => xray_inbounds.push(cb.value));
  }

  const body = {
    username: document.getElementById('nu_username').value.trim(),
    password: document.getElementById('nu_password').value || null,
    days: isNaN(days) ? null : days,
    max_logins: isNaN(maxl) ? null : maxl,
    temporary: document.getElementById('nu_temp').checked,
    services: services.length > 0 ? services : null,
    xray_inbounds: xray_inbounds.length > 0 ? xray_inbounds : null
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
  toggleXrayInbounds();
  loadUsers();
}

async function toggleXrayInbounds() {
  const show = document.getElementById('nu_svc_xray').checked;
  document.getElementById('xrayInboundsSelect').style.display = show ? 'block' : 'none';
  if (!show) return;

  const res = await apiFetch('/api/xray/inbounds');
  const inbounds = res.ok ? await res.json() : [];

  const container = document.getElementById('xrayInboundsList');
  if (!inbounds || inbounds.length === 0) {
    container.innerHTML = '<span style="font-size:12px;color:var(--text3)">No inbounds available</span>';
    return;
  }

  container.innerHTML = inbounds.map(ib => `
    <label class="toggle-row" style="border:none;padding:4px 0">
      <span style="font-size:13px">${ib.tag} (${ib.protocol || '?'})</span>
      <label class="toggle"><input type="checkbox" value="${ib.tag}" checked><span class="toggle-slider"></span></label>
    </label>
  `).join('');
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
  document.getElementById('xrayContent').innerHTML = '<div style="text-align:center;padding:40px">'+LOADING_HTML+'</div>';
  try {
    // Load inbounds
    const inboundsRes = await apiFetch('/api/xray/inbounds');
    let inbounds = [];
    if (inboundsRes.ok) inbounds = await inboundsRes.json();
    else throw new Error('Failed to load inbounds');

    // Fetch users for each inbound
    for (const ib of inbounds) {
      const usersRes = await apiFetch(`/api/xray/inbounds/${ib.tag}/users`);
      ib.users = usersRes.ok ? await usersRes.json() : [];
    }

    // Load all DB users
    const usersRes = await apiFetch('/api/users');
    let dbUsers = [];
    if (usersRes.ok) dbUsers = await usersRes.json();
    else throw new Error('Failed to load users');
    const xrayUsers = dbUsers.filter(u => u.services && u.services.includes('xray'));
    const dbUsernames = new Set(xrayUsers.map(u => u.username));

    // Build user list for all inbounds combined
    const allInboundUsers = [];
    for (const ib of inbounds) {
      for (const u of ib.users || []) {
        allInboundUsers.push({ ...u, inbound: ib.tag, inDb: dbUsernames.has(u.email) || dbUsernames.has(u.email?.split('@')[0]) });
      }
    }

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

        <h5 style="margin-top:24px">All Xray Users (${allInboundUsers.length})</h5>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>Email</th><th>UUID</th><th>Inbound</th><th>Status</th><th>Actions</th>
            </tr></thead>
            <tbody>
              ${allInboundUsers.length ? allInboundUsers.map(u => `
                <tr class="${u.inDb ? '' : 'row-dimmed'}">
                  <td><strong style="font-family:var(--font-mono)">${u.email}</strong></td>
                  <td style="font-family:var(--font-mono);font-size:11px" title="${u.id}">${u.id ? u.id.substring(0,8) + '...' : '—'}</td>
                  <td><span class="badge">${u.inbound}</span></td>
                  <td><span class="badge ${u.inDb ? 'badge-active' : 'badge-inactive'}">${u.inDb ? 'Known' : 'Unknown'}</span></td>
                  <td>
                    <button class="btn-sm btn-danger" onclick="deleteInboundUser('${u.inbound}', '${u.email}')">Delete</button>
                  </td>
                </tr>
              `).join('') : '<tr><td colspan="5" style="text-align:center;color:var(--text3)">No users in any inbound</td></tr>'}
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
    <div class="modal-box" style="max-width:900px; max-height:90vh;">
      <h4>Edit Xray Config</h4>
      <textarea id="xrayConfigEditor-${uniqueId}" style="width:100%; height:60vh; font-family:var(--font-mono); font-size:13px; padding:15px; resize:none;">${data.content}</textarea>
      <div class="modal-footer">
        <button class="btn-sm" onclick="closeXrayModal('${uniqueId}')">Cancel</button>
        <button class="btn" onclick="saveXrayConfig('${uniqueId}')">Save</button>
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

function toggleTLSFields(uniqueId, network) {
  const tlsFields = document.getElementById('tlsFields-' + uniqueId);
  const wsRow = document.getElementById('wsRow-' + uniqueId);
  const wsRowPath = document.getElementById('wsRowPath-' + uniqueId);

  tlsFields.style.display = 'none';
  wsRow.style.display = 'none';
  wsRowPath.style.display = 'none';

  if (network === 'tcp') {
    clearWSFields(uniqueId);
  } else if (network === 'ws') {
    wsRow.style.display = 'block';
    wsRowPath.style.display = 'block';
  }
  toggleSecurity(uniqueId);
}

function toggleSecurity(uniqueId) {
  const tlsCheck = document.getElementById('inboundTLS-' + uniqueId);
  const tlsFields = document.getElementById('tlsFields-' + uniqueId);
  if (tlsCheck && tlsCheck.checked) {
    tlsFields.style.display = 'block';
  } else {
    tlsFields.style.display = 'none';
  }
}

function clearTLSFields(uniqueId) {
  const sni = document.getElementById('inboundSNI-' + uniqueId);
  const cert = document.getElementById('inboundCert-' + uniqueId);
  const key = document.getElementById('inboundKey-' + uniqueId);
  const alpn = document.getElementById('inboundALPN-' + uniqueId);
  if (sni) sni.value = '';
  if (cert) cert.value = '/root/srtunnel/server.crt';
  if (key) key.value = '/root/srtunnel/server.key';
  if (alpn) alpn.value = 'h2, http/1.1';
}

function clearWSFields(uniqueId) {
  const wsHost = document.getElementById('inboundWSHost-' + uniqueId);
  const wsPath = document.getElementById('inboundWSPath-' + uniqueId);
  if (wsHost) wsHost.value = '';
  if (wsPath) wsPath.value = '';
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
        <input type="text" id="inboundTag-${uniqueId}" placeholder="e.g., xray-vless">
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
        <label>Listen</label>
        <input type="text" id="inboundListen-${uniqueId}" value="0.0.0.0" style="font-family:var(--font-mono)">
      </div>
      <div class="form-row">
        <label>Port</label>
        <input type="number" id="inboundPort-${uniqueId}" placeholder="443">
      </div>
      <div class="form-row">
        <label>Network</label>
        <select id="inboundNetwork-${uniqueId}" onchange="toggleTLSFields('${uniqueId}', this.value)">
          <option value="tcp">TCP</option>
          <option value="ws">WebSocket</option>
        </select>
      </div>
      <div class="toggle-row">
        <span>TLS</span>
        <label class="toggle"><input type="checkbox" id="inboundTLS-${uniqueId}" onchange="toggleSecurity('${uniqueId}')"><span class="toggle-slider"></span></label>
      </div>
      <div id="tlsFields-${uniqueId}" style="display:none">
        <div class="form-row">
          <label>SNI / Server Name</label>
          <input type="text" id="inboundSNI-${uniqueId}" placeholder="e.g., mydomain.com">
        </div>
        <div class="form-row">
          <label>Cert Path</label>
          <input type="text" id="inboundCert-${uniqueId}" value="/root/srtunnel/server.crt" style="font-family:var(--font-mono)">
        </div>
        <div class="form-row">
          <label>Key Path</label>
          <input type="text" id="inboundKey-${uniqueId}" value="/root/srtunnel/server.key" style="font-family:var(--font-mono)">
        </div>
        <div class="form-row">
          <label>ALPN</label>
          <input type="text" id="inboundALPN-${uniqueId}" value="h2, http/1.1" placeholder="h2, http/1.1" style="font-family:var(--font-mono)">
        </div>
      </div>
      <div class="form-row" id="wsRow-${uniqueId}" style="display:none">
        <label>WebSocket Host</label>
        <input type="text" id="inboundWSHost-${uniqueId}" placeholder="e.g., mydomain.com">
      </div>
      <div class="form-row" id="wsRowPath-${uniqueId}" style="display:none">
        <label>WebSocket Path</label>
        <input type="text" id="inboundWSPath-${uniqueId}" placeholder="e.g., /kun">
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

  // Initialize TLS fields visibility based on default network
  const defaultNetwork = document.getElementById('inboundNetwork-' + uniqueId).value;
  toggleTLSFields(uniqueId, defaultNetwork);
}

async function doAddInbound(modalId) {
  const tag = document.getElementById('inboundTag-' + modalId).value.trim();
  const protocol = document.getElementById('inboundProtocol-' + modalId).value;
  const listen = document.getElementById('inboundListen-' + modalId).value.trim();
  const port = parseInt(document.getElementById('inboundPort-' + modalId).value);
  const network = document.getElementById('inboundNetwork-' + modalId).value;

  const tlsEl = document.getElementById('inboundTLS-' + modalId);
  const useTLS = tlsEl ? tlsEl.checked : false;
  const sniEl = document.getElementById('inboundSNI-' + modalId);
  const sni = sniEl ? sniEl.value.trim() : '';
  const certEl = document.getElementById('inboundCert-' + modalId);
  const certPath = certEl ? certEl.value.trim() : '';
  const keyEl = document.getElementById('inboundKey-' + modalId);
  const keyPath = keyEl ? keyEl.value.trim() : '';
  const wsHostEl = document.getElementById('inboundWSHost-' + modalId);
  const wsHost = wsHostEl ? wsHostEl.value.trim() : '';
  const wsPathEl = document.getElementById('inboundWSPath-' + modalId);
  const wsPath = wsPathEl ? wsPathEl.value.trim() : '';
  const alpnEl = document.getElementById('inboundALPN-' + modalId);
  const alpn = alpnEl ? alpnEl.value.trim() : '';

  if (!tag || !port) {
    toast('Tag and port required', 'err');
    return;
  }

  const inbound = {
    tag: tag,
    protocol: protocol,
    listen: listen,
    port: port,
    settings: {
      clients: [],
      decryption: 'none',
      encryption: 'none'
    }
  };

  const streamSettings = { network: network };
  const wsSettings = {};

  const wsRowVisible = document.getElementById('wsRow-' + modalId)?.style.display !== 'none';
  if (network === 'ws' && wsRowVisible) {
    if (wsHost) wsSettings.host = wsHost;
    if (wsPath) wsSettings.path = wsPath;
    if (Object.keys(wsSettings).length) streamSettings.wsSettings = wsSettings;
  }

  const tlsFieldsVisible = document.getElementById('tlsFields-' + modalId)?.style.display !== 'none';

  if (useTLS && tlsFieldsVisible) {
    streamSettings.security = 'tls';
    streamSettings.tlsSettings = {
      alpn: alpn ? alpn.split(',').map(x => x.trim()).filter(x => x) : ['h2', 'http/1.1'],
      certificates: [{
        certificateFile: certPath || '/root/srtunnel/server.crt',
        keyFile: keyPath || '/root/srtunnel/server.key'
      }],
      minVersion: '1.2',
      maxVersion: '1.3'
    };
    if (sni) streamSettings.tlsSettings.serverName = sni;
  }

  inbound.streamSettings = streamSettings;

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
  modal.style.display = 'flex';
  modal.innerHTML = `
    <div class="modal-box" style="max-width:600px">
      <h4>Users in ${tag}</h4>
      <div class="table-wrap" style="max-height:400px;overflow:auto">
        <table>
          <thead><tr><th>Email</th><th>UUID</th><th>Action</th></tr></thead>
          <tbody>
            ${users.length ? users.map(u => `
              <tr>
                <td style="font-family:var(--font-mono)">${u.email}</td>
                <td style="font-family:var(--font-mono);font-size:11px">${u.id ? u.id.substring(0,8)+'...' : '—'}</td>
                <td><button class="btn-sm btn-danger" onclick="deleteInboundUser('${tag}', '${u.email}')">Delete</button></td>
              </tr>
            `).join('') : '<tr><td colspan="3" style="text-align:center;color:var(--text3)">No users</td></tr>'}
          </tbody>
        </table>
      </div>
      <div class="modal-footer">
        <button class="btn-sm" onclick="document.getElementById('${uniqueId}').remove()">Close</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
}

async function deleteInboundUser(tag, clientUuid) {
  // clientUuid is actually email here
  if (!confirm(`Delete user ${clientUuid} from ${tag}?`)) return;
  const res = await apiFetch(`/api/xray/inbounds/${tag}/users/${encodeURIComponent(clientUuid)}`, { method: 'DELETE' });
  if (res.ok) {
    toast('User removed');
    loadXray();
  } else {
    const data = await res.json();
    toast(data.detail || 'Failed to delete', 'err');
  }
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
