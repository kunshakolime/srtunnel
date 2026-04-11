// ── Dashboard ─────────────────────────────────────────────────────────────────

async function loadDashboard() {
  try {
    const res = await apiFetch('/api/system');
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
  if (!res.ok) return;
  const users = await res.json();
  document.getElementById('usersBody').innerHTML = users.map(u => `
    <tr style="cursor:pointer" onclick="openUserPanel('${u.username}')">
      <td><strong style="font-family:var(--font-mono)">${u.username}</strong></td>
      <td><code>${u.password}</code></td>
      <td><span class="badge ${u.status === 'Active' ? 'badge-active' : 'badge-inactive'}">${u.status}</span></td>
      <td><span class="badge ${u.temporary ? 'badge-temp' : 'badge-perm'}">${u.temporary ? 'Temp' : 'Perm'}</span></td>
      <td style="font-family:var(--font-mono);font-size:12px">${u.expires ? u.expires.substring(0,10) : 'Never'}</td>
      <td style="font-family:var(--font-mono);font-size:12px">${u.max_logins || '∞'}</td>
      <td>
        <span class="conn-badge">
          <span class="conn-dot"></span>${u.connections || 0}
        </span>
      </td>
      <td onclick="event.stopPropagation()">
        <div style="display:flex;gap:6px">
          <button class="btn-sm btn-icon" title="Edit" onclick="openUserPanel('${u.username}')">✎</button>
          <button class="btn-danger btn-icon" title="Delete" onclick="deleteUser('${u.username}')">✕</button>
        </div>
      </td>
    </tr>
  `).join('') || '<tr><td colspan="8" class="empty-state">No users found</td></tr>';
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
  const body = {
    username: document.getElementById('nu_username').value.trim(),
    password: document.getElementById('nu_password').value || null,
    days: isNaN(days) ? null : days,
    max_logins: isNaN(maxl) ? null : maxl,
    temporary: document.getElementById('nu_temp').checked
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
    <div class="info-item"><div class="lbl">Connections</div><div class="val connections-val">${u.connections||0}</div></div>
  `;
  const isActive = u.status === 'Active';
  const isTemp = u.temporary;
  document.getElementById('panel_actions').innerHTML = `
    <button class="btn-sm" onclick="openPwdModal('${u.username}')">🔑 Password</button>
    <button class="btn-sm" onclick="openExpiryModal('${u.username}')">📅 Expiry</button>
    <button class="btn-sm" onclick="openMaxlogModal('${u.username}',${u.max_logins||0})">🔒 Max Logins</button>
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
