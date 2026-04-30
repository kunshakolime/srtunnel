// ── Home Server ───────────────────────────────────────────────────────────────
// The one API that owns the server list. URL + token stored in localStorage.
// Everything else (other managed servers) lives in /api/serverlist on this API.

let HOME_API   = localStorage.getItem('home_api')   || '';
let HOME_TOKEN = localStorage.getItem('home_token') || '';

function setHome(url, token) {
  HOME_API   = url;
  HOME_TOKEN = token;
  localStorage.setItem('home_api',   url);
  localStorage.setItem('home_token', token);
}

// ── Active server ─────────────────────────────────────────────────────────────

let _activeId = localStorage.getItem('srv_active') || null;

function getActiveId() { return _activeId; }
function setActiveId(id) {
  _activeId = id;
  if (id) localStorage.setItem('srv_active', id);
  else    localStorage.removeItem('srv_active');
}

// ── Server list (API-backed) ──────────────────────────────────────────────────

let _servers = [];

async function fetchServers() {
  try {
    const res = await fetch(HOME_API + '/api/serverlist', {
      headers: { 'Authorization': 'Bearer ' + HOME_TOKEN }
    });
    if (res.ok) { _servers = await res.json(); return true; }
    return false;  // 401 or other error
  } catch { return false; }
}

async function pushServers() {
  try {
    await fetch(HOME_API + '/api/serverlist', {
      method:  'POST',
      headers: { 'Authorization': 'Bearer ' + HOME_TOKEN, 'Content-Type': 'application/json' },
      body:    JSON.stringify({ servers: _servers })
    });
  } catch (e) {
    console.warn('pushServers failed (non-fatal):', e?.message);
  }
}

function getServers() { return _servers; }

async function upsertServer(srv) {
  const idx = _servers.findIndex(s => s.id === srv.id);
  if (idx >= 0) _servers[idx] = srv; else _servers.push(srv);
  await pushServers();
}

async function removeServer(id) {
  _servers = _servers.filter(s => s.id !== id);
  if (_activeId === id) setActiveId(null);
  await pushServers();
}

function getActiveServer() {
  return _servers.find(s => s.id === _activeId) || null;
}

// ── Auth & API (active server) ────────────────────────────────────────────────

let API   = '';
let TOKEN = '';

function applyActive() {
  const srv = getActiveServer();
  if (srv) { API = srv.url; TOKEN = srv.token; }
}

let _sessionDead = false;

async function apiFetch(path, opts = {}) {
  if (_sessionDead) return new Response(null, { status: 401 });
  const isFormData = opts.body instanceof FormData;
  const headers = { 'Authorization': 'Bearer ' + TOKEN };
  if (!isFormData) headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  if (res.status === 401 && path !== '/api/login') {
    _sessionDead = true;
    _stopDashboardTimer();
    stopLogStream();
    toast('Session expired — please log in again', 'err');
    setTimeout(logout, 1500);
  }
  return res;
}

// ── Toast ─────────────────────────────────────────────────────────────────────

let _toastTimer;
function toast(msg, type = 'ok') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'show ' + type;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.className = '', 3000);
}

// ── Login page ────────────────────────────────────────────────────────────────

function togglePassVisibility() {
  const input = document.getElementById('loginPass');
  const eyeOff = document.getElementById('passEyeOff');
  const eyeOn = document.getElementById('passEyeOn');
  if (input.type === 'password') {
    input.type = 'text';
    eyeOff.style.display = 'none';
    eyeOn.style.display = '';
  } else {
    input.type = 'password';
    eyeOff.style.display = '';
    eyeOn.style.display = 'none';
  }
}

async function doLogin() {
  const url  = document.getElementById('apiUrl').value.trim().replace(/\/$/, '');
  const name = document.getElementById('serverName').value.trim() || url.replace(/^https?:\/\//, '').split(':')[0];
  const tok  = document.getElementById('loginToken').value.trim();
  document.getElementById('loginErr').textContent = '';

  if (!url) { document.getElementById('loginErr').textContent = 'API URL is required'; return; }

  if (tok) {
    setHome(url, tok);      // set first so fetchServers uses this token
    await fetchServers();   // best-effort
    const existing = _servers.find(s => s.url === url);
    const id = existing ? existing.id : 'srv_' + Date.now();
    await upsertServer({ id, name, url, token: tok });
    setActiveId(id);
    applyActive();
    start();
    return;
  }

  try {
    const res = await fetch(url + '/api/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        username: document.getElementById('loginUser').value,
        password: document.getElementById('loginPass').value
      })
    });
    const d = await res.json();
    if (!res.ok) { document.getElementById('loginErr').textContent = d.detail || 'Login failed'; return; }

    // Set home FIRST so fetchServers uses the new token
    setHome(url, d.token);
    await fetchServers();   // best-effort — failure won't block login

    const existing = _servers.find(s => s.url === url);
    const id = existing ? existing.id : 'srv_' + Date.now();
    await upsertServer({ id, name, url, token: d.token });
    setActiveId(id);
    applyActive();
    start();
  } catch (e) {
    console.error('doLogin error:', e);
    document.getElementById('loginErr').textContent = 'Connection failed — ' + (e?.message || 'check API URL');
  }
}

// ── Online-status cache ───────────────────────────────────────────────────────

// ── Server status: read from API-maintained serverlist.json ──────────────────
// The API loops every 30s pinging servers and writing online/last_seen back.
// Dashboard just fetches /api/serverlist/status every 20s and updates dots.

const STATUS_INTERVAL = 20_000;
let _statusTimer  = null;
let _statusCache  = {};   // url -> { online, last_seen }

async function _fetchServerStatus() {
  try {
    const res = await apiFetch('/api/serverlist/status');
    if (!res.ok) return;
    const text = await res.text();
    if (!text || !text.trim().startsWith('[')) return;
    const servers = JSON.parse(text);
    for (const s of servers) {
      _statusCache[s.url] = { online: s.online ?? false, last_seen: s.last_seen };
      const dot = document.getElementById('hub-dot-' + s.id);
      if (dot) dot.className = 'server-dot ' + (s.online ? 'online' : 'offline');
    }
  } catch { /* silent — dots stay as-is */ }
}

function _startHealthLoop() {
  clearInterval(_statusTimer);
  _fetchServerStatus();
  _statusTimer = setInterval(() => {
    if (!document.hidden) _fetchServerStatus();
  }, STATUS_INTERVAL);
}

function checkServerOnline(url) {
  return _statusCache[url]?.online ?? false;
}

// ── Hub ───────────────────────────────────────────────────────────────────────

async function renderHub() {
  const list      = getServers();
  const activeId  = getActiveId();
  const container = document.getElementById('hubServers');
  if (!container) return;

  container.innerHTML = list.map(s => {
    const cached = _statusCache[s.url];
    const dotClass = cached ? (cached.online ? 'online' : 'offline') : 'checking';
    const isHome   = s.url === HOME_API;
    return `
    <div class="hub-server ${s.id === activeId ? 'active' : ''}" id="hub-srv-${s.id}" onclick="switchServer('${s.id}')">
      <div class="server-dot ${dotClass}" id="hub-dot-${s.id}"></div>
      <div class="hub-srv-info">
        <div class="hub-srv-name">${isHome ? '👑 ' : ''}${escHtml(s.name)}</div>
        <div class="hub-srv-url" title="${escHtml(s.url)}" onclick="event.stopPropagation();navigator.clipboard.writeText('${escHtml(s.url)}').then(()=>toast('URL copied'))">${escHtml(s.url)}</div>
      </div>
      <button class="hub-srv-del" onclick="event.stopPropagation();hubRemoveServer('${s.id}')" title="Remove">✕</button>
    </div>`;
  }).join('');


}

async function hubRemoveServer(id) {
  await removeServer(id);
  const remaining = getServers();
  if (remaining.length) {
    setActiveId(remaining[0].id);
    applyActive();
    await renderHub();
    loadDashboard();
  } else {
    logout();
  }
}

// ── App lifecycle ─────────────────────────────────────────────────────────────

function start() {
  document.getElementById('loginPage').style.display = 'none';
  document.getElementById('app').style.display       = 'block';
  const active = getActiveServer();
  document.getElementById('topUser').textContent = active?.name || '—';
  _sessionDead = false;
  renderHub();
  _startHealthLoop();
  // load the current page (default: dashboard)
  showPage(_currentPage, document.querySelector('.nav button.active') || document.querySelector('.nav button'));
}

function logout() {
  const remaining = getServers().filter(s => s.id !== getActiveId());
  if (remaining.length) {
    setActiveId(remaining[0].id);
    applyActive();
    renderHub();
    document.getElementById('topUser').textContent = remaining[0].name || '—';
    _refresh();
    toast('Disconnected from server');
    return;
  }
  localStorage.removeItem('home_api');
  localStorage.removeItem('home_token');
  localStorage.removeItem('srv_active');
  HOME_API = ''; HOME_TOKEN = ''; TOKEN = ''; API = ''; _servers = []; _activeId = null;
  document.getElementById('loginPage').style.display = '';
  document.getElementById('app').style.display       = 'none';
  document.getElementById('loginUser').value  = '';
  document.getElementById('loginPass').value  = '';
  document.getElementById('loginToken').value = '';
}

function switchServer(id) {
  setActiveId(id);
  applyActive();
  renderHub();
  _fetchServerStatus();  // refresh dots immediately instead of waiting for the 20s timer
  const active = getActiveServer();
  document.getElementById('topUser').textContent = active?.name || '—';
  showPage(_currentPage, document.querySelector('.nav button.active'));
  toast('Switched to ' + (active?.name || id));
}

// ── Add Server Modal ──────────────────────────────────────────────────────────

async function doAddServer() {
  const url   = document.getElementById('as_url').value.trim().replace(/\/$/, '');
  const name  = document.getElementById('as_name').value.trim() || url.replace(/^https?:\/\//, '').split(':')[0];
  const user  = document.getElementById('as_user').value.trim();
  const pass  = document.getElementById('as_pass').value;
  const tok   = document.getElementById('as_token').value.trim();
  const errEl = document.getElementById('asErr');
  errEl.textContent = '';

  if (!url) { errEl.textContent = 'API URL is required'; return; }

  let token = tok;
  if (!token) {
    if (!user || !pass) { errEl.textContent = 'Username + password or token required'; return; }
    try {
      const res = await fetch(url + '/api/login', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username: user, password: pass })
      });
      const d = await res.json();
      if (!res.ok) { errEl.textContent = d.detail || 'Login failed'; return; }
      token = d.token;
    } catch { errEl.textContent = 'Connection failed'; return; }
  }

  const existing = _servers.find(s => s.url === url);
  const id       = existing ? existing.id : 'srv_' + Date.now();
  await upsertServer({ id, name, url, token });
  toast('Server saved');
  closeModal('addServerModal');
  ['as_url','as_name','as_user','as_pass','as_token'].forEach(i => document.getElementById(i).value = '');
  renderHub();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────

(async () => {
  if (HOME_API && HOME_TOKEN) {
    const ok = await fetchServers();
    if (!ok) {
      // Stale or revoked token — clear home and show login
      localStorage.removeItem('home_api');
      localStorage.removeItem('home_token');
      localStorage.removeItem('srv_active');
      HOME_API = ''; HOME_TOKEN = '';
      document.getElementById('loginPage').style.display = '';
      document.getElementById('app').style.display       = 'none';
      const apiUrlInput = document.getElementById('apiUrl');
      if (!apiUrlInput.value) apiUrlInput.value = window.location.origin;
      return;
    }
    applyActive();
    if (getActiveServer()) { start(); return; }
    if (_servers.length)  { setActiveId(_servers[0].id); applyActive(); start(); return; }
  }
  document.getElementById('loginPage').style.display = '';
  document.getElementById('app').style.display       = 'none';
  const apiUrlInput = document.getElementById('apiUrl');
  if (!apiUrlInput.value) apiUrlInput.value = window.location.origin;
})();
