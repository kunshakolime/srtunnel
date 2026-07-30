// ── Navigation ────────────────────────────────────────────────────────────────

let _currentPage = 'dashboard';

function showPage(name, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  if (btn) btn.classList.add('active');

  const leaving = _currentPage;
  _currentPage  = name;

  // stop page-specific timers from the page we're leaving
  if (leaving === 'dashboard') _stopDashboardTimer();
  if (leaving === 'services')  stopLogStream();

  // start timers for the page we're entering
  if (name === 'dashboard') {
    loadDashboard();
    _startDashboardTimer();
  } else if (name === 'services') {
    loadServices();
  } else {
    const loader = _loaders[name];
    if (loader) loader();
  }
}

// ── Dashboard auto-refresh (own timer, no overlap) ────────────────────────────

function _getDashInterval() {
  return parseInt(localStorage.getItem('dash_interval')) || 5000;
}

let _dashTimer   = null;
let _dashFetching = false;

function setDashInterval(val) {
  localStorage.setItem('dash_interval', val);
  if (_currentPage === 'dashboard') {
    _stopDashboardTimer();
    if (parseInt(val) > 0) _startDashboardTimer();
  }
}

function _startDashboardTimer() {
  _stopDashboardTimer();
  const ms = _getDashInterval();
  if (ms > 0 && !document.hidden) _dashTimer = setTimeout(_dashTick, ms);
}

function _stopDashboardTimer() {
  clearTimeout(_dashTimer);
  _dashTimer = null;
}

async function _dashTick() {
  if (_currentPage !== 'dashboard' || document.hidden || _sessionDead) return;
  const ms = _getDashInterval();
  if (_dashFetching) { _dashTimer = setTimeout(_dashTick, ms); return; }
  _dashFetching = true;
  try { await loadDashboard(); } catch { /* silent */ }
  _dashFetching = false;
  if (_currentPage === 'dashboard' && !document.hidden && !_sessionDead) {
    _dashTimer = setTimeout(_dashTick, ms);
  }
}

// ── Other pages: load once on tab switch, no auto-refresh ─────────────────────

const _loaders = {
  users:   () => loadUsers(),
  xray:    () => loadXray(),
  dns:     () => loadDns(),
  terminal: () => loadTerminal(),
  scope:   () => loadScope(),
  servers: () => { loadServersPage(); loadTokens(); },
  tokens:  () => {},
  files:   () => loadFiles(),
};

function manualRefresh() {
  if (_currentPage === 'dashboard') { loadDashboard(); return; }
  if (_currentPage === 'services')  { loadServices();  return; }
  const loader = _loaders[_currentPage];
  if (loader) loader();
}

// ── Last-refresh stamp (in dash-spin) ─────────────────────────────────────────

let _lastRefresh = null;
let _stampTimer  = null;

function markRefresh() {
  _lastRefresh = Date.now();
  _updateStamp();
}

function _updateStamp() {
  clearInterval(_stampTimer);
  const el = document.getElementById('dash-stamp');
  if (!el) return;
  const update = () => {
    if (!_lastRefresh) { el.textContent = ''; return; }
    const s = Math.round((Date.now() - _lastRefresh) / 1000);
    el.textContent = s < 5 ? 'just now' : `${s}s ago`;
  };
  update();
  _stampTimer = setInterval(update, 5000);
}

// ── Pause/resume on tab visibility ───────────────────────────────────────────

document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    _stopDashboardTimer();
    stopLogStream();
  } else {
    if (_currentPage === 'dashboard') _startDashboardTimer();
    if (_currentPage === 'services')  startLogStream();
  }
});

// ── Hub dot state (driven by health-check loop in auth.js) ───────────────────

function _setDot(serverId, state) {
  const dot = document.getElementById('hub-dot-' + serverId);
  if (!dot) return;
  dot.className = 'server-dot ' + state;
}

// ── Modal Helpers ─────────────────────────────────────────────────────────────

function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.modal').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
  });
  const sel = document.getElementById('dash-interval');
  if (sel) sel.value = '' + _getDashInterval();
});

function copySessionToken() {
  if (!TOKEN) { toast('No active token', 'err'); return; }
  navigator.clipboard.writeText(TOKEN).then(() => {
    const btn = document.getElementById('tokenCopyBtn');
    btn.textContent = '✓ copied';
    setTimeout(() => btn.textContent = 'copy token', 1500);
  });
}
