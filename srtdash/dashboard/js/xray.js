// ── Xray.js ────────────────────────────────────────────────────────────────────
// Client-side helpers for Xray management in the dashboard

// Xray API endpoints and utilities
const XrayAPI = {
  // Get all Xray inbounds
  async listInbounds() {
    const res = await apiFetch('/api/xray/inbounds');
    return res.ok ? res.json() : [];
  },

  // Get users for a specific inbound
  async listUsersForInbound(tag) {
    const res = await apiFetch(`/api/xray/inbounds/${tag}/users`);
    return res.ok ? res.json() : [];
  },

  // Add a user to an inbound
  async addUserToInbound(tag, username, password, uid) {
    const body = { username, password, uid };
    const res = await apiFetch(`/api/xray/inbounds/${tag}/users`, {
      method: 'POST',
      body: JSON.stringify(body)
    });
    return res.ok ? res.json() : null;
  },

  // Remove a user from an inbound
  async removeUserFromInbound(tag, username) {
    const res = await apiFetch(`/api/xray/inbounds/${tag}/users/${username}`, {
      method: 'DELETE'
    });
    return res.ok;
  }
};

// Xray UI helpers
const XrayUI = {
  // Render inbound management card
  renderInboundCard(inbound) {
    const { tag, protocol, port, clients } = inbound;
    const clientCount = clients ? clients.length : 0;
    
    return `
      <div class="inbound-card" style="border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            <h5 style="margin:0;font-size:14px;font-weight:600">${tag}</h5>
            <div style="font-size:12px;color:var(--text3);margin-top:4px">
              ${protocol.toUpperCase()} on port ${port} — ${clientCount} client(s)
            </div>
          </div>
          <div style="display:flex;gap:6px">
            <button class="btn-sm" onclick="XrayUI.showInboundDetails('${tag}')">Info</button>
            <button class="btn-sm" onclick="XrayUI.showClientsModal('${tag}')">Manage</button>
          </div>
        </div>
      </div>
    `;
  },

  // Show inbound details
  async showInboundDetails(tag) {
    const users = await XrayAPI.listUsersForInbound(tag);
    if (!users || !users.length) {
      toast('No users in this inbound', 'info');
      return;
    }
    
    const html = users.map(u => `
      <div style="font-size:12px;padding:8px;border-bottom:1px solid var(--border)">
        <strong>${u.email || u.username}</strong>
        <div style="color:var(--text3);font-size:11px;margin-top:2px">${u.id || u.password || '—'}</div>
      </div>
    `).join('');
    
    alert(`Users in ${tag}:\n\n${html}`);
  },

  // Show clients management modal
  async showClientsModal(tag) {
    const users = await XrayAPI.listUsersForInbound(tag);
    toast(`Managing ${users ? users.length : 0} users in ${tag}`, 'info');
    // Extended functionality can be added here
  }
};

// Initialize Xray panel on dashboard load
function initXrayPanel() {
  // Can be called from main dashboard initialization
  // Placeholder for future enhancements
}
