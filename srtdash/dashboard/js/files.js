// ── Files ────────────────────────────────────────────────────────────────────

let currentFilePath = ".";

async function loadFiles() {
  document.getElementById('filesContent').innerHTML = '<div style="text-align:center;padding:40px"><span class="spinner"></span></div>';
  try {
    const res = await apiFetch('/api/files/list/' + encodeURIComponent(currentFilePath));
    if (!res.ok) throw new Error('Failed to load files');
    const data = await res.json();
    
    if (!data.exists) {
      document.getElementById('filesContent').innerHTML = '<div style="padding:20px;color:var(--text3)">Directory not found</div>';
      return;
    }
    
    const rows = [];
    
    // Parent directory
    if (currentFilePath !== ".") {
      rows.push('<tr style="cursor:pointer" onclick="goUpDir()"><td colspan="4" style="color:var(--accent)">⬆ ..</td></tr>');
    }
    
    // Directories
    for (const d of data.dirs || []) {
      rows.push(`<tr style="cursor:pointer" onclick="enterDir('${d.name}')">
        <td>📁</td>
        <td><strong>${d.name}</strong></td>
        <td style="color:var(--text3)">—</td>
        <td><button class="btn-sm btn-danger" onclick="event.stopPropagation();deleteItem('${d.name}', true)">Delete</button></td>
      </tr>`);
    }
    
    // Files
    for (const f of data.files || []) {
      const size = formatBytes(f.size);
      rows.push(`<tr>
        <td>📄</td>
        <td style="cursor:pointer" onclick="editFile('${f.name}')"><strong>${f.name}</strong></td>
        <td>${size}</td>
        <td style="display:flex;gap:6px">
          <button class="btn-sm" onclick="editFile('${f.name}')">Edit</button>
          <button class="btn-sm" onclick="downloadFile('${f.name}')">Get</button>
          <button class="btn-sm btn-danger" onclick="deleteItem('${f.name}', false)">Delete</button>
        </td>
      </tr>`);
    }
    
    if (rows.length === 0) {
      document.getElementById('filesContent').innerHTML = '<div style="padding:20px;color:var(--text3)">Empty directory</div>';
    } else {
      document.getElementById('filesContent').innerHTML = '<table><thead><tr><th></th><th>Name</th><th>Size</th><th>Actions</th></tr></thead><tbody>' + rows.join('') + '</tbody></table>';
    }
  } catch (e) {
    document.getElementById('filesContent').innerHTML = '<div style="padding:20px;color:var(--red)">Error: ' + e.message + '</div>';
  }
}

function formatBytes(b) {
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + "G";
  if (b >= 1048576) return (b / 1048576).toFixed(1) + "M";
  if (b >= 1024) return (b / 1024).toFixed(1) + "K";
  return b + "B";
}

function enterDir(name) {
  if (currentFilePath === ".") currentFilePath = name;
  else currentFilePath += "/" + name;
  document.getElementById('filesPath').value = currentFilePath;
  loadFiles();
}

function goToPath() {
  currentFilePath = document.getElementById('filesPath').value || ".";
  loadFiles();
}

function goUpDir() {
  const parts = currentFilePath.split("/");
  parts.pop();
  currentFilePath = parts.join("/") || ".";
  if (currentFilePath === "") currentFilePath = ".";
  document.getElementById('filesPath').value = currentFilePath;
  loadFiles();
}

async function editFile(name) {
  const path = currentFilePath === "." ? name : currentFilePath + "/" + name;
  const res = await apiFetch('/api/files/read/' + encodeURIComponent(path));
  if (!res.ok) { toast('Failed to read file', 'err'); return; }
  const data = await res.json();
  
  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.display = 'flex';
  modal.innerHTML = `
    <div class="modal-box" style="max-width:800px;max-height:90vh">
      <h4>Edit: ${name}</h4>
      <textarea id="fileEditor" style="width:100%;height:60vh;font-family:var(--font-mono);font-size:12px;padding:10px;">${data.content}</textarea>
      <div class="modal-footer">
        <button class="btn-sm" onclick="this.closest('.modal').remove()">Cancel</button>
        <button class="btn" onclick="saveFileContent('${path.replace(/'/g, "\\'")}')">Save</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
}

async function saveFileContent(path) {
  const content = document.getElementById('fileEditor').value;
  const res = await apiFetch('/api/files/write/' + encodeURIComponent(path), {
    method: 'POST',
    body: JSON.stringify({ path, content })
  });
  if (res.ok) { toast('File saved'); document.querySelector('.modal:last-child').remove(); loadFiles(); }
  else { toast('Failed to save', 'err'); }
}

async function downloadFile(name) {
  const path = currentFilePath === "." ? name : currentFilePath + "/" + name;
  const res = await apiFetch('/api/files/download-info/' + encodeURIComponent(path));
  if (!res.ok) { toast('Failed to get download info', 'err'); return; }
  const data = await res.json();
  toast('wget: ' + data.wget + '\ncurl: ' + data.curl, 'info');
}

async function deleteItem(name, isDir) {
  if (!confirm(`Delete ${name}?`)) return;
  const path = currentFilePath === "." ? name : currentFilePath + "/" + name;
  const res = await apiFetch('/api/files/' + encodeURIComponent(path), { method: 'DELETE' });
  if (res.ok) { toast('Deleted'); loadFiles(); }
  else { toast('Failed to delete', 'err'); }
}

function openNewFileModal() {
  const name = prompt("File name:");
  if (!name) return;
  const path = currentFilePath === "." ? name : currentFilePath + "/" + name;
  const res = apiFetch('/api/files/create/' + encodeURIComponent(path), {
    method: 'POST',
    body: JSON.stringify({ path, content: "" })
  });
  if (res.ok) { toast('File created'); loadFiles(); }
  else { toast('Failed to create', 'err'); }
}

function openNewDirModal() {
  const name = prompt("Folder name:");
  if (!name) return;
  const path = currentFilePath === "." ? name : currentFilePath + "/" + name;
  const res = apiFetch('/api/files/create-dir/' + encodeURIComponent(path), { method: 'POST' });
  if (res.ok) { toast('Folder created'); loadFiles(); }
  else { toast('Failed to create', 'err'); }
}