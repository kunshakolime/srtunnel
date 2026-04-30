let currentFilePath = "/";

async function loadFiles() {
  document.getElementById('filesContent').innerHTML = '<div style="text-align:center;padding:40px"><span class="spinner"></span></div>';
  try {
    const res = await apiFetch('/api/files/list?directory=' + encodeURIComponent(currentFilePath));
    if (!res.ok) throw new Error('Failed to load files');
    
    const data = await res.json();
    
    if (!data.exists) {
      document.getElementById('filesContent').innerHTML = '<div style="padding:20px;color:var(--text3)">Directory not found</div>';
      return;
    }
    
    const rows = [];
    
    if (currentFilePath !== "/") {
      rows.push('<tr style="cursor:pointer" onclick="goUpDir()"><td colspan="4" style="color:var(--accent)">⬆ ..</td></tr>');
    }
    
    for (const d of data.dirs || []) {
      rows.push(`<tr style="cursor:pointer" onclick="enterDir('${d.name}')">
        <td>📁</td>
        <td><strong>${d.name}</strong></td>
        <td style="color:var(--text3)">—</td>
        <td><button class="btn-sm btn-danger" onclick="event.stopPropagation();deleteItem('${d.name}', true)">Delete</button></td>
      </tr>`);
    }
    
    for (const f of data.files || []) {
      const size = formatBytes(f.size);
      rows.push(`<tr>
        <td>📄</td>
        <td style="cursor:pointer" onclick="editFile('${f.name}')"><strong>${f.name}</strong></td>
        <td>${size}</td>
        <td style="display:flex;gap:6px">
          <button class="btn-sm" onclick="editFile('${f.name}')">Edit</button>
          <button class="btn-sm" onclick="downloadFile('${f.name}')">Get</button>
          <button class="btn-sm btn-danger" onclick="event.stopPropagation();deleteItem('${f.name}', false)">Delete</button>
        </td>
      </tr>`);
    }
    
    const container = document.getElementById('filesContent');
    if (rows.length === 0) {
      container.innerHTML = '<div style="padding:20px;color:var(--text3)">Empty directory</div>';
    } else {
      container.innerHTML = '<table><thead><tr><th></th><th>Name</th><th>Size</th><th>Actions</th></tr></thead><tbody>' + rows.join('') + '</tbody></table>';
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
  if (currentFilePath === "/") currentFilePath = "/" + name;
  else currentFilePath += "/" + name;
  document.getElementById('filesPath').value = currentFilePath;
  loadFiles();
}

function goToPath() {
  currentFilePath = document.getElementById('filesPath').value || "/";
  if (!currentFilePath.startsWith("/")) currentFilePath = "/" + currentFilePath;
  loadFiles();
}

function goUpDir() {
  if (currentFilePath === "/") return;
  const parts = currentFilePath.split("/").filter(Boolean);
  parts.pop();
  currentFilePath = "/" + parts.join("/");
  document.getElementById('filesPath').value = currentFilePath;
  loadFiles();
}

async function editFile(name) {
  const path = currentFilePath === "/" ? name : currentFilePath + "/" + name;
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
  const path = currentFilePath === "/" ? name : currentFilePath + "/" + name;
  const token = localStorage.getItem('home_token') || '';
  
  const res = await fetch('/api/files/download/' + encodeURIComponent(path), {
    headers: { 'Authorization': 'Bearer ' + token }
  });
  if (!res.ok) { toast('Failed to download', 'err'); return; }
  
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}

function openUploadModal() {
  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.display = 'flex';
  modal.innerHTML = `
    <div class="modal-box" style="max-width:500px">
      <h4>Upload File</h4>
      <div style="color:var(--text3);font-size:13px;margin-bottom:12px">Uploading to <code style="color:var(--accent)">${currentFilePath}</code></div>
      <div class="upload-drop-zone" id="uploadDropZone">
        <input type="file" id="uploadInput" style="display:none">
        <div id="uploadDropText">
          <div style="font-size:28px;margin-bottom:8px">📂</div>
          <div>Click to select or drag &amp; drop a file</div>
        </div>
      </label>
      <div id="uploadProgressWrap" style="display:none;margin-top:16px">
        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
          <span id="uploadFileName" style="color:var(--text3)"></span>
          <span id="uploadPercent" style="color:var(--accent)">0%</span>
        </div>
        <div class="bar-wrap" style="height:6px">
          <div id="uploadBar" class="bar" style="width:0%;background:var(--accent);transition:width 0.15s"></div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn-sm" onclick="this.closest('.modal').remove()">Cancel</button>
        <button class="btn" id="uploadBtn" onclick="doUpload()" disabled>Upload</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  const input = document.getElementById('uploadInput');
  const dropZone = document.getElementById('uploadDropZone');
  const btn = document.getElementById('uploadBtn');
  const dropText = document.getElementById('uploadDropText');

  input.addEventListener('click', e => e.stopPropagation());
  input.addEventListener('change', () => { if (input.files.length) handleUploadFile(input.files[0]); });
  dropZone.addEventListener('click', () => input.click());
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.style.borderColor = 'var(--accent)'; });
  dropZone.addEventListener('dragleave', () => { dropZone.style.borderColor = ''; });
  dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.style.borderColor = ''; handleUploadFile(e.dataTransfer.files[0]); });

  function handleUploadFile(file) {
    dropText.innerHTML = `<div style="font-size:20px;margin-bottom:4px">📄</div><div><strong>${file.name}</strong><br><span style="color:var(--text3)">${formatBytes(file.size)}</span></div>`;
    btn.disabled = false;
    modal._uploadFile = file;
  }
}

async function doUpload() {
  const modal = document.querySelector('.modal:last-child');
  const file = modal._uploadFile;
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  const token = localStorage.getItem('home_token') || '';
  const progressWrap = document.getElementById('uploadProgressWrap');
  const bar = document.getElementById('uploadBar');
  const percent = document.getElementById('uploadPercent');
  const nameEl = document.getElementById('uploadFileName');
  const btn = document.getElementById('uploadBtn');

  btn.disabled = true;
  btn.textContent = 'Uploading…';
  progressWrap.style.display = 'block';
  nameEl.textContent = file.name;

  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/files/upload/' + encodeURIComponent(currentFilePath));
    xhr.setRequestHeader('Authorization', 'Bearer ' + token);

    xhr.upload.addEventListener('progress', e => {
      if (e.lengthComputable) {
        const pct = Math.round(e.loaded / e.total * 100);
        bar.style.width = pct + '%';
        percent.textContent = pct + '%';
      }
    });

    xhr.addEventListener('load', () => {
      if (xhr.status === 200) {
        toast('File uploaded: ' + file.name);
        modal.remove();
        loadFiles();
      } else {
        try { const d = JSON.parse(xhr.responseText); toast(d.detail || 'Failed to upload', 'err'); }
        catch { toast('Failed to upload', 'err'); }
        btn.disabled = false;
        btn.textContent = 'Upload';
      }
      resolve();
    });

    xhr.addEventListener('error', () => { toast('Upload failed', 'err'); resolve(); });
    xhr.send(formData);
  });
}

async function deleteItem(name, isDir) {
  if (!confirm(`Delete ${name}?`)) return;
  const path = currentFilePath === "/" ? name : currentFilePath + "/" + name;
  const res = await apiFetch('/api/files/' + encodeURIComponent(path), { method: 'DELETE' });
  if (res.ok) { toast('Deleted'); loadFiles(); }
  else { toast('Failed to delete', 'err'); }
}

function openNewFileModal() {
  const name = prompt("File name:");
  if (!name) return;
  const path = currentFilePath === "/" ? name : currentFilePath + "/" + name;
  const res = apiFetch('/api/files/create/' + encodeURIComponent(path), {
    method: 'POST',
    body: JSON.stringify({ path, content: "" })
  });
  if (res.ok) { toast('File created'); loadFiles(); }
  else { toast('Failed to create', 'err'); }
}

async function openNewDirModal() {
  const name = prompt("Folder name:");
  if (!name) return;
  const path = currentFilePath === "/" ? name : currentFilePath + "/" + name;
  const res = await apiFetch('/api/files/create-dir/' + encodeURIComponent(path), { method: 'POST' });
  if (res.ok) { toast('Folder created'); loadFiles(); }
  else { toast('Failed to create', 'err'); }
}
