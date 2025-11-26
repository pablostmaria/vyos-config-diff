// static/app.js
// VyOS VPN Tools JavaScript

console.log('VyOS VPN Tools JS loaded');

const uploadBtn = document.getElementById('uploadBtn');
const fileInput = document.getElementById('fileInput');
const content = document.getElementById('content');
const themeSelect = document.getElementById('themeSelect');

// --- THEME LOGIC ---
const savedTheme = localStorage.getItem('vyos-theme') || 'light';
document.documentElement.setAttribute('data-theme', savedTheme);
themeSelect.value = savedTheme;

themeSelect.addEventListener('change', (e) => {
  const t = e.target.value;
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('vyos-theme', t);
});

let VPN_DATA = [];

// ========= CARGA DE FICHERO =========
uploadBtn.onclick = () => fileInput.click();

fileInput.onchange = async () => {
  try {
    const file = fileInput.files[0];
    if (!file) return;
    const fd = new FormData(); fd.append('file', file);
    const res = await fetch('/upload', { method: 'POST', body: fd });
    const j = await res.json();
    if (j.status !== 'ok') return alert(j.message);
    VPN_DATA = j.data;
    renderIPsecTable(VPN_DATA);
  } catch (e) { console.error(e); alert('Error uploading file'); }
};

// ========= RENDER IPSEC TABLE =========
function renderIPsecTable(data) {
  if (!data || data.length === 0) {
    content.innerHTML = '<div class="card"><p>No IPsec configuration found.</p></div>';
    return;
  }

  let html = `
    <div class="card">
      <div class="flex justify-between items-center mb-4">
        <h2>IPsec Configuration</h2>
        <button class="btn" onclick="downloadCommands()">Descargar comandos</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Peer</th>
              <th>Tipo</th>
              <th>Encryption</th>
              <th>Hash</th>
              <th>DH Group</th>
              <th>Lifetime</th>
              <th>Detalles</th>
            </tr>
          </thead>
          <tbody>
  `;

  data.forEach(row => {
    html += `
      <tr>
        <td>${row.name}</td>
        <td>${row.peer}</td>
        <td>${row.type}</td>
        <td>${row.encryption}</td>
        <td>${row.hash}</td>
        <td>${row.dh_group}</td>
        <td>${row.lifetime}</td>
        <td style="white-space: pre-wrap; font-size: 0.85em;">${row.details}</td>
      </tr>
    `;
  });

  html += `
          </tbody>
        </table>
      </div>
    </div>
  `;

  content.innerHTML = html;
}

// ========= DOWNLOAD COMMANDS =========
function downloadCommands() {
  if (!VPN_DATA || VPN_DATA.length === 0) return alert('No data to download');

  let text = '';
  VPN_DATA.forEach(row => {
    if (row.raw_config) {
      text += row.raw_config + '\n';
    }
  });

  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vyos_ipsec_commands.txt';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ========= CONNECT MODAL =========
document.getElementById('fetchBtn').onclick = openFetchModal;

function openFetchModal() {
  // Check if modal already exists
  if (document.querySelector('.modal')) return;

  const html = `
    <div class="modal">
      <div class="modal-content">
        <h3>Connect to VyOS</h3>
        <label>Host / FQDN:
          <input id="fw_host" placeholder="10.0.0.5" />
        </label><br/>
        <label>SSH Port:
          <input id="fw_port" placeholder="22" value="22" />
        </label><br/>
        <label>User (default vyos):
          <input id="fw_user" placeholder="vyos" />
        </label><br/>
        <label>Password (optional):
          <input id="fw_pass" type="password" />
        </label><br/><br/>
        <button class="btn primary" id="doFetch">Conectar</button>
        <button class="btn" onclick="closeModal()">Cancelar</button>
        <div id="fetchError" style="color:red;margin-top:8px;"></div>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', html);
  document.getElementById('doFetch').onclick = doFetchConfig;
}

function closeModal() {
  const m = document.querySelector('.modal');
  if (m) m.remove();
}

async function doFetchConfig() {
  const host = document.getElementById('fw_host').value.trim();
  const port = parseInt(document.getElementById('fw_port').value, 10) || 22;
  const user = document.getElementById('fw_user').value.trim() || 'vyos';
  const pass = document.getElementById('fw_pass').value;

  if (!host) {
    return document.getElementById('fetchError').textContent = 'Host is required';
  }

  const btn = document.getElementById('doFetch');
  btn.disabled = true;
  btn.textContent = 'Cargando configuración IPsec...';
  document.getElementById('fetchError').textContent = '';

  try {
    const res = await fetch('/fetch-config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port, user, password: pass || null })
    });
    const j = await res.json();
    if (!res.ok) throw new Error(j.error || 'Unknown error');

    closeModal();
    VPN_DATA = j.data;
    renderIPsecTable(VPN_DATA);
  }
  catch (e) {
    document.getElementById('fetchError').textContent = e.message;
  }
  finally {
    btn.disabled = false;
    btn.textContent = 'Conectar';
  }
}
