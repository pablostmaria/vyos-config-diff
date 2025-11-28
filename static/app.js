// static/app.js
// VyOS VPN Tools JavaScript

console.log('VyOS VPN Tools JS loaded');

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

// ========= RENDER IPSEC SA TABLE =========
function renderIPsecSA(data) {
  if (!data) {
    content.innerHTML = '<div class="card"><p>No data available.</p></div>';
    return;
  }

  const hostname = data.system?.hostname || 'Unknown';

  // Helper function to remove network mask from IP
  const cleanIP = (ip) => {
    if (!ip || ip === 'N/A') return 'N/A';
    return ip.split('/')[0];
  };

  let html = `
    <div class="card">
      <h2 style="margin-bottom: 1.5rem;">VyOS: ${hostname}</h2>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Versión</th>
              <th>Modo IPsec</th>
              <th>IP Gestión</th>
              <th>IP WAN</th>
  `;

  // Add VLAN headers if they exist
  if (data.system?.eth2_vlans && data.system.eth2_vlans.length > 0) {
    data.system.eth2_vlans.forEach(vlan => {
      html += `<th>VLAN ${vlan.vlan_id}</th>`;
    });
  }

  html += `
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>${data.system?.version || 'N/A'}</td>
              <td>${data.mode || 'N/A'}</td>
              <td>${cleanIP(data.system?.eth0_ip)}</td>
              <td>${cleanIP(data.system?.eth1_ip)}</td>
  `;

  // Add VLAN IPs
  if (data.system?.eth2_vlans && data.system.eth2_vlans.length > 0) {
    data.system.eth2_vlans.forEach(vlan => {
      html += `<td>${cleanIP(vlan.ip)}</td>`;
    });
  }

  html += `
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  `;

  if (data.sa && data.sa.length > 0) {
    html += `
      <div class="card">
        <h2>Security Associations</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Conexión</th>
                <th>Estado</th>
                <th>Uptime</th>
                <th>Bytes</th>
                <th>Paquetes</th>
                <th>Remote Address</th>
                <th>Remote ID</th>
                <th>Proposal</th>
              </tr>
            </thead>
            <tbody>
    `;

    data.sa.forEach(row => {
      html += `
        <tr>
          <td>${row.connection}</td>
          <td>${row.state}</td>
          <td>${row.uptime}</td>
          <td>${row.bytes}</td>
          <td>${row.packets}</td>
          <td>${row.remote_address}</td>
          <td>${row.remote_id}</td>
          <td style="font-size: 0.85em;">${row.proposal}</td>
        </tr>
      `;
    });

    html += `
            </tbody>
          </table>
        </div>
      </div>
    `;
  } else {
    html += `
      <div class="card">
        <p>No active Security Associations found.</p>
      </div>
    `;
  }

  content.innerHTML = html;
}

// ========= CONNECT MODAL =========
document.getElementById('fetchBtn').onclick = openFetchModal;

function openFetchModal() {
  // Check if modal already exists
  if (document.querySelector('.modal')) return;

  const html = `
    <div class="modal">
      <div class="modal-content">
        <h3>Conectar a VyOS</h3>
        <label>Host / FQDN:
          <input id="fw_host" placeholder="10.0.0.5" />
        </label><br/>
        <label>Puerto SSH:
          <input id="fw_port" placeholder="22" value="22" />
        </label><br/>
        <label>Usuario (por defecto vyos):
          <input id="fw_user" placeholder="vyos" />
        </label><br/>
        <label>Password (opcional):
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
  btn.textContent = 'Conectando a VyOS...';
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
    renderIPsecSA(j.data);
  }
  catch (e) {
    document.getElementById('fetchError').textContent = e.message;
  }
  finally {
    btn.disabled = false;
    btn.textContent = 'Conectar';
  }
}
