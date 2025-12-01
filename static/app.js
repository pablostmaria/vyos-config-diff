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

  // Determine labels based on environment
  const isNGCS = data.system?.environment === 'NGCS';
  const labelEth0 = isNGCS ? 'IP WAN/Gestión' : 'IP Gestión';
  const labelEth1 = isNGCS ? 'IP LAN' : 'IP WAN';

  let html = `
    <div class="card">
      <h2 style="margin-bottom: 1.5rem;">VyOS: ${hostname}</h2>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Versión</th>
              <th>Entorno</th>
              <th>Modo IPsec</th>
              <th>${labelEth0}</th>
              <th>${labelEth1}</th>
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
              <td>${data.system?.environment || 'N/A'}</td>
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

  const vpnData = data.vpn_data || data.sa; // Fallback for backward compatibility if needed

  if (vpnData && vpnData.length > 0) {
    html += `
      <div class="card">
        <h2 style="margin-bottom: 1.5rem;">Información VPN IPsec</h2>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Peer</th>
                <th>Type</th>
                <th>Estado</th>
                <th>Local TS</th>
                <th>Remote TS</th>
                <th>Uptime</th>
              </tr>
            </thead>
            <tbody>
    `;

    vpnData.forEach(row => {
      // Create status indicator (green circle for "up", red circle for "down")
      const statusIcon = row.state.toLowerCase() === 'up'
        ? '<span style="display: inline-block; width: 12px; height: 12px; background-color: #10b981; border-radius: 50%;"></span>'
        : '<span style="display: inline-block; width: 12px; height: 12px; background-color: #ef4444; border-radius: 50%;"></span>';

      // Handle old data structure if fallback is used (though backend is updated)
      const peer = row.peer || row.connection;
      const type = row.type || 'N/A';
      const localTS = row.local_ts || 'N/A';
      const remoteTS = row.remote_ts || 'N/A';
      const uptime = row.uptime || 'N/A';

      html += `
        <tr>
          <td>${peer}</td>
          <td>${type}</td>
          <td>${statusIcon}</td>
          <td>${localTS}</td>
          <td>${remoteTS}</td>
          <td>${uptime}</td>
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
