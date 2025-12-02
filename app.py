# app.py
from flask import Flask, render_template, request, jsonify
import json
import paramiko
import threading
import time
import socket
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def get_system_info(ssh):
    """
    Gets VyOS system information: hostname, eth0 IP, eth1 IP, eth2 VLANs, version
    """
    info = {
        'hostname': 'Unknown',
        'version': 'N/A',
        'environment': 'N/A',
        'eth0_ip': 'N/A',
        'eth1_ip': 'N/A',
        'eth2_vlans': []
    }
    
    try:
        # Get hostname
        cmd = "/usr/bin/vbash -ic 'show host name'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        hostname = stdout.read().decode('utf-8', errors='ignore').strip()
        if hostname:
            info['hostname'] = hostname
            
            # Determine Environment
            parts = hostname.split('-')
            if len(parts) >= 3 and parts[2] == 'flx':
                info['environment'] = 'Flexxible'
            elif len(parts) >= 5:
                if parts[4].startswith('cdc'):
                    if hostname.startswith('es-por-'):
                        info['environment'] = 'Cloud Builder Logroño'
                    elif hostname.startswith('es-glb-'):
                        info['environment'] = 'Cloud Builder Madrid'
                    else:
                        info['environment'] = 'Cloud Builder'
                elif parts[4].startswith('cb'):
                    info['environment'] = 'NGCS'
            
        print(f"DEBUG Hostname: {hostname}")
        print(f"DEBUG Environment: {info.get('environment', 'N/A')}")
        
        # Get version
        cmd = "/usr/bin/vbash -ic 'show version'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        version_output = stdout.read().decode('utf-8', errors='ignore')
        # Extract version number from "Version:          VyOS 1.4.3"
        match = re.search(r'Version:\s+VyOS\s+([\d.]+)', version_output)
        if match:
            info['version'] = match.group(1)
        print(f"DEBUG Version: {info['version']}")
        
        # Get eth0 IP (Always present, role depends on env)
        cmd = "/usr/bin/vbash -ic 'show interfaces ethernet eth0'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        eth0_output = stdout.read().decode('utf-8', errors='ignore')
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', eth0_output)
        if match:
            info['eth0_ip'] = match.group(1)
        print(f"DEBUG eth0: {info['eth0_ip']}")
        
        # Get eth1 IP
        # For NGCS: eth1 is LAN
        # For others: eth1 is WAN (check tagged)
        
        cmd = "/usr/bin/vbash -ic 'show interfaces ethernet eth1'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        eth1_output = stdout.read().decode('utf-8', errors='ignore')
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', eth1_output)
        
        if match:
            info['eth1_ip'] = match.group(1)
            print(f"DEBUG eth1: {info['eth1_ip']}")
        elif info['environment'] != 'NGCS':
            # Only check for tagged eth1 if NOT NGCS (or if we want to be safe, check anyway)
            # If no IP on eth1 directly, check for eth1.XXX tagged interfaces
            cmd = "/usr/bin/vbash -ic 'show interfaces'"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            interfaces_output = stdout.read().decode('utf-8', errors='ignore')
            
            # Find eth1.XXX interfaces
            eth1_vlan_matches = re.findall(r'eth1\.(\d+)', interfaces_output)
            if eth1_vlan_matches:
                # Get IP from the first eth1.XXX interface found
                vlan_id = eth1_vlan_matches[0]
                cmd = f"/usr/bin/vbash -ic 'show interfaces ethernet eth1 vif {vlan_id}'"
                stdin, stdout, stderr = ssh.exec_command(cmd)
                eth1_vlan_output = stdout.read().decode('utf-8', errors='ignore')
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', eth1_vlan_output)
                if match:
                    info['eth1_ip'] = match.group(1)
                    print(f"DEBUG eth1.{vlan_id}: {info['eth1_ip']}")
        
        if info['eth1_ip'] == 'N/A':
             print(f"DEBUG eth1: No IP found")

        # Get eth2 VLANs (Only for Cloud Builder / Flexxible usually, but safe to check)
        if info['environment'] != 'NGCS':
            cmd = "/usr/bin/vbash -ic 'show interfaces'"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            interfaces_output = stdout.read().decode('utf-8', errors='ignore')
            
            # Find all eth2.XXX interfaces
            vlan_matches = re.findall(r'eth2\.(\d+)', interfaces_output)
            print(f"DEBUG VLAN matches: {vlan_matches}")
            
            for vlan_id in set(vlan_matches):  # Use set to avoid duplicates
                # Get IP for this VLAN interface
                cmd = f"/usr/bin/vbash -ic 'show interfaces ethernet eth2 vif {vlan_id}'"
                stdin, stdout, stderr = ssh.exec_command(cmd)
                vlan_output = stdout.read().decode('utf-8', errors='ignore')
                
                vlan_ip = 'N/A'
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', vlan_output)
                if match:
                    vlan_ip = match.group(1)
                
                info['eth2_vlans'].append({
                    'vlan_id': vlan_id,
                    'interface': f'eth2.{vlan_id}',
                    'ip': vlan_ip
                })
                print(f"DEBUG VLAN {vlan_id}: {vlan_ip}")
        
        return info
        
    except Exception as e:
        print(f"ERROR in get_system_info: {str(e)}")
        import traceback
        traceback.print_exc()
        return info


def get_ipsec_mode(ssh):
    """
    Detects IPsec mode by checking if VTI interfaces exist.
    Returns: "Enrutado (VTI)" or "Políticas"
    """
    try:
        # VyOS commands need to be wrapped with /opt/vyatta/bin/vyatta-op-cmd-wrapper
        # Or we can use vbash -ic 'command'
        cmd = "/usr/bin/vbash -ic 'show interfaces vti'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdout_data = stdout.read().decode('utf-8', errors='ignore')
        stderr_data = stderr.read().decode('utf-8', errors='ignore')
        
        print(f"DEBUG VTI: Command: {cmd}")
        print(f"DEBUG VTI: stdout='{stdout_data[:200]}'")
        print(f"DEBUG VTI: stderr='{stderr_data[:200]}'")
        
        # Look for interface names like vti0, vti1, etc.
        if re.search(r'vti\d+', stdout_data, re.IGNORECASE):
            print("DEBUG VTI: Found VTI interface")
            return "Enrutado (VTI)"
        
        # Alternative: Check configuration
        cmd2 = "/usr/bin/vbash -ic 'show configuration commands | grep \"set interfaces vti\"'"
        stdin, stdout, stderr = ssh.exec_command(cmd2)
        config_data = stdout.read().decode('utf-8', errors='ignore')
        print(f"DEBUG VTI Config: '{config_data[:200]}'")
        
        if "set interfaces vti" in config_data:
            print("DEBUG VTI: Found VTI in configuration")
            return "Enrutado (VTI)"
        
        print("DEBUG VTI: No VTI found, returning Políticas")
        return "Políticas"
        
    except Exception as e:
        print(f"ERROR in get_ipsec_mode: {str(e)}")
        import traceback
        traceback.print_exc()
        return "Políticas"

def get_ipsec_connections(ssh):
    """
    Parses 'show vpn ipsec connections' output.
    Returns: Dict of connections with details (type, local_ts, remote_ts)
    """
    try:
        cmd = "/usr/bin/vbash -ic 'show vpn ipsec connections'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        raw = stdout.read().decode('utf-8', errors='ignore')
        
        print(f"DEBUG CONNECTIONS: Command: {cmd}")
        # print(f"DEBUG CONNECTIONS: First 500 chars:\n{raw[:500]}")
        
        connections = {}
        
        # Based on user screenshot, the output is a table:
        # Connection                     State    Type    Remote address    Local TS    Remote TS
        # -----------------------------  -------  ------  ----------------  ----------  ----------
        # peer_195-53-238-105            up       IKEv2   195.53.238.105    -           -
        # peer_195-53-238-105-tunnel-0   up       IPsec   195.53.238.105    0.0.0.0/0   0.0.0.0/0
        
        lines = raw.splitlines()
        
        # Filter out empty lines and separator lines
        filtered_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('-'):
                filtered_lines.append(stripped)
        
        if len(filtered_lines) < 2:
            print("DEBUG CONNECTIONS: Not enough lines")
            return {}
            
        # Skip header line (starts with "Connection")
        # We assume the columns are consistent
        
        for line in filtered_lines:
            if line.lower().startswith('connection'):
                continue
                
            # Split by whitespace
            parts = line.split()
            
            # Expected columns:
            # 0: Connection
            # 1: State
            # 2: Type
            # 3: Remote address
            # 4: Local TS
            # 5: Remote TS
            
            if len(parts) >= 6:
                conn_name = parts[0]
                conn_state = parts[1]
                conn_type = parts[2]
                local_ts = parts[4]
                remote_ts = parts[5]
                
                connections[conn_name] = {
                    'state': conn_state,
                    'type': conn_type,
                    'local_ts': local_ts if local_ts != '-' else 'N/A',
                    'remote_ts': remote_ts if remote_ts != '-' else 'N/A'
                }
            elif len(parts) >= 3:
                 # Fallback for partial lines?
                 conn_name = parts[0]
                 connections[conn_name] = {
                    'state': parts[1] if len(parts) > 1 else 'down',
                    'type': parts[2] if len(parts) > 2 else 'N/A',
                    'local_ts': 'N/A',
                    'remote_ts': 'N/A'
                }
        
        print(f"DEBUG CONNECTIONS: Parsed {len(connections)} connections")
        return connections

    except Exception as e:
        print(f"ERROR in get_ipsec_connections: {str(e)}")
        return {}

def get_vti_data(ssh):
    """
    Retrieves VTI specific configuration: bindings, local-lans, and static routes.
    """
    vti_info = {
        'bindings': {}, # peer_name -> vti_interface
        'local_lans': [],
        'routes': {} # vti_interface -> [routes]
    }
    
    try:
        # 1. Get VTI bindings
        cmd = "/usr/bin/vbash -ic 'show configuration commands | grep \"set vpn ipsec site-to-site peer\" | grep \"vti bind\"'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode('utf-8', errors='ignore')
        
        # Parse: set vpn ipsec site-to-site peer peer_185-179-185-209 vti bind 'vti1'
        for line in output.splitlines():
            match = re.search(r'peer\s+([^\s]+)\s+vti bind\s+\'?([^\']+)\'?', line)
            if match:
                peer_name = match.group(1)
                vti_iface = match.group(2)
                vti_info['bindings'][peer_name] = vti_iface
        
        # 2. Get Local LANs
        cmd = "/usr/bin/vbash -ic 'show configuration commands | grep \"set firewall group network-group local-lans\"'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode('utf-8', errors='ignore')
        
        # Parse: set firewall group network-group local-lans network '192.168.4.0/24'
        for line in output.splitlines():
            match = re.search(r'network\s+\'?([\d\./]+)\'?', line)
            if match:
                vti_info['local_lans'].append(match.group(1))
                
        # 3. Get Static Routes per VTI
        cmd = "/usr/bin/vbash -ic 'show configuration commands | grep \"set protocols static route\" | grep \"interface vti\"'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode('utf-8', errors='ignore')
        
        # Parse: set protocols static route 192.168.0.0/24 interface vti1
        for line in output.splitlines():
            match = re.search(r'route\s+([^\s]+)\s+interface\s+([^\s]+)', line)
            if match:
                route = match.group(1)
                vti_iface = match.group(2)
                if vti_iface not in vti_info['routes']:
                    vti_info['routes'][vti_iface] = []
                vti_info['routes'][vti_iface].append(route)
                
        return vti_info
        
    except Exception as e:
        print(f"ERROR in get_vti_data: {str(e)}")
        return vti_info

def get_ipsec_sa(ssh):
    """
    Parses 'show vpn ipsec sa' output.
    Returns: Dict of SA entries keyed by connection name
    """
    try:
        # Use vbash to execute VyOS commands
        cmd = "/usr/bin/vbash -ic 'show vpn ipsec sa'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        raw = stdout.read().decode('utf-8', errors='ignore')
        
        print(f"DEBUG SA: Command: {cmd}")
        
        lines = raw.splitlines()
        filtered_lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('-')]
        
        entries = {}
        
        if len(filtered_lines) < 2:
            return {}
        
        # Skip header
        for line in filtered_lines[1:]:
            parts = re.split(r'\s{2,}', line)
            if len(parts) < 7:
                parts = line.split()
            
            if len(parts) < 7:
                continue
            
            connection_name = parts[0]
            
            entry = {
                "connection": connection_name,
                "state": parts[1],
                "uptime": parts[2],
                "bytes": parts[3],
                "packets": parts[4],
                "remote_address": parts[5],
                "remote_id": parts[6],
                "proposal": parts[7] if len(parts) > 7 else ""
            }
            entries[connection_name] = entry
            
        return entries
        
    except Exception as e:
        print(f"ERROR in get_ipsec_sa: {str(e)}")
        import traceback
        traceback.print_exc()
        return {}

@app.route('/fetch-config', methods=['POST'])
def fetch_config():
    data = request.get_json() or {}
    host     = data.get('host')
    port     = data.get('port', 22)
    user     = data.get('user', 'vyos')
    password = data.get('password')

    if not host:
        return jsonify(error='Host es obligatorio'), 400

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ip_address = socket.gethostbyname(host.strip())
        except Exception as e:
            return jsonify(error=f"DNS resolution failed: {str(e)}"), 400

        if password:
            ssh.connect(hostname=ip_address, port=port, username=user,
                        password=password, timeout=5)
        else:
            ssh.connect(hostname=ip_address, port=port, username=user, timeout=5)

        # Get system information
        system_info = get_system_info(ssh)
        
        # Get IPsec mode
        mode = get_ipsec_mode(ssh)
        
        # Get IPsec connections (config)
        connections = get_ipsec_connections(ssh)
        
        # Get IPsec SA information (status)
        sa_info = get_ipsec_sa(ssh)
        
        # Get VTI specific data if mode is VTI
        vti_data = {}
        if 'VTI' in mode:
            vti_data = get_vti_data(ssh)
        
        ssh.close()
        
        # Process data based on mode
        processed_vpn_data = []
        
        # Helper to extract IP from peer name
        def extract_peer_ip(name):
            if name.startswith('peer_'):
                ip_match = re.search(r'(\d+)-(\d+)-(\d+)-(\d+)', name)
                if ip_match:
                    return f"{ip_match.group(1)}.{ip_match.group(2)}.{ip_match.group(3)}.{ip_match.group(4)}"
            return 'N/A'

        # Helper to get combined status
        def get_combined_status(peer_base_name):
            # Status is GREEN (up) only if BOTH Phase 1 and Phase 2 are UP
            # Phase 1 is usually the base name (e.g., peer_X)
            # Phase 2 usually has suffix (e.g., peer_X-tunnel-0)
            
            # Find Phase 1 status
            p1_state = 'down'
            if peer_base_name in connections:
                p1_state = connections[peer_base_name].get('state', 'down')
            elif peer_base_name in sa_info:
                p1_state = sa_info[peer_base_name].get('state', 'down')
                
            # Find Phase 2 status (any tunnel associated with this peer)
            p2_state = 'down'
            # Look for any connection starting with peer_base_name + '-'
            for conn_name, conn_val in connections.items():
                if conn_name.startswith(peer_base_name + '-'):
                    if conn_val.get('state') == 'up':
                        p2_state = 'up'
                        break
            
            # If not found in connections, check SAs
            if p2_state == 'down':
                for sa_name, sa_val in sa_info.items():
                    if sa_name.startswith(peer_base_name + '-'):
                        if sa_val.get('state') == 'up':
                            p2_state = 'up'
                            break
            
            return 'up' if (p1_state == 'up' and p2_state == 'up') else 'down'

        # Group connections by Peer (base name)
        peers = set()
        for conn_name in connections.keys():
            # Extract base peer name (e.g., peer_195-53-238-105 from peer_195-53-238-105-tunnel-0 or -vti)
            # We want to group by the IP part basically.
            # Match peer_IP-IP-IP-IP and treat everything else as suffix
            match = re.match(r'(peer_\d+-\d+-\d+-\d+)', conn_name)
            if match:
                peers.add(match.group(1))
            else:
                # Fallback for non-standard names
                peers.add(conn_name)
                
        for peer_base in peers:
            peer_ip = extract_peer_ip(peer_base)
            combined_status = get_combined_status(peer_base)
            
            if 'VTI' in mode:
                # VTI Mode Data
                vti_iface = vti_data['bindings'].get(peer_base, 'N/A')
                local_lans = vti_data['local_lans']
                routed_nets = vti_data['routes'].get(vti_iface, [])
                
                processed_vpn_data.append({
                    'peer': peer_ip,
                    'vti_iface': vti_iface,
                    'status': combined_status,
                    'local_lans': local_lans,
                    'routed_nets': routed_nets
                })
            else:
                # Policy Mode Data
                # Get Local/Remote TS from the Phase 2 connection (tunnel)
                local_ts = []
                remote_ts = []
                
                # Find associated tunnels
                for conn_name, conn_val in connections.items():
                    if conn_name.startswith(peer_base + '-'):
                        l_ts = conn_val.get('local_ts', 'N/A')
                        r_ts = conn_val.get('remote_ts', 'N/A')
                        if l_ts != 'N/A': local_ts.append(l_ts)
                        if r_ts != 'N/A': remote_ts.append(r_ts)
                
                processed_vpn_data.append({
                    'peer': peer_ip,
                    'status': combined_status,
                    'local_ts': local_ts,
                    'remote_ts': remote_ts
                })

        return jsonify({
            'status': 'ok',
            'data': {
                'system': system_info,
                'mode': mode,
                'vpn_data': processed_vpn_data
            }
        })
    except paramiko.AuthenticationException:
        return jsonify(error='Autenticación SSH fallida'), 401
    except Exception as e:
        return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=False)
