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
        return {}

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
        
        ssh.close()
        
        # Merge data
        merged_data = []
        
        # Iterate over configured connections
        for conn_name, conn_data in connections.items():
            # Find matching SA status
            sa_status = sa_info.get(conn_name, {})
            
            # Extract Peer IP from connection name (e.g. peer_195-53-238-105)
            peer_ip = 'N/A'
            if conn_name.startswith('peer_'):
                # Remove 'peer_' and replace '-' with '.'
                # Also handle suffixes like '-tunnel-0' if present in name (though usually it's just peer_IP)
                # Let's try to extract the IP part.
                # Regex for IP with dashes: \d+-\d+-\d+-\d+
                ip_match = re.search(r'(\d+)-(\d+)-(\d+)-(\d+)', conn_name)
                if ip_match:
                    peer_ip = f"{ip_match.group(1)}.{ip_match.group(2)}.{ip_match.group(3)}.{ip_match.group(4)}"
            
            # Map Type
            conn_type = conn_data.get('type', 'N/A')
            if 'ikev2' in conn_type.lower():
                display_type = 'Fase 1'
            elif 'ipsec' in conn_type.lower():
                display_type = 'Fase 2'
            else:
                display_type = conn_type # Fallback
            
            merged_entry = {
                'peer': peer_ip,
                'type': display_type,
                'state': sa_status.get('state', 'down'), # Default to down if no SA found
                'local_ts': conn_data.get('local_ts', 'N/A'),
                'remote_ts': conn_data.get('remote_ts', 'N/A'),
                'uptime': sa_status.get('uptime', 'N/A')
            }
            merged_data.append(merged_entry)
            
        # Also add any SAs that weren't in connections (orphans? or maybe parsing failed)
        for conn_name, sa_data in sa_info.items():
            if conn_name not in connections:
                 # Try to extract IP
                peer_ip = 'N/A'
                ip_match = re.search(r'(\d+)-(\d+)-(\d+)-(\d+)', conn_name)
                if ip_match:
                    peer_ip = f"{ip_match.group(1)}.{ip_match.group(2)}.{ip_match.group(3)}.{ip_match.group(4)}"
                
                merged_data.append({
                    'peer': peer_ip,
                    'type': 'Unknown',
                    'state': sa_data.get('state', 'down'),
                    'local_ts': 'N/A',
                    'remote_ts': 'N/A',
                    'uptime': sa_data.get('uptime', 'N/A')
                })

        return jsonify({
            'status': 'ok',
            'data': {
                'system': system_info,
                'mode': mode,
                'vpn_data': merged_data # New merged list
            }
        })
    except paramiko.AuthenticationException:
        return jsonify(error='Autenticación SSH fallida'), 401
    except Exception as e:
        return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=False)
