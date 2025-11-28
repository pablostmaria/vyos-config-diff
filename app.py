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

def get_ipsec_sa(ssh):
    """
    Parses 'show vpn ipsec sa' output.
    Returns: List of SA entries
    """
    try:
        # Use vbash to execute VyOS commands
        cmd = "/usr/bin/vbash -ic 'show vpn ipsec sa'"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        raw = stdout.read().decode('utf-8', errors='ignore')
        
        print(f"DEBUG SA: Command: {cmd}")
        print(f"DEBUG SA: Raw output length: {len(raw)}")
        print(f"DEBUG SA: First 500 chars:\n{raw[:500]}")
        
        # Split into lines
        lines = raw.splitlines()
        print(f"DEBUG SA: Total lines: {len(lines)}")
        
        # Filter out empty lines and separator lines
        filtered_lines = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('-'):
                filtered_lines.append(stripped)
                print(f"DEBUG SA: Line {i}: '{stripped}'")
        
        print(f"DEBUG SA: Filtered lines count: {len(filtered_lines)}")
        
        if len(filtered_lines) < 2:
            print("DEBUG SA: Not enough lines (need at least header + 1 data row)")
            return []
        
        entries = []
        # Skip the first line (header)
        for i, line in enumerate(filtered_lines[1:], start=1):
            print(f"DEBUG SA: Processing data line {i}: '{line}'")
            
            # Try different splitting strategies
            # Strategy 1: Split by 2+ spaces
            parts = re.split(r'\s{2,}', line)
            print(f"DEBUG SA: Split by 2+ spaces: {parts} (count: {len(parts)})")
            
            # If that didn't work well, try single space but be smarter
            if len(parts) < 7:
                parts = line.split()
                print(f"DEBUG SA: Split by single space: {parts} (count: {len(parts)})")
            
            if len(parts) < 7:
                print(f"DEBUG SA: Skipping line {i} - not enough parts")
                continue
            
            entry = {
                "connection": parts[0],
                "state": parts[1],
                "uptime": parts[2],
                "bytes": parts[3],
                "packets": parts[4],
                "remote_address": parts[5],
                "remote_id": parts[6],
                "proposal": parts[7] if len(parts) > 7 else ""
            }
            
            print(f"DEBUG SA: Created entry: {entry}")
            entries.append(entry)
        
        print(f"DEBUG SA: Total entries parsed: {len(entries)}")
        return entries
        
    except Exception as e:
        print(f"ERROR in get_ipsec_sa: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

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

        # Get IPsec mode
        mode = get_ipsec_mode(ssh)
        
        # Get IPsec SA information
        sa_info = get_ipsec_sa(ssh)
        
        ssh.close()
        
        return jsonify({
            'status': 'ok',
            'data': {
                'mode': mode,
                'sa': sa_info
            }
        })
    except paramiko.AuthenticationException:
        return jsonify(error='Autenticación SSH fallida'), 401
    except Exception as e:
        return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=False)
