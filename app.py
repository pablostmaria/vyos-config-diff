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
        # Use a more specific command to check for VTI interfaces
        stdin, stdout, stderr = ssh.exec_command("show interfaces vti")
        data = stdout.read().decode('utf-8', errors='ignore')
        
        # If the command returns interface details (not an error), VTI exists
        if "vti" in data.lower() and ("up" in data.lower() or "down" in data.lower()):
            return "Enrutado (VTI)"
        else:
            return "Políticas"
    except Exception as e:
        # If command fails, try alternative method
        try:
            stdin, stdout, stderr = ssh.exec_command("show interfaces")
            data = stdout.read().decode('utf-8', errors='ignore')
            if "vti" in data.lower():
                return "Enrutado (VTI)"
            else:
                return "Políticas"
        except:
            return "Políticas"

def get_ipsec_sa(ssh):
    """
    Parses 'show vpn ipsec sa' output.
    Returns: List of SA entries
    """
    try:
        stdin, stdout, stderr = ssh.exec_command("show vpn ipsec sa")
        raw = stdout.read().decode('utf-8', errors='ignore')
        
        # Split into lines and filter
        lines = raw.splitlines()
        lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith('-')]
        
        # Debug: print raw output (will appear in server logs)
        print(f"DEBUG: Raw SA output:\n{raw}")
        print(f"DEBUG: Filtered lines: {len(lines)}")
        
        if len(lines) < 2:
            return []
        
        entries = []
        # Skip the first line (header)
        for line in lines[1:]:
            # Split by multiple spaces (2 or more)
            parts = re.split(r'\s{2,}', line)
            
            print(f"DEBUG: Line: {line}")
            print(f"DEBUG: Parts: {parts} (count: {len(parts)})")
            
            if len(parts) < 7:
                continue
            
            entries.append({
                "connection": parts[0],
                "state": parts[1],
                "uptime": parts[2],
                "bytes": parts[3],
                "packets": parts[4],
                "remote_address": parts[5],
                "remote_id": parts[6],
                "proposal": parts[7] if len(parts) > 7 else ""
            })
        
        print(f"DEBUG: Total entries parsed: {len(entries)}")
        return entries
    except Exception as e:
        print(f"ERROR in get_ipsec_sa: {str(e)}")
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
