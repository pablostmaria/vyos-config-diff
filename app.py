# app.py
from flask import Flask, render_template, request, jsonify
import json
import paramiko
import threading
import time
import socket
from parser import parse_ipsec_blocks

app = Flask(__name__)

# Variable global para almacenar la configuración (ahora lista de VPNs)
VPN_DATA = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    # Mantener soporte de upload si el usuario sube un fichero de comandos?
    # El usuario pidió "Descargar CSV o Descargar comandos", no explícitamente subir.
    # Pero el botón de upload existe en la UI.
    # Si suben un JSON, fallará. Si suben texto, podríamos parsearlo.
    # Por ahora, dejaremos esto como stub o intentaremos parsear si es texto.
    global VPN_DATA
    f = request.files.get('file')
    if not f:
        return jsonify({'status':'error','message':'No file uploaded'}), 400
    try:
        content = f.read().decode('utf-8', errors='ignore')
        VPN_DATA = parse_ipsec_blocks(content)
        return jsonify({'status':'ok', 'data': VPN_DATA})
    except Exception as e:
        return jsonify({'status':'error','message': str(e)}), 400

@app.route('/api/ipsec')
def get_ipsec():
    return jsonify(VPN_DATA)

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

        chan = ssh.invoke_shell()
        time.sleep(0.5)
        chan.recv(9999)

        chan.send('configure\n')
        time.sleep(0.2)
        # Usamos 'show configuration commands | match vpn' para extraer solo VPN
        chan.send('run show configuration commands | match vpn\n')
        time.sleep(0.5)
        chan.send('exit\n') # exit config mode
        time.sleep(0.2)
        chan.send('exit\n') # exit shell
        
        output = b''
        start_time = time.time()
        last_recv  = start_time
        while time.time() - start_time < 30:
            if chan.recv_ready():
                chunk = chan.recv(4096)
                output += chunk
                last_recv = time.time()
            else:
                time.sleep(0.1)
                if time.time() - last_recv > 2:
                    break

        ssh.close()

        text = output.decode('utf-8', errors='ignore')
        
        # Parsear la salida
        global VPN_DATA
        VPN_DATA = parse_ipsec_blocks(text)
        
        return jsonify({'status': 'ok', 'data': VPN_DATA})
    except paramiko.AuthenticationException:
        return jsonify(error='Autenticación SSH fallida'), 401
    except Exception as e:
        return jsonify(error=str(e)), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5500, debug=False)

