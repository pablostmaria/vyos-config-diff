import re

def parse_ipsec_blocks(raw_output):
    """
    Parses 'show configuration commands' output to extract IPsec VPN configuration.
    Ignores firewall and NAT configurations.
    Normalizes IKE and ESP group names to IKE-ACS-<n> and ESP-ACS-<n>.
    """
    lines = raw_output.splitlines()
    
    ike_groups = {}
    esp_groups = {}
    peers = {}
    
    ike_counter = 1
    esp_counter = 1
    
    # Regex patterns
    # set vpn ipsec ike-group <name> ...
    ike_pattern = re.compile(r'set vpn ipsec ike-group (\S+) (.*)')
    # set vpn ipsec ipsec-esp-group <name> ...
    esp_pattern = re.compile(r'set vpn ipsec ipsec-esp-group (\S+) (.*)')
    # set vpn ipsec site-to-site peer <peer> ...
    peer_pattern = re.compile(r'set vpn ipsec site-to-site peer (\S+) (.*)')
    
    # Mappings for normalized names
    ike_name_map = {}
    esp_name_map = {}

    for line in lines:
        line = line.strip()
        if not line.startswith('set vpn ipsec'):
            continue
            
        # IKE Groups
        match_ike = ike_pattern.match(line)
        if match_ike:
            name, rest = match_ike.groups()
            if name not in ike_name_map:
                ike_name_map[name] = f"IKE-ACS-{ike_counter}"
                ike_counter += 1
                ike_groups[ike_name_map[name]] = {
                    'original_name': name,
                    'proposals': [],
                    'lifetime': None,
                    'raw_lines': []
                }
            
            norm_name = ike_name_map[name]
            ike_groups[norm_name]['raw_lines'].append(line)
            
            # Extract details
            if 'proposal' in rest:
                # set vpn ipsec ike-group FOO proposal 1 encryption ...
                prop_match = re.search(r'proposal (\d+) (.*)', rest)
                if prop_match:
                    prop_id, prop_rest = prop_match.groups()
                    # Parse proposal details (encryption, hash, dh-group)
                    # This is a bit simplified, assuming one proposal per line usually
                    # We can aggregate them.
                    pass # Logic to parse proposal details can be refined
            
            if 'lifetime' in rest:
                 ike_groups[norm_name]['lifetime'] = rest.split('lifetime')[-1].strip()

            continue

        # ESP Groups
        match_esp = esp_pattern.match(line)
        if match_esp:
            name, rest = match_esp.groups()
            if name not in esp_name_map:
                esp_name_map[name] = f"ESP-ACS-{esp_counter}"
                esp_counter += 1
                esp_groups[esp_name_map[name]] = {
                    'original_name': name,
                    'proposals': [],
                    'lifetime': None,
                    'pfs': None,
                    'raw_lines': []
                }
            
            norm_name = esp_name_map[name]
            esp_groups[norm_name]['raw_lines'].append(line)
            
            if 'lifetime' in rest:
                esp_groups[norm_name]['lifetime'] = rest.split('lifetime')[-1].strip()
            if 'pfs' in rest:
                 esp_groups[norm_name]['pfs'] = rest.split('pfs')[-1].strip()
            
            continue

        # Peers
        match_peer = peer_pattern.match(line)
        if match_peer:
            peer_ip, rest = match_peer.groups()
            if peer_ip not in peers:
                peers[peer_ip] = {
                    'local_address': None,
                    'remote_address': peer_ip,
                    'ike_group': None,
                    'esp_group': None,
                    'tunnels': [],
                    'description': None,
                    'raw_lines': []
                }
            
            peers[peer_ip]['raw_lines'].append(line)
            
            if 'authentication pre-shared-secret' in rest:
                # Mask PSK in the raw line if we want to hide it there too, 
                # but raw_lines are used for "Descargar comandos". 
                # The user said "no mostrar la PSK en la UI".
                # But "Descargar comandos" might need the real PSK? 
                # "Si el pre-shared-key aparece en la config, no mostrarlo en texto claro en la UI. Mostrar **** (exists) o similar."
                # Usually "Descargar comandos" implies getting the config to apply it, so it should probably have the key.
                # But for the UI table "Detalles", it should be hidden.
                # The parser returns `details` string. I should check where I put the PSK.
                # Currently I don't put PSK in `details`.
                # But I do put `raw_config`.
                # If the user wants to download commands, they probably want the key.
                # If the user wants to see it in the table, they don't.
                # The table uses `details`.
                # `raw_config` is used for download.
                # So I should leave `raw_lines` as is?
                # "En el campo Detalles de la tabla incluye: nombre original (si difiere), línea original set ... completa, y peer(s) asociados."
                # "línea original set ... completa" -> This implies showing the line in Details.
                # So I MUST mask it in `details`.
                pass
            
            if 'ike-group' in rest:
                gname = rest.split('ike-group')[-1].strip().split()[0]
                peers[peer_ip]['ike_group'] = gname # Will need to map to normalized name later
            
            if 'default-esp-group' in rest:
                gname = rest.split('default-esp-group')[-1].strip().split()[0]
                peers[peer_ip]['esp_group'] = gname

            continue

    # Post-processing to build the final list
    results = []
    
    # Helper to mask PSK in lines
    def mask_lines(lines):
        masked = []
        for l in lines:
            if 'authentication pre-shared-secret' in l:
                # set vpn ipsec site-to-site peer 1.2.3.4 authentication pre-shared-secret 'SECRET'
                # We want to replace 'SECRET' with ****
                # Regex to find the secret
                l = re.sub(r'(authentication pre-shared-secret\s+)(\S+)', r'\1**** (exists)', l)
            masked.append(l)
        return masked

    # Add IKE Groups
    for norm_name, data in ike_groups.items():
        # Extract proposal details from raw lines for better accuracy
        enc = []
        hash_alg = []
        dh = []
        
        for l in data['raw_lines']:
            if 'encryption' in l: enc.append(l.split('encryption')[-1].strip().split()[0])
            if 'hash' in l: hash_alg.append(l.split('hash')[-1].strip().split()[0])
            if 'dh-group' in l: dh.append(l.split('dh-group')[-1].strip().split()[0])
        
        results.append({
            'name': norm_name,
            'original_name': data['original_name'],
            'type': 'IKE',
            'peer': '-', # Will be filled later
            'encryption': ', '.join(sorted(list(set(enc)))),
            'hash': ', '.join(sorted(list(set(hash_alg)))),
            'dh_group': ', '.join(sorted(list(set(dh)))),
            'lifetime': data['lifetime'] or '-',
            'details': f"Original: {data['original_name']}\n" + '\n'.join(mask_lines(data['raw_lines'])),
            'raw_config': '\n'.join(data['raw_lines'])
        })

    # Add ESP Groups
    for norm_name, data in esp_groups.items():
        enc = []
        hash_alg = []
        
        for l in data['raw_lines']:
             if 'encryption' in l: enc.append(l.split('encryption')[-1].strip().split()[0])
             if 'hash' in l: hash_alg.append(l.split('hash')[-1].strip().split()[0])

        results.append({
            'name': norm_name,
            'original_name': data['original_name'],
            'type': 'ESP',
            'peer': '-',
            'encryption': ', '.join(sorted(list(set(enc)))),
            'hash': ', '.join(sorted(list(set(hash_alg)))),
            'dh_group': data['pfs'] or '-', 
            'lifetime': data['lifetime'] or '-',
            'details': f"Original: {data['original_name']}\n" + '\n'.join(mask_lines(data['raw_lines'])),
            'raw_config': '\n'.join(data['raw_lines'])
        })
        
    # Map peers to groups
    for p_ip, p_data in peers.items():
        # Check IKE group
        if p_data['ike_group']:
            orig = p_data['ike_group']
            norm = ike_name_map.get(orig)
            if norm:
                for r in results:
                    if r['name'] == norm:
                        curr = r['peer']
                        if curr == '-': r['peer'] = p_ip
                        else: r['peer'] += f", {p_ip}"
                        # Append peer config to details (masked)
                        r['details'] += f"\n\nPeer {p_ip}:\n" + '\n'.join(mask_lines(p_data['raw_lines']))
                        # Append peer config to raw_config (unmasked)
                        r['raw_config'] += f"\n\n! Peer {p_ip}\n" + '\n'.join(p_data['raw_lines'])
        
        # Check ESP group
        if p_data['esp_group']:
            orig = p_data['esp_group']
            norm = esp_name_map.get(orig)
            if norm:
                for r in results:
                    if r['name'] == norm:
                        curr = r['peer']
                        if curr == '-': r['peer'] = p_ip
                        else: r['peer'] += f", {p_ip}"
                        # Append peer config to details (masked)
                        r['details'] += f"\n\nPeer {p_ip}:\n" + '\n'.join(mask_lines(p_data['raw_lines']))
                        # Append peer config to raw_config (unmasked)
                        r['raw_config'] += f"\n\n! Peer {p_ip}\n" + '\n'.join(p_data['raw_lines'])

    # Sort by name
    results.sort(key=lambda x: x['name'])
    
    return results
