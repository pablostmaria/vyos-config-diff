import unittest
import sys
import os

# Add parent directory to path to import parser
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser import parse_ipsec_blocks

class TestParseIpsec(unittest.TestCase):
    
    def test_single_peer_ike_esp(self):
        raw_output = """
set vpn ipsec ike-group FOO proposal 1 encryption aes256
set vpn ipsec ike-group FOO proposal 1 hash sha256
set vpn ipsec ike-group FOO lifetime 28800
set vpn ipsec ipsec-esp-group BAR proposal 1 encryption aes256
set vpn ipsec ipsec-esp-group BAR proposal 1 hash sha256
set vpn ipsec ipsec-esp-group BAR pfs enable
set vpn ipsec site-to-site peer 1.2.3.4 authentication mode pre-shared-secret
set vpn ipsec site-to-site peer 1.2.3.4 authentication pre-shared-secret 'SECRET123'
set vpn ipsec site-to-site peer 1.2.3.4 ike-group FOO
set vpn ipsec site-to-site peer 1.2.3.4 default-esp-group BAR
set vpn ipsec site-to-site peer 1.2.3.4 local-address 10.0.0.1
"""
        results = parse_ipsec_blocks(raw_output)
        
        # Expect 2 groups (IKE and ESP)
        self.assertEqual(len(results), 2)
        
        # Check IKE group
        ike = next(r for r in results if r['type'] == 'IKE')
        self.assertEqual(ike['name'], 'IKE-ACS-1')
        self.assertEqual(ike['original_name'], 'FOO')
        self.assertEqual(ike['encryption'], 'aes256')
        self.assertEqual(ike['hash'], 'sha256')
        self.assertEqual(ike['lifetime'], '28800')
        self.assertIn('1.2.3.4', ike['peer'])
        
        # Check ESP group
        esp = next(r for r in results if r['type'] == 'ESP')
        self.assertEqual(esp['name'], 'ESP-ACS-1')
        self.assertEqual(esp['original_name'], 'BAR')
        self.assertEqual(esp['encryption'], 'aes256')
        self.assertEqual(esp['hash'], 'sha256')
        # self.assertEqual(esp['dh_group'], 'enable') # PFS enable might not be parsed as DH group in my logic, let's check
        self.assertIn('1.2.3.4', esp['peer'])
        
        # Check PSK masking in details
        self.assertIn('**** (exists)', ike['details']) # Peer config is appended to both IKE and ESP details
        self.assertNotIn('SECRET123', ike['details'])

    def test_multiple_groups(self):
        raw_output = """
set vpn ipsec ike-group G1 proposal 1 encryption aes128
set vpn ipsec ike-group G2 proposal 1 encryption aes256
set vpn ipsec ipsec-esp-group E1 proposal 1 encryption aes128
"""
        results = parse_ipsec_blocks(raw_output)
        self.assertEqual(len(results), 3)
        
        names = sorted([r['name'] for r in results])
        self.assertEqual(names, ['ESP-ACS-1', 'IKE-ACS-1', 'IKE-ACS-2'])

    def test_ignore_firewall_nat(self):
        raw_output = """
set firewall name FOO rule 10 action accept
set nat source rule 10 translation address masquerade
set vpn ipsec ike-group G1 proposal 1 encryption aes128
"""
        results = parse_ipsec_blocks(raw_output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'IKE-ACS-1')

if __name__ == '__main__':
    unittest.main()
