import unittest
from tools.watch_network import summarize_interface, summarize_controller, subnet_overlap


class NetworkWatchTests(unittest.TestCase):
    def test_link_addresses_are_recorded_without_mac_or_ipv6_identifiers(self):
        state = summarize_interface('''en5: flags=8863<UP,BROADCAST,RUNNING>
            ether aa:bb:cc:dd:ee:ff
            inet6 fe80::abc%en5 prefixlen 64
            inet 172.20.10.5 netmask 0xfffffff0 broadcast 172.20.10.15
            status: active''')
        self.assertEqual(state, {'active': True, 'ipv4': ['172.20.10.5'], 'subnets': ['172.20.10.0/28']})

    def test_inactive_or_link_local_interface_is_not_a_ready_hotspot(self):
        state = summarize_interface('inet 169.254.1.2 netmask 0xffff0000\nstatus: inactive')
        self.assertFalse(state['active'])
        self.assertEqual(state['ipv4'], [])
        self.assertEqual(state['subnets'], [])

    def test_two_phone_networks_are_detected_as_overlapping(self):
        self.assertTrue(subnet_overlap(['172.20.10.0/28'], ['172.20.10.0/28']))
        self.assertTrue(subnet_overlap(['172.20.10.0/24'], ['172.20.10.0/28']))
        self.assertFalse(subnet_overlap(['172.20.10.0/28'], ['192.168.43.0/24']))

    def test_controller_summary_detects_unsafe_binding_without_private_labels(self):
        result = summarize_controller({'mode': 'rule', 'interface-name': 'en5', 'tun': {'enable': True}}, {
            'Node with private label': {'type': 'Trojan', 'interface': 'en0'},
            'Private group': {'type': 'Selector', 'all': ['Node with private label', 'DIRECT']},
            'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
            'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en5'},
            'DIRECT': {'type': 'Direct'}, 'GLOBAL': {'type': 'Selector', 'all': ['DIRECT']},
            'PASS-RULE': {'type': 'PassRule'}
        }, {'connections': [{'chains': ['Node with private label', 'Private group'],
                              'metadata': {'host': 'private-visited-site', 'destinationIP': '10.3.4.5'}}]}, 'en5')
        self.assertEqual(result['remote_node_count'], 1)
        self.assertEqual(result['remote_nodes_outside_usb'], 1)
        self.assertEqual(result['groups_with_direct_fallback'], 1)
        self.assertEqual(result['proxy_connection_count'], 1)
        self.assertNotIn('private', str(result).lower())
        self.assertNotIn('10.3.4.5', str(result))

    def test_reject_fallback_is_safe_and_not_misreported_as_direct(self):
        result = summarize_controller({}, {
            'Proxy': {'type': 'Selector', 'all': ['REJECT', 'REJECT-DROP']}
        }, {}, 'en5')
        self.assertEqual(result['groups_with_direct_fallback'], 0)


if __name__ == '__main__':
    unittest.main()
