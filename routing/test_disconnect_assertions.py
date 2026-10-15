import unittest
from tools.disconnect_assertions import direct_only_matches, packet_summary


def fixture():
    return ({'mode': 'direct', 'interface-name': 'en0', 'tun': {'enable': True}},
            {'DIRECT': {'type': 'Direct'},
             'GLOBAL': {'type': 'Selector', 'all': ['DIRECT', 'EZ-Campus', 'EZ-USB-DNS']},
             'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
             'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en0'}},
            [{'type': 'Match', 'payload': '', 'proxy': 'EZ-Campus'}])


class DisconnectAssertionsTests(unittest.TestCase):
    def test_direct_mode_does_not_hide_retained_remote_nodes_or_groups(self):
        g, p, r = fixture()
        self.assertTrue(direct_only_matches(g, p, r, 'en0'))
        p['old-node'] = {'type': 'Trojan', 'interface': 'en5'}
        self.assertFalse(direct_only_matches(g, p, r, 'en0'))
        del p['old-node']
        p['old-group'] = {'type': 'Selector', 'all': ['REJECT']}
        self.assertFalse(direct_only_matches(g, p, r, 'en0'))

    def test_wrong_interface_tun_or_rules_cannot_pass_direct_only(self):
        for kind in ['interface', 'dns', 'tun', 'rules']:
            g, p, r = fixture()
            if kind == 'interface': g['interface-name'] = 'en5'
            if kind == 'dns': p['EZ-USB-DNS']['interface'] = 'en5'
            if kind == 'tun': g['tun']['enable'] = False
            if kind == 'rules': r.append({'type': 'Domain', 'proxy': 'old-node'})
            with self.subTest(kind=kind):
                self.assertFalse(direct_only_matches(g, p, r, 'en0'))

    def test_reusing_builtin_name_cannot_hide_remote_node(self):
        g, p, r = fixture()
        p['DIRECT']['type'] = 'Trojan'
        self.assertFalse(direct_only_matches(g, p, r, 'en0'))

    def test_wifi_packet_parser_detects_proxy_endpoint_and_keeps_ports_distinct(self):
        lines = [
            '12:00:00.100 IP 192.0.2.1.40000 > 203.0.113.8.443: tcp 0, if en0, proc verge-mihomo:10',
            '12:00:00.200 IP 203.0.113.8.8443 > 192.0.2.1.40001: tcp 40, if en0, proc verge-mihomo:10',
            '12:00:00.300 IP 192.0.2.1.40002 > 198.51.100.4.443: tcp 80, if en0, proc verge-mihomo:10',
            '12:00:00.400 IP 223.5.5.5.53 > 192.0.2.1.40003: UDP, length 90, if en0, proc verge-mihomo:10',
            '12:00:00.500 IP 192.0.2.2.40004 > 203.0.113.8.443: tcp 10, if en5, proc verge-mihomo:10',
        ]
        got = packet_summary(lines, {('203.0.113.8', 443)}, {('198.51.100.4', 443)}, 'en0')
        self.assertEqual(got, {'remote_on_wifi': 1, 'direct_on_wifi': 1, 'dns_on_wifi': 1,
                               'parsed_ip_lines': 4, 'unparsed_ip_lines': 0})

    def test_ipv6_and_malformed_ip_lines_cannot_be_silently_discarded(self):
        lines = [
            '12:00:00 IP6 2001:db8::1.40000 > 2001:db8::8.443: tcp 10, if en0, proc verge-mihomo:10',
            '12:00:01 IP6 malformed-packet, if en0, proc verge-mihomo:10',
        ]
        got = packet_summary(lines, {('2001:db8::8', 443)}, set(), 'en0')
        self.assertEqual(got['remote_on_wifi'], 1)
        self.assertEqual(got['parsed_ip_lines'], 1)
        self.assertEqual(got['unparsed_ip_lines'], 1)


if __name__ == '__main__':
    unittest.main()
