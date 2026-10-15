import unittest
from check_active import audit


def fixture():
    dns = {k: ['223.5.5.5#EZ-USB-DNS'] for k in
           ['nameserver', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver']}
    dns['enable'] = True
    generated = {'interface-name': 'en5', 'dns': dns,
                 'rules': ['DOMAIN-SUFFIX,bilibili.com,EZ-Campus', 'MATCH,Proxy'],
                 'sniffer': {'enable': True, 'parse-pure-ip': True, 'sniff': {'TLS': {'ports': [443]}, 'QUIC': {'ports': [443]}}}}
    runtime = {'mode': 'rule', 'interface-name': 'en5', 'tun': {'enable': False}}
    proxies = {'node': {'type': 'Trojan', 'interface': 'en5'},
               'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
               'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en5'},
               'Proxy': {'type': 'Selector', 'all': ['node']},
               'DIRECT': {'type': 'Direct'}}
    rules = [{'type': 'DomainSuffix', 'proxy': 'EZ-Campus'}, {'type': 'Match', 'proxy': 'Proxy'}]
    return generated, runtime, proxies, rules


class AuditTests(unittest.TestCase):
    def test_bound_system_proxy_configuration_is_valid_without_claiming_tun(self):
        self.assertEqual(audit(*fixture()), [])

    def test_unbound_proxy_is_detected_even_when_other_nodes_are_bound(self):
        g, c, p, r = fixture()
        p['unbound'] = {'type': 'VMess', 'interface': ''}
        self.assertIn('remote-node-not-bound-to-usb', audit(g, c, p, r))

    def test_builtin_direct_fallback_is_detected(self):
        g, c, p, r = fixture()
        p['Proxy']['all'].append('DIRECT')
        r.append({'proxy': 'DIRECT'})
        self.assertIn('unsafe-group-member', audit(g, c, p, r))
        self.assertIn('unsafe-rule-target', audit(g, c, p, r))

    def test_wrong_campus_interface_or_wrong_mode_is_detected(self):
        g, c, p, r = fixture()
        p['EZ-Campus']['interface'] = 'en5'
        c['mode'] = 'global'
        self.assertIn('campus-interface-mismatch', audit(g, c, p, r))
        self.assertIn('mode-is-not-rule', audit(g, c, p, r))

    def test_old_or_overridden_dns_configuration_is_detected(self):
        g, c, p, r = fixture()
        g['dns']['nameserver'] = ['system']
        g['dns']['nameserver-policy'] = {'example': 'system'}
        self.assertIn('dns-not-bound-to-usb', audit(g, c, p, r))

    def test_reserved_names_cannot_hide_a_proxy_on_campus(self):
        g, c, p, r = fixture()
        p['EZ-Campus']['type'] = 'Trojan'
        self.assertIn('reserved-policy-is-not-direct', audit(g, c, p, r))

    def test_extra_direct_policy_cannot_bypass_the_approved_rule_targets(self):
        g, c, p, r = fixture()
        p['extra-direct'] = {'type': 'Direct', 'interface': 'en5'}
        self.assertIn('unexpected-direct-policy', audit(g, c, p, r))

    def test_builtin_pass_rule_is_not_a_remote_node(self):
        g, c, p, r = fixture()
        p['PASS-RULE'] = {'type': 'PassRule', 'interface': ''}
        self.assertEqual(audit(g, c, p, r), [])

    def test_pass_rule_cannot_bypass_a_proxy_group_or_route(self):
        g, c, p, r = fixture()
        p['Proxy']['all'].append('PASS-RULE')
        r.append({'proxy': 'PASS-RULE'})
        self.assertIn('unsafe-group-member', audit(g, c, p, r))
        self.assertIn('unsafe-rule-target', audit(g, c, p, r))

    def test_tun_without_domain_identification_is_not_ready(self):
        g, c, p, r = fixture()
        c['tun']['enable'] = True
        g['sniffer']['enable'] = False
        self.assertIn('domain-identification-not-enabled', audit(g, c, p, r))

    def test_runtime_ip_direct_rule_is_detected_even_if_generated_rules_are_safe(self):
        g, c, p, r = fixture()
        r.insert(0, {'type': 'GeoIP', 'proxy': 'EZ-Campus'})
        self.assertIn('unsafe-campus-rule', audit(g, c, p, r))

    def test_known_lab_exception_is_not_reported_as_an_unsafe_campus_rule(self):
        g, c, p, r = fixture()
        r.insert(0, {'type': 'IPCIDR', 'payload': '192.0.2.10/32', 'proxy': 'EZ-Campus'})
        self.assertNotIn('unsafe-campus-rule', audit(g, c, p, r))

    def test_other_ip_targets_still_cannot_authorize_the_campus_outlet(self):
        for payload in ['10.0.0.0/8', '192.0.2.11/32', '172.16.0.0/16']:
            g, c, p, r = fixture()
            r.insert(0, {'type': 'IPCIDR', 'payload': payload, 'proxy': 'EZ-Campus'})
            self.assertIn('unsafe-campus-rule', audit(g, c, p, r), payload)


if __name__ == '__main__':
    unittest.main()
