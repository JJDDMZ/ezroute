import copy
import os
from pathlib import Path
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from unittest.mock import patch
from tools.disconnect_assertions import hotspot_matches, registered_wifi_checks_pass
from tools.verify_registered_wifi import RegisteredWifiDiagnostic


def fixture():
    values = ({'mode': 'rule', 'interface-name': 'en0', 'tun': {'enable': True}},
              {'Node': {'type': 'Trojan', 'interface': 'en0'},
               'Group': {'type': 'Selector', 'all': ['Node']},
               'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
               'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en0'}},
              [{'type': 'Match', 'payload': '', 'proxy': 'Group',
                'extra': {'disabled': False, 'hitCount': 3}}])
    return values, {'Node': {'type': 'trojan'}}, {'Group': ['Node']}, copy.deepcopy(values[2])


class RegisteredWifiTests(unittest.TestCase):
    def test_baseline_only_capture_never_prompts_for_physical_disconnect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = RegisteredWifiDiagnostic(os.getuid(), root, 'en5', 'en0')
            diagnostic.preflight = lambda: diagnostic.result.update(registered_hotspot_count=1)
            def capture():
                (root / 'physical-packets.txt').write_text('')
                diagnostic.capture_messages = ['0 packets dropped by kernel\n']
            diagnostic.start_capture = capture
            diagnostic.probe = lambda kind: {'case': kind, 'request_success': True,
                'transport': 'Tun', 'policy_matches': True, 'domain_identified': True,
                'actual_endpoint_identified': True, 'http_status': 204}
            diagnostic.runtime = lambda: ()
            diagnostic.usb_mode = lambda values: True
            def physical_step(*args):
                self.fail('baseline-only diagnostic attempted a physical USB step')
            diagnostic.wait_usb = physical_step
            output = io.StringIO()
            with patch('tools.probe_logs.CoreProbeLog.start'), redirect_stdout(output):
                diagnostic.run(False, baseline_only=True)
            self.assertNotIn('步骤 1/2', output.getvalue())
            self.assertTrue(diagnostic.result['baseline_verified'])
            self.assertFalse(diagnostic.result['all_requested_checks_verified'])
            self.assertTrue((root / 'core-probe-log.json').exists())
            self.assertTrue((root / 'result.json').exists())

    def test_baseline_failure_preserves_evidence_without_asking_to_reconnect(self):
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = RegisteredWifiDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.stage = 'check-usb-baseline'
            diagnostic.result['baseline_requests'] = [{'case': 'proxy', 'request_success': False,
                'failed_operation': 'tls-handshake', 'error_code': 'SSLEOFError'}]
            output = io.StringIO()
            with redirect_stdout(output):
                diagnostic.record_failure(RuntimeError('usb-priority-baseline-failed'))
            self.assertIn('保持 USB 连接', output.getvalue())
            self.assertNotIn('请插回', output.getvalue())
            saved = __import__('json').loads((Path(directory) / 'result.json').read_text())
            self.assertEqual(saved['failed_stage'], 'check-usb-baseline')
            self.assertFalse(saved['all_requested_checks_verified'])
            self.assertEqual(saved['baseline_requests'][0]['error_code'], 'SSLEOFError')

    def test_failure_after_observed_disconnect_asks_for_usb_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = RegisteredWifiDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.stage = 'check-registered-wifi-only'
            diagnostic.result['usb_offline_observed'] = True
            output = io.StringIO()
            with redirect_stdout(output):
                diagnostic.record_failure(RuntimeError('automatic-routing-did-not-reach-expected-mode'))
            self.assertIn('请插回', output.getvalue())
            self.assertFalse(diagnostic.result['all_requested_checks_verified'])

    def test_failure_cleanup_can_finalize_already_saved_capture_without_losing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = RegisteredWifiDiagnostic(os.getuid(), root, 'en5', 'en0')
            (root / 'physical-packets.txt').write_text(
                '12:00:00 IP 192.0.2.1.40000 > 198.51.100.4.443: tcp 0, if en0\n')
            diagnostic.direct_targets.add(('198.51.100.4', 443))
            diagnostic.capture_messages = ['1 packets captured\n0 packets dropped by kernel\n']
            diagnostic.finish_capture()
            original = (root / 'probe-endpoints.json').read_bytes()
            diagnostic.finish_capture()
            self.assertEqual((root / 'probe-endpoints.json').read_bytes(), original)
            self.assertEqual(diagnostic.result['all_capture_packet_counts']['en0']['direct_packets'], 1)
            self.assertFalse(diagnostic.result['all_requested_checks_verified'])

    def test_one_outlet_rejects_any_remote_direct_or_dns_using_another_interface(self):
        for field in ['Node', 'EZ-Campus', 'EZ-USB-DNS', 'core', 'tun', 'type', 'extra']:
            values, nodes, groups, rules = fixture()
            self.assertTrue(hotspot_matches(values, 'en0', nodes, groups, rules))
            if field == 'core': values[0]['interface-name'] = 'en5'
            elif field == 'tun': values[0]['tun']['enable'] = False
            elif field == 'type': values[1]['Node']['type'] = 'Direct'
            elif field == 'extra': values[1]['Unexpected'] = {'type': 'Trojan', 'interface': 'en0'}
            else: values[1][field]['interface'] = 'en5'
            with self.subTest(field=field):
                self.assertFalse(hotspot_matches(values, 'en0', nodes, groups, rules))

    def test_counters_can_change_but_route_group_or_disabled_state_cannot(self):
        values, nodes, groups, rules = fixture()
        values[2][0]['extra']['hitCount'] = 100
        self.assertTrue(hotspot_matches(values, 'en0', nodes, groups, rules))
        values[2][0]['extra']['disabled'] = True
        self.assertFalse(hotspot_matches(values, 'en0', nodes, groups, rules))
        values[2][0]['extra']['disabled'] = False
        values[1]['Group']['all'].append('DIRECT')
        self.assertFalse(hotspot_matches(values, 'en0', nodes, groups, rules))
        values[1]['Group']['all'] = ['Node']
        values[2][0]['proxy'] = 'EZ-Campus'
        self.assertFalse(hotspot_matches(values, 'en0', nodes, groups, rules))

    def test_missing_packets_failed_dns_or_changed_selections_cannot_pass(self):
        counts = {'remote_packets': 10, 'direct_packets': 8, 'dns_packets': 4,
                  'parsed_ip_lines': 22, 'unparsed_ip_lines': 0}
        absent = dict(counts, remote_packets=0, direct_packets=0, dns_packets=0, parsed_ip_lines=0)
        result = {'baseline_verified': True, 'automatic_wifi_hotspot_verified': True,
                  'wifi_requests_verified': True, 'wifi_dns_status': 3,
                  'recovery_dns_status': 0,
                  'automatic_usb_priority_recovered': True, 'recovery_requests_verified': True,
                  'selections_preserved': True, 'registration_unchanged': True, 'wifi_network_unchanged': True,
                  'kernel_dropped': 0,
                  'phase_packet_counts': {'wifi_only': {'en0': counts, 'en5': absent},
                                          'usb_recovery': {'en5': counts, 'en0': absent}}}
        self.assertTrue(registered_wifi_checks_pass(result, 'en5', 'en0'))
        for mutation in ['dns', 'no-proxy-packet', 'usb-leak', 'wifi-leak', 'unknown-drops', 'selection']:
            changed = copy.deepcopy(result)
            if mutation == 'dns': changed['wifi_dns_status'] = 2
            elif mutation == 'no-proxy-packet': changed['phase_packet_counts']['wifi_only']['en0']['remote_packets'] = 0
            elif mutation == 'usb-leak': changed['phase_packet_counts']['wifi_only']['en5']['direct_packets'] = 1
            elif mutation == 'wifi-leak': changed['phase_packet_counts']['usb_recovery']['en0']['remote_packets'] = 1
            elif mutation == 'unknown-drops': changed['kernel_dropped'] = None
            else: changed['selections_preserved'] = False
            with self.subTest(mutation=mutation):
                self.assertFalse(registered_wifi_checks_pass(changed, 'en5', 'en0'))


if __name__ == '__main__':
    unittest.main()
