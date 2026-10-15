import copy
import importlib.util
import json
import io
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from tools import disconnect_assertions as assertions


def fixture():
    used = {'remote_packets': 8, 'direct_packets': 6, 'dns_packets': 2,
            'parsed_ip_lines': 16, 'unparsed_ip_lines': 0}
    idle = {'remote_packets': 0, 'direct_packets': 0, 'dns_packets': 0,
            'parsed_ip_lines': 0, 'unparsed_ip_lines': 0}
    return {'baseline_verified': True, 'registered_wifi_verified': True,
            'removal_confirmed': True, 'registration_removed_verified': True,
            'automatic_direct_only_verified': True, 'revoked_direct_requests_verified': True,
            'restoration_confirmed': True, 'registration_content_restored': True,
            'registered_return_verified': True, 'usb_recovery_verified': True,
            'wifi_addresses_unchanged': True, 'selections_preserved': True, 'kernel_dropped': 0,
            'revoked_dns_status': 3, 'registered_wifi_dns_status': 0,
            'registered_return_dns_status': 3, 'usb_recovery_dns_status': 0,
            'phase_packet_counts': {
                'registered_wifi': {'en0': used, 'en5': idle},
                'revoked_after_confirmation': {'en0': dict(used, remote_packets=0), 'en5': idle},
                'registered_return': {'en0': used, 'en5': idle},
                'usb_recovery': {'en5': used, 'en0': idle}}}


class RegistrationTests(unittest.TestCase):
    def diagnostic_type(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.verify_registration'), 'missing registration diagnostic')
        from tools.verify_registration import RegistrationDiagnostic
        return RegistrationDiagnostic

    def test_revocation_acceptance_requires_zero_node_packets_and_restored_registration(self):
        self.assertTrue(hasattr(assertions, 'registration_checks_pass'), 'missing registration acceptance')
        self.assertTrue(assertions.registration_checks_pass(fixture(), 'en5', 'en0'))
        for mutation in ['leak', 'removed', 'restored', 'dns', 'capture', 'interface', 'unparsed', 'selection']:
            result = copy.deepcopy(fixture())
            if mutation == 'leak': result['phase_packet_counts']['revoked_after_confirmation']['en0']['remote_packets'] = 1
            elif mutation == 'removed': result['registration_removed_verified'] = False
            elif mutation == 'restored': result['registration_content_restored'] = False
            elif mutation == 'dns': result['revoked_dns_status'] = 2
            elif mutation == 'capture': result['kernel_dropped'] = None
            elif mutation == 'interface': result['phase_packet_counts']['usb_recovery']['en0']['direct_packets'] = 1
            elif mutation == 'unparsed': result['phase_packet_counts']['revoked_after_confirmation']['en0']['unparsed_ip_lines'] = 1
            else: result['selections_preserved'] = False
            with self.subTest(mutation=mutation):
                self.assertFalse(assertions.registration_checks_pass(result, 'en5', 'en0'))

    def test_new_uuid_is_allowed_but_different_hotspot_or_added_registration_is_not(self):
        cls = self.diagnostic_type()
        original = [{'id': 'original-id', 'ssid': 'UGhvbmU=', 'security': 2, 'displayName': 'Phone'}]
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.registration = json.dumps(original).encode()
            changed = copy.deepcopy(original)
            changed[0]['id'] = 'new-id'
            diagnostic.preferences = lambda: {'EZSwitch.registeredHotspots': json.dumps(changed).encode()}
            self.assertTrue(diagnostic.registration_restored())
            changed[0]['ssid'] = 'T3RoZXI='
            self.assertFalse(diagnostic.registration_restored())
            changed = copy.deepcopy(original) * 2
            self.assertFalse(diagnostic.registration_restored())
            changed = copy.deepcopy(original)
            changed[0]['security'] = 3
            self.assertFalse(diagnostic.registration_restored())

    def test_only_empty_registry_can_authorize_revoked_mode(self):
        cls = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.registration = b'[{"id":"1","ssid":"UGhvbmU=","security":2,"displayName":"Phone"}]'
            diagnostic.initial_wifi_addresses = ['192.0.2.1']
            prefs = {'EZSwitch.automaticRouting': True, 'EZSwitch.registeredHotspots': b'[]'}
            diagnostic.preferences = lambda: prefs
            diagnostic.online = lambda name: name == 'en0'
            diagnostic.wifi_addresses = lambda: ['192.0.2.1']
            values = ({'mode': 'direct', 'interface-name': 'en0', 'tun': {'enable': True}},
                      {'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
                       'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en0'}},
                      [{'type': 'Match', 'payload': '', 'proxy': 'EZ-Campus'}])
            self.assertTrue(diagnostic.direct_mode(values))
            prefs['EZSwitch.registeredHotspots'] = diagnostic.registration
            self.assertFalse(diagnostic.direct_mode(values))
            prefs['EZSwitch.registeredHotspots'] = b'[]'
            prefs['EZSwitch.automaticRouting'] = False
            self.assertFalse(diagnostic.direct_mode(values))
            prefs['EZSwitch.automaticRouting'] = True
            diagnostic.wifi_addresses = lambda: ['192.0.2.2']
            self.assertFalse(diagnostic.direct_mode(values))

    def test_complete_guided_flow_restores_content_with_new_id_and_preserves_evidence(self):
        cls = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = cls(os.getuid(), root, 'en5', 'en0')
            original = [{'id': 'old', 'ssid': 'UGhvbmU=', 'security': 2, 'displayName': 'Phone'}]
            diagnostic.registration = json.dumps(original).encode()
            state = {'usb': True, 'entries': original}
            diagnostic.preferences = lambda: {'EZSwitch.automaticRouting': True,
                'EZSwitch.registeredHotspots': json.dumps(state['entries']).encode()}
            diagnostic.online = lambda name: state['usb'] if name == 'en5' else True
            diagnostic.initial_wifi_addresses = ['192.0.2.1']
            diagnostic.wifi_addresses = lambda: ['192.0.2.1']
            diagnostic.nodes = {'Node': {'type': 'trojan'}}
            diagnostic.original_groups = {'Group': ['Node']}
            diagnostic.original_rules = [{'type': 'Match', 'payload': '', 'proxy': 'Group'}]
            diagnostic.selections = {'Group': 'Node'}
            def runtime():
                interface = 'en5' if state['usb'] else 'en0'
                direct = not state['usb'] and not state['entries']
                adapters = {'EZ-Campus': {'type': 'Direct', 'interface': interface},
                            'EZ-USB-DNS': {'type': 'Direct', 'interface': interface}}
                if not direct:
                    adapters.update(Node={'type': 'Trojan', 'interface': interface},
                                    Group={'type': 'Selector', 'all': ['Node'], 'now': 'Node'})
                return ({'mode': 'direct' if direct else 'rule', 'interface-name': interface, 'tun': {'enable': True}},
                        adapters, [{'type': 'Match', 'payload': '', 'proxy': 'EZ-Campus'}] if direct else diagnostic.original_rules)
            diagnostic.runtime = runtime
            diagnostic.preflight = lambda: diagnostic.result.update(registered_hotspot_count=1)
            def capture():
                (root / 'physical-packets.txt').write_text('')
                diagnostic.capture_messages = ['0 packets dropped by kernel\n']
            diagnostic.start_capture = capture
            def packet(address, port):
                interface = 'en5' if state['usb'] else 'en0'
                with (root / 'physical-packets.txt').open('a') as handle:
                    handle.write(f'12:00:00 IP 192.0.2.1.40000 > {address}.{port}: tcp 0, if {interface}\n')
            def probe(kind):
                target = ('198.51.100.2', 443) if kind == 'proxy' else ('203.0.113.3', 443)
                (diagnostic.remote_targets if kind == 'proxy' else diagnostic.direct_targets).add(target)
                packet(*target)
                return {'case': kind, 'request_success': True, 'transport': 'Tun',
                        'policy_matches': True, 'domain_identified': True,
                        'actual_endpoint_identified': True, 'http_status': 204 if kind == 'proxy' else 302}
            diagnostic.probe = probe
            def api(path):
                self.assertTrue(path.startswith('/dns/query?'))
                packet('192.0.2.53', 53)
                return {'Status': 3}
            diagnostic.api = api
            diagnostic.wait_usb = lambda wanted, seconds: state.update(usb=wanted)
            def confirm(expected):
                state['entries'] = [] if expected == '1' else [dict(original[0], id='new')]
            diagnostic.confirm_switch = confirm
            with patch('tools.probe_logs.CoreProbeLog.start'), patch('time.sleep'), redirect_stdout(io.StringIO()):
                diagnostic.run()
            saved = json.loads((root / 'result.json').read_text())
            self.assertTrue(saved['all_requested_checks_verified'])
            self.assertTrue(saved['registration_content_restored'])
            self.assertFalse(saved['registration_bytes_unchanged'])
            self.assertFalse(saved['revocation_zero_leak_verified'])
            self.assertEqual(saved['phase_packet_counts']['revoked_after_confirmation']['en0']['remote_packets'], 0)
            self.assertEqual(saved['phase_packet_counts']['usb_recovery']['en0']['remote_packets'], 0)
            self.assertEqual(len(json.loads((root / 'phase-byte-ranges.json').read_text())), 6)
            self.assertTrue((root / 'probe-endpoints.json').exists())


if __name__ == '__main__':
    unittest.main()
