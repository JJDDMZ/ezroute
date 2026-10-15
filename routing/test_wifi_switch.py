import copy
import io
import importlib.util
import os
from pathlib import Path
import tempfile
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from tools import disconnect_assertions as assertions


def acceptance_fixture():
    used = {'remote_packets': 8, 'direct_packets': 6, 'dns_packets': 2,
            'parsed_ip_lines': 16, 'unparsed_ip_lines': 0}
    idle = {'remote_packets': 0, 'direct_packets': 0, 'dns_packets': 0,
            'parsed_ip_lines': 0, 'unparsed_ip_lines': 0}
    return {'baseline_verified': True, 'registered_wifi_verified': True,
            'unregistered_confirmed': True, 'automatic_direct_only_verified': True,
            'unregistered_direct_requests_verified': True,
            'registered_return_confirmed': True, 'registered_return_verified': True,
            'usb_recovery_verified': True, 'registration_unchanged': True,
            'selections_preserved': True, 'kernel_dropped': 0,
            'unregistered_dns_status': 3, 'registered_wifi_dns_status': 0,
            'registered_return_dns_status': 3, 'usb_recovery_dns_status': 0,
            'phase_packet_counts': {
                'registered_wifi': {'en0': used, 'en5': idle},
                'unregistered_after_confirmation': {'en0': dict(used, remote_packets=0), 'en5': idle},
                'registered_return': {'en0': used, 'en5': idle},
                'usb_recovery': {'en5': used, 'en0': idle}}}


class WifiSwitchAcceptanceTests(unittest.TestCase):
    def diagnostic_type(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.verify_wifi_switch'), 'missing switch diagnostic')
        from tools.verify_wifi_switch import WifiSwitchDiagnostic
        return WifiSwitchDiagnostic

    def test_post_confirmation_node_packet_invalidates_acceptance(self):
        self.assertTrue(hasattr(assertions, 'wifi_switch_checks_pass'), 'missing switch acceptance')
        result = acceptance_fixture()
        self.assertTrue(assertions.wifi_switch_checks_pass(result, 'en5', 'en0'))
        result['phase_packet_counts']['unregistered_after_confirmation']['en0']['remote_packets'] = 1
        self.assertFalse(assertions.wifi_switch_checks_pass(result, 'en5', 'en0'))

    def test_missing_evidence_or_wrong_outlet_cannot_pass(self):
        self.assertTrue(hasattr(assertions, 'wifi_switch_checks_pass'), 'missing switch acceptance')
        for mutation in ['confirmation', 'registry', 'selectors', 'dns', 'drop', 'unknown-packet', 'usb-leak', 'missing-proxy', 'missing-phase']:
            result = copy.deepcopy(acceptance_fixture())
            if mutation == 'confirmation': result['unregistered_confirmed'] = False
            elif mutation == 'registry': result['registration_unchanged'] = False
            elif mutation == 'selectors': result['selections_preserved'] = False
            elif mutation == 'dns': result['unregistered_dns_status'] = 2
            elif mutation == 'drop': result['kernel_dropped'] = None
            elif mutation == 'unknown-packet': result['phase_packet_counts']['unregistered_after_confirmation']['en0']['unparsed_ip_lines'] = 1
            elif mutation == 'usb-leak': result['phase_packet_counts']['unregistered_after_confirmation']['en5']['direct_packets'] = 1
            elif mutation == 'missing-proxy': result['phase_packet_counts']['registered_return']['en0']['remote_packets'] = 0
            else: del result['phase_packet_counts']['usb_recovery']
            with self.subTest(mutation=mutation):
                self.assertFalse(assertions.wifi_switch_checks_pass(result, 'en5', 'en0'))

    def test_wrong_confirmation_stops_before_direct_probe(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = WifiSwitchDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b'wrong\n')
            os.close(write_fd)
            with os.fdopen(read_fd) as stream, patch('sys.stdin', stream):
                with self.assertRaisesRegex(RuntimeError, 'network-confirmation-not-received'):
                    diagnostic.confirm_switch('1')

    def test_unknown_mode_rejects_usb_reconnect_or_changed_registration(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = WifiSwitchDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.registration = b'original'
            prefs = {'EZSwitch.automaticRouting': True, 'EZSwitch.registeredHotspots': b'original'}
            diagnostic.preferences = lambda: prefs
            diagnostic.online = lambda name: name == 'en0'
            values = ({'mode': 'direct', 'interface-name': 'en0', 'tun': {'enable': True}},
                      {'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
                       'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en0'}},
                      [{'type': 'Match', 'payload': '', 'proxy': 'EZ-Campus'}])
            self.assertTrue(diagnostic.direct_mode(values))
            prefs['EZSwitch.registeredHotspots'] = b'changed'
            self.assertFalse(diagnostic.direct_mode(values))
            prefs['EZSwitch.registeredHotspots'] = b'original'
            diagnostic.online = lambda name: True
            self.assertFalse(diagnostic.direct_mode(values))

    def test_failure_before_physical_steps_does_not_ask_to_replug(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = WifiSwitchDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            output = io.StringIO()
            with redirect_stdout(output):
                diagnostic.record_failure(RuntimeError('usb-priority-baseline-failed'))
            self.assertNotIn('请插回', output.getvalue())
            self.assertTrue((Path(directory) / 'result.json').exists())
            self.assertFalse(diagnostic.result['transition_zero_leak_verified'])

    def test_controller_reset_during_reload_is_recorded_and_requires_stable_recovery(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = WifiSwitchDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            readings = iter([ConnectionResetError(), 'valid', 'invalid', 'valid', 'valid'])
            seen = []
            def runtime():
                value = next(readings)
                seen.append(value)
                if isinstance(value, Exception):
                    raise value
                return value
            diagnostic.runtime = runtime
            with patch('time.sleep'):
                diagnostic.wait_mode(lambda value: value == 'valid')
            self.assertEqual(len(seen), 5)
            self.assertEqual(diagnostic.result['controller_wait_read_errors'][0]['error_type'], 'ConnectionResetError')

    def test_controller_never_recovers_cannot_pass(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = WifiSwitchDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.runtime = lambda: (_ for _ in ()).throw(ConnectionResetError())
            with patch('time.monotonic', side_effect=[0, 0, 30]), patch('time.sleep'):
                with self.assertRaisesRegex(RuntimeError, 'automatic-routing-did-not-reach-expected-mode'):
                    diagnostic.wait_mode(lambda value: True)
            self.assertFalse(diagnostic.result['all_requested_checks_verified'])

    def test_complete_guided_flow_keeps_switch_boundary_unverified_and_saves_capture(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = WifiSwitchDiagnostic(os.getuid(), root, 'en5', 'en0')
            state = {'usb': True, 'registered': True}
            diagnostic.registration = b'original'
            diagnostic.preferences = lambda: {'EZSwitch.automaticRouting': True, 'EZSwitch.registeredHotspots': b'original'}
            diagnostic.online = lambda name: state['usb'] if name == 'en5' else True
            diagnostic.nodes = {'Node': {'type': 'trojan'}}
            diagnostic.original_groups = {'Group': ['Node']}
            diagnostic.original_rules = [{'type': 'Match', 'payload': '', 'proxy': 'Group'}]
            diagnostic.selections = {'Group': 'Node'}
            def runtime():
                interface = 'en5' if state['usb'] else 'en0'
                adapters = {'EZ-Campus': {'type': 'Direct', 'interface': interface},
                            'EZ-USB-DNS': {'type': 'Direct', 'interface': interface}}
                direct = not state['usb'] and not state['registered']
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
                diagnostic.result['capture_started'] = True
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
                state['registered'] = expected == '2'
            diagnostic.confirm_switch = confirm
            with patch('tools.probe_logs.CoreProbeLog.start'), patch('time.sleep'), redirect_stdout(io.StringIO()):
                diagnostic.run()
            saved = json.loads((root / 'result.json').read_text())
            self.assertTrue(saved['all_requested_checks_verified'])
            self.assertFalse(saved['transition_zero_leak_verified'])
            self.assertFalse(saved['physical_identity_independently_verified'])
            self.assertEqual(saved['phase_packet_counts']['unregistered_after_confirmation']['en0']['remote_packets'], 0)
            self.assertEqual(saved['phase_packet_counts']['usb_recovery']['en0']['remote_packets'], 0)
            self.assertEqual(len(json.loads((root / 'phase-byte-ranges.json').read_text())), 6)
            self.assertTrue((root / 'probe-endpoints.json').exists())

    def test_prepare_only_does_not_claim_physical_switch_or_capture(self):
        WifiSwitchDiagnostic = self.diagnostic_type()
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = WifiSwitchDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.preflight = lambda: None
            diagnostic.probe = lambda kind: {'case': kind, 'request_success': True,
                'transport': 'Tun', 'policy_matches': True, 'domain_identified': True,
                'actual_endpoint_identified': True, 'http_status': 204}
            diagnostic.runtime = lambda: ()
            diagnostic.usb_mode = lambda values: True
            diagnostic.wait_usb = lambda *args: self.fail('preflight requested unplug')
            with patch('tools.probe_logs.CoreProbeLog.start'), redirect_stdout(io.StringIO()):
                diagnostic.run(prepare_only=True)
            self.assertEqual(diagnostic.result['capture_scope'], 'none')
            self.assertFalse(diagnostic.result['all_requested_checks_verified'])
            self.assertFalse(diagnostic.result['physical_switch_tested'])


if __name__ == '__main__':
    unittest.main()
