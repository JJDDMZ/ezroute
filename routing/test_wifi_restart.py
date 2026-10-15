import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


def acceptance_fixture():
    used = {'remote_packets': 8, 'direct_packets': 6, 'dns_packets': 2,
            'parsed_ip_lines': 16, 'unparsed_ip_lines': 0}
    idle = {'remote_packets': 0, 'direct_packets': 0, 'dns_packets': 0,
            'parsed_ip_lines': 0, 'unparsed_ip_lines': 0}
    return {'baseline_verified': True, 'registered_wifi_verified': True,
            'quit_confirmed': True, 'automatic_exit_direct_only_verified': True,
            'exit_direct_requests_verified': True, 'restart_confirmed': True,
            'application_restarted_verified': True, 'wifi_restart_verified': True,
            'usb_recovery_verified': True, 'registration_unchanged': True,
            'wifi_network_unchanged': True, 'selections_preserved': True,
            'kernel_dropped': 0, 'registered_wifi_dns_status': 0,
            'exit_direct_dns_status': 3, 'wifi_restart_dns_status': 0,
            'usb_recovery_dns_status': 3,
            'phase_packet_counts': {'registered_wifi': {'en0': used, 'en5': idle},
                'exit_direct': {'en0': dict(used, remote_packets=0), 'en5': idle},
                'wifi_restart': {'en0': used, 'en5': idle},
                'usb_recovery': {'en5': used, 'en0': idle}}}


class WifiRestartTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.verify_wifi_restart'), 'missing restart diagnostic')
        from tools import verify_wifi_restart
        return verify_wifi_restart

    def test_renamed_app_and_legacy_app_are_both_counted(self):
        cls = self.module().WifiRestartDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(), Path(directory), 'en5', 'en0')
            for name in ['EZ Route.app', 'EZSwitch.app']:
                diagnostic.command = lambda arguments, name=name: ('/Users/test/Applications/' + name + '/Contents/MacOS/EZSwitch\n').encode()
                self.assertEqual(diagnostic.app_count(), 1)
            diagnostic.command = lambda arguments: b'/Users/test/Applications/EZ Route.app/Contents/MacOS/EZSwitch\n/Users/test/Applications/EZSwitch.app/Contents/MacOS/EZSwitch\n'
            self.assertEqual(diagnostic.app_count(), 2)

    def test_unsafe_exit_or_failed_restart_cannot_pass(self):
        check = self.module().restart_checks_pass
        self.assertTrue(check(acceptance_fixture(), 'en5', 'en0'))
        for mutation in ['exit-leak', 'not-quit', 'not-restarted', 'registration', 'dns', 'drop', 'other-interface']:
            result = copy.deepcopy(acceptance_fixture())
            if mutation == 'exit-leak': result['phase_packet_counts']['exit_direct']['en0']['remote_packets'] = 1
            elif mutation == 'not-quit': result['automatic_exit_direct_only_verified'] = False
            elif mutation == 'not-restarted': result['application_restarted_verified'] = False
            elif mutation == 'registration': result['registration_unchanged'] = False
            elif mutation == 'dns': result['wifi_restart_dns_status'] = 2
            elif mutation == 'drop': result['kernel_dropped'] = None
            else: result['phase_packet_counts']['wifi_restart']['en5']['remote_packets'] = 1
            with self.subTest(mutation=mutation):
                self.assertFalse(check(result, 'en5', 'en0'))

    def test_exit_requires_process_absence_and_restart_requires_one_instance(self):
        cls = self.module().WifiRestartDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.context_unchanged = lambda: True
            diagnostic.online = lambda name: name == 'en0'
            values = ({'mode': 'direct', 'interface-name': 'en0', 'tun': {'enable': True}},
                      {'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
                       'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en0'}},
                      [{'type': 'Match', 'payload': '', 'proxy': 'EZ-Campus'}])
            diagnostic.command = lambda arguments: b'/Users/test/Applications/EZSwitch.app/Contents/MacOS/EZSwitch\n'
            self.assertFalse(diagnostic.exit_mode(values))
            diagnostic.command = lambda arguments: b'/Applications/Other.app/Contents/MacOS/Other\n'
            self.assertTrue(diagnostic.exit_mode(values))
            diagnostic.wifi_mode = lambda values: True
            self.assertFalse(diagnostic.restart_mode(values))
            diagnostic.command = lambda arguments: b'EZSwitch\n'
            self.assertTrue(diagnostic.restart_mode(values))
            diagnostic.command = lambda arguments: b'EZSwitch\nEZSwitch\n'
            self.assertFalse(diagnostic.restart_mode(values))

    def test_failure_after_quit_prompts_for_app_recovery_and_keeps_evidence(self):
        cls = self.module().WifiRestartDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.result['usb_offline_observed'] = True
            diagnostic.stage = 'check-app-exit'
            output = io.StringIO()
            with redirect_stdout(output):
                diagnostic.record_failure(RuntimeError('app-not-exited'))
            self.assertIn('重新打开', output.getvalue())
            self.assertIn('插回', output.getvalue())
            saved = json.loads((Path(directory)/'result.json').read_text())
            self.assertFalse(saved['all_requested_checks_verified'])
            self.assertEqual(saved['failed_stage'], 'check-app-exit')

    def test_complete_guided_restart_flow_saves_all_phases_without_changing_registration(self):
        cls = self.module().WifiRestartDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = cls(os.getuid(), root, 'en5', 'en0')
            state = {'usb': True, 'app': True}
            diagnostic.registration = b'original'
            diagnostic.preferences = lambda: {'EZSwitch.automaticRouting': True, 'EZSwitch.registeredHotspots': b'original'}
            diagnostic.online = lambda name: state['usb'] if name == 'en5' else True
            diagnostic.initial_wifi_addresses = ['192.0.2.1']
            diagnostic.wifi_addresses = lambda: ['192.0.2.1']
            diagnostic.command = lambda arguments: b'EZSwitch\n' if state['app'] else b''
            diagnostic.nodes = {'Node': {'type': 'trojan'}}
            diagnostic.original_groups = {'Group': ['Node']}
            diagnostic.original_rules = [{'type': 'Match', 'payload': '', 'proxy': 'Group'}]
            diagnostic.selections = {'Group': 'Node'}
            def runtime():
                interface = 'en5' if state['usb'] else 'en0'
                adapters = {'EZ-Campus': {'type': 'Direct', 'interface': interface},
                            'EZ-USB-DNS': {'type': 'Direct', 'interface': interface}}
                if state['app']:
                    adapters.update(Node={'type': 'Trojan', 'interface': interface},
                                    Group={'type': 'Selector', 'all': ['Node'], 'now': 'Node'})
                return ({'mode': 'rule' if state['app'] else 'direct', 'interface-name': interface, 'tun': {'enable': True}},
                        adapters, diagnostic.original_rules if state['app'] else [{'type': 'Match', 'payload': '', 'proxy': 'EZ-Campus'}])
            diagnostic.runtime = runtime
            diagnostic.preflight = lambda: diagnostic.result.update(registered_hotspot_count=1)
            def capture():
                (root/'physical-packets.txt').write_text('')
                diagnostic.capture_messages = ['0 packets dropped by kernel\n']
            diagnostic.start_capture = capture
            def packet(address,port):
                interface = 'en5' if state['usb'] else 'en0'
                with (root/'physical-packets.txt').open('a') as handle:
                    handle.write(f'12:00:00 IP 192.0.2.1.40000 > {address}.{port}: tcp 0, if {interface}\n')
            def probe(kind):
                self.assertFalse(kind == 'proxy' and not state['app'], 'unexpected proxy probe after quit')
                target = ('198.51.100.2',443) if kind == 'proxy' else ('203.0.113.3',443)
                (diagnostic.remote_targets if kind == 'proxy' else diagnostic.direct_targets).add(target)
                packet(*target)
                return {'case':kind,'request_success':True,'transport':'Tun','policy_matches':True,
                        'domain_identified':True,'actual_endpoint_identified':True,'http_status':204 if kind=='proxy' else 302}
            diagnostic.probe = probe
            def api(path):
                self.assertTrue(path.startswith('/dns/query?'))
                packet('192.0.2.53',53)
                return {'Status':3}
            diagnostic.api = api
            diagnostic.wait_usb = lambda wanted,seconds: state.update(usb=wanted)
            diagnostic.confirm_switch = lambda expected: state.update(app=expected=='2')
            with patch('tools.probe_logs.CoreProbeLog.start'), patch('time.sleep'), redirect_stdout(io.StringIO()):
                diagnostic.run()
            saved = json.loads((root/'result.json').read_text())
            self.assertTrue(saved['all_requested_checks_verified'])
            self.assertTrue(saved['registration_unchanged'])
            self.assertFalse(saved['instant_exit_protection_verified'])
            self.assertEqual(saved['phase_packet_counts']['exit_direct']['en0']['remote_packets'],0)
            self.assertEqual(saved['phase_packet_counts']['wifi_restart']['en5']['remote_packets'],0)
            self.assertEqual(len(json.loads((root/'phase-byte-ranges.json').read_text())),6)
