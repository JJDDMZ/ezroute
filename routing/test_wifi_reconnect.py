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


class WifiReconnectTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.verify_wifi_reconnect'))
        from tools import verify_wifi_reconnect
        return verify_wifi_reconnect

    def test_blocked_configuration_rejects_retained_nodes_or_bypass_modes(self):
        check = self.module().blocked_matches
        values = ({'mode':'rule','interface-name':'en5','tun':{'enable':True}},
                  {'DIRECT':{'type':'Direct'},'REJECT':{'type':'Reject'},
                   'GLOBAL':{'type':'Selector','all':['DIRECT','REJECT']}},
                  [{'type':'Match','payload':'','proxy':'REJECT'}])
        self.assertTrue(check(values, 'en5'))
        for mutation in ('node','member','mode','tun','rule','iface'):
            changed = copy.deepcopy(values)
            if mutation == 'node': changed[1]['Node'] = {'type':'Trojan'}
            elif mutation == 'member': changed[1]['GLOBAL']['all'].append('Node')
            elif mutation == 'mode': changed[0]['mode'] = 'direct'
            elif mutation == 'tun': changed[0]['tun']['enable'] = False
            elif mutation == 'rule': changed[2][0]['proxy'] = 'DIRECT'
            else: changed[0]['interface-name'] = 'en0'
            with self.subTest(mutation=mutation): self.assertFalse(check(changed, 'en5'))

    def test_wifi_off_requires_power_off_single_app_and_unchanged_registration(self):
        cls = self.module().WifiReconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(),Path(directory),'en5','en0')
            diagnostic.registration = b'original'
            state = {'online':False,'power':False,'app':1,'registration':b'original'}
            diagnostic.preferences = lambda: {'EZSwitch.automaticRouting':True,'EZSwitch.registeredHotspots':state['registration']}
            diagnostic.online = lambda name: state['online']
            diagnostic.wifi_power_off = lambda: not state['power']
            diagnostic.app_count = lambda: state['app']
            values = ({'mode':'rule','interface-name':'en5','tun':{'enable':True}}, {}, [{'type':'Match','proxy':'REJECT'}])
            self.assertTrue(diagnostic.offline_mode(values))
            for key,value in [('online',True),('power',True),('app',0),('registration',b'changed')]:
                old=state[key]; state[key]=value
                self.assertFalse(diagnostic.offline_mode(values)); state[key]=old

    def test_failure_after_wifi_off_saves_stage_and_recovery_instructions(self):
        cls = self.module().WifiReconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            diagnostic = cls(os.getuid(),Path(directory),'en5','en0')
            diagnostic.result['usb_offline_observed'] = True
            diagnostic.stage = 'check-offline-blocked-config'
            output = io.StringIO()
            with redirect_stdout(output): diagnostic.record_failure(RuntimeError('unsafe-core-config'))
            saved = json.loads((Path(directory)/'result.json').read_text())
            self.assertFalse(saved['all_requested_checks_verified'])
            self.assertEqual(saved['failed_stage'],'check-offline-blocked-config')
            self.assertIn('打开 Mac Wi-Fi',output.getvalue())
            self.assertIn('插回',output.getvalue())

    def test_complete_reconnect_accepts_new_dhcp_address_and_keeps_phase_evidence(self):
        cls = self.module().WifiReconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); diagnostic=cls(os.getuid(),root,'en5','en0')
            state={'usb':True,'wifi':True,'address':'192.0.2.1'}
            diagnostic.registration=b'original'
            diagnostic.preferences=lambda: {'EZSwitch.automaticRouting':True,'EZSwitch.registeredHotspots':b'original'}
            diagnostic.online=lambda name: state['usb'] if name=='en5' else state['wifi']
            diagnostic.wifi_power_off=lambda: not state['wifi']
            diagnostic.app_count=lambda:1
            diagnostic.initial_wifi_addresses=['192.0.2.1']
            diagnostic.wifi_addresses=lambda:[state['address']]
            diagnostic.nodes={'Node':{'type':'trojan'}}
            diagnostic.original_groups={'Group':['Node']}
            diagnostic.original_rules=[{'type':'Match','payload':'','proxy':'Group'}]
            diagnostic.selections={'Group':'Node'}
            def runtime():
                if not state['wifi'] and not state['usb']:
                    return ({'mode':'rule','interface-name':'en5','tun':{'enable':True}}, {}, [{'type':'Match','proxy':'REJECT'}])
                interface='en5' if state['usb'] else 'en0'
                adapters={'EZ-Campus':{'type':'Direct','interface':interface},'EZ-USB-DNS':{'type':'Direct','interface':interface},
                          'Node':{'type':'Trojan','interface':interface},'Group':{'type':'Selector','all':['Node'],'now':'Node'}}
                return ({'mode':'rule','interface-name':interface,'tun':{'enable':True}},adapters,diagnostic.original_rules)
            diagnostic.runtime=runtime
            diagnostic.preflight=lambda:diagnostic.result.update(registered_hotspot_count=1)
            def capture():
                (root/'physical-packets.txt').write_text(''); diagnostic.capture_messages=['0 packets dropped by kernel\n']
            diagnostic.start_capture=capture
            def packet(address,port):
                self.assertTrue(state['wifi'] or state['usb'], 'unexpected offline external probe')
                interface='en5' if state['usb'] else 'en0'
                with (root/'physical-packets.txt').open('a') as handle:
                    handle.write(f'12:00:00 IP 192.0.2.1.40000 > {address}.{port}: tcp 0, if {interface}\n')
            def probe(kind):
                target=('198.51.100.2',443) if kind=='proxy' else ('203.0.113.3',443)
                (diagnostic.remote_targets if kind=='proxy' else diagnostic.direct_targets).add(target); packet(*target)
                return {'case':kind,'request_success':True,'transport':'Tun','policy_matches':True,'domain_identified':True,
                        'actual_endpoint_identified':True,'http_status':204 if kind=='proxy' else 302}
            diagnostic.probe=probe
            diagnostic.api=lambda path:(packet('192.0.2.53',53) or {'Status':3})
            diagnostic.wait_usb=lambda wanted,seconds:state.update(usb=wanted)
            def confirm(expected):
                state['wifi']=expected=='2'
                if expected=='2': state['address']='192.0.2.99'
            diagnostic.confirm_switch=confirm
            with patch('tools.probe_logs.CoreProbeLog.start'),patch('time.sleep'),redirect_stdout(io.StringIO()): diagnostic.run()
            saved=json.loads((root/'result.json').read_text())
            self.assertTrue(saved['all_requested_checks_verified'])
            self.assertTrue(saved['wifi_ipv4_changed'])
            self.assertFalse(saved['transition_zero_leak_verified'])
            self.assertEqual(saved['phase_packet_counts']['offline_settled']['en0']['remote_packets'],0)
            self.assertEqual(len(json.loads((root/'phase-byte-ranges.json').read_text())),6)
            for mutation in ('blocked','offline-packet','drop','registration','dns','wrong-interface'):
                changed=copy.deepcopy(saved)
                if mutation=='blocked': changed['blocked_config_verified']=False
                elif mutation=='offline-packet': changed['phase_packet_counts']['offline_settled']['en0']['dns_packets']=1
                elif mutation=='drop': changed['kernel_dropped']=None
                elif mutation=='registration': changed['registration_unchanged']=False
                elif mutation=='dns': changed['wifi_reconnected_dns_status']=2
                else: changed['phase_packet_counts']['wifi_reconnected']['en5']['remote_packets']=1
                with self.subTest(mutation=mutation): self.assertFalse(self.module().reconnect_checks_pass(changed,'en5','en0'))
