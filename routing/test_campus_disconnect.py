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


class CampusDisconnectTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.verify_campus_disconnect'))
        from tools import verify_campus_disconnect
        return verify_campus_disconnect

    def test_complete_unplug_flow_never_probes_proxy_while_usb_is_offline(self):
        cls=self.module().CampusDisconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);d=cls(os.getuid(),root,'en5','en0');state={'usb':True}
            d.registration=b'phone-registration'
            d.preferences=lambda:{'EZSwitch.automaticRouting':True,'EZSwitch.registeredHotspots':d.registration}
            d.online=lambda name:state['usb'] if name=='en5' else True
            d.app_count=lambda:1;d.source_unchanged=lambda:True
            d.nodes={'Node':{'type':'trojan'}};d.original_groups={'Group':['Node']}
            d.original_rules=[{'type':'DomainSuffix','payload':'bilibili.com','proxy':'EZ-Campus'},
                              {'type':'Match','payload':'','proxy':'Group'}]
            d.selections={'Group':'Node'}
            def runtime():
                interface='en5' if state['usb'] else 'en0'
                proxies={'EZ-Campus':{'type':'Direct','interface':'en0'},'EZ-USB-DNS':{'type':'Direct','interface':interface}}
                if state['usb']:
                    proxies.update(Node={'type':'Trojan','interface':'en5'},Group={'type':'Selector','all':['Node'],'now':'Node'})
                return ({'mode':'rule' if state['usb'] else 'direct','interface-name':interface,'tun':{'enable':True}},
                        proxies,d.original_rules if state['usb'] else [{'type':'Match','payload':'','proxy':'EZ-Campus'}])
            d.runtime=runtime;d.preflight=lambda:None
            def capture():
                (root/'physical-packets.txt').write_text('');d.capture_messages=['0 packets dropped by kernel\n']
            d.start_capture=capture
            def packet(address,port,interface):
                with (root/'physical-packets.txt').open('a') as handle:
                    handle.write(f'12:00:00 IP 192.0.2.1.40000 > {address}.{port}: tcp 0, if {interface}\n')
            def probe(kind):
                self.assertFalse(kind=='proxy' and not state['usb'],'foreign proxy probe during campus direct-only')
                target=('198.51.100.2',443) if kind=='proxy' else ('203.0.113.3',443)
                (d.remote_targets if kind=='proxy' else d.direct_targets).add(target)
                packet(*target,'en5' if kind=='proxy' else 'en0')
                return {'case':kind,'request_success':True,'transport':'Tun','policy_matches':True,
                        'domain_identified':True,'actual_endpoint_identified':True,'http_status':204 if kind=='proxy' else 302}
            d.probe=probe
            d.api=lambda path:(packet('192.0.2.53',53,'en5' if state['usb'] else 'en0') or {'Status':3})
            d.system_dns_probe=lambda:(packet('192.0.2.53',53,'en5' if state['usb'] else 'en0') or True)
            d.wait_usb=lambda wanted,seconds:state.update(usb=wanted)
            with patch('tools.probe_logs.CoreProbeLog.start'),patch('time.sleep'),redirect_stdout(io.StringIO()): d.run()
            saved=json.loads((root/'result.json').read_text())
            self.assertTrue(saved['all_requested_checks_verified'])
            self.assertEqual(saved['phase_packet_counts']['campus_direct_only']['en0']['remote_packets'],0)
            self.assertFalse(saved['transition_zero_leak_verified'])
            self.assertEqual(saved['phase_packet_counts']['campus_recovery']['en5']['dns_packets'],2)
            self.assertEqual(len(json.loads((root/'phase-byte-ranges.json').read_text())),5)
            for mutation in ('removed','leak','baseline-dns','recovery-dns','unknown','drop','selector','system-dns'):
                changed=copy.deepcopy(saved)
                if mutation=='removed': changed['automatic_direct_only_verified']=False
                elif mutation=='leak': changed['all_capture_packet_counts']['en0']['remote_packets']=1
                elif mutation=='baseline-dns': changed['phase_packet_counts']['campus_baseline']['en0']['dns_packets']=1
                elif mutation=='recovery-dns': changed['phase_packet_counts']['campus_recovery']['en0']['dns_packets']=1
                elif mutation=='unknown': changed['phase_packet_counts']['campus_direct_only']['en0']['unparsed_ip_lines']=1
                elif mutation=='drop': changed['kernel_dropped']=None
                elif mutation=='selector': changed['selections_preserved']=False
                else: changed['direct_only_system_dns_fake_ipv4']=False
                with self.subTest(mutation=mutation): self.assertFalse(self.module().disconnect_checks_pass(changed,'en5','en0'))

    def test_direct_only_requires_no_usb_and_no_retained_remote_nodes(self):
        cls=self.module().CampusDisconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            d=cls(os.getuid(),Path(directory),'en5','en0');d.context_unchanged=lambda:True
            state={'usb':False};d.online=lambda name:state['usb'] if name=='en5' else True
            values=({'mode':'direct','interface-name':'en0','tun':{'enable':True}},
                    {'EZ-Campus':{'type':'Direct','interface':'en0'},'EZ-USB-DNS':{'type':'Direct','interface':'en0'}},
                    [{'type':'Match','payload':'','proxy':'EZ-Campus'}])
            self.assertTrue(d.direct_mode(values));state['usb']=True
            self.assertFalse(d.direct_mode(values));state['usb']=False
            changed=copy.deepcopy(values);changed[1]['Node']={'type':'Trojan','interface':'en0'}
            self.assertFalse(d.direct_mode(changed))

    def test_recovery_waits_for_old_direct_only_then_blocked_then_two_split_reads(self):
        cls=self.module().CampusDisconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            d=cls(os.getuid(),Path(directory),'en5','en0')
            self.assertTrue(callable(getattr(d,'recovery_mode',None)), 'missing recovery settling predicate')
            d.context_unchanged=lambda:True;d.online=lambda name:True
            d.nodes={'Node':{'type':'trojan'}};d.original_groups={'Group':['Node']}
            d.original_rules=[{'type':'Match','payload':'','proxy':'Group'}]
            direct=({'mode':'direct','interface-name':'en0','tun':{'enable':True}},
                    {'EZ-Campus':{'type':'Direct','interface':'en0'},'EZ-USB-DNS':{'type':'Direct','interface':'en0'}},
                    [{'type':'Match','payload':'','proxy':'EZ-Campus'}])
            blocked=({'mode':'rule','interface-name':'en5','tun':{'enable':True}}, {}, [{'type':'Match','payload':'','proxy':'REJECT'}])
            split=({'mode':'rule','interface-name':'en5','tun':{'enable':True}},
                   {'EZ-Campus':{'type':'Direct','interface':'en0'},'EZ-USB-DNS':{'type':'Direct','interface':'en5'},
                    'Node':{'type':'Trojan','interface':'en5'},'Group':{'type':'Selector','all':['Node'],'now':'Node'}},d.original_rules)
            sequence=iter([direct,blocked,split,split]);d.runtime=lambda:next(sequence)
            with patch('time.sleep'): d.wait_mode(d.recovery_mode)
            observations=d.result['recovery_state_observations']
            self.assertEqual([x['state'] for x in observations],['direct-only-settling','blocked-settling','split','split'])
            d.online=lambda name:False if name=='en5' else True
            self.assertFalse(d.recovery_mode(split), 'brief USB bounce must not start recovery probes')
            d.online=lambda name:True
            unsafe=copy.deepcopy(split);unsafe[1]['Node']['interface']='en0'
            with self.assertRaisesRegex(RuntimeError,'remote-node-outside-usb'): d.recovery_mode(unsafe)
            unsafe=copy.deepcopy(split);unsafe[1]['EZ-USB-DNS']['interface']='en0'
            with self.assertRaisesRegex(RuntimeError,'dns-adapter-outside-usb'): d.recovery_mode(unsafe)
            d.runtime=lambda:direct
            with patch('time.monotonic',side_effect=[0,0,1]),patch('time.sleep'):
                with self.assertRaisesRegex(RuntimeError,'automatic-routing-did-not-reach-expected-mode'):
                    d.wait_mode(d.recovery_mode,seconds=.1)

    def test_failure_reports_restore_usb_and_close_wifi_without_false_pass(self):
        cls=self.module().CampusDisconnectDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            d=cls(os.getuid(),Path(directory),'en5','en0');d.stage='check-campus-direct-only'
            output=io.StringIO()
            with redirect_stdout(output):d.record_failure(RuntimeError('unsafe-runtime'))
            saved=json.loads((Path(directory)/'result.json').read_text())
            self.assertFalse(saved['all_requested_checks_verified']);self.assertEqual(saved['failed_stage'],d.stage)
            self.assertIn('插回',output.getvalue());self.assertIn('关闭 Mac Wi-Fi',output.getvalue())
