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


class CampusSplitTests(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(importlib.util.find_spec('tools.verify_campus_split'))
        from tools import verify_campus_split
        return verify_campus_split

    def test_split_drops_ip_based_direct_permission_but_keeps_proxy_ip_rule(self):
        rules=[{'type':'DomainSuffix','payload':'bilibili.com','proxy':'EZ-Campus'},
               {'type':'GeoIP','payload':'CN','proxy':'EZ-Campus'},
               {'type':'IPCIDR','payload':'192.0.2.0/24','proxy':'Group'},
               {'type':'Match','payload':'','proxy':'Group'}]
        self.assertEqual(self.module().split_rules(rules),[rules[0],rules[2],rules[3]])

    def test_campus_does_not_pass_when_proxy_or_dns_observed_on_wifi(self):
        usb={'remote_packets':8,'direct_packets':0,'dns_packets':4,'parsed_ip_lines':12,'unparsed_ip_lines':0}
        wifi={'remote_packets':0,'direct_packets':6,'dns_packets':0,'parsed_ip_lines':6,'unparsed_ip_lines':0}
        result={'usb_baseline_verified':True,'campus_confirmed':True,'campus_split_verified':True,
                'campus_requests_verified':True,'system_dns_fake_ipv4':True,'campus_dns_status':3,
                'registration_unchanged':True,'selections_preserved':True,'single_app_verified':True,
                'source_unchanged':True,'kernel_dropped':0,
                'phase_packet_counts':{'campus_split':{'en5':usb,'en0':wifi}},
                'all_capture_packet_counts':{'en5':usb,'en0':wifi}}
        check=self.module().campus_checks_pass
        self.assertTrue(check(result,'en5','en0'))
        for mutation in ('remote','dns','transition-dns','system-dns','drop','missing','unknown-packet','direct-on-usb'):
            changed=copy.deepcopy(result)
            if mutation=='remote': changed['phase_packet_counts']['campus_split']['en0']['remote_packets']=1
            elif mutation=='dns': changed['phase_packet_counts']['campus_split']['en0']['dns_packets']=1
            elif mutation=='transition-dns': changed['all_capture_packet_counts']['en0']['dns_packets']=1
            elif mutation=='system-dns': changed['system_dns_fake_ipv4']=False
            elif mutation=='drop': changed['kernel_dropped']=None
            elif mutation=='missing': changed['campus_requests_verified']=False
            elif mutation=='unknown-packet': changed['all_capture_packet_counts']['en0']['unparsed_ip_lines']=1
            else: changed['phase_packet_counts']['campus_split']['en5']['direct_packets']=1
            with self.subTest(mutation=mutation): self.assertFalse(check(changed,'en5','en0'))

    def test_split_mode_checks_all_nodes_and_dns_binding_and_domain_only_direct_rules(self):
        cls=self.module().CampusSplitDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            d=cls(os.getuid(),Path(directory),'en5','en0')
            d.nodes={'Node':{'type':'trojan'}};d.original_groups={'Group':['Node']}
            d.original_rules=[{'type':'DomainSuffix','payload':'bilibili.com','proxy':'EZ-Campus'},
                              {'type':'GeoIP','payload':'CN','proxy':'EZ-Campus'},
                              {'type':'Match','payload':'','proxy':'Group'}]
            d.context_unchanged=lambda:True
            d.online=lambda name:True
            values=({'mode':'rule','interface-name':'en5','tun':{'enable':True}},
                    {'EZ-Campus':{'type':'Direct','interface':'en0'},'EZ-USB-DNS':{'type':'Direct','interface':'en5'},
                     'Node':{'type':'Trojan','interface':'en5'},'Group':{'type':'Selector','all':['Node'],'now':'Node'}},
                    [d.original_rules[0],d.original_rules[2]])
            self.assertTrue(d.campus_mode(values))
            for mutation in ('node','dns','rule','fallback'):
                changed=copy.deepcopy(values)
                if mutation=='node': changed[1]['Node']['interface']='en0'
                elif mutation=='dns': changed[1]['EZ-USB-DNS']['interface']='en0'
                elif mutation=='rule': changed[2].insert(1,d.original_rules[1])
                else: changed[1]['Group']['all'].append('DIRECT')
                with self.subTest(mutation=mutation): self.assertFalse(d.campus_mode(changed))

    def test_binding_guard_aborts_on_usb_loss_or_wireless_proxy_binding(self):
        cls=self.module().CampusSplitDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            d=cls(os.getuid(),Path(directory),'en5','en0')
            d.nodes={'Node':{'type':'trojan'}};d.original_groups={'Group':['Node']}
            d.online=lambda name:True
            values=({'interface-name':'en5'},{'Node':{'interface':'en5'},'EZ-USB-DNS':{'interface':'en5'}},[])
            d.guard_usb_binding(values)
            changed=copy.deepcopy(values);changed[1]['Node']['interface']='en0'
            with self.assertRaisesRegex(RuntimeError,'remote-node-outside-usb'): d.guard_usb_binding(changed)
            d.online=lambda name:False
            with self.assertRaisesRegex(RuntimeError,'usb-not-online'): d.guard_usb_binding(values)

    def test_complete_connection_flow_keeps_usb_and_saves_packet_phases(self):
        cls=self.module().CampusSplitDiagnostic
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);d=cls(os.getuid(),root,'en5','en0')
            state={'wifi':False}
            d.registration=b'registered-phone-only'
            d.preferences=lambda:{'EZSwitch.automaticRouting':True,'EZSwitch.registeredHotspots':d.registration}
            d.online=lambda name:name=='en5' or state['wifi']
            d.wifi_power_off=lambda:not state['wifi']
            d.app_count=lambda:1;d.source_unchanged=lambda:True
            d.nodes={'Node':{'type':'trojan'}};d.original_groups={'Group':['Node']}
            d.original_rules=[{'type':'DomainSuffix','payload':'bilibili.com','proxy':'EZ-Campus'},
                              {'type':'Match','payload':'','proxy':'Group'}]
            d.selections={'Group':'Node'}
            def runtime():
                return ({'mode':'rule','interface-name':'en5','tun':{'enable':True}},
                        {'EZ-Campus':{'type':'Direct','interface':'en0' if state['wifi'] else 'en5'},
                         'EZ-USB-DNS':{'type':'Direct','interface':'en5'},'Node':{'type':'Trojan','interface':'en5'},
                         'Group':{'type':'Selector','all':['Node'],'now':'Node'}},d.original_rules)
            d.runtime=runtime;d.preflight=lambda:None
            def capture():
                (root/'physical-packets.txt').write_text('');d.capture_messages=['0 packets dropped by kernel\n']
            d.start_capture=capture
            def packet(address,port,interface):
                with (root/'physical-packets.txt').open('a') as handle:
                    handle.write(f'12:00:00 IP 192.0.2.1.40000 > {address}.{port}: tcp 0, if {interface}\n')
            def probe(kind):
                target=('198.51.100.2',443) if kind=='proxy' else ('203.0.113.3',443)
                (d.remote_targets if kind=='proxy' else d.direct_targets).add(target)
                packet(*target,'en0' if kind=='direct' and state['wifi'] else 'en5')
                return {'case':kind,'request_success':True,'transport':'Tun','policy_matches':True,
                        'domain_identified':True,'actual_endpoint_identified':True,'http_status':204 if kind=='proxy' else 302}
            d.probe=probe
            d.api=lambda path:(packet('192.0.2.53',53,'en5') or {'Status':3})
            d.system_dns_probe=lambda:True
            d.confirm_switch=lambda expected:state.update(wifi=True)
            with patch('tools.probe_logs.CoreProbeLog.start'),patch('time.sleep'),redirect_stdout(io.StringIO()): d.run()
            saved=json.loads((root/'result.json').read_text())
            self.assertTrue(saved['all_requested_checks_verified'])
            self.assertFalse(saved['transition_zero_leak_verified'])
            self.assertEqual(saved['phase_packet_counts']['campus_split']['en0']['remote_packets'],0)
            self.assertEqual(saved['phase_packet_counts']['campus_split']['en5']['direct_packets'],0)
            self.assertEqual(len(json.loads((root/'phase-byte-ranges.json').read_text())),3)
            self.assertTrue(d.online('en5'))
