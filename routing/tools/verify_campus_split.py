#!/usr/bin/env python3
"""Read-only campus split acceptance, beginning with Wi-Fi off and USB online."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.verify_wifi_restart import WifiRestartDiagnostic
from tools.verify_auto_disconnect import BUILTINS, GROUPS
from tools.disconnect_assertions import hotspot_matches
from tools.probe_logs import CoreProbeLog


def split_rules(rules):
    allowed = {'Domain','DomainSuffix','DomainKeyword','GeoSite'}
    return [rule for rule in rules if rule.get('proxy') != 'EZ-Campus' or rule.get('type') in allowed]


def campus_checks_pass(result, usb, wifi):
    required = ['usb_baseline_verified','campus_confirmed','campus_split_verified',
                'campus_requests_verified','system_dns_fake_ipv4','registration_unchanged',
                'selections_preserved','single_app_verified','source_unchanged']
    if not all(result.get(key) is True for key in required) or result.get('kernel_dropped') != 0 or result.get('campus_dns_status') not in (0,3):
        return False
    phase = result.get('phase_packet_counts',{}).get('campus_split',{})
    on_usb, on_wifi = phase.get(usb,{}), phase.get(wifi,{})
    if (on_usb.get('remote_packets',0) <= 0 or on_usb.get('dns_packets',0) <= 0
            or on_usb.get('direct_packets') != 0 or on_wifi.get('direct_packets',0) <= 0
            or on_wifi.get('remote_packets') != 0 or on_wifi.get('dns_packets') != 0):
        return False
    for counts in (phase,result.get('all_capture_packet_counts',{})):
        if (any(counts.get(interface,{}).get('unparsed_ip_lines') != 0 for interface in (usb,wifi))
                or counts.get(wifi,{}).get('remote_packets') != 0
                or counts.get(wifi,{}).get('dns_packets') != 0):
            return False
    return True


class CampusSplitDiagnostic(WifiRestartDiagnostic):
    def __init__(self,uid,root,usb,wifi):
        super().__init__(uid,root,usb,wifi)
        self.result.pop('instant_exit_protection_verified',None)
        self.result.update(scope='specified-ipv4-tun-campus-split-and-system-dns',
            network_identity='campus-wifi-user-confirmation-pending',
            transition_boundary='manual-campus-confirmation-not-association-time',
            campus_disconnect_tested=False, all_node_egress_tested=False)

    def wifi_power_off(self):
        return self.command(['/usr/sbin/networksetup','-getairportpower',self.wifi]).decode().strip().endswith(': Off')

    def source_unchanged(self):
        return hashlib.sha256(self.source_path.read_bytes()).digest() == self.source_digest

    def context_unchanged(self):
        prefs = self.preferences()
        return (prefs.get('EZSwitch.automaticRouting') is True
                and prefs.get('EZSwitch.registeredHotspots') == self.registration
                and self.app_count() == 1 and self.source_unchanged())

    def usb_only_mode(self,values):
        return (self.online(self.usb) and not self.online(self.wifi) and self.wifi_power_off()
                and self.context_unchanged() and self.outlet_matches(values,self.usb))

    def campus_mode(self,values):
        general,adapters,rules = values
        if not self.online(self.usb) or not self.online(self.wifi) or not self.context_unchanged():
            return False
        if adapters.get('EZ-Campus',{}).get('interface') != self.wifi:
            return False
        # Reuse the strict supported-node/group validator; only direct's outlet differs.
        normalized = copy.deepcopy(adapters)
        normalized['EZ-Campus']['interface'] = self.usb
        return hotspot_matches((general,normalized,rules),self.usb,self.nodes,
                               self.original_groups,split_rules(self.original_rules))

    def guard_usb_binding(self,values):
        general,adapters,_ = values
        if not self.online(self.usb) or general.get('interface-name') != self.usb:
            raise RuntimeError('usb-not-online-or-core-binding-changed')
        known = set(self.nodes) | set(self.original_groups) | BUILTINS | {'EZ-Campus','EZ-USB-DNS'}
        if set(adapters)-known:
            raise RuntimeError('unexpected-runtime-adapter')
        if any(adapters[name].get('interface') != self.usb for name in self.nodes if name in adapters):
            raise RuntimeError('remote-node-outside-usb')
        if 'EZ-USB-DNS' in adapters and adapters['EZ-USB-DNS'].get('interface') != self.usb:
            raise RuntimeError('dns-adapter-outside-usb')

    def preflight(self, dual_online=False):
        prefs = self.preferences()
        self.registration = prefs.get('EZSwitch.registeredHotspots')
        if (prefs.get('EZSwitch.automaticRouting') is not True
                or prefs.get('EZSwitch.bootstrapUSBInterface') != self.usb
                or not prefs.get('EZSwitch.routingDeviceID')
                or prefs.get('EZSwitch.bootstrapDeviceID') != prefs.get('EZSwitch.routingDeviceID')):
            raise RuntimeError('automatic-routing-or-selected-usb-association-invalid')
        wifi_ready = self.online(self.wifi) if dual_online else not self.online(self.wifi) and self.wifi_power_off()
        if not self.online(self.usb) or not wifi_ready or self.app_count() != 1:
            raise RuntimeError('keep-usb-and-campus-wifi-online-with-one-app' if dual_online else 'keep-usb-online-wifi-power-off-and-one-app')
        self.source_path = self.home/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
        self.source_digest = hashlib.sha256(self.source_path.read_bytes()).digest()
        source = json.loads(self.command(['/usr/bin/ruby','-ryaml','-rjson','-e',
            'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))',str(self.source_path)],15))
        self.nodes = {node['name']:node for node in source.get('proxies',[]) if node.get('type') != 'direct'}
        self.original_groups = {group['name']:list(group.get('proxies',[])) for group in source.get('proxy-groups',[])}
        values = self.runtime()
        self.original_rules = values[2]
        self.selections = {name:item['now'] for name,item in values[1].items()
                           if name not in BUILTINS and item.get('type') == 'Selector'}
        targets = set(self.nodes) | set(self.original_groups) | {'EZ-Campus','REJECT','REJECT-DROP'}
        if (not self.nodes or not self.original_rules
                or any(rule.get('proxy') not in targets for rule in self.original_rules)
                or self.original_rules[-1].get('type') != 'Match'
                or self.original_rules[-1].get('proxy') == 'EZ-Campus'
                or not (self.campus_mode(values) if dual_online else self.usb_only_mode(values))):
            raise RuntimeError('campus-split-routing-preflight-failed' if dual_online else 'usb-only-routing-preflight-failed')
        self.result['remote_node_count'] = len(self.nodes)

    def system_dns_probe(self):
        host = 'ez-campus-system-'+str(time.time_ns())+'.bilibili.com'
        script = ('import socket,json,ipaddress,sys; '
                  'values=socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM); '
                  'print(json.dumps(bool(values) and all(ipaddress.ip_address(v[4][0]) '
                  'in ipaddress.ip_network("198.18.0.0/16") for v in values)))')
        try:
            return json.loads(self.command(['/usr/bin/python3','-c',script,host],10)) is True
        except Exception as error:
            self.result['system_dns_error_type'] = type(error).__name__
            return False

    def run(self,prepare_only=False):
        self.preflight()
        self.stage = 'start-core-probe-log'
        self.core_log = CoreProbeLog(self.endpoint,lambda:self.stage)
        self.core_log.start()
        if not prepare_only:
            self.stage = 'start-packet-capture'
            self.start_capture()
            self.begin_phase('usb_baseline')
        self.stage = 'check-usb-baseline'
        requests = [self.probe(kind) for kind in ('proxy','direct')]
        self.result['usb_baseline_requests'] = requests
        self.result['usb_baseline_verified'] = all(self.valid_probe(item) for item in requests) and self.usb_only_mode(self.runtime())
        if not self.result['usb_baseline_verified']:
            raise RuntimeError('usb-only-request-or-config-failed')
        if prepare_only:
            self.result.update(scope='campus-test-usb-only-preflight-no-capture',capture_scope='none')
            self.finish_capture();self.write('result.json',self.result)
            print(json.dumps(self.result,ensure_ascii=False),flush=True)
            return
        time.sleep(1);self.end_phase()

        self.stage = 'wait-for-campus-wifi'
        self.begin_phase('campus_before_confirmation')
        print('单 USB 预检通过。现在保持自己的 iPhone USB 热点，打开 Mac Wi-Fi 并连接校园网。不要将校园网登记为手机热点，不退出应用、不关闭 TUN 或自动路由。确认连接成功后在本终端输入 1 并回车；全程不要拔 USB。',flush=True)
        self.confirm_switch('1')
        self.result.update(campus_confirmed=True,network_identity='campus-wifi-user-confirmed')
        self.end_phase()
        self.stage = 'check-campus-split-config'
        def guarded(values):
            self.guard_usb_binding(values)
            return self.campus_mode(values)
        self.wait_mode(guarded)
        self.result['campus_split_verified'] = True
        self.begin_phase('campus_split')
        self.stage = 'probe-campus-split'
        self.guard_usb_binding(self.runtime())
        requests = [self.probe(kind) for kind in ('proxy','direct')]
        self.result['campus_requests'] = requests
        self.result['campus_requests_verified'] = all(self.valid_probe(item) for item in requests)
        self.result['campus_dns_status'] = self.api('/dns/query?name=ez-campus-'+str(time.time_ns())+'.bilibili.com&type=TXT').get('Status')
        self.result['system_dns_fake_ipv4'] = self.system_dns_probe()
        time.sleep(2)
        self.end_phase()
        values = self.runtime()
        self.guard_usb_binding(values)
        self.result['campus_split_verified'] = self.campus_mode(values)
        self.result['registration_unchanged'] = self.preferences().get('EZSwitch.registeredHotspots') == self.registration
        self.result['selections_preserved'] = all(values[1].get(name,{}).get('now') == selected for name,selected in self.selections.items())
        self.result['single_app_verified'] = self.app_count() == 1
        self.result['source_unchanged'] = self.source_unchanged()
        self.finish_capture()
        self.result['all_requested_checks_verified'] = campus_checks_pass(self.result,self.usb,self.wifi)
        if not self.result['all_requested_checks_verified']:
            print('本轮未通过完整验收，请关闭 Mac Wi-Fi、保留 USB 和热点，发回结果供排查。不要拔线。',flush=True)
        self.write('result.json',self.result)
        print(json.dumps(self.result,ensure_ascii=False),flush=True)

    def record_failure(self,error):
        self.result.update(failed_stage=self.stage,error_code=str(error) if isinstance(error,RuntimeError) else type(error).__name__)
        print('检查未通过。请关闭 Mac Wi-Fi，保留自己的 iPhone USB 热点、TUN 和自动路由；不要拔线。程序未修改配置。',flush=True)
        self.finish_capture();self.write('result.json',self.result)
        print(json.dumps(self.result,ensure_ascii=False),flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--wifi-will-be-campus',action='store_true',required=True)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--usb',default='en5');parser.add_argument('--wifi',default='en0')
    args = parser.parse_args()
    uid = os.getuid() if args.prepare_only else int(os.environ.get('SUDO_UID','-1'))
    if uid <= 0 or (not args.prepare_only and os.geteuid() != 0):
        parser.error('Use sudo in your Terminal for capture.')
    if not args.prepare_only and not sys.stdin.isatty():
        parser.error('Run interactively; campus connection confirmation is required.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+',name) for name in (args.usb,args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True);info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-campus-split.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = CampusSplitDiagnostic(uid,root,args.usb,args.wifi)
    try:
        diagnostic.run(args.prepare_only)
        return 0 if args.prepare_only or diagnostic.result['all_requested_checks_verified'] else 1
    except (Exception,KeyboardInterrupt) as error:
        diagnostic.record_failure(error);return 2
    finally:
        if diagnostic.core_log: diagnostic.core_log.stop()
        diagnostic.stop_capture()


if __name__ == '__main__':
    raise SystemExit(main())
