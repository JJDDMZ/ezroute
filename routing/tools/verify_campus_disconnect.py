#!/usr/bin/env python3
"""Read-only campus USB unplug/reconnect acceptance; only domestic probes when USB is off."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.verify_campus_split import CampusSplitDiagnostic
from tools.disconnect_assertions import direct_only_matches
from tools.probe_logs import CoreProbeLog
from tools.verify_wifi_reconnect import blocked_matches


def disconnect_checks_pass(result,usb,wifi):
    required=['campus_baseline_verified','usb_offline_observed','automatic_direct_only_verified',
              'direct_only_requests_verified','direct_only_system_dns_fake_ipv4',
              'campus_recovery_verified','recovery_system_dns_fake_ipv4','registration_unchanged',
              'selections_preserved','source_unchanged','single_app_verified']
    if not all(result.get(key) is True for key in required) or result.get('kernel_dropped') != 0:
        return False
    for phase in ('campus_baseline','campus_recovery'):
        values=result.get('phase_packet_counts',{}).get(phase,{})
        on_usb,on_wifi=values.get(usb,{}),values.get(wifi,{})
        if (result.get(phase+'_dns_status') not in (0,3)
                or on_usb.get('remote_packets',0)<=0 or on_usb.get('dns_packets',0)<=0
                or on_usb.get('direct_packets')!=0 or on_wifi.get('direct_packets',0)<=0
                or on_wifi.get('remote_packets')!=0 or on_wifi.get('dns_packets')!=0
                or on_usb.get('unparsed_ip_lines')!=0 or on_wifi.get('unparsed_ip_lines')!=0):
            return False
    values=result.get('phase_packet_counts',{}).get('campus_direct_only',{})
    on_usb,on_wifi=values.get(usb,{}),values.get(wifi,{})
    if (result.get('direct_only_dns_status') not in (0,3)
            or on_wifi.get('direct_packets',0)<=0 or on_wifi.get('dns_packets',0)<=0
            or on_wifi.get('remote_packets')!=0 or on_wifi.get('unparsed_ip_lines')!=0
            or any(on_usb.get(key)!=0 for key in ('remote_packets','direct_packets','dns_packets','unparsed_ip_lines'))):
        return False
    all_counts=result.get('all_capture_packet_counts',{})
    return (all_counts.get(wifi,{}).get('remote_packets')==0
            and all(all_counts.get(interface,{}).get('unparsed_ip_lines')==0 for interface in (usb,wifi)))


class CampusDisconnectDiagnostic(CampusSplitDiagnostic):
    def __init__(self,uid,root,usb,wifi):
        super().__init__(uid,root,usb,wifi)
        self.result.update(diagnostic_version=2,scope='specified-campus-direct-only-on-usb-unplug-and-split-recovery',
            network_identity='campus-wifi-user-confirmed',
            transition_boundary='physical-usb-state-observation-and-settled-config-not-event-time')

    def preflight(self):
        super().preflight(dual_online=True)

    def direct_mode(self,values):
        return (not self.online(self.usb) and self.online(self.wifi) and self.context_unchanged()
                and direct_only_matches(*values,self.wifi))

    def recovery_mode(self,values):
        general,adapters,_=values
        usb_online=self.online(self.usb)
        def observe(state):
            records=self.result.setdefault('recovery_state_observations',[])
            if len(records)<60:
                core=general.get('interface-name')
                records.append({'state':state,'usb_online':usb_online,
                    'core_interface':core if core in (self.usb,self.wifi) else 'other',
                    'remote_node_count':sum(name in adapters for name in self.nodes),
                    'remote_nodes_outside_usb':sum(adapters[name].get('interface')!=self.usb
                                                 for name in self.nodes if name in adapters)})
        # A physical IPv4 address can reappear before the coordinator leaves DirectOnly.
        # Only the exact node-free DirectOnly or blocked configurations may settle.
        if any(adapters[name].get('interface')!=self.usb for name in self.nodes if name in adapters):
            observe('unsafe-remote-binding')
            raise RuntimeError('remote-node-outside-usb')
        if not self.online(self.wifi) or not self.context_unchanged():
            observe('context-changed')
            raise RuntimeError('campus-or-application-context-changed')
        if direct_only_matches(*values,self.wifi):
            observe('direct-only-settling')
            return False
        if blocked_matches(values,self.usb):
            observe('blocked-settling')
            return False
        if not usb_online:
            observe('usb-not-ready')
            return False
        self.guard_usb_binding(values)
        ready=self.campus_mode(values)
        observe('split' if ready else 'awaiting-split-config')
        return ready

    def run(self,prepare_only=False):
        self.preflight()
        self.stage='start-core-probe-log'
        self.core_log=CoreProbeLog(self.endpoint,lambda:self.stage);self.core_log.start()
        if prepare_only:
            self.stage='campus-preflight-requests'
            requests=[self.probe(kind) for kind in ('proxy','direct')]
            self.result['preflight_requests']=requests
            self.result['preflight_verified']=all(self.valid_probe(item) for item in requests) and self.campus_mode(self.runtime())
            if not self.result['preflight_verified']:raise RuntimeError('campus-preflight-requests-failed')
            self.result.update(scope='campus-disconnect-preflight-no-capture-no-unplug',capture_scope='none')
            self.finish_capture();self.write('result.json',self.result)
            print(json.dumps(self.result,ensure_ascii=False),flush=True)
            return
        self.stage='start-packet-capture';self.start_capture()
        self.stage='check-campus-baseline'
        self.check_phone_phase('campus_baseline',self.campus_mode)

        self.stage='wait-for-usb-disconnect'
        self.begin_phase('disconnect_transition')
        print('步骤 1/2：现在拔掉自己的 iPhone USB，保留校园 Wi-Fi。不退出 EZ Route 或 Clash，不关闭 TUN 或自动路由。不要访问额外网站，聊天断网时继续看本终端，暂时不要插回。',flush=True)
        self.wait_usb(False,120)
        self.result.update(usb_offline_observed=True,campus_disconnect_tested=True)
        self.stage='check-campus-direct-only'
        self.wait_mode(self.direct_mode)
        self.result['automatic_direct_only_verified']=True
        self.end_phase();self.begin_phase('campus_direct_only')
        requests=[self.probe('direct') for _ in range(2)]
        self.result['direct_only_requests']=requests
        self.result['direct_only_requests_verified']=all(self.valid_probe(item) for item in requests)
        self.result['direct_only_dns_status']=self.api('/dns/query?name=ez-campus-direct-'+str(time.time_ns())+'.bilibili.com&type=TXT').get('Status')
        self.result['direct_only_system_dns_fake_ipv4']=self.system_dns_probe()
        if not self.direct_mode(self.runtime()):raise RuntimeError('campus-direct-only-config-or-network-changed')
        time.sleep(2);self.end_phase()

        self.stage='wait-for-usb-reconnect';self.begin_phase('reconnect_transition')
        print('步骤 2/2：拔线检查结束。现在插回自己的 iPhone USB，保持个人热点开启和校园 Wi-Fi，等待程序检查恢复。不要手动更改 Clash。',flush=True)
        self.wait_usb(True,120)
        self.stage='check-campus-recovery'
        self.wait_mode(self.recovery_mode);self.end_phase()
        self.begin_phase('campus_recovery')
        requests=[self.probe(kind) for kind in ('proxy','direct')]
        self.result['campus_recovery_requests']=requests
        self.result['campus_recovery_dns_status']=self.api('/dns/query?name=ez-campus-recovery-'+str(time.time_ns())+'.bilibili.com&type=TXT').get('Status')
        self.result['recovery_system_dns_fake_ipv4']=self.system_dns_probe()
        self.result['campus_recovery_verified']=all(self.valid_probe(item) for item in requests) and self.campus_mode(self.runtime())
        time.sleep(2);self.end_phase()
        values=self.runtime();self.guard_usb_binding(values)
        self.result['campus_recovery_verified']=self.result['campus_recovery_verified'] and self.campus_mode(values)
        self.result['registration_unchanged']=self.preferences().get('EZSwitch.registeredHotspots')==self.registration
        self.result['selections_preserved']=all(values[1].get(name,{}).get('now')==value for name,value in self.selections.items())
        self.result['source_unchanged']=self.source_unchanged();self.result['single_app_verified']=self.app_count()==1
        self.finish_capture()
        self.result['all_requested_checks_verified']=disconnect_checks_pass(self.result,self.usb,self.wifi)
        if not self.result['all_requested_checks_verified']:
            print('本轮未通过完整验收。请保持 USB 热点并关闭 Mac Wi-Fi，把结果发回排查。',flush=True)
        self.write('result.json',self.result);print(json.dumps(self.result,ensure_ascii=False),flush=True)

    def record_failure(self,error):
        self.result.update(failed_stage=self.stage,error_code=str(error) if isinstance(error,RuntimeError) else type(error).__name__)
        print('检查未通过。请插回自己的 iPhone USB、保持个人热点开启，并关闭 Mac Wi-Fi，保留 TUN 和自动路由。程序未修改配置。',flush=True)
        self.finish_capture();self.write('result.json',self.result);print(json.dumps(self.result,ensure_ascii=False),flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--wifi-is-campus',action='store_true',required=True)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--usb',default='en5');parser.add_argument('--wifi',default='en0')
    args=parser.parse_args()
    uid=os.getuid() if args.prepare_only else int(os.environ.get('SUDO_UID','-1'))
    if uid<=0 or (not args.prepare_only and os.geteuid()!=0):parser.error('Use sudo in your Terminal for capture.')
    if not args.prepare_only and not sys.stdin.isatty():parser.error('Run interactively in your Terminal.')
    if args.usb==args.wifi or any(not re.fullmatch(r'en\d+',name) for name in (args.usb,args.wifi)):parser.error('Invalid interfaces.')
    root=args.output_dir.resolve(strict=True);info=root.stat()
    if root.parent!=Path('/private/tmp') or not root.name.startswith('ez-switch-campus-disconnect.') or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic=CampusDisconnectDiagnostic(uid,root,args.usb,args.wifi)
    try:
        diagnostic.run(args.prepare_only)
        return 0 if args.prepare_only or diagnostic.result['all_requested_checks_verified'] else 1
    except (Exception,KeyboardInterrupt) as error:
        diagnostic.record_failure(error);return 2
    finally:
        if diagnostic.core_log:diagnostic.core_log.stop()
        diagnostic.stop_capture()


if __name__=='__main__':raise SystemExit(main())
