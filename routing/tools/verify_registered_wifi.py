#!/usr/bin/env python3
"""Read-only acceptance: registered Wi-Fi handover and USB-priority recovery."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import select
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.verify_auto_disconnect import Diagnostic, BUILTINS, GROUPS
from tools.disconnect_assertions import hotspot_matches, packet_summary, registered_wifi_checks_pass
from tools.watch_network import summarize_interface
from tools.probe_logs import CoreProbeLog


class RegisteredWifiDiagnostic(Diagnostic):
    def __init__(self, uid, root, usb, wifi):
        super().__init__(uid, root, usb, wifi)
        self.phases = {}
        self.core_log = None
        self.result.update(diagnostic_version=3,
            scope='selected-tun-proxy-direct-dns-usb-to-registered-wifi-and-back',
            network_identity='registered-phone-hotspot-user-confirmed',
            capture_scope='physical-usb-and-wifi-tcp-udp-all-processes-headers-only')

    def preferences(self):
        arguments = ['/usr/bin/defaults', 'export', 'dev.ezswitch.app', '-']
        if os.geteuid() == 0:
            arguments = ['/usr/bin/sudo', '-n', '-u', '#' + str(self.uid)] + arguments
        return plistlib.loads(self.command(arguments))

    def wifi_addresses(self):
        text = self.command(['/sbin/ifconfig', self.wifi]).decode()
        return sorted(summarize_interface(text)['ipv4'])

    def preflight(self):
        prefs = self.preferences()
        self.registration = prefs.get('EZSwitch.registeredHotspots')
        if not prefs.get('EZSwitch.automaticRouting') or not self.registration or not json.loads(self.registration):
            raise RuntimeError('automatic-routing-off-or-no-registered-hotspot')
        if (prefs.get('EZSwitch.bootstrapUSBInterface') != self.usb
                or not prefs.get('EZSwitch.routingDeviceID')
                or prefs.get('EZSwitch.bootstrapDeviceID') != prefs.get('EZSwitch.routingDeviceID')):
            raise RuntimeError('usb-interface-does-not-match-selected-phone')
        if not self.online(self.usb) or not self.online(self.wifi):
            raise RuntimeError('keep-usb-and-registered-phone-wifi-online')
        self.initial_wifi_addresses = self.wifi_addresses()
        source_path = self.home / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
        source = json.loads(self.command(['/usr/bin/ruby', '-ryaml', '-rjson', '-e',
            'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))', str(source_path)], 15))
        self.nodes = {item['name']: item for item in source.get('proxies', []) if item.get('type') != 'direct'}
        if not self.nodes:
            raise RuntimeError('no-supported-remote-nodes')
        values = self.runtime()
        self.original_rules = values[2]
        self.original_groups = {name: list(item.get('all', [])) for name, item in values[1].items()
                                if name not in BUILTINS and item.get('type') in GROUPS}
        self.selections = {name: item['now'] for name, item in values[1].items()
                           if name not in BUILTINS and item.get('type') == 'Selector'}
        if not self.outlet_matches(values, self.usb):
            raise RuntimeError('registered-hotspot-usb-priority-preflight-failed')
        self.result['registered_hotspot_count'] = len(json.loads(self.registration))

    def outlet_matches(self, values, interface):
        return hotspot_matches(values, interface, self.nodes, self.original_groups, self.original_rules)

    def context_unchanged(self):
        prefs = self.preferences()
        return (prefs.get('EZSwitch.automaticRouting') is True
                and prefs.get('EZSwitch.registeredHotspots') == self.registration
                and self.online(self.wifi) and self.wifi_addresses() == self.initial_wifi_addresses)

    def wifi_mode(self, values):
        return not self.online(self.usb) and self.context_unchanged() and self.outlet_matches(values, self.wifi)

    def usb_mode(self, values):
        return self.online(self.usb) and self.context_unchanged() and self.outlet_matches(values, self.usb)

    def start_capture(self):
        with self.private_file('physical-packets.txt') as output:
            self.capture = subprocess.Popen(['/usr/sbin/tcpdump', '-i', 'pktap,' + self.wifi + ',' + self.usb,
                '-k', 'INPD', '-n', '-q', '-l', '-p', '-s', '256', '(ip or ip6) and (tcp or udp)'],
                stdout=output, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self.capture.poll() is None:
            if select.select([self.capture.stderr], [], [], .2)[0]:
                message = os.read(self.capture.stderr.fileno(), 8192).decode(errors='replace')
                self.capture_messages.append(message)
                if 'listening on' in message:
                    self.result['capture_started'] = True
                    return
        raise RuntimeError('capture-not-started')

    def packet_counts(self, data, interface):
        counts = packet_summary(data.decode(errors='replace').splitlines(), self.remote_targets,
                                self.direct_targets, interface)
        for old, new in [('remote_on_wifi', 'remote_packets'), ('direct_on_wifi', 'direct_packets'),
                         ('dns_on_wifi', 'dns_packets')]:
            counts[new] = counts.pop(old)
        return counts

    def record_capture_summary(self):
        packets = self.root / 'physical-packets.txt'
        if not packets.exists():
            return
        data = packets.read_bytes()
        self.result['all_capture_packet_counts'] = {interface: self.packet_counts(data, interface)
                                                  for interface in (self.usb, self.wifi)}
        self.result['phase_packet_counts'] = {
            phase: {interface: self.packet_counts(data[bounds[0]:bounds[1]], interface)
                    for interface in (self.usb, self.wifi)} for phase, bounds in self.phases.items()}
        drops = re.findall(r'(\d+) packets dropped by kernel', ''.join(self.capture_messages))
        self.result['kernel_dropped'] = int(drops[-1]) if drops else None
        self.result['packet_endpoint_scope'] = 'probes-with-identified-endpoints-only'

    def finish_capture(self):
        if getattr(self, 'capture_finalized', False):
            return
        if self.core_log:
            self.core_log.stop()
            self.write('core-probe-log.json', self.core_log.entries)
            self.result['core_probe_log'] = self.core_log.summary()
        self.stop_capture()
        packets = self.root / 'physical-packets.txt'
        if hasattr(self, 'pending_phase') and packets.exists():
            name, begin = self.pending_phase
            self.phases[name] = (begin, packets.stat().st_size)
            del self.pending_phase
        self.record_capture_summary()
        if packets.exists():
            self.write('probe-endpoints.json', {'remote': sorted(self.remote_targets), 'direct': sorted(self.direct_targets)})
            self.write('phase-byte-ranges.json', self.phases)
            with self.private_file('capture-stderr.txt') as handle:
                handle.write(''.join(self.capture_messages))
        self.capture_finalized = True

    def phase_probes(self, phase, interface):
        packets = self.root / 'physical-packets.txt'
        self.pending_phase = (phase, packets.stat().st_size)
        key = 'wifi' if phase == 'wifi_only' else 'recovery'
        self.result[key + '_requests'] = [self.probe(kind) for kind in ['proxy', 'direct']]
        self.result[key + '_requests_verified'] = all(self.valid_probe(x) for x in self.result[key + '_requests'])
        self.result[key + '_dns_status'] = self.api('/dns/query?name=ez-hotspot-' + str(time.time_ns()) + '.example.com&type=TXT').get('Status')
        if not self.context_unchanged() or not self.outlet_matches(self.runtime(), interface):
            raise RuntimeError('network-or-routing-changed-during-probes')
        time.sleep(1)
        self.phases[phase] = (self.pending_phase[1], packets.stat().st_size)
        del self.pending_phase

    def run(self, prepare_only, baseline_only=False):
        if baseline_only:
            self.result.update(baseline_only=True, physical_handover_tested=False,
                               scope='usb-priority-baseline-only-no-physical-handover')
        self.preflight()
        self.stage = 'start-core-probe-log'
        self.core_log = CoreProbeLog(self.endpoint, lambda: self.stage)
        self.core_log.start()
        if not prepare_only:
            self.stage = 'start-packet-capture'
            self.start_capture()
        self.stage = 'check-usb-baseline'
        self.result['baseline_requests'] = [self.probe(kind) for kind in ['proxy', 'direct']]
        self.result['baseline_verified'] = all(self.valid_probe(x) for x in self.result['baseline_requests']) and self.usb_mode(self.runtime())
        if not self.result['baseline_verified']:
            raise RuntimeError('usb-priority-baseline-failed')
        if prepare_only or baseline_only:
            self.finish_capture()
            self.write('result.json', self.result)
            if baseline_only:
                print(json.dumps(self.result, ensure_ascii=False), flush=True)
                return
            print(json.dumps({'preflight_verified': True, 'registered_hotspot_count': self.result['registered_hotspot_count'],
                              'outlet': self.usb, 'requests': self.result['baseline_requests'],
                              'core_probe_log': self.result['core_probe_log'], 'live_clash_modified': False}), flush=True)
            return
        self.stage = 'wait-for-usb-disconnect'
        print('步骤 1/2：现在拔掉自己的 iPhone USB，保持已登记手机 Wi-Fi。不关闭 TUN 或自动路由，不切换 Wi-Fi。聊天断网时请继续看终端。', flush=True)
        self.wait_usb(False, 120)
        self.result['usb_offline_observed'] = True
        self.stage = 'check-registered-wifi-only'
        print('已检测到拔线，正在检查代理、直连和 DNS 是否全部使用已登记 Wi-Fi。请暂时不要插回。', flush=True)
        self.wait_mode(self.wifi_mode)
        self.result['automatic_wifi_hotspot_verified'] = True
        time.sleep(1)
        self.phase_probes('wifi_only', self.wifi)
        if self.online(self.usb):
            raise RuntimeError('usb-reconnected-before-wifi-only-check-ended')
        self.stage = 'wait-for-usb-reconnect'
        print('步骤 2/2：单无线检查结束。现在插回自己的 iPhone USB，保持个人热点开启，等待自动恢复 USB 优先。', flush=True)
        self.wait_usb(True, 120)
        self.stage = 'check-usb-priority-recovery'
        self.wait_mode(self.usb_mode)
        self.result['automatic_usb_priority_recovered'] = True
        time.sleep(1)
        self.phase_probes('usb_recovery', self.usb)
        values = self.runtime()
        self.result['selections_preserved'] = all(values[1].get(name, {}).get('now') == value
                                                 for name, value in self.selections.items())
        self.result['registration_unchanged'] = self.preferences().get('EZSwitch.registeredHotspots') == self.registration
        self.result['wifi_network_unchanged'] = self.context_unchanged()
        if not self.usb_mode(values):
            raise RuntimeError('usb-priority-state-changed-before-finish')
        self.finish_capture()
        self.result['all_requested_checks_verified'] = registered_wifi_checks_pass(self.result, self.usb, self.wifi)
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)

    def record_failure(self, error):
        self.result.update(failed_stage=self.stage,
            error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        if self.result.get('usb_offline_observed'):
            print('检查未通过。请插回自己的 iPhone USB、保持热点开启和已登记 Wi-Fi。程序未修改 Clash 配置。', flush=True)
        else:
            print('拔线前检查未通过，尚未完成拔线验收。请保持 USB 连接和已登记 Wi-Fi，不要拔线。程序未修改 Clash 配置。', flush=True)
        self.finish_capture()
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--prepare-only', action='store_true')
    scope.add_argument('--baseline-only', action='store_true')
    parser.add_argument('--wifi-is-registered-phone-hotspot', action='store_true', required=True)
    parser.add_argument('--usb', default='en5')
    parser.add_argument('--wifi', default='en0')
    args = parser.parse_args()
    uid = os.getuid() if args.prepare_only else int(os.environ.get('SUDO_UID', '-1'))
    if uid <= 0 or (not args.prepare_only and os.geteuid() != 0):
        parser.error('Use sudo in your Terminal for capture.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+', name) for name in (args.usb, args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True)
    info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-registered-wifi.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = RegisteredWifiDiagnostic(uid, root, args.usb, args.wifi)
    try:
        diagnostic.run(args.prepare_only, args.baseline_only)
        return 0 if args.prepare_only or args.baseline_only or diagnostic.result['all_requested_checks_verified'] else 1
    except (Exception, KeyboardInterrupt) as error:
        diagnostic.record_failure(error)
        return 2
    finally:
        if diagnostic.core_log:
            diagnostic.core_log.stop()
        diagnostic.stop_capture()


if __name__ == '__main__':
    raise SystemExit(main())
