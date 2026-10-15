#!/usr/bin/env python3
"""Read-only, user-guided Wi-Fi power-cycle and registered hotspot recovery."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.verify_wifi_restart import WifiRestartDiagnostic
from tools.verify_wifi_switch import WifiSwitchDiagnostic
from tools.probe_logs import CoreProbeLog


def blocked_matches(values, usb):
    general, adapters, rules = values
    builtin_types = {'DIRECT':'Direct', 'REJECT':'Reject', 'REJECT-DROP':'RejectDrop',
                     'PASS':'Pass', 'PASS-RULE':'PassRule', 'COMPATIBLE':'Compatible', 'GLOBAL':'Selector'}
    return (general.get('mode') == 'rule' and general.get('interface-name') == usb
            and general.get('tun', {}).get('enable') is True
            and set(adapters) <= set(builtin_types)
            and all(adapters[name].get('type') == builtin_types[name] for name in adapters)
            and set(adapters.get('GLOBAL', {}).get('all', [])) <= set(builtin_types)
            and len(rules) == 1 and rules[0].get('type') == 'Match'
            and rules[0].get('payload', '') == '' and rules[0].get('proxy') == 'REJECT')


def reconnect_checks_pass(result, usb, wifi):
    required = ['baseline_verified', 'registered_wifi_verified', 'wifi_off_confirmed',
                'blocked_config_verified', 'wifi_reconnect_confirmed', 'wifi_reconnected_verified',
                'usb_recovery_verified', 'registration_unchanged', 'selections_preserved', 'single_app_verified']
    if not all(result.get(key) is True for key in required) or result.get('kernel_dropped') != 0:
        return False
    phases = result.get('phase_packet_counts', {})
    for phase, expected, other in [('registered_wifi', wifi, usb), ('wifi_reconnected', wifi, usb),
                                   ('usb_recovery', usb, wifi)]:
        chosen, unused = phases.get(phase, {}).get(expected, {}), phases.get(phase, {}).get(other, {})
        if (result.get(phase + '_dns_status') not in (0, 3)
                or any(chosen.get(key, 0) <= 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or any(unused.get(key) != 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or chosen.get('unparsed_ip_lines') != 0 or unused.get('unparsed_ip_lines') != 0):
            return False
    for interface in (usb, wifi):
        offline = phases.get('offline_settled', {}).get(interface, {})
        if any(offline.get(key) != 0 for key in ['remote_packets', 'direct_packets', 'dns_packets', 'unparsed_ip_lines']):
            return False
    return True


class WifiReconnectDiagnostic(WifiRestartDiagnostic):
    def __init__(self, uid, root, usb, wifi):
        super().__init__(uid, root, usb, wifi)
        self.result.pop('instant_exit_protection_verified', None)
        self.result.update(scope='selected-endpoints-wifi-power-cycle-blocked-config-and-hotspot-recovery',
            transition_boundary='manual-power-and-reassociation-confirmations-not-event-time',
            offline_request_rejection_tested=False)

    def prefs_unchanged(self):
        prefs = self.preferences()
        return (prefs.get('EZSwitch.automaticRouting') is True
                and prefs.get('EZSwitch.registeredHotspots') == self.registration)

    def context_unchanged(self):
        # DHCP may allocate a new address. Address equality cannot prove SSID identity.
        return WifiSwitchDiagnostic.context_unchanged(self) and self.app_count() == 1

    def wifi_power_off(self):
        output = self.command(['/usr/sbin/networksetup', '-getairportpower', self.wifi]).decode().strip()
        return output.endswith(': Off')

    def offline_mode(self, values):
        return (not self.online(self.usb) and not self.online(self.wifi) and self.wifi_power_off()
                and self.prefs_unchanged() and self.app_count() == 1 and blocked_matches(values, self.usb))

    def run(self, prepare_only=False):
        if prepare_only:
            return WifiSwitchDiagnostic.run(self, prepare_only=True)
        self.preflight()
        self.stage = 'start-core-probe-log'
        self.core_log = CoreProbeLog(self.endpoint, lambda: self.stage)
        self.core_log.start()
        self.stage = 'start-packet-capture'
        self.start_capture()
        self.stage = 'check-usb-baseline'
        self.result['baseline_requests'] = [self.probe(kind) for kind in ('proxy', 'direct')]
        self.result['baseline_verified'] = all(self.valid_probe(item) for item in self.result['baseline_requests']) and self.usb_mode(self.runtime())
        if not self.result['baseline_verified']:
            raise RuntimeError('usb-priority-baseline-failed')

        self.stage = 'wait-for-usb-disconnect'
        print('步骤 1/4：拔掉自己的 iPhone USB，保持已登记手机 Wi-Fi。不关闭 TUN 或自动路由，不退出应用，先不要关闭 Wi-Fi。', flush=True)
        self.wait_usb(False, 120)
        self.result['usb_offline_observed'] = True
        self.stage = 'check-registered-wifi'
        self.wait_mode(self.wifi_mode)
        self.check_phone_phase('registered_wifi', self.wifi_mode)

        self.stage = 'wait-for-wifi-power-off'
        self.begin_phase('wifi_off_before_confirmation')
        print('步骤 2/4：保持 USB 拔出，关闭 Mac 的 Wi-Fi 开关。不要关闭手机热点，不关闭 TUN 或自动路由。确认 Wi-Fi 已关闭后，在本终端输入 1 并回车。此时聊天断网，请继续看终端。', flush=True)
        self.confirm_switch('1')
        self.result['wifi_off_confirmed'] = True
        self.end_phase()
        self.stage = 'check-offline-blocked-config'
        self.wait_mode(self.offline_mode)
        self.begin_phase('offline_settled')
        # No external requests in this phase; inspect the core over its local Unix socket.
        for _ in range(6):
            if not self.offline_mode(self.runtime()):
                raise RuntimeError('offline-blocked-config-or-network-changed')
            time.sleep(.5)
        self.result['blocked_config_verified'] = True
        self.end_phase()

        self.stage = 'wait-for-same-hotspot-reconnect'
        self.begin_phase('wifi_reconnect_before_confirmation')
        print('步骤 3/4：保持 USB 拔出，打开 Mac Wi-Fi，重新连接刚才同一个已登记手机热点。不要连接校园网。确认连接成功后，在本终端输入 2 并回车。', flush=True)
        self.confirm_switch('2')
        self.result['wifi_reconnect_confirmed'] = True
        self.end_phase()
        self.stage = 'check-wifi-recovery'
        self.wait_mode(self.wifi_mode)
        self.check_phone_phase('wifi_reconnected', self.wifi_mode)
        self.result['wifi_ipv4_changed'] = self.wifi_addresses() != self.initial_wifi_addresses

        self.stage = 'wait-for-usb-reconnect'
        print('步骤 4/4：重新插回自己的 iPhone USB，保持个人热点开启和同一个已登记手机 Wi-Fi，等待程序完成。', flush=True)
        self.wait_usb(True, 120)
        self.stage = 'check-usb-recovery'
        self.wait_mode(self.usb_mode)
        self.check_phone_phase('usb_recovery', self.usb_mode)
        values = self.runtime()
        self.result['selections_preserved'] = all(values[1].get(name, {}).get('now') == value for name, value in self.selections.items())
        self.result['registration_unchanged'] = self.preferences().get('EZSwitch.registeredHotspots') == self.registration
        self.result['single_app_verified'] = self.app_count() == 1
        if not self.usb_mode(values):
            raise RuntimeError('usb-priority-or-registration-changed-before-finish')
        self.finish_capture()
        self.result['all_requested_checks_verified'] = reconnect_checks_pass(self.result, self.usb, self.wifi)
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)

    def record_failure(self, error):
        self.result.update(failed_stage=self.stage,
            error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        if self.result.get('usb_offline_observed'):
            print('检查未通过。请插回自己的 iPhone USB、保持热点开启，打开 Mac Wi-Fi 并连回原已登记手机热点。不连接校园网，不退出 Clash 或 EZ Route。程序未修改 Clash 配置。', flush=True)
        else:
            print('操作前检查未通过。请保持 USB 和已登记手机 Wi-Fi，不要拔线或关闭 Wi-Fi。程序未修改 Clash 配置。', flush=True)
        self.finish_capture()
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--wifi-is-registered-phone-hotspot', action='store_true', required=True)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--usb', default='en5')
    parser.add_argument('--wifi', default='en0')
    args = parser.parse_args()
    uid = os.getuid() if args.prepare_only else int(os.environ.get('SUDO_UID', '-1'))
    if uid <= 0 or (not args.prepare_only and os.geteuid() != 0):
        parser.error('Use sudo in your Terminal for capture.')
    if not args.prepare_only and not sys.stdin.isatty():
        parser.error('Run interactively in your Terminal; Wi-Fi confirmations are required.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+', name) for name in (args.usb, args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True)
    info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-wifi-reconnect.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = WifiReconnectDiagnostic(uid, root, args.usb, args.wifi)
    try:
        diagnostic.run(args.prepare_only)
        return 0 if args.prepare_only or diagnostic.result['all_requested_checks_verified'] else 1
    except (Exception, KeyboardInterrupt) as error:
        diagnostic.record_failure(error)
        return 2
    finally:
        if diagnostic.core_log:
            diagnostic.core_log.stop()
        diagnostic.stop_capture()


if __name__ == '__main__':
    raise SystemExit(main())
