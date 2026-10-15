#!/usr/bin/env python3
"""Read-only, user-guided normal app exit/restart acceptance on registered phone Wi-Fi."""
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
from tools.verify_wifi_switch import WifiSwitchDiagnostic
from tools.disconnect_assertions import direct_only_matches
from tools.probe_logs import CoreProbeLog


def restart_checks_pass(result, usb, wifi):
    required = ['baseline_verified', 'registered_wifi_verified', 'quit_confirmed',
                'automatic_exit_direct_only_verified', 'exit_direct_requests_verified',
                'restart_confirmed', 'application_restarted_verified', 'wifi_restart_verified',
                'usb_recovery_verified', 'registration_unchanged', 'wifi_network_unchanged',
                'selections_preserved']
    if not all(result.get(key) is True for key in required) or result.get('kernel_dropped') != 0:
        return False
    phases = result.get('phase_packet_counts', {})
    for phase, expected, other in [('registered_wifi', wifi, usb), ('exit_direct', wifi, usb),
                                   ('wifi_restart', wifi, usb), ('usb_recovery', usb, wifi)]:
        chosen, unused = phases.get(phase, {}).get(expected, {}), phases.get(phase, {}).get(other, {})
        if (result.get(phase + '_dns_status') not in (0, 3)
                or any(chosen.get(key, 0) <= 0 for key in ['direct_packets', 'dns_packets'])
                or any(unused.get(key) != 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or chosen.get('unparsed_ip_lines') != 0 or unused.get('unparsed_ip_lines') != 0):
            return False
        if phase == 'exit_direct':
            if chosen.get('remote_packets') != 0:
                return False
        elif chosen.get('remote_packets', 0) <= 0:
            return False
    return True


class WifiRestartDiagnostic(WifiSwitchDiagnostic):
    def __init__(self, uid, root, usb, wifi):
        super().__init__(uid, root, usb, wifi)
        self.result.update(scope='selected-endpoints-normal-app-exit-and-restart-on-registered-phone-wifi',
            network_identity='same-registered-phone-wifi-user-confirmed',
            transition_boundary='manual-app-exit-confirmation-not-quit-time',
            instant_exit_protection_verified=False)

    def app_count(self):
        commands = self.command(['/bin/ps', '-U', str(self.uid), '-o', 'comm=']).decode().splitlines()
        return sum(value.strip() == 'EZSwitch'
                   or value.strip().endswith(('/EZ Route.app/Contents/MacOS/EZSwitch', '/EZSwitch.app/Contents/MacOS/EZSwitch')) for value in commands)

    def preflight(self):
        super().preflight()
        if self.app_count() != 1:
            raise RuntimeError('keep-exactly-one-ezswitch-instance-running')

    def context_unchanged(self):
        return super().context_unchanged() and self.wifi_addresses() == self.initial_wifi_addresses

    def exit_mode(self, values):
        return (not self.online(self.usb) and self.context_unchanged()
                and self.app_count() == 0 and direct_only_matches(*values, self.wifi))

    def restart_mode(self, values):
        return self.app_count() == 1 and self.wifi_mode(values)

    def run(self, prepare_only=False):
        if prepare_only:
            return super().run(prepare_only=True)
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
        print('步骤 1/4：拔掉自己的 iPhone USB，保持当前已登记手机 Wi-Fi。不关闭 TUN 或自动路由，不切换 Wi-Fi，先不要退出 EZ Route。', flush=True)
        self.wait_usb(False, 120)
        self.result['usb_offline_observed'] = True
        self.stage = 'check-registered-wifi'
        self.wait_mode(self.restart_mode)
        self.check_phone_phase('registered_wifi', self.restart_mode)

        self.stage = 'wait-for-normal-app-exit'
        self.begin_phase('exit_before_confirmation')
        print('步骤 2/4：保持 USB 拔出和同一个已登记手机 Wi-Fi，从菜单栏 EZ Route 菜单选择“退出”。不要强制退出，不退出 Clash，也不要只关闭设置窗口。等 EZ Route 菜单栏图标消失后，在本终端输入 1 并回车。聊天断网时继续看终端。', flush=True)
        self.confirm_switch('1')
        self.result['quit_confirmed'] = True
        self.end_phase()
        self.begin_phase('exit_direct')
        self.stage = 'check-app-exit'
        self.wait_mode(self.exit_mode)
        self.result['automatic_exit_direct_only_verified'] = True
        requests = [self.probe('direct') for _ in range(2)]
        self.result['exit_direct_requests'] = requests
        self.result['exit_direct_requests_verified'] = all(self.valid_probe(item) for item in requests)
        self.result['exit_direct_dns_status'] = self.api('/dns/query?name=ez-exit-' + str(time.time_ns()) + '.bilibili.com&type=TXT').get('Status')
        if not self.exit_mode(self.runtime()):
            raise RuntimeError('app-exit-state-changed-during-probes')
        time.sleep(1)
        self.end_phase()
        if not self.result['exit_direct_requests_verified']:
            raise RuntimeError('app-exit-direct-requests-failed')

        self.stage = 'wait-for-app-restart'
        self.begin_phase('restart_before_confirmation')
        print('步骤 3/4：保持 USB 拔出和同一个已登记手机 Wi-Fi。在 Finder 中重新打开 ~/Applications/EZ Route.app；等菜单栏图标出现后，在本终端输入 2 并回车。不要手动改 Clash 配置。', flush=True)
        self.confirm_switch('2')
        self.result['restart_confirmed'] = True
        self.end_phase()
        self.stage = 'check-app-restart-on-wifi'
        self.wait_mode(self.restart_mode)
        self.result['application_restarted_verified'] = True
        self.check_phone_phase('wifi_restart', self.restart_mode)

        self.stage = 'wait-for-usb-reconnect'
        print('步骤 4/4：重新插回自己的 iPhone USB，保持个人热点开启和同一个已登记手机 Wi-Fi，等待程序完成。', flush=True)
        self.wait_usb(True, 120)
        self.stage = 'check-usb-recovery'
        self.wait_mode(self.usb_mode)
        self.check_phone_phase('usb_recovery', self.usb_mode)
        values = self.runtime()
        self.result['selections_preserved'] = all(values[1].get(name, {}).get('now') == value for name, value in self.selections.items())
        self.result['registration_unchanged'] = self.preferences().get('EZSwitch.registeredHotspots') == self.registration
        self.result['wifi_network_unchanged'] = self.context_unchanged()
        if not self.usb_mode(values) or self.app_count() != 1:
            raise RuntimeError('usb-priority-or-app-state-changed-before-finish')
        self.finish_capture()
        self.result['all_requested_checks_verified'] = restart_checks_pass(self.result, self.usb, self.wifi)
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)

    def record_failure(self, error):
        self.result.update(failed_stage=self.stage,
            error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        if self.result.get('usb_offline_observed'):
            print('检查未通过。请插回自己的 iPhone USB，保持热点开启和原已登记手机 Wi-Fi；如果 EZ Route 已退出，请重新打开 ~/Applications/EZ Route.app。不要连接校园网。程序未修改 Clash 配置。', flush=True)
        else:
            print('操作前检查未通过。请保持 USB 和已登记手机 Wi-Fi，不要拔线或退出 EZ Route。程序未修改 Clash 配置。', flush=True)
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
        parser.error('Run interactively in your Terminal; app exit/restart confirmations are required.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+', name) for name in (args.usb, args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True)
    info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-wifi-restart.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = WifiRestartDiagnostic(uid, root, args.usb, args.wifi)
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
