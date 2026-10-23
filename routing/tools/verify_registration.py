#!/usr/bin/env python3
"""Read-only diagnostic of user-driven registration removal/restoration on one phone Wi-Fi."""
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
from tools.disconnect_assertions import direct_only_matches, registration_checks_pass
from tools.probe_logs import CoreProbeLog


class RegistrationDiagnostic(WifiSwitchDiagnostic):
    def __init__(self, uid, root, usb, wifi):
        super().__init__(uid, root, usb, wifi)
        self.result.update(scope='selected-endpoints-after-user-registration-removal-and-restoration',
            network_identity='same-phone-wifi-user-confirmed-no-physical-wifi-switch',
            transition_boundary='manual-registration-confirmation-not-revocation-time',
            revocation_zero_leak_verified=False)

    @staticmethod
    def entries(data):
        items = json.loads(data) if data is not None else []
        if not isinstance(items, list) or any(not isinstance(item, dict)
                or set(item) != {'id', 'ssid', 'security', 'displayName'}
                or any(not isinstance(item[key], str) for key in ('id', 'ssid', 'displayName'))
                or type(item['security']) is not int for item in items):
            raise RuntimeError('malformed-hotspot-registration')
        return items

    def registration_removed(self):
        return self.entries(self.preferences().get('EZSwitch.registeredHotspots')) == []

    def registration_restored(self):
        def content(data):
            return sorted(json.dumps({key: value for key, value in item.items() if key != 'id'},
                                     sort_keys=True) for item in self.entries(data))
        return content(self.preferences().get('EZSwitch.registeredHotspots')) == content(self.registration)

    def preflight(self):
        super().preflight()
        if len(self.entries(self.registration)) != 1:
            raise RuntimeError('this-test-requires-exactly-one-current-registered-phone-hotspot')

    def context_unchanged(self):
        prefs = self.preferences()
        return (prefs.get('EZSwitch.automaticRouting') is True and self.online(self.wifi)
                and self.wifi_addresses() == self.initial_wifi_addresses)

    def wifi_mode(self, values):
        return self.registration_restored() and super().wifi_mode(values)

    def usb_mode(self, values):
        return self.registration_restored() and super().usb_mode(values)

    def direct_mode(self, values):
        return (self.registration_removed() and not self.online(self.usb)
                and self.context_unchanged() and direct_only_matches(*values, self.wifi))

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
        print('步骤 1/4：拔掉自己的 iPhone USB，保持当前已登记手机 Wi-Fi。不要关闭 TUN 或自动路由，不切换 Wi-Fi，暂不移除登记。', flush=True)
        self.wait_usb(False, 120)
        self.result['usb_offline_observed'] = True
        self.stage = 'check-registered-wifi'
        self.wait_mode(self.wifi_mode)
        self.check_phone_phase('registered_wifi', self.wifi_mode)

        self.stage = 'wait-for-registration-removal'
        self.begin_phase('removal_before_confirmation')
        print('步骤 2/4：保持 USB 拔出和同一个手机 Wi-Fi。在 EZ Route 设置的“已登记手机热点”中，点击当前热点的“移除”。完成后在本终端输入 1 并回车。不要关闭自动路由，聊天断网时继续看终端。', flush=True)
        self.confirm_switch('1')
        self.result['removal_confirmed'] = True
        self.end_phase()
        self.begin_phase('revoked_after_confirmation')
        self.stage = 'check-registration-revoked'
        self.wait_mode(self.direct_mode)
        self.result.update(registration_removed_verified=True, automatic_direct_only_verified=True)
        requests = [self.probe('direct') for _ in range(2)]
        self.result['revoked_direct_requests'] = requests
        self.result['revoked_direct_requests_verified'] = all(self.valid_probe(item) for item in requests)
        self.result['revoked_dns_status'] = self.api('/dns/query?name=ez-revoked-' + str(time.time_ns()) + '.bilibili.com&type=TXT').get('Status')
        if not self.direct_mode(self.runtime()):
            raise RuntimeError('revoked-direct-only-state-changed-during-probes')
        time.sleep(1)
        self.end_phase()
        if not self.result['revoked_direct_requests_verified']:
            raise RuntimeError('revoked-direct-requests-failed')

        self.stage = 'wait-for-registration-restoration'
        self.begin_phase('restoration_before_confirmation')
        print('步骤 3/4：仍保持 USB 拔出和同一个手机 Wi-Fi。在 EZ Route 设置中点击“信任当前无线连接…”，再确认“添加信任”。完成后在本终端输入 2 并回车。', flush=True)
        self.confirm_switch('2')
        self.result['restoration_confirmed'] = True
        self.end_phase()
        self.stage = 'check-registration-restored'
        self.wait_mode(self.wifi_mode)
        self.result['registration_content_restored'] = self.registration_restored()
        self.check_phone_phase('registered_return', self.wifi_mode)

        self.stage = 'wait-for-usb-reconnect'
        print('步骤 4/4：重新插回自己的 iPhone USB，保持个人热点开启和同一个已登记手机 Wi-Fi，等待程序结束。', flush=True)
        self.wait_usb(True, 120)
        self.stage = 'check-usb-recovery'
        self.wait_mode(self.usb_mode)
        self.check_phone_phase('usb_recovery', self.usb_mode)
        values = self.runtime()
        self.result['selections_preserved'] = all(values[1].get(name, {}).get('now') == value for name, value in self.selections.items())
        self.result['registration_content_restored'] = self.registration_restored()
        self.result['registration_bytes_unchanged'] = self.preferences().get('EZSwitch.registeredHotspots') == self.registration
        self.result['wifi_addresses_unchanged'] = self.context_unchanged()
        if not self.usb_mode(values):
            raise RuntimeError('usb-priority-state-changed-before-finish')
        self.finish_capture()
        self.result['all_requested_checks_verified'] = registration_checks_pass(self.result, self.usb, self.wifi)
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)

    def record_failure(self, error):
        self.result.update(failed_stage=self.stage,
            error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        if self.result.get('usb_offline_observed'):
            print('检查未通过。请插回自己的 iPhone USB、保持热点开启。如果当前手机热点登记已移除，请在 EZ Route 设置中重新登记它；不要连接校园网。程序不会替你修改或恢复登记。', flush=True)
        else:
            print('操作前检查未通过。请保持 USB 和原已登记手机 Wi-Fi，不要拔线或移除登记。程序未修改 Clash 配置。', flush=True)
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
        parser.error('Run interactively in your Terminal; registration confirmations are required.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+', name) for name in (args.usb, args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True)
    info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-registration.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = RegistrationDiagnostic(uid, root, args.usb, args.wifi)
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
