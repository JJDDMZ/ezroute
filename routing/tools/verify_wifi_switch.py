#!/usr/bin/env python3
"""Read-only phone Wi-Fi switching diagnostic with explicitly limited phase attribution."""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.verify_registered_wifi import RegisteredWifiDiagnostic
from tools.disconnect_assertions import direct_only_matches, wifi_switch_checks_pass
from tools.probe_logs import CoreProbeLog


class WifiSwitchDiagnostic(RegisteredWifiDiagnostic):
    def __init__(self, uid, root, usb, wifi):
        super().__init__(uid, root, usb, wifi)
        self.result.update(diagnostic_version=1,
            scope='selected-endpoints-post-user-confirmation-and-settled-phone-wifi-modes',
            network_identity='initial-registered-phone-hotspot-target-identity-pending',
            transition_zero_leak_verified=False, physical_identity_independently_verified=False,
            physical_switch_tested=False,
            transition_boundary='manual-confirmation-not-association-time')

    def context_unchanged(self):
        # IPs may change on either hotspot; identical IPs do not establish SSID identity.
        prefs = self.preferences()
        return (prefs.get('EZSwitch.automaticRouting') is True
                and prefs.get('EZSwitch.registeredHotspots') == self.registration
                and self.online(self.wifi))

    def direct_mode(self, values):
        return (not self.online(self.usb) and self.context_unchanged()
                and direct_only_matches(*values, self.wifi))

    def confirm_switch(self, expected):
        if not select.select([sys.stdin], [], [], 180)[0] or sys.stdin.readline().strip() != expected:
            raise RuntimeError('network-confirmation-not-received')

    def wait_mode(self, predicate, seconds=25):
        deadline, consecutive = time.monotonic() + seconds, 0
        while time.monotonic() < deadline:
            try:
                consecutive = consecutive + 1 if predicate(self.runtime()) else 0
                if consecutive >= 2:
                    return
            except (OSError, http.client.HTTPException) as error:
                consecutive = 0
                records = self.result.setdefault('controller_wait_read_errors', [])
                if len(records) < 20:
                    records.append({'stage': self.stage, 'error_type': type(error).__name__})
            time.sleep(.5)
        raise RuntimeError('automatic-routing-did-not-reach-expected-mode')

    def begin_phase(self, name):
        self.pending_phase = (name, (self.root / 'physical-packets.txt').stat().st_size)

    def end_phase(self):
        name, begin = self.pending_phase
        self.phases[name] = (begin, (self.root / 'physical-packets.txt').stat().st_size)
        del self.pending_phase

    def check_phone_phase(self, name, predicate):
        self.begin_phase(name)
        requests = [self.probe(kind) for kind in ('proxy', 'direct')]
        self.result[name + '_requests'] = requests
        self.result[name + '_dns_status'] = self.api('/dns/query?name=ez-switch-' + str(time.time_ns()) + '.bilibili.com&type=TXT').get('Status')
        self.result[name + '_verified'] = all(self.valid_probe(item) for item in requests) and predicate(self.runtime())
        time.sleep(1)
        self.end_phase()
        if not self.result[name + '_verified']:
            raise RuntimeError('phone-phase-request-or-routing-failed')

    def run(self, prepare_only=False):
        if prepare_only:
            self.result.update(scope='usb-priority-preflight-no-capture-no-physical-switch', capture_scope='none')
        self.preflight()
        self.stage = 'start-core-probe-log'
        self.core_log = CoreProbeLog(self.endpoint, lambda: self.stage)
        self.core_log.start()
        if not prepare_only:
            self.stage = 'start-packet-capture'
            self.start_capture()
        self.stage = 'check-usb-baseline'
        self.result['baseline_requests'] = [self.probe(kind) for kind in ('proxy', 'direct')]
        self.result['baseline_verified'] = all(self.valid_probe(item) for item in self.result['baseline_requests']) and self.usb_mode(self.runtime())
        if not self.result['baseline_verified']:
            raise RuntimeError('usb-priority-baseline-failed')
        if prepare_only:
            self.finish_capture()
            self.write('result.json', self.result)
            print(json.dumps(self.result, ensure_ascii=False), flush=True)
            return

        self.stage = 'wait-for-usb-disconnect'
        print('步骤 1/4：拔掉自己的 iPhone USB，保持当前已登记手机 Wi-Fi。不要关闭 TUN 或自动路由，先不要切换 Wi-Fi。', flush=True)
        self.wait_usb(False, 120)
        self.result['usb_offline_observed'] = True
        self.stage = 'check-registered-wifi'
        self.wait_mode(self.wifi_mode)
        self.check_phone_phase('registered_wifi', self.wifi_mode)

        self.stage = 'wait-for-unregistered-phone-wifi'
        self.begin_phase('transition_to_unregistered_unattributed')
        print('步骤 2/4：保持 USB 拔出，将 Mac Wi-Fi 切换到另一部未登记手机热点；不要连接校园网，不要登记这个热点。确认 Mac 已连接成功后，在本终端输入 1 并回车。聊天断网时继续看终端。', flush=True)
        self.confirm_switch('1')
        self.result['unregistered_confirmed'] = True
        self.result.update(physical_switch_tested=True, network_identity='two-distinct-phone-hotspots-user-confirmed')
        self.end_phase()
        # Include controller settling after the user's confirmation, not only final direct probes.
        self.begin_phase('unregistered_after_confirmation')
        self.stage = 'check-unregistered-direct-only'
        self.wait_mode(self.direct_mode)
        self.result['automatic_direct_only_verified'] = True
        requests = [self.probe('direct') for _ in range(2)]
        self.result['unregistered_direct_requests'] = requests
        self.result['unregistered_direct_requests_verified'] = all(self.valid_probe(item) for item in requests)
        self.result['unregistered_dns_status'] = self.api('/dns/query?name=ez-direct-' + str(time.time_ns()) + '.bilibili.com&type=TXT').get('Status')
        if not self.direct_mode(self.runtime()):
            raise RuntimeError('direct-only-state-changed-during-probes')
        time.sleep(1)
        self.end_phase()
        if not self.result['unregistered_direct_requests_verified']:
            raise RuntimeError('unregistered-direct-requests-failed')

        self.stage = 'wait-for-registered-phone-return'
        self.begin_phase('transition_to_registered_unattributed')
        print('步骤 3/4：保持 USB 拔出，将 Mac Wi-Fi 切回原来已登记的手机热点。确认连接成功后，在本终端输入 2 并回车。', flush=True)
        self.confirm_switch('2')
        self.result['registered_return_confirmed'] = True
        self.end_phase()
        self.stage = 'check-registered-phone-return'
        self.wait_mode(self.wifi_mode)
        self.check_phone_phase('registered_return', self.wifi_mode)

        self.stage = 'wait-for-usb-reconnect'
        print('步骤 4/4：重新插回自己的 iPhone USB，保持个人热点开启和已登记手机 Wi-Fi，等待程序完成。', flush=True)
        self.wait_usb(True, 120)
        self.stage = 'check-usb-recovery'
        self.wait_mode(self.usb_mode)
        self.check_phone_phase('usb_recovery', self.usb_mode)
        values = self.runtime()
        self.result['selections_preserved'] = all(values[1].get(name, {}).get('now') == value for name, value in self.selections.items())
        self.result['registration_unchanged'] = self.preferences().get('EZSwitch.registeredHotspots') == self.registration
        if not self.usb_mode(values):
            raise RuntimeError('usb-priority-state-changed-before-finish')
        self.finish_capture()
        self.result['all_requested_checks_verified'] = wifi_switch_checks_pass(self.result, self.usb, self.wifi)
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)

    def record_failure(self, error):
        self.result.update(failed_stage=self.stage,
            error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        if self.result.get('usb_offline_observed'):
            print('检查未通过。请插回自己的 iPhone USB，并切回原已登记手机热点，保持个人热点开启。不要连接校园网。程序未修改 Clash 配置。', flush=True)
        else:
            print('切网前检查未通过。请保持 USB 和原已登记手机 Wi-Fi，不要拔线或切网。程序未修改 Clash 配置。', flush=True)
        self.finish_capture()
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--two-phone-hotspots-no-campus', action='store_true', required=True)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--usb', default='en5')
    parser.add_argument('--wifi', default='en0')
    args = parser.parse_args()
    uid = os.getuid() if args.prepare_only else int(os.environ.get('SUDO_UID', '-1'))
    if uid <= 0 or (not args.prepare_only and os.geteuid() != 0):
        parser.error('Use sudo in your Terminal for capture.')
    if not args.prepare_only and not sys.stdin.isatty():
        parser.error('Run interactively in your Terminal; network confirmations are required.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+', name) for name in (args.usb, args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True)
    info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-wifi-switch.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = WifiSwitchDiagnostic(uid, root, args.usb, args.wifi)
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
