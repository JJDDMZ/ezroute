#!/usr/bin/env python3
"""Read-only, user-guided acceptance of automatic USB disconnect and recovery."""
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import select
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_active import UnixHTTP
from tools.disconnect_assertions import direct_only_matches, packet_summary, stable_rules
from tools.watch_network import summarize_interface

BUILTINS = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'GLOBAL', 'COMPATIBLE'}
GROUPS = {'Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay'}


class Diagnostic:
    def __init__(self, uid, root, usb, wifi):
        self.uid, self.root, self.usb, self.wifi = uid, root, usb, wifi
        self.endpoint = f'/var/run/clash-verge-service/users/{uid}/verge-mihomo.sock'
        self.home = Path(pwd.getpwuid(uid).pw_dir)
        self.remote_targets, self.direct_targets = set(), set()
        self.stage, self.capture = 'preflight', None
        self.capture_messages = []
        self.result = {'diagnostic_version': 2, 'test_date': datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d'),
                       'scope': 'selected-proxy-endpoint-and-direct-control-during-auto-usb-disconnect',
                       'network_identity': 'other-phone-unregistered-hotspot-user-confirmed',
                       'live_clash_modified': False, 'record_directory': str(root),
                       'capture_scope': 'physical-wifi-tcp-udp-all-processes-headers-only',
                       'all_requested_checks_verified': False}

    def api(self, path):
        connection = UnixHTTP(self.endpoint)
        try:
            connection.request('GET', path, headers={'Host': 'localhost'})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError('controller-read-failed')
            return json.loads(response.read())
        finally:
            connection.close()

    def command(self, arguments, timeout=8):
        return subprocess.run(arguments, capture_output=True, check=True, timeout=timeout).stdout

    def private_file(self, name):
        fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, self.uid, pwd.getpwuid(self.uid).pw_gid)
        return os.fdopen(fd, 'w')

    def write(self, name, value):
        with self.private_file(name) as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)

    def online(self, interface):
        r = subprocess.run(['/sbin/ifconfig', interface], capture_output=True, text=True, timeout=4)
        x = summarize_interface(r.stdout)
        return r.returncode == 0 and x['active'] and bool(x['ipv4'])

    def runtime(self):
        return (self.api('/configs'), self.api('/proxies')['proxies'],
                self.api('/rules').get('rules', []))

    def split_matches(self, values):
        g, p, rules = values
        named = set(p) - BUILTINS
        return (g.get('mode') == 'rule' and g.get('tun', {}).get('enable') is True
                and g.get('interface-name') == self.usb
                and p.get('EZ-Campus', {}).get('type') == 'Direct'
                and p.get('EZ-Campus', {}).get('interface') == self.wifi
                and p.get('EZ-USB-DNS', {}).get('type') == 'Direct'
                and p.get('EZ-USB-DNS', {}).get('interface') == self.usb
                and named == self.original_names and stable_rules(rules) == stable_rules(self.original_rules)
                and all(p.get(n, {}).get('interface') == self.usb for n in self.nodes)
                and all(p.get(n, {}).get('type') in GROUPS
                        and p[n].get('all') == members for n, members in self.original_groups.items()))

    def preflight(self):
        args = ['/usr/bin/defaults', 'export', 'dev.ezswitch.app', '-']
        if os.geteuid() == 0:
            args = ['/usr/bin/sudo', '-n', '-u', '#' + str(self.uid)] + args
        prefs = plistlib.loads(self.command(args))
        registrations = prefs.get('EZSwitch.registeredHotspots')
        if not prefs.get('EZSwitch.automaticRouting') or (registrations and json.loads(registrations)):
            raise RuntimeError('automatic-routing-off-or-hotspots-already-registered')
        if (prefs.get('EZSwitch.bootstrapUSBInterface') != self.usb
                or not prefs.get('EZSwitch.routingDeviceID')
                or prefs.get('EZSwitch.bootstrapDeviceID') != prefs.get('EZSwitch.routingDeviceID')):
            raise RuntimeError('usb-interface-does-not-match-remembered-selected-phone')
        if not self.online(self.usb) or not self.online(self.wifi):
            raise RuntimeError('keep-both-usb-and-other-phone-wifi-online')
        path = self.home / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
        source = json.loads(self.command(['/usr/bin/ruby', '-ryaml', '-rjson', '-e',
                 'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))', str(path)], 15))
        self.nodes = {x['name']: x for x in source.get('proxies', []) if x.get('type') != 'direct'}
        if not self.nodes:
            raise RuntimeError('no-supported-remote-nodes-in-generated-source')
        values = self.runtime()
        self.original_names = set(self.nodes) | {g['name'] for g in source.get('proxy-groups', [])} | {'EZ-Campus', 'EZ-USB-DNS'}
        self.original_rules = values[2]
        self.original_groups = {n: list(p.get('all', [])) for n, p in values[1].items()
                                if n not in BUILTINS and p.get('type') in GROUPS}
        self.selections = {n: p['now'] for n, p in values[1].items()
                           if n not in BUILTINS and p.get('type') == 'Selector'}
        if not self.split_matches(values):
            raise RuntimeError('initial-split-routing-preflight-failed')

    def probe(self, kind):
        host, path = ('www.gstatic.com', '/generate_204') if kind == 'proxy' else ('www.bilibili.com', '/')
        context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(host, 443, timeout=8, context=context)
        result = {'case': kind, 'request_success': False, 'actual_endpoint_identified': False}
        operation = 'tcp-connect'
        port = None
        try:
            # Separate TCP from TLS so a reset has a useful, non-sensitive location.
            http.client.HTTPConnection.connect(connection)
            port = connection.sock.getsockname()[1]
            peer = ipaddress.ip_address(connection.sock.getpeername()[0])
            result['system_destination_is_fake_ipv4'] = peer.version == 4 and peer in ipaddress.ip_network('198.18.0.0/16')
            operation = 'tls-handshake'
            connection.sock = context.wrap_socket(connection.sock, server_hostname=host)
            operation = 'connection-metadata'
            matches = [x for x in self.api('/connections').get('connections', [])
                       if str(x.get('metadata', {}).get('sourcePort')) == str(port)]
            if len(matches) != 1:
                raise RuntimeError('request-not-uniquely-identified')
            item = matches[0]
            metadata, chains = item.get('metadata', {}), item.get('chains', [])
            leaves = [self.nodes[n] for n in chains if n in self.nodes]
            proxy = len(leaves) == 1
            direct = not leaves and bool(set(chains) & {'DIRECT', 'EZ-Campus'})
            actual = str(ipaddress.ip_address(metadata['remoteDestination']))
            if kind == 'proxy' and proxy:
                self.remote_targets.add((actual, int(leaves[0]['port'])))
            elif kind == 'direct' and direct:
                self.direct_targets.add((actual, 443))
            result.update(transport=metadata.get('type'), policy_matches=proxy if kind == 'proxy' else direct,
                          domain_identified=host in (metadata.get('host'), metadata.get('sniffHost')),
                          actual_endpoint_identified=True)
            operation = 'http-request'
            connection.request('HEAD', path)
            operation = 'http-response'
            response = connection.getresponse()
            response.read()
            result.update(http_status=response.status, request_success=True)
        except Exception as error:
            result.update(failed_operation=operation,
                          error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        finally:
            connection.close()
        return result

    def valid_probe(self, result):
        return (result.get('request_success') is True and result.get('transport') == 'Tun'
                and result.get('policy_matches') and result.get('domain_identified')
                and result.get('actual_endpoint_identified') and 200 <= result.get('http_status', 0) < 400)

    def record_capture_summary(self):
        packets = self.root / 'wifi-packets.txt'
        if not packets.exists():
            return
        self.result['wifi_packet_counts'] = packet_summary(
            packets.read_text().splitlines(), self.remote_targets, self.direct_targets, self.wifi)
        if hasattr(self, 'direct_phase_begin'):
            with packets.open('rb') as handle:
                handle.seek(self.direct_phase_begin)
                phase = handle.read(getattr(self, 'direct_phase_end', packets.stat().st_size) - self.direct_phase_begin)
            self.result['direct_only_phase_packet_counts'] = packet_summary(
                phase.decode(errors='replace').splitlines(), self.remote_targets, self.direct_targets, self.wifi)
        drops = re.findall(r'(\d+) packets dropped by kernel', ''.join(self.capture_messages))
        self.result['kernel_dropped'] = int(drops[-1]) if drops else None
        self.result['packet_endpoint_scope'] = 'probes-with-identified-endpoints-only'

    def start_capture(self):
        with self.private_file('wifi-packets.txt') as output:
            self.capture = subprocess.Popen(['/usr/sbin/tcpdump', '-i', 'pktap,' + self.wifi,
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

    def stop_capture(self):
        if self.capture is None:
            return
        if self.capture.poll() is None:
            self.capture.send_signal(signal.SIGINT)
        try:
            _, tail = self.capture.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.capture.kill()
            _, tail = self.capture.communicate(timeout=5)
        self.capture_messages.append(tail.decode(errors='replace'))
        self.capture = None

    def wait_usb(self, wanted, seconds):
        consecutive = 0
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not self.online(self.wifi):
                raise RuntimeError('keep-other-phone-wifi-connected')
            consecutive = consecutive + 1 if self.online(self.usb) == wanted else 0
            if consecutive >= 3:
                return
            time.sleep(.5)
        raise RuntimeError('usb-state-wait-timeout')

    def wait_mode(self, predicate, seconds=25):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate(self.runtime()):
                return
            time.sleep(.5)
        raise RuntimeError('automatic-routing-did-not-reach-expected-mode')

    def direct_mode(self, values):
        return not self.online(self.usb) and self.online(self.wifi) and direct_only_matches(*values, self.wifi)

    def run(self, prepare_only):
        self.preflight()
        if not prepare_only:
            self.start_capture()
        self.result['baseline_requests'] = [self.probe(k) for k in ['proxy', 'direct']]
        if not all(self.valid_probe(x) for x in self.result['baseline_requests']):
            raise RuntimeError('baseline-requests-failed')
        if prepare_only:
            print(json.dumps({'preflight_verified': True, 'requests': self.result['baseline_requests'],
                              'hotspots_registered': 0, 'live_clash_modified': False}), flush=True)
            return
        self.stage = 'wait-for-usb-disconnect'
        print('步骤 1/2：现在拔掉自己的 iPhone USB，保持另一部手机 Wi-Fi。不要关闭 TUN 或自动路由。聊天暂时断网时，请继续看本终端。', flush=True)
        self.wait_usb(False, 120)
        self.result['usb_offline_observed'] = True
        self.stage = 'check-auto-direct-only'
        print('已检测到拔线，正在检查自动强制直连。请暂时不要插回。', flush=True)
        self.wait_mode(self.direct_mode)
        self.result['automatic_direct_only_verified'] = True
        time.sleep(1)
        packets = self.root / 'wifi-packets.txt'
        self.direct_phase_begin = packets.stat().st_size
        self.result['disconnected_direct_requests'] = [self.probe('direct') for _ in range(2)]
        self.result['disconnected_dns_status'] = self.api('/dns/query?name=ez-direct-' + str(time.time_ns()) + '.example.com&type=TXT').get('Status')
        if not self.direct_mode(self.runtime()):
            raise RuntimeError('direct-only-state-changed-during-probes')
        time.sleep(1)
        self.direct_phase_end = packets.stat().st_size
        self.stage = 'wait-for-usb-reconnect'
        print('步骤 2/2：拔线检查结束。现在重新插回自己的 iPhone USB，保持个人热点开启，等待结果。', flush=True)
        self.wait_usb(True, 120)
        self.stage = 'check-split-recovery'
        self.wait_mode(self.split_matches)
        self.result['automatic_split_recovered'] = True
        self.result['recovery_requests'] = [self.probe(k) for k in ['proxy', 'direct']]
        now = self.runtime()[1]
        self.result['selections_preserved'] = all(now.get(n, {}).get('now') == value for n, value in self.selections.items())
        if not self.split_matches(self.runtime()) or not self.online(self.usb) or not self.online(self.wifi):
            raise RuntimeError('recovery-state-changed-during-probes')
        time.sleep(1)
        self.stop_capture()
        self.record_capture_summary()
        summary = self.result['wifi_packet_counts']
        phase = self.result['direct_only_phase_packet_counts']
        self.result['all_requested_checks_verified'] = (
            all(self.valid_probe(x) for x in self.result['disconnected_direct_requests'] + self.result['recovery_requests'])
            and self.result['disconnected_dns_status'] in (0, 3) and self.result['selections_preserved']
            and summary['remote_on_wifi'] == 0 and summary['unparsed_ip_lines'] == 0
            and phase['direct_on_wifi'] > 0 and phase['dns_on_wifi'] > 0
            and phase['unparsed_ip_lines'] == 0 and self.result['kernel_dropped'] == 0)
        self.write('result.json', self.result)
        print(json.dumps(self.result, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--wifi-is-phone-hotspot', action='store_true', required=True)
    parser.add_argument('--usb', default='en5')
    parser.add_argument('--wifi', default='en0')
    args = parser.parse_args()
    uid = os.getuid() if args.prepare_only else int(os.environ.get('SUDO_UID', '-1'))
    if uid <= 0 or (not args.prepare_only and os.geteuid() != 0):
        parser.error('Use sudo in your own Terminal for capture.')
    if args.usb == args.wifi or any(not re.fullmatch(r'en\d+', x) for x in (args.usb, args.wifi)):
        parser.error('Invalid physical interfaces.')
    root = args.output_dir.resolve(strict=True)
    info = root.stat()
    if root.parent != Path('/private/tmp') or not root.name.startswith('ez-switch-auto-disconnect.') or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('Use a private mktemp directory owned by your user.')
    diagnostic = Diagnostic(uid, root, args.usb, args.wifi)
    try:
        diagnostic.run(args.prepare_only)
        return 0 if args.prepare_only or diagnostic.result['all_requested_checks_verified'] else 1
    except (Exception, KeyboardInterrupt) as error:
        diagnostic.result.update(failed_stage=diagnostic.stage,
                                error_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        print('检查未通过。请保持另一部手机 Wi-Fi，并将自己的 iPhone USB 插回、保持热点开启。本程序未修改 Clash。', flush=True)
        diagnostic.stop_capture()
        diagnostic.record_capture_summary()
        diagnostic.write('result.json', diagnostic.result)
        print(json.dumps(diagnostic.result, ensure_ascii=False), flush=True)
        return 2
    finally:
        diagnostic.stop_capture()


if __name__ == '__main__':
    raise SystemExit(main())
