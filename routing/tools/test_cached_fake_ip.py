#!/usr/bin/env python3
"""Native converter + isolated Mihomo regression; never touches the live core."""
import argparse
import http.client
import json
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CORE = '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo'
DNS_KEYS = ['nameserver', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver']


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError('socket-closed')
        data += chunk
    return data


def run(tool, interface):
    result = {'scope': 'isolated-native-cached-fake-ip-and-blocked-dns', 'live_clash_modified': False,
              'tun_enabled_in_test': False, 'all_requested_checks_verified': False}
    with tempfile.TemporaryDirectory(prefix='ez-cached-fake-', dir='/private/tmp') as name:
        root = Path(name)
        base = {'interface-name': 'en5', 'tun': {'enable': True}, 'proxies': [
            {'name': 'Node', 'type': 'trojan', 'server': 'example.invalid', 'port': 443,
             'password': 'fixture', 'interface-name': 'en5'},
            {'name': 'EZ-Campus', 'type': 'direct', 'interface-name': 'en0'},
            {'name': 'EZ-USB-DNS', 'type': 'direct', 'interface-name': 'en5'}],
            'proxy-groups': [{'name': 'Proxy', 'type': 'select', 'proxies': ['Node']}],
            'rules': ['DOMAIN-SUFFIX,bilibili.com,EZ-Campus', 'MATCH,Proxy']}
        private_json(root / 'base.json', base)
        mixed, controller, dns = free_port(), free_port(), free_port()
        configurations = {}
        for mode in ['directOnly', 'blocked']:
            decision = {'mode': mode, 'proxyInterface': None,
                        'directInterface': interface if mode == 'directOnly' else None}
            private_json(root / (mode + '-decision.json'), decision)
            subprocess.run([str(tool), '--routing-fixture', str(root / 'base.json'),
                            str(root / (mode + '-decision.json')), str(root / (mode + '.json'))],
                           check=True, capture_output=True, timeout=10)
            cfg = json.loads((root / (mode + '.json')).read_text())
            cfg.update({'mixed-port': mixed, 'external-controller': f'127.0.0.1:{controller}',
                        'external-controller-unix': '', 'allow-lan': False, 'bind-address': '127.0.0.1',
                        'tun': {'enable': False}, 'log-level': 'debug', 'ipv6': False,
                        'profile': {'store-selected': False, 'store-fake-ip': False}})
            if cfg['dns'].get('enable'):
                cfg['dns']['listen'] = f'127.0.0.1:{dns}'
            configurations[mode] = cfg
        config_path = root / 'isolated.json'
        private_json(config_path, configurations['directOnly'])

        def api(method, path, body=None):
            connection = http.client.HTTPConnection('127.0.0.1', controller, timeout=5)
            try:
                connection.request(method, path, None if body is None else json.dumps(body))
                response = connection.getresponse()
                data = response.read()
                if response.status not in (200, 204):
                    raise RuntimeError('isolated-controller-response')
                return data
            finally:
                connection.close()

        def apply(cfg):
            api('PUT', '/configs?force=true', {'payload': json.dumps(cfg)})

        def query(host, kind=1, tcp=False):
            question = b''.join(bytes([len(x)]) + x.encode() for x in host.split('.')) + b'\0'
            message = struct.pack('!HHHHHH', 123, 0x100, 1, 0, 0, 0) + question + struct.pack('!HH', kind, 1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                if tcp:
                    client.connect(('127.0.0.1', dns))
                    client.sendall(struct.pack('!H', len(message)) + message)
                    return exact(client, struct.unpack('!H', exact(client, 2))[0])
                client.sendto(message, ('127.0.0.1', dns))
                return client.recv(4096)

        def cached_https(ip):
            try:
                with socket.create_connection(('127.0.0.1', mixed), timeout=5) as client:
                    client.sendall(b'\x05\x01\x00')
                    if exact(client, 2) != b'\x05\x00':
                        raise RuntimeError('socks-auth')
                    client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(ip) + struct.pack('!H', 443))
                    if exact(client, 10)[1] != 0:
                        return False
                    with ssl.create_default_context().wrap_socket(client, server_hostname='www.bilibili.com') as secure:
                        secure.sendall(b'HEAD / HTTP/1.1\r\nHost: www.bilibili.com\r\nConnection: close\r\n\r\n')
                        response = secure.recv(1024)
                        return response.startswith(b'HTTP/') and 200 <= int(response.split()[1]) < 400
            except (OSError, EOFError):
                return False

        log_path = root / 'core.log'
        with log_path.open('wb') as log:
            process = subprocess.Popen([CORE, '-d', str(root), '-f', str(config_path)], stdout=log, stderr=log)
            try:
                for _ in range(50):
                    try:
                        api('GET', '/configs')
                        break
                    except OSError:
                        time.sleep(.1)
                address = socket.inet_ntoa(query('www.bilibili.com')[-4:])
                result['baseline_cached_ip_https'] = cached_https(address)
                # Observe both potential DNS transport destinations on loopback.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
                    udp.bind(('127.0.0.1', 0))
                    port = udp.getsockname()[1]
                    tcp.bind(('127.0.0.1', port))
                    tcp.listen()
                    blocked = configurations['blocked']
                    result['native_blocked_dns_reject_policy'] = (
                        blocked['dns'].get('enable') is True and all(
                            blocked['dns'].get(k) == ['223.5.5.5#REJECT'] for k in DNS_KEYS))
                    codes = []
                    for index, transport in enumerate(['udp', 'tcp']):
                        for key in DNS_KEYS:
                            blocked['dns'][key] = [f'{transport}://127.0.0.1:{port}#REJECT']
                        apply(blocked)
                        if index == 0:
                            result['cached_https_blocked'] = not cached_https(address)
                        answer = query(f'ez-blocked-{index}.example.com', kind=16, tcp=index == 1)
                        codes.append(struct.unpack('!H', answer[2:4])[0] & 15)
                    result['blocked_dns_rcodes'] = codes
                    result['blocked_dns_upstream_packets'] = len(select.select([udp, tcp], [], [], .2)[0])
                apply(configurations['directOnly'])
                result['same_cached_ip_https_after_recovery'] = cached_https(address)
                result['fake_mapping_missing'] = 'fake DNS record' in log_path.read_text(errors='replace')
                result['all_requested_checks_verified'] = (
                    result['baseline_cached_ip_https'] and result['cached_https_blocked']
                    and result['native_blocked_dns_reject_policy'] and codes == [2, 2]
                    and result['blocked_dns_upstream_packets'] == 0
                    and result['same_cached_ip_https_after_recovery'] and not result['fake_mapping_missing'])
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tool', type=Path, default=ROOT / '.build/debug/EZRoutingTool')
    parser.add_argument('--interface', default='en0')
    args = parser.parse_args()
    try:
        output = run(args.tool, args.interface)
        print(json.dumps(output), flush=True)
        raise SystemExit(0 if output['all_requested_checks_verified'] else 1)
    except Exception as error:
        print(json.dumps({'all_requested_checks_verified': False, 'error_type': type(error).__name__,
                          'live_clash_modified': False}), flush=True)
        raise SystemExit(2)
