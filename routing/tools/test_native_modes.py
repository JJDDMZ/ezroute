#!/usr/bin/env python3
"""Exercise the Swift converter with private copies and isolated Mihomo instances.

No live controller calls, TUN changes, system DNS writes or network switching.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
APP_DATA = Path.home() / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
CORE = Path('/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo')


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=30, **kwargs)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out, ensure_ascii=False)


def redacted_validation_error(result, configuration):
    strings = []
    def collect(value):
        if isinstance(value, str) and len(value) >= 3:
            strings.append(value)
        elif isinstance(value, dict):
            for item in value.values(): collect(item)
        elif isinstance(value, list):
            for item in value: collect(item)
    collect(configuration)
    message = (result.stdout + result.stderr).decode(errors='replace')
    for value in sorted(set(strings), key=len, reverse=True):
        message = message.replace(value, '[redacted]')
    return message[-1600:]


def run(args):
    source = command(['/usr/bin/ruby', '-ryaml', '-rjson', '-e',
                      'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))',
                      str(APP_DATA / 'clash-verge.yaml')])
    if source.returncode:
        raise RuntimeError('generated-configuration-unreadable')
    base = json.loads(source.stdout)
    with tempfile.TemporaryDirectory(prefix='ez-native-modes-', dir='/private/tmp') as name:
        directory = Path(name)
        core_data = directory / 'core-data'
        core_data.mkdir(mode=0o700)
        for resource in APP_DATA.iterdir():
            if resource.is_file() and resource.suffix.lower() in {'.dat', '.mmdb', '.metadb'}:
                shutil.copy2(resource, core_data / resource.name)
        input_path = directory / 'base.json'
        private_json(input_path, base)
        modes = [
            ('split', args.usb, args.wifi),
            ('usbHotspot', args.usb, args.usb),
            ('wifiHotspot', args.wifi, args.wifi),
            ('directOnly', None, args.usb),  # Test direct semantics on the currently usable USB.
            ('blocked', None, None),
            ('usbHotspot', 'en999', 'en999'),
        ]
        for index, (mode, proxy, direct) in enumerate(modes):
            decision = directory / f'decision-{index}.json'
            output = directory / f'output-{index}.json'
            private_json(decision, {'mode': mode, 'proxyInterface': proxy, 'directInterface': direct})
            converted = command([str(args.tool), '--routing-fixture', str(input_path), str(decision), str(output)])
            if converted.returncode:
                raise RuntimeError('native-conversion-failed')
            # Test exactly the Swift-emitted bytes before Python normalizes them.
            # Foundation's default slash escaping is valid JSON but invalid YAML.
            original_validation = command([str(CORE), '-t', '-d', str(core_data), '-f', str(output)])
            if original_validation.returncode:
                raise RuntimeError('native-payload-validation-failed')
            config = json.loads(output.read_text())
            remote_count = sum(p['type'] != 'direct' for p in config['proxies'])
            if mode in {'directOnly', 'blocked'}:
                assert remote_count == 0 and not config['proxy-groups']
            else:
                assert all(p['interface-name'] == proxy for p in config['proxies'] if p['type'] != 'direct')
            port = free_port()
            config.update({'tun': {'enable': False}, 'mixed-port': port, 'port': 0,
                           'socks-port': 0, 'redir-port': 0, 'tproxy-port': 0,
                           'external-controller': '', 'external-controller-unix': '',
                           'external-controller-tls': '', 'allow-lan': False,
                           'profile': {'store-selected': False, 'store-fake-ip': False},
                           'geodata-mode': False, 'geo-auto-update': False, 'log-level': 'info'})
            if config.get('dns', {}).get('enable'):
                config['dns']['listen'] = '127.0.0.1:0'
            # Preserve groups but suppress background health checks in isolated tests.
            for group in config['proxy-groups']:
                group['lazy'] = True
            isolated = directory / f'isolated-{index}.json'
            private_json(isolated, config)
            validation = command([str(CORE), '-t', '-d', str(core_data), '-f', str(isolated)])
            if validation.returncode:
                print(json.dumps({'core_validation_error': redacted_validation_error(validation, config)}), flush=True)
                raise RuntimeError('isolated-core-validation-failed')
            outcome = {'mode': mode, 'config_valid': True, 'remote_node_count': remote_count,
                       'test_outlet': proxy or direct, 'live_clash_modified': False, 'native_payload_valid': True}
            # Wi-Fi and split modes are syntax checks while Wi-Fi is offline.
            if not args.syntax_only and (mode == 'directOnly' or proxy == 'en999' or mode == 'blocked'):
                log_path = directory / f'log-{index}'
                fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as log:
                    process = subprocess.Popen([str(CORE), '-d', str(core_data), '-f', str(isolated)],
                                               stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 10
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise RuntimeError('isolated-core-stopped')
                            with socket.socket() as probe:
                                probe.settimeout(0.1)
                                if probe.connect_ex(('127.0.0.1', port)) == 0:
                                    break
                            time.sleep(0.1)
                        result = command(['/usr/bin/curl', '--silent', '--noproxy', '', '--max-time', '8',
                                          '--proxy', f'http://127.0.0.1:{port}', '-o', '/dev/null',
                                          '-w', '%{http_code}', 'https://www.apple.com.cn/'])
                        logs = log_path.read_text(errors='replace')
                        if mode == 'directOnly':
                            assert result.returncode == 0 and result.stdout == b'200'
                            assert 'using DIRECT' in logs
                            outcome['direct_http_status'] = 200
                        else:
                            assert result.returncode != 0
                            outcome['request_failed_as_required'] = True
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait(timeout=3)
            print(json.dumps(outcome), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tool', type=Path, default=ROOT / '.build/out/Products/Debug/EZRoutingTool')
    parser.add_argument('--syntax-only', action='store_true', help='Only parse configurations; do not start cores or send requests')
    parser.add_argument('--usb', default='en5')
    parser.add_argument('--wifi', default='en0')
    options = parser.parse_args()
    try:
        run(options)
    except Exception as error:
        # Do not expose parser/core errors containing subscription values.
        known = {'generated-configuration-unreadable', 'native-conversion-failed',
                 'isolated-core-validation-failed', 'isolated-core-stopped', 'native-payload-validation-failed'}
        code = str(error) if isinstance(error, RuntimeError) and str(error) in known else 'test-failed'
        print(json.dumps({'isolated_test_passed': False, 'error_type': type(error).__name__, 'code': code}), flush=True)
        raise SystemExit(1)
