#!/usr/bin/env python3
"""Bounded, read-only local diagnostics survive a temporary internet outage.

Stores interface IPv4/subnets, routes, DNS and aggregate controller state.
Does not store SSIDs, MAC addresses, node labels, credentials or visited sites.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_active import UnixHTTP


def summarize_interface(text):
    addresses, subnets = [], []
    for address, mask in re.findall(r'\binet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+|[\d.]+)', text):
        try:
            ip = ipaddress.IPv4Address(address)
            if ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                continue
            netmask = str(ipaddress.IPv4Address(int(mask, 16))) if mask.startswith('0x') else mask
            network = ipaddress.IPv4Network(f'{address}/{netmask}', strict=False)
            addresses.append(address); subnets.append(str(network))
        except ValueError:
            continue
    return {'active': bool(re.search(r'\bstatus:\s*active\b', text)),
            'ipv4': addresses, 'subnets': subnets}


def subnet_overlap(first, second):
    return any(ipaddress.ip_network(a).overlaps(ipaddress.ip_network(b)) for a in first for b in second)


def summarize_controller(config, proxies, connections, usb):
    builtin = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'GLOBAL', 'COMPATIBLE'}
    types = {'Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay'}
    remote, groups = {}, []
    for name, value in proxies.items():
        if name in builtin or name in {'EZ-Campus', 'EZ-USB-DNS'}:
            continue
        if name == 'PASS-RULE' and value.get('type') == 'PassRule':
            continue
        if value.get('type') in types:
            groups.append(value)
        elif value.get('type') != 'Direct':
            remote[name] = value
    dangerous = (builtin | {'PASS-RULE', 'EZ-Campus', 'EZ-USB-DNS'}) - {'REJECT', 'REJECT-DROP'}
    return {'readable': True, 'mode': config.get('mode'), 'core_interface': config.get('interface-name'),
            'tun_enabled': bool(config.get('tun', {}).get('enable')),
            'remote_node_count': len(remote),
            'remote_nodes_outside_usb': sum(p.get('interface') != usb for p in remote.values()),
            'groups_with_direct_fallback': sum(bool(set(g.get('all', [])) & dangerous) for g in groups),
            'campus_interface': proxies.get('EZ-Campus', {}).get('interface'),
            'dns_interface': proxies.get('EZ-USB-DNS', {}).get('interface'),
            'connection_count': len(connections.get('connections', [])),
            'proxy_connection_count': sum(bool(set(c.get('chains', [])) & set(remote))
                                          for c in connections.get('connections', []))}


def read_command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=4)
    return result.stdout if result.returncode == 0 else None


def route(interface=None):
    args = ['/sbin/route', '-n', 'get']
    if interface:
        args += ['-ifscope', interface]
    args.append('default')
    value = read_command(args)
    if value is None:
        return {'readable': False}
    result = {'readable': True}
    for key in ['interface', 'gateway']:
        match = re.search(r'^\s*' + key + r':\s*(\S+)', value, re.MULTILINE)
        if match:
            result[key] = match.group(1)
    return result


def controller(usb):
    endpoint = f'/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock'
    values = []
    for path in ['/configs', '/proxies', '/connections']:
        connection = UnixHTTP(endpoint)
        try:
            connection.request('GET', path, headers={'Host': 'localhost'})
            response = connection.getresponse()
            if response.status != 200:
                return {'readable': False, 'http_status': response.status}
            values.append(json.loads(response.read()))
        finally:
            connection.close()
    return summarize_controller(values[0], values[1].get('proxies', {}), values[2], usb)


def snapshot(usb, wifi):
    result = {'time_utc': datetime.now(timezone.utc).isoformat(), 'live_clash_modified': False}
    interfaces = {}
    for name in [usb, wifi]:
        try:
            value = read_command(['/sbin/ifconfig', name])
            interfaces[name] = summarize_interface(value or '')
            interfaces[name]['readable'] = value is not None
        except Exception as error:
            interfaces[name] = {'readable': False, 'error_type': type(error).__name__}
    result['interfaces'] = interfaces
    result['phone_subnet_overlap'] = subnet_overlap(interfaces[usb].get('subnets', []),
                                                    interfaces[wifi].get('subnets', []))
    for key, interface in [('default_route', None), ('usb_route', usb), ('wifi_route', wifi)]:
        try:
            result[key] = route(interface)
        except Exception as error:
            result[key] = {'readable': False, 'error_type': type(error).__name__}
    try:
        dns = read_command(['/usr/sbin/scutil', '--dns'])
        result['system_dns_addresses'] = sorted(set(re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', dns or '')))
        manual = read_command(['/usr/sbin/networksetup', '-getdnsservers', 'Wi-Fi'])
        result['wifi_manual_dns'] = [line for line in (manual or '').splitlines()
                                     if re.fullmatch(r'[0-9a-fA-F:.]+', line)]
    except Exception as error:
        result['dns_error_type'] = type(error).__name__
    try:
        result['clash'] = controller(usb)
    except Exception as error:
        result['clash'] = {'readable': False, 'error_type': type(error).__name__}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--duration', type=int, default=180)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--usb', default='en5')
    parser.add_argument('--wifi', default='en0')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.duration <= 900 or not 1 <= args.interval <= 10 or args.usb == args.wifi or any(
            not re.fullmatch(r'en\d+', name) for name in [args.usb, args.wifi]):
        parser.error('invalid duration, interval or interfaces')
    # Exclusive creation prevents overwriting or following an existing symlink.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGINT, stop); signal.signal(signal.SIGTERM, stop)
    with os.fdopen(fd, 'w') as log:
        deadline = time.monotonic() + args.duration
        count = 0
        while not stopped:
            log.write(json.dumps(snapshot(args.usb, args.wifi), ensure_ascii=False) + '\n')
            log.flush(); count += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(args.interval, remaining))
    print(json.dumps({'snapshots_saved': count, 'live_clash_modified': False}))


if __name__ == '__main__':
    main()
