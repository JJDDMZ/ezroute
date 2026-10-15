#!/usr/bin/env python3
"""Read-only audit; no credentials or node labels are printed."""
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

# The lab host is the one deliberate IP exception. RoutingConfiguration.make
# injects it ahead of the subscription rules so phone-only modes can REJECT it.
# Every other IP, process, port or network rule that authorizes the campus
# outlet is still a problem.
LAB_EXCEPTION = ('IPCIDR', '192.0.2.10/32')

def audit(generated, runtime, proxies, rules):
    problems = []
    if runtime.get('mode') != 'rule':
        problems.append('mode-is-not-rule')
    if runtime.get('interface-name') != 'en5':
        problems.append('core-not-bound-to-usb')
    if proxies.get('EZ-Campus', {}).get('interface') != 'en0':
        problems.append('campus-interface-mismatch')
    if proxies.get('EZ-USB-DNS', {}).get('interface') != 'en5':
        problems.append('dns-interface-mismatch')
    if any(proxies.get(name, {}).get('type') != 'Direct' for name in ['EZ-Campus', 'EZ-USB-DNS']):
        problems.append('reserved-policy-is-not-direct')
    builtins = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'GLOBAL', 'COMPATIBLE'}
    groups = {'Selector', 'URLTest', 'Fallback', 'LoadBalance', 'Relay'}
    for name, proxy in proxies.items():
        if name == 'PASS-RULE' and proxy.get('type') == 'PassRule':
            continue
        if name in builtins or name in {'EZ-Campus', 'EZ-USB-DNS'}:
            continue
        if proxy.get('type') in groups:
            if any(x in {'DIRECT', 'PASS', 'PASS-RULE', 'COMPATIBLE', 'GLOBAL', 'EZ-Campus', 'EZ-USB-DNS'}
                   for x in proxy.get('all', [])):
                problems.append('unsafe-group-member')
        else:
            if proxy.get('type') == 'Direct':
                problems.append('unexpected-direct-policy')
            if proxy.get('interface') != 'en5':
                problems.append('remote-node-not-bound-to-usb')
    if not rules or any(r.get('proxy') in {'DIRECT', 'PASS', 'PASS-RULE', 'GLOBAL', 'COMPATIBLE', 'EZ-USB-DNS'}
                        for r in rules):
        problems.append('unsafe-rule-target')
    if any(r.get('proxy') == 'EZ-Campus' and r.get('type') not in
           {'Domain', 'DomainSuffix', 'DomainKeyword', 'GeoSite'}
           and (r.get('type'), r.get('payload')) != LAB_EXCEPTION for r in rules):
        problems.append('unsafe-campus-rule')
    sniffer = generated.get('sniffer', {})
    if runtime.get('tun', {}).get('enable') and (
            not sniffer.get('enable') or not sniffer.get('parse-pure-ip') or
            any(443 not in sniffer.get('sniff', {}).get(protocol, {}).get('ports', [])
                for protocol in ['TLS', 'QUIC'])):
        problems.append('domain-identification-not-enabled')
    dns = generated.get('dns', {})
    keys = ['nameserver', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver']
    if (not dns.get('enable') or dns.get('ipv6') is True or
        any(not dns.get(k) or not all(v.endswith('#EZ-USB-DNS') for v in dns[k]) for k in keys) or
        any(dns.get(k) for k in ['nameserver-policy', 'proxy-server-nameserver-policy', 'fallback'])):
        problems.append('dns-not-bound-to-usb')
    return sorted(set(problems))


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(self.host)


def main():
    base = Path.home() / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
    try:
        raw = subprocess.run(
            ['/usr/bin/ruby', '-ryaml', '-rjson', '-e',
             'puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))',
             str(base / 'clash-verge.yaml')], check=True, capture_output=True).stdout
        generated = json.loads(raw)
        service = Path(f'/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock')
        endpoint = str(service) if service.exists() else generated.get('external-controller-unix')
        results = []
        for path in ['/configs', '/proxies', '/rules']:
            conn = UnixHTTP(endpoint)
            conn.request('GET', path, headers={
                'Host': 'localhost', 'Authorization': 'Bearer ' + generated.get('secret', '')})
            response = conn.getresponse()
            if response.status != 200:
                raise RuntimeError('controller-response')
            results.append(json.loads(response.read()))
            conn.close()
        runtime, proxies, rules = results
        problems = audit(generated, runtime, proxies.get('proxies', {}), rules.get('rules', []))
        routing_problems = [p for p in problems if p != 'dns-not-bound-to-usb']
        print(json.dumps({'runtime_routing_verified': not routing_problems,
                          'generated_dns_verified': 'dns-not-bound-to-usb' not in problems,
                          'generated_sniffer_verified': 'domain-identification-not-enabled' not in problems,
                          'runtime_dns_verified': False,
                          'problems': problems,
                          'scope': 'tun' if runtime.get('tun', {}).get('enable') else 'system-proxy',
                          'dual_network_test_completed': False}, ensure_ascii=False))
        return 1 if problems else 0
    except Exception as error:
        print(json.dumps({'runtime_routing_verified': False, 'runtime_dns_verified': False,
                          'error_type': type(error).__name__}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
