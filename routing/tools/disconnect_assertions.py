"""Acceptance criteria for the automatic USB disconnect diagnostic."""
import ipaddress
import re


def hotspot_matches(values, interface, nodes, groups, rules):
    general, adapters, actual_rules = values
    builtins = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'GLOBAL', 'COMPATIBLE'}
    reserved = {'EZ-Campus', 'EZ-USB-DNS'}
    types = {'trojan': 'Trojan', 'vmess': 'Vmess', 'vless': 'Vless', 'ss': 'Shadowsocks',
             'ssr': 'ShadowsocksR', 'http': 'Http', 'socks5': 'Socks5', 'snell': 'Snell'}
    return (general.get('mode') == 'rule' and general.get('interface-name') == interface
            and general.get('tun', {}).get('enable') is True
            and set(adapters) - builtins == set(nodes) | set(groups) | reserved
            and all(adapters.get(name, {}).get('type') == 'Direct'
                    and adapters[name].get('interface') == interface for name in reserved)
            and all(node.get('type') in types
                    and adapters.get(name, {}).get('type') == types[node['type']]
                    and adapters[name].get('interface') == interface for name, node in nodes.items())
            and all(adapters.get(name, {}).get('type') in {'Selector', 'URLTest', 'Fallback', 'LoadBalance'}
                    and adapters[name].get('all') == members
                    and set(members) <= set(nodes) | set(groups) | {'REJECT', 'REJECT-DROP'}
                    for name, members in groups.items())
            and stable_rules(actual_rules) == stable_rules(rules))


def registered_wifi_checks_pass(result, usb, wifi):
    required = ['baseline_verified', 'automatic_wifi_hotspot_verified', 'wifi_requests_verified',
                'automatic_usb_priority_recovered', 'recovery_requests_verified', 'selections_preserved',
                'registration_unchanged', 'wifi_network_unchanged']
    if not all(result.get(key) is True for key in required) or result.get('wifi_dns_status') not in (0, 3) or result.get('kernel_dropped') != 0:
        return False
    phases = result.get('phase_packet_counts', {})
    for phase, expected, other in [('wifi_only', wifi, usb), ('usb_recovery', usb, wifi)]:
        chosen = phases.get(phase, {}).get(expected, {})
        unused = phases.get(phase, {}).get(other, {})
        if (any(chosen.get(key, 0) <= 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or any(unused.get(key) != 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or chosen.get('unparsed_ip_lines') != 0 or unused.get('unparsed_ip_lines') != 0):
            return False
    return result.get('recovery_dns_status') in (0, 3)


def wifi_switch_checks_pass(result, usb, wifi):
    """Accept specified post-confirmation/settled probes, never the unobserved switch boundary."""
    required = ['baseline_verified', 'registered_wifi_verified', 'unregistered_confirmed',
                'automatic_direct_only_verified', 'unregistered_direct_requests_verified',
                'registered_return_confirmed', 'registered_return_verified',
                'usb_recovery_verified', 'registration_unchanged', 'selections_preserved']
    if not all(result.get(key) is True for key in required) or result.get('kernel_dropped') != 0:
        return False
    phases = result.get('phase_packet_counts', {})
    for phase, expected, other in [('registered_wifi', wifi, usb),
                                   ('unregistered_after_confirmation', wifi, usb),
                                   ('registered_return', wifi, usb), ('usb_recovery', usb, wifi)]:
        chosen, unused = phases.get(phase, {}).get(expected, {}), phases.get(phase, {}).get(other, {})
        dns_key = 'unregistered_dns_status' if phase == 'unregistered_after_confirmation' else phase + '_dns_status'
        if (result.get(dns_key) not in (0, 3)
                or any(chosen.get(key, 0) <= 0 for key in ['direct_packets', 'dns_packets'])
                or any(unused.get(key) != 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or chosen.get('unparsed_ip_lines') != 0 or unused.get('unparsed_ip_lines') != 0):
            return False
        if phase == 'unregistered_after_confirmation':
            if chosen.get('remote_packets') != 0:
                return False
        elif chosen.get('remote_packets', 0) <= 0:
            return False
    return True


def registration_checks_pass(result, usb, wifi):
    required = ['baseline_verified', 'registered_wifi_verified', 'removal_confirmed',
                'registration_removed_verified', 'automatic_direct_only_verified',
                'revoked_direct_requests_verified', 'restoration_confirmed',
                'registration_content_restored', 'registered_return_verified',
                'usb_recovery_verified', 'wifi_addresses_unchanged', 'selections_preserved']
    if not all(result.get(key) is True for key in required) or result.get('kernel_dropped') != 0:
        return False
    phases = result.get('phase_packet_counts', {})
    for phase, expected, other in [('registered_wifi', wifi, usb),
                                   ('revoked_after_confirmation', wifi, usb),
                                   ('registered_return', wifi, usb), ('usb_recovery', usb, wifi)]:
        chosen, unused = phases.get(phase, {}).get(expected, {}), phases.get(phase, {}).get(other, {})
        dns_key = 'revoked_dns_status' if phase == 'revoked_after_confirmation' else phase + '_dns_status'
        if (result.get(dns_key) not in (0, 3)
                or any(chosen.get(key, 0) <= 0 for key in ['direct_packets', 'dns_packets'])
                or any(unused.get(key) != 0 for key in ['remote_packets', 'direct_packets', 'dns_packets'])
                or chosen.get('unparsed_ip_lines') != 0 or unused.get('unparsed_ip_lines') != 0):
            return False
        if phase == 'revoked_after_confirmation':
            if chosen.get('remote_packets') != 0:
                return False
        elif chosen.get('remote_packets', 0) <= 0:
            return False
    return True


def stable_rules(rules):
    """Preserve route/disabled state while excluding volatile API counters."""
    counters = {'hitAt', 'hitCount', 'missAt', 'missCount'}
    result = []
    for rule in rules:
        item = dict(rule)
        if isinstance(item.get('extra'), dict):
            item['extra'] = {key: value for key, value in item['extra'].items() if key not in counters}
        result.append(item)
    return result


def direct_only_matches(general, adapters, rules, wifi):
    builtin_types = {'DIRECT': 'Direct', 'REJECT': 'Reject', 'REJECT-DROP': 'RejectDrop',
                     'PASS': 'Pass', 'PASS-RULE': 'PassRule', 'COMPATIBLE': 'Compatible',
                     'GLOBAL': 'Selector'}
    reserved = {'EZ-Campus', 'EZ-USB-DNS'}
    allowed = set(builtin_types) | reserved
    return (general.get('mode') == 'direct' and general.get('interface-name') == wifi
            and general.get('tun', {}).get('enable') is True
            and set(adapters) <= allowed
            and all(adapters.get(n, {}).get('type') == 'Direct'
                    and adapters.get(n, {}).get('interface') == wifi for n in reserved)
            and all(n not in adapters or adapters[n].get('type') == t
                    for n, t in builtin_types.items())
            and set(adapters.get('GLOBAL', {}).get('all', [])) <= allowed
            and len(rules) == 1 and rules[0].get('type') == 'Match'
            and rules[0].get('payload', '') == '' and rules[0].get('proxy') == 'EZ-Campus')


def packet_summary(lines, remote_targets, direct_targets, wifi):
    result = {'remote_on_wifi': 0, 'direct_on_wifi': 0, 'dns_on_wifi': 0,
              'parsed_ip_lines': 0, 'unparsed_ip_lines': 0}
    for line in lines:
        if not re.search(r'\b' + re.escape(wifi) + r'\b', line):
            continue
        match = re.search(r'\bIP6? (\S+) > (\S+): ', line)
        if match is None:
            result['unparsed_ip_lines'] += bool(re.search(r'\bIP6?\b', line))
            continue
        try:
            endpoints = set()
            for value in (match[1], match[2]):
                address, port = value.rsplit('.', 1)
                endpoints.add((str(ipaddress.ip_address(address.split('%')[0])), int(port)))
        except ValueError:
            result['unparsed_ip_lines'] += 1
            continue
        result['parsed_ip_lines'] += 1
        result['remote_on_wifi'] += bool(endpoints & remote_targets)
        result['direct_on_wifi'] += bool(endpoints & direct_targets)
        result['dns_on_wifi'] += any(port == 53 for _, port in endpoints)
    return result
