"""Representative rule diagnostics through the local Clash entry; no config writes."""
from collections import Counter, defaultdict, deque
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time

from tools.guided_routing_suite import REMOTE, GROUPS, connection_rows, runtime_summary, safe_interface


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def rule_fingerprint(rules):
    # Mihomo updates these counters/timestamps on requests and rule checks.
    # Preserve disabled, order, size, and any unknown fields conservatively.
    statistics = {'hitCount', 'hitAt', 'missCount', 'missAt'}
    normalized = []
    for rule in rules:
        row = dict(rule)
        if isinstance(row.get('extra'), dict):
            row['extra'] = {k: v for k, v in row['extra'].items() if k not in statistics}
        normalized.append(row)
    return fingerprint(normalized)


def public_host(value):
    if not isinstance(value, str) or len(value) > 253:
        return None
    host = value.lower()
    labels = host.split('.')
    if (len(labels) < 2 or not any('a' <= c <= 'z' for c in labels[-1])
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in labels)):
        return None
    if host.endswith(('.local', '.lan', '.internal', '.localhost', '.test', '.example', '.invalid', '.arpa')):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def first_domain_match(rules, host):
    for i, r in enumerate(rules):
        kind, value = r.get('type'), str(r.get('payload', '')).lower()
        if ((kind == 'Domain' and host == value)
                or (kind == 'DomainSuffix' and (host == value or host.endswith('.' + value)))
                or (kind == 'DomainKeyword' and value and value in host)):
            return i
    return None


def policy_kind(name, adapters, visited=frozenset()):
    if not isinstance(name, str) or name in visited or len(visited) >= 32:
        return 'unknown'
    p = adapters.get(name, {})
    kind = p.get('type')
    if kind == 'Direct': return 'direct'
    if kind in REMOTE: return 'proxy'
    if kind in {'Reject', 'RejectDrop'}: return 'reject'
    if kind in GROUPS:
        if isinstance(p.get('now'), str):
            return policy_kind(p['now'], adapters, visited | {name})
        members = p.get('all')
        if isinstance(members, list) and members:
            kinds = {policy_kind(n, adapters, visited | {name}) for n in members}
            if len(kinds) == 1:
                return kinds.pop()
    return 'unknown'


def make_plan(rules, adapters, limit=12):
    buckets, unprobeable, kinds = defaultdict(deque), Counter(), Counter()
    eligible = 0
    for i, r in enumerate(rules):
        kind = policy_kind(r.get('proxy'), adapters)
        kinds[kind] += 1
        host = public_host(r.get('payload')) if r.get('type') in {'Domain', 'DomainSuffix'} else None
        if not host or kind == 'unknown' or first_domain_match(rules, host) != i:
            unprobeable[r.get('type', 'unknown')] += 1
            continue
        eligible += 1
        policy = fingerprint(r.get('proxy'))
        buckets[(kind, r['type'], policy)].append({'host': host, 'rule_index': i,
            'rule_type': r['type'], 'rule_payload': r['payload'], 'policy_hash': policy, 'expected_kind': kind})
    cases, by_kind, families = [], defaultdict(deque), set()
    for key in buckets:
        by_kind[key[0]].append(key)
    while by_kind and len(cases) < max(0, min(limit, 12)):
        for kind in list(by_kind):
            key = by_kind[kind].popleft()
            while buckets[key]:
                case = buckets[key].popleft()
                # A sampling heuristic, not a public-suffix or network-identity claim.
                family = (kind, case['rule_type'], '.'.join(case['host'].split('.')[-2:]))
                if family not in families:
                    families.add(family)
                    cases.append(case)
                    break
            if buckets[key]: by_kind[kind].append(key)
            if not by_kind[kind]: del by_kind[kind]
            if len(cases) >= max(0, min(limit, 12)): break
    return {'cases': cases, 'rule_count': len(rules), 'rule_fingerprint': rule_fingerprint(rules),
            'rule_fingerprint_scope': 'ordered-rules-excluding-extra-hit-miss-counters-and-timestamps',
            'rule_types': dict(Counter(r.get('type', 'unknown') for r in rules)),
            'policy_kinds': dict(kinds), 'eligible_domain_rules': eligible, 'unprobeable_by_type': dict(unprobeable),
            'scope': 'runtime-rules-after-EZ-Switch-transform', 'all_rules_live_tested': False,
            'sampling_family_heuristic': 'last-two-labels-per-kind-and-rule-type-not-public-suffix-identification'}


def find_evidence(rows, previous_ids, host, port, rules, adapters):
    found = []
    for r in rows:
        m, chain = r.get('metadata', {}), r.get('chains')
        if (not isinstance(r.get('id'), str) or r['id'] in previous_ids
                or m.get('sourceIP') != '127.0.0.1' or str(m.get('sourcePort')) != str(port)
                or str(m.get('host', '')).lower() != host or not isinstance(chain, list) or not chain):
            continue
        leaves = []
        for name in chain:
            p = adapters.get(name, {})
            kind = p.get('type')
            if kind in GROUPS: continue
            if kind != 'Direct' and kind not in REMOTE: return None
            interface = safe_interface(p.get('interface'))
            if interface == 'unknown': return None
            leaves.append(('direct' if kind == 'Direct' else 'proxy', interface))
        indices = [i for i, rule in enumerate(rules) if rule.get('type') == r.get('rule')
                   and rule.get('payload', '') == r.get('rulePayload') and rule.get('proxy') in chain]
        if not leaves or len(set(leaves)) != 1 or len(indices) != 1: return None
        i = indices[0]
        found.append({'rule_index': i, 'kind': leaves[0][0], 'interface': leaves[0][1],
                      'policy_kind': policy_kind(rules[i]['proxy'], adapters),
                      'rule_type': rules[i]['type'], 'rule_payload_hash': fingerprint(rules[i].get('payload', '')),
                      'policy_hash': fingerprint(rules[i]['proxy'])})
    if not found or any(row != found[0] for row in found): return None
    return found[0]


def verdict(case, evidence, interface, unchanged):
    if evidence is None: return 'UNKNOWN'
    if evidence['interface'] != interface: return 'FAIL'
    if evidence.get('policy_kind', evidence['kind']) != evidence['kind']: return 'FAIL'
    if not unchanged: return 'UNKNOWN'
    if evidence['rule_index'] != case['rule_index']: return 'OBSERVED'
    return 'PASS' if evidence['kind'] == case['expected_kind'] else 'FAIL'


def adapter_bindings(adapters):
    return {n: {k: p.get(k) for k in ('type', 'interface', 'now', 'all')} for n, p in adapters.items()}


def config_binding(g):
    return {k: g.get(k) for k in ('mode', 'interface-name', 'mixed-port', 'port')} | {'tun': g.get('tun', {}).get('enable')}


def read_header(client, deadline):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError('header-deadline')
        client.settimeout(min(4, remaining))
        chunk = client.recv(1)
        if not chunk: raise OSError('incomplete-header')
        data.extend(chunk)
        if len(data) > 8192: raise ValueError('header-too-large')
    match = re.match(rb'HTTP/1\.[01] ([1-5]\d\d)(?: |\r)', data)
    if not match: raise ValueError('malformed-http-status')
    return int(match[1])


def probe_case(case, rules, adapters, general, interface, read):
    result = {**case, 'status': 'UNKNOWN', 'physical_egress_verified': False,
              'binding_confirmed': False, 'content_response_success': False, 'network_identity_verified': False}
    if case['expected_kind'] == 'reject':
        result.update(status='SKIPPED', reason='拒绝类仅统计规则，不主动请求广告或跟踪目标；不算实机拒绝验收')
        return result
    if public_host(case['host']) != case['host']: raise ValueError('invalid-probe-host')
    c = runtime_summary(general, adapters, rules)
    if (c['mode'] != 'rule' or not c['tun'] or c['unsupported_count'] or c['unsafe_group_count']
            or not c['remote_count'] or c['remote_bindings'] != {interface: c['remote_count']}
            or c['core_interface'] != interface or c['direct_interface'] != interface
            or c['dns_interface'] != interface or not c['reserved_direct_types'] or not c['entry_port']):
        raise ValueError('phone-binding-not-confirmed')
    previous = {r.get('id') for r in connection_rows(read('/connections'))}
    client, evidence = None, None
    start, deadline = time.monotonic(), time.monotonic() + 8
    try:
        client = socket.create_connection(('127.0.0.1', c['entry_port']), timeout=4)
        local_port = client.getsockname()[1]
        host = case['host']
        client.sendall(('CONNECT ' + host + ':443 HTTP/1.1\r\nHost: ' + host + ':443\r\n\r\n').encode('ascii'))
        if read_header(client, deadline) != 200: raise OSError('proxy-connect-not-accepted')
        for _ in range(4):
            evidence = find_evidence(connection_rows(read('/connections')), previous, host, local_port, rules, adapters)
            if evidence: break
            time.sleep(.05)
        result['actual_rule'] = evidence
        if verdict(case, evidence, interface, unchanged=False) == 'FAIL':
            result.update(status='FAIL', reason='已确认接口或策略类别失配；立即停止，不继续 TLS／HEAD')
            return result
        try:
            client.settimeout(max(.001, min(4, deadline - time.monotonic())))
            client = ssl.create_default_context().wrap_socket(client, server_hostname=host)
            client.sendall(('HEAD / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n').encode('ascii'))
            status = read_header(client, deadline)
            result.update(http_status=status, content_response_success=200 <= status < 400, tls_confirmed=True)
        except (OSError, ValueError) as error:
            result.update(request_error_type=type(error).__name__)
        after_adapters = read('/proxies')['proxies']
        after_rules = read('/rules')['rules']
        after_general = read('/configs')
        stability = {'rules': rule_fingerprint(rules) == rule_fingerprint(after_rules),
                     'adapters': adapter_bindings(adapters) == adapter_bindings(after_adapters),
                     'configuration': config_binding(general) == config_binding(after_general)}
        unchanged = all(stability.values())
        result.update(status=verdict(case, evidence, interface, unchanged), rules_and_bindings_unchanged=unchanged,
                      stability_checks=stability,
                      actual_rule=evidence, binding_confirmed=evidence is not None and evidence['interface'] == interface and unchanged)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result.update(error_type=type(error).__name__)
    finally:
        if client: client.close()
        result['milliseconds'] = round((time.monotonic() - start) * 1000)
    return result
