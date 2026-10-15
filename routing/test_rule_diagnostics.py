import json
import unittest


class RuleDiagnosticTests(unittest.TestCase):
    def fixtures(self):
        return ({'EZ-Campus': {'type': 'Direct', 'interface': 'en5'},
                 'private-node-name': {'type': 'Trojan', 'interface': 'en5'},
                 'private-group-name': {'type': 'Selector', 'all': ['private-node-name'], 'now': 'private-node-name'},
                 'REJECT': {'type': 'Reject'}},
                [{'type': 'Domain', 'payload': 'video.service.com', 'proxy': 'EZ-Campus'},
                 {'type': 'DomainSuffix', 'payload': 'service.com', 'proxy': 'private-group-name'},
                 {'type': 'DomainSuffix', 'payload': 'blocked.com', 'proxy': 'REJECT'},
                 {'type': 'DomainKeyword', 'payload': 'keyword', 'proxy': 'private-group-name'},
                 {'type': 'IPCIDR', 'payload': '192.0.2.0/24', 'proxy': 'private-group-name'},
                 {'type': 'Match', 'payload': '', 'proxy': 'private-group-name'}])

    def test_plan_is_derived_from_rules_and_keeps_unprobeable_coverage_visible(self):
        from tools.rule_diagnostics import make_plan
        adapters, rules = self.fixtures()
        plan = make_plan(rules, adapters)
        self.assertEqual({c['host'] for c in plan['cases']}, {'video.service.com', 'service.com', 'blocked.com'})
        self.assertEqual({c['expected_kind'] for c in plan['cases']}, {'direct', 'proxy', 'reject'})
        self.assertEqual(plan['rule_count'], 6)
        self.assertEqual(plan['unprobeable_by_type'], {'DomainKeyword': 1, 'IPCIDR': 1, 'Match': 1})
        output = json.dumps(plan)
        self.assertNotIn('private-node-name', output)
        self.assertNotIn('private-group-name', output)

    def test_earlier_suffix_shadows_exact_domain_and_boundary_is_respected(self):
        from tools.rule_diagnostics import make_plan, first_domain_match
        adapters, _ = self.fixtures()
        rules = [{'type': 'DomainSuffix', 'payload': 'service.com', 'proxy': 'EZ-Campus'},
                 {'type': 'Domain', 'payload': 'video.service.com', 'proxy': 'private-group-name'}]
        self.assertEqual(first_domain_match(rules, 'video.service.com'), 0)
        self.assertIsNone(first_domain_match(rules, 'evilservice.com'))
        self.assertEqual([c['rule_index'] for c in make_plan(rules, adapters)['cases']], [0])

    def test_rule_plan_stays_valid_when_mihomo_hit_and_miss_statistics_change(self):
        from copy import deepcopy
        from tools.rule_diagnostics import make_plan
        adapters, rules = self.fixtures()
        for index, rule in enumerate(rules):
            rule.update(index=index, size=-1, extra={'disabled': False, 'hitCount': 0,
                        'hitAt': '', 'missCount': 0, 'missAt': ''})
        after = deepcopy(rules)
        after[0]['extra'].update(hitCount=1, hitAt='2026-10-11T03:27:36Z')
        after[1]['extra'].update(missCount=4, missAt='2026-10-11T03:27:37Z')
        self.assertEqual(make_plan(rules, adapters)['rule_fingerprint'],
                         make_plan(after, adapters)['rule_fingerprint'])

    def test_rule_plan_invalidates_on_semantic_changes_including_disable_and_unknown_fields(self):
        from copy import deepcopy
        from tools.rule_diagnostics import make_plan
        adapters, rules = self.fixtures()
        rules[0]['extra'] = {'disabled': False, 'hitCount': 0}
        original = make_plan(rules, adapters)['rule_fingerprint']
        mutations = [('type', 'DomainSuffix'), ('payload', 'other.com'),
                     ('proxy', 'private-group-name'), ('size', 5), ('futureMatchOption', True)]
        for key, value in mutations:
            after = deepcopy(rules); after[0][key] = value
            with self.subTest(field=key): self.assertNotEqual(original, make_plan(after, adapters)['rule_fingerprint'])
        for extra in ({'disabled': True, 'hitCount': 0}, {'disabled': False, 'futureMatchOption': True}):
            after = deepcopy(rules); after[0]['extra'] = extra
            with self.subTest(extra=extra): self.assertNotEqual(original, make_plan(after, adapters)['rule_fingerprint'])
        self.assertNotEqual(original, make_plan(list(reversed(rules)), adapters)['rule_fingerprint'])
        self.assertNotEqual(original, make_plan(rules[:-1], adapters)['rule_fingerprint'])

    def test_plan_never_turns_local_or_invalid_names_into_requests(self):
        from tools.rule_diagnostics import public_host
        for host in ('127.0.0.1', '127.1', '0177.0.0.1', 'example.123', 'router.local', 'localhost', 'host.lan', 'x.home.arpa', '*.service.com', 'a.com/path', 'a.com:443', 'a\r\n.com', '-a.com', 'x.invalid'):
            with self.subTest(host=host): self.assertIsNone(public_host(host))
        self.assertEqual(public_host('VIDEO.Service.com'), 'video.service.com')

    def test_policy_cycle_is_unknown_and_not_silently_direct(self):
        from tools.rule_diagnostics import policy_kind
        self.assertEqual(policy_kind('cycle', {'cycle': {'type': 'Selector', 'now': 'cycle'}}), 'unknown')
        self.assertEqual(policy_kind('missing', {}), 'unknown')

    def test_sampling_is_bounded_and_balances_direct_proxy_and_reject(self):
        from tools.rule_diagnostics import make_plan
        adapters, rules = self.fixtures()
        rules = [{'type': 'Domain', 'payload': f'h{i}.service.com', 'proxy': 'EZ-Campus'} for i in range(30)] + rules[1:]
        plan = make_plan(rules, adapters, limit=3)
        self.assertEqual(len(plan['cases']), 3)
        self.assertEqual({c['expected_kind'] for c in plan['cases']}, {'direct', 'proxy', 'reject'})
        self.assertGreater(plan['eligible_domain_rules'], len(plan['cases']))

    def test_many_direct_policy_buckets_do_not_crowd_out_proxy_samples(self):
        from tools.rule_diagnostics import make_plan
        adapters, tail = self.fixtures()
        rules = []
        for i in range(15):
            adapters[f'direct-{i}'] = {'type': 'Direct', 'interface': 'en5'}
            rules.append({'type': 'Domain', 'payload': f'd{i}.service.com', 'proxy': f'direct-{i}'})
        plan = make_plan(rules + tail[1:], adapters, limit=3)
        self.assertEqual({c['expected_kind'] for c in plan['cases']}, {'direct', 'proxy', 'reject'})

    def test_repeated_subdomains_do_not_consume_all_representative_slots(self):
        from tools.rule_diagnostics import make_plan
        adapters, _ = self.fixtures()
        rules = [{'type': 'Domain', 'payload': f'alt{i}.google.com', 'proxy': 'EZ-Campus'} for i in range(20)]
        rules += [{'type': 'Domain', 'payload': 'video.service.com', 'proxy': 'EZ-Campus'}]
        cases = make_plan(rules, adapters, limit=3)['cases']
        self.assertIn('video.service.com', [c['host'] for c in cases])
        self.assertEqual(sum(c['host'].endswith('.google.com') for c in cases), 1)

    def test_connection_requires_host_new_id_source_port_and_actual_rule(self):
        from tools.rule_diagnostics import find_evidence
        adapters, rules = self.fixtures()
        row = {'id': 'new', 'metadata': {'sourceIP': '127.0.0.1', 'sourcePort': '43210', 'host': 'service.com'},
               'chains': ['private-node-name', 'private-group-name'], 'rule': 'DomainSuffix', 'rulePayload': 'service.com'}
        result = find_evidence([row], set(), 'service.com', 43210, rules, adapters)
        self.assertIsNotNone(result)
        self.assertEqual(result['rule_index'], 1)
        self.assertEqual(result['kind'], 'proxy')
        self.assertEqual(result['interface'], 'en5')
        self.assertIsNone(find_evidence([row], {'new'}, 'service.com', 43210, rules, adapters))
        self.assertIsNone(find_evidence([row], set(), 'service.com', 11111, rules, adapters))
        row['rulePayload'] = 'other.com'
        self.assertIsNone(find_evidence([row], set(), 'service.com', 43210, rules, adapters))

    def test_route_verdict_separates_403_from_binding_failure(self):
        from tools.rule_diagnostics import verdict
        case = {'rule_index': 1, 'expected_kind': 'proxy'}
        evidence = {'rule_index': 1, 'kind': 'proxy', 'interface': 'en5'}
        self.assertEqual(verdict(case, evidence, 'en5', unchanged=True), 'PASS')
        self.assertEqual(verdict(case, evidence, 'en5', unchanged=False), 'UNKNOWN')
        evidence['interface'] = 'en0'
        self.assertEqual(verdict(case, evidence, 'en5', unchanged=True), 'FAIL')

    def test_observed_different_rule_does_not_pass_intended_sample(self):
        from tools.rule_diagnostics import verdict
        self.assertEqual(verdict({'rule_index': 2, 'expected_kind': 'proxy'},
                                 {'rule_index': 1, 'kind': 'direct', 'interface': 'en5'},
                                 'en5', unchanged=True), 'OBSERVED')

    def test_null_connections_is_empty_but_malformed_is_not_success(self):
        from tools.guided_routing_suite import connection_rows
        self.assertEqual(connection_rows({'connections': None}), [])
        for value in ({}, {'connections': 0}, {'connections': 'bad'}, {'connections': [None]}):
            with self.subTest(value=value), self.assertRaises(ValueError): connection_rows(value)

    def test_live_probe_skips_reject_without_opening_external_connection(self):
        from tools.rule_diagnostics import probe_case
        from unittest.mock import patch
        with patch('tools.rule_diagnostics.socket.create_connection', side_effect=AssertionError('network must not run')):
            result = probe_case({'expected_kind': 'reject', 'host': 'blocked.com', 'rule_index': 2}, [], {}, {}, 'en5', lambda _: {})
        self.assertEqual(result['status'], 'SKIPPED')
        self.assertFalse(result['physical_egress_verified'])

    def probe_fixture(self, changed=False, wrong_port=False, mismatch=False, after_failure=False, statistics=False):
        from tools.rule_diagnostics import make_plan, probe_case
        from unittest.mock import patch
        adapters, rules = self.fixtures()
        adapters['EZ-USB-DNS'] = {'type': 'Direct', 'interface': 'en5'}
        general = {'mode': 'rule', 'tun': {'enable': True}, 'interface-name': 'en5', 'mixed-port': 7897}
        if mismatch:
            adapters['DIRECT'] = {'type': 'Direct', 'interface': 'en0'}
            rules[1]['proxy'] = 'DIRECT'
        case = next(c for c in make_plan(rules, adapters)['cases'] if c['host'] == 'service.com')
        row = {'id': 'new', 'metadata': {'sourceIP': '127.0.0.1', 'sourcePort': 12345 if wrong_port else 43210, 'host': 'service.com'},
               'chains': ['private-node-name', 'private-group-name'], 'rule': 'DomainSuffix', 'rulePayload': 'service.com'}
        if mismatch: row['chains'] = ['DIRECT']
        class Wire:
            def __init__(self):
                self.bytes = bytearray(b'HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.1 403 Forbidden\r\n\r\n')
                self.sent = []; self.closed = False
            def recv(self, length):
                value = bytes(self.bytes[:length]); del self.bytes[:length]; return value
            def sendall(self, value): self.sent.append(value)
            def getsockname(self): return ('127.0.0.1', 43210)
            def settimeout(self, value): pass
            def close(self): self.closed = True
        wire = Wire()
        class TLS:
            def wrap_socket(self, client, server_hostname): return client
        reads = 0
        def read(path):
            nonlocal reads
            if path == '/connections':
                reads += 1
                return {'connections': None if reads == 1 else [row]}
            if after_failure: raise OSError('fixture-after-read-failure')
            if path == '/configs': return general
            if path == '/proxies': return {'proxies': adapters}
            if path == '/rules':
                from copy import deepcopy
                after = deepcopy(rules)
                if statistics: after[1]['extra']['hitCount'] += 1
                return {'rules': list(reversed(after)) if changed else after}
            raise AssertionError(path)
        if statistics:
            for rule in rules:
                rule['extra'] = {'disabled': False, 'hitCount': 0, 'hitAt': '', 'missCount': 0, 'missAt': ''}
        with patch('tools.rule_diagnostics.socket.create_connection', return_value=wire), \
             patch('tools.rule_diagnostics.ssl.create_default_context', return_value=TLS()):
            result = probe_case(case, rules, adapters, general, 'en5', read)
        return result, wire

    def test_proxy_probe_correlates_real_wire_contract_and_keeps_403_separate(self):
        result, wire = self.probe_fixture()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['http_status'], 403)
        self.assertFalse(result['content_response_success'])
        self.assertTrue(result['binding_confirmed'])
        self.assertTrue(wire.closed)
        self.assertEqual(wire.sent, [b'CONNECT service.com:443 HTTP/1.1\r\nHost: service.com:443\r\n\r\n',
                                     b'HEAD / HTTP/1.1\r\nHost: service.com\r\nConnection: close\r\n\r\n'])
        self.assertNotIn('private-group-name', json.dumps(result))

    def test_rule_change_during_probe_is_unknown(self):
        result, _ = self.probe_fixture(changed=True)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertFalse(result['binding_confirmed'])
        self.assertEqual(result['stability_checks'], {'rules': False, 'adapters': True, 'configuration': True})

    def test_statistics_during_proxy_probe_do_not_erase_correlated_binding(self):
        result, _ = self.probe_fixture(statistics=True)
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['binding_confirmed'])
        self.assertTrue(result['rules_and_bindings_unchanged'])

    def test_uncorrelated_port_does_not_pass_despite_http_response(self):
        result, _ = self.probe_fixture(wrong_port=True)
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(result['http_status'], 403)

    def test_known_binding_mismatch_stops_before_tls_or_head(self):
        result, wire = self.probe_fixture(mismatch=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(wire.sent), 1)
        self.assertTrue(wire.closed)
        self.assertEqual(result['actual_rule']['interface'], 'en0')

    def test_read_failure_cannot_erase_known_binding_mismatch(self):
        result, wire = self.probe_fixture(mismatch=True, after_failure=True)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(wire.sent), 1)
        self.assertEqual(result['actual_rule']['interface'], 'en0')


if __name__ == '__main__':
    unittest.main()
