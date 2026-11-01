"""严格校园直连白名单准入探测的离线单元测试。"""

import io
import json
import socket
import struct
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

try:
    from routing.tools import probe_strict_candidates as module
except ModuleNotFoundError:
    from tools import probe_strict_candidates as module


def dns_reply(identifier, host, addresses, rcode=0):
    """构造一个只含 A 记录的最小 DNS 响应，供解析器测试使用。"""
    question = b''.join(bytes([len(label)]) + label.encode('ascii')
                        for label in host.split('.')) + b'\x00' + struct.pack('!HH', 1, 1)
    answers = b''
    for address in addresses:
        answers += (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) +
                    socket.inet_aton(address))
    header = struct.pack('!HHHHHH', identifier, 0x8180 | rcode, 1, len(addresses), 0, 0)
    return header + question + answers


class AddressFilterTests(unittest.TestCase):
    def test_fake_ip_range_is_rejected(self):
        """198.18.0.0/16 内的地址一律标记为 fake_ip。"""
        for address in ['198.18.0.0', '198.18.0.1', '198.18.255.254']:
            self.assertTrue(module.forbidden_address(address), address)
            self.assertEqual(module.registrable_address_filter(address), 'fake_ip')
        for address in ['198.17.255.255', '8.8.8.8', '223.5.5.5']:
            self.assertFalse(module.forbidden_address(address), address)
            self.assertIsNone(module.registrable_address_filter(address))

    def test_private_loopback_link_local_and_reserved_are_rejected(self):
        """私有、回环、链路本地、组播和保留地址都不可准入。"""
        for address in ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1',
                        '127.0.0.1', '169.254.10.20', '0.0.0.0', '224.0.0.1',
                        '239.255.255.250', '255.255.255.255', '100.64.0.1',
                        '192.0.2.1', '198.19.0.0']:
            self.assertTrue(module.forbidden_address(address), address)
            self.assertEqual(module.registrable_address_filter(address),
                             'private_address', address)

    def test_invalid_address_text_raises_value_error(self):
        """非 IPv4 文本不能静默通过过滤。"""
        with self.assertRaises(ValueError):
            module.forbidden_address('not-an-address')
        with self.assertRaises(ValueError):
            module.registrable_address_filter('2001:db8::1')


class DnsReconcileTests(unittest.TestCase):
    def result(self, resolver, addresses=(), rcode=0, timed_out=False, failed=False):
        """构造一个解析器结果。"""
        return {'resolver': resolver, 'addresses': list(addresses), 'rcode': rcode,
                'timed_out': timed_out, 'failed': failed}

    def test_equal_answers_are_concatenated_in_order_without_duplicates(self):
        """两个解析器答案集合相同时按顺序合并并去重。"""
        merged = module.reconcile_dns([
            self.result('223.5.5.5', ['1.1.1.1', '2.2.2.2']),
            self.result('119.29.29.29', ['2.2.2.2', '1.1.1.1']),
        ])
        self.assertTrue(merged['consistent'])
        self.assertIsNone(merged['error'])
        self.assertEqual(merged['addresses'], ['1.1.1.1', '2.2.2.2'])

    def test_different_answers_are_recorded_as_conflict(self):
        """解析器返回不同 A 记录时继续探测，一致性记为 False 并给出 warning。"""
        merged = module.reconcile_dns([
            self.result('223.5.5.5', ['1.1.1.1']),
            self.result('119.29.29.29', ['1.1.1.2']),
        ])
        self.assertFalse(merged['consistent'])
        self.assertIsNone(merged['error'])
        self.assertEqual(merged['warning'], 'dns_conflict')
        self.assertEqual(merged['addresses'], ['1.1.1.1', '1.1.1.2'])

    def test_missing_answer_on_one_resolver_is_conflict(self):
        """只有一个解析器有 A 记录也算不一致，但地址可用时继续探测。"""
        merged = module.reconcile_dns([
            self.result('223.5.5.5', ['1.1.1.1']),
            self.result('119.29.29.29', []),
        ])
        self.assertFalse(merged['consistent'])
        self.assertIsNone(merged['error'])
        self.assertEqual(merged['warning'], 'dns_conflict')
        self.assertEqual(merged['addresses'], ['1.1.1.1'])

    def test_all_resolvers_without_a_record_is_no_a_record(self):
        """所有解析器都没有 A 记录时判定 no_a_record。"""
        merged = module.reconcile_dns([
            self.result('223.5.5.5', []),
            self.result('119.29.29.29', []),
        ])
        self.assertFalse(merged['consistent'])
        self.assertEqual(merged['error'], 'no_a_record')

    def test_nxdomain_is_classified(self):
        """rcode 为 3 时判定 dns_nxdomain。"""
        merged = module.reconcile_dns([self.result('223.5.5.5', rcode=3)])
        self.assertEqual(merged['error'], 'dns_nxdomain')
        self.assertFalse(merged['consistent'])

    def test_timeout_and_parse_failure_are_dns_timeout(self):
        """超时或解析失败都归入 dns_timeout。"""
        self.assertEqual(module.reconcile_dns([self.result('a', timed_out=True)])['error'],
                         'dns_timeout')
        self.assertEqual(module.reconcile_dns([self.result('a', failed=True)])['error'],
                         'dns_timeout')


class CandidateParseTests(unittest.TestCase):
    def test_object_shape_with_optional_url(self):
        """支持带 candidates 键的对象和可选 url 字段。"""
        parsed = module.parse_candidates({'candidates': [
            {'host': 'Example.COM', 'url': 'https://www.example.com/path'},
            {'host': 'second.example'},
            'third.example',
        ]})
        self.assertEqual([item['host'] for item in parsed],
                         ['example.com', 'second.example', 'third.example'])
        self.assertEqual(parsed[0]['url'], 'https://www.example.com/path')
        self.assertEqual(parsed[1]['url'], 'https://second.example/')

    def test_plain_host_list(self):
        """纯主机列表同样可用，并规范化大小写与末尾点。"""
        parsed = module.parse_candidates(['A.example.', 'b.example'])
        self.assertEqual([item['host'] for item in parsed], ['a.example', 'b.example'])
        self.assertEqual(parsed[0]['url'], 'https://a.example/')

    def test_duplicate_hosts_keep_first_entry(self):
        """重复主机只保留第一次出现的候选，避免重复探测。"""
        parsed = module.parse_candidates([
            {'host': 'a.example', 'url': 'https://a.example/x'},
            {'host': 'A.EXAMPLE'},
        ])
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]['url'], 'https://a.example/x')

    def test_invalid_shapes_raise_value_error(self):
        """结构或主机非法时抛 ValueError，而不是静默跳过。"""
        for value in [None, 'a.example', {'host': 'a.example'},
                      {'candidates': 'a.example'},
                      {'candidates': [{'url': 'https://a.example/'}]},
                      {'candidates': [{'host': 5}]}, {'candidates': ['']},
                      {'candidates': ['http://a.example/']},
                      {'candidates': ['a b.example']},
                      {'candidates': ['1.2.3.4']}, {'candidates': []}]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    module.parse_candidates(value)

    def test_invalid_url_raises_value_error(self):
        """可选 url 必须是 http/https 地址。"""
        for url in ['ftp://a.example/', 'not-a-url', 5]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    module.parse_candidates([{'host': 'a.example', 'url': url}])

    def test_decision_is_normalized_and_optional(self):
        """decision 字段可选，存在时规范化为小写。"""
        parsed = module.parse_candidates({'candidates': [
            {'host': 'a.example', 'decision': ' HOLD '},
            {'host': 'b.example'},
        ]})
        self.assertEqual(parsed[0]['decision'], 'hold')
        self.assertIsNone(parsed[1]['decision'])
        with self.assertRaises(ValueError):
            module.parse_candidates([{'host': 'a.example', 'decision': 3}])


class DecisionSelectionTests(unittest.TestCase):
    def write_candidates(self, directory, items):
        """把混合决策候选写入临时 JSON 文件。"""
        path = Path(directory) / 'candidates.json'
        path.write_text(json.dumps({'candidates': items}), encoding='utf-8')
        return path

    def invoke(self, directory, path, extra=()):
        """在屏蔽接口与探测的前提下调用 main，返回退出码与捕获输出。"""
        snapshot = {'interface': 'en0', 'interface_index': 12,
                    'ipv4': '198.51.100.31', 'ready': True}
        document = {'counts': {'pass': 0, 'fail': 0, 'total': 0,
                               'all_passed': True}}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(module, 'interface_snapshot',
                          return_value=snapshot) as interface_mock, \
                patch.object(module, 'run', return_value=([], document)) as run_mock, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = module.main(['--candidates', str(path),
                                '--outdir', str(directory), *extra])
        return code, stdout.getvalue(), stderr.getvalue(), interface_mock, run_mock

    def mixed(self):
        """构造 pending/hold/reject/无 decision 的混合列表。"""
        return [
            {'host': 'pending.example', 'decision': 'pending'},
            {'host': 'hold.example', 'decision': 'hold'},
            {'host': 'reject.example', 'decision': 'reject'},
            {'host': 'undecided.example'},
            {'host': 'upper.example', 'decision': 'PENDING'},
        ]

    def test_default_selects_pending_and_undecided_only(self):
        """默认只探测 pending 和没有 decision 的条目。"""
        with TemporaryDirectory() as directory:
            path = self.write_candidates(directory, self.mixed())
            code, output, _, interface_mock, run_mock = self.invoke(directory, path)
        self.assertEqual(code, 0)
        selected = run_mock.call_args.args[0]
        self.assertEqual([item['host'] for item in selected],
                         ['pending.example', 'undecided.example', 'upper.example'])
        self.assertIn('候选 5 条，跳过 2 条', output)
        interface_mock.assert_called_once()

    def test_decision_hold_selects_hold_and_undecided(self):
        """--decision hold 只选 hold 与没有 decision 的条目。"""
        with TemporaryDirectory() as directory:
            path = self.write_candidates(directory, self.mixed())
            code, _, _, _, run_mock = self.invoke(
                directory, path, ('--decision', 'hold'))
        self.assertEqual(code, 0)
        selected = run_mock.call_args.args[0]
        self.assertEqual([item['host'] for item in selected],
                         ['hold.example', 'undecided.example'])

    def test_multiple_decisions_are_unioned(self):
        """重复 --decision 取并集，仍排除未请求的 reject。"""
        with TemporaryDirectory() as directory:
            path = self.write_candidates(directory, self.mixed())
            code, _, _, _, run_mock = self.invoke(
                directory, path, ('--decision', 'pending', '--decision', 'hold'))
        self.assertEqual(code, 0)
        self.assertEqual([item['host'] for item in run_mock.call_args.args[0]],
                         ['pending.example', 'hold.example',
                          'undecided.example', 'upper.example'])

    def test_empty_filter_refuses_without_touching_the_interface(self):
        """过滤后为空时退出码 2，且不创建接口或网络套接字。"""
        with TemporaryDirectory() as directory:
            path = self.write_candidates(directory, [
                {'host': 'hold.example', 'decision': 'hold'},
                {'host': 'reject.example', 'decision': 'reject'},
            ])
            code, output, error, interface_mock, run_mock = self.invoke(
                directory, path)
        self.assertEqual(code, 2)
        self.assertIn('候选 2 条，跳过 2 条', output)
        self.assertIn('过滤', error)
        interface_mock.assert_not_called()
        run_mock.assert_not_called()


class DnsReplyTests(unittest.TestCase):
    def test_parser_extracts_a_records_and_rcode(self):
        """DNS 响应解析器只收集 A 记录并保留 rcode。"""
        identifier = 0x1234
        data = dns_reply(identifier, 'prts.wiki', ['27.148.187.109', '183.61.231.36'])
        parsed = module.parse_reply(data, identifier)
        self.assertEqual(parsed['addresses'], ['27.148.187.109', '183.61.231.36'])
        self.assertEqual(parsed['rcode'], 0)
        self.assertFalse(parsed['truncated'])

    def test_parser_rejects_unrelated_identifier_and_short_packet(self):
        """标识不匹配或长度不足的响应必须拒绝。"""
        identifier = 0x1234
        data = dns_reply(identifier, 'a.example', ['1.1.1.1'])
        with self.assertRaises(ValueError):
            module.parse_reply(data, identifier + 1)
        with self.assertRaises(ValueError):
            module.parse_reply(data[:8], identifier)


class SummaryTests(unittest.TestCase):
    def test_counts_and_error_categories(self):
        """汇总统计通过、失败和每个错误类别的数量。"""
        rows = [
            {'host': 'a.example', 'status': 'pass', 'error': None},
            {'host': 'b.example', 'status': 'fail', 'error': 'dns_conflict'},
            {'host': 'c.example', 'status': 'fail', 'error': 'fake_ip'},
            {'host': 'd.example', 'status': 'fail', 'error': 'fake_ip'},
            {'host': 'e.example', 'status': 'pass', 'error': None},
        ]
        summary = module.summarize(rows)
        self.assertEqual(summary['total'], 5)
        self.assertEqual(summary['pass'], 2)
        self.assertEqual(summary['fail'], 3)
        self.assertEqual(summary['error_categories'],
                         {'dns_conflict': 1, 'fake_ip': 2})
        self.assertFalse(summary['all_passed'])

    def test_empty_rows_are_not_all_passed(self):
        """没有结果时不能声称全部通过。"""
        summary = module.summarize([])
        self.assertEqual(summary['total'], 0)
        self.assertFalse(summary['all_passed'])
        self.assertTrue(module.summarize([{'status': 'pass'}])['all_passed'])


class DecisionTests(unittest.TestCase):
    def attempt(self, tcp='connected', tls_ok=False, http_status=None, http_error=False):
        """构造单地址探测结果。"""
        return {'tcp': tcp, 'tls_ok': tls_ok,
                'http_status': http_status, 'http_error': http_error}

    def test_pass_and_fail_decision_table(self):
        """pass/fail 决策表覆盖 DNS、过滤、TLS、HTTP 和 TCP 失败。"""
        cases = [
            ('dns_error_wins', dict(dns_error='dns_conflict',
                                    attempts=[self.attempt(tls_ok=True)]),
             ('fail', 'dns_conflict')),
            ('forbidden_wins', dict(forbidden='fake_ip',
                                    attempts=[self.attempt(tls_ok=True)]),
             ('fail', 'fake_ip')),
            ('tls_success', dict(attempts=[self.attempt(tls_ok=True)]), ('pass', None)),
            ('http_any_status', dict(attempts=[self.attempt(tcp='refused'),
                                              self.attempt(http_status=503)]),
             ('pass', None)),
            ('tcp_refused', dict(attempts=[self.attempt(tcp='refused')]),
             ('fail', 'tcp_refused')),
            ('tcp_timeout', dict(attempts=[self.attempt(tcp='timeout')]),
             ('fail', 'tcp_timeout')),
            ('tls_error', dict(attempts=[self.attempt()]), ('fail', 'tls_error')),
            ('http_error', dict(attempts=[self.attempt(http_error=True)]),
             ('fail', 'http_error')),
            ('interface_down', dict(attempts=[self.attempt(tcp='interface_down')]),
             ('fail', 'interface_down')),
            ('fail_closed_without_attempts', dict(attempts=[]),
             ('fail', 'tcp_timeout')),
        ]
        for name, arguments, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(module.decide(**arguments), expected)

    def test_interface_down_outranks_other_tcp_errors(self):
        """接口中途失效时不能被普通的超时错误掩盖。"""
        attempts = [self.attempt(tcp='interface_down'), self.attempt(tcp='refused')]
        self.assertEqual(module.decide(attempts=attempts), ('fail', 'interface_down'))


class OutputTests(unittest.TestCase):
    def test_journal_appends_and_flushes_each_record(self):
        """JSONL 逐条追加并立即刷新，summary.json 单独写入。"""
        with TemporaryDirectory() as directory:
            first = module.Journal(directory)
            first.emit('begin', interface='en0', selected=1)
            path = Path(directory) / 'requests.jsonl'
            lines = path.read_text(encoding='utf-8').splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])['kind'], 'begin')
            self.assertIn('at', json.loads(lines[0]))
            first.emit('summary', host='a.example', status='pass', error=None)
            first.finish({'counts': {'pass': 1}})
            second = module.Journal(directory)
            second.emit('begin', interface='en0', selected=0)
            second.finish({'counts': {'pass': 0}})
            lines = path.read_text(encoding='utf-8').splitlines()
            self.assertEqual([json.loads(line)['kind'] for line in lines],
                             ['begin', 'summary', 'begin'])
            summary = json.loads((Path(directory) / 'summary.json').read_text(
                encoding='utf-8'))
            self.assertEqual(summary['counts'], {'pass': 0})

    def test_run_writes_method_counts_and_source_sha256(self):
        """summary.json 含方法元数据、计数、候选文件和过滤统计。"""
        with TemporaryDirectory() as directory:
            snapshot = {'interface': 'en0', 'interface_index': 12,
                        'ipv4': '198.51.100.31'}
            source = {'path': '/tmp/candidates.json', 'sha256': 'a' * 64,
                      'limit': 5}
            selection = {'candidate_count': 7,
                         'requested_decisions': ['pending'],
                         'skipped_by_decision': 2}
            rows, document = module.run([], snapshot, 'en0', directory, 3.0,
                                        ['223.5.5.5'], source, selection)
            self.assertEqual(rows, [])
            summary = json.loads((Path(directory) / 'summary.json').read_text(
                encoding='utf-8'))
            self.assertEqual(summary['source']['sha256'], 'a' * 64)
            self.assertEqual(summary['method']['interface'], 'en0')
            self.assertEqual(summary['method']['interface_index'], 12)
            self.assertEqual(summary['method']['resolvers'], ['223.5.5.5'])
            self.assertEqual(summary['method']['timeout_seconds'], 3.0)
            self.assertEqual(summary['requested_decisions'], ['pending'])
            self.assertEqual(summary['skipped_by_decision'], 2)
            self.assertEqual(summary['candidate_count'], 7)
            self.assertEqual(summary['counts']['total'], 0)
            self.assertEqual(summary['results'], [])


if __name__ == '__main__':
    unittest.main()
