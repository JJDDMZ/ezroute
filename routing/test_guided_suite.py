import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.guided_routing_suite import (Suite, StopSuite, PLAN, main, owned_app_pids,
                                       phone_mode, runtime_summary, sleep_events, sleep_diagnostics, wifi_interface)


def fixture():
    adapters = {'EZ-Campus': {'type': 'Direct', 'interface': 'en5'},
                'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en5'},
                'secret-node': {'type': 'Trojan', 'interface': 'en5'},
                'secret-group': {'type': 'Selector', 'all': ['secret-node']}}
    general = {'mode': 'rule', 'tun': {'enable': True}, 'interface-name': 'en5', 'mixed-port': 7890}
    return general, adapters, [{'type': 'Match', 'proxy': 'secret-group'}]


def phone_snapshot():
    return {'snapshot_complete': True, 'controller': runtime_summary(*fixture()), 'auto_routing': True,
            'app_count': 1, 'selection_preserved': True, 'registration_preserved': True}


class GuidedSuiteTests(unittest.TestCase):
    def test_plan_has_chinese_operations_and_never_touches_network(self):
        with patch('sys.stdout', new=io.StringIO()) as output, patch('tools.guided_routing_suite.command') as cmd, patch('tools.guided_routing_suite.api') as api:
            self.assertEqual(main(['--plan']), 0)
        self.assertIn('拔掉 USB', output.getvalue())
        self.assertIn('恢复方法', output.getvalue())
        self.assertEqual(len(PLAN), 14)
        cmd.assert_not_called(); api.assert_not_called()

    def test_noninteractive_execution_refuses_before_actions(self):
        with patch('sys.stdin.isatty', return_value=False), patch('sys.stderr', new=io.StringIO()), patch('tools.guided_routing_suite.command') as cmd:
            with self.assertRaises(SystemExit) as result:
                main([])
        self.assertEqual(result.exception.code, 2)
        cmd.assert_not_called()

    def test_pid_selection_requires_exact_uid_and_installed_executable(self):
        text = '10 501 /Users/a/Applications/EZSwitch.app/Contents/MacOS/EZSwitch\n11 0 /Users/a/Applications/EZSwitch.app/Contents/MacOS/EZSwitch\n12 501 /tmp/EZSwitch.app/Contents/MacOS/EZSwitch\n13 501 /Users/a/Applications/EZSwitch.app/Contents/MacOS/EZSwitch --arg\n'
        self.assertEqual(owned_app_pids(text, 501, Path('/Users/a/Applications/EZSwitch.app/Contents/MacOS/EZSwitch')), [10])

    def test_controller_summary_does_not_include_node_or_group_names(self):
        text = json.dumps(runtime_summary(*fixture()))
        self.assertNotIn('secret-node', text); self.assertNotIn('secret-group', text)

    def test_phone_mode_rejects_fallback_and_wrong_interface(self):
        s = phone_snapshot()
        self.assertTrue(phone_mode(s, 'en5'))
        s['controller']['unsafe_group_count'] = 1
        self.assertFalse(phone_mode(s, 'en5'))
        self.assertFalse(phone_mode(phone_snapshot(), 'en0'))

    def test_partial_snapshot_cannot_authorize_phone_mode(self):
        s = phone_snapshot(); s['snapshot_complete'] = False
        self.assertFalse(phone_mode(s, 'en5'))

    def test_phone_guard_rejects_missing_extra_interface_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0'); suite.confirmed_phone = True
            try:
                self.assertFalse(suite.phone_guard({'usb': {'online': True}, 'wifi_power_off': True}))
            finally:
                suite.finish()

    def test_chinese_prefix_does_not_truncate_site_results(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0')
            suite.say('中文动作与恢复说明' * 100)
            def record(step, cwd, transcript):
                transcript.write(json.dumps({'event': 'site-result', 'result': {'site': 'fixture', 'configuration_binding_confirmed': True, 'strategy': 'proxy'}}, ensure_ascii=False) + '\n')
                return {'status': 'PASS'}
            try:
                with patch.object(suite, 'baseline'), patch('tools.guided_routing_suite.run_step', side_effect=record):
                    suite.websites('fixture-sites')
                self.assertEqual(len(suite.results[-1]['sites']), 1)
            finally:
                suite.finish()

    def test_chinese_prefix_cannot_hide_binding_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0'); suite.say('恢复：插回自己的手机。' * 100)
            def record(step, cwd, transcript):
                transcript.write(json.dumps({'event': 'site-result', 'result': {'site': 'fixture', 'configuration_binding_confirmed': False, 'strategy': 'proxy'}}) + '\n')
                return {'status': 'FAIL'}
            try:
                with patch.object(suite, 'baseline'), patch('tools.guided_routing_suite.run_step', side_effect=record):
                    with self.assertRaises(StopSuite):
                        suite.websites('fixture-sites')
            finally:
                suite.finish()

    def test_rule_samples_keep_403_separate_and_save_the_generated_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0')
            _, adapters, _ = fixture()
            rules = [{'type': 'Domain', 'payload': 'service.com', 'proxy': 'secret-node'}]
            def read(path):
                return {'rules': rules} if path == '/rules' else {'proxies': adapters} if path == '/proxies' else {}
            try:
                with patch.object(suite, 'baseline'), patch('tools.guided_routing_suite.api', side_effect=read), \
                     patch('tools.rule_diagnostics.probe_case', return_value={'status': 'PASS', 'http_status': 403, 'content_response_success': False}):
                    suite.rule_tests('G02-rules')
                self.assertEqual(suite.results[0]['status'], 'PASS')
                self.assertEqual(suite.results[0]['http_status'], 403)
                self.assertFalse(suite.results[0]['content_response_success'])
                plan = json.loads(Path(directory, 'rule-plan.json').read_text())
                self.assertEqual(plan['cases'][0]['host'], 'service.com')
            finally:
                suite.finish()

    def test_rule_binding_failure_stops_remaining_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0')
            _, adapters, _ = fixture()
            rules = [{'type': 'Domain', 'payload': h, 'proxy': 'secret-node'} for h in ('service.com', 'other.com')]
            def read(path):
                return {'rules': rules} if path == '/rules' else {'proxies': adapters} if path == '/proxies' else {}
            try:
                with patch.object(suite, 'baseline'), patch('tools.guided_routing_suite.api', side_effect=read), \
                     patch('tools.rule_diagnostics.probe_case', return_value={'status': 'FAIL', 'actual_rule': {'interface': 'en0'}}):
                    with self.assertRaises(StopSuite): suite.rule_tests('G02-rules')
                self.assertEqual(len(suite.results), 1)
                self.assertEqual(suite.results[0]['status'], 'FAIL')
            finally:
                suite.finish()

    def test_rule_statistics_changes_do_not_stop_next_sample(self):
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0')
            _, adapters, _ = fixture()
            rules = [{'type': 'Domain', 'payload': h, 'proxy': 'secret-node',
                      'extra': {'disabled': False, 'hitCount': 0, 'hitAt': '', 'missCount': 0, 'missAt': ''}}
                     for h in ('service.com', 'other.com')]
            count = 0
            def read(path):
                nonlocal count
                if path != '/rules': return {'proxies': adapters} if path == '/proxies' else {}
                count += 1
                after = deepcopy(rules); after[0]['extra']['hitCount'] = count
                return {'rules': after}
            try:
                with patch.object(suite, 'baseline'), patch('tools.guided_routing_suite.api', side_effect=read), \
                     patch('tools.rule_diagnostics.probe_case', return_value={'status': 'PASS'}):
                    suite.rule_tests('G02-rules')
                self.assertEqual([r['status'] for r in suite.results], ['PASS', 'PASS'])
            finally:
                suite.finish()

    def test_rule_disable_change_stops_before_any_probe(self):
        from copy import deepcopy
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0')
            _, adapters, _ = fixture()
            rules = [{'type': 'Domain', 'payload': 'service.com', 'proxy': 'secret-node', 'extra': {'disabled': False}}]
            count = 0
            def read(path):
                nonlocal count
                if path != '/rules': return {'proxies': adapters} if path == '/proxies' else {}
                count += 1
                after = deepcopy(rules); after[0]['extra']['disabled'] = count > 1
                return {'rules': after}
            try:
                with patch.object(suite, 'baseline'), patch('tools.guided_routing_suite.api', side_effect=read), \
                     patch('tools.rule_diagnostics.probe_case', side_effect=AssertionError('must stop before network probe')):
                    with self.assertRaises(StopSuite): suite.rule_tests('G02-rules')
                self.assertEqual(suite.results[0]['status'], 'UNKNOWN')
            finally:
                suite.finish()

    def test_no_registration_is_preserved_for_usb_only_users(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0'); suite.registration = None
            g, a, rules = fixture()
            values = {'/configs': g, '/proxies': {'proxies': a}, '/rules': {'rules': rules}, '/connections': {'connections': []}}
            try:
                with patch('tools.guided_routing_suite.preferences', return_value={'EZSwitch.automaticRouting': True}), \
                     patch('tools.guided_routing_suite.app_pids', return_value=[10]), \
                     patch('tools.guided_routing_suite.interface_state', return_value={'online': True, 'active_ip': True}), \
                     patch('tools.guided_routing_suite.command', side_effect=lambda args: b'en5 en0' if args[-1] == '-l' else b'Wi-Fi Power (en0): Off'), \
                     patch('tools.guided_routing_suite.api', side_effect=lambda path: values[path]):
                    snapshot = suite.snapshot()
                self.assertTrue(snapshot['registration_preserved'])
                self.assertTrue(phone_mode(snapshot, 'en5'))
            finally:
                suite.finish()

    def test_controller_absence_requires_an_actual_failed_probe(self):
        from tools.guided_routing_suite import controller_absent
        g, adapters, rules = fixture()
        for failure, expected_checked, expected_absent in (
                ('interface', False, False), ('transport', True, True),
                ('malformed', True, False), ('later-read', True, False)):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                suite = Suite(Path(directory), 'en5', 'en0')
                def response(path):
                    if path == '/configs':
                        if failure == 'transport':
                            raise OSError('fixture')
                        if failure == 'malformed':
                            raise ValueError('fixture')
                        return g
                    if failure == 'later-read':
                        raise OSError('fixture')
                    return {'proxies': adapters, 'rules': rules, 'connections': []}
                try:
                    with patch('tools.guided_routing_suite.preferences', return_value={}), \
                         patch('tools.guided_routing_suite.app_pids', return_value=[10]), \
                         patch('tools.guided_routing_suite.interface_state', side_effect=TimeoutError() if failure == 'interface' else None,
                               return_value={'online': True, 'active_ip': True}), \
                         patch('tools.guided_routing_suite.command', side_effect=lambda args: b'en5 en0' if args[-1] == '-l' else b'Wi-Fi Power (en0): Off'), \
                         patch('tools.guided_routing_suite.api', side_effect=response) as read:
                        snapshot = suite.snapshot()
                    self.assertEqual(snapshot['controller_checked'], expected_checked)
                    self.assertEqual(controller_absent(snapshot), expected_absent)
                    if failure == 'interface':
                        read.assert_not_called()
                finally:
                    suite.finish()

    def test_open_success_without_confirmed_first_start_cannot_pass_order(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0'); suite.stage = 'G09'
            try:
                with patch.object(suite, 'ask', return_value=True), patch.object(suite, 'phone_guard', return_value=True), \
                     patch.object(suite, 'snapshot', return_value={}), patch.object(suite, 'launch_app'), \
                     patch.object(suite, 'wait', side_effect=[{'app_count': 0}, None]):
                    with self.assertRaises(StopSuite):
                        suite.startup_order(True)
                self.assertEqual(suite.results[-1]['status'], 'UNKNOWN')
                self.assertFalse(any(r['status'] == 'PASS' for r in suite.results))
            finally:
                suite.finish()

    def test_tun_pause_requires_running_app_and_complete_observation(self):
        from tools.guided_routing_suite import paused_mode
        snapshot = phone_snapshot(); snapshot['controller']['tun'] = False; snapshot['auto_routing'] = False
        self.assertTrue(paused_mode(snapshot))
        snapshot['app_count'] = 0
        self.assertFalse(paused_mode(snapshot))
        snapshot['app_count'] = 1; snapshot['snapshot_complete'] = False
        self.assertFalse(paused_mode(snapshot))

    def test_fragmented_tcp_length_is_read_completely(self):
        from tools.guided_routing_suite import receive_exact
        class Fragmented:
            def __init__(self):
                self.parts = [b'\x00', b'\x10']
            def recv(self, length):
                return self.parts.pop(0) if self.parts else b''
        self.assertEqual(receive_exact(Fragmented(), 2), b'\x00\x10')
        with self.assertRaises(OSError):
            receive_exact(Fragmented(), 3)

    def test_blocked_requires_reject_rule_and_builtin_types(self):
        g = {'mode': 'rule', 'tun': {'enable': True}, 'interface-name': 'en5'}
        a = {'REJECT': {'type': 'Reject'}}
        self.assertTrue(runtime_summary(g, a, [{'type': 'Match', 'proxy': 'REJECT'}])['blocked'])
        self.assertFalse(runtime_summary(g, a, [{'type': 'Match', 'proxy': 'DIRECT'}])['blocked'])
        self.assertFalse(runtime_summary(g, {'REJECT': {'type': 'Trojan'}}, [{'type': 'Match', 'proxy': 'REJECT'}])['blocked'])

    def test_empty_null_connections_does_not_hide_confirmed_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0'); suite.registration = None; suite.old_id = 'old'
            values = {'/configs': {'mode': 'rule', 'tun': {'enable': True}},
                      '/proxies': {'proxies': {'REJECT': {'type': 'Reject'}}},
                      '/rules': {'rules': [{'type': 'Match', 'payload': '', 'proxy': 'REJECT'}]},
                      '/connections': {'connections': None}}
            try:
                with patch('tools.guided_routing_suite.preferences', return_value={'EZSwitch.automaticRouting': True}), \
                     patch('tools.guided_routing_suite.app_pids', return_value=[10]), \
                     patch('tools.guided_routing_suite.interface_state', return_value={'readable': False, 'online': False, 'active_ip': False}), \
                     patch('tools.guided_routing_suite.command', side_effect=lambda args: b'en0' if args[-1] == '-l' else b'Wi-Fi Power (en0): Off'), \
                     patch('tools.guided_routing_suite.api', side_effect=lambda path: values[path]):
                    s = suite.snapshot()
                self.assertTrue(s['snapshot_complete'])
                self.assertTrue(s['controller']['blocked'])
                self.assertEqual(s['connection_count'], 0)
                self.assertFalse(s['old_connection_remaining'])
            finally:
                suite.finish()

    def test_sleep_events_require_recent_sleep_and_wake(self):
        text = '2026-10-10 10:00:00 +0800 Sleep Entering Sleep\n2026-10-10 10:00:10 +0800 Wake Wake reason\n'
        self.assertEqual(sleep_events(text, 0), {'Sleep': 1, 'Wake': 1})
        self.assertEqual(sleep_events(text, 9999999999), {})

    def test_sleep_log_timeout_is_distinct_from_no_events_and_redacts_output(self):
        error = subprocess.TimeoutExpired(['pmset'], 12, output=b'private-power-log')
        with patch('tools.guided_routing_suite.command', side_effect=error) as cmd:
            result = sleep_diagnostics(123)
        self.assertEqual(result['read_status'], 'timeout')
        self.assertEqual(result['error_type'], 'TimeoutExpired')
        self.assertEqual(result['events'], {})
        self.assertNotIn('private-power-log', json.dumps(result))
        cmd.assert_called_once_with(['/usr/bin/pmset', '-g', 'log'], timeout=12)

    def test_sleep_log_command_error_remains_unknown_without_error_message(self):
        with patch('tools.guided_routing_suite.command', side_effect=StopSuite('private-detail')):
            result = sleep_diagnostics(123)
        self.assertEqual(result['read_status'], 'error')
        self.assertEqual(result['error_type'], 'StopSuite')
        self.assertEqual(result['events'], {})
        self.assertNotIn('private-detail', json.dumps(result))

    def test_sleep_log_success_without_sleep_is_distinct_from_read_failure(self):
        with patch('tools.guided_routing_suite.command', return_value=b'no matching events'):
            result = sleep_diagnostics(123)
        self.assertEqual(result['read_status'], 'complete')
        self.assertEqual(result['events'], {})
        self.assertNotIn('error_type', result)

    def test_sleep_log_success_preserves_recent_events(self):
        text = b'2026-10-10 10:00:00 +0800 Sleep Entering Sleep\n2026-10-10 10:00:10 +0800 Wake Wake reason\n'
        with patch('tools.guided_routing_suite.command', return_value=text):
            result = sleep_diagnostics(0)
        self.assertEqual(result['read_status'], 'complete')
        self.assertEqual(result['events'], {'Sleep': 1, 'Wake': 1})

    def test_sleep_diagnostic_survives_failed_or_interrupted_recovery(self):
        diagnostic = {'read_status': 'timeout', 'error_type': 'TimeoutExpired', 'events': {}}
        for error in (StopSuite('recovery-unconfirmed'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                suite = Suite(Path(directory), 'en5', 'en0'); suite.stage = 'G07'
                with patch.object(suite, 'baseline', side_effect=[phone_snapshot(), error]), \
                     patch.object(suite, 'ask', return_value=True), \
                     patch('tools.guided_routing_suite.sleep_diagnostics', return_value=diagnostic):
                    with self.assertRaises(type(error)):
                        suite.sleep_check()
                suite.finish(interrupted=isinstance(error, KeyboardInterrupt), failure='recovery-unconfirmed')
                summary = json.loads(Path(directory, 'summary.json').read_text())
                row = next(r for r in summary['results'] if r['case'] == 'G07')
                self.assertEqual(row['sleep_diagnostic'], diagnostic)
                self.assertEqual(row['status'], 'INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'UNKNOWN')

    def test_sleep_recovery_requires_events_and_keeps_one_result(self):
        for events, expected in (({}, 'UNKNOWN'), ({'Sleep': 1, 'Wake': 1}, 'PASS')):
            with self.subTest(events=events), tempfile.TemporaryDirectory() as directory:
                suite = Suite(Path(directory), 'en5', 'en0'); suite.stage = 'G07'
                try:
                    with patch.object(suite, 'baseline', return_value=phone_snapshot()), \
                         patch.object(suite, 'ask', return_value=True), \
                         patch('tools.guided_routing_suite.sleep_diagnostics', return_value={'read_status': 'complete', 'events': events}):
                        suite.sleep_check()
                    self.assertEqual(len(suite.results), 1)
                    self.assertEqual(suite.results[0]['status'], expected)
                    self.assertEqual(suite.results[0]['sleep_events'], events)
                finally:
                    suite.finish()

    def test_wifi_interface_is_detected_instead_of_historical_default(self):
        self.assertEqual(wifi_interface('Hardware Port: Wi-Fi\nDevice: en7\nEthernet Address: private'), 'en7')
        self.assertIsNone(wifi_interface('Device: en0'))

    def test_interruption_preserves_partial_results_and_unrun_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            suite = Suite(Path(directory), 'en5', 'en0')
            suite.result('G02-websites', 'RUNNING'); suite.mutations.append({'action': 'fixture'})
            self.assertEqual(suite.finish(interrupted=True), 130)
            result = json.loads(Path(directory, 'summary.json').read_text())
            self.assertEqual(result['results'][0]['status'], 'INTERRUPTED')
            self.assertTrue(any(r['status'] == 'NOT_RUN' for r in result['results']))
            self.assertEqual(result['actions'], [{'action': 'fixture'}])
            self.assertFalse(result['strict_protection_verified'])
            self.assertEqual(Path(directory, 'output.log').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
