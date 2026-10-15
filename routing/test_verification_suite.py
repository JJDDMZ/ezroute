import io
import json
import os
import signal
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.verify_routing_suite import (REPO, Step, Transcript, live_plan, main,
                                       offline_steps, run_steps, strict_readiness)


class VerificationSuiteTests(unittest.TestCase):
    def test_failure_does_not_hide_independent_results_or_verify_stale_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            transcript = Transcript(directory, io.StringIO())
            steps = [Step('Build', (sys.executable, '-c', 'raise SystemExit(9)')),
                     Step('Signature', (sys.executable, '-c', 'raise SystemExit(99)'), 'Build'),
                     Step('Independent', (sys.executable, '-c', 'print("complete-log-marker")'))]
            result = run_steps(steps, REPO, transcript)
            transcript.close()
            self.assertEqual([r['status'] for r in result], ['FAIL', 'SKIPPED', 'PASS'])
            self.assertEqual(result[0]['exit_code'], 9)
            self.assertIn('complete-log-marker', Path(directory, 'output.log').read_text())

    def test_timeout_stops_owned_child_and_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            transcript = Transcript(directory, io.StringIO())
            result = run_steps([Step('Hang', (sys.executable, '-c', 'import time; time.sleep(20)'), timeout=.15),
                                Step('Next', (sys.executable, '-c', 'pass'))], REPO, transcript)
            transcript.close()
            self.assertEqual([r['status'] for r in result], ['TIMEOUT', 'PASS'])
            self.assertIsNotNone(result[0]['exit_code'])

    def test_timeout_cleans_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory, 'child-stopped')
            child_code = ("import signal,time,pathlib; "
                          "signal.signal(signal.SIGTERM,lambda *_: (pathlib.Path(" + repr(str(marker)) + ").write_text('stopped'),exit(0))); "
                          "print('child-ready',flush=True); time.sleep(20)")
            leader_code = "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c'," + repr(child_code) + "]); print(p.pid,flush=True)"
            transcript = Transcript(directory, io.StringIO())
            result = run_steps([Step('Descendant', (sys.executable, '-c', leader_code), timeout=.3)], REPO, transcript)
            transcript.close()
            log = Path(directory, 'output.log').read_text()
            child_pid = next(int(line) for line in log.splitlines() if line.isdigit())
            try:
                self.assertEqual(result[0]['status'], 'TIMEOUT')
                deadline = time.monotonic() + 1
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), 'child survived after the leader exited')
            finally:
                if not marker.exists():
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_command_not_found_is_recorded_and_next_step_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            transcript = Transcript(directory, io.StringIO())
            result = run_steps([Step('Missing', ('/nonexistent/ez-switch-test-command',)),
                                Step('Next', (sys.executable, '-c', 'pass'))], REPO, transcript)
            transcript.close()
            self.assertEqual([r['status'] for r in result], ['FAIL', 'PASS'])

    def test_current_mode_is_explicit_and_reuses_fixed_site_command(self):
        captured = []
        def record(steps, cwd, transcript, results):
            captured.extend(steps)
            return [{'name': step.name, 'status': 'PASS'} for step in steps]
        with tempfile.TemporaryDirectory() as directory:
            with patch('tools.verify_routing_suite.tempfile.mkdtemp', return_value=directory), \
                 patch('tools.verify_routing_suite.run_steps', side_effect=record), \
                 patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--current']), 0)
            summary = json.loads(Path(directory, 'summary.json').read_text())
            self.assertEqual([step.name for step in captured], ['Build', 'Signature', 'CurrentWebsites'])
            self.assertEqual(captured[-1].command[-1], '--website-tests')
            self.assertEqual(captured[-1].dependency, 'Signature')
            self.assertTrue(summary['website_diagnostic_started'])
            self.assertFalse(summary['physical_egress_verified'])
            self.assertFalse(summary['live_configuration_modified'])
            self.assertNotIn('offline_checks_passed', summary)
        self.assertFalse(any(step.name == 'CurrentWebsites' for step in offline_steps()))

    def test_timeout_retains_shutdown_output(self):
        code = "import signal,time; signal.signal(signal.SIGTERM,lambda *_: print('shutdown-tail-marker',flush=True)); print('ready',flush=True); time.sleep(20)"
        with tempfile.TemporaryDirectory() as directory:
            transcript = Transcript(directory, io.StringIO())
            result = run_steps([Step('Hang', (sys.executable, '-c', code), timeout=.3)], REPO, transcript)
            transcript.close()
            self.assertEqual(result[0]['status'], 'TIMEOUT')
            self.assertIn('shutdown-tail-marker', Path(directory, 'output.log').read_text())

    def test_completed_site_record_survives_later_timeout(self):
        record = json.dumps({'event': 'site-result', 'result': {'site': 'fixture', 'status': 'UNKNOWN'}})
        code = "import time; print(" + repr(record) + ",flush=True); time.sleep(20)"
        with tempfile.TemporaryDirectory() as directory:
            transcript = Transcript(directory, io.StringIO())
            result = run_steps([Step('CurrentWebsites', (sys.executable, '-c', code), timeout=.3)], REPO, transcript)
            transcript.close()
            self.assertEqual(result[0]['status'], 'TIMEOUT')
            self.assertIn(record, Path(directory, 'output.log').read_text())

    def test_current_interrupt_records_attempt_and_partial_results(self):
        def interrupt(steps, cwd, transcript, results):
            results.extend([{'name': 'Build', 'status': 'PASS'},
                            {'name': 'CurrentWebsites', 'status': 'INTERRUPTED'}])
            raise KeyboardInterrupt
        with tempfile.TemporaryDirectory() as directory:
            with patch('tools.verify_routing_suite.tempfile.mkdtemp', return_value=directory), \
                 patch('tools.verify_routing_suite.run_steps', side_effect=interrupt), \
                 patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--current']), 130)
            summary = json.loads(Path(directory, 'summary.json').read_text())
            self.assertTrue(summary['website_diagnostic_started'])
            self.assertTrue(summary['live_actions_executed'])
            self.assertEqual(summary['offline_steps'][-1]['status'], 'INTERRUPTED')
            self.assertFalse(summary['physical_egress_verified'])

    def test_log_is_exclusive_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            transcript = Transcript(directory, io.StringIO())
            transcript.write('one')
            transcript.close()
            self.assertEqual(Path(directory, 'output.log').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                Transcript(directory, io.StringIO())
            self.assertEqual(Path(directory, 'output.log').read_text(), 'one')

    def test_live_request_never_starts_commands_or_network_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('tools.verify_routing_suite.tempfile.mkdtemp', return_value=directory), \
                 patch('tools.verify_routing_suite.subprocess.Popen') as popen, \
                 patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--live']), 78)
            popen.assert_not_called()
            summary = json.loads(Path(directory, 'summary.json').read_text())
            self.assertFalse(summary['live_actions_executed'])
            self.assertFalse(summary['strict_acceptance_passed'])
            self.assertEqual(summary['offline_steps'], [])
            self.assertTrue(all(s['status'] == 'BLOCKED_NOT_RUN' for s in summary['live_scenarios']))

    def test_offline_pass_does_not_turn_readiness_into_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('tools.verify_routing_suite.tempfile.mkdtemp', return_value=directory), \
                 patch('tools.verify_routing_suite.run_steps', return_value=[{'name': 'fixture', 'status': 'PASS'}]), \
                 patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--offline']), 0)
            summary = json.loads(Path(directory, 'summary.json').read_text())
            self.assertTrue(summary['offline_checks_passed'])
            self.assertFalse(summary['strict_acceptance_passed'])
            self.assertEqual(summary['readiness']['status'], 'BLOCKED')

    def test_preflight_does_not_run_offline_suites(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('tools.verify_routing_suite.tempfile.mkdtemp', return_value=directory), \
                 patch('tools.verify_routing_suite.run_steps') as run, \
                 patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--preflight']), 78)
            run.assert_not_called()

    def test_steps_only_build_and_do_not_launch_install_or_repeat_live_tests(self):
        steps = offline_steps()
        build = next(step for step in steps if step.name == 'Build')
        self.assertIn('--build-only', build.command)
        self.assertFalse(any('install.sh' in part or 'verify_campus' in part for step in steps for part in step.command))
        self.assertEqual(strict_readiness()['distribution_signing_required'], False)
        self.assertEqual(len(live_plan()), 11)
        self.assertTrue(all(s['criterion'] and s['action'] and s['recovery'] for s in live_plan()))

    def test_interrupt_does_not_lose_partial_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('tools.verify_routing_suite.tempfile.mkdtemp', return_value=directory), \
                 patch('tools.verify_routing_suite.run_steps', side_effect=KeyboardInterrupt), \
                 patch('sys.stdout', new=io.StringIO()):
                self.assertEqual(main(['--offline']), 130)
            self.assertTrue(json.loads(Path(directory, 'summary.json').read_text())['interrupted'])


if __name__ == '__main__':
    unittest.main()
