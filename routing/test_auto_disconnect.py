import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import copy
import unittest
from unittest.mock import patch

from tools.verify_auto_disconnect import Diagnostic


class AutoDisconnectTests(unittest.TestCase):
    def test_split_verification_ignores_hit_statistics_but_rejects_disabled_or_changed_rules(self):
        diagnostic = Diagnostic(os.getuid(), Path('/private/tmp'), 'en5', 'en0')
        diagnostic.nodes = {'Node': {'port': 443}}
        diagnostic.original_names = {'Node', 'Group', 'EZ-Campus', 'EZ-USB-DNS'}
        diagnostic.original_groups = {'Group': ['Node']}
        diagnostic.original_rules = [{'type': 'Match', 'payload': '', 'proxy': 'Group',
            'index': 0, 'size': 0, 'extra': {'disabled': False, 'hitAt': 0, 'hitCount': 1,
                                           'missAt': 0, 'missCount': 0}}]
        general = {'mode': 'rule', 'interface-name': 'en5', 'tun': {'enable': True}}
        proxies = {'Node': {'type': 'Trojan', 'interface': 'en5'},
                   'Group': {'type': 'Selector', 'all': ['Node']},
                   'EZ-Campus': {'type': 'Direct', 'interface': 'en0'},
                   'EZ-USB-DNS': {'type': 'Direct', 'interface': 'en5'}}
        rules = copy.deepcopy(diagnostic.original_rules)
        rules[0]['extra'].update(hitAt=123, hitCount=9, missAt=124, missCount=6)
        self.assertTrue(diagnostic.split_matches((general, proxies, rules)))
        rules[0]['extra']['disabled'] = True
        self.assertFalse(diagnostic.split_matches((general, proxies, rules)))
        rules[0]['extra']['disabled'] = False
        rules[0]['proxy'] = 'EZ-Campus'
        self.assertFalse(diagnostic.split_matches((general, proxies, rules)))

    def test_tls_reset_is_retained_as_a_failed_probe_not_an_aborted_run(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()

            def reset_client():
                conn, _ = listener.accept()
                with conn:
                    conn.recv(4096)
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

            worker = threading.Thread(target=reset_client)
            worker.start()
            diagnostic = Diagnostic(os.getuid(), Path(directory), 'en5', 'en0')
            diagnostic.nodes = {}
            diagnostic.api = lambda path: {'connections': []}

            # Only substitute external TCP establishment; the TLS handshake and
            # peer reset are real sockets, handled by the production probe.
            def connect_local(connection):
                connection.sock = socket.create_connection(listener.getsockname(), timeout=2)

            try:
                with patch('http.client.HTTPConnection.connect', connect_local):
                    result = diagnostic.probe('direct')
            finally:
                worker.join(timeout=3)
            self.assertFalse(result['request_success'])
            self.assertEqual(result['failed_operation'], 'tls-handshake')
            self.assertEqual(result['error_code'], 'ConnectionResetError')
            self.assertFalse(diagnostic.valid_probe(result))

    def test_failure_capture_summary_is_saved_without_marking_acceptance_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            diagnostic = Diagnostic(os.getuid(), root, 'en5', 'en0')
            diagnostic.direct_targets.add(('198.51.100.4', 443))
            (root / 'wifi-packets.txt').write_text(
                '12:00:00 IP 192.0.2.1.40000 > 198.51.100.4.443: tcp 0, if en0\n')
            diagnostic.capture_messages = ['1 packets captured\n0 packets dropped by kernel\n']
            diagnostic.record_capture_summary()
            diagnostic.write('result.json', diagnostic.result)
            saved = json.loads((root / 'result.json').read_text())
            self.assertEqual(saved['wifi_packet_counts']['direct_on_wifi'], 1)
            self.assertEqual(saved['kernel_dropped'], 0)
            self.assertFalse(saved['all_requested_checks_verified'])


if __name__ == '__main__':
    unittest.main()
