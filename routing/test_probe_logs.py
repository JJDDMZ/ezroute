import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools.probe_logs import CoreProbeLog
from tools.verify_registered_wifi import RegisteredWifiDiagnostic


class ProbeLogTests(unittest.TestCase):
    def test_deferred_http_headers_do_not_block_the_request_that_produces_a_log(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            endpoint = str(Path(directory) / 'controller.sock')
            listener.bind(endpoint)
            listener.listen()
            release_response = threading.Event()
            start_returned = threading.Event()
            errors = []
            def serve():
                conn, _ = listener.accept()
                with conn:
                    request = b''
                    while b'\r\n\r\n' not in request:
                        request += conn.recv(4096)
                    release_response.wait(7)
                    try:
                        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
                            b'{"type":"info","payload":"www.gstatic.com using PRIVATE-NODE"}\n')
                    except BrokenPipeError:
                        pass
            worker = threading.Thread(target=serve)
            worker.start()
            log = CoreProbeLog(endpoint, lambda: 'check-usb-baseline')
            def start():
                try:
                    log.start()
                    start_returned.set()
                except Exception as error:
                    errors.append(type(error).__name__)
            caller = threading.Thread(target=start)
            caller.start()
            try:
                self.assertTrue(start_returned.wait(.5), 'logger blocked before the diagnostic could produce a log')
                self.assertFalse(log.summary()['started'])
                release_response.set()
                worker.join(3)
                log.reader.join(3)
                self.assertTrue(log.summary()['started'])
                self.assertEqual(len(log.entries), 1)
                self.assertEqual(errors, [])
            finally:
                release_response.set()
                caller.join(6)
                log.stop()
                worker.join(3)

    def test_stopping_open_chunked_stream_does_not_raise_thread_exception(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            endpoint = str(Path(directory) / 'controller.sock')
            listener.bind(endpoint)
            listener.listen()
            def serve():
                conn, _ = listener.accept()
                with conn:
                    request = b''
                    while b'\r\n\r\n' not in request:
                        request += conn.recv(4096)
                    conn.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
                    conn.recv(1)
            worker = threading.Thread(target=serve)
            worker.start()
            log = CoreProbeLog(endpoint, lambda: 'check-usb-baseline')
            errors = []
            try:
                with patch('threading.excepthook', lambda args: errors.append(args.exc_type.__name__)):
                    log.start()
                    log.stop()
                    log.stop()
                self.assertEqual(errors, [])
                self.assertFalse(log.reader.is_alive())
            finally:
                log.stop()
                worker.join(3)

    def test_core_errors_are_retained_privately_without_exposing_labels_in_summary(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            endpoint = str(Path(directory) / 'controller.sock')
            listener.bind(endpoint)
            listener.listen()
            sent = threading.Event()

            def serve():
                conn, _ = listener.accept()
                with conn:
                    request = b''
                    while b'\r\n\r\n' not in request:
                        request += conn.recv(4096)
                    if not request.startswith(b'GET /logs?level=debug '):
                        return
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n')
                    for entry in [
                        {'type': 'info', 'payload': 'unrelated.example using PRIVATE-NODE'},
                        {'type': 'warning', 'payload': '[TCP] dial PRIVATE-NODE --> www.gstatic.com:443 error: i/o timeout'},
                        {'type': 'warning', 'payload': 'no existing fake ip record found'},
                    ]:
                        conn.sendall(json.dumps(entry).encode() + b'\n')
                    sent.set()

            worker = threading.Thread(target=serve)
            worker.start()
            log = CoreProbeLog(endpoint, lambda: 'check-usb-baseline')
            try:
                log.start()
                self.assertTrue(sent.wait(3))
                worker.join(3)
                log.reader.join(3)
                log.stop()
                self.assertEqual(len(log.entries), 2)
                self.assertEqual(log.summary()['warning_records'], 2)
                self.assertEqual(log.summary()['error_signals']['timeout'], 1)
                self.assertEqual(log.summary()['error_signals']['fake_ip_missing'], 1)
                self.assertNotIn('PRIVATE-NODE', json.dumps(log.summary()))
                diagnostic = RegisteredWifiDiagnostic(os.getuid(), Path(directory), 'en5', 'en0')
                diagnostic.core_log = log
                diagnostic.finish_capture()
                saved = Path(directory) / 'core-probe-log.json'
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
                self.assertIn('PRIVATE-NODE', saved.read_text())
                self.assertEqual(diagnostic.result['core_probe_log']['relevant_records'], 2)
                diagnostic.finish_capture()
            finally:
                log.stop()
                worker.join(3)

    def test_unavailable_core_log_does_not_create_false_ready_or_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            log = CoreProbeLog(str(Path(directory) / 'missing.sock'), lambda: 'check-usb-baseline')
            with self.assertRaises(OSError):
                log.start()
            log.stop()
            self.assertFalse(log.summary()['started'])


if __name__ == '__main__':
    unittest.main()
