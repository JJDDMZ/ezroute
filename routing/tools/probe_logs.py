"""Private, read-only core log observation for diagnostic requests."""
import json
import http.client
import socket
import threading
import time
from check_active import UnixHTTP


class CoreProbeLog:
    def __init__(self, endpoint, stage):
        self.endpoint, self.stage = endpoint, stage
        self.entries = []
        self.started = False
        self.request_sent = False
        self.connection = None
        self.stream_socket = None
        self.reader = None
        self.read_error = None
        self.stopping = False
        self.truncated = False

    def start(self):
        self.connection = UnixHTTP(self.endpoint)
        self.connection.request('GET', '/logs?level=debug', headers={'Host': 'localhost'})
        self.request_sent = True
        self.stream_socket = self.connection.sock
        if self.stream_socket:
            self.stream_socket.settimeout(None)

        def read():
            try:
                # Mihomo flushes its ordinary HTTP response only on a log event.
                # Waiting here, on the reader thread, lets the probe produce it.
                response = self.connection.getresponse()
                if response.status != 200:
                    self.read_error = 'controller-status-' + str(response.status)
                    return
                self.started = True
                while True:
                    line = response.readline()
                    if not line:
                        break
                    entry = json.loads(line)
                    payload = entry.get('payload', '')
                    if not isinstance(payload, str) or not any(value in payload.lower()
                            for value in ['www.gstatic.com', 'www.bilibili.com', 'fake ip', 'fake-ip']):
                        continue
                    if len(self.entries) >= 1000:
                        self.truncated = True
                        continue
                    self.entries.append({'type': entry.get('type'), 'payload': payload,
                                         'stage': self.stage(), 'monotonic_time': time.monotonic()})
            except (OSError, ValueError, http.client.HTTPException) as error:
                if not self.stopping:
                    self.read_error = type(error).__name__

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def stop(self):
        self.stopping = True
        if self.connection:
            if self.stream_socket:
                try:
                    self.stream_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            if self.reader:
                self.reader.join(3)
            self.connection.close()

    def summary(self):
        payloads = [entry['payload'].lower() for entry in self.entries]
        signals = {
            'fake_ip_missing': lambda text: 'no existing' in text and ('fake ip' in text or 'fake-ip' in text),
            'timeout': lambda text: 'timeout' in text or 'timed out' in text,
            'dial_failed': lambda text: 'dial' in text and 'error' in text,
            'dns_failed': lambda text: 'dns' in text and ('fail' in text or 'error' in text),
            'rejected': lambda text: 'using reject' in text,
        }
        return {'request_sent': self.request_sent, 'started': self.started, 'relevant_records': len(self.entries),
                'warning_records': sum(entry.get('type') in ('warning', 'error') for entry in self.entries),
                'error_signals': {name: sum(test(text) for text in payloads) for name, test in signals.items()},
                'read_error_type': self.read_error, 'truncated': self.truncated}
