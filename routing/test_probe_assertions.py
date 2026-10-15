import unittest
from tools.probe_assertions import request_passed


class ProbeAssertionsTests(unittest.TestCase):
    def test_offline_wifi_direct_success_is_a_test_failure(self):
        self.assertFalse(request_passed('usb', 'direct', 0, '200', True, False))

    def test_direct_failure_must_actually_have_attempted_campus_policy(self):
        self.assertFalse(request_passed('usb', 'direct', 35, '000', False, False))
        self.assertTrue(request_passed('usb', 'direct', 35, '000', True, False))

    def test_online_wifi_direct_failure_is_not_a_pass(self):
        self.assertFalse(request_passed('usb', 'direct', 35, '000', True, True))
        self.assertTrue(request_passed('usb', 'direct', 0, '200', True, True))

    def test_missing_usb_success_is_a_failure(self):
        self.assertFalse(request_passed('missing', 'proxy', 0, '204', False, False))
        self.assertTrue(request_passed('missing', 'proxy', 35, '000', False, False))

    def test_http_204_alone_does_not_prove_use_of_a_remote_proxy(self):
        self.assertFalse(request_passed('usb', 'proxy', 0, '204', False, True))


if __name__ == '__main__':
    unittest.main()
