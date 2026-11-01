"""校园严格保护拔插测试脚本的离线单元测试。"""

from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from unittest.mock import patch

try:
    from routing.tools import test_campus_usb_unplug as module
except ModuleNotFoundError:
    from tools import test_campus_usb_unplug as module


class FakeController:
    def __init__(self, config, proxies, rules):
        self._data = {"/configs": config, "/proxies": {"proxies": proxies}, "/rules": {"rules": rules}}

    def read(self, path):
        return self._data[path]


def rules(strict=True, fallback="⚓️其他流量"):
    rows = [
        {"type": "Domain", "payload": "mask.icloud.com", "proxy": "⚓️其他流量"},
        {"type": "DomainSuffix", "payload": "qq.com", "proxy": "EZ-Campus"},
    ]
    if strict:
        rows.append({"type": "DomainSuffix", "payload": "campus.example", "proxy": "EZ-Campus"})
    rows.append({"type": "Match", "proxy": fallback})
    return rows


def proxies(usb="en6", extra=True):
    rows = {
        "DIRECT": {"type": "Direct"},
        "REJECT": {"type": "Reject"},
        "EZ-Campus": {"type": "Direct", "interface": "en0"},
        "EZ-USB-DNS": {"type": "Direct", "interface": usb},
    }
    if extra:
        rows["Node"] = {"type": "Trojan", "interface": "en6"}
    return rows


class SnapshotTests(unittest.TestCase):
    def snapshot(self, rules_rows, proxies_rows, interface="en6"):
        controller = FakeController({"mode": "rule", "interface-name": interface, "tun": {"enable": True}},
                                    proxies_rows, rules_rows)
        with patch.object(module, "iface_ipv4", side_effect=lambda name: "10.0.0.2" if name == "en0" else "192.168.0.2"):
            return module.snapshot(controller, "en0", "en6")

    def test_strict_online_snapshot(self):
        state = self.snapshot(rules(), proxies())
        self.assertTrue(state["strict_rule"])
        self.assertEqual(state["match_target"], "⚓️其他流量")
        self.assertFalse(state["fallback_reject"])
        self.assertEqual(state["campus_interface"], "en0")
        self.assertEqual(state["dns_interface"], "en6")
        self.assertEqual(state["remote_adapters"], ["Node"])

    def test_offline_snapshot_rejects_and_drops_remote_adapters(self):
        state = self.snapshot(rules(fallback="REJECT"), proxies(extra=False))
        self.assertTrue(state["fallback_reject"])
        self.assertEqual(state["remote_adapters"], [])
        self.assertTrue(state["strict_rule"])

    def test_missing_strict_rule_is_detected(self):
        state = self.snapshot(rules(strict=False), proxies())
        self.assertFalse(state["strict_rule"])

    def test_match_target_uses_last_match_rule(self):
        rows = [{"type": "Match", "proxy": "A"}, {"type": "Domain", "payload": "x", "proxy": "B"},
                {"type": "Match", "proxy": "C"}]
        self.assertEqual(module.match_target(rows), "C")

    def test_remote_adapters_ignores_reject_and_direct(self):
        rows = {"DIRECT": {"type": "Direct"}, "X": {"type": "Reject"}, "EZ-Campus": {"type": "Direct"},
                "Node": {"type": "Shadowsocks"}, "Group": {"type": "Selector"}}
        self.assertEqual(module.remote_adapters(rows), ["Group", "Node"])


class ProbeRetryTests(unittest.TestCase):
    def test_retries_until_expected_verdict(self):
        journal = module.Journal(__import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        sequence = [{"verdict": "blocked", "http_code": "000", "returncode": 35, "error": "x"},
                    {"verdict": "reachable", "http_code": "200", "returncode": 0, "error": None}]
        with patch.object(module, "curl_probe", side_effect=sequence), patch.object(module.time, "sleep"):
            rows = module.probe_set("offline", [("campus", "https://x/", "reachable")], journal=journal,
                                    timeout=1, retries=2)
        self.assertTrue(rows[0]["ok"])
        self.assertEqual(len(rows[0]["attempts"]), 2)

    def test_fails_after_retries(self):
        journal = module.Journal(__import__("pathlib").Path(__import__("tempfile").mkdtemp()))
        stuck = {"verdict": "blocked", "http_code": "000", "returncode": 7, "error": "x"}
        with patch.object(module, "curl_probe", return_value=stuck), patch.object(module.time, "sleep"):
            rows = module.probe_set("offline", [("campus", "https://x/", "reachable")], journal=journal,
                                    timeout=1, retries=2)
        self.assertFalse(rows[0]["ok"])
        self.assertEqual(len(rows[0]["attempts"]), 3)


class ReadyTests(unittest.TestCase):
    def state(self, **overrides):
        base = {"strict_rule": True, "fallback_reject": True, "campus_interface": "en0",
                "dns_interface": "en0", "remote_adapters": [], "rule_count": 1200}
        base.update(overrides)
        return base

    def test_offline_ready_requires_strict_rule(self):
        self.assertTrue(module.offline_ready(self.state(), "en0"))
        self.assertFalse(module.offline_ready(self.state(strict_rule=False), "en0"))
        self.assertFalse(module.offline_ready(self.state(rule_count=1), "en0"))
        self.assertFalse(module.offline_ready(self.state(campus_interface=None), "en0"))
        self.assertFalse(module.offline_ready(self.state(remote_adapters=["Node"]), "en0"))
        self.assertFalse(module.offline_ready(self.state(fallback_reject=False), "en0"))

    def test_restored_ready_requires_proxy_and_usb_dns(self):
        base = {"strict_rule": True, "fallback_reject": False, "campus_interface": "en0",
                "dns_interface": "en6", "remote_adapters": ["Node"], "rule_count": 1600}
        self.assertTrue(module.restored_ready(base, "en0", "en6"))
        self.assertFalse(module.restored_ready({**base, "dns_interface": "en0"}, "en0", "en6"))
        self.assertFalse(module.restored_ready({**base, "remote_adapters": []}, "en0", "en6"))


class CurlClassificationTests(unittest.TestCase):
    def test_table(self):
        cases = [
            (0, "200", "reachable"),
            (0, "403", "reachable"),
            (0, "000", "unknown"),
            (7, "000", "blocked"),
            (28, "000", "blocked"),
            (35, "", "blocked"),
            (52, "000", "blocked"),
        ]
        for returncode, code, expected in cases:
            with self.subTest(returncode=returncode, code=code):
                self.assertEqual(module.classify_curl(returncode, code), expected)


class JournalTests(unittest.TestCase):
    def test_probe_row_can_carry_role_without_clashing_with_kind(self):
        with TemporaryDirectory() as directory:
            journal = module.Journal(Path(directory))
            journal.write("probe", phase="offline", role="campus", url="u", verdict="reachable")
            row = json.loads((Path(directory) / "requests.jsonl").read_text().strip())
            self.assertEqual(row["kind"], "probe")
            self.assertEqual(row["role"], "campus")


class SummaryTests(unittest.TestCase):
    def test_pass_when_all_checks_and_probes_hold(self):
        rows = [{"phase": "offline", "url": "u", "verdict": "blocked", "expected": "blocked", "ok": True}]
        self.assertEqual(module.summarize({"a": True}, rows)["verdict"], "pass")

    def test_fail_lists_both_checks_and_probes(self):
        rows = [{"phase": "offline", "url": "u", "verdict": "reachable", "expected": "blocked", "ok": False}]
        result = module.summarize({"a": False}, rows)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("a", result["failures"])
        self.assertTrue(any("offline:u" in item for item in result["failures"]))

    def test_expected_tables_cover_required_cases(self):
        offline = {url for _, url, _ in module.OFFLINE_EXPECT}
        self.assertIn("https://lib.campus.example/", offline)
        self.assertIn("https://data.bilibili.com/", offline)
        self.assertIn("https://www.gov.cn/", offline)
        restored = {url for _, url, _ in module.RESTORE_EXPECT}
        self.assertIn("https://github.com/", restored)


if __name__ == "__main__":
    unittest.main()
