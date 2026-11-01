"""严格无线名单数据源与生成物的一致性测试。"""

import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "routing/data/strict-whitelist.json"


def load_data():
    return json.loads(DATA.read_text(encoding="utf-8"))


class StrictWhitelistDataTests(unittest.TestCase):
    def test_generated_artifacts_are_current(self):
        result = subprocess.run(
            [sys.executable, "script/generate-strict-whitelist.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_entries_are_unique_and_lowercase(self):
        data = load_data()
        seen = set()
        for entry in data["entries"]:
            key = (entry["host"], entry["match"])
            self.assertNotIn(key, seen, entry["host"])
            seen.add(key)
            self.assertEqual(entry["host"], entry["host"].lower())

    def test_allow_sets_do_not_overlap(self):
        data = load_data()
        allow = [e for e in data["entries"] if e["decision"] == "allow"]
        suffixes = {e["host"] for e in allow if e["match"] == "suffix"}
        exact = {e["host"] for e in allow if e["match"] == "exact"}
        apple = {e["host"] for e in allow if e["group"] == "apple"}
        self.assertTrue(suffixes.isdisjoint(exact))
        self.assertTrue(apple.isdisjoint(exact - apple))
        for host in exact:
            self.assertFalse(
                any(host == suffix or host.endswith("." + suffix) for suffix in suffixes),
                host,
            )

    def test_exclusions_do_not_collide_with_allows(self):
        data = load_data()
        allow = [e for e in data["entries"] if e["decision"] == "allow"]
        exact = {e["host"] for e in allow if e["match"] == "exact"}
        suffixes = {e["host"] for e in allow if e["match"] == "suffix"}
        for item in data["exclusions"]["telemetry"] + data["exclusions"]["foreign_sensitive"]:
            self.assertNotIn((item["host"], item.get("match", "exact")), {(e["host"], e["match"]) for e in allow})
            if item.get("match", "exact") == "suffix":
                self.assertFalse(any(h == item["host"] or h.endswith("." + item["host"]) for h in exact))
        self.assertTrue(any(item["host"] == "youtube.com" for item in data["exclusions"]["foreign_sensitive"]))

    def test_foreign_sensitive_list_covers_known_platforms(self):
        data = load_data()
        hosts = {item["host"] for item in data["exclusions"]["foreign_sensitive"]}
        for required in ["x.com", "youtube.com", "google.com", "openai.com", "telegram.org", "bbc.com"]:
            self.assertIn(required, hosts)
        self.assertNotIn("apple.com", hosts)
        self.assertNotIn("microsoft.com", hosts)

    def test_telemetry_entries_are_known_reporting_hosts(self):
        data = load_data()
        hosts = {item["host"] for item in data["exclusions"]["telemetry"]}
        for required in ["data.bilibili.com", "hm.baidu.com", "badjs.weixinbridge.com"]:
            self.assertIn(required, hosts)
        self.assertTrue(all("." in host for host in hosts))

    def test_dns_extra_is_covered_and_not_derived(self):
        data = load_data()
        allow = [e for e in data["entries"] if e["decision"] == "allow"]
        suffixes = {e["host"] for e in allow if e["match"] == "suffix"}
        exact = {e["host"] for e in allow if e["match"] == "exact"}
        for host in data["dns_extra"]:
            covered = host in exact or any(host == s or host.endswith("." + s) for s in suffixes)
            self.assertTrue(covered, host)
            self.assertFalse(host.startswith("www.") and host[4:] in suffixes, host)
            self.assertNotIn(host, {item["host"] for item in data["exclusions"]["telemetry"]})

    def test_candidate_queue_only_admits_reviewable_domestic_sites(self):
        path = ROOT / "routing/data/strict-whitelist-candidates.json"
        if not path.exists():
            self.skipTest("候选队列尚未生成")
        data = json.loads(path.read_text(encoding="utf-8"))
        foreign = {item["host"] for item in data["sensitive_foreign"]}
        seen = set()
        for item in data["candidates"]:
            host = item["host"]
            self.assertNotIn(host, seen, host)
            seen.add(host)
            self.assertEqual(host, host.lower())
            self.assertIn(item["decision"], {"pending", "hold", "reject", "admitted"})
            if item["decision"] != "pending":
                continue
            self.assertIn(item["domestic"], {"cn-suffix", "known-brand"}, host)
            self.assertNotIn(item["category"], {"广告追踪", "云服务与CDN"}, host)
            self.assertIsNone(item.get("covered_by"), host)
            self.assertFalse(
                any(host == entry or host.endswith("." + entry) for entry in foreign), host
            )
        pending = [item for item in data["candidates"] if item["decision"] == "pending"]
        self.assertEqual(data["summary"]["pending"], len(pending))
        # 已迁入主数据源的候选必须出现在主数据源；因连通性测试失败转 hold 的也允许。
        main = {(e["host"], e["match"]): e for e in load_data()["entries"]}
        for item in data["candidates"]:
            if item["decision"] != "admitted":
                continue
            entry = main.get((item["host"], "suffix"))
            self.assertIsNotNone(entry, item["host"])
            self.assertIn(entry["decision"], {"allow", "hold"}, item["host"])
            if entry["decision"] == "hold":
                self.assertIn("连通性", entry["reason"], item["host"])
        self.assertEqual(
            data["summary"]["pending"] + data["summary"]["hold"] + data["summary"]["reject"]
            + data["summary"].get("admitted", 0),
            len(data["candidates"]),
        )

    def test_candidate_exclusions_are_foreign_or_tracking(self):
        path = ROOT / "routing/data/strict-whitelist-candidates.json"
        if not path.exists():
            self.skipTest("候选队列尚未生成")
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data["candidates"]:
            if item["decision"] == "reject":
                self.assertEqual(item["category"], "广告追踪", item["host"])
        tracking = {entry["host"] for entry in data.get("excluded_tracking", [])}
        rejected = {item["host"] for item in data["candidates"] if item["decision"] == "reject"}
        self.assertEqual(tracking, rejected)

    def test_no_non_apple_allow_matches_explicit_proxy_rule(self):
        rules_path = ROOT / "routing/evidence/2026-10-30-strict-whitelist/current-rules.json"
        data = load_data()
        if not rules_path.exists():
            self.skipTest("缺少运行规则快照")
        rules = json.loads(rules_path.read_text(encoding="utf-8"))["rules"]
        proxy = [r for r in rules if r["target"] == "proxy"
                 and r["type"] in ("Domain", "DomainSuffix", "DomainKeyword")]
        for entry in (e for e in data["entries"] if e["decision"] == "allow" and e["group"] != "apple"):
            host = entry["host"]
            for rule in proxy:
                payload = rule["payload"]
                matched = (
                    (rule["type"] == "Domain" and host == payload)
                    or (rule["type"] == "DomainSuffix" and (host == payload or host.endswith("." + payload)))
                    or (rule["type"] == "DomainKeyword" and payload in host)
                )
                self.assertFalse(matched, f"{host} 被订阅代理规则 {payload} 要求代理，不得进入校园直连")
        self.assertIn("qq.com", {e["host"] for e in data["entries"] if e["decision"] == "allow"})

    def test_connectivity_queue_covers_allow_entries(self):
        path = ROOT / "routing/evidence/2026-11-01-strict-whitelist/connectivity-queue.json"
        if not path.exists():
            self.skipTest("连通性队列尚未生成")
        queue = {item["host"] for item in json.loads(path.read_text(encoding="utf-8"))["candidates"]}
        data = load_data()
        allow = [e for e in data["entries"] if e["decision"] == "allow"]
        for entry in allow:
            host = entry["host"]
            if host == "campus.example" or host.endswith(".campus.example"):
                continue
            self.assertIn(host, queue, host)
            if entry["match"] == "suffix" and entry["group"] != "apple":
                self.assertIn("www." + host, queue, host)
        self.assertGreater(len(queue), 500)


if __name__ == "__main__":
    unittest.main()
