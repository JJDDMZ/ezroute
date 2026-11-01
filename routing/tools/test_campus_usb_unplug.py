#!/usr/bin/env python3
"""校园严格保护拔插测试：USB 移除后只保留白名单直连，插回后恢复代理。

脚本只读控制器和接口状态，不写网络配置、不重启 Clash、不终止应用。
物理动作由使用者完成：按提示拔掉、插回 USB。默认全自动检测，无需按键。
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BUILTIN = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "COMPATIBLE", "PASS-RULE"}
OFFLINE_EXPECT = [
    ("campus", "https://lib.campus.example/", "reachable"),
    ("campus", "https://www.bilibili.com/", "reachable"),
    ("campus", "https://www.zhihu.com/", "reachable"),
    ("proxy", "https://www.nature.com/", "blocked"),
    ("proxy", "https://www.gov.cn/", "blocked"),
    ("proxy", "https://www.youtube.com/", "blocked"),
    ("proxy", "https://data.bilibili.com/", "blocked"),
]
RESTORE_EXPECT = [
    ("campus", "https://www.bilibili.com/", "reachable"),
    ("proxy", "https://github.com/", "reachable"),
    ("proxy", "https://www.google.com/", "reachable"),
]


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


class Journal:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.path = directory / "requests.jsonl"

    def write(self, event: str, **fields) -> None:
        row = {"at": now(), "kind": event, **fields}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print = staticmethod(print)


def iface_ipv4(name: str) -> str | None:
    """读取接口的 IPv4；接口不存在或未启用时返回 None。"""
    try:
        output = subprocess.check_output(["/sbin/ifconfig", name], text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) >= 2 and fields[0] == "inet":
            return fields[1]
    return None


class Controller:
    """只读访问本机 Clash 控制接口。"""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self.path = f"/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock"

    def read(self, path: str):
        class Connection(http.client.HTTPConnection):
            def connect(self_inner):
                self_inner.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self_inner.sock.settimeout(self.timeout)
                self_inner.sock.connect(self.path)

        connection = Connection("localhost", timeout=self.timeout)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError(f"控制器返回 {response.status}")
            return json.loads(response.read())
        finally:
            connection.close()


def match_target(rules: list[dict]) -> str | None:
    for rule in reversed(rules):
        if str(rule.get("type", "")).lower() in ("match", "final"):
            return rule.get("proxy")
    return None


def remote_adapters(proxies: dict) -> list[str]:
    names = []
    for name, adapter in proxies.items():
        kind = str(adapter.get("type", "")).lower()
        if name in BUILTIN or kind in ("direct", "reject", "rejectdrop", "reject-drop"):
            continue
        names.append(name)
    return sorted(names)


def snapshot(controller: Controller, wifi: str, usb: str) -> dict:
    config = controller.read("/configs")
    proxies = controller.read("/proxies").get("proxies", {})
    rules = controller.read("/rules").get("rules", [])
    campus = proxies.get("EZ-Campus", {})
    dns = proxies.get("EZ-USB-DNS", {})
    strict_rule = any(
        str(rule.get("type", "")).lower() == "domainsuffix"
        and rule.get("payload") == "campus.example"
        and rule.get("proxy") == "EZ-Campus"
        for rule in rules
    )
    return {
        "mode": config.get("mode"),
        "interface": config.get("interface-name"),
        "tun": (config.get("tun") or {}).get("enable"),
        "rule_count": len(rules),
        "match_target": match_target(rules),
        "campus_interface": campus.get("interface"),
        "dns_interface": dns.get("interface"),
        "remote_adapters": remote_adapters(proxies),
        "strict_rule": strict_rule,
        "fallback_reject": str(match_target(rules) or "").upper().startswith("REJECT"),
        "wifi_ipv4": iface_ipv4(wifi),
        "usb_ipv4": iface_ipv4(usb),
        "at": now(),
    }


def offline_ready(state: dict, wifi: str) -> bool:
    """无 USB 时必须是严格白名单配置，而不是过渡期的全阻断配置。"""
    return (state["strict_rule"]
            and state["fallback_reject"]
            and state["campus_interface"] == wifi
            and not state["remote_adapters"]
            and state["rule_count"] > 100)


def restored_ready(state: dict, wifi: str, usb: str) -> bool:
    return (state["strict_rule"]
            and not state["fallback_reject"]
            and state["campus_interface"] == wifi
            and state["dns_interface"] == usb
            and bool(state["remote_adapters"])
            and state["rule_count"] > 100)


def classify_curl(returncode: int, http_code: str) -> str:
    """curl 退出码与状态码归为可达、被阻断或不确定。"""
    code = (http_code or "").strip()
    reachable = returncode == 0 and code not in ("", "000")
    blocked = returncode != 0 and code in ("", "000")
    if reachable:
        return "reachable"
    if blocked:
        return "blocked"
    return "unknown"


def curl_probe(url: str, timeout: float = 6.0) -> dict:
    env = {key: value for key, value in os.environ.items()
           if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy")}
    started = time.monotonic()
    try:
        result = subprocess.run(
            ["/usr/bin/curl", "-sS", "-o", "/dev/null", "--max-time", str(timeout),
             "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 4, env=env,
        )
        code, returncode, error = result.stdout.strip(), result.returncode, result.stderr.strip()
    except subprocess.TimeoutExpired:
        code, returncode, error = "000", 28, "curl 超时"
    return {
        "url": url,
        "http_code": code or "000",
        "returncode": returncode,
        "seconds": round(time.monotonic() - started, 3),
        "verdict": classify_curl(returncode, code),
        "error": error[:200] if error else None,
    }


def system_host(host: str) -> list[str]:
    """读取 macOS 系统解析缓存中的地址，用于区分缓存与实际规则。"""
    try:
        out = subprocess.run(["/usr/bin/dscacheutil", "-q", "host", "-a", "name", host],
                             capture_output=True, text=True, timeout=5).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    return [line.strip() for line in out.splitlines()
            if line.strip().startswith(("ip_address:", "name:"))]


def curl_resolve(url: str, host: str, address: str, timeout: float = 6.0) -> dict:
    """绕过系统 DNS，直接把域名指到给定地址，验证 fake-IP 映射是否可用。"""
    env = {key: value for key, value in os.environ.items()
           if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy")}
    try:
        result = subprocess.run(
            ["/usr/bin/curl", "-sS", "-o", "/dev/null", "--max-time", str(timeout),
             "--resolve", f"{host}:443:{address}", "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 4, env=env,
        )
        code, returncode, error = result.stdout.strip(), result.returncode, result.stderr.strip()
    except subprocess.TimeoutExpired:
        code, returncode, error = "000", 28, "curl 超时"
    return {"address": address, "http_code": code or "000", "returncode": returncode,
            "verdict": classify_curl(returncode, code), "error": error[:200] if error else None}


def dns_probe(host: str, resolver: str = "198.18.0.2") -> list[str]:
    try:
        result = subprocess.run(["/usr/bin/dig", "+short", "+time=2", "+tries=1",
                                 f"@{resolver}", host],
                                capture_output=True, text=True, timeout=6)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def wait_for(label: str, predicate, timeout: float, journal: Journal) -> bool:
    deadline = time.monotonic() + timeout
    announced = False
    while time.monotonic() < deadline:
        if predicate():
            return True
        if not announced:
            print(f"等待{label}（最多 {int(timeout)} 秒）…", flush=True)
            announced = True
        time.sleep(0.5)
    return False


def probe_set(phase: str, expectations, journal: Journal, timeout: float,
              retries: int = 2) -> list[dict]:
    """期望可达的条目在切换后可能遇到短暂 DNS/TLS 未稳定，重试后再判定。"""
    rows = []
    for kind, url, expected in expectations:
        attempts = []
        for attempt in range(retries + 1):
            row = curl_probe(url, timeout=timeout)
            attempts.append({"verdict": row["verdict"], "http_code": row["http_code"],
                             "returncode": row["returncode"], "error": row["error"]})
            if row["verdict"] == expected:
                break
            if attempt < retries:
                time.sleep(2)
        row.update({"phase": phase, "role": kind, "expected": expected, "attempts": attempts})
        row["ok"] = row["verdict"] == expected
        rows.append(row)
        journal.write("probe", **row)
        mark = "OK" if row["ok"] else "FAIL"
        extra = f"（尝试 {len(attempts)} 次）" if len(attempts) > 1 else ""
        print(f"[{phase}] {mark:4} {url:38} {row['verdict']:9} HTTP {row['http_code']}{extra}", flush=True)
    return rows


def summarize(checks: dict, rows: list[dict]) -> dict:
    failures = []
    for name, ok in checks.items():
        if not ok:
            failures.append(name)
    for row in rows:
        if not row.get("ok"):
            failures.append(f"{row['phase']}:{row['url']}:{row['verdict']}!={row['expected']}")
    return {"verdict": "pass" if not failures else "fail", "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wifi", default="en0")
    parser.add_argument("--usb", default="en6")
    parser.add_argument("--timeout", type=float, default=180, help="等待拔掉或插回的秒数")
    parser.add_argument("--probe-timeout", type=float, default=6)
    parser.add_argument("--outdir", type=Path)
    parser.add_argument("--check", action="store_true", help="只做前置检查，不等待拔插")
    args = parser.parse_args()

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = args.outdir or ROOT / f"routing/evidence/{dt.date.today().isoformat()}-campus-usb-unplug/{stamp}"
    journal = Journal(outdir)
    controller = Controller()
    summary: dict = {"schema": 1, "at": now(), "wifi": args.wifi, "usb": args.usb,
                     "phases": {}, "probes": [], "checks": {}}

    try:
        before = snapshot(controller, args.wifi, args.usb)
    except Exception as error:
        print(f"无法读取 Clash 控制器：{error}", file=sys.stderr)
        return 2
    summary["phases"]["before"] = before
    journal.write("snapshot", phase="before", **before)
    preflight = {
        "strict_rule": before["strict_rule"],
        "campus_on_wifi": before["campus_interface"] == args.wifi,
        "usb_online": bool(before["usb_ipv4"]),
        "wifi_online": bool(before["wifi_ipv4"]),
        "proxy_adapters": bool(before["remote_adapters"]),
        "not_fallback_reject": not before["fallback_reject"],
    }
    summary["checks"].update({f"preflight:{k}": v for k, v in preflight.items()})
    print("前置检查：", json.dumps(preflight, ensure_ascii=False), flush=True)
    if not all(preflight.values()):
        print("前置条件不满足：需要严格保护已在校园 Wi-Fi 生效，USB 与 Wi-Fi 都在线。", file=sys.stderr)
        return 2

    baseline = probe_set("baseline", [("campus", "https://www.bilibili.com/", "reachable"),
                                     ("proxy", "https://github.com/", "reachable")],
                         journal, args.probe_timeout)
    summary["probes"].extend(baseline)
    if not all(row["ok"] for row in baseline):
        print("基线探测失败：当前分流不满足测试前提，未开始拔插。", file=sys.stderr)
        return 2
    if args.check:
        summary["checks"]["baseline"] = True
        print("前置检查通过；去掉 --check 即可开始拔插测试。", flush=True)
        return 0

    print(f"\n请现在拔掉 USB（{args.usb}）。保持 Clash 与 TUN 运行，不要关闭 Wi-Fi。", flush=True)
    print("如果系统弹出“修改网络设置”授权，请点击允许；脚本会等到严格白名单状态生效（最多 90 秒）。", flush=True)
    if not wait_for("USB 移除", lambda: not iface_ipv4(args.usb), args.timeout, journal):
        print("等待 USB 移除超时，未执行任何更改。", file=sys.stderr)
        return 2
    journal.write("event", phase="usb_removed")

    # USB 移除会先经过一个短暂的“全阻断”过渡态（1 条 MATCH,REJECT、无 EZ-Campus）。
    # 必须等到严格白名单状态（含 campus.example 规则和 EZ-Campus 绑定 Wi-Fi）再探测。
    if not wait_for("严格白名单切换到无 USB 状态",
                    lambda: offline_ready(snapshot(controller, args.wifi, args.usb), args.wifi),
                    90, journal):
        print("应用未在 90 秒内进入严格无 USB 配置（仍是全阻断或缺少 campus.example 规则）。"
              "若出现网络设置授权弹窗，请允许后重试；被拒绝时应用会停在阻断状态。", file=sys.stderr)
        return 2
    # 切换后系统 DNS 与 fake-ip 映射需要几秒稳定；先预热校内允许主机的解析。
    time.sleep(5)
    for host in ("lib.campus.example", "www.bilibili.com", "www.zhihu.com"):
        dns_probe(host)
    offline = snapshot(controller, args.wifi, args.usb)
    summary["phases"]["offline"] = offline
    journal.write("snapshot", phase="offline", **offline)
    print("无 USB 配置：", json.dumps({k: offline[k] for k in
          ("match_target", "campus_interface", "dns_interface", "rule_count", "remote_adapters")},
          ensure_ascii=False), flush=True)
    summary["checks"]["offline:fallback_reject"] = offline["fallback_reject"]
    summary["checks"]["offline:strict_rule"] = offline["strict_rule"]
    summary["checks"]["offline:campus_interface"] = offline["campus_interface"] == args.wifi
    summary["checks"]["offline:no_remote_adapters"] = not offline["remote_adapters"]
    summary["checks"]["offline:rule_count"] = offline["rule_count"] > 100
    summary["checks"]["offline:dns_on_wifi"] = offline["dns_interface"] == args.wifi

    offline_dns = {host: dns_probe(host) for host in ("lib.campus.example", "www.bilibili.com")}
    journal.write("dns", phase="offline", answers=offline_dns)
    summary["phases"]["offline_dns"] = offline_dns
    diagnostics = {}
    for host in ("lib.campus.example", "www.bilibili.com", "www.zhihu.com"):
        answers = dns_probe(host)
        fake = next((item for item in answers if item.startswith("198.18.")), None)
        entry = {"tun_answers": answers, "system": system_host(host)}
        if fake:
            entry["explicit_fake_ip"] = curl_resolve(f"https://{host}/", host, fake, args.probe_timeout)
        diagnostics[host] = entry
    summary["phases"]["offline_diagnostics"] = diagnostics
    journal.write("diagnostics", phase="offline", results=diagnostics)

    offline_rows = probe_set("offline", OFFLINE_EXPECT, journal, args.probe_timeout)
    summary["probes"].extend(offline_rows)

    print(f"\n请现在插回 USB（{args.usb}）。", flush=True)
    if not wait_for("USB 恢复", lambda: iface_ipv4(args.usb), args.timeout, journal):
        print("等待 USB 恢复超时。请插回 USB，保持 Clash 与 TUN 运行；应用会自动恢复规则。", file=sys.stderr)
        return 1
    journal.write("event", phase="usb_restored")

    def restored() -> bool:
        return restored_ready(snapshot(controller, args.wifi, args.usb), args.wifi, args.usb)

    if not wait_for("严格配置恢复代理出口", restored, 90, journal):
        print("应用未在 90 秒内恢复代理出口，请检查菜单状态。", file=sys.stderr)
        return 1
    time.sleep(1)
    after = snapshot(controller, args.wifi, args.usb)
    summary["phases"]["restored"] = after
    journal.write("snapshot", phase="restored", **after)
    summary["checks"].update({
        "restored:not_fallback_reject": not after["fallback_reject"],
        "restored:dns_on_usb": after["dns_interface"] == args.usb,
        "restored:proxy_adapters": bool(after["remote_adapters"]),
    })

    restored_rows = probe_set("restored", RESTORE_EXPECT, journal, args.probe_timeout)
    summary["probes"].extend(restored_rows)

    result = summarize(summary["checks"], summary["probes"])
    summary.update(result)
    summary["limitations"] = [
        "只验证控制器规则与工程出口，不做抓包；物理链路仍需包级证据。",
        "拔插过程需要人工操作；脚本不写网络配置，不重启 Clash，不终止应用。",
        "403/405 等站点响应按可达处理；被阻断以连接失败或 000 状态码判定。",
    ]
    summary["outdir"] = str(outdir)
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n",
                                         encoding="utf-8")
    print(f"\n结果：{summary['verdict']}；证据：{outdir}", flush=True)
    if summary["failures"]:
        print("失败项：" + "；".join(summary["failures"]), flush=True)
    return 0 if summary["verdict"] == "pass" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n已中断：没有修改任何网络配置。请确认 USB 状态并保持 Clash/TUN 运行。", file=sys.stderr)
        raise SystemExit(130)
