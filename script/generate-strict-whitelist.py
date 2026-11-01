#!/usr/bin/env python3
"""从单一数据源生成严格无线名单的 Swift 数组与证据快照。

数据源：routing/data/strict-whitelist.json
生成物：
- Sources/EZSwitchCore/RoutingStrictDomains.swift
- routing/evidence/<revision 所在日期>-strict-whitelist/merged-whitelist.json
- routing/evidence/<...>/merged-whitelist.md

用法：
    python3 script/generate-strict-whitelist.py
    python3 script/generate-strict-whitelist.py --check   # 只校验生成物是否最新
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "routing/data/strict-whitelist.json"
SWIFT = ROOT / "Sources/EZSwitchCore/RoutingStrictDomains.swift"
EVIDENCE_DATE = "2026-11-01"
EVIDENCE_DIR = ROOT / "routing/evidence" / f"{EVIDENCE_DATE}-strict-whitelist"
MAX_DSN_LEN = 255


class DataError(Exception):
    pass


def load(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DataError(f"缺少数据文件：{path}") from error
    except json.JSONDecodeError as error:
        raise DataError(f"数据文件不是合法 JSON：{error}") from error


def validate(data: dict) -> None:
    if data.get("schema") != 1:
        raise DataError("schema 必须为 1")
    if not data.get("revision"):
        raise DataError("缺少 revision")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise DataError("entries 不能为空")

    seen: dict[tuple[str, str], str] = {}
    groups = {"domestic": 0, "apple": 0, "campus": 0}
    for entry in entries:
        host = entry.get("host")
        match = entry.get("match")
        group = entry.get("group")
        decision = entry.get("decision")
        if not host or not isinstance(host, str):
            raise DataError(f"条目缺少 host：{entry}")
        if match not in ("suffix", "exact"):
            raise DataError(f"{host} 的 match 必须是 suffix 或 exact")
        if group not in groups:
            raise DataError(f"{host} 的 group 不合法：{group}")
        if decision not in ("allow", "hold", "reject", "pending"):
            raise DataError(f"{host} 的 decision 不合法：{decision}")
        if "*" in host or host.startswith("+.") or "/" in host:
            raise DataError(f"{host} 不是精确域名或后缀")
        if len(host) > MAX_DSN_LEN or any(not label for label in host.split(".")):
            raise DataError(f"{host} 不是合法主机名")
        if host != host.lower():
            raise DataError(f"{host} 必须小写")
        key = (host, match)
        if key in seen:
            raise DataError(f"重复条目：{host}（{match}）")
        seen[key] = group
        if decision == "allow":
            groups[group] += 1

    if groups["apple"] == 0 or groups["domestic"] == 0:
        raise DataError("domestic 与 apple 组都必须有 allow 条目")

    allowed = {(e["host"], e["match"]) for e in entries if e["decision"] == "allow"}
    suffix_hosts = {e["host"] for e in entries if e["decision"] == "allow" and e["match"] == "suffix"}
    exact_hosts = {e["host"] for e in entries if e["decision"] == "allow" and e["match"] == "exact"}

    for host in sorted(exact_hosts):
        if any(host == s or host.endswith("." + s) for s in suffix_hosts):
            raise DataError(f"精确主机 {host} 已被后缀条目覆盖，删掉重复项")
    for host in sorted(exact_hosts & {e["host"] for e in entries if e["group"] == "apple"}):
        if any(e["host"] == host and e["group"] != "apple" for e in entries):
            raise DataError(f"{host} 同时出现在 Apple 与非 Apple 组")

    exclusions = data.get("exclusions") or {}
    for kind in ("telemetry", "foreign_sensitive"):
        for item in exclusions.get(kind) or []:
            host = item["host"]
            match = item.get("match", "exact")
            if match == "exact" and (host, "exact") in allowed:
                raise DataError(f"排除项 {host} 同时是精确许可，冲突")
            if match == "suffix" and (host, "suffix") in allowed:
                raise DataError(f"排除项 {host} 同时是后缀许可，冲突")
            if match == "suffix":
                for exact in exact_hosts:
                    if exact == host or exact.endswith("." + host):
                        raise DataError(f"排除后缀 {host} 会挡住精确许可 {exact}")

    dns_extra = data.get("dns_extra") or []
    if len(set(dns_extra)) != len(dns_extra):
        raise DataError("dns_extra 有重复")
    for host in dns_extra:
        if host in suffix_hosts or host in exact_hosts or host.startswith("www.") and host[4:] in suffix_hosts:
            raise DataError(f"dns_extra 里的 {host} 可由后缀或精确主机派生，不应重复维护")
        covered = host in exact_hosts or any(host == s or host.endswith("." + s) for s in suffix_hosts)
        if not covered:
            raise DataError(f"dns_extra 里的 {host} 没有任何许可覆盖")


def pack(items: list[str], per_line: int = 4) -> str:
    lines = []
    for index in range(0, len(items), per_line):
        chunk = items[index:index + per_line]
        lines.append("        " + ", ".join(f'"{item}"' for item in chunk) + ",")
    return "\n".join(lines)


def swift_source(data: dict) -> str:
    allow = [e for e in data["entries"] if e["decision"] == "allow"]
    suffixes = sorted(e["host"] for e in allow if e["match"] == "suffix")
    exact = sorted(e["host"] for e in allow if e["match"] == "exact" and e["group"] == "domestic")
    apple = sorted(e["host"] for e in allow if e["group"] == "apple")
    excluded = data.get("exclusions") or {}
    telemetry = excluded.get("telemetry") or []
    foreign = excluded.get("foreign_sensitive") or []
    excluded_suffixes = sorted({i["host"] for i in foreign if i.get("match", "exact") == "suffix"})
    excluded_hosts = sorted(
        {i["host"] for i in telemetry if i.get("match", "exact") == "exact"}
        | {i["host"] for i in foreign if i.get("match", "exact") == "exact"}
    )
    dns_extra = sorted(data.get("dns_extra") or [])
    counts = {
        "non_apple_suffixes": len([h for h in suffixes if h != "campus.example"]),
        "campus_suffixes": 1 if "campus.example" in suffixes else 0,
        "non_apple_exact": len(exact),
        "apple_exact": len(apple),
        "excluded_hosts": len(excluded_hosts),
        "excluded_suffixes": len(excluded_suffixes),
        "dns_extra": len(dns_extra),
        "dns_total": len(dns_extra) + 2 * len(suffixes) + len(exact) + len(apple),
    }
    revision = data["revision"]
    return f'''import Foundation

/// 严格无线保护固定名单。由 script/generate-strict-whitelist.py 从
/// routing/data/strict-whitelist.json 生成（revision {revision}）。不要手工修改本文件。
public enum RoutingStrictDomains {{
    /// 校内自有域名与非 Apple 服务父域。子域一并放行。
    public static let suffixes: [String] = [
{pack(suffixes)}
    ]

    /// 非 Apple 的精确主机。
    public static let exact: [String] = [
{pack(exact)}
    ]

    /// Apple 条件主机：关闭“Apple 走代理”时直连，开启时整组走 USB。
    public static let apple: [String] = [
{pack(apple)}
    ]

    /// 上报、统计与遥测端点：映射到 USB 兜底，USB 缺失时拒绝，不授予校园直连。
    public static let excludedHosts: [String] = [
{pack(excluded_hosts)}
    ]

    /// 境外可能涉敏站点：不论是否有父域许可，都不授予校园直连。
    public static let excludedSuffixes: [String] = [
{pack(excluded_suffixes)}
    ]

    /// 需要离线解析的已观察子域。后缀的 apex 与 www 由 knownDNSHosts 派生。
    public static let dnsExtra: [String] = [
{pack(dns_extra)}
    ]

    public static var knownDNSHosts: [String] {{
        dnsExtra + suffixes.flatMap {{ [$0, "www." + $0] }} + exact
    }}

    public static func rules(campus: String) -> [String] {{
        suffixes.map {{ "DOMAIN-SUFFIX,\\($0),\\(campus)" }} +
        exact.map {{ "DOMAIN,\\($0),\\(campus)" }}
    }}
}}
'''


def connectivity_queue(data: dict) -> dict:
    allow = [e for e in data["entries"] if e["decision"] == "allow"]
    hosts: list[str] = []
    for entry in allow:
        if entry["group"] == "apple":
            hosts.append(entry["host"])
            continue
        if entry["host"] == "campus.example" or entry["host"].endswith(".campus.example"):
            continue
        if entry["match"] == "suffix":
            hosts.extend([entry["host"], "www." + entry["host"]])
        else:
            hosts.append(entry["host"])
    for host in data.get("dns_extra") or []:
        if host == "campus.example" or host.endswith(".campus.example"):
            continue
        hosts.append(host)
    return {
        "schema": 1,
        "purpose": "严格无线名单统一连通性测试队列",
        "revision": data["revision"],
        "generated_by": "script/generate-strict-whitelist.py",
        "note": "校内域名不在此队列，需在校园网络内单独验证；探测使用绑定 Wi-Fi 出口的 probe_strict_candidates.py。",
        "candidates": [{"host": host} for host in sorted(set(hosts))],
    }


def merged_json(data: dict) -> dict:
    allow = [e for e in data["entries"] if e["decision"] == "allow"]
    exclusions = data.get("exclusions") or {}
    return {
        "revision": data["revision"],
        "generated_by": "script/generate-strict-whitelist.py",
        "source": "routing/data/strict-whitelist.json",
        "source_sha256": hashlib.sha256(
            json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "non_apple_suffixes": sorted(
            e["host"] for e in allow if e["match"] == "suffix" and e["group"] != "apple" and e["host"] != "campus.example"
        ),
        "campus_suffixes": sorted(e["host"] for e in allow if e["group"] == "campus"),
        "non_apple_exact": sorted(
            e["host"] for e in allow if e["match"] == "exact" and e["group"] != "apple"
        ),
        "apple_exact": sorted(e["host"] for e in allow if e["group"] == "apple"),
        "exclusions": {
            "telemetry": [i["host"] for i in exclusions.get("telemetry") or []],
            "foreign_sensitive": [i["host"] for i in exclusions.get("foreign_sensitive") or []],
        },
        "dns_extra": sorted(data.get("dns_extra") or []),
        "counts": {
            "non_apple_suffixes": len([e for e in allow if e["match"] == "suffix" and e["group"] == "domestic"]),
            "campus_suffixes": len([e for e in allow if e["group"] == "campus"]),
            "non_apple_exact": len([e for e in allow if e["match"] == "exact" and e["group"] == "domestic"]),
            "apple_exact": len([e for e in allow if e["group"] == "apple"]),
        },
    }


def merged_md(data: dict) -> str:
    allow = [e for e in data["entries"] if e["decision"] == "allow"]
    suffixes = sorted(e["host"] for e in allow if e["match"] == "suffix")
    exact = sorted(e["host"] for e in allow if e["match"] == "exact" and e["group"] != "apple")
    apple = sorted(e["host"] for e in allow if e["group"] == "apple")
    exclusions = data.get("exclusions") or {}
    lines = [
        "# 严格无线保护合并名单",
        "",
        f"由 `script/generate-strict-whitelist.py` 从 `routing/data/strict-whitelist.json` 生成，"
        f"revision `{data['revision']}`。不要手工编辑。",
        "",
        f"非 Apple 许可 {len(suffixes) + len(exact)} 条（{len(suffixes)} 个后缀、{len(exact)} 个精确主机），"
        f"Apple 条件许可 {len(apple)} 条，显式排除 "
        f"{len((exclusions.get('telemetry') or [])) + len((exclusions.get('foreign_sensitive') or []))} 条。",
        "",
        "## 服务域名及其子域",
        "",
    ]
    lines += [f"- `{host}`" for host in suffixes]
    lines += ["", "## 精确主机", ""]
    lines += [f"- `{host}`" for host in exact]
    lines += ["", "## Apple 精确主机", ""]
    lines += [f"- `{host}`" for host in apple]
    lines += ["", "## 显式排除", ""]
    for item in exclusions.get("telemetry") or []:
        lines.append(f"- `{item['host']}`（上报／统计）")
    for item in exclusions.get("foreign_sensitive") or []:
        lines.append(f"- `{item['host']}`（境外站点）")
    lines.append("")
    return "\n".join(lines)


def write(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()

    try:
        data = load(DATA)
        validate(data)
    except DataError as error:
        print(f"数据校验失败：{error}", file=sys.stderr)
        return 2

    swift = swift_source(data)
    outputs = {
        SWIFT: swift,
        EVIDENCE_DIR / "merged-whitelist.json": json.dumps(merged_json(data), ensure_ascii=False, indent=1) + "\n",
        EVIDENCE_DIR / "merged-whitelist.md": merged_md(data) + "\n",
        EVIDENCE_DIR / "connectivity-queue.json": json.dumps(connectivity_queue(data), ensure_ascii=False, indent=1) + "\n",
    }

    if options.check:
        stale = [path for path, text in outputs.items() if not path.exists() or path.read_text(encoding="utf-8") != text]
        if stale:
            print("生成物不是最新，请运行 python3 script/generate-strict-whitelist.py：", file=sys.stderr)
            for path in stale:
                print(f"  - {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print("生成物与数据源一致。")
        return 0

    for path, text in outputs.items():
        write(path, text)
        print(f"已生成 {path.relative_to(ROOT)}")
    counts = merged_json(data)["counts"]
    print(
        "数目：非 Apple 后缀 {non_apple_suffixes}，校内后缀 {campus_suffixes}，"
        "非 Apple 精确 {non_apple_exact}，Apple {apple_exact}".format(**counts)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
