#!/usr/bin/env python3
"""One offline verification run and a strict-live readiness gate.

There is no strict data-plane backend in this repository. Live scenarios are
listed as blocked, never represented by mock execution or automatic network edits.
"""
import argparse
import codecs
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
REPO = Path(__file__).resolve().parents[2]
SCENARIOS = (
    ("S01-A", "事件前首包与无线接口复用", "切换瞬间代理不得进入校园接口", "仅在独立保护已确认的受控环境切换手机与未登记无线网络", "恢复原手机网络；保持代理授权关闭直到重新确认"),
    ("S01-C", "旧 TCP/UDP 传输撤销", "网络授权失效后旧传输不能继承新许可", "保持一个已识别的旧连接并触发授权撤销", "停止探测，恢复原网络后重新授权"),
    ("S02-B1", "应用崩溃", "独立机制撤销许可，不能依赖退出钩子", "受控崩溃 EZ Route；禁止在未确认的校园环境执行", "恢复手机网络，再启动固定安装"),
    ("S02-B2", "应用强制终止", "强制终止后独立保护仍有效", "核对固定安装进程后强制终止；不能替代正常退出测试", "恢复手机网络，再启动固定安装"),
    ("S02-C", "睡眠中断与唤醒", "未确认的睡前事务不算成功，唤醒前先拒绝旧许可", "在控制事务期间睡眠，唤醒后核对许可与包时间", "停止探测，恢复手机网络并重新确认许可"),
    ("S02-D", "Clash 内核重启", "内核重启到重新授权之间无代理校园出站", "从 Clash 界面重启内核，保留完整时间线", "在手机网络恢复内核及原选择，核对保护后再开放"),
    ("S02-E", "两种启动顺序与控制失联", "首次接管前也有独立拒绝，恢复不能授予旧身份", "分别先启动应用和先启动 Clash；受控断开控制接口", "在手机网络恢复控制接口及固定安装"),
    ("S02-F", "事务期间关闭 TUN", "应用不能重开 TUN；绕过 TUN 的流量另计", "从 Clash 界面关闭 TUN，观察应用是否暂停", "按原设置恢复 TUN，显式开启自动路由并重新确认"),
    ("S03", "UDP/QUIC、DNS/DoH、IPv6 与绕过 TUN", "分别关联策略、身份、物理出口；不能用 HTTPS 代替", "使用少量固定协议探测，禁止默认遍历节点", "停止探测并恢复原网络及 TUN 设置"),
    ("S04", "未归类包与历史失败", "未知保持未知；后续成功不能覆盖失败", "分析原始时间线、丢包和缺失关联，保留旧证据", "只读分析无需恢复；不重做旧浏览观察"),
    ("S05", "设置页网站测试与物理出口", "5 个固定站点结果与实际接口分别计证据", "点击一次测试全部网站；保持原节点和网络", "取消测试即可；不自动修改路由配置"),
)


@dataclass(frozen=True)
class Step:
    name: str
    command: tuple
    dependency: str = ""
    timeout: float = 600


class Transcript:
    def __init__(self, directory, console=None):
        self.path = Path(directory) / "output.log"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.file = os.fdopen(fd, "w", encoding="utf-8")
        self.console = sys.stdout if console is None else console

    def write(self, value):
        self.file.write(value)
        self.file.flush()
        if self.console is not None:
            try:
                self.console.write(value)
                self.console.flush()
            except BrokenPipeError:
                self.console = None

    def close(self):
        self.file.close()


def stop_child(process, emit=lambda chunk: None):
    # Keep the leader PID reserved until the group has been signalled.
    try:
        os.killpg(process.pid, signal.SIGTERM)
        time.sleep(.1)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            # Darwin can report EPERM for an exited group. Below, require
            # both an exited leader and EOF from every stdout writer.
            pass
    except ProcessLookupError:
        pass
    process.wait(timeout=3)
    os.set_blocking(process.stdout.fileno(), False)
    while True:
        try:
            chunk = os.read(process.stdout.fileno(), 8192)
        except BlockingIOError:
            raise PermissionError("child-group-cleanup-unconfirmed") from None
        if not chunk:
            break
        emit(chunk)


def run_step(step, cwd, transcript):
    transcript.write("\n[" + step.name + "] START\n")
    process = None
    started = time.monotonic()
    status, code = "FAIL", None
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    try:
        process = subprocess.Popen(step.command, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() - started >= step.timeout:
                    status = "TIMEOUT"
                    stop_child(process, lambda chunk: transcript.write(decoder.decode(chunk)))
                    code = process.returncode
                    break
                for key, _ in selector.select(timeout=.25):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if chunk:
                        transcript.write(decoder.decode(chunk))
                    else:
                        selector.unregister(key.fileobj)
        remaining = max(.01, step.timeout - (time.monotonic() - started))
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            stop_child(process, lambda chunk: transcript.write(decoder.decode(chunk)))
            code = process.returncode
        if status != "TIMEOUT":
            status = "PASS" if code == 0 else "FAIL"
    except OSError as error:
        # Never include arbitrary exception payloads or configuration content.
        transcript.write("Offline command failed: " + type(error).__name__ + "\n")
    finally:
        if process is not None:
            if code is None:
                stop_child(process, lambda chunk: transcript.write(decoder.decode(chunk)))
            transcript.write(decoder.decode(b"", final=True))
            process.stdout.close()
    transcript.write("[" + step.name + "] " + status + "\n")
    return {"name": step.name, "status": status, "exit_code": code}


def run_steps(steps, cwd, transcript, results=None):
    if results is None:
        results = []
    for step in steps:
        if step.dependency and not any(r["name"] == step.dependency and r["status"] == "PASS" for r in results):
            results.append({"name": step.name, "status": "SKIPPED", "reason": "dependency-failed"})
            transcript.write("\n[" + step.name + "] SKIPPED: dependency failed\n")
        else:
            try:
                results.append(run_step(step, cwd, transcript))
            except OSError:
                results.append({"name": step.name, "status": "FAIL", "reason": "child-cleanup-unavailable"})
                raise
            except KeyboardInterrupt:
                results.append({"name": step.name, "status": "INTERRUPTED"})
                raise
    return results


def strict_readiness():
    # This is the capability of the current implementation, not a live account
    # inventory. No JSON receipt, caller boolean or command-line bypass can turn
    # an absent backend into a verified runtime enforcement mechanism.
    return {"status": "BLOCKED", "strict_backend_implemented": False,
            "strict_live_executor_implemented": False,
            "runtime_provider_activated_verified": False,
            "pre_send_process_interface_binding_verified": False,
            "reasons": ["strict-data-plane-backend-absent",
                        "pre-send-process-interface-binding-unproved",
                        "wireless-pre-event-identity-unproved",
                        "provider-runtime-permission-and-failure-behavior-unverified"],
            "distribution_signing_required": False}


def live_plan():
    return [{"id": ident, "question": title, "criterion": criterion,
             "action": action, "recovery": recovery, "status": "BLOCKED_NOT_RUN"}
            for ident, title, criterion, action, recovery in SCENARIOS]


def offline_steps(source_root=None):
    steps = [Step("Swift", ("./script/test.sh",)),
             Step("Python", ("/usr/bin/python3", "-m", "unittest", "discover", "-s", "routing", "-p", "test_*.py")),
             Step("Node", ("node", "--test", *[str(p.relative_to(REPO)) for p in sorted((REPO / "routing").glob("*.test.cjs"))])),
             Step("Build", ("./script/build_and_run.sh", "--build-only")),
             Step("Signature", ("/usr/bin/codesign", "--verify", "--deep", "--strict", "dist/EZ Route.app"), "Build"),
             Step("FilterAPIAndModels", ("./script/probe-filter-classification.sh",))]
    if source_root is not None:
        base = Path(source_root).resolve() / "hardening/routing-protection/artifacts"
        steps += [Step("PinnedClassification", ("/usr/bin/python3", "routing/prototypes/filter-classification/probe.py", "--source-dir", str(base / "classification/mihomo"))),
                  Step("PinnedExecutorHandoff", ("/usr/bin/python3", "routing/prototypes/executor-separation/probe.py", "--source-dir", str(base / "executor-separation/mihomo")))]
    return steps


def save_json(directory, name, value):
    fd = os.open(Path(directory) / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")


def main(arguments=None):
    raw = list(sys.argv[1:] if arguments is None else arguments)
    if '--guided' in raw:
        from tools.guided_routing_suite import main as guided_main
        raw.remove('--guided')
        return guided_main(raw)
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--guided", action="store_true", help="中文逐步实机检查；--guided --plan 只显示步骤")
    modes.add_argument("--offline", action="store_true", help="Run offline checks only; exit 0 says nothing about strict protection")
    modes.add_argument("--preflight", action="store_true", help="Write readiness and scenario plan without running suites")
    modes.add_argument("--current", action="store_true", help="Build and run existing fixed-site diagnostics once; no configuration edits")
    modes.add_argument("--live", action="store_true", help="Request strict live acceptance; currently blocked before any action")
    parser.add_argument("--source-root", type=Path, help="Optional returned Codex Security collection root for pinned source checks")
    args = parser.parse_args(arguments)
    os.umask(0o077)
    directory = Path(tempfile.mkdtemp(prefix="ez-switch-routing-verification."))
    transcript = Transcript(directory)
    summary = {"schema_version": 1, "live_configuration_modified": False, "started_at": datetime.now(timezone.utc).isoformat(),
               "scope": "offline-checks-and-strict-readiness-only", "output_directory": str(directory),
               "offline_steps": [], "readiness": strict_readiness(), "live_scenarios": live_plan(),
               "live_actions_executed": False, "physical_egress_verified": False,
               "strict_acceptance_passed": False}
    exit_code = 78
    previous_term = signal.getsignal(signal.SIGTERM)
    def terminate(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        transcript.write("EZ Route unified verification\nLog: " + str(transcript.path) + "\n")
        transcript.write("No app install/launch, packet capture or network configuration changes.\n")
        if not args.preflight and not args.live:
            steps = offline_steps(args.source_root)
            if args.current:
                steps = [step for step in steps if step.name in {"Build", "Signature"}]
                steps.append(Step("CurrentWebsites", (str(REPO / ".build/debug/EZRoutingTool"), "--website-tests"), "Signature", timeout=90))
                summary["scope"] = "current-binding-and-fixed-website-diagnostics"
                transcript.write("Explicit current-site diagnostics: up to five fixed HTTPS requests via Clash; no direct fallback.\n")
            summary["offline_steps"] = run_steps(steps, REPO, transcript, summary["offline_steps"])
            summary["website_diagnostic_started"] = any(r["name"] == "CurrentWebsites" and r["status"] != "SKIPPED" for r in summary["offline_steps"])
            summary["live_actions_executed"] = summary["website_diagnostic_started"]
            if args.source_root is None and not args.current:
                summary["offline_steps"].append({"name": "PinnedSources", "status": "SKIPPED", "reason": "source-root-not-supplied"})
                transcript.write("\n[PinnedSources] SKIPPED: source root not supplied\n")
            failed = any(r["status"] in {"FAIL", "TIMEOUT"} for r in summary["offline_steps"])
            summary["checks_passed" if args.current else "offline_checks_passed"] = not failed
            exit_code = 1 if failed else 0
        transcript.write("\nDeferred strict system-layer acceptance: NOT IMPLEMENTED (not a prerequisite for current personal-use checks)\n")
        for reason in summary["readiness"]["reasons"]:
            transcript.write("- " + reason + "\n")
        for item in summary["live_scenarios"]:
            transcript.write(item["id"] + ": " + item["status"] + " — " + item["question"] + "\n")
        transcript.write("An offline PASS does not close any blocked live scenario.\n")
    except Exception as error:
        summary["internal_failure"] = type(error).__name__
        exit_code = 1
        transcript.write("\nVerification aborted: " + type(error).__name__ + "; inspect retained output.\n")
    except KeyboardInterrupt:
        summary["interrupted"] = True
        exit_code = 130
        transcript.write("\nInterrupted: offline child stopped; no live state needs restoring.\n")
    finally:
        summary["website_diagnostic_started"] = any(
            r["name"] == "CurrentWebsites" and r["status"] != "SKIPPED"
            for r in summary["offline_steps"])
        summary["live_actions_executed"] = summary["website_diagnostic_started"]
        summary["finished_at"] = datetime.now(timezone.utc).isoformat()
        summary["exit_code"] = exit_code
        save_json(directory, "summary.json", summary)
        save_json(directory, "live-plan.json", summary["live_scenarios"])
        transcript.write("\nExit: " + str(exit_code) + "\nSummary: " + str(directory / "summary.json") + "\n")
        transcript.close()
        signal.signal(signal.SIGTERM, previous_term)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
