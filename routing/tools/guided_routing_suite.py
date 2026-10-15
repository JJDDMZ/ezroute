#!/usr/bin/env python3
"""中文交互实机检查：单次终端会话，保留失败与未知；测试程序不直接写 Clash 配置。"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

from tools.verify_routing_suite import REPO, Step, Transcript, run_step, save_json
from tools.watch_network import summarize_interface

UNSET = object()
APP = Path.home() / 'Applications/EZ Route.app'
REMOTE = {'Trojan', 'Vmess', 'Vless', 'Shadowsocks', 'ShadowsocksR', 'Http', 'Socks5', 'Snell'}
GROUPS = {'Selector', 'URLTest', 'Fallback', 'LoadBalance'}
BUILTINS = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PASS-RULE', 'GLOBAL', 'COMPATIBLE'}
RECOVERY = ('以下恢复方法仅用于测试中止、失败或结束后；正常测试按当前步骤操作，不要提前恢复。\n'
            '恢复方法：\n'
            '1. 在 Mac 控制中心关闭 Wi-Fi 总开关。只断开某个无线网络不等于关闭此开关。\n'
            '2. 用 USB 线连接 Mac 与自己的指定 iPhone；线已连接则保持连接。确认 iPhone 的个人热点已开启。\n'
            '3. Clash Verge 未运行时启动它，并确认 TUN（虚拟网卡）开关已开启；已经运行则不要重复启动。\n'
            '4. EZ Route 未运行时启动固定安装的应用；然后打开其设置，开启“自动路由”。\n'
            '5. 等待 EZ Route 显示“自动路由已应用”，且“当前识别”为“USB 手机热点”。若仍异常，保持 Mac Wi-Fi 关闭并保留日志。\n'
            '6. 测试已结束且上述状态确认后，再按日常需要恢复 Mac Wi-Fi。恢复过程中保持 USB 线连接，不改热点登记或节点选择。')
PLAN = [
    ('G01', '确认 USB 线连接自己的指定 iPhone，手机个人热点已开启；程序只读核对安装与保存的 USB 绑定'),
    ('G02', 'USB 线保持连接；关闭 Mac Wi-Fi 总开关，按回车后程序按当前 Clash 生效规则取样'),
    ('G03', 'Mac Wi-Fi 保持关闭；按提示拔掉 USB 线并回车，检查后等恢复提示再插回并回车'),
    ('G04', 'USB 线保持连接、Mac Wi-Fi 保持关闭；回车确认后程序强制终止 EZ Route，确认退出及网络条件后尝试启动；中止时按恢复说明操作'),
    ('G05', 'USB 线保持连接、Mac Wi-Fi 保持关闭；回车确认后程序触发 EZ Route 崩溃，确认退出及网络条件后尝试启动；中止时按恢复说明操作'),
    ('G06', 'USB 线保持连接、Mac Wi-Fi 保持关闭；手动关闭 Clash TUN，检查后按提示恢复 TUN 和自动路由'),
    ('G07', 'USB 线保持连接、Mac Wi-Fi 保持关闭；让 Mac 睡眠约 10 秒，唤醒后回终端按回车'),
    ('G08', 'USB 线保持连接、Mac Wi-Fi 保持关闭；手动重启 Clash 内核，重启完成后回终端按回车'),
    ('G09', 'USB 线保持连接、Mac Wi-Fi 保持关闭；正常退出两应用并停止内核，程序先启动 EZ Route，你再按提示启动 Clash'),
    ('G10', 'USB 线保持连接、Mac Wi-Fi 保持关闭；正常退出两应用并停止内核，你先按提示启动 Clash，程序再启动 EZ Route'),
    ('G11', '先保持 USB 连接并连接自己的已登记手机 Wi-Fi；随后按分段提示拔线、关闭 Wi-Fi、重新连接同一热点'),
    ('G12', '重新连接 USB 线并关闭 Mac Wi-Fi 总开关，按回车后程序执行 UDP/TCP DNS 检查'),
    ('G13', '在 EZ Route 设置中完成一次全部网站测试，再启动第二次测试并取消；回终端统一记录界面反馈'),
    ('G14', '程序核对登记和节点选择，保存整轮汇总；出现结束提示后才恢复日常 Wi-Fi'),
]


class StopSuite(Exception):
    pass


def command(arguments, timeout=8):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout)
    if result.returncode:
        raise StopSuite('本机命令未完成；仅记录失败，不转储命令的敏感输出。')
    return result.stdout


class LocalHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1)
        self.sock.connect(self.host)


def api(path):
    if path not in {'/configs', '/proxies', '/rules', '/connections'}:
        raise ValueError('unsupported-read')
    conn = LocalHTTP(f'/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock')
    try:
        conn.request('GET', path, headers={'Host': 'localhost'})
        response = conn.getresponse()
        if response.status != 200:
            raise OSError('controller-unavailable')
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ValueError('response-too-large')
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError('malformed-response')
        return value
    finally:
        conn.close()


def connection_rows(response):
    if 'connections' not in response:
        raise ValueError('missing-connections')
    rows = response['connections']
    if rows is None:
        return []
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('malformed-connections')
    return rows


def preferences():
    return plistlib.loads(command(['/usr/bin/defaults', 'export', 'dev.ezswitch.app', '-']))


def wifi_interface(text):
    match = re.search(r'Hardware Port: (?:Wi-Fi|AirPort)\s+Device: (en\d+)\b', text)
    return match.group(1) if match else None


def owned_app_pids(text, uid, executable):
    found = []
    for row in text.splitlines():
        fields = row.strip().split(None, 2)
        if len(fields) == 3 and fields[0].isdigit() and fields[1] == str(uid) and fields[2] == str(executable):
            found.append(int(fields[0]))
    return found


def app_pids():
    return owned_app_pids(command(['/bin/ps', '-ax', '-o', 'pid=,uid=,comm=']).decode(), os.getuid(), APP / 'Contents/MacOS/EZSwitch')


def interface_state(name):
    result = subprocess.run(['/sbin/ifconfig', name], capture_output=True, timeout=4)
    text = result.stdout.decode(errors='replace')
    value = summarize_interface(text)
    ipv6 = any(not a.lower().startswith(('fe80:', '::1')) for a in re.findall(r'\binet6 (\S+)', text))
    return {'readable': result.returncode == 0, 'online': value['active'] and bool(value['ipv4']),
            'active_ip': value['active'] and (bool(value['ipv4']) or ipv6)}


def safe_interface(value):
    return value if isinstance(value, str) and re.fullmatch(r'en\d+', value) else 'unknown'


def receive_exact(client, size, deadline=None):
    data = b''
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('frame-deadline')
            client.settimeout(remaining)
        chunk = client.recv(size - len(data))
        if not chunk:
            raise OSError('incomplete-frame')
        data += chunk
    return data


def runtime_summary(g, adapters, rules):
    remote = {n: p for n, p in adapters.items() if p.get('type') in REMOTE}
    unsupported = [n for n, p in adapters.items() if n not in BUILTINS | {'EZ-Campus', 'EZ-USB-DNS'} and p.get('type') not in REMOTE | GROUPS]
    unsafe = sum(bool(set(p.get('all', [])) & {'DIRECT', 'PASS', 'PASS-RULE', 'GLOBAL', 'COMPATIBLE', 'EZ-Campus', 'EZ-USB-DNS'})
                 for n, p in adapters.items() if n not in BUILTINS and p.get('type') in GROUPS)
    blocked_types = {'DIRECT': 'Direct', 'REJECT': 'Reject', 'REJECT-DROP': 'RejectDrop',
                     'PASS': 'Pass', 'PASS-RULE': 'PassRule', 'COMPATIBLE': 'Compatible', 'GLOBAL': 'Selector'}
    blocked = (g.get('mode') == 'rule' and g.get('tun', {}).get('enable') is True
               and set(adapters) <= set(blocked_types)
               and all(p.get('type') == blocked_types[n] for n, p in adapters.items())
               and set(adapters.get('GLOBAL', {}).get('all', [])) <= set(blocked_types)
               and len(rules) == 1 and rules[0].get('type') == 'Match'
               and rules[0].get('payload', '') == '' and rules[0].get('proxy') == 'REJECT')
    port = next((v for v in (g.get('mixed-port'), g.get('port')) if type(v) is int and 1 <= v <= 65535), None)
    return {'readable': True, 'mode': g.get('mode') if g.get('mode') in {'rule', 'direct', 'global'} else 'unknown', 'tun': g.get('tun', {}).get('enable') is True,
            'core_interface': safe_interface(g.get('interface-name')), 'remote_count': len(remote),
            'remote_bindings': dict(Counter(safe_interface(p.get('interface')) for p in remote.values())),
            'reserved_direct_types': all(adapters.get(n, {}).get('type') == 'Direct' for n in ('EZ-Campus', 'EZ-USB-DNS')),
            'direct_interface': safe_interface(adapters.get('EZ-Campus', {}).get('interface')),
            'dns_interface': safe_interface(adapters.get('EZ-USB-DNS', {}).get('interface')),
            'unsupported_count': len(unsupported), 'unsafe_group_count': unsafe,
            'blocked': blocked, 'entry_port': port, 'runtime_dns_upstream_verified': False}


def phone_mode(s, interface):
    c = s.get('controller', {})
    return (s.get('snapshot_complete') is True and c.get('readable') and c.get('mode') == 'rule' and c.get('tun') is True
            and c.get('remote_count', 0) > 0 and c.get('remote_bindings') == {interface: c['remote_count']}
            and c.get('core_interface') == c.get('direct_interface') == c.get('dns_interface') == interface
            and c.get('reserved_direct_types') and c.get('unsupported_count') == 0 and c.get('unsafe_group_count') == 0
            and s.get('auto_routing') is True and s.get('app_count') == 1
            and s.get('selection_preserved') is not False and s.get('registration_preserved') is True)


def paused_mode(s):
    return (s.get('snapshot_complete') is True and s.get('app_count') == 1
            and s.get('registration_preserved') is True and s.get('auto_routing') is False
            and s.get('controller', {}).get('readable') is True and s['controller'].get('tun') is False)


def controller_absent(s):
    return s.get('controller_checked') is True and s.get('controller_unavailable') is True


def sleep_events(text, since):
    counts = Counter()
    for row in text.splitlines():
        match = re.match(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ([+-]\d{4})\s+(Sleep|Wake)\s', row)
        if match:
            moment = datetime.strptime(match[1] + ' ' + match[2], '%Y-%m-%d %H:%M:%S %z').timestamp()
            if moment >= since:
                counts[match[3]] += 1
    return dict(counts)


def sleep_diagnostics(since):
    result = {'source': 'pmset -g log', 'timeout_seconds': 12,
              'since_timestamp': since, 'events': {}}
    try:
        text = command(['/usr/bin/pmset', '-g', 'log'], timeout=12).decode(errors='replace')
        result['events'] = sleep_events(text, since)
        result['read_status'] = 'complete'
    except subprocess.TimeoutExpired as error:
        result.update(read_status='timeout', error_type=type(error).__name__)
    except Exception as error:
        result.update(read_status='error', error_type=type(error).__name__)
    return result


class Suite:
    def __init__(self, directory, usb, wifi):
        self.directory, self.usb, self.wifi = directory, usb, wifi
        self.log = Transcript(directory)
        fd = os.open(directory / 'timeline.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.timeline = os.fdopen(fd, 'w', encoding='utf-8')
        self.lock = threading.RLock()
        self.stopping = threading.Event()
        self.thread = None
        self.registration = UNSET
        self.selections = {}
        self.old_id = None
        self.old_socket = None
        self.confirmed_phone = False
        self.results = []
        self.stage = 'G01'
        self.mutations = []

    def say(self, text):
        with self.lock:
            self.log.write(text + '\n')

    def result(self, name, status, **facts):
        item = {'case': name, 'status': status, **facts}
        self.results.append(item)
        labels = {'PASS': '通过（仅限本行范围）', 'FAIL': '失败', 'OBSERVED': '已观察，完整保证未验证', 'UNKNOWN': '未知', 'SKIPPED': '已跳过', 'RUNNING': '正在检查'}
        self.say('【' + name + '】' + labels.get(status, status))
        self.say(json.dumps(item, ensure_ascii=False, sort_keys=True))
        return item

    def ask(self, title, action, recovery=RECOVERY, *, automatic=False, impact=None):
        actor = '程序执行；你只需确认前提' if automatic else '由你手动完成'
        self.say('\n' + title + '\n操作（' + actor + '）：\n' + action)
        self.say('影响：' + (impact or '本步可能暂时中断网络请求。请保持终端窗口打开，测试程序会继续在本机保存日志。'))
        self.say(recovery)
        while True:
            self.say('回车时机：' + ('确认以上前提后按回车，程序才执行本步应用退出操作；不要手动终止或重启应用。'
                                   if automatic else '完成上面的手动操作后，回到本终端按回车；程序收到回车后继续本步流程。'))
            self.say('等待你输入期间，后台仍可能进行只读采样并保存日志；看到新的操作提示后再做下一动作。')
            self.say('尚未操作时可输入 s 并回车跳过当前提示；跳过不会撤销已做的操作。输入 q 并回车或按 Control-C 结束整轮，然后按恢复方法操作。无需回聊天逐项汇报。')
            answer = input('> ').strip().lower()
            if answer == 'q':
                raise KeyboardInterrupt
            if answer == 's':
                self.result(self.stage, 'SKIPPED', reason='用户在终端跳过，不能算通过')
                return False
            if not answer:
                return True
            self.say('直接按回车表示继续；或输入 s／q 后按回车。其他文字不会开始检查。')

    def snapshot(self):
        s = {'time_utc': datetime.now(timezone.utc).isoformat(), 'stage': self.stage,
             'physical_egress_verified': False, 'controller_checked': False, 'controller_unavailable': False,
             'identity_source': '用户手机确认与现有登记；不是独立身份认证'}
        try:
            p = preferences()
            s['auto_routing'] = p.get('EZSwitch.automaticRouting') is True
            s['registration_preserved'] = self.registration is not UNSET and p.get('EZSwitch.registeredHotspots') == self.registration
            s['app_count'] = len(app_pids())
            s['usb'] = interface_state(self.usb)
            s['wifi'] = interface_state(self.wifi)
            power = command(['/usr/sbin/networksetup', '-getairportpower', self.wifi]).decode()
            s['wifi_power_off'] = bool(re.search(r':\s*Off\s*$', power))
            names = command(['/sbin/ifconfig', '-l']).decode().split()
            s['extra_active_interfaces'] = [n for n in names if re.fullmatch(r'en\d+', n) and n not in {self.usb, self.wifi} and interface_state(n)['active_ip']]
            s['controller_checked'] = True
            try:
                g = api('/configs')
            except (OSError, http.client.HTTPException):
                s['controller_unavailable'] = True
                raise
            adapters, rules = api('/proxies').get('proxies', {}), api('/rules').get('rules', [])
            s['controller'] = runtime_summary(g, adapters, rules)
            chosen = {n: v.get('now') for n, v in adapters.items() if v.get('type') == 'Selector' and n != 'GLOBAL'}
            s['selection_preserved'] = all(chosen.get(n) == v for n, v in self.selections.items()) if s['controller']['remote_count'] else None
            rows = connection_rows(api('/connections'))
            s['connection_count'] = len(rows)
            s['old_connection_remaining'] = any(r.get('id') == self.old_id for r in rows) if self.old_id else None
        except Exception as error:
            s.setdefault('controller', {'readable': False, 'error_type': type(error).__name__})
            s['snapshot_complete'] = False
            s['snapshot_error_type'] = type(error).__name__
        else:
            s['snapshot_complete'] = True
        with self.lock:
            self.timeline.write(json.dumps(s, ensure_ascii=False) + '\n')
            self.timeline.flush()
        return s

    def wait(self, predicate, seconds=30):
        end = time.monotonic() + seconds
        last = {}
        while time.monotonic() < end:
            last = self.snapshot()
            if predicate(last):
                return last
            time.sleep(.5)
        return None

    def phone_guard(self, s, allow_wifi=False):
        return (self.confirmed_phone and s.get('extra_active_interfaces') == [] and s.get('usb', {}).get('online') is True
                and (s.get('wifi_power_off') is True or (allow_wifi and s.get('wifi', {}).get('online') is True)))

    def baseline(self):
        s = self.wait(lambda s: self.phone_guard(s) and phone_mode(s, self.usb))
        if not s:
            raise StopSuite('未确认 USB 手机模式、Wi-Fi 关闭和恢复状态；停止后续异常操作。')
        return s

    def monitor(self):
        # Fast, read-only controller sampling continues while the user acts.
        # Physical interface and preference guards stay on the foreground path.
        while not self.stopping.is_set():
            s = {'time_utc': datetime.now(timezone.utc).isoformat(), 'stage': self.stage,
                 'sampling_scope': 'controller-only', 'physical_egress_verified': False}
            try:
                s['app_count'] = len(app_pids())
                s['controller'] = runtime_summary(api('/configs'), api('/proxies').get('proxies', {}), api('/rules').get('rules', []))
                rows = connection_rows(api('/connections'))
                s['old_connection_remaining'] = any(r.get('id') == self.old_id for r in rows) if self.old_id else None
            except Exception as error:
                s['controller'] = {'readable': False, 'error_type': type(error).__name__}
            with self.lock:
                if not self.stopping.is_set():
                    self.timeline.write(json.dumps(s, ensure_ascii=False) + '\n')
                    self.timeline.flush()
            self.stopping.wait(1)

    def websites(self, label):
        self.baseline()
        self.say('自动检查：通过 Clash 本地端口测试 5 个固定网站；无系统直连回退。请求或连接记录缺失会标记未知，HTTP 403 不算网页成功。')
        offset = self.log.file.tell()
        row = self.result(label, 'RUNNING')
        step = run_step(Step(label, (str(REPO / '.build/debug/EZRoutingTool'), '--website-tests'), timeout=90), REPO, self.log)
        with self.log.path.open('rb') as handle:
            handle.seek(offset)
            text = handle.read().decode('utf-8', errors='replace')
        records = []
        for line in text.splitlines():
            try:
                value = json.loads(line)
                if value.get('event') == 'site-result':
                    records.append(value['result'])
            except (ValueError, AttributeError):
                pass
        mismatch = any(r.get('strategy') and r.get('configuration_binding_confirmed') is False for r in records)
        row.update(status='FAIL' if mismatch else ('PASS' if step['status'] == 'PASS' and len(records) == 5 else 'UNKNOWN'),
                   sites=records, command_status=step['status'], physical_egress_verified=False)
        self.say('网站检查结果：' + row['status'] + '；此处只核对请求和接口绑定。')
        if mismatch:
            raise StopSuite('站点绑定失配，停止后续探测并保留失败。')

    def rule_tests(self, label):
        from tools.rule_diagnostics import make_plan, probe_case, rule_fingerprint
        self.baseline()
        rules = api('/rules')['rules']
        adapters = api('/proxies')['proxies']
        plan = make_plan(rules, adapters)
        save_json(self.directory, 'rule-plan.json', plan)
        self.say('按当前 Clash 生效规则生成代表测试，不再使用固定 5 网站作为整轮规则验收。')
        self.say('规则总数：' + str(plan['rule_count']) + '；类型：' + json.dumps(plan['rule_types'], ensure_ascii=False)
                 + '；选取目标：' + str(len(plan['cases'])) + '；其余规则不算实机通过。')
        if not plan['cases']:
            self.result(label, 'UNKNOWN', reason='没有可安全生成 HTTPS 目标的显式域名规则', rule_count=plan['rule_count'])
            return
        for i, case in enumerate(plan['cases'], 1):
            self.baseline()
            name = label + '-' + str(i)
            self.say('规则样本 ' + str(i) + '/' + str(len(plan['cases'])) + '：' + case['rule_type'] + ' ' + case['host']
                     + ' → ' + {'direct': '直连', 'proxy': '代理', 'reject': '拒绝'}.get(case['expected_kind'], '未知'))
            row = self.result(name, 'RUNNING', rule_index=case['rule_index'], host=case['host'])
            try:
                observed_hash = rule_fingerprint(api('/rules')['rules'])
                if observed_hash != plan['rule_fingerprint']:
                    row.update(status='UNKNOWN', reason='规则内容、顺序或启停状态在整轮中改变，停止继续请求',
                               expected_rule_fingerprint=plan['rule_fingerprint'], observed_rule_fingerprint=observed_hash)
                    raise StopSuite('生效规则已变化；保留此前结果，不继续请求。')
                value = probe_case(case, rules, adapters, api('/configs'), self.usb, api)
            except StopSuite:
                raise
            except Exception as error:
                value = {**case, 'status': 'UNKNOWN', 'error_type': type(error).__name__, 'physical_egress_verified': False}
            row.update(value)
            self.say('路由判定：' + {'PASS': '通过该规则与接口核对', 'FAIL': '失配', 'UNKNOWN': '缺证，未知',
                                    'OBSERVED': '命中另一规则，未通过原样本', 'SKIPPED': '跳过，不算通过'}.get(row['status'], row['status'])
                     + '；网站 HTTP：' + str(row.get('http_status', '未取得响应')) + '（与路由判定分开）')
            self.say(json.dumps(row, ensure_ascii=False, sort_keys=True))
            if row['status'] == 'FAIL':
                raise StopSuite('规则或出口绑定失配，停止后续异常测试。')
        self.baseline()

    def keep_old_connection(self):
        s = self.baseline()
        port = s['controller']['entry_port']
        if not port:
            self.result('G03-old-connection', 'UNKNOWN', reason='没有可用本地代理端口')
            return
        raw = None
        try:
            raw = socket.create_connection(('127.0.0.1', port), timeout=4)
            local_port = raw.getsockname()[1]
            raw.sendall(b'CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n')
            header = b''
            while b'\r\n\r\n' not in header and len(header) <= 8192:
                chunk = raw.recv(1)
                if not chunk:
                    raise OSError('connect-closed')
                header += chunk
            if not re.match(rb'HTTP/1\.[01] 200(?: |\r)', header):
                raise OSError('connect-not-accepted')
            self.old_socket = ssl.create_default_context().wrap_socket(raw, server_hostname='github.com')
            raw = None
            adapters = api('/proxies')['proxies']
            for r in connection_rows(api('/connections')):
                m = r.get('metadata', {})
                if (m.get('sourceIP') == '127.0.0.1' and str(m.get('sourcePort')) == str(local_port)
                        and m.get('host') == 'github.com' and any(adapters.get(n, {}).get('type') in REMOTE for n in r.get('chains', []))):
                    self.old_id = r.get('id')
                    break
            self.result('G03-old-connection', 'OBSERVED' if self.old_id else 'UNKNOWN', correlated=self.old_id is not None)
        except Exception as error:
            self.result('G03-old-connection', 'UNKNOWN', error_type=type(error).__name__)
        finally:
            if raw:
                raw.close()

    def blocked_check(self, name):
        s = self.wait(lambda s: s.get('snapshot_complete') is True and s.get('extra_active_interfaces') == [] and s.get('auto_routing') is True and s.get('registration_preserved') is True and s.get('app_count') == 1 and not s.get('usb', {}).get('online') and s.get('wifi_power_off') is True and s.get('controller', {}).get('blocked') is True)
        self.result(name, 'PASS' if s else 'FAIL', scope='无网络后的控制配置；不是切换瞬间抓包', physical_egress_verified=False)
        if not s:
            raise StopSuite('无网络阻断配置未确认；请恢复 USB 后再分析。')
        if self.old_id:
            self.result(name + '-old', 'OBSERVED' if s['old_connection_remaining'] is False else 'FAIL', old_connection_absent=s['old_connection_remaining'] is False, revocation_caused_closure_verified=False, scope='控制接口旧连接观测；自然关闭与撤销因果尚未区分')
        port = s['controller']['entry_port']
        if port:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=2) as client:
                    client.sendall(b'CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n')
                    data = client.recv(4096)
                    rejected = not data or bool(re.match(rb'HTTP/1\.[01] [45]\d\d(?: |\r)', data))
                self.result(name + '-reject', 'OBSERVED' if rejected else 'UNKNOWN', local_proxy_connected=True, connect_rejected=rejected,
                            scope='本地 CONNECT 探测，200 或超时不能证明 HTTPS 可达或不可达')
            except Exception as error:
                self.result(name + '-reject', 'UNKNOWN', error_type=type(error).__name__)

    def interrupt_app(self, sig, title):
        self.baseline()
        if not self.ask(title, '1. USB 线保持连接，iPhone 个人热点保持开启；Mac 的 Wi-Fi 总开关保持关闭。\n'
                        '2. 按回车确认后，程序会' + ('强制终止' if sig == signal.SIGKILL else '触发崩溃并终止') + '固定安装的 EZ Route。确认应用已退出且网络前提仍成立后，程序会尝试自动启动同一应用；若程序中止，请在日志保存后按恢复方法操作。Clash Verge 保持运行，TUN 保持开启。\n'
                        '3. 你不用执行退出、强制退出或启动操作。若 macOS 弹出意外退出提示，请关闭提示，不要点击“重新打开”。',
                        automatic=True, impact='EZ Route 会短暂退出，当前网络请求可能中断。程序会记录退出后的配置与重新启动后的恢复；这不是独立崩溃保护的证明。'):
            return
        self.baseline()
        pids = app_pids()
        if len(pids) != 1:
            raise StopSuite('不能唯一确认固定安装的进程，未发送信号。')
        # Revalidate the same PID and executable immediately before the signal.
        if pids != app_pids():
            raise StopSuite('进程发生变化，未发送信号。')
        self.mutations.append({'case': self.stage, 'action': 'SIGKILL' if sig == signal.SIGKILL else 'SIGABRT'})
        os.kill(pids[0], sig)
        stopped = self.wait(lambda s: s.get('app_count') == 0, seconds=8)
        self.result(self.stage + '-death', 'OBSERVED' if stopped else 'UNKNOWN', app_exit_observed=bool(stopped),
                    core_retains_proxy=bool(stopped and stopped.get('controller', {}).get('remote_count', 0)),
                    independent_crash_protection_verified=False, strict_guarantee='未实现独立崩溃撤销，不计为通过')
        if not stopped:
            raise StopSuite('应用退出未确认；不要重复发送信号。')
        self.launch_app()
        self.baseline()
        self.result(self.stage + '-recovery', 'PASS', scope='应用重新启动后的配置恢复')

    def launch_app(self):
        if app_pids():
            return
        if not self.phone_guard(self.snapshot()):
            raise StopSuite('启动前 USB／Wi-Fi 条件未确认，请按恢复方法操作。')
        self.mutations.append({'case': self.stage, 'action': '启动固定安装'})
        command(['/usr/bin/open', str(APP)])

    def startup_order(self, app_first):
        if not self.ask(('第 9 步' if app_first else '第 10 步') + '：启动顺序准备',
                        '1. USB 线保持连接，iPhone 个人热点保持开启；Mac 的 Wi-Fi 总开关保持关闭。\n'
                        '2. 先确认知道如何从两应用正常退出并停止 Clash 内核。若找不到停止内核的方式，保持两应用运行，输入 s 跳过本步。\n'
                        '3. 点击 Mac 菜单栏中的 EZ Route 图标，选择“退出”，等待应用退出。关闭设置窗口不等于退出应用。\n'
                        '4. 使用 Clash Verge 自身的退出功能，确保其内核也停止。若出现退出时是否保留内核的选项，选择停止内核。不要用系统的强制退出或终端命令结束后台服务。\n'
                        '5. 两应用都退出后回到终端按回车；暂时不要重新启动任一应用。如果已退出部分应用却无法完成准备，请输入 q 结束本轮，等日志路径打印后按恢复方法操作；此时不要输入 s。',
                        impact='两应用及 Clash 内核退出后，代理请求暂时不可用。USB 热点仍保持连接，终端会继续记录。'):
            return
        absent = self.wait(lambda s: s.get('app_count') == 0 and controller_absent(s), seconds=15)
        if not absent:
            self.result(self.stage, 'UNKNOWN', reason='两应用关闭／控制失联前提未成立，不能计为启动顺序测试')
            if not self.ask('启动顺序前提未确认：恢复运行环境', '先启动 Clash Verge 并开启 TUN；再启动固定安装的 EZ Route，在其设置中开启“自动路由”。USB 线保持连接，Mac Wi-Fi 总开关保持关闭。完成后回车，让程序确认恢复。'):
                raise StopSuite('未恢复运行环境，停止其余测试。')
            self.baseline()
            return
        if app_first:
            # The phone guard uses physical state even when the controller is absent.
            if not self.phone_guard(self.snapshot()):
                raise StopSuite('启动前手机／Wi-Fi 条件发生变化。')
            self.launch_app()
            first = self.wait(lambda s: s.get('app_count') == 1 and controller_absent(s), seconds=10)
            if not first:
                self.result(self.stage, 'UNKNOWN', reason='未确认 EZ Route 已先启动且控制器仍不可读，不能判断启动顺序')
                raise StopSuite('启动顺序前提未确认，请恢复两应用后分析。')
            self.result(self.stage + '-controller-absent', 'OBSERVED', controller_readable=False)
            action = 'EZ Route 已由程序先启动，你不用再启动它。现在手动启动 Clash Verge，并确认其 TUN 开关已开启。若 EZ Route 的“自动路由”开关已关闭，请在其设置中重新开启。完成后回到终端按回车；USB 线保持连接，Mac Wi-Fi 保持关闭，不切换节点。'
        else:
            action = '先手动启动 Clash Verge，并确认其 TUN 开关已开启。EZ Route 此时应保持退出状态，不要手动启动它。完成后回到终端按回车；程序确认 Clash 已运行后才会启动 EZ Route。USB 线保持连接，Mac Wi-Fi 保持关闭。'
        if not self.ask(('第 9 步' if app_first else '第 10 步') + '：按指定顺序启动', action):
            raise StopSuite('启动顺序未完成，请按恢复方法操作。')
        if not app_first:
            available = self.wait(lambda s: s.get('snapshot_complete') is True and s.get('app_count') == 0 and s.get('controller', {}).get('tun') is True)
            if not available:
                raise StopSuite('Clash 先启动的前提未确认。')
            self.launch_app()
        self.baseline()
        self.result(self.stage, 'PASS', scope='指定启动顺序的控制接口恢复；不证明首次接管前独立阻断')

    def dns_checks(self):
        self.baseline()
        question = b''.join(bytes([len(p)]) + p.encode() for p in 'www.bilibili.com'.split('.')) + b'\0' + struct.pack('!HH', 1, 1)
        for tcp in (False, True):
            self.baseline()
            ident = secrets.randbelow(65536)
            query = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + question
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    client.connect(('223.5.5.5', 53))
                    client.sendall(struct.pack('!H', len(query)) + query if tcp else query)
                    if tcp:
                        deadline = time.monotonic() + 3
                        header = receive_exact(client, 2, deadline)
                        wanted = struct.unpack('!H', header)[0]
                        data = receive_exact(client, wanted, deadline)
                    else:
                        data = client.recv(4096)
                    response, flags, _, answers, _, _ = struct.unpack('!HHHHHH', data[:12])
                    success = response == ident and bool(flags & 0x8000) and flags & 15 == 0 and answers > 0
                self.result('G12-' + ('TCP' if tcp else 'UDP'), 'OBSERVED' if success else 'UNKNOWN', response_received=success, physical_egress_verified=False)
            except Exception as error:
                self.result('G12-' + ('TCP' if tcp else 'UDP'), 'UNKNOWN', error_type=type(error).__name__)

    def run(self):
        self.say('EZ Route 中文实机串联检查\n日志目录：' + str(self.directory) + '\n物理拔线、网络开关及应用界面操作由你按提示完成，确认与反馈统一在本终端输入。测试全程不连接校园网、不改热点登记、不切换节点或代理组。\n' + RECOVERY)
        self.say('本轮会访问规则样本和少量网站、发送 DNS 请求，并测试 EZ Route 异常退出，会消耗少量手机流量。测试程序不重装应用，不直接写 Clash 配置，也不自动开关 Mac Wi-Fi 或 Clash TUN；EZ Route 仍会按网络变化自动应用路由配置。物理出口、精确切换瞬间、全部 QUIC/DoH/IPv6 和 TUN 绕行不凭此自动通过。')
        self.say('开始前请确认：USB 线连接的是自己的指定 iPhone，且 iPhone 个人热点已开启。Clash Verge 已运行并开启 TUN；EZ Route 已运行并开启“自动路由”。手机身份由你确认，程序不会认证运营商。\n本轮需要连接 Wi-Fi 时，只能选择自己已在 EZ Route 登记的手机热点；没有该条件可在第 11 步跳过，不要为测试新增登记。\n现在输入“手机”并按回车开始；输入其他内容后回车则结束。')
        if input('> ').strip() != '手机':
            raise StopSuite('未确认受控手机环境，没有执行测试。')
        self.confirmed_phone = True
        p = preferences()
        self.registration = p.get('EZSwitch.registeredHotspots')
        if not (p.get('EZSwitch.routingDeviceID') and p.get('EZSwitch.routingDeviceID') == p.get('EZSwitch.bootstrapDeviceID')
                and p.get('EZSwitch.bootstrapUSBInterface') == self.usb):
            raise StopSuite('USB 未匹配应用保存的指定手机绑定，请在设置检查；不要修改配置来凑通过。')
        adapters = api('/proxies').get('proxies', {})
        self.selections = {n: v.get('now') for n, v in adapters.items() if n != 'GLOBAL' and v.get('type') == 'Selector'}
        install = json.loads((REPO / 'routing/evidence/2026-10-10-local-install.json').read_text())
        command(['/usr/bin/codesign', '--verify', '--strict', str(APP)])
        digest = hashlib.sha256((APP / 'Contents/MacOS/EZSwitch').read_bytes()).hexdigest()
        if not install.get('installed') or digest != install.get('executable_sha256'):
            raise StopSuite('固定安装与本轮安装证据不匹配，先分析版本，不执行异常测试。')
        self.result('G01', 'PASS', version=install.get('version'), build=install.get('build'), scope='安装哈希及保存的 USB 绑定；手机身份由用户确认')
        self.thread = threading.Thread(target=self.monitor, daemon=True)
        self.thread.start()
        self.stage = 'G02'
        if not self.ask('第 2 步：仅使用 USB 手机热点', '1. USB 线保持连接，iPhone 个人热点保持开启。\n2. 在 Mac 控制中心关闭 Wi-Fi 总开关，不是只断开某个无线网络；不要关闭 iPhone 的个人热点。\n3. 暂停其他应用的下载；Clash Verge 的 TUN 和 EZ Route 的“自动路由”保持开启。完成后回到终端按回车。'):
            raise StopSuite('未建立异常测试所需的 USB 单出口条件。')
        self.baseline()
        self.rule_tests('G02-rules')
        self.stage = 'G03'
        self.say('第 3 步准备：程序现在先尝试建立并记录一条旧代理连接。USB 线保持连接，Mac Wi-Fi 保持关闭；等下一条“拔掉 USB”操作提示出现后再拔线。')
        self.keep_old_connection()
        if self.ask('第 3 步：拔掉 USB，检查断网与旧连接', '1. Mac 的 Wi-Fi 总开关保持关闭；Clash Verge 和 EZ Route 都保持运行。\n2. 拔下连接 Mac 与 iPhone 的 USB 线；iPhone 个人热点开关保持开启。\n3. 拔线后立即回到本终端按回车，程序才进行本步前台核对。保持 USB 线拔出，直到出现“第 3 步：插回 USB”提示再插回；不要等待联网后才回车。', impact='Mac 暂时没有可用网络，网页和聊天可能断开。终端本地检查及日志保存仍可继续。'):
            self.blocked_check('G03-blocked')
            if not self.ask('第 3 步：插回 USB', '现在用 USB 线重新连接 Mac 与刚才同一部 iPhone。确认 iPhone 个人热点保持开启，Mac 的 Wi-Fi 总开关继续关闭。插线后回到终端按回车，程序会等待 USB 热点和路由恢复。'):
                raise StopSuite('USB 未恢复。')
            self.baseline()
            self.result('G03-recovery', 'PASS', scope='USB 插回后的稳定配置恢复；不证明切换瞬间物理出口')
        if self.old_socket:
            self.old_socket.close(); self.old_socket = None
        self.old_id = None
        self.stage = 'G04'; self.interrupt_app(signal.SIGKILL, '第 4 步：应用强制终止')
        self.stage = 'G05'; self.interrupt_app(signal.SIGABRT, '第 5 步：应用崩溃')
        self.stage = 'G06'
        if self.ask('第 6 步：关闭 Clash 的 TUN', 'USB 线保持连接，iPhone 个人热点保持开启；Mac 的 Wi-Fi 总开关保持关闭。在 Clash Verge 界面关闭 TUN（虚拟网卡）开关，然后回终端按回车。两应用都不要退出，也不要手动关闭 EZ Route 的“自动路由”；程序检查它是否自行暂停。', impact='Clash 的虚拟网卡转发暂时停止，部分网络请求可能失败。程序会检查 TUN 和自动路由的关闭状态；不会替你重开 TUN。'):
            paused = self.wait(lambda s: self.phone_guard(s) and paused_mode(s))
            self.result('G06-paused', 'PASS' if paused else 'FAIL', scope='TUN 关闭后自动路由开关暂停')
            if not self.ask('第 6 步：恢复 TUN 与自动路由', '先在 Clash Verge 开启 TUN（虚拟网卡）；再打开 EZ Route 设置，开启“自动路由”。USB 线保持连接，Mac Wi-Fi 总开关保持关闭。两个开关都恢复后，回到终端按回车。'):
                raise StopSuite('TUN／自动路由未恢复。')
            self.baseline()
        self.stage = 'G07'; self.sleep_check()
        self.stage = 'G08'
        self.baseline()
        if self.ask('第 8 步：重启 Clash 内核', 'USB 线保持连接，iPhone 个人热点保持开启；Mac 的 Wi-Fi 总开关保持关闭。使用 Clash Verge 自身提供的内核重启功能；不要用关闭窗口、开关 TUN 或重装代替。重启完成后，确认 Clash 的 TUN 已开启，再回到终端按回车。EZ Route 保持运行；如果它的“自动路由”已关闭，请重新开启。找不到明确的内核重启入口时，输入 s 跳过。', impact='Clash 内核会短暂停止，代理连接可能中断；程序记录恢复状态，短时中断可能未被采样。'):
            self.baseline()
            self.result('G08', 'OBSERVED', scope='用户确认内核重启后的恢复；短时失联可能未被采样，不计瞬间安全通过')
        self.stage = 'G09'; self.startup_order(True)
        self.stage = 'G10'; self.startup_order(False)
        self.stage = 'G11'
        if self.ask('第 11 步：准备手机无线热点', 'USB 线暂时保持连接，iPhone 个人热点保持开启。开启 Mac 的 Wi-Fi 总开关，并连接自己的、已在 EZ Route 登记的手机热点。此时 USB 和手机 Wi-Fi 同时连接。连接完成后回终端按回车；尚无这个已登记热点条件时，输入 s 跳过整个第 11 步，不要新增或移除登记，也不要连接校园网。'):
            if not self.registration:
                raise StopSuite('没有已登记热点，不能安排无线异常步骤。')
            ready = self.wait(lambda s: self.phone_guard(s, allow_wifi=True) and s.get('wifi', {}).get('online') and phone_mode(s, self.usb))
            if not ready:
                raise StopSuite('USB 优先与已登记手机 Wi-Fi 条件未确认。')
            if not self.ask('第 11 步：切为仅手机 Wi-Fi', '拔下 Mac 与 iPhone 之间的 USB 线；Mac Wi-Fi 保持开启，并保持连接刚才同一个手机热点。拔线后回到终端按回车，程序会等待无线绑定确认。保持 USB 线拔出，直到第 12 步提示重新连接。'):
                raise StopSuite('无线异常步骤未完成，请恢复 USB。')
            if not self.wait(lambda s: not s.get('usb', {}).get('online') and phone_mode(s, self.wifi)):
                raise StopSuite('无线代理绑定未确认，请插回 USB。')
            if not self.ask('第 11 步：关闭 Mac Wi-Fi，检查断网', 'USB 线保持拔出。现在在 Mac 控制中心关闭 Wi-Fi 总开关，然后立即回到终端按回车，程序才进行本步阻断的前台核对。不要关闭 iPhone 个人热点，也不要提前重开 Mac Wi-Fi；等到下一条“恢复手机 Wi-Fi”提示再操作。', impact='Mac 暂时没有可用网络，网页和聊天可能断开；终端本地检查及日志保存仍可继续。'):
                raise StopSuite('无线异常步骤未完成，请恢复 USB。')
            self.blocked_check('G11-blocked')
            if not self.ask('第 11 步：恢复手机 Wi-Fi', 'USB 线保持拔出。开启 Mac 的 Wi-Fi 总开关，重新连接刚才同一个、已登记的自有手机热点。连接完成后回到终端按回车，程序会等待无线恢复；仍不要插 USB，等第 12 步提示再插。'):
                raise StopSuite('无线网络未恢复，请插回 USB。')
            if not self.wait(lambda s: not s.get('usb', {}).get('online') and phone_mode(s, self.wifi)):
                raise StopSuite('无线恢复配置未确认，请插回 USB。')
            self.result('G11-recovery', 'PASS', scope='无线断网异常后的稳定配置；不是重做历史接管抓包')
        self.stage = 'G12'
        if not self.ask('第 12 步：恢复仅 USB，检查 DNS', '用 USB 线连接 Mac 与自己的指定 iPhone；如果线仍连接则保持连接。确认 iPhone 个人热点已开启，并在 Mac 控制中心关闭 Wi-Fi 总开关。Clash TUN 和 EZ Route 的“自动路由”应开启。完成后回终端按回车，程序会等待恢复并执行 UDP/TCP DNS 请求；之后还有第 13 步界面检查和第 14 步汇总。'):
            raise StopSuite('未恢复最终 USB 基线。')
        self.dns_checks()
        self.stage = 'G13'
        self.baseline()
        if self.ask('第 13 步：网站列表与取消操作', 'USB 线保持连接，Mac Wi-Fi 总开关保持关闭。打开 EZ Route 设置中的“网站与出口测试”。\n1. 点击一次“测试全部网站”，等待按钮从“正在测试…”恢复为“测试全部网站”，查看列表与每个网站的结果。\n2. 再点击一次“测试全部网站”；在第二次测试仍运行且“取消”按钮可见时点击“取消”。\n3. 两次操作完成后回到终端按回车，终端随后会询问界面反馈。HTTP 403／405、请求失败或路由未知本身不等于界面操作故障，不要求所有网站通过。', impact='第一次会尝试测试全部固定网站；第二次会发出部分请求直到取消，消耗少量手机流量。不修改网络、节点或路由设置。'):
            self.say('现在输入界面反馈后按回车：1＝网站列表、全部测试按钮和取消操作正常；2＝列表显示、按钮响应或取消操作存在问题；s＝未完成或无法确认；q＝结束整轮并按恢复方法操作。此处只记录界面操作体验，各网站的网络结果另看页面提示，不证明物理出口。')
            answer = input('> ').strip()
            if answer == 'q':
                raise KeyboardInterrupt
            self.result('G13-ui', 'OBSERVED' if answer == '1' else ('FAIL' if answer == '2' else 'UNKNOWN'), user_report=answer if answer in {'1', '2'} else '未确认', scope='用户界面反馈')
        self.stage = 'G14'
        s = self.baseline()
        self.result('G14', 'PASS', registration_preserved=s['registration_preserved'], selection_preserved=s['selection_preserved'])
        self.say('流程已到第 14 步，程序现在保存汇总。请先保持 USB 线连接、Mac Wi-Fi 关闭，等下方日志路径打印后再按恢复方法恢复日常网络。出现 UNKNOWN、OBSERVED 或跳过不等于全部项目通过。')

    def sleep_check(self):
        self.baseline()
        since = time.time()
        if self.ask('第 7 步：让 Mac 睡眠后唤醒', 'USB 线保持连接，iPhone 个人热点保持开启；Mac 的 Wi-Fi 总开关保持关闭。选择 Mac 苹果菜单中的“睡眠”，约 10 秒后唤醒并解锁 Mac。唤醒后回到本终端按回车。不是锁屏，也不是关闭终端；本步不用拔线或操作网络开关。', impact='Mac 睡眠期间测试程序也会暂停，网络连接可能中断；唤醒后程序读取睡眠记录并检查配置恢复。'):
            diagnostic = sleep_diagnostics(since)
            events = diagnostic['events']
            row = self.result('G07', 'RUNNING', sleep_events=events, sleep_diagnostic=diagnostic,
                              scope='实际睡眠／唤醒记录与恢复配置；事务中断时序未证明')
            if diagnostic['read_status'] == 'timeout':
                self.say('系统睡眠日志读取超过 12 秒，已记录超时；本步保持未知，不表示你没有让 Mac 睡眠。')
            elif diagnostic['read_status'] == 'error':
                self.say('系统睡眠日志读取或解析失败，已记录错误类别；本步保持未知。')
            elif not (events.get('Sleep') and events.get('Wake')):
                self.say('系统日志读取完成，但本步没有取得完整的睡眠与唤醒记录；本步保持未知。')
            self.baseline()
            row['status'] = 'PASS' if events.get('Sleep') and events.get('Wake') else 'UNKNOWN'
            self.say('【G07】' + ('通过（仅限本行范围）' if row['status'] == 'PASS' else '未知'))
            self.say(json.dumps(row, ensure_ascii=False, sort_keys=True))

    def finish(self, interrupted=False, failure=None):
        self.stopping.set()
        if self.thread:
            self.thread.join(timeout=15)
        if self.old_socket:
            self.old_socket.close()
        for row in self.results:
            if row['status'] == 'RUNNING':
                row['status'] = 'INTERRUPTED' if interrupted else 'UNKNOWN'
        known = {r['case'].split('-')[0] for r in self.results}
        for name, _ in PLAN:
            if name not in known:
                self.results.append({'case': name, 'status': 'NOT_RUN'})
        summary = {'scope': 'personal-controlled-phone-guided-functional-checks', 'results': self.results,
                   'interrupted': interrupted, 'failure': failure, 'actions': self.mutations,
                   'physical_egress_verified': False, 'strict_protection_verified': False,
                   'coverage': {'startup_recovery': 'see-results', 'app_death': 'observation-only-independent-revocation-absent',
                                'pre_event_boundary': 'NOT_VERIFIED', 'sleep_during_transaction': 'NOT_VERIFIED',
                                'QUIC_DoH_native_IPv6_TUN_bypass': 'NOT_TESTED', 'unknown_historical_packets': 'REMAIN_UNKNOWN'},
                   'recovery': RECOVERY, 'timeline': 'timeline.jsonl'}
        exit_code = 130 if interrupted else (1 if failure or any(r['status'] == 'FAIL' for r in self.results) else 0)
        summary.update(exit_code=exit_code, flow_completed=not interrupted and failure is None and any(r['case'] == 'G14' and r['status'] == 'PASS' for r in self.results), all_results_verified=all(r['status'] == 'PASS' for r in self.results))
        save_json(self.directory, 'summary.json', summary)
        self.say('\n统一汇总：' + json.dumps(dict(Counter(r['status'] for r in self.results)), ensure_ascii=False))
        self.say('PASS 只指该行的范围；OBSERVED、UNKNOWN、SKIPPED、NOT_RUN 均不等于完整保护通过。\n' + RECOVERY)
        self.say('整轮日志文件：' + str(self.log.path) + '\n机器汇总文件：' + str(self.directory / 'summary.json') + '\n请一次性提供上述路径下的 output.log 文件；进一步分析需要时，再提供同一目录中的 summary.json 和 timeline.jsonl。不要发送订阅原文、密码或凭据。')
        self.timeline.close(); self.log.close()
        return exit_code


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', help='只显示中文步骤，不读取网络、不发送请求')
    args = parser.parse_args(arguments)
    if args.plan:
        for name, title in PLAN:
            print(name + '：' + title)
        print(RECOVERY)
        return 0
    if not sys.stdin.isatty():
        parser.error('请在自己的终端交互运行；不要把标准输入接到管道。')
    if os.geteuid() == 0:
        parser.error('请用自己的用户运行，不要加 sudo。')
    os.umask(0o077)
    try:
        p = preferences()
        usb = p.get('EZSwitch.bootstrapUSBInterface')
        wifi = wifi_interface(command(['/usr/sbin/networksetup', '-listallhardwareports']).decode())
        if not isinstance(usb, str) or not re.fullmatch(r'en\d+', usb) or not wifi or usb == wifi:
            raise StopSuite('不能读取有效 USB／Wi-Fi 接口，请先检查 EZ Route 设置，不沿用历史 en5/en0。')
    except Exception as error:
        print(str(error) if isinstance(error, StopSuite) else '只读预检失败：' + type(error).__name__)
        return 2
    directory = Path(tempfile.mkdtemp(prefix='ez-switch-guided-routing.'))
    suite = Suite(directory, usb, wifi)
    previous = signal.getsignal(signal.SIGTERM)
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    interrupted, failure = False, None
    try:
        suite.run()
    except (KeyboardInterrupt, EOFError):
        interrupted = True
        suite.say('用户中断，保留此前结果，不继续网络或进程动作。')
    except Exception as error:
        failure = str(error) if isinstance(error, StopSuite) else type(error).__name__
        suite.say('本轮停止：' + failure)
    finally:
        signal.signal(signal.SIGTERM, previous)
    return suite.finish(interrupted, failure)


if __name__ == '__main__':
    raise SystemExit(main())
