#!/usr/bin/env python3
"""按指定接口绑定出口，验证候选域名可直连，供严格校园直连白名单准入。"""

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse

sys.dont_write_bytecode = True

IP_BOUND_IF = getattr(socket, 'IP_BOUND_IF', 25)
FAKE_IP_NETWORK = ipaddress.ip_network('198.18.0.0/16')
DEFAULT_RESOLVERS = ['223.5.5.5', '119.29.29.29']
SIOCGIFFLAGS = 0xc0206911
SIOCGIFADDR = 0xc0206921
IFF_UP = 0x1
IFF_RUNNING = 0x40
IFREQ_SIZE = 32
HOST_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


class InterfaceDown(RuntimeError):
    """接口在探测过程中失效。"""


def now_iso():
    """返回带本地时区的 ISO 时间戳。"""
    return datetime.now(timezone.utc).astimezone().isoformat()


def forbidden_address(ip):
    """判断 IPv4 地址是否属于假 IP、私有、回环、链路本地等不可准入范围。"""
    value = ipaddress.IPv4Address(ip)
    if value in FAKE_IP_NETWORK:
        return True
    return (not value.is_global or value.is_private or value.is_loopback or
            value.is_link_local or value.is_reserved or value.is_multicast or
            value.is_unspecified)


def registrable_address_filter(address):
    """返回地址被拒绝的类别；地址可准入时返回 None。"""
    if not forbidden_address(address):
        return None
    if ipaddress.IPv4Address(address) in FAKE_IP_NETWORK:
        return 'fake_ip'
    return 'private_address'


def interface_down_error(error):
    """判断一个系统错误是否意味着指定接口已经失效。"""
    text = str(error).lower()
    return any(marker in text for marker in
               ['no such device', "can't assign requested address",
                'network is down', 'device not configured', 'bad file descriptor'])


def _ifreq(interface):
    """构造 ioctl 使用的接口名结构。"""
    name = interface.encode('utf-8')
    if not name or len(name) >= 16:
        raise ValueError('接口名长度非法')
    return name + b'\x00' * (IFREQ_SIZE - len(name))


def interface_flags(interface):
    """通过 ioctl 读取接口运行标志，不依赖 ifconfig。"""
    request = _ifreq(interface)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        result = fcntl.ioctl(probe.fileno(), SIOCGIFFLAGS, request)
    return struct.unpack_from('H', result, 16)[0]


def interface_ipv4(interface):
    """通过 ioctl 读取接口 IPv4 地址；没有地址时返回 None。"""
    request = _ifreq(interface)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            result = fcntl.ioctl(probe.fileno(), SIOCGIFADDR, request)
        except OSError:
            return None
    if result[17] != socket.AF_INET:
        return None
    return socket.inet_ntoa(result[20:24])


def interface_snapshot(interface):
    """检查接口存在、已启用并具有可用于探测的 IPv4 地址。"""
    try:
        index = socket.if_nametoindex(interface)
    except OSError:
        return {'interface': interface, 'interface_index': None, 'active': False,
                'ipv4': None, 'ready': False, 'flags': 0}
    try:
        flags = interface_flags(interface)
        address = interface_ipv4(interface)
    except (OSError, ValueError):
        flags, address = 0, None
    active = bool(flags & IFF_UP) and bool(flags & IFF_RUNNING)
    usable = False
    if address:
        value = ipaddress.IPv4Address(address)
        usable = not (value.is_loopback or value.is_link_local or
                      value.is_unspecified or value.is_multicast)
    return {'interface': interface, 'interface_index': index, 'active': active,
            'ipv4': address, 'ready': active and usable, 'flags': flags}


def bound_socket(kind, interface_index, timeout):
    """创建绑定到指定接口索引的 IPv4 套接字；绑定失败不降级。"""
    if sys.platform != 'darwin':
        raise OSError('仅支持 macOS 接口绑定')
    connection = socket.socket(socket.AF_INET, kind)
    try:
        connection.settimeout(timeout)
        connection.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, interface_index)
        return connection
    except OSError as error:
        connection.close()
        if interface_down_error(error):
            raise InterfaceDown(str(error)) from error
        raise
    except BaseException:
        connection.close()
        raise


def encode_name(host):
    """把域名编码为 DNS 问题段的标签序列。"""
    return (b''.join(bytes([len(label)]) + label.encode('ascii')
                     for label in host.split('.')) + b'\x00')


def make_query(identifier, host, qtype=1):
    """构造一条递归 DNS 查询报文。"""
    question = encode_name(host) + struct.pack('!HH', qtype, 1)
    return struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + question


def decode_name(data, offset):
    """解析 DNS 名称，支持压缩指针，返回名称和下一个偏移。"""
    labels = []
    resume = None
    hops = 0
    while True:
        if offset >= len(data):
            raise ValueError('DNS 名称越界')
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError('DNS 压缩指针越界')
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if resume is None:
                resume = offset + 2
            offset = pointer
            hops += 1
            if hops > 16:
                raise ValueError('DNS 压缩指针循环')
            continue
        if length & 0xC0:
            raise ValueError('DNS 标签长度非法')
        offset += 1
        if offset + length > len(data):
            raise ValueError('DNS 标签越界')
        labels.append(data[offset:offset + length].decode('ascii', 'replace'))
        offset += length
    return '.'.join(labels), resume if resume is not None else offset


def _txt_strings(data):
    """解析 TXT 记录中的长度前缀字符串。"""
    values, offset = [], 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            break
        values.append(data[offset:offset + length].decode('utf-8', 'replace'))
        offset += length
    return values


def parse_reply(data, identifier):
    """解析 DNS 响应中的 A 记录、CNAME 和 TXT，并保留 rcode。"""
    if len(data) < 12:
        raise ValueError('DNS 响应过短')
    actual, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', data[:12])
    if actual != identifier or not flags & 0x8000:
        raise ValueError('DNS 响应标识或标志不匹配')
    offset = 12
    for _ in range(questions):
        _, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError('DNS 问题段越界')
        offset += 4
    addresses, cnames, texts = [], [], []
    for _ in range(answers):
        _, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError('DNS 答案段越界')
        rtype, rclass, _, length = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        if offset + length > len(data):
            raise ValueError('DNS 记录数据越界')
        rdata = data[offset:offset + length]
        rdata_offset = offset
        offset += length
        if rclass != 1:
            continue
        if rtype == 1 and length == 4:
            addresses.append(socket.inet_ntoa(rdata))
        elif rtype == 5:
            cname, _ = decode_name(data, rdata_offset)
            cnames.append(cname)
        elif rtype == 16:
            texts.extend(_txt_strings(rdata))
    return {'rcode': flags & 15, 'truncated': bool(flags & 0x0200),
            'addresses': addresses, 'cnames': cnames, 'texts': texts}


def query_dns(host, resolver, interface_index, timeout, qtype=1):
    """通过绑定接口向单个解析器查询一条 DNS 记录。"""
    identifier = int.from_bytes(os.urandom(2), 'big')
    started = time.monotonic()

    def failure(timed_out, truncated=False):
        return {'resolver': resolver, 'addresses': [], 'cnames': [], 'texts': [],
                'rcode': None, 'timed_out': timed_out, 'failed': not timed_out,
                'truncated': truncated,
                'seconds': round(time.monotonic() - started, 3)}

    try:
        connection = bound_socket(socket.SOCK_DGRAM, interface_index, timeout)
    except InterfaceDown:
        raise
    except OSError:
        return failure(timed_out=False)
    try:
        with connection:
            connection.connect((resolver, 53))
            connection.send(make_query(identifier, host, qtype))
            data = connection.recv(4096)
    except socket.timeout:
        return failure(timed_out=True)
    except OSError as error:
        if interface_down_error(error):
            raise InterfaceDown(str(error)) from error
        return failure(timed_out=False)
    try:
        parsed = parse_reply(data, identifier)
    except ValueError:
        return failure(timed_out=False)
    return {'resolver': resolver, 'addresses': parsed['addresses'],
            'cnames': parsed['cnames'], 'texts': parsed['texts'],
            'rcode': parsed['rcode'], 'timed_out': False, 'failed': False,
            'truncated': parsed['truncated'],
            'seconds': round(time.monotonic() - started, 3)}


def _unique_ordered(values):
    """按出现顺序去重。"""
    seen, result = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def reconcile_dns(results):
    """合并各解析器的 A 记录并判定一致性，返回地址与失败类别。"""
    if not results:
        raise ValueError('至少需要一个解析器结果')
    empty = {'addresses': [], 'cnames': [], 'consistent': False, 'error': None}
    if any(row.get('timed_out') or row.get('failed') for row in results):
        return {**empty, 'error': 'dns_timeout'}
    if any(row.get('rcode') == 3 for row in results):
        return {**empty, 'error': 'dns_nxdomain'}
    if any((row.get('rcode') or 0) != 0 for row in results):
        return {**empty, 'error': 'dns_timeout'}
    addresses = _unique_ordered(
        address for row in results for address in (row.get('addresses') or []))
    cnames = _unique_ordered(
        name for row in results for name in (row.get('cnames') or []))
    answer_sets = [frozenset(row.get('addresses') or []) for row in results]
    if not any(answer_sets):
        return {**empty, 'cnames': cnames, 'error': 'no_a_record'}
    if len(set(answer_sets)) != 1:
        # CDN 和 GeoDNS 经常对两个解析器返回不同边缘地址。地址都合法时继续探测，
        # 只记录 warning；一致性仍写入证据，供人工复核。
        return {'addresses': addresses, 'cnames': cnames,
                'consistent': False, 'error': None, 'warning': 'dns_conflict'}
    return {'addresses': addresses, 'cnames': cnames,
            'consistent': True, 'error': None}


def decide(dns_error=None, forbidden=None, attempts=None):
    """按固定决策表返回 (status, error)；证据不足时失败关闭。"""
    if dns_error:
        return 'fail', dns_error
    if forbidden:
        return 'fail', forbidden
    attempts = attempts or []
    if any(item.get('tls_ok') for item in attempts):
        return 'pass', None
    if any(item.get('http_status') is not None for item in attempts):
        return 'pass', None
    if any(item.get('tcp') == 'interface_down' for item in attempts):
        return 'fail', 'interface_down'
    if any(item.get('tcp') == 'connected' for item in attempts):
        if any(item.get('http_error') for item in attempts):
            return 'fail', 'http_error'
        return 'fail', 'tls_error'
    if any(item.get('tcp') == 'timeout' for item in attempts):
        return 'fail', 'tcp_timeout'
    if any(item.get('tcp') == 'refused' for item in attempts):
        return 'fail', 'tcp_refused'
    return 'fail', 'tcp_timeout'


def summarize(rows):
    """统计结果行中的通过、失败数量和每个错误类别的数量。"""
    summary = {'total': len(rows), 'pass': 0, 'fail': 0,
               'error_categories': {}, 'all_passed': False}
    for row in rows:
        if row.get('status') == 'pass':
            summary['pass'] += 1
            continue
        summary['fail'] += 1
        category = row.get('error') or 'unknown'
        counts = summary['error_categories']
        counts[category] = counts.get(category, 0) + 1
    summary['all_passed'] = summary['total'] > 0 and summary['fail'] == 0
    return summary


def parse_host(value):
    """规范化并校验候选域名。"""
    if not isinstance(value, str):
        raise ValueError('候选域名必须是字符串')
    host = value.strip().lower().rstrip('.')
    if not host or len(host) > 253 or '..' in host:
        raise ValueError('候选域名格式非法')
    labels = host.split('.')
    if len(labels) < 2 or any(not HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError('候选域名必须是合法完整域名')
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        pass
    else:
        raise ValueError('候选域名不能是 IPv4 地址')
    return host


def candidate_url(value, host):
    """校验可选的样本 URL；缺省为 https://host/。"""
    if value is None:
        return f'https://{host}/'
    if not isinstance(value, str):
        raise ValueError('候选 url 必须是字符串')
    url = value.strip()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        raise ValueError('候选 url 必须是 http 或 https 地址')
    if parsed.username or parsed.password:
        raise ValueError('候选 url 不能包含凭据')
    return url


def normalize_decision(value):
    """规范化候选的 decision 字段；缺失时返回 None。"""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError('候选 decision 必须是字符串')
    decision = value.strip().lower()
    return decision or None


def parse_candidates(obj):
    """解析候选文件内容，支持对象包装和纯主机列表两种形状。"""
    items = obj.get('candidates') if isinstance(obj, dict) else obj
    if not isinstance(items, list):
        raise ValueError('候选文件必须包含候选列表')
    result, seen = [], set()
    for item in items:
        if isinstance(item, str):
            host_text, url, decision = item, None, None
        elif isinstance(item, dict):
            if 'host' not in item:
                raise ValueError('候选条目缺少 host')
            host_text, url = item.get('host'), item.get('url')
            decision = normalize_decision(item.get('decision'))
        else:
            raise ValueError('候选条目必须是主机名或对象')
        host = parse_host(host_text)
        normalized_url = candidate_url(url, host)
        if host in seen:
            continue
        seen.add(host)
        result.append({'host': host, 'url': normalized_url,
                       'decision': decision})
    if not result:
        raise ValueError('候选列表为空')
    return result


def select_candidates(candidates, decisions):
    """按 decision 过滤候选；decision 为空或命中请求值时保留。"""
    requested = {value.strip().lower() for value in decisions
                 if value and value.strip()}
    if not requested:
        raise ValueError('至少需要一个 decision 过滤值')
    selected, skipped = [], 0
    for candidate in candidates:
        decision = candidate.get('decision')
        if decision is None or decision in requested:
            selected.append(candidate)
        else:
            skipped += 1
    return selected, skipped


def read_candidates(path):
    """读取候选 JSON 文件并返回解析结果和源文件 sha256。"""
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    try:
        obj = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('候选文件不是合法 JSON') from error
    return parse_candidates(obj), digest


def http_status(connection, host, timeout):
    """发送一次最小 GET 请求并返回状态码，不跟随跳转。"""
    connection.settimeout(timeout)
    request = (f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
               ).encode('ascii')
    connection.sendall(request)
    data = b''
    while b'\r\n\r\n' not in data and len(data) < 65536:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
    if not data:
        raise OSError('HTTP 响应为空')
    line = data.split(b'\r\n', 1)[0].decode('latin-1')
    match = re.match(r'HTTP/\d(?:\.\d)?\s+(\d{3})', line)
    if match is None:
        raise OSError('HTTP 状态行非法')
    return int(match.group(1))


def tls_handshake(connection, host, timeout):
    """执行带 SNI 和默认证书校验的 TLS 握手，返回连接与参数。"""
    context = ssl.create_default_context()
    connection.settimeout(timeout)
    peer = context.wrap_socket(connection, server_hostname=host)
    cipher = peer.cipher()
    return peer, {'version': peer.version(), 'verified': True,
                  'cipher': cipher[0] if cipher else None}


def probe_address(host, address, port, interface, index, timeout, journal):
    """对单个地址的一个端口执行 TCP、TLS 与 HTTP 探测。"""
    attempt = {'address': address, 'port': port, 'tcp': None, 'tls_ok': False,
               'tls': None, 'http_status': None, 'http_error': False}
    connection = peer = None
    try:
        connection = bound_socket(socket.SOCK_STREAM, index, timeout)
        started = time.monotonic()
        connection.connect((address, port))
        attempt['tcp'] = 'connected'
        journal.emit('tcp', host=host, address=address, port=port, connected=True,
                     bound_interface=interface, bound_index=index,
                     seconds=round(time.monotonic() - started, 3))
        peer = connection
        if port == 443:
            try:
                peer, info = tls_handshake(connection, host, timeout)
            except (ssl.SSLError, OSError) as error:
                attempt['tls'] = {'ok': False, 'error': str(error)}
                journal.emit('tls', host=host, address=address, port=port,
                             ok=False, version=None, cipher=None, error=str(error),
                             seconds=round(time.monotonic() - started, 3))
                return attempt
            attempt['tls'] = info
            attempt['tls_ok'] = True
            journal.emit('tls', host=host, address=address, port=port, ok=True,
                         version=info['version'], cipher=info['cipher'], error=None,
                         seconds=round(time.monotonic() - started, 3))
        try:
            attempt['http_status'] = http_status(peer, host, timeout)
            journal.emit('http', host=host, address=address, port=port,
                         status=attempt['http_status'], error=None,
                         seconds=round(time.monotonic() - started, 3))
        except (OSError, ValueError) as error:
            attempt['http_error'] = True
            journal.emit('http', host=host, address=address, port=port,
                         status=None, error=str(error),
                         seconds=round(time.monotonic() - started, 3))
        return attempt
    except InterfaceDown:
        attempt['tcp'] = 'interface_down'
        journal.emit('tcp', host=host, address=address, port=port, connected=False,
                     error='interface_down', bound_interface=interface,
                     bound_index=index)
        return attempt
    except ConnectionRefusedError:
        attempt['tcp'] = 'refused'
        journal.emit('tcp', host=host, address=address, port=port, connected=False,
                     error='refused', bound_interface=interface, bound_index=index)
        return attempt
    except socket.timeout:
        attempt['tcp'] = 'timeout'
        journal.emit('tcp', host=host, address=address, port=port, connected=False,
                     error='timeout', bound_interface=interface, bound_index=index)
        return attempt
    except OSError as error:
        if interface_down_error(error):
            attempt['tcp'] = 'interface_down'
            journal.emit('tcp', host=host, address=address, port=port,
                         connected=False, error='interface_down',
                         bound_interface=interface, bound_index=index)
            return attempt
        attempt['tcp'] = 'timeout'
        journal.emit('tcp', host=host, address=address, port=port, connected=False,
                     error=str(error), bound_interface=interface, bound_index=index)
        return attempt
    finally:
        for target in (peer, connection):
            if target is not None:
                try:
                    target.close()
                except OSError:
                    pass


def probe_addresses(host, addresses, interface, index, timeout, journal):
    """先探测全部地址的 443，全部失败后再退到 80。"""
    attempts = [probe_address(host, address, 443, interface, index, timeout, journal)
                for address in addresses]
    succeeded = any(item['tls_ok'] or item['http_status'] is not None
                    for item in attempts)
    if not succeeded:
        attempts.extend(probe_address(host, address, 80, interface, index,
                                      timeout, journal)
                        for address in addresses)
    return attempts


def parse_asn(text):
    """把 Team Cymru TXT 文本解析成字段对象；格式不符时返回 None。"""
    fields = [field.strip() for field in text.split('|')]
    if len(fields) < 2 or not fields[0] or not fields[1]:
        return None
    result = {'asn': fields[0], 'prefix': fields[1]}
    names = ['country', 'registry', 'allocated']
    for name, value in zip(names, fields[2:]):
        if value:
            result[name] = value
    return result


def lookup_asn(address, interface, index, resolvers, timeout):
    """尽力查询 Team Cymru ASN TXT 记录；任何失败都返回 None。"""
    host = '.'.join(reversed(address.split('.'))) + '.origin.asn.cymru.com'
    try:
        for resolver in resolvers:
            result = query_dns(host, resolver, index, timeout, qtype=16)
            if result['texts']:
                return parse_asn(result['texts'][0])
    except Exception:
        return None
    return None


class Journal:
    """逐条追加并刷新 JSONL 证据，结束时写入 summary.json。"""

    def __init__(self, outdir):
        self.directory = Path(outdir)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'requests.jsonl'
        self.file = self.path.open('a', encoding='utf-8')

    def emit(self, kind, **fields):
        """写入一条带时间戳的记录并立即刷新。"""
        record = {'at': now_iso(), 'kind': kind, **fields}
        self.file.write(json.dumps(record, ensure_ascii=False) + '\n')
        self.file.flush()

    def finish(self, summary):
        """写入汇总文件并关闭 JSONL。"""
        (self.directory / 'summary.json').write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8')
        self.file.close()


def check_host(candidate, snapshot, interface, resolvers, timeout, journal):
    """完成单个候选域名的 DNS、TCP、TLS、HTTP 与 ASN 证据收集。"""
    host = candidate['host']
    index = snapshot['interface_index']
    row = {'host': host, 'url': candidate['url'], 'status': 'fail',
           'error': None, 'dns': None, 'attempts': [], 'asn': None}
    try:
        dns_results = []
        for resolver in resolvers:
            result = query_dns(host, resolver, index, timeout)
            dns_results.append(result)
            journal.emit('dns', host=host, resolver=resolver,
                         addresses=result['addresses'], cnames=result['cnames'],
                         rcode=result['rcode'], timed_out=result['timed_out'],
                         bound_interface=interface, bound_index=index,
                         seconds=result['seconds'])
        merged = reconcile_dns(dns_results)
        row['dns'] = merged
        if merged['error']:
            row['status'], row['error'] = decide(dns_error=merged['error'])
        else:
            forbidden = next(
                (category for address in merged['addresses']
                 if (category := registrable_address_filter(address))), None)
            if forbidden:
                row['status'], row['error'] = decide(forbidden=forbidden)
            else:
                row['attempts'] = probe_addresses(
                    host, merged['addresses'], interface, index, timeout, journal)
                row['asn'] = lookup_asn(merged['addresses'][0], interface, index,
                                        resolvers, timeout)
                row['status'], row['error'] = decide(attempts=row['attempts'])
    except InterfaceDown:
        row['status'], row['error'] = 'fail', 'interface_down'
    journal.emit('summary', host=host, status=row['status'], error=row['error'],
                 addresses=(row['dns'] or {}).get('addresses', []),
                 asn=row['asn'], interface=interface, interface_index=index)
    return row


def run(candidates, snapshot, interface, outdir, timeout, resolvers, source,
        selection):
    """按顺序探测候选并持续写入证据，返回结果行与汇总文档。"""
    journal = Journal(outdir)
    document = {'at': now_iso(),
                'source': source,
                'candidate_count': selection['candidate_count'],
                'requested_decisions': selection['requested_decisions'],
                'skipped_by_decision': selection['skipped_by_decision'],
                'method': {
                    'platform': ('macOS IPv4' if sys.platform == 'darwin'
                                 else f'{sys.platform} IPv4'),
                    'dns_and_tcp_bound_by': f'IP_BOUND_IF = {IP_BOUND_IF}',
                    'interface': interface,
                    'interface_index': snapshot['interface_index'],
                    'interface_ipv4': snapshot['ipv4'],
                    'resolvers': list(resolvers),
                    'timeout_seconds': timeout,
                    'tls_certificate_verification': True,
                    'explicit_proxy_used': False,
                    'http_ports': [443, 80],
                    'asn_lookup': 'Team Cymru origin.asn.cymru.com（尽力而为）',
                },
                'results': []}
    journal.emit('begin', interface=interface,
                 interface_index=snapshot['interface_index'],
                 interface_ipv4=snapshot['ipv4'], resolvers=list(resolvers),
                 timeout=timeout, selected=len(candidates),
                 candidate_count=selection['candidate_count'],
                 requested_decisions=selection['requested_decisions'],
                 skipped_by_decision=selection['skipped_by_decision'],
                 source_path=source.get('path'), source_sha256=source.get('sha256'),
                 limit=source.get('limit'))
    rows = []
    for candidate in candidates:
        row = check_host(candidate, snapshot, interface, resolvers, timeout, journal)
        rows.append(row)
        if row['error'] == 'interface_down':
            break
    document['results'] = rows
    document['counts'] = summarize(rows)
    journal.finish(document)
    return rows, document


def build_parser():
    """构造命令行参数解析器。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidates', required=True, help='候选 JSON 文件')
    parser.add_argument('--interface', default='en0', help='绑定出口的接口名')
    parser.add_argument('--outdir', required=True, help='证据输出目录')
    parser.add_argument('--limit', type=int, default=None, help='最多探测的候选数')
    parser.add_argument('--timeout', type=float, default=3.0,
                        help='单次网络操作超时秒数')
    parser.add_argument('--resolver', action='append', dest='resolvers',
                        default=None, help='DNS 解析器，可重复指定')
    parser.add_argument('--decision', action='append', dest='decisions',
                        default=None,
                        help='只探测该 decision 的候选，可重复；默认 pending')
    return parser


def main(argv=None):
    """解析参数、过滤候选、校验接口并执行探测；用法错误返回 2，存在失败返回 1。"""
    arguments = build_parser().parse_args(argv)
    resolvers = arguments.resolvers or list(DEFAULT_RESOLVERS)
    try:
        decisions = _unique_ordered(
            value.strip().lower()
            for value in (arguments.decisions or ['pending']))
        if any(not value for value in decisions):
            raise ValueError
        for resolver in resolvers:
            ipaddress.IPv4Address(resolver)
        if arguments.limit is not None and arguments.limit < 1:
            raise ValueError
        if arguments.timeout <= 0:
            raise ValueError
    except ValueError:
        print('参数非法：解析器必须是 IPv4，decision 不能为空，'
              'limit 必须为正整数，timeout 必须大于 0。', file=sys.stderr)
        return 2
    try:
        candidates, digest = read_candidates(arguments.candidates)
    except (OSError, ValueError) as error:
        print(f'候选文件不可用：{error}', file=sys.stderr)
        return 2
    selected, skipped = select_candidates(candidates, decisions)
    print(f"候选 {len(candidates)} 条，跳过 {skipped} 条"
          f"（decision={','.join(decisions)}）")
    if not selected:
        print('决策过滤后没有候选，拒绝执行。', file=sys.stderr)
        return 2
    snapshot = interface_snapshot(arguments.interface)
    if not snapshot['ready']:
        print(f'接口不可用：{arguments.interface} 必须存在、已启用并具有 IPv4 地址。',
              file=sys.stderr)
        return 2
    if arguments.limit is not None:
        selected = selected[:arguments.limit]
    source = {'path': str(Path(arguments.candidates)), 'sha256': digest,
              'limit': arguments.limit}
    selection = {'candidate_count': len(candidates),
                 'requested_decisions': decisions,
                 'skipped_by_decision': skipped}
    try:
        _, document = run(selected, snapshot, arguments.interface,
                          arguments.outdir, arguments.timeout, resolvers,
                          source, selection)
    except OSError as error:
        print(f'探测中止：{error}', file=sys.stderr)
        return 2
    counts = document['counts']
    print(f"完成：{counts['pass']} 通过，{counts['fail']} 失败，共 {counts['total']} 个候选。")
    return 0 if counts['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
