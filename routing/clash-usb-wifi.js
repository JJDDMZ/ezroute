// EZ Switch USB/Wi-Fi routing v3
// Paste into the ACTIVE subscription's extension script in Clash Verge.
// Re-check these names after changing Mac, iPhone, dock or USB connection.
const USB_INTERFACE = 'en5';
const WIFI_INTERFACE = 'en0';

function main(config) {
  const fail = message => { throw new Error('EZ Switch: ' + message); };
  const out = JSON.parse(JSON.stringify(config));
  const campus = 'EZ-Campus';
  const usbDNS = 'EZ-USB-DNS';
  const reserved = new Set([campus, usbDNS]);
  if (!/^en\d+$/.test(USB_INTERFACE) || !/^en\d+$/.test(WIFI_INTERFACE) ||
      USB_INTERFACE === WIFI_INTERFACE) fail('invalid or identical interface names');
  for (const key of ['proxy-providers', 'rule-providers', 'sub-rules', 'listeners', 'tunnels']) {
    if (out[key] && Object.keys(out[key]).length) fail('unsupported configuration: ' + key);
  }
  const nodes = out.proxies || [];
  let groups = out['proxy-groups'] || [];
  const supported = new Set(['trojan', 'vmess', 'vless', 'ss', 'ssr', 'http', 'socks5', 'snell']);
  const names = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'GLOBAL']);
  const directNames = new Set(['DIRECT']);
  for (const item of [...nodes, ...groups]) {
    if (!item.name || names.has(item.name) || reserved.has(item.name)) fail('duplicate or reserved policy name');
    names.add(item.name);
  }
  for (const node of nodes) {
    if (node['dialer-proxy']) fail('dialer-proxy requires a separate routing review');
    if (node.type === 'direct') {
      directNames.add(node.name);
    } else {
      if (!supported.has(node.type)) fail('unsupported proxy protocol');
      node['interface-name'] = USB_INTERFACE;
      node['ip-version'] = 'ipv4';
      node.mptcp = false;
    }
  }
  for (const group of groups) {
    if (!['select', 'url-test', 'fallback', 'load-balance'].includes(group.type) ||
        group.use?.length || group['include-all'] || group['include-all-proxies'] ||
        group['include-all-providers']) fail('unsupported proxy group');
  }
  // A dedicated DIRECT group is itself a direct policy, not a failed proxy.
  // Resolve nested direct-only groups before removing campus fallbacks.
  let changed = true;
  while (changed) {
    changed = false;
    for (const group of groups) {
      if (!directNames.has(group.name) && group.proxies?.length &&
          group.proxies.every(name => directNames.has(name))) {
        directNames.add(group.name);
        changed = true;
      }
    }
  }
  groups = groups.filter(group => !directNames.has(group.name));
  const remoteNames = new Set(nodes.filter(n => n.type !== 'direct').map(n => n.name));
  for (const group of groups) remoteNames.add(group.name);
  for (const group of groups) {
    group.proxies = (group.proxies || []).filter(name => !directNames.has(name));
    for (const name of group.proxies) {
      if (!remoteNames.has(name) && !['REJECT', 'REJECT-DROP'].includes(name)) fail('unsafe proxy group member');
    }
    if (!group.proxies.length) group.proxies = ['REJECT'];
  }
  const ordinaryRules = new Set(['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
    'GEOSITE', 'GEOIP', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'SRC-IP-CIDR',
    'DST-PORT', 'SRC-PORT', 'PROCESS-NAME', 'PROCESS-PATH', 'NETWORK']);
  if (!Array.isArray(out.rules) || !out.rules.length) fail('missing route rules');
  // IP geolocation, process/port rules and a DIRECT catch-all cannot identify
  // a domestic site. Unknown-domain requests must retain the phone fallback.
  const namedDirectRules = new Set(['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'GEOSITE']);
  out.rules = out.rules.flatMap(rule => {
    const fields = rule.split(',');
    const index = fields.length - (fields.at(-1) === 'no-resolve' ? 2 : 1);
    if (fields[0] === 'MATCH' ? fields.length !== 2 :
        !ordinaryRules.has(fields[0]) || index !== 2) fail('unsupported route rule');
    const target = fields[index];
    if (directNames.has(target)) {
      if (fields[0] === 'MATCH') fail('a direct catch-all is unsafe for split routing');
      if (!namedDirectRules.has(fields[0])) return [];
      fields[index] = campus;
    }
    else if (!remoteNames.has(target) && !['REJECT', 'REJECT-DROP'].includes(target)) fail('unsafe route target');
    return [fields.join(',')];
  });
  if (!out.rules.at(-1).startsWith('MATCH,')) fail('a final MATCH rule is required');
  out.proxies = nodes.filter(node => node.type !== 'direct');
  out.proxies.push(
    { name: campus, type: 'direct', udp: true, 'ip-version': 'ipv4', 'interface-name': WIFI_INTERFACE },
    { name: usbDNS, type: 'direct', udp: true, 'ip-version': 'ipv4', 'interface-name': USB_INTERFACE }
  );
  out['proxy-groups'] = groups;
  // Core background connections also default to USB, never campus Wi-Fi.
  out['interface-name'] = USB_INTERFACE;
  // DNS volume is small. Keep ALL core DNS on USB, including rule evaluation
  // and node bootstrap, so proxy-related DNS cannot spill onto campus Wi-Fi.
  const resolvers = ['223.5.5.5#' + usbDNS, '119.29.29.29#' + usbDNS];
  out.dns = {
    enable: true, listen: '127.0.0.1:1053', ipv6: false,
    'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter': ['*.lan', '*.local'],
    'respect-rules': false, 'prefer-h3': false,
    'default-nameserver': resolvers.slice(), nameserver: resolvers.slice(),
    'proxy-server-nameserver': resolvers.slice(), 'direct-nameserver': resolvers.slice(),
    'direct-nameserver-follow-policy': false
  };
  // Cached real IPs may arrive at TUN without a DNS mapping. Recover the
  // visible HTTP host/TLS SNI/QUIC domain before evaluating domain rules.
  out.sniffer = {
    enable: true, 'force-dns-mapping': true, 'parse-pure-ip': true,
    'override-destination': false,
    sniff: {
      HTTP: { ports: [80, 8080] },
      TLS: { ports: [443, 8443] },
      QUIC: { ports: [443, 8443] }
    }
  };
  // Verge owns mode, IPv6 and TUN settings. Set those in its UI separately.
  return out;
}
