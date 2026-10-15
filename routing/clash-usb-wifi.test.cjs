const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(`${__dirname}/clash-usb-wifi.js`, 'utf8'), context);
const apply = input => JSON.parse(JSON.stringify(context.main(input)));
const fixture = () => ({
  mode: 'rule', 'mixed-port': 7897,
  tun: { enable: false },
  proxies: [{ name: 'node', type: 'trojan', server: 'node.example', port: 443,
    password: 'fixture', 'interface-name': 'en0', mptcp: true }],
  'proxy-groups': [{ name: 'Proxy', type: 'select', proxies: ['node', 'DIRECT'] }],
  rules: ['DOMAIN,example.cn,DIRECT', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'DOMAIN,direct.example,Proxy', 'MATCH,Proxy'],
  dns: { enable: false, nameserver: ['system'], fallback: ['8.8.8.8'],
    'nameserver-policy': { '+.example': 'system' },
    'proxy-server-nameserver-policy': { '+.example': 'system' } }
});

test('remote nodes bind USB even if subscription previously bound Wi-Fi', () => {
  const out = apply(fixture());
  assert.equal(out.proxies[0]['interface-name'], 'en5');
  assert.equal(out.proxies[0].mptcp, false);
  assert.equal(out.proxies[0]['ip-version'], 'ipv4');
  assert.equal(out['interface-name'], 'en5');
  assert.equal(out['mixed-port'], 7897);
  assert.equal(out.tun.enable, false);
});

test('only named direct rules get Wi-Fi; proxy groups cannot fall back to DIRECT', () => {
  const out = apply(fixture());
  assert.equal(out.rules[0], 'DOMAIN,example.cn,EZ-Campus');
  assert.equal(out.rules[1], 'DOMAIN,direct.example,Proxy');
  assert.deepEqual(out['proxy-groups'][0].proxies, ['node']);
  assert.equal(out.proxies.find(p => p.name === 'EZ-Campus')['interface-name'], 'en0');
});

test('all Clash DNS including direct resolution stays on USB, without inherited DNS policy', () => {
  const out = apply(fixture());
  assert.equal(out.dns.enable, true);
  for (const key of ['nameserver', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver']) {
    assert.ok(out.dns[key].length > 0);
    assert.ok(out.dns[key].every(v => v.endsWith('#EZ-USB-DNS')));
  }
  assert.equal(out.proxies.find(p => p.name === 'EZ-USB-DNS')['interface-name'], 'en5');
  assert.equal(out.dns['nameserver-policy'], undefined);
  assert.equal(out.dns.fallback, undefined);
  assert.equal(out.dns['proxy-server-nameserver-policy'], undefined);
});

test('custom direct node cannot appear in a proxy group as a campus fallback', () => {
  const input = fixture();
  input.proxies.push({ name: 'old-direct', type: 'direct' });
  input['proxy-groups'][0].proxies.push('old-direct');
  input.rules.unshift('DOMAIN,local.example,old-direct');
  const out = apply(input);
  assert.equal(out.rules[0], 'DOMAIN,local.example,EZ-Campus');
  assert.deepEqual(out['proxy-groups'][0].proxies, ['node']);
});

test('dedicated direct group maps its rules to campus rather than rejecting domestic traffic', () => {
  const input = fixture();
  input['proxy-groups'].push({ name: 'DedicatedDirect', type: 'select', proxies: ['DIRECT'] });
  input.rules.unshift('DOMAIN,local.example,DedicatedDirect');
  const out = apply(input);
  assert.equal(out.rules[0], 'DOMAIN,local.example,EZ-Campus');
  assert.equal(out.rules.at(-1), 'MATCH,Proxy');
  assert.equal(out['proxy-groups'].length, 1);
});

test('nested direct-only groups stay direct, but cannot be a proxy group fallback', () => {
  const input = fixture();
  input['proxy-groups'].push({ name: 'Direct', type: 'select', proxies: ['DIRECT'] },
    { name: 'NestedDirect', type: 'select', proxies: ['Direct'] });
  input['proxy-groups'][0].proxies.push('NestedDirect');
  input.rules.unshift('DOMAIN,local.example,NestedDirect');
  const out = apply(input);
  assert.equal(out.rules[0], 'DOMAIN,local.example,EZ-Campus');
  assert.deepEqual(out['proxy-groups'][0].proxies, ['node']);
  assert.equal(out['proxy-groups'].length, 1);
});

test('reject unsupported or ambiguous routing instead of silently accepting it', () => {
  const variants = [
    c => { c.proxies[0].type = 'wireguard'; },
    c => { c.proxies[0]['dialer-proxy'] = 'DIRECT'; },
    c => { c['proxy-providers'] = { remote: { type: 'http' } }; },
    c => { c['proxy-groups'][0]['include-all'] = true; },
    c => { c['sub-rules'] = { sub: ['MATCH,DIRECT'] }; },
    c => { c.proxies[0].name = 'EZ-Campus'; },
    c => { c.rules[0] = 'AND,((DOMAIN,example.cn)),DIRECT'; },
    c => { c['proxy-groups'][0].proxies.push('PASS'); },
  ];
  for (const change of variants) {
    const input = fixture(); change(input);
    assert.throws(() => apply(input), /EZ Switch/);
  }
});

test('transformation is deterministic and leaves caller input intact', () => {
  const input = fixture(); const before = JSON.stringify(input);
  assert.deepEqual(apply(input), apply(input));
  assert.equal(JSON.stringify(input), before);
});

test('TUN IP-only TLS requests get domain identification without subscription exclusions', () => {
  const input = fixture();
  input.sniffer = { enable: false, 'skip-domain': ['+.gstatic.com'], 'parse-pure-ip': false };
  const out = apply(input);
  assert.equal(out.sniffer.enable, true);
  assert.equal(out.sniffer['parse-pure-ip'], true);
  assert.ok(out.sniffer.sniff.TLS.ports.includes(443));
  assert.ok(out.sniffer.sniff.QUIC.ports.includes(443));
  assert.equal(out.sniffer['skip-domain'], undefined);
});

test('IP or process location alone cannot authorize campus direct traffic', () => {
  const input = fixture();
  input.rules.unshift('GEOIP,CN,DIRECT', 'PROCESS-NAME,browser,DIRECT');
  const out = apply(input);
  assert.deepEqual(out.rules, ['DOMAIN,example.cn,EZ-Campus', 'DOMAIN,direct.example,Proxy', 'MATCH,Proxy']);
});

test('a direct catch-all cannot authorize unknown traffic on campus', () => {
  const input = fixture(); input.rules[input.rules.length - 1] = 'MATCH,DIRECT';
  assert.throws(() => apply(input), /EZ Switch/);
});
