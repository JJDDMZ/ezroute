// Called after the existing subscription normalizer, inside Verge's global script.
function main(config, profileName) {
  try {
    const out = ezSubscriptionNormalizer(config);
    // No campus outlet has been verified during bootstrap; keep the lab IP off airport nodes.
    out.rules = ['IP-CIDR,192.0.2.10/32,REJECT,no-resolve', ...out.rules.filter(
      rule => !rule.startsWith('IP-CIDR,192.0.2.10/32,'))];
    // Safe bootstrap for every supported subscription: all outlets start on USB.
    // EZ Switch subsequently applies the current network mode to the live core.
    for (const node of out.proxies) node['interface-name'] = out['interface-name'];
    out['ez-switch-bootstrap-version'] = 1;
    out['ez-switch-profile-name'] = profileName || '';
    delete out['ez-switch-bootstrap-error'];
    return out;
  } catch (_) {
    // Verge keeps its input when a script throws. Return a valid rejected config.
    const out = {};
    for (const key of ['tun', 'mixed-port', 'port', 'socks-port', 'redir-port',
      'tproxy-port', 'external-controller', 'external-controller-unix',
      'external-controller-tls', 'secret', 'allow-lan', 'bind-address',
      'log-level', 'ipv6', 'find-process-mode']) {
      if (config && config[key] !== undefined) out[key] = config[key];
    }
    // This value is rendered from the selected USB interface by EZ Switch.
    const usb = EZ_BOOTSTRAP_USB;
    out.mode = 'rule';
    out['interface-name'] = usb;
    out.proxies = [
      {name:'EZ-Campus',type:'direct','interface-name':usb,'ip-version':'ipv4'},
      {name:'EZ-USB-DNS',type:'direct','interface-name':usb,'ip-version':'ipv4'}
    ];
    out['proxy-groups'] = [];
    out.rules = ['MATCH,REJECT'];
    out.dns = {enable:false};
    out.sniffer = {enable:false};
    out['ez-switch-bootstrap-version'] = 1;
    out['ez-switch-profile-name'] = profileName || '';
    out['ez-switch-bootstrap-error'] = 'unsupported-subscription';
    return out;
  }
}
