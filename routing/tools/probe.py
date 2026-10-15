"""Isolated integration test. Never modifies the active Clash instance."""
import pathlib, tempfile, subprocess, socket, time, json, os, http.client, struct, re
from probe_assertions import request_passed
BASE=pathlib.Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
CORE='/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo'
SCRIPT=pathlib.Path(__file__).resolve().parents[1]/'clash-usb-wifi.js'
wifi_state=subprocess.run(['/sbin/ifconfig','en0'],capture_output=True,check=True,text=True).stdout
wifi_online='status: active' in wifi_state and bool(re.search(r'\binet \d',wifi_state))
print(json.dumps({'wifi_ipv4_online':wifi_online,'expected_direct_success':wifi_online}),flush=True)
raw=subprocess.run(['/usr/bin/ruby','-ryaml','-rjson','-e','puts JSON.generate(YAML.safe_load(File.read(ARGV[0]),aliases:true))',str(BASE/'clash-verge.yaml')],capture_output=True,check=True).stdout
live=json.loads(raw)
class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(4); self.sock.connect(self.host)
try:
    conn=UnixHTTP(f'/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock')
    conn.request('GET','/proxies',headers={'Host':'localhost','Authorization':'Bearer '+live.get('secret','')})
    selections=json.loads(conn.getresponse().read()).get('proxies',{})
    conn.close()
except Exception as error:
    print(json.dumps({'controller_read_error_type':type(error).__name__,'unix_controller_configured':bool(live.get('external-controller-unix')),'tcp_controller':live.get('external-controller')}),flush=True)
    selections={}
if any(p.get('name')=='EZ-Campus' for p in live.get('proxies',[])):
    config=live
else:
    transformed=subprocess.run(['node','-e',"const fs=require('fs'),vm=require('vm');const ctx=vm.createContext({});vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),ctx);process.stdout.write(JSON.stringify(ctx.main(JSON.parse(fs.readFileSync(0,'utf8')))));",str(SCRIPT)],input=raw,capture_output=True)
    if transformed.returncode:
        print(json.dumps({'transformation_ok':False})); raise SystemExit(1)
    config=json.loads(transformed.stdout)
for group in config['proxy-groups']:
    chosen=selections.get(group['name'],{}).get('now')
    if chosen in group['proxies']: group['proxies']=[chosen]+[x for x in group['proxies'] if x!=chosen]
proxy_policies=[p['name'] for p in config['proxies'] if p['type']!='direct']+[g['name'] for g in config['proxy-groups']]
print(json.dumps({'transformation_ok':True,'remote_node_count':len(config['proxies'])-2,'live_selections_read':bool(selections),'all_remote_nodes_bound_usb':all(p.get('interface-name')=='en5' for p in config['proxies'] if p['type']!='direct')}),flush=True)

def port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
failed=False
with tempfile.TemporaryDirectory(prefix='ez-switch-core-',dir='/private/tmp') as root:
    root=pathlib.Path(root)
    for f in ['geoip.dat','Country.mmdb','geosite.dat']:
        if (BASE/f).exists(): os.symlink(BASE/f,root/f)
    for label,iface in [('usb','en5'),('missing','ezmissing999')]:
        cfg=json.loads(json.dumps(config)); p=port()
        for proxy in cfg['proxies']:
            if proxy['name']!='EZ-Campus': proxy['interface-name']=iface
        cfg['interface-name']=iface
        cfg['mixed-port']=p; cfg['port']=0; cfg['socks-port']=0
        cfg['external-controller']=''; cfg.pop('external-controller-unix',None); cfg.pop('secret',None)
        cfg['allow-lan']=False;cfg['bind-address']='127.0.0.1';cfg['ipv6']=False
        cfg['tun']={'enable':False};dns_port=port();cfg['dns']['listen']='127.0.0.1:'+str(dns_port)
        cfg['dns']['fake-ip-filter']=['www.apple.com.cn']
        cfg['geo-auto-update']=False
        cfg['log-level']='info';cfg['profile']={'store-selected':False,'store-fake-ip':False}
        file=root/(label+'.json');file.write_text(json.dumps(cfg,ensure_ascii=False));file.chmod(0o600)
        validation=subprocess.run([CORE,'-t','-d',str(root),'-f',str(file)],capture_output=True,timeout=25)
        print(json.dumps({'case':label,'core_config_valid':validation.returncode==0}),flush=True)

        if validation.returncode:
            error=(validation.stdout+validation.stderr).decode(errors='replace')
            for node in live.get('proxies',[]):
                for key in ['name','server','password','uuid']:
                    value=node.get(key)
                    if isinstance(value,str) and len(value)>3: error=error.replace(value,'[redacted]')
            print(error[-1500:]); raise SystemExit(2)
        with (root/(label+'.log')).open('w+') as log:
            process=subprocess.Popen([CORE,'-d',str(root),'-f',str(file)],stdout=log,stderr=log)
            try:
                for _ in range(50):
                    try:
                        with socket.create_connection(('127.0.0.1',p),timeout=.1): break
                    except OSError: time.sleep(.1)
                question=b''.join(bytes([len(part)])+part.encode() for part in 'www.apple.com.cn'.split('.'))+b'\0'+struct.pack('!HH',1,1)
                query=struct.pack('!HHHHHH',12345,0x100,1,0,0,0)+question
                dns_ok=False
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(4);client.sendto(query,('127.0.0.1',dns_port))
                    try:
                        answer=client.recv(4096)
                        identifier,flags,_,count,_,_=struct.unpack('!HHHHHH',answer[:12])
                        dns_ok=identifier==12345 and flags&15==0 and count>0
                    except socket.timeout: pass
                print(json.dumps({'case':label,'real_udp_dns_success':dns_ok}),flush=True)
                if dns_ok != (label=='usb'): failed=True
                for url,expected in [('https://www.gstatic.com/generate_204','proxy'),('https://www.bilibili.com/','direct')]:
                    result=subprocess.run(['/usr/bin/curl','--silent','--show-error','--noproxy','','--proxy','http://127.0.0.1:'+str(p),'--connect-timeout','5','--max-time','10','--output','/dev/null','--write-out','%{http_code}',url],capture_output=True,timeout=12)
                    log.flush();log.seek(0);logs=log.read()
                    campus_seen=any('www.bilibili.com' in line and 'EZ-Campus' in line for line in logs.splitlines())
                    proxy_seen=any('www.gstatic.com:443' in line and any(re.search(r' using '+re.escape(name)+r'(?:\[|"|$)',line) for name in proxy_policies) for line in logs.splitlines())
                    passed=request_passed(label,expected,result.returncode,result.stdout.decode().strip(),campus_seen,wifi_online,proxy_seen)
                    print(json.dumps({'case':label,'request':expected,'curl_exit':result.returncode,'http_status':result.stdout.decode().strip(),'campus_policy_seen':campus_seen if expected=='direct' else None,'proxy_policy_seen':proxy_seen if expected=='proxy' else None,'assertion_passed':passed}),flush=True)
                    if not passed: failed=True
            finally:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill();process.wait(timeout=3)
raise SystemExit(1 if failed else 0)
