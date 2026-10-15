const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');const vm=require('node:vm');
const fixture=()=>({tun:{enable:true},'mixed-port':7897,proxies:[{name:'new-node',type:'trojan',server:'example.invalid',port:443,password:'fixture'}],'proxy-groups':[{name:'new-group',type:'select',proxies:['new-node','DIRECT']}],rules:['DOMAIN,domestic.example,DIRECT','MATCH,new-group']});
const apply=c=>{const context=vm.createContext({});vm.runInContext("const EZ_BOOTSTRAP_USB='en5';\nconst ezSubscriptionNormalizer=(()=>{"+fs.readFileSync('routing/clash-usb-wifi.js','utf8')+';return main;})();\n'+fs.readFileSync('routing/clash-bootstrap.js','utf8'),context);return JSON.parse(JSON.stringify(context.main(c)));};
test('new subscriptions retain their own groups and domain rules with USB bootstrap outlets',()=>{
 const input=fixture(),out=apply(input);
 assert.equal(out.rules[1],'DOMAIN,domestic.example,EZ-Campus');assert.equal(out.rules[2],'MATCH,new-group');
 assert.deepEqual(out['proxy-groups'][0].proxies,['new-node']);assert.ok(out.proxies.every(p=>p['interface-name']==='en5'));
 assert.equal(out.tun.enable,true);assert.equal(out['mixed-port'],7897);assert.equal(out['ez-switch-bootstrap-error'],undefined);
});
test('unsupported subscription returns explicit rejection without providers or background proxies',()=>{
 const input=fixture();input['proxy-providers']={remote:{type:'http',url:'https://example.invalid/secret'}};
 const out=apply(input);assert.deepEqual(out.rules,['MATCH,REJECT']);assert.deepEqual(out['proxy-groups'],[]);
 assert.equal(out.proxies.filter(p=>p.type!=='direct').length,0);assert.equal(out['proxy-providers'],undefined);assert.equal(out.dns.enable,false);
 assert.equal(out['ez-switch-bootstrap-error'],'unsupported-subscription');assert.equal(out.tun.enable,true);
});
test('unsafe direct catch-all and chained node return blocked configuration',()=>{
 for(const change of [c=>c.rules=['MATCH,DIRECT'],c=>c.proxies[0]['dialer-proxy']='DIRECT']){const c=fixture();change(c);assert.deepEqual(apply(c).rules,['MATCH,REJECT']);}
});
test('lab IP is blocked at bootstrap until EZ Switch establishes a campus outlet',()=>{
 const out=apply(fixture());
 assert.equal(out.rules[0],'IP-CIDR,192.0.2.10/32,REJECT,no-resolve');
});
