const assert=require('node:assert/strict');
require('../extension/connector_parameters.js');
require('../extension/connector_config.js');
require('../extension/connector_sources.js');
const p=globalThis.ConnectorParameters,s=globalThis.ConnectorSources;
const rows=p.resolve([
  {source:'text',selector:'#rows',pattern:'tenant=(?<tenant>\\w+); id=(?<id>[^ ]+)',repeat:true,decode:true},
  {source:'page_url',pattern:'/case/(?<case_id>\\d+)'},
  {source:'constant',name:'region'}
],[[{text:'tenant=a; id=x%2Fy tenant=b; id=two'}],[{text:'https://cases.test/case/42'}],[{text:'west'}]]).records;
assert.deepEqual(rows.map(r=>r.params),[{case_id:'42',region:'west',tenant:'a',id:'x/y'},{case_id:'42',region:'west',tenant:'b',id:'two'}]);
assert.throws(()=>p.resolve([{source:'text',selector:'#a',name:'id'}],[[{text:'one'},{text:'two'}]]),/different values/);
assert.throws(()=>p.resolve([{source:'page_url',pattern:'(?<id>one)'},{source:'constant',name:'id'}],[[{text:'one'}],[{text:'two'}]]),/Conflicting/);
assert.throws(()=>p.resolve([{source:'page_url',pattern:'(?<id>one)'}],[[]]),/no value/);
assert.deepEqual(p.resolve([{source:'page_url',pattern:'(?<id>one)',required:false}],[[]]).records[0].params,{});
assert.throws(()=>p.validate([{source:'constant',name:'__proto__'}]),/name/);
assert.throws(()=>p.validate([{source:'text',selector:'#a',pattern:'(.)'}]),/named/);
assert.throws(()=>p.validate([{source:'constant',name:'a',repeat:true},{source:'constant',name:'b',repeat:true}]),/Only one/);
assert.throws(()=>p.resolve([{source:'constant',name:'id'}],[[{text:'x'.repeat(200001)}]]),/too large/);
assert.equal(s.matches({website:'https://cases.test',urlIncludes:'#/case/'},'https://cases.test/#/case/42'),true);
assert.equal(s.matches({website:'https://cases.test'},'https://cases.test:444/#/case/42'),false);
assert.equal(s.matches({website:'https://cases.test'},'https://cases.test.evil/#/case/42'),false);
assert.throws(()=>s.validate({website:'https://cases.test',mode:'links',linkTemplate:'https://console.test/e/{id}',rules:[{source:'constant',name:'a',repeat:true}]}),/already makes one request per link/);
// A hostname without a scheme matches that host on any port or protocol; a port narrows it.
assert.equal(s.matches({website:'cases.test'},'http://cases.test:9000/case/1'),true);
assert.equal(s.matches({website:'cases.test:9000'},'https://cases.test:9000/case/1'),true);
assert.equal(s.matches({website:'cases.test:9000'},'https://cases.test/case/1'),false);
assert.equal(s.matches({website:'cases.test'},'https://cases.test.evil/case/1'),false);
assert.equal(s.matches({website:'cases.test'},'file://cases.test/x'),false);
assert.doesNotThrow(()=>s.validate({website:'cases.test:9000',mode:'parameters',rules:[{source:'constant',name:'a'}]}));
assert.throws(()=>s.validate({website:'cases test',mode:'parameters',rules:[{source:'constant',name:'a'}]}),/hostname/);
assert.equal(p.resolve([{source:'links',pattern:'/(?<id>one)',repeat:true}],[[{text:'https://a/one',url:'https://a/one'},{text:'https://b/one',url:'https://b/one'}]]).links.length,2);
console.log('Page parameter capture, pairing, conflicts, bounds and origin matching passed');
const generic={schemaVersion:2,api:{}};
const source={website:'https://cases.test',mode:'links',rules:[]};
// A links source needs its own pattern; it never borrows one from the connection.
assert.throws(()=>s.linkRule(generic,source),e=>e.field==='linkTemplate'&&/Enter a link pattern/.test(e.message));
assert.throws(()=>s.linkRule({...generic,api:{linkRegex:'/events/(?<id>\d+)'}},source),/Enter a link pattern/);
assert.throws(()=>s.validate(source),/Enter a link pattern/);
assert.throws(()=>s.linkRule(generic,{...source,pattern:'[oops'}),e=>e.field==='pattern'&&/Link regular expression/.test(e.message));
assert.throws(()=>s.linkRule(generic,{...source,linkTemplate:'https://console.test/events/42'}),e=>e.field==='linkTemplate'&&/parameter/.test(e.message));
assert.throws(()=>s.linkRule(generic,{...source,linkTemplate:'https://console.test/{id}',pattern:'(?<id>.*)'}),/not both/);
assert.throws(()=>p.validate([{source:'constant',name:'good'},{source:'page_url',pattern:'(.*)'}]),e=>e.ruleIndex===1&&e.field==='pattern'&&/Parameter rule 2/.test(e.message));
const simple=s.linkRule(generic,{...source,linkTemplate:'https://console.test/events/{id}?tenant={tenant}'});
assert.deepEqual(p.resolve([simple],[[{text:'https://console.test/events/evt%2042?tenant=prod'}]]).records[0].params,{id:'evt 42',tenant:'prod'});
const regex=s.linkRule(generic,{...source,pattern:'/records/(?<index>[^/?#]+)/(?<doc_id>[^/?#]+)'});
assert.deepEqual(p.resolve([regex],[[{text:'https://console.test/records/logs-index/evt%2042'}]]).records[0].params,{index:'logs-index',doc_id:'evt 42'});
assert.equal(s.validate({...source,mode:'parameters',pattern:'not used',selector:'[invalid',rules:[{source:'constant',name:'id'}]}).mode,'parameters');
assert.throws(()=>s.linkRule(generic,{...source,linkTemplate:'https://console.test/{__proto__}'}),/reserved/);
console.log('Missing and simple link formats, field errors and inactive link settings passed');
