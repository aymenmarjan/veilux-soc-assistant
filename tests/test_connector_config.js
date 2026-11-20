const assert=require('node:assert/strict');
require('../extension/connector_config.js');
const c=globalThis.VeiluxConnectors;
const p={schemaVersion:2,api:{linkTemplate:'https://logs.test/event/{id}?tenant={tenant}'}};
assert.deepEqual(c.linkParams(p,'https://logs.test/event/a%2Fb?tenant=t%201'),{id:'a/b',tenant:'t 1'});
assert.equal(c.linkParams(p,'https://logsXtest/event/a?tenant=b'),null);
assert.throws(()=>c.linkPattern({api:{linkTemplate:'https://logs.test/{id}/{id}'}}),/only once/);
assert.equal(c.api({schemaVersion:2,api:{}}).bodyTemplate,'');
assert.deepEqual(c.api({schemaVersion:2,api:{}}).headers,{});
assert.equal(c.api({schemaVersion:2,api:{responsePath:''}}).responsePath,'');
// Nothing falls back to template values.
assert.equal(c.api({}).pathTemplate,'');
assert.equal(c.linkPattern({schemaVersion:2,platform:'opensearch',api:{}}),'(?!)');
assert.equal(c.statsMode({schemaVersion:2,platform:'opensearch'}),'records');

// Only connections in the current format are used; anything else was saved by a
// development build before 1.0.0 and is set aside, unchanged, never converted.
const current={schemaVersion:2,name:'Current',api:{pathTemplate:'/own'}};
const preRelease=[{id:'v1',name:'No version',siemHost:'siem.test',api:{}},{...current,legacyDefaults:true},
  {...current,soarHost:'cases.test'},null,'text'];
const split=c.usable([current,...preRelease]);
assert.deepEqual(split.profiles,[current]);assert.equal(split.setAside.length,preRelease.length);
assert.equal(split.profiles[0],current);assert.deepEqual(split.setAside[0],preRelease[0]);
assert.deepEqual(c.usable(undefined),{profiles:[],setAside:[]});
assert.ok(c.isCurrent({schemaVersion:2,legacyDefaults:false,soarHost:''}));
assert.ok(!('convertOld' in c));
assert.deepEqual(c.records({columns:['x','y'],rows:[[false,null],[3,'text']]},'rows','columns','columns'),[{x:false,y:null},{x:3,y:'text'}]);
assert.throws(()=>c.records({columns:['x','x'],rows:[[1,2]]},'rows','columns','columns'),/unique/);
assert.equal(c.matches({siemHost:'portal.test',pageMatch:'/workspace/a'},'https://portal.test/workspace/b'),false);
assert.equal(c.matches({siemHost:''},'file:///tmp/logs'),false);
// Top values per field: 5 by default, adjustable from 1 to 10.
const many=Array.from({length:12},(_,i)=>({user:'u'+String(i).padStart(2,'0')}));
assert.equal(c.statistics(many)[0].topValues.length,5);
assert.equal(c.statistics(many,10)[0].topValues.length,10);
assert.equal(c.statistics(many,50)[0].topValues.length,10);
assert.equal(c.statistics(many,0)[0].topValues.length,5);
const stats=c.statistics([JSON.parse('{"__proto__":"value","tags":["a","a","b"]}'),{tags:['a']}]);
assert.equal(stats.find(s=>s.field==='__proto__').topValues[0].value,'value');
assert.equal(stats.find(s=>s.field==='tags').topValues[0].count,2);
assert.equal(stats.find(s=>s.field==='tags').percentage,100);
assert.equal({}.value,undefined);
console.log('Connector configuration, link parsing and local statistics checks passed');
