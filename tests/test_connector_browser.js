const assert=require('node:assert/strict');
require('../extension/connector_config.js');
require('../extension/connector_browser.js');
require('../extension/connector_client.js');
const session=VeiluxBrowserSession;
const base={schemaVersion:2,websiteUrl:'https://siem.test',siemBaseUrl:'https://siem.test',name:'SIEM',
  auth:{type:'browser_session'},api:{enabled:true,method:'GET',pathTemplate:'/records/${id}',responsePath:'rows',totalPath:'total'}};
const tab={id:4,url:'https://siem.test/app',incognito:false};
let sent=[],respond;
globalThis.browser={tabs:{query:async()=>[tab]},scripting:{executeScript:async options=>{
  const spec=options.args[0];sent.push(spec);return [{result:await respond(spec)}];
}},cookies:{get:async()=>{throw Error('Cookie values must stay in the browser');},getAll:async()=>{throw Error('No cookie copying');}}};
async function run(profile,params=[{id:'one'}],options={}) {
  sent=[];
  return VeiluxConnectorClient.fetchAPI(profile,{params,...options});
}
async function main() {
  assert.equal(session.supports(base),true);
  for(const p of [
    {...base,auth:{type:'cookie'}},{...base,auth:{type:'header'}},{...base,siemBaseUrl:'https://api.test'},
    {...base,api:{...base.api,executeVia:'backend'}},{...base,api:{...base.api,fetchMode:'search_job'}},
    {...base,api:{...base.api,context:{pathTemplate:'/context'}}}])assert.equal(session.supports(p),false);
  respond=async()=>({status:200,data:{rows:[{ok:true}],total:1}});
  let result=await run(base,[{id:'a/b',query:'x'},{query:'x',id:'a/b'}]);
  assert.equal(sent.length,1);assert.equal(new URL(sent[0].url).pathname,'/records/a%2Fb');
  assert.deepEqual(JSON.parse(result.logs[0]),{ok:true});assert.equal(result.total,1);
  assert.equal(result.limited,false);assert.equal(result.failed,0);
  await assert.rejects(()=>run({...base,maxRecords:100001}),/Invalid extraction limit/);assert.equal(sent.length,0);
  let payload=await VeiluxConnectorClient.requestPayload({...base,api:{...base.api,method:'POST',
    pathTemplate:'/records/${id}',bodyTemplate:'{"text":"${text}","count":${n+2}}',queryTemplate:{q:'${text}'},headersTemplate:{'X-Ref':'${id}'}}},
    {params:[{id:'x/y',text:'"é\\\n',n:'3'}],includeAuth:false});
  let spec=session.requestSpec(payload,payload.parsed_params[0]);
  assert.deepEqual(JSON.parse(spec.body),{text:'"é\\\n',count:5});
  assert.equal(new URL(spec.url).searchParams.get('q'),'"é\\\n');assert.equal(spec.headers['X-Ref'],'x/y');
  assert.throws(()=>session.requestSpec({...payload,api_path_template:'//elsewhere.test'},{}),/relative/);
  assert.throws(()=>session.requestSpec(payload,{}),/Missing request/);
  respond=async spec=>({status:200,data:{rows:[{n:Number(new URL(spec.url).searchParams.get('offset'))}],total:3}});
  const paged={...base,api:{...base.api,pagination:{mode:'offset',pageSize:1,maxPages:5,parameter:'offset'}}};
  result=await run(paged);assert.equal(sent.length,3);assert.equal(result.logs.length,3);assert.equal(result.limited,false);
  result=await run({...paged,maxRecords:2});assert.equal(sent.length,2);assert.equal(result.logs.length,2);assert.equal(result.limited,true);
  respond=async()=>({status:200,data:{columns:[{name:'x'}],rows:[[true]],next:'repeat'}});
  const columns={...base,api:{...base.api,recordFormat:'columns',columnsPath:'columns'}};
  result=await run(columns);assert.deepEqual(JSON.parse(result.logs[0]),{x:true});assert.equal(result.total,null);
  await assert.rejects(()=>run({...columns,api:{...columns.api,pagination:{mode:'cursor',parameter:'next',cursorPath:'next',maxPages:5}}}),/repeated/);
  assert.equal(sent.length,2);
  respond=async spec=>new URL(spec.url).pathname.endsWith('/one')?{status:403}:{status:200,data:{rows:[{allowed:true}]}};
  result=await run(base,[{id:'one'},{id:'two'}]);assert.equal(result.failed,1);assert.equal(sent.length,2);assert.equal(result.logs.length,1);
  respond=async()=>({status:401});await assert.rejects(()=>run(base,[{id:'one'},{id:'two'}]),/signed-in SIEM tab.*401/);assert.equal(sent.length,1);
  // A record another account cannot see (404) skips only that record: earlier and later records are kept.
  respond=async spec=>new URL(spec.url).pathname.endsWith('/b')?{status:404}:{status:200,data:{rows:[{id:new URL(spec.url).pathname.split('/').pop()}]}};
  result=await run(base,[{id:'a'},{id:'b'},{id:'c'}]);
  assert.equal(sent.length,3);assert.deepEqual(result.logs.map(l=>JSON.parse(l).id),['a','c']);assert.equal(result.failed,1);
  assert.match(result.errors[0],/^For id=b: .*HTTP 404 \(not found\).*signed-in account/);
  respond=async()=>({status:404});
  await assert.rejects(()=>run(base,[{id:'a'},{id:'b'}]),/All 2 requests failed\. First failure: For id=a: .*HTTP 404/);assert.equal(sent.length,2);
  await assert.rejects(()=>run(base,[{id:'a'}]),/^Error: For id=a: The SIEM API returned HTTP 404/);
  browser.tabs.query=async()=>[{id:8,url:'https://cases.test',incognito:false}];
  await assert.rejects(()=>run(base),/leave that tab open/);assert.equal(sent.length,0);
  browser.tabs.query=async()=>[tab];
  await assert.rejects(()=>run(base,[{id:'one'}],{tab:{id:8,incognito:true}}),/leave that tab open/);
  await assert.rejects(()=>run(base,[{id:'one'}],{tab:{id:8,incognito:false,cookieStoreId:'different-container'}}),/leave that tab open/);
  // The injected boundary checks a navigation race and never follows redirects.
  globalThis.location={origin:'https://cases.test'};let network=0;
  globalThis.fetch=async()=>{network++;return {type:'opaqueredirect'};};
  result=await session.pageRequest({origin:'https://siem.test',url:'https://siem.test/records',timeout:100});
  assert.match(result.error,/changed websites/);assert.equal(network,0);
  location.origin='https://siem.test';
  globalThis.fetch=async(url,options)=>{network++;assert.equal(options.credentials,'same-origin');assert.equal(options.redirect,'manual');return {type:'opaqueredirect'};};
  result=await session.pageRequest({origin:'https://siem.test',url:'https://siem.test/records',timeout:100});
  assert.match(result.error,/redirected/);assert.equal(network,1);
  let started=false,aborted=false;
  globalThis.fetch=async(url,options)=>new Promise((resolve,reject)=>{
    started=true;options.signal.addEventListener('abort',()=>{aborted=true;reject(Error('aborted'));});
  });
  result=await session.pageRequest({origin:'https://siem.test',url:'https://siem.test/records',timeout:20});
  assert.equal(started,true);assert.equal(aborted,true);assert.match(result.error,/timed out/);
  globalThis.fetch=async()=>({ok:true,status:200,json:async()=>({recovered:true})});
  result=await session.pageRequest({origin:'https://siem.test',url:'https://siem.test/records',timeout:100});
  assert.deepEqual(result.data,{recovered:true});
  console.log('Browser-session routing, templates, cookie isolation, mapping, pagination, failures, origins and started-request timeout checks passed');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
