// Minimal extension APIs; popup.js and background.js themselves are unmodified.
(() => {
 // Sandboxed frames (report previews) have no storage and need no extension APIs.
 try { window.localStorage; } catch (_) { return; }
 const listeners=[]; const messages=[]; const pending=[];
 const values=JSON.parse(localStorage.getItem('testStorage') || '{}');
 if (!values.capturedLogs) Object.assign(values,{capturedLogs:['password=synthetic-initial'],groqApiKey:'synthetic-api',virustotalApiKey:'synthetic-ti',enablePatternSanitization:false,
  backendToken:'veilux-test-backend-key-0123456789'});  // tests/backend_key.py
 function area(data, persistent) {
  return {
   async get(keys) { if(typeof keys==='string') keys=[keys];return keys ? Object.fromEntries(keys.map(k=>[k,data[k]])) : {...data}; },
   async set(next) {
    const changes=Object.fromEntries(Object.entries(next).map(([k,v])=>[k,{oldValue:data[k],newValue:v}]));
    Object.assign(data,next);if(persistent)localStorage.setItem('testStorage',JSON.stringify(data));else sessionStorage.setItem('testSession',JSON.stringify(data));
    for(const fn of listeners)fn(changes,persistent?'local':'session');
   },
   async remove(keys) {if(typeof keys==='string')keys=[keys];keys.forEach(k=>delete data[k]);if(persistent)localStorage.setItem('testStorage',JSON.stringify(data));else sessionStorage.setItem('testSession',JSON.stringify(data));},
   async clear() { await this.remove(Object.keys(data)); }
  };
 }
 const emptyEvent={addListener(){}};
 async function deliver(m){let answer;for(const fn of messages){const r=await fn(m);if(answer===undefined&&r!==undefined&&typeof r!=='boolean')answer=r;}return answer;}
 window.browser={
  storage:{local:area(values,true),session:area(JSON.parse(sessionStorage.getItem('testSession') || '{}'),false),onChanged:{addListener(fn){listeners.push(fn)},removeListener(fn){const i=listeners.indexOf(fn);if(i>=0)listeners.splice(i,1)}}},
  // Messages sent before the background frame has loaded wait for its listener.
  // Like the browser, sendMessage resolves with the first listener reply that is not true/false/undefined.
  runtime:{onInstalled:emptyEvent,onMessage:{addListener(fn){messages.push(fn);pending.splice(0).forEach(([m,reply])=>deliver(m).then(reply))}},getURL:p=>'/extension/'+p,getPlatformInfo:async()=>({}),getManifest:()=>({version:'1.0.0'}),
   sendMessage:m=>messages.length?deliver(m):new Promise(reply=>pending.push([m,reply]))},
  action:{setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{}},
  tabs:{query:async()=>[],create:async()=>{}},contextMenus:{onClicked:emptyEvent,create(){}},windows:{create(){}}
 };
 // The popup's background worker runs in a hidden frame with the same scripts
 // the extension loads, sharing these mocked APIs.
 if (location.pathname.endsWith('/popup.html')) document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('background-test')) return;
  const frame=document.createElement('iframe');frame.id='background-test';frame.hidden=true;document.body.appendChild(frame);
  frame.contentWindow.browser=window.browser;
  for (const file of ['backend_address.js','cases.js','connector_config.js','connector_parameters.js','connector_sources.js',
                      'connector_client.js','connector_browser.js','extraction_jobs.js','background.js']) {
   const script=frame.contentDocument.createElement('script');script.src='/extension/'+file;script.async=false;
   frame.contentDocument.head.appendChild(script);
  }
 });
})();
