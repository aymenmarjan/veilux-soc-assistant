/* Same-origin reads through the signed-in tab. Cookies stay in the browser. */
globalThis.VeiluxBrowserSession = (() => {
  function supports(p) {
    try {
      return p.auth?.type==='browser_session' && p.api?.executeVia!=='backend' &&
        (p.api?.fetchMode||'single_request')==='single_request' && !p.api?.context?.pathTemplate &&
        new URL(p.websiteUrl||p.siemBaseUrl).origin===new URL(p.siemBaseUrl).origin;
    } catch (_) { return false; }
  }
  const at=(data,path)=>path ? path.split('.').reduce((v,k)=>v?.[k],data) : data;
  // A short, local-only label naming the values one request used, such as id=abc.
  function describe(params) {
    const parts=Object.entries(params||{}).filter(([key])=>key!=='query').map(([key,value])=>key+'='+String(value).slice(0,60));
    return parts.slice(0,3).join(', ')+(parts.length>3?', …':'');
  }
  function render(template,params,encode=v=>v) {
    return String(template||'').replace(/\$\{([A-Za-z0-9_.]+)(?:\s*([+-])\s*(\d+))?\}/g,(_,key,op,n)=>{
      if(!Object.hasOwn(params,key))throw Error('Missing request value: '+key+'. No value source supplied it for this page. Open the page that shows it, or add a value source or fixed value under Request values.');
      let value=String(params[key]);
      if(op && Number.isFinite(Number(value)))value=String(Math.trunc(Number(value))+(op==='+'?1:-1)*Number(n));
      return encode(value);
    });
  }
  function requestSpec(payload,params,health=false) {
    const path=health?payload.test_path:payload.api_path_template;
    if(!path?.startsWith('/')||path.startsWith('//'))throw Error('Enter a request path beginning with /, relative to the API address.');
    const base=new URL(payload.siem_base_url);
    const url=new URL(payload.siem_base_url.replace(/\/$/,'')+render(path,params,encodeURIComponent));
    if(!['http:','https:'].includes(base.protocol)||base.username||base.password||url.origin!==base.origin)
      throw Error('The request must stay on this connection’s API address.');
    const headers={'Content-Type':'application/json'};
    for(const [key,value] of Object.entries(payload.api_headers_template||{}))headers[key]=render(value,params);
    const method=health?'GET':payload.api_method;
    let body;
    if(!health) {
      for(const [key,value] of Object.entries(payload.api_query_template||{}))url.searchParams.set(key,render(value,params));
      if(payload.api_body_template) {
        if(method.toUpperCase()==='GET')throw Error('GET requests use query parameters; leave Request body empty.');
        body=JSON.stringify(JSON.parse(render(payload.api_body_template,params,v=>JSON.stringify(v).slice(1,-1))));
      }
    }
    return {url:url.href,origin:base.origin,method,headers,...(body===undefined?{}:{body})};
  }
  // Self-contained, injected into the extension's isolated world. Recheck origin
  // inside the tab so navigation between selection and injection cannot send data elsewhere.
  async function pageRequest(spec) {
    if(location.origin!==spec.origin||new URL(spec.url).origin!==location.origin)
      return {error:'The SIEM tab changed websites. Open this connection’s SIEM and try again.'};
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),spec.timeout);
    try {
      const response=await fetch(spec.url,{method:spec.method,headers:spec.headers,body:spec.body,
        credentials:'same-origin',redirect:'manual',cache:'no-store',signal:controller.signal});
      if(response.type==='opaqueredirect'||(response.status>=300&&response.status<400))
        return {error:'The signed-in SIEM tab redirected the API request. Check the request path and finish signing in on that tab.'};
      if(!response.ok)return {status:response.status};
      if(spec.health)return {status:response.status};
      try{return {status:response.status,data:await response.json()};}
      catch(_){return {error:controller.signal.aborted?'The SIEM request timed out; no further requests were sent.':
        'The SIEM did not return JSON. Check the request path and that the SIEM tab is signed in.'};}
    } catch (_) {
      return {error:controller.signal.aborted?'The SIEM request timed out; no further requests were sent.':
        'The browser could not read the SIEM API. Check the SIEM tab, its certificate and the request path.'};
    } finally {clearTimeout(timer);}
  }
  async function sessionTab(p,preferred) {
    const origin=new URL(p.siemBaseUrl).origin;
    const tabs=await browser.tabs.query({});
    const matches=t=>{try{return new URL(t.url).origin===origin && (!preferred||t.incognito===preferred.incognito) &&
      (!preferred?.cookieStoreId||t.cookieStoreId===preferred.cookieStoreId);}catch(_){return false;}};
    const matching=tabs.filter(matches);
    const tab=matching.find(t=>t.id===preferred?.id)||matching.find(t=>t.active)||matching[0];
    if(!tab)throw Error('Open '+(p.name||'this connection')+'’s SIEM in this browser, sign in, leave that tab open and retry. The case-management tab cannot supply the SIEM login.');
    return tab;
  }
  async function send(p,tab,spec,deadline,health=false) {
    const timeout=Math.min(30000,deadline-Date.now());
    if(timeout<=0)throw Error('The SIEM request timed out; no further requests were sent.');
    const headers={...spec.headers};
    // Only cookies named under "Send login cookies as headers" are read here.
    // Otherwise the tab sends its own cookies; none are read or copied.
    for(const [header,name] of Object.entries(p.auth?.headersFromCookies||{})) {
      const options={url:spec.url,name};
      if(tab.cookieStoreId)options.storeId=tab.cookieStoreId;
      else if(browser.cookies.getAllCookieStores) {
        const stores=await browser.cookies.getAllCookieStores();
        const store=stores.find(s=>s.tabIds.includes(tab.id));if(store)options.storeId=store.id;
      }
      const cookie=await browser.cookies.get(options);
      if(!cookie?.value)throw Error('A required cookie is missing. Check “Send login cookies as headers” under Sign-in; leave it blank unless this API requires it.');
      headers[header]=cookie.value;
    }
    let injected;
    try {injected=await browser.scripting.executeScript({target:{tabId:tab.id},func:pageRequest,args:[{...spec,headers,timeout,health}]});}
    catch (_) {throw Error('The SIEM tab could not be read. Reopen the SIEM in this browser and retry.');}
    const result=injected?.[0]?.result;
    if(!result)throw Error('The SIEM tab closed or changed while reading records. Reopen it and retry.');
    if(result.error)throw Error(result.error);
    if(result.status===401)throw Error('The API rejected the request from the signed-in SIEM tab (HTTP 401). Check this API path and the account’s access to these records. A successful status check does not verify record access.');
    if(result.status<200||result.status>=300) {
      const advice={403:'. Check account permissions and any required security headers.',404:' (not found). The record may not exist, or the signed-in account may not be allowed to see it.'}[result.status]||'. Check the request settings.';
      const error=Error('The SIEM API returned HTTP '+result.status+advice);
      error.status=result.status;throw error;
    }
    return result.data;
  }
  async function check(p,payload) {
    const tab=await sessionTab(p);
    await send(p,tab,requestSpec(payload,{},true),Date.now()+10000,true);
    return {status:'connected',message:'Connection check succeeded in the SIEM tab; record access has not been checked. Use Preview extraction to verify records.'};
  }
  async function read(p,payload,options={}) {
    for(const [key,max] of [['max_results_per_link',100000],['page_size',5000],['max_pages',50]])
      if(!Number.isInteger(payload[key])||payload[key]<1||payload[key]>max)throw Error('Invalid extraction limit. Check Maximum records and pagination settings.');
    if(!Number.isFinite(payload.connector_timeout_seconds)||payload.connector_timeout_seconds<=0||payload.connector_timeout_seconds>180)
      throw Error('The connector timeout must be between 1 and 180 seconds.');
    const tab=await sessionTab(p,options.tab),deadline=Date.now()+payload.connector_timeout_seconds*1000;
    const rows=[],errors=[],totals=[],seenParams=new Set();let limited=false;
    for(const params of payload.parsed_params) {
      const key=JSON.stringify(Object.entries(params).sort(([a],[b])=>a.localeCompare(b)));
      if(seenParams.has(key))continue;seenParams.add(key);
      if(options.signal?.aborted)throw Error('Extraction cancelled; no further requests were sent.');
      if(rows.length>=payload.max_results_per_link){limited=true;break;}
      const spec=requestSpec(payload,params),seenCursors=new Set();let cursor=null,available=null,count=0;
      for(let page=0;page<payload.max_pages;page++) {
        const url=new URL(spec.url),mode=payload.pagination_mode;
        if(mode!=='none') {
          if(!payload.pagination_parameter)throw Error('Enter the pagination parameter name.');
          if(payload.pagination_size_parameter)url.searchParams.set(payload.pagination_size_parameter,payload.page_size);
          if(mode==='offset')url.searchParams.set(payload.pagination_parameter,page*payload.page_size);
          else if(cursor!==null)url.searchParams.set(payload.pagination_parameter,cursor);
        }
        let data;
        try{data=await send(p,tab,{...spec,url:url.href},deadline);}
        // An HTTP error for one record (404, 403, 5xx…) skips that record only. Sign-in
        // rejections (401), redirects, timeouts and tab problems still stop the batch.
        catch(e){if(!e.status)throw e;const label=describe(params);errors.push((label?'For '+label+': ':'')+e.message);break;}
        const batch=VeiluxConnectors.records(data,payload.response_path,payload.record_format,payload.columns_path);
        const total=payload.total_path?at(data,payload.total_path):null;
        available=Number.isInteger(total)&&total>=0?total:null;
        const room=payload.max_results_per_link-rows.length;
        rows.push(...batch.slice(0,room));count+=Math.min(batch.length,room);
        cursor=payload.pagination_cursor_path?at(data,payload.pagination_cursor_path):null;
        const exhausted=!batch.length||(available!==null&&count>=available)||(mode==='offset'&&batch.length<payload.page_size)||(mode==='cursor'&&(cursor==null||cursor===''));
        limited ||= batch.length>room;
        if(mode==='none'||exhausted){limited ||= available!==null&&count<available;break;}
        if(rows.length>=payload.max_results_per_link||page===payload.max_pages-1){limited=true;break;}
        if(mode==='cursor') {
          if(!['string','number'].includes(typeof cursor)||seenCursors.has(String(cursor)))throw Error('The API returned a repeated or invalid page token. Check pagination settings.');
          seenCursors.add(String(cursor));
        }
      }
      totals.push(available);
    }
    if(!rows.length&&errors.length)throw Error(errors.length===1?errors[0]:'All '+errors.length+' requests failed. First failure: '+errors[0]);
    return {logs:rows.map(r=>JSON.stringify(r,null,2)),failed:errors.length,errors,limited,
      total:totals.length===seenParams.size&&totals.every(n=>n!==null)?totals.reduce((a,b)=>a+b,0):null,
      info:'configured API request through the signed-in SIEM tab'+(limited?'; record or page limit reached':''),
      query:options.query??p.api?.defaultQuery??'',linkedUrls:options.links||[]};
  }
  return {supports,check,read,requestSpec,pageRequest};
})();
