/* Reads records for connections from the current editor. Used by the popup and by Settings' Preview. */
globalThis.VeiluxConnectorClient = (() => {
  const config=VeiluxConnectors;
  async function requestPayload(p, options={}) {
    const a=p.api||{}, effective=config.api(p), auth=p.auth||{}, job=a.job||{}, context=a.context||{};
    const inputParams=options.params||options.links?.map(url=>config.linkParams(p,url))||[{}];
    const payload={siem_base_url:p.siemBaseUrl,siem_links:[],parsed_params:inputParams.map(params=>({...a.parameters,...params})),
      link_regex:config.linkPattern(p),auth_type:auth.type||'none',verify_ssl:p.verifySsl!==false,
      tls_trust:p.tlsTrust||'system',ca_bundle_pem:p.caBundlePem||'',
      api_method:effective.method,api_path_template:effective.pathTemplate,api_headers_template:effective.headers,
      api_body_template:effective.bodyTemplate,response_path:effective.responsePath,api_query_template:a.queryTemplate||{},
      fetch_mode:a.fetchMode||'single_request',result_mode:'records',record_format:a.recordFormat||'objects',
      columns_path:a.columnsPath||'',total_path:a.totalPath||'',max_results_per_link:options.limit||p.maxRecords||5000,
      pagination_mode:a.pagination?.mode||'none',pagination_parameter:a.pagination?.parameter||'offset',
      pagination_size_parameter:a.pagination?.sizeParameter||'',pagination_cursor_path:a.pagination?.cursorPath||'',
      page_size:a.pagination?.pageSize||100,max_pages:a.pagination?.maxPages||10,test_path:a.testPath||'/' };
    payload.connector_timeout_seconds=Math.max(60,Number(job.timeoutSeconds)||0);
    if (options.includeAuth===false) {
      // Native browser-session requests use the tab's cookie jar directly.
    } else if (auth.type==='header') {
      if(!auth.headerValue) throw new Error('Enter the API key or token value.');
      if(!auth.headerName) throw new Error('Enter the header name under Sign-in.');
      payload.auth_header_name=auth.headerName;payload.auth_header_value=auth.headerValue;
    } else if(auth.type==='basic') {
      if(!auth.username||!auth.password) throw new Error('Enter the API username and password.');
      payload.auth_username=auth.username;payload.auth_password=auth.password;
    } else if(auth.type==='cookie') {
      if(!auth.cookieName) throw new Error('Enter the cookie name under Sign-in.');
      const cookie=await browser.cookies.get({url:p.siemBaseUrl,name:auth.cookieName});
      if(!cookie?.value) throw new Error('Log in to the API website first; its session cookie was not found.');
      payload.auth_cookie=cookie.value;payload.auth_cookie_name=auth.cookieName;
    } else if(auth.type==='oauth_client_credentials') {
      // The backend exchanges these for a short-lived access token.
      if(!auth.tokenUrl||!auth.clientId||!auth.clientSecret) throw new Error('Enter the token address, client ID and client secret under Sign-in.');
      payload.oauth_token_url=auth.tokenUrl;payload.oauth_client_id=auth.clientId;payload.oauth_client_secret=auth.clientSecret;payload.oauth_scope=auth.scope||'';
    } else if(auth.type==='browser_session') {
      const cookies=await browser.cookies.getAll({url:p.siemBaseUrl});
      if(!cookies.length) throw new Error('No login cookies found for the API address. Log in or choose API key authentication.');
      payload.auth_cookies=Object.fromEntries(cookies.map(c=>[c.name,c.value]));
      payload.auth_headers_from_cookies=auth.headersFromCookies||{};
      if(Object.values(payload.auth_headers_from_cookies).some(name=>!payload.auth_cookies[name])) throw new Error('A required cookie is missing. Check the cookie names and log in again.');
    }
    const map={createMethod:'create_method',createPathTemplate:'create_path_template',createQueryTemplate:'create_query_template',
      createBodyTemplate:'create_body_template',jobIdPath:'id_path',statusPathTemplate:'status_path_template',statusField:'status_field',
      resultsPathTemplate:'results_path_template',pollIntervalSeconds:'poll_interval_seconds',timeoutSeconds:'timeout_seconds'};
    Object.entries(map).forEach(([key,target])=>{if(job[key])payload['job_'+target]=job[key];});
    if(job.createParametersAs==='form')payload.job_create_parameters_as='form';
    if(job.errorMessagePath)payload.job_error_message_path=job.errorMessagePath;
    ['completeValues','errorValues'].forEach((key,i)=>{if(job[key])payload[i?'job_error_values':'job_complete_values']=job[key].split(',').map(v=>v.trim()).filter(Boolean);});
    const query=options.query??((options.links?.length||options.params?.length)?'':a.defaultQuery??'');
    if(query) {
      payload.parsed_params=(payload.parsed_params||[{}]).map(params=>({...params,query}));
      if(payload.fetch_mode==='search_job'&&job.queryParameter) payload.job_create_query_template={...job.createQueryTemplate,[job.queryParameter]:query};
    }
    if(!payload.siem_links.length&&!payload.parsed_params) payload.parsed_params=[{}];
    if(context.pathTemplate&&!query) {
      payload.context_method=context.method||'GET';payload.context_path_template=context.pathTemplate;payload.context_response_path=context.responsePath||'';
    }
    return payload;
  }
  async function fetchAPI(p,options={}) {
    if(p.api?.enabled===false&&p.dom?.discover?.strategy!=='api_request')throw new Error('This connection does not use an API. Choose “An API request” in step 2 of its settings.');
    const nativeSession=VeiluxBrowserSession.supports(p);
    const payload=await requestPayload(p,{...options,includeAuth:!nativeSession});
    if(nativeSession)return VeiluxBrowserSession.read(p,payload,options);
    // Cancelling the job (options.signal) or three minutes without an answer stops the wait.
    const timeout=AbortSignal.timeout(180000);
    const signal=options.signal&&AbortSignal.any?AbortSignal.any([timeout,options.signal]):timeout;
    const response=await VeiluxBackend.fetch('/fetch-siem-logs',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload),signal});
    const data=await response.json();
    if(!response.ok) throw new Error(errorMessage(data));
    return {logs:(options.statistics?data.record_logs:data.logs)||[],failed:data.failed||0,total:data.available_total??null,limited:!!data.limited,
      errors:data.errors||[],info:'configured API request'+(data.limited?'; record or page limit reached':'')+((data.warnings||[]).length?'; '+data.warnings.join('; '):''),query:options.query??p.api?.defaultQuery??'',linkedUrls:options.links||[]};
  }
  function pageJSON(selector) {
    const el=document.querySelector(selector||'pre');
    if(!el)throw new Error('The JSON element was not found. Check its selector.');
    return JSON.parse(el.textContent);
  }
  function pageIdentity(pattern,selector,flags) {
    // Without a selector, the page title and all visible text are searched.
    let text;
    try {text=selector?[...document.querySelectorAll(selector)].map(el=>el.innerText??el.textContent??'').join('\n'):document.title+'\n'+(document.body?.innerText||'');}
    catch(_) {return null;}
    const match=new RegExp(pattern.replace(/\(\?P</g,'(?<'),(flags||'').replace(/[^ims]/g,'')).exec(text.slice(0,1000000));
    return match?.groups ? Object.fromEntries(Object.entries(match.groups).filter(([,v])=>v!==undefined)) : null;
  }
  function matchesPage(p,url) {
    return config.matches(p,url)||(p.pageSources||[]).some(s=>ConnectorSources.matches(s,url));
  }
  async function candidates(profiles,tab) {
    const candidates=[],errors=[];let matched=0;
    for(const profile of profiles.filter(p=>p.schemaVersion===2&&matchesPage(p,tab.url))) {
      matched++;
      const sources=(profile.pageSources||[]).filter(s=>ConnectorSources.matches(s,tab.url));
      if(sources.length) {
        const ownSite=config.matches(profile,tab.url);
        for(const source of sources)try {
          let prepared=await ConnectorSources.prepare(profile,source,tab);
          if(ownSite) {
            // On the connection's own website, page-address values are shared with
            // its page sources. If nothing is found, the configured page reader runs.
            const own=config.linkParams(profile,tab.url)||{};
            prepared={...prepared,records:prepared.records.map(r=>({...r,params:{...own,...r.params}}))};
            if(prepared.records.every(r=>!Object.keys(r.params).length)&&profile.dom?.discover?.strategy!=='api_request') {
              candidates.push({profile,prepared:null,label:'source page'});continue;
            }
          }
          candidates.push({profile,prepared,label:source.name||source.website});
        }
        catch(e){errors.push(profile.name+': '+e.message);}
      } else candidates.push({profile,prepared:null,label:'source page'});
    }
    return {candidates,errors,matched};
  }
  async function read(p,tab,options={}) {
    if(!tab?.id)throw new Error('Open a page belonging to this connection first.');
    options={...options,tab};
    let prepared=options.prepared;
    const max=options.limit||p.maxRecords||5000;
    // options.resolved: the caller already read the page's value sources (candidates()).
    if(!prepared&&!options.resolved&&(p.pageSources||[]).some(s=>ConnectorSources.matches(s,tab.url))) {
      const found=await candidates([p],tab);
      if(found.candidates.length!==1)throw Error(found.candidates.length?'Several page sources match. Narrow their page filters or select a source in the popup.':found.errors.join('\n'));
      prepared=found.candidates[0].prepared;
    }
    if(prepared)return fetchAPI(p,{...options,params:prepared.records.map(r=>r.params),links:prepared.links});
    if(!config.matches(p,tab.url))throw new Error('Switch to the website for this connection, then try again.');
    const params=config.linkParams(p,tab.url);
    if(params&&p.api?.enabled!==false)return fetchAPI(p,{...options,params:[params]});
    const dom=p.dom?.discover||{};
    // Values read from page text come first, so API-only connections can use them too.
    if(p.api?.contentRegex&&p.api?.enabled!==false&&(!p.discoverPathHint||!tab.url.toLowerCase().includes(p.discoverPathHint.toLowerCase()))) {
      const frames=await browser.scripting.executeScript({target:{tabId:tab.id,allFrames:true},func:pageIdentity,args:[p.api.contentRegex,p.api.contentSelector||'',p.api.contentFlags||'']});
      const found=[...new Map(frames.filter(r=>r.result&&Object.keys(r.result).length).map(r=>[JSON.stringify(r.result),r.result])).values()];
      if(found.length)return fetchAPI(p,{...options,params:found});
    }
    if(dom.strategy==='api_request')return fetchAPI(p,options);
    if(dom.strategy==='json_dom') {
      const result=await browser.scripting.executeScript({target:{tabId:tab.id},func:pageJSON,args:[dom.jsonSelector||'pre']});
      const rows=config.records(result[0]?.result,p.api?.responsePath||'',p.api?.recordFormat,p.api?.columnsPath);
      return {logs:rows.slice(0,max).map(r=>JSON.stringify(r,null,2)),total:rows.length,limited:rows.length>max,info:'JSON displayed on the page'};
    }
    if(dom.strategy==='table_scrape'||!dom.strategy) {
      let results;
      try { results=await browser.scripting.executeScript({target:{tabId:tab.id,allFrames:true},func:tableScrapeInjected,args:[dom.tableSelector||'',max]}); }
      catch (_) { results=await browser.scripting.executeScript({target:{tabId:tab.id},func:tableScrapeInjected,args:[dom.tableSelector||'',max]}); }
      const best=pickScrapedTable(results.map(r=>r.result),p.discoverPathHint||'');
      if(!best)throw new Error('No visible result rows found. Open a search or enter its table selector.');
      return {...best,limited:best.total>best.logs.length,info:'visible rows only; other pages and virtualized rows are not included'};
    }
    if(dom.strategy==='custom_script') {
      // Runs in the page's own JavaScript world: extension scripts may not
      // turn text into code under Manifest V3, in Chrome or in Firefox.
      const results=await browser.scripting.executeScript({target:{tabId:tab.id},world:'MAIN',func:customScriptInjected,args:[dom.customScript||'']});
      const result=results&&results[0]&&results[0].result;
      if(!result||result.error)throw new Error(result?.error||'The page script returned nothing. It must return { logs: [...] }.');
      return {...result,info:result.info||'page script',logs:(result.logs||[]).map(v=>typeof v==='string'?v:JSON.stringify(v,null,2))};
    }
    const message={action:'veiluxDiscoverExtract',config:dom};
    let response;
    try {response=await browser.tabs.sendMessage(tab.id,message);} catch (_) {
      await browser.scripting.executeScript({target:{tabId:tab.id},files:['browser-polyfill.js','content.js']});
      response=await browser.tabs.sendMessage(tab.id,message);
    }
    if(!response||response.success===false||response.error)throw new Error(response?.error||'The page did not return records.');
    return {...response,info:'page extraction',logs:(response.logs||[]).map(v=>typeof v==='string'?v:JSON.stringify(v,null,2))};
  }
  // A connection's own page script, run in the page's JavaScript world. It is
  // real JavaScript with the page's rights, the same trust as code the analyst
  // runs in their own session. The body may await and must return
  // { logs: [...], failed?, total?, info? }. Self-contained: injected as is.
  function customScriptInjected(source) {
    if (!source || !source.trim()) return { error: 'No page script is configured for this connection.' };
    function getByPath(obj, path) {
      return !path ? obj : path.split('.').reduce((value, key) => value == null ? undefined : value[key], obj);
    }
    function readCodeBlockText(element) {
      const lines = element.querySelectorAll('span.euiCodeBlock__line');
      return lines.length ? Array.from(lines).map(line => line.textContent).join('\n').trim() : element.textContent.trim();
    }
    function waitForElement(selector, timeoutMs, message) {
      return new Promise((resolve, reject) => {
        const start = Date.now();
        (function check() {
          const found = document.querySelector(selector);
          if (found) return resolve(found);
          if (Date.now() - start > (timeoutMs || 10000)) return reject(new Error(message || 'Timed out waiting for: ' + selector));
          setTimeout(check, 150);
        })();
      });
    }
    let runner;
    try { runner = new Function('helpers', 'document', 'window', '"use strict";\nreturn (async () => {\n' + source + '\n})();'); }
    catch (error) {
      return { error: error instanceof EvalError || /unsafe-eval|Content Security Policy/i.test(error.message)
        ? 'This page\'s security policy does not allow page scripts. Use the table, JSON or API reader for this connection.'
        : 'The page script has a syntax error: ' + error.message };
    }
    return Promise.resolve(runner({ waitForElement, readCodeBlockText, getByPath }, document, window)).then(result => {
      if (!result || typeof result !== 'object') return { error: 'The page script must return an object like { logs: [...] }.' };
      const logs = Array.isArray(result.logs) ? result.logs.map(item => typeof item === 'string' ? item : JSON.stringify(item, null, 2)) : [];
      return { logs, failed: typeof result.failed === 'number' ? result.failed : 0,
        total: typeof result.total === 'number' ? result.total : logs.length, note: result.note || 'custom_script', info: String(result.info || '') };
    }, error => ({ error: 'The page script failed: ' + (error && error.message ? error.message : String(error)) }));
  }

  // Page table reader, injected into the page. Every caller uses this copy.
  function tableScrapeInjected(selector, maxRows) {
  function cellText(c) { return (c.innerText || '').replace(/\s+/g, ' ').trim(); }
  var tables;
  try {
    tables = Array.prototype.slice.call(document.querySelectorAll(selector || 'table'));
  } catch (e) {
    return { logs: [], total: 0, error: 'Bad table selector: ' + e.message };
  }

  var best = null;
  var bestScore = 0;
  tables.forEach(function(t) {
    if (!(t.offsetWidth || t.offsetHeight)) return;  // hidden
    if (!t.rows || t.rows.length < 2) return;        // needs header + data
    var score = t.rows.length * (t.rows[0].cells ? t.rows[0].cells.length : 0);
    if (score > bestScore) { best = t; bestScore = score; }
  });
  if (!best) return { logs: [], total: 0 };

  var headerCells;
  var dataRows;
  if (best.tHead && best.tHead.rows.length) {
    headerCells = best.tHead.rows[best.tHead.rows.length - 1].cells;
    dataRows = [];
    for (var b = 0; b < best.tBodies.length; b++) {
      dataRows = dataRows.concat(Array.prototype.slice.call(best.tBodies[b].rows));
    }
  } else {
    headerCells = best.rows[0].cells;
    dataRows = Array.prototype.slice.call(best.rows).slice(1);
  }
  var headers = Array.prototype.map.call(headerCells, cellText);

  var logs = [];
  for (var i = 0; i < dataRows.length && logs.length < maxRows; i++) {
    var cells = dataRows[i].cells;
    if (!cells || !cells.length) continue;
    var obj = {};
    var nonEmpty = 0;
    for (var j = 0; j < cells.length; j++) {
      var key = headers[j] && headers[j].length ? headers[j] : ('col_' + j);
      var val = cellText(cells[j]);
      if (val) nonEmpty++;
      obj[key] = val;
    }
    if (nonEmpty > 0) logs.push(JSON.stringify(obj, null, 2));
  }
  return {
    logs: logs,
    total: dataRows.length,
    frameUrl: (window.location && window.location.href) || ''
  };
}

// Choose which frame's scraped table to keep. Frameset consoles keep every
// previously-visited screen alive as a hidden frame, so "largest table
// anywhere" can grab a table the analyst is NOT looking at (e.g. an alert
// list in a hidden frame beating the events table on screen). A table from a
// frame whose URL matches the connector's search-page hint IS the search
// results — prefer it regardless of size; fall back to largest overall.
function pickScrapedTable(candidates, hint) {
  const withLogs = candidates.filter(function(c) { return c && Array.isArray(c.logs) && c.logs.length > 0; });
  const hintL = (hint || '').toLowerCase();
  const preferred = hintL
    ? withLogs.filter(function(c) { return (c.frameUrl || '').toLowerCase().indexOf(hintL) !== -1; })
    : [];
  const pool = preferred.length ? preferred : withLogs;
  let best = null;
  pool.forEach(function(c) { if (!best || c.logs.length > best.logs.length) best = c; });
  return best;
}


  function errorMessage(data) {
    return typeof data.detail==='string'?data.detail:Array.isArray(data.detail)?data.detail.map(e=>(e.loc||[]).slice(1).join('.')+': '+e.msg).join('; '):'The API request failed. Check the connection settings.';
  }
  return {requestPayload,fetchAPI,read,matchesPage,candidates,errorMessage,table:tableScrapeInjected};
})();
