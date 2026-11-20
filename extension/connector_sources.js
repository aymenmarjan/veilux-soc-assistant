/* Value sources that read a page (address, links, text, attributes) and fill a connection's API request. */
globalThis.ConnectorSources = (() => {
  // A website written without a scheme (cases.example.com or cases.example.com:9000)
  // matches that host on http or https; a full address must match its exact origin.
  const hostOnly=website=>!/^[a-z][a-z0-9+.-]*:\/\//i.test(website||'');
  function matches(source,url) {
    try {
      const page=new URL(url);
      if(!['http:','https:'].includes(page.protocol))return false;
      let same;
      if(hostOnly(source.website)) {const site=new URL('https://'+source.website);same=site.hostname===page.hostname&&(!site.port||site.port===page.port);}
      else same=new URL(source.website).origin===page.origin;
      return same && (!source.urlIncludes||url.includes(source.urlIncludes));
    }
    catch(_) {return false;}
  }
  function validate(source) {
    let site;
    try {
      if(hostOnly(source.website)&&!/^[A-Za-z0-9.-]+(:\d+)?$/.test(source.website||''))throw Error();
      site=new URL(hostOnly(source.website)?'https://'+source.website:source.website);
      if(!['https:','http:'].includes(site.protocol)||site.username||site.password||site.search||site.hash)throw Error();
    }catch(_){throw Object.assign(Error('Use an HTTP(S) website address, or just a hostname such as cases.example.com. Put page filters in “Only when the page address contains”.'),{field:'website'});}
    if(!['links','parameters'].includes(source.mode))throw Error('Choose record links or page parameters.');
    const rules=source.rules||[];ConnectorParameters.validate(rules);
    if(rules.some(r=>r.source==='links'))throw Error('Use an element attribute rule for link values.');
    if(source.mode==='links')linkRule(null,source);
    if(source.mode==='links'&&rules.some(r=>r.repeat))throw Error('“Links on a page” already makes one request per link. Turn off “Make one request for each value found” on the other value sources for this page.');
    if(source.mode==='parameters'&&!rules.length)throw Error('Add at least one value source for this page.');
    for(const selector of [source.mode==='links'?source.selector:null,...rules.filter(r=>['text','html','attribute'].includes(r.source)).map(r=>r.selector)].filter(Boolean)) {
      if(selector.length>2000)throw Error('The element selector is too long.');
      if(typeof document!=='undefined')document.createDocumentFragment().querySelector(selector);
    }
    return source;
  }
  function linkRule(profile,source) {
    const field=source.linkTemplate?'linkTemplate':'pattern';
    const fail=message=>{throw Object.assign(Error(message),{field});};
    if(source.pattern&&source.linkTemplate)fail('Use either a link pattern or a regular expression, not both.');
    if(!source.pattern&&!source.linkTemplate)
      throw Object.assign(Error('Enter a link pattern for “Links on a page”.'),{field:'linkTemplate'});
    let pattern;
    try {
      pattern=VeiluxConnectors.linkPattern({api:{linkTemplate:source.linkTemplate,linkRegex:source.pattern}});
      ConnectorParameters.validateRule({source:'links',pattern});
    } catch(error) {
      fail((source.linkTemplate?'Link pattern':'Link regular expression')+': '+error.message);
    }
    return {source:'links',pattern,repeat:true,required:true,decode:true};
  }
  function captureDOM(rules,selector) {
    try {
      let size=0;
      const inputs=rules.map(r=>{
        if(!['text','html','attribute'].includes(r.source))return [];
        const elements=document.querySelectorAll(r.selector);
        if(elements.length>500)throw Error('Too many elements. Use a more specific selector.');
        return [...elements].map(el=>{
          const text=r.source==='html'?el.innerHTML:r.source==='attribute'?(r.attribute==='href'&&el.href?el.href:el.getAttribute(r.attribute)):(el.innerText??el.textContent);
          if(text==null)return null;
          size+=text.length;
          if(text.length>200000||size>1000000)throw Error('Selected content is too large. Use a more specific selector.');
          return {text,url:r.source==='attribute'&&r.attribute==='href'&&/^https?:/i.test(text)?text:null};
        }).filter(Boolean);
      });
      const links=new Set();
      if(selector!==null) {
        const roots=document.querySelectorAll(selector||'a[href]');
        if(roots.length>500)throw Error('Too many link elements. Use a more specific selector.');
        for(const root of roots) {
          const anchors=[...(root.matches('a[href]')?[root]:[]),...root.querySelectorAll('a[href]')];
          for(const a of anchors)if(/^https?:/i.test(a.href))links.add(a.href);
          const text=root.innerText??root.textContent??'';size+=text.length;
          if(text.length>200000||size>1000000)throw Error('Selected content is too large. Narrow the links selector.');
          for(const m of text.matchAll(/https?:\/\/[^\s<>"']+/g))links.add(m[0].replace(/[),.;]+$/,''));
          if(links.size>500)throw Error('More than 500 links. Narrow the links selector.');
        }
      }
      return {inputs,links:[...links]};
    } catch(error) {return {error:error.message};}
  }
  function run(rules,inputs,timeout=750) {
    return new Promise((resolve,reject)=>{
      if(inputs.flat().reduce((size,v)=>size+String(v.text??'').length,0)>1000000) {reject(Error('Selected content is too large. Narrow the selectors.'));return;}
      const worker=new Worker(new URL('connector_worker.js',location.href));
      const timer=setTimeout(()=>{worker.terminate();reject(Error('Parameter matching took too long and was stopped. Simplify the regex or narrow the selector.'));},timeout);
      const finish=(error,result)=>{clearTimeout(timer);worker.terminate();error?reject(Error(error)):resolve(result);};
      worker.onmessage=e=>{if(!e.data.started)finish(e.data.error,e.data.result);};
      worker.onerror=()=>finish('Parameter matching could not run. Reload the extension and try again.');
      worker.postMessage({rules,inputs});
    });
  }
  async function prepare(profile,source,tab) {
    validate(source);
    if(!matches(source,tab.url))throw Error('Switch to the website and page configured for this source.');
    const rules=structuredClone(source.rules||[]);
    // Validate the link pattern before injecting into or reading the page.
    const recordRule=source.mode==='links'?linkRule(profile,source):null;
    let frames;
    try {frames=await browser.scripting.executeScript({target:{tabId:tab.id,allFrames:true},func:captureDOM,args:[rules,source.mode==='links'?source.selector||'a[href]':null]});}
    catch(_) {frames=await browser.scripting.executeScript({target:{tabId:tab.id},func:captureDOM,args:[rules,source.mode==='links'?source.selector||'a[href]':null]});}
    const results=frames.map(f=>f.result).filter(Boolean);
    if(!results.length)throw Error('The page did not return any readable content.');
    const error=results.find(r=>r.error);if(error)throw Error(error.error);
    const inputs=rules.map((r,i)=>r.source==='page_url'?[{text:tab.url}]:r.source==='constant'?[{text:r.value||''}]:results.flatMap(f=>f.inputs[i]||[]));
    if(source.mode==='links') {
      const host=source.linkHost||profile.siemHost;
      // linkHost '*' leaves host checks to the link pattern itself.
      const links=[...new Set(results.flatMap(f=>f.links))].filter(url=>{try{return host==='*'||new URL(url).hostname===host;}catch(_){return false;}});
      rules.push(recordRule);
      inputs.push(links.map(text=>({text,url:text})));
    }
    const resolved=await run(rules,inputs);
    const links=resolved.links;
    return {...resolved,links,sourceName:source.name||source.website};
  }
  return {matches,validate,linkRule,prepare,run,captureDOM,hostOnly};
})();
