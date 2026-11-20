/* Connection settings helpers (link patterns, response mapping) and local record statistics. No network calls. */
globalThis.VeiluxConnectors = (() => {
  // OpenSearch Dashboards / Wazuh values, used by that platform template and to
  // fill the Inspector panel's selectors in the editor. Nothing falls back to them.
  const opensearch = Object.freeze({
    linkRegex: '#/doc/[^/]+/(?<index>[^/?]+)\\?(?:[^#]*&)?id=(?<doc_id>[^&]+)',
    method: 'POST', pathTemplate: '/internal/search/opensearch-with-long-numerals',
    headersTemplate: Object.freeze({'osd-xsrf':'osd-fetch'}), responsePath: 'rawResponse.hits.hits',
    bodyTemplate: JSON.stringify({params:{index:'${index}',body:{query:{ids:{values:['${doc_id}']}},stored_fields:['*'],_source:true,
      docvalue_fields:[{field:'@timestamp',format:'date_time'}],script_fields:{}}}}),
    testPath: '/api/status', discoverPathHint: 'discover',
    inspector: Object.freeze({
      openButtonSelector: '[data-test-subj="openInspectorButton"]', closeButtonSelector: '[data-test-subj="euiFlyoutCloseButton"]',
      responseTabSelector: '[data-test-subj="inspectorRequestDetailResponse"]', responseBodySelector: '[data-test-subj="inspectorResponseBody"]',
      requestTabSelector: '[data-test-subj="inspectorRequestDetailRequest"]', requestBodySelector: '[data-test-subj="inspectorRequestBody"]',
      requestUrlSelector: '[data-test-subj="inspectorRequestUrl"]', statisticsTabSelector: '[data-test-subj="inspectorRequestDetailStatistics"]',
      hitsPath: 'hits.hits', totalPath: 'hits.total'
    })
  });
  // Connections in the current format (schemaVersion 2). A connection in any
  // other format was saved by a development build before 1.0.0: it is kept in
  // storage untouched, but not used, and Settings says so.
  function isCurrent(p) {
    return !!p && typeof p === 'object' && p.schemaVersion === 2 && p.legacyDefaults !== true && !p.soarHost;
  }
  function usable(list) {
    const all = Array.isArray(list) ? list : [];
    return {profiles: all.filter(isCurrent), setAside: all.filter(p => !isCurrent(p))};
  }

  function linkPattern(p) {
    const template=p.api?.linkTemplate;
    if (!template) return (p.api?.linkRegex || '(?!)').replace(/\(\?P</g,'(?<');
    const names=new Set(); let offset=0, pattern='^';
    const escape=text=>text.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    for (const match of template.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
      if(names.has(match[1])) throw new Error('Use each link parameter name only once.');
      names.add(match[1]);pattern+=escape(template.slice(offset,match.index))+'(?<'+match[1]+'>[^/?&#]+)';offset=match.index+match[0].length;
    }
    if(!names.size) throw new Error('Add a parameter such as {id} to the record link pattern.');
    return pattern+escape(template.slice(offset))+'(?:[&#].*)?$';
  }
  function linkParams(p,url) {
    const match=new RegExp(linkPattern(p)).exec(url);
    return match?.groups ? Object.fromEntries(Object.entries(match.groups).filter(([,v])=>v!==undefined).map(([k,v])=>[k,decodeURIComponent(v)])) : null;
  }
  function matches(p,url) {
    try {const u=new URL(url);return ['http:','https:'].includes(u.protocol)&&!!p.siemHost&&u.hostname===p.siemHost&&(!p.pageMatch||url.includes(p.pageMatch));} catch (_) {return false;}
  }
  function api(p) {
    const a = p.api || {};
    return {method:a.method || 'GET', pathTemplate:a.pathTemplate || '', headers:a.headersTemplate || {},
      bodyTemplate:a.bodyTemplate || '', responsePath:a.responsePath || ''};
  }
  function statsMode(p) {
    return p.statistics?.mode || 'records';
  }
  function records(data, path, format='objects', columnsPath='') {
    const at = (value, key) => key ? key.split('.').reduce((v,k)=>v == null ? undefined : v[k], value) : value;
    const found = at(data,path);
    if (found == null) throw new Error('No records at this location. Choose an array or object in the sample response.');
    const rows = Array.isArray(found) ? found : [found];
    if (format === 'columns') {
      const columns = at(data,columnsPath);
      if (!Array.isArray(columns)) throw new Error('Column names location must point to an array.');
      const names = columns.map(c=>typeof c === 'object' && c !== null ? c.name : c);
      if (names.some(n=>typeof n !== 'string'||!n) || new Set(names).size !== names.length) throw new Error('Column names must be unique text.');
      return rows.map(row=>{
        if (!Array.isArray(row)||row.length!==names.length) throw new Error('Each row must have one value per column.');
        return Object.fromEntries(names.map((name,i)=>[name,row[i]]));
      });
    }
    if (rows.some(row=>!row||typeof row!=='object'||Array.isArray(row))) throw new Error('Choose JSON objects, or use column names + rows for table-shaped responses.');
    return rows;
  }
  // topCount: most frequent values kept per field, 1 to 10 (default 5).
  function statistics(rows, topCount = 5) {
    const top = Number.isInteger(topCount) && topCount >= 1 ? Math.min(topCount, 10) : 5;
    const fields = new Map();
    function flatten(value, prefix, out, depth=0) {
      if (value == null || depth>50) return;
      if (Array.isArray(value)) { value.forEach(v=>flatten(v,prefix,out,depth+1)); return; }
      if (typeof value === 'object') { Object.keys(value).forEach(k=>flatten(value[k],prefix?prefix+'.'+k:k,out,depth+1)); return; }
      if (prefix) { if (!out.has(prefix)) out.set(prefix,new Set()); out.get(prefix).add(String(value)); }
    }
    rows.forEach(row=>{
      const values=new Map(); flatten(row?._source || row,'',values);
      values.forEach((unique,name)=>{
        if (!fields.has(name)) fields.set(name,{count:0,values:new Map()});
        const field=fields.get(name); field.count++;
        unique.forEach(value=>field.values.set(value,(field.values.get(value)||0)+1));
      });
    });
    const percentage=count=>rows.length?count*100/rows.length:0;
    return [...fields].sort(([a],[b])=>a.localeCompare(b)).map(([field,data])=>({field,count:data.count,percentage:percentage(data.count),
      topValues:[...data.values].map(([value,count])=>({value,count,percentage:percentage(count)}))
        .sort((a,b)=>b.count-a.count||a.value.localeCompare(b.value)).slice(0,top)}));
  }
  function samplePaths(data) {
    const paths=[];
    function walk(value,path,depth) {
      if (!value || typeof value!=='object' || depth>8 || paths.length>150) return;
      paths.push(path);
      if (Array.isArray(value)) { if (value.length) walk(value[0],path?path+'.0':'0',depth+1); }
      else Object.keys(value).forEach(key=>walk(value[key],path?path+'.'+key:key,depth+1));
    }
    walk(data,'',0);return paths;
  }
  return {opensearch,isCurrent,usable,api,statsMode,records,statistics,samplePaths,linkPattern,linkParams,matches};
})();
