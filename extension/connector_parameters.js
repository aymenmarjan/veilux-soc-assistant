/* Pure capture/merge logic, also loaded in the bounded regex worker. */
globalThis.ConnectorParameters = (() => {
  const safeName = name => /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !['__proto__','constructor','prototype'].includes(name);
  const invalid = (field,message) => {throw Object.assign(Error(message),{field});};
  function validateRule(r) {
    if (!['text','html','attribute','page_url','constant','links'].includes(r.source)) invalid('source','Choose where to read this parameter.');
    if (['text','html','attribute'].includes(r.source) && !r.selector?.trim()) invalid('selector','Enter an element selector, such as #description or div[name="Description"].');
    if (r.source === 'attribute' && !r.attribute?.trim()) invalid('attribute','Enter an attribute name, such as href or data-event-id.');
    if (r.pattern) {
      if (r.pattern.length > 4000) invalid('pattern','Use a regex of at most 4,000 characters.');
      if (/[^imsu]/.test(r.flags || '') || new Set(r.flags || '').size !== (r.flags || '').length) invalid('flags','Use regex flags i, m, s or u, once each.');
      const pattern=r.pattern.replace(/\(\?P</g,'(?<');
      try {new RegExp(pattern,r.flags || '');} catch (_) {invalid('pattern','This regex is invalid. Check its brackets, parentheses and escapes.');}
      const groups=[...pattern.matchAll(/\(\?<([A-Za-z_][A-Za-z0-9_]*)>/g)].map(m=>m[1]);
      if (!groups.length) invalid('pattern','This regex does not name any captured values. Use named groups such as (?<event_id>\\d+) instead of (\\d+), then use ${event_id} in the API request.');
      if (groups.some(n=>!safeName(n))) invalid('pattern','Use safe parameter names; __proto__, constructor and prototype are reserved.');
    } else if (!safeName(r.name || '')) invalid('name','Enter a parameter name, such as event_id, or a regex with named groups.');
  }
  function validate(rules) {
    if (!Array.isArray(rules) || rules.length > 30) throw Error('Use at most 30 parameter rules.');
    if (rules.filter(r => r.repeat).length > 1) throw Error('Only one value source per page can use “Make one request for each value found”. The others supply shared values.');
    rules.forEach((r,index)=>{try {validateRule(r);}catch(error){error.ruleIndex=index;error.message='Parameter rule '+(index+1)+': '+error.message;throw error;}});
  }
  function merge(a,b) {
    const out={...a};
    for (const [key,value] of Object.entries(b)) {
      if (!safeName(key)) throw Error('Unsupported parameter name: '+key);
      if (Object.hasOwn(out,key) && out[key] !== value) throw Error('Conflicting values for '+key+'. Narrow the selectors or use different parameter names.');
      out[key]=value;
    }
    return out;
  }
  function resolve(rules,inputs) {
    validate(rules);
    let common={}, repeated=null;const diagnostics=[],links=new Set();
    rules.forEach((r,index)=>{
      const values=inputs[index] || [], found=new Map();let matches=0;
      if(values.length>500)throw Error('Too many elements. Use a more specific selector.');
      for(const input of values) {
        const text=String(input.text ?? '');
        if(text.length>200000)throw Error('Selected content is too large. Use a more specific selector.');
        const captures=r.pattern ? text.matchAll(new RegExp(r.pattern.replace(/\(\?P</g,'(?<'),(r.flags||'')+'g'))
          : [{groups:{[r.name]:text}}];
        for(const match of captures) {
          if(++matches>500)throw Error('More than 500 matches. Narrow the selector or regex.');
          let params=Object.fromEntries(Object.entries(match.groups||{}).filter(([,v])=>v!==undefined));
          if(r.decode) params=Object.fromEntries(Object.entries(params).map(([k,v])=>[k,decodeURIComponent(v)]));
          if(!Object.keys(params).length)continue;
          if(input.url)links.add(input.url);
          params=merge({},params);
          const key=JSON.stringify(Object.entries(params).sort(([a],[b])=>a.localeCompare(b)));
          if(!found.has(key))found.set(key,{params,link:input.url||null});
        }
      }
      const rows=[...found.values()];
      diagnostics.push({rule:index+1,matches:rows.length});
      if(!rows.length) {if(r.required!==false)throw Error('Value source '+(index+1)+' on this page found no value. Check its element and pattern.');return;}
      if(r.repeat)repeated=rows;
      else {if(rows.length>1)throw Error('Value source '+(index+1)+' on this page found different values. Narrow its element or pattern, or turn on “Make one request for each value found”.');common=merge(common,rows[0].params);}
    });
    return {records:(repeated||[{params:{},link:null}]).map(row=>({...row,params:merge(common,row.params)})),diagnostics,links:[...links]};
  }
  return {validate,validateRule,resolve,merge};
})();
